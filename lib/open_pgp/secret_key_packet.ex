defmodule OpenPGP.SecretKeyPacket do
  @v05x_note """
  As of 0.5.x Secret-Key Packet supports only:

    1. V4 packets
    1. Iterated and Salted String-to-Key (S2K) specifier (ID: 3)
    1. S2K usage convention octet of 254 only
    1. S2K hashing algo SHA1
    1. AES128 symmetric encryption of secret key material
  """
  @moduledoc """
  Represents structured data for Secret-Key Packet.

  > NOTE: #{@v05x_note}
  ---

  ## [RFC4880](https://www.ietf.org/rfc/rfc4880.txt)

  5.5.3.  Secret-Key Packet Formats

  The Secret-Key and Secret-Subkey packets contain all the data of the
  Public-Key and Public-Subkey packets, with additional algorithm-
  specific secret-key data appended, usually in encrypted form.

  The packet contains:

    - A Public-Key or Public-Subkey packet, as described above.

    - One octet indicating string-to-key usage conventions.  Zero
      indicates that the secret-key data is not encrypted.  255 or 254
      indicates that a string-to-key specifier is being given.  Any
      other value is a symmetric-key encryption algorithm identifier.

    - [Optional] If string-to-key usage octet was 255 or 254, a one-
      octet symmetric encryption algorithm.

    - [Optional] If string-to-key usage octet was 255 or 254, a
      string-to-key specifier.  The length of the string-to-key
      specifier is implied by its type, as described above.

    - [Optional] If secret data is encrypted (string-to-key usage octet
      not zero), an Initial Vector (IV) of the same length as the
      cipher's block size.

    - Plain or encrypted multiprecision integers comprising the secret
      key data.  These algorithm-specific fields are as described
      below.

    - If the string-to-key usage octet is zero or 255, then a two-octet
      checksum of the plaintext of the algorithm-specific portion (sum
      of all octets, mod 65536).  If the string-to-key usage octet was
      254, then a 20-octet SHA-1 hash of the plaintext of the
      algorithm-specific portion.  This checksum or hash is encrypted
      together with the algorithm-specific fields (if string-to-key
      usage octet is not zero).  Note that for all other values, a
      two-octet checksum is required.

      Algorithm-Specific Fields for RSA secret keys:

      - multiprecision integer (MPI) of RSA secret exponent d.

      - MPI of RSA secret prime value p.

      - MPI of RSA secret prime value q (p < q).

      - MPI of u, the multiplicative inverse of p, mod q.

      Algorithm-Specific Fields for DSA secret keys:

      - MPI of DSA secret exponent x.

      Algorithm-Specific Fields for Elgamal secret keys:

      - MPI of Elgamal secret exponent x.

  Secret MPI values can be encrypted using a passphrase.  If a string-
  to-key specifier is given, that describes the algorithm for
  converting the passphrase to a key, else a simple MD5 hash of the
  passphrase is used.  Implementations MUST use a string-to-key
  specifier; the simple hash is for backward compatibility and is
  deprecated, though implementations MAY continue to use existing
  private keys in the old format.  The cipher for encrypting the MPIs
  is specified in the Secret-Key packet.

  Encryption/decryption of the secret data is done in CFB mode using
  the key created from the passphrase and the Initial Vector from the
  packet.  A different mode is used with V3 keys (which are only RSA)
  than with other key formats.  With V3 keys, the MPI bit count prefix
  (i.e., the first two octets) is not encrypted.  Only the MPI non-
  prefix data is encrypted.  Furthermore, the CFB state is
  resynchronized at the beginning of each new MPI value, so that the
  CFB block boundary is aligned with the start of the MPI data.

  With V4 keys, a simpler method is used.  All secret MPI values are
  encrypted in CFB mode, including the MPI bitcount prefix.

  The two-octet checksum that follows the algorithm-specific portion is
  the algebraic sum, mod 65536, of the plaintext of all the algorithm-
  specific octets (including MPI prefix and data).  With V3 keys, the
  checksum is stored in the clear.  With V4 keys, the checksum is
  encrypted like the algorithm-specific data.  This value is used to
  check that the passphrase was correct.  However, this checksum is
  deprecated; an implementation SHOULD NOT use it, but should rather
  use the SHA-1 hash denoted with a usage octet of 254.  The reason for
  this is that there are some attacks that involve undetectably
  modifying the secret key.
  """

  @behaviour OpenPGP.Packet.Behaviour

  alias OpenPGP.Util

  defstruct [
    :public_key,
    :s2k_usage,
    :s2k_specifier,
    :sym_key_algo,
    :sym_key_initial_vector,
    :sym_key_size,
    :ciphertext,
    :secret_key_material
  ]

  alias OpenPGP.PublicKeyPacket
  alias OpenPGP.S2KSpecifier
  alias OpenPGP.Util

  @type t :: %__MODULE__{
          public_key: PublicKeyPacket.t(),
          s2k_usage: {0..255, binary()},
          s2k_specifier: S2KSpecifier.t(),
          sym_key_algo: OpenPGP.Util.sym_algo_tuple(),
          sym_key_initial_vector: binary(),
          sym_key_size: non_neg_integer(),
          secret_key_material: tuple() | nil,
          ciphertext: binary()
        }

  @doc """
  Decode Secret Key Packet given input binary.
  Return structured packet and remaining binary (empty binary).
  """
  @impl OpenPGP.Packet.Behaviour
  @spec decode(binary()) :: {t(), <<>>}
  def decode("" <> _ = input) do
    {public_key, next} = PublicKeyPacket.decode(input)

    case next do
      <<s2k_usage::8, sym_algo::8, next::binary>> when s2k_usage == 254 ->
        {s2k_specifier, next} = S2KSpecifier.decode(next)
        iv_size = Util.sym_algo_cipher_block_size(sym_algo)
        <<iv::bits-size(iv_size), ciphertext::binary>> = next

        packet = %__MODULE__{
          public_key: public_key,
          s2k_specifier: s2k_specifier,
          s2k_usage: s2k_usage_tuple(s2k_usage),
          sym_key_algo: Util.sym_algo_tuple(sym_algo),
          sym_key_initial_vector: iv,
          sym_key_size: iv_size,
          ciphertext: ciphertext
        }

        {packet, ""}
    end
  end

  @doc """
  Decrypt Secret-Key Packet given decoded Secret-Key Packet and a
  passphrase.
  Return Secret-Key Packet with `:secret_key_material` attr assigned.
  Raises an error if checksum does not match.
  """
  @spec decrypt(t(), passphrase :: binary()) :: t()
  def decrypt(%__MODULE__{} = packet, "" <> _ = passphrase) do
    case packet do
      %__MODULE__{public_key: %{version: 4}, s2k_usage: {254, _}, sym_key_algo: {7, _}} -> :ok
      %__MODULE__{} -> raise(@v05x_note <> "\n Got: #{inspect(packet)}")
    end

    %__MODULE__{
      sym_key_size: session_key_size,
      sym_key_initial_vector: iv,
      ciphertext: ciphertext,
      s2k_specifier: s2k_specifier
    } = packet

    session_key = S2KSpecifier.build_session_key(s2k_specifier, session_key_size, passphrase)

    plaintext = :crypto.crypto_one_time(:aes_128_cfb128, session_key, iv, ciphertext, false)
    {data, _checksum} = validate_checksum!(plaintext)

    {secret_exp_d, next} = Util.decode_mpi(data)
    {prime_val_p, next} = Util.decode_mpi(next)
    {prime_val_q, next} = Util.decode_mpi(next)
    {secret_u, ""} = Util.decode_mpi(next)

    material = {secret_exp_d, prime_val_p, prime_val_q, secret_u}

    %{packet | secret_key_material: material}
  end

  @checksum_byte_size 20
  @spec validate_checksum!(binary()) :: {data :: binary(), checksum :: binary()}
  defp validate_checksum!("" <> _ = plaintext) do
    plaintext_byte_size = byte_size(plaintext) - @checksum_byte_size

    <<data::bytes-size(plaintext_byte_size), expected_checksum::bytes-size(@checksum_byte_size)>> = plaintext

    actual_checksum = :crypto.hash(:sha, data)

    if actual_checksum == expected_checksum do
      {data, actual_checksum}
    else
      expected_hex = expected_checksum |> Base.encode16() |> inspect()
      actual_hex = actual_checksum |> Base.encode16() |> inspect()

      msg = "Expected SecretKeyPacket checksum to be #{expected_hex}, got #{actual_hex}. Maybe incorrect passphrase?"

      raise(msg)
    end
  end

  @s2k_spec_given_text "String-to-key specifier is being given"
  defp s2k_usage_tuple(octet) when octet in 254..255, do: {octet, @s2k_spec_given_text}
  defp s2k_usage_tuple(octet), do: Util.sym_algo_tuple(octet)
end
