defmodule OpenPGP.PublicKeyEncryptedSessionKeyPacket do
  @v06x_note """
  As of 0.6.x Public Key Encrypted Session Key Packet:

    1. Encrypts the session key with "Elgamal (Encrypt-Only)" algorithm only (algo 16)
    1. Decrypts the session key encrypted with "RSA (Encrypt or Sign)" algorithm only (algo 1)
  """

  @moduledoc """
  Represents structured data for Public-Key Encrypted Session Key Packet.

  The `:ciphertext` attribute is set once the packet is decoded with
  `.decode/1` and the packet data is still symmetrically encrypted. The
  next logical step is to decrypt packet with `.decrypt/2` to get
  symmetrically encrypted session key material.

  > NOTE: #{@v06x_note}

  ---

  ## [RFC4880](https://www.ietf.org/rfc/rfc4880.txt)

  ### 5.1.  Public-Key Encrypted Session Key Packets (Tag 1)

  A Public-Key Encrypted Session Key packet holds the session key used
  to encrypt a message.  Zero or more Public-Key Encrypted Session Key
  packets and/or Symmetric-Key Encrypted Session Key packets may
  precede a Symmetrically Encrypted Data Packet, which holds an
  encrypted message.  The message is encrypted with the session key,
  and the session key is itself encrypted and stored in the Encrypted
  Session Key packet(s).  The Symmetrically Encrypted Data Packet is
  preceded by one Public-Key Encrypted Session Key packet for each
  OpenPGP key to which the message is encrypted.  The recipient of the
  message finds a session key that is encrypted to their public key,
  decrypts the session key, and then uses the session key to decrypt
  the message.

  The body of this packet consists of:

    - A one-octet number giving the version number of the packet type.
      The currently defined value for packet version is 3.

    - An eight-octet number that gives the Key ID of the public key to
      which the session key is encrypted.  If the session key is
      encrypted to a subkey, then the Key ID of this subkey is used
      here instead of the Key ID of the primary key.

    - A one-octet number giving the public-key algorithm used.

    - A string of octets that is the encrypted session key.  This
      string takes up the remainder of the packet, and its contents are
      dependent on the public-key algorithm used.

  Algorithm Specific Fields for RSA encryption

    - multiprecision integer (MPI) of RSA encrypted value m**e mod n.

  Algorithm Specific Fields for Elgamal encryption:

    - MPI of Elgamal (Diffie-Hellman) value g**k mod p.

    - MPI of Elgamal (Diffie-Hellman) value m * y**k mod p.

  The value "m" in the above formulas is derived from the session key
  as follows.  First, the session key is prefixed with a one-octet
  algorithm identifier that specifies the symmetric encryption
  algorithm used to encrypt the following Symmetrically Encrypted Data
  Packet.  Then a two-octet checksum is appended, which is equal to the
  sum of the preceding session key octets, not including the algorithm
  identifier, modulo 65536.  This value is then encoded as described in
  PKCS#1 block encoding EME-PKCS1-v1_5 in Section 7.2.1 of [RFC3447] to
  form the "m" value used in the formulas above.  See Section 13.1 of
  this document for notes on OpenPGP's use of PKCS#1.

  Note that when an implementation forms several PKESKs with one
  session key, forming a message that can be decrypted by several keys,
  the implementation MUST make a new PKCS#1 encoding for each key.

  An implementation MAY accept or use a Key ID of zero as a "wild card"
  or "speculative" Key ID.  In this case, the receiving implementation
  would try all available private keys, checking for a valid decrypted
  session key.  This format helps reduce traffic analysis of messages.
  """

  @behaviour OpenPGP.Packet.Behaviour

  alias OpenPGP.PublicKeyPacket, as: PKPacket
  alias OpenPGP.SecretKeyPacket, as: SKPacket
  alias OpenPGP.Util

  defstruct [
    :version,
    :public_key_id,
    :public_key_algo,
    :ciphertext,
    :session_key_algo,
    :session_key_material
  ]

  @type t :: %__MODULE__{
          version: byte(),
          public_key_id: binary(),
          public_key_algo: Util.public_key_algo_tuple(),
          ciphertext: binary(),
          session_key_algo: Util.sym_algo_tuple() | nil,
          session_key_material: tuple() | nil
        }

  @doc """
  Decode Public-Key Encrypted Session Key Packet given input binary.
  Return structured packet and remaining binary.
  """
  @impl OpenPGP.Packet.Behaviour
  @spec decode(binary()) :: {t(), <<>>}
  def decode("" <> _ = input) do
    <<version::8, pub_key_id::bytes-size(8), pub_key_algo, ciphertext::binary>> = input

    packet = %__MODULE__{
      version: version,
      public_key_id: pub_key_id,
      public_key_algo: Util.public_key_algo_tuple(pub_key_algo),
      ciphertext: ciphertext
    }

    {packet, ""}
  end

  @doc """
  Encode Public-Key Encrypted Session Key Packet given input ciphertext, public key ID and public key algo.
  Return Public-Key Encrypted Session Key Packet binary.

  ### Example

      iex> alias OpenPGP.PublicKeyEncryptedSessionKeyPacket, as: PKESK 
      ...> ciphertext = "Ciphertext"
      ...> recipient_public_key_id = "6BAF2C48"
      ...> recipient_public_key_algo = {16, "Elgamal (Encrypt-Only) [ELGAMAL] [HAC]"}
      ...> PKESK.encode(ciphertext, recipient_public_key_id, recipient_public_key_algo)
      <<3::8, recipient_public_key_id::binary, 16::8, ciphertext::binary>>
  """
  @version 3
  @spec encode(ciphertext :: binary(), public_key_id :: binary(), Util.public_key_algo_tuple()) :: binary()
  def encode("" <> _ = ciphertext, "" <> _ = public_key_id, {pub_key_algo_id, _}) do
    <<@version::8, public_key_id::binary, pub_key_algo_id::8, ciphertext::binary>>
  end

  @doc """
  Decrypt Public-Key Encrypted Session Key Packet given decoded
  Public-Key Encrypted Session Key Packet and decoded and decrypted
  Secret-Key Packet.
  Return Public-Key Encrypted Session Key Packet with
  `:session_key_algo` and `:session_key_material` attrs assigned.
  Raises an error if checksum does not match.
  """
  @spec decrypt(t(), SKPacket.t()) :: t()
  def decrypt(%__MODULE__{} = packet, %SKPacket{} = sk_packet) do
    %SKPacket{
      public_key: %PKPacket{
        algo: {1, _},
        material: {mod_n, exp_e}
      },
      secret_key_material: {exp_d, _, _, _}
    } = sk_packet

    {encrypted_session_key, ""} = Util.decode_mpi(packet.ciphertext)

    priv_key = [exp_e, mod_n, exp_d]
    payload = :crypto.private_decrypt(:rsa, encrypted_session_key, priv_key, [])

    bsize = byte_size(payload) - 2 - 1
    <<sym_key_algo::8, session_key::bytes-size(bsize), expected_checksum::16>> = payload
    octets = for <<b::8 <- session_key>>, do: b
    actual_checksum = octets |> Enum.sum() |> rem(65536)

    if expected_checksum == actual_checksum do
      %{
        packet
        | session_key_algo: Util.sym_algo_tuple(sym_key_algo),
          session_key_material: {session_key}
      }
    else
      msg = "Expected PublicKeyEncryptedSessionKeyPacket checksum to be #{expected_checksum}, got #{actual_checksum}."

      raise(msg)
    end
  end

  @doc """
  Encrypt session key with a given public key.
  Require session key algo as it will be encoded and encrypted as well.
  Require public key algo as it will be used to generate public key material.
  Return ciphertext binary (encrypted session key), which consist of algorithm specific encrypted MPIs.
  """
  @spec encrypt(session_key, session_key_algo, public_key_material, public_key_algo) :: ciphertext
        when session_key: binary(),
             session_key_algo: Util.sym_algo_tuple(),
             public_key_material: tuple(),
             public_key_algo: Util.public_key_algo_tuple(),
             ciphertext: binary()
  def encrypt("" <> _ = session_key, session_key_algo, public_key_material, public_key_algo) do
    material = build_material(session_key, session_key_algo, public_key_material, public_key_algo)

    for el <- Tuple.to_list(material), reduce: "" do
      acc -> acc <> Util.encode_mpi(el)
    end
  end

  # {16, "Elgamal (Encrypt-Only) [ELGAMAL] [HAC]"}
  @spec build_material(session_key, session_key_algo, public_key_material, public_key_algo) :: pkesk_material
        when session_key: binary(),
             session_key_algo: Util.sym_algo_tuple(),
             public_key_material: tuple(),
             public_key_algo: Util.public_key_algo_tuple(),
             pkesk_material: tuple()
  defp build_material("" <> _ = session_key, session_key_algo, public_key_material, {16, _} = _public_key_algo) do
    {prime_p, group_g, value_y} = public_key_material
    {sym_algo_id, _} = session_key_algo

    {sender_pub_key, _private} = :crypto.generate_key(:dh, [prime_p, group_g])

    k = :binary.decode_unsigned(sender_pub_key)
    p = :binary.decode_unsigned(prime_p)
    g = :binary.decode_unsigned(group_g)
    y = :binary.decode_unsigned(value_y)

    checksum =
      for <<byte::8 <- session_key>>, reduce: 0 do
        acc -> rem(acc + byte, 65536)
      end

    value_m = Util.PKCS1.encode(:eme_pkcs1_v1_5, <<sym_algo_id::8, session_key::binary, checksum::16>>, sender_pub_key)
    m = :binary.decode_unsigned(value_m)

    g_k_mod_p = :crypto.mod_pow(g, k, p)
    y_k_mod_p = :crypto.mod_pow(y, k, p)
    m_y_k_mod_p = (m * :binary.decode_unsigned(y_k_mod_p)) |> rem(p) |> :binary.encode_unsigned()

    {g_k_mod_p, m_y_k_mod_p}
  end

  defp build_material(_session_key, _session_key_algo, _public_key_material, public_key_algo) do
    raise("Unsupported PKESK encription algo #{inspect(public_key_algo)}. " <> @v06x_note)
  end
end
