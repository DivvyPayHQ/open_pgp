defmodule OpenPGP.IntegrityProtectedDataPacket do
  @v05x_note """
  As of 0.5.x Symmetrically Encrypted Integrity Protected Data Packet:

    1. Supports Session Key algo 9 (AES with 256-bit key) in CFB mode
    2. Modification Detection Code system is not supported
  """
  @moduledoc """
  Represents structured data for Integrity Protected Data Packet.

  ### Example:

      iex> alias OpenPGP.IntegrityProtectedDataPacket
      iex> alias OpenPGP.PublicKeyEncryptedSessionKeyPacket
      ...>
      iex> key = <<38, 165, 130, 172, 168, 51, 184, 238, 96, 204, 88,
      ...>   134, 93, 25, 162, 22, 83, 211, 140, 176, 115, 113, 37, 201,
      ...>   171, 249, 115, 64, 94, 59, 35, 60>>
      ...>
      iex> iv = <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>
      iex> <<prefix::14*8, chsum::2*8>> = :crypto.strong_rand_bytes(16)
      iex> plaintext = <<prefix::14*8, chsum::2*8, chsum::2*8, "Hello">>
      ...>
      iex> ciphertext =
      ...>   :crypto.crypto_one_time(
      ...>    :aes_256_cfb128,
      ...>    key,
      ...>    iv,
      ...>    plaintext,
      ...>    true)
      ...>
      iex> payload = <<1::8, ciphertext::binary>>
      iex> {packet_decoded, <<>>} =
      ...>   IntegrityProtectedDataPacket.decode(payload)
      {
        %IntegrityProtectedDataPacket{
          ciphertext: ciphertext,
          plaintext: nil,
          version: 1
        },
        <<>>
      }
      iex> pkesk = %PublicKeyEncryptedSessionKeyPacket{
      ...>   version: 3,
      ...>   session_key_algo: {9, "AES with 256-bit key"},
      ...>   session_key_material: {key}
      ...> }
      ...>
      iex> IntegrityProtectedDataPacket.decrypt(packet_decoded, pkesk)
      %IntegrityProtectedDataPacket{
        version: 1,
        plaintext: "Hello",
        ciphertext: ciphertext
      }


  > NOTE: #{@v05x_note}

  ---

  ## [RFC4880](https://www.ietf.org/rfc/rfc4880.txt)

  ### 5.13.  Sym. Encrypted Integrity Protected Data Packet (Tag 18)

  The Symmetrically Encrypted Integrity Protected Data packet is a
  variant of the Symmetrically Encrypted Data packet.

  ...

  This packet contains data encrypted with a symmetric-key algorithm
  and protected against modification by the SHA-1 hash algorithm.  When
  it has been decrypted, it will typically contain other packets (often
  a Literal Data packet or Compressed Data packet).  The last decrypted
  packet in this packet's payload MUST be a Modification Detection Code
  packet.

  The body of this packet consists of:

    - A one-octet version number.  The only currently defined value is
      1.

    - Encrypted data, the output of the selected symmetric-key cipher
      operating in Cipher Feedback mode with shift amount equal to the
      block size of the cipher (CFB-n where n is the block size).

  The symmetric cipher used MUST be specified in a Public-Key or
  Symmetric-Key Encrypted Session Key packet that precedes the
  Symmetrically Encrypted Data packet.  In either case, the cipher
  algorithm octet is prefixed to the session key before it is
  encrypted.

  The data is encrypted in CFB mode, with a CFB shift size equal to the
  cipher's block size.  The Initial Vector (IV) is specified as all
  zeros.  Instead of using an IV, OpenPGP prefixes an octet string to
  the data before it is encrypted.  The length of the octet string
  equals the block size of the cipher in octets, plus two.  The first
  octets in the group, of length equal to the block size of the cipher,
  are random; the last two octets are each copies of their 2nd
  preceding octet.  For example, with a cipher whose block size is 128
  bits or 16 octets, the prefix data will contain 16 random octets,
  then two more octets, which are copies of the 15th and 16th octets,
  respectively.  Unlike the Symmetrically Encrypted Data Packet, no
  special CFB resynchronization is done after encrypting this prefix
  data.  See "OpenPGP CFB Mode" below for more details.

  The repetition of 16 bits in the random data prefixed to the message
  allows the receiver to immediately check whether the session key is
  incorrect.

  ...

  """

  @behaviour OpenPGP.Packet.Behaviour

  alias OpenPGP.PublicKeyEncryptedSessionKeyPacket, as: PKESK
  alias OpenPGP.Util

  defstruct [:version, :ciphertext, :plaintext]

  @type t :: %__MODULE__{
          version: byte(),
          ciphertext: binary(),
          plaintext: binary() | nil
        }

  @doc """
  Decode Sym. Encrypted and Integrity Protected Data Packet given input
  binary.
  Return structured packet and remaining binary (empty binary).
  """
  @impl OpenPGP.Packet.Behaviour
  @spec decode(binary()) :: {t(), <<>>}
  def decode(<<version::8, ciphertext::binary>>) when version == 1 do
    packet = %__MODULE__{
      version: version,
      ciphertext: ciphertext
    }

    {packet, <<>>}
  end

  @doc """
  Decrypt Sym. Encrypted and Integrity Protected Data Packet
  (PKESK-Packet) given decoded PKESK-Packet and a decrypted Public-Key
  Encrypted Session Key Packet.
  Return PKESK-Packet with `:plaintext` attr assigned.
  Raises an error if checksum does not match.
  """
  @spec decrypt(t(), PKESK.t()) :: t()
  def decrypt(%__MODULE__{ciphertext: ciphertext} = packet, %PKESK{} = pkesk) do
    session_key =
      case pkesk do
        %PKESK{session_key_algo: {9, _}, session_key_material: {session_key}} -> session_key
        _ -> raise(@v05x_note <> "\n Got: #{inspect(pkesk)}")
      end

    null_iv = build_null_iv(pkesk)
    payload = decrypt(:aes_256_cfb128, session_key, null_iv, ciphertext)
    {data, _chsum} = validate_checksum!(payload, pkesk)

    %{packet | plaintext: data}
  end

  @checksum_octets 2
  defp validate_checksum!("" <> _ = plaintext, %PKESK{session_key_algo: sk_algo}) do
    cipher_block_octets = sk_algo |> Util.sym_algo_cipher_block_size() |> Kernel.div(8)
    prefix_byte_size = cipher_block_octets - @checksum_octets

    <<
      _::bytes-size(prefix_byte_size),
      chsum1::bytes-size(@checksum_octets),
      chsum2::bytes-size(@checksum_octets),
      data::binary
    >> = plaintext

    if chsum1 == chsum2 do
      {data, chsum1}
    else
      chsum1_hex = inspect(chsum1, base: :binary)
      chsum2_hex = inspect(chsum2, base: :binary)

      msg =
        "Expected IntegrityProtectedDataPacket prefix octets " <>
          "#{prefix_byte_size + 1}, #{prefix_byte_size + 2} to match octets " <>
          "#{prefix_byte_size + 3}, #{prefix_byte_size + 4}: #{chsum1_hex} != #{chsum2_hex}."

      raise(msg)
    end
  end

  defp build_null_iv(%PKESK{session_key_algo: sk_algo}) do
    size_bits = Util.sym_algo_cipher_block_size(sk_algo)
    for(_ <- 1..size_bits, into: <<>>, do: <<0::1>>)
  end

  defp decrypt(cipher, key, iv, ciphertext),
    do: :crypto.crypto_one_time(cipher, key, iv, ciphertext, false)
end
