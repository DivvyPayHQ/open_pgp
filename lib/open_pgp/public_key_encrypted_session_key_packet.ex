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
end
