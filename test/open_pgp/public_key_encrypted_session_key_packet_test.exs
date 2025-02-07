defmodule OpenPGP.PublicKeyEncryptedSessionKeyPacketTest do
  use OpenPGP.Test.Case, async: true
  doctest OpenPGP.PublicKeyEncryptedSessionKeyPacket
  doctest OpenPGP.Encode.impl_for!(%OpenPGP.PublicKeyEncryptedSessionKeyPacket{})

  alias OpenPGP.Encode
  alias OpenPGP.Encrypt
  alias OpenPGP.Packet
  alias OpenPGP.Packet.PacketTag
  alias OpenPGP.PublicKeyEncryptedSessionKeyPacket
  alias OpenPGP.PublicKeyPacket
  alias OpenPGP.SecretKeyPacket
  alias OpenPGP.Util

  @rsa2048_priv File.read!("test/fixtures/rsa2048-priv.pgp")
  @encrypted_file File.read!("test/fixtures/words.dict.gpg")

  describe ".decode/1" do
    test "decodes packet and assignes ciphertext" do
      # The Symmetrically Encrypted Data Packet is preceded by one
      # Public-Key Encrypted Session Key packet for each OpenPGP key to
      # which the message is encrypted.  The recipient of the message
      # finds a session key that is encrypted to their public key,
      # decrypts the session key, and then uses the session key to
      # decrypt the message.
      assert [packet | _] = OpenPGP.list_packets(@encrypted_file)

      assert {packet, ""} = packet |> Util.concat_body() |> PublicKeyEncryptedSessionKeyPacket.decode()

      assert %PublicKeyEncryptedSessionKeyPacket{
               ciphertext: <<7, 255, 101, 61, 27, 178, 49, 190, 16, _::binary>>,
               public_key_algo: {1, "RSA (Encrypt or Sign) [HAC]"},
               public_key_id: <<184, 5, 16, 71, 78, 123, 136, 254>>,
               session_key_algo: nil,
               session_key_material: nil,
               version: 3
             } = packet
    end
  end

  describe ".encode/3" do
    test "encodes packet body" do
      packet = %PublicKeyEncryptedSessionKeyPacket{
        ciphertext: "Ciphertext",
        public_key_id: "6BAF2C48",
        public_key_algo: {16, "Elgamal (Encrypt-Only) [ELGAMAL] [HAC]"}
      }

      assert <<3::8, "6BAF2C48", 16::8, "Ciphertext">> == Encode.encode(packet)
    end
  end

  describe ".decrypt/2" do
    test "decrypts key material given a valid decrypted Secret-Key Packet" do
      [
        %Packet{tag: %PacketTag{tag: {5, "Secret-Key Packet"}}},
        %Packet{tag: %PacketTag{tag: {13, "User ID Packet"}}},
        %Packet{tag: %PacketTag{tag: {2, "Signature Packet"}}},
        %Packet{tag: %PacketTag{tag: {7, "Secret-Subkey Packet"}}} = sk_packet,
        %Packet{tag: %PacketTag{tag: {2, "Signature Packet"}}}
      ] = OpenPGP.list_packets(@rsa2048_priv)

      {sk_packet_decoded, _} =
        sk_packet
        |> Util.concat_body()
        |> SecretKeyPacket.decode()

      sk_packet_decrypted = SecretKeyPacket.decrypt(sk_packet_decoded, "passphrase")

      assert [packet | _] = OpenPGP.list_packets(@encrypted_file)

      assert {cipher_packet, ""} = packet |> Util.concat_body() |> PublicKeyEncryptedSessionKeyPacket.decode()

      assert %PublicKeyEncryptedSessionKeyPacket{
               session_key_material: session_key_material
             } = PublicKeyEncryptedSessionKeyPacket.decrypt(cipher_packet, sk_packet_decrypted)

      assert {m_e_mod_n} = session_key_material

      assert "26A582ACA833B8EE60CC58865D19A21653D38CB0737125C9ABF973405E3B233C" = Base.encode16(m_e_mod_n)
    end
  end

  describe "OpenPGP.Encrypt.encrypt/2" do
    # [RFC3526](https://datatracker.ietf.org/doc/html/rfc3526)
    @modp_group_1536 """
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF
    """
    @prime_p @modp_group_1536 |> String.replace(~r/[^0-9ABCDEF]/, "") |> Base.decode16!()
    @group_g <<2::8>>
    test "encrypts AES-256 session key with Elgamal" do
      alias PublicKeyEncryptedSessionKeyPacket, as: PKESK

      # Define Diffie-Hellman (DH) parameters (p and g). These are commonly used predefined values.
      p = :binary.decode_unsigned(@prime_p)
      g = :binary.decode_unsigned(@group_g)

      # Generate private key such as "1 < private_key < p-1"
      # Any 1024-bit (128 bytes) big-endian will be smaller than 1536-bit big-endian.
      private_key = :crypto.strong_rand_bytes(128)
      a = :binary.decode_unsigned(private_key)

      # Generate the public key exp (g**private_key mod p)
      e = :crypto.mod_pow(g, a, p)

      recipient_public_key = %PublicKeyPacket{
        algo: {16, "Elgamal (Encrypt-Only) [ELGAMAL] [HAC]"},
        material: {@prime_p, @group_g, e}
      }

      pkesk_packet = %PKESK{
        session_key_algo: {9, "AES with 256-bit key"},
        session_key_material: {"12345678901234567890123456789012"}
      }

      assert %PKESK{ciphertext: ciphertext} = Encrypt.encrypt(pkesk_packet, recipient_public_key: recipient_public_key)

      # Decrypt Elgamal
      assert {c1, next} = Util.decode_mpi(ciphertext)
      assert {c2, <<>>} = Util.decode_mpi(next)

      x = :crypto.mod_pow(c1, a, p)
      y = :crypto.mod_pow(x, p - 2, p)
      decoded_value = rem(:binary.decode_unsigned(c2) * :binary.decode_unsigned(y), p)
      plaintext = :binary.encode_unsigned(decoded_value)

      assert [_, <<0x09, "12345678901234567890123456789012", _::16>>] = String.split(plaintext, <<0>>, parts: 2)
    end
  end
end
