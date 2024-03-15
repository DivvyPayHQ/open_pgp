defmodule OpenPGP.PublicKeyEncryptedSessionKeyPacketTest do
  use OpenPGP.Test.Case, async: true

  alias OpenPGP.Packet
  alias OpenPGP.Packet.PacketTag
  alias OpenPGP.PublicKeyEncryptedSessionKeyPacket
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
end
