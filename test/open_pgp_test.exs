defmodule OpenPGPTest do
  use OpenPGP.Test.Case, async: true
  doctest OpenPGP

  alias OpenPGP.CompressedDataPacket
  alias OpenPGP.IntegrityProtectedDataPacket
  alias OpenPGP.LiteralDataPacket
  alias OpenPGP.Packet
  alias OpenPGP.Packet.BodyChunk
  alias OpenPGP.Packet.PacketTag
  alias OpenPGP.PublicKeyEncryptedSessionKeyPacket
  alias OpenPGP.PublicKeyPacket
  alias OpenPGP.SecretKeyPacket

  @moduledoc """
  ## Handy GPG commands

  Generate keyring with RSA2048 algo:
  `gpg --batch --passphrase "passphrase" --quick-generate-key "John Doe (RSA2048) <john.doe@example.com>" rsa2048 default never`

  Export private key:
  `gpg --export-secret-keys "john.doe@example.com" > test/fixtures/rsa2048-priv.pgp`

  Inspect packets:
  `gpg --verbose --list-packets test/fixtures/rsa2048-priv.pgp`

  Add subkey with Encryption capability:
  ```
  gpg --edit-key <KEY ID HERE>
  gpg> addkey
  Please select what kind of key you want:
    (3) DSA (sign only)
    (4) RSA (sign only)
    (5) Elgamal (encrypt only)
    (6) RSA (encrypt only)
    (14) Existing key from card
  Your selection? 6
  ...
  """

  @rsa2048_priv File.read!("test/fixtures/rsa2048-priv.pgp")
  @encrypted_file File.read!("test/fixtures/words.dict.gpg")

  describe ".list_packets/1" do
    test "decode all packets in a message with secret key packets (does not cast packets)" do
      assert [
               %Packet{
                 body: [
                   %BodyChunk{
                     chunk_length: {:fixed, 966},
                     data: <<4, _::binary>>,
                     header_length: 2
                   }
                 ],
                 tag: %PacketTag{
                   format: :old,
                   length_type: {1, "two-octet"},
                   tag: {5, "Secret-Key Packet"}
                 }
               },
               %Packet{
                 body: [
                   %BodyChunk{
                     chunk_length: {:fixed, 41},
                     data: "John Doe (RSA2048) <john.doe@example.com>",
                     header_length: 1
                   }
                 ],
                 tag: %PacketTag{
                   format: :old,
                   length_type: {0, "one-octet"},
                   tag: {13, "User ID Packet"}
                 }
               },
               %Packet{
                 body: [
                   %BodyChunk{
                     chunk_length: {:fixed, 334},
                     data: <<4, _::binary>>,
                     header_length: 2
                   }
                 ],
                 tag: %PacketTag{
                   format: :old,
                   length_type: {1, "two-octet"},
                   tag: {2, "Signature Packet"}
                 }
               },
               %Packet{
                 body: [
                   %BodyChunk{
                     chunk_length: {:fixed, 966},
                     data: <<4, _::binary>>,
                     header_length: 2
                   }
                 ],
                 tag: %PacketTag{
                   format: :old,
                   length_type: {1, "two-octet"},
                   tag: {7, "Secret-Subkey Packet"}
                 }
               },
               %Packet{
                 body: [
                   %BodyChunk{
                     chunk_length: {:fixed, 310},
                     data: <<4, _::binary>>,
                     header_length: 2
                   }
                 ],
                 tag: %PacketTag{
                   format: :old,
                   length_type: {1, "two-octet"},
                   tag: {2, "Signature Packet"}
                 }
               }
             ] = OpenPGP.list_packets(@rsa2048_priv)
    end

    test "decode all packets in a message with encrypted data packets (does not cast packets)" do
      assert [
               %Packet{
                 body: [
                   %BodyChunk{chunk_length: {:fixed, 268}}
                 ],
                 tag: %PacketTag{
                   format: :old,
                   length_type: {1, "two-octet"},
                   tag: {1, "Public-Key Encrypted Session Key Packet"}
                 }
               },
               %Packet{
                 body: [
                   %BodyChunk{chunk_length: {:partial, 8192}},
                   %BodyChunk{chunk_length: {:partial, 8192}},
                   %BodyChunk{chunk_length: {:partial, 8192}},
                   %BodyChunk{chunk_length: {:partial, 4096}},
                   %BodyChunk{chunk_length: {:partial, 2048}},
                   %BodyChunk{chunk_length: {:partial, 1024}},
                   %BodyChunk{chunk_length: {:partial, 512}},
                   %BodyChunk{chunk_length: {:fixed, 332}}
                 ],
                 tag: %PacketTag{
                   format: :new,
                   length_type: nil,
                   tag: {18, "Sym. Encrypted and Integrity Protected Data Packet"}
                 }
               }
             ] = OpenPGP.list_packets(@encrypted_file)
    end
  end

  test "decode secret key message" do
    assert [
             %SecretKeyPacket{},
             %Packet{tag: %PacketTag{tag: {13, "User ID Packet"}}},
             %Packet{tag: %PacketTag{tag: {2, "Signature Packet"}}},
             %SecretKeyPacket{},
             %Packet{tag: %PacketTag{tag: {2, "Signature Packet"}}}
           ] = @rsa2048_priv |> OpenPGP.list_packets() |> OpenPGP.cast_packets()
  end

  test "decode Sym. Encrypted and Integrity Protected message" do
    assert [
             %PublicKeyEncryptedSessionKeyPacket{},
             %IntegrityProtectedDataPacket{}
           ] = @encrypted_file |> OpenPGP.list_packets() |> OpenPGP.cast_packets()
  end

  @passphrase "passphrase"
  test "full integration: load private key and decrypt encrypted file" do
    ###################################
    ### Load encrypted message/file ###
    ###################################

    assert [
             %PublicKeyEncryptedSessionKeyPacket{} = pkesk_packet,
             %IntegrityProtectedDataPacket{} = ipdata_packet
           ] = @encrypted_file |> OpenPGP.list_packets() |> OpenPGP.cast_packets()

    assert %PublicKeyEncryptedSessionKeyPacket{public_key_id: public_key_id} = pkesk_packet

    #######################
    ### Load secret key ###
    #######################

    assert keyring =
             [
               %SecretKeyPacket{},
               %Packet{tag: %PacketTag{tag: {13, "User ID Packet"}}},
               %Packet{tag: %PacketTag{tag: {2, "Signature Packet"}}},
               %SecretKeyPacket{},
               %Packet{tag: %PacketTag{tag: {2, "Signature Packet"}}}
             ] = @rsa2048_priv |> OpenPGP.list_packets() |> OpenPGP.cast_packets()

    sk_packet =
      Enum.find_value(keyring, fn
        %SecretKeyPacket{public_key: %PublicKeyPacket{id: ^public_key_id}} = packet -> packet
        _ -> nil
      end)

    sk_packet_decrypted = SecretKeyPacket.decrypt(sk_packet, @passphrase)

    ################################
    ### Decode encrypted message ###
    ################################

    pkesk_packet_decrypted =
      PublicKeyEncryptedSessionKeyPacket.decrypt(
        pkesk_packet,
        sk_packet_decrypted
      )

    ipdata_packet_decrypted = IntegrityProtectedDataPacket.decrypt(ipdata_packet, pkesk_packet_decrypted)

    assert %IntegrityProtectedDataPacket{
             version: 1,
             ciphertext: "" <> _,
             plaintext: plaintext
           } = ipdata_packet_decrypted

    assert [
             %CompressedDataPacket{
               algo: {2, "ZLIB [RFC1950]"},
               data_deflated: <<_::bitstring>>,
               data_inflated: data_inflated
             }
           ] = plaintext |> OpenPGP.list_packets() |> OpenPGP.cast_packets()

    assert [
             %LiteralDataPacket{
               format: {<<0x62>>, :binary},
               file_name: "words.dict",
               created_at: ~U[2024-01-04 00:27:32Z],
               data: data
             }
           ] = data_inflated |> OpenPGP.list_packets() |> OpenPGP.cast_packets()

    assert 104_475 == byte_size(data)

    assert """
           A
           a
           aa
           aal
           aalii
           aam
           Aani
           aardvark
           aardwolf
           Aaron
           """ <> _ = data

    assert "B47C587A45BBC76310CED7FA05E7BB3DC1F3FB07" == Base.encode16(:crypto.hash(:sha, data))
  end
end
