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

  Generate private key with DSA2048 algo and ELG2046 sub-key:

  ```
  gpg --batch --passphrase "passphrase" --quick-generate-key "John Doe (ELG2048) <john.doe.elg2048@example.com>" dsa2048 default never
  gpg --quick-add-key <KEY_ID_HERE> elg2048 default never
  ```

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

  @expected_error "OpenPGP.PublicKeyPacket.decode/1 decoded 697 unexpected trailing byte(s): " <>
                    "<<254, 7, 3, 2, 248, 49, 205, 223, 27, 66, 166, 109, 252, 54, 235, 29, 19, 66, " <>
                    "217, 249, 233, 73, 143, 69, 142, 10, 18, 42, 106, 122, 114, 71, 167, 145, 111, " <>
                    "190, 206, 40, 102, 166, 213, 241, 148, 116, 163, 167, 163, 228, 5, 223, ...>>"
  test "cast_packet/1 raises on trailing bytes from decoder" do
    # PublicKeyPacket.decode/1 stops after reading the key material MPIs,
    # so a Tag 6 packet body with extra trailing bytes produces a remainder.
    # The secret key body starts with the public key fields followed by secret key data.
    # Casting it as a Tag 6 (Public-Key) packet will leave the secret key bytes as remainder.

    [%Packet{body: chunks, tag: %PacketTag{tag: {5, "Secret-Key Packet"}}} | _] = OpenPGP.list_packets(@rsa2048_priv)

    ptag = %PacketTag{format: :new, tag: {6, "Public-Key Packet"}}
    packet = %Packet{tag: ptag, body: chunks}

    assert_raise RuntimeError, @expected_error, fn ->
      OpenPGP.cast_packet(packet)
    end
  end

  test "decode secret key message" do
    assert [
             %SecretKeyPacket{},
             %OpenPGP.UserIdPacket{},
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
               %OpenPGP.UserIdPacket{},
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
