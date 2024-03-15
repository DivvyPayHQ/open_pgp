defmodule OpenPGP.SecretKeyPacketTest do
  use OpenPGP.Test.Case, async: true
  alias OpenPGP.Packet
  alias OpenPGP.Packet.PacketTag
  alias OpenPGP.PublicKeyPacket
  alias OpenPGP.S2KSpecifier
  alias OpenPGP.SecretKeyPacket
  alias OpenPGP.Util

  @rsa2048_priv File.read!("test/fixtures/rsa2048-priv.pgp")

  describe ".decode/1" do
    test "decodes Secret-Key Packet and assignes ciphertext" do
      assert [
               %Packet{tag: %PacketTag{tag: {5, "Secret-Key Packet"}}} = sk_packet
               | _
             ] = OpenPGP.list_packets(@rsa2048_priv)

      assert {%SecretKeyPacket{} = sk_packet_decoded, <<>>} =
               sk_packet
               |> Util.concat_body()
               |> SecretKeyPacket.decode()

      assert %SecretKeyPacket{
               public_key: %PublicKeyPacket{
                 algo: {1, "RSA (Encrypt or Sign) [HAC]"},
                 version: 4
               },
               s2k_usage: {254, "String-to-key specifier is being given"},
               s2k_specifier: %S2KSpecifier{
                 algo: {2, "SHA-1 [FIPS180]"},
                 id: {3, "Iterated and Salted S2K"},
                 protect_count: {252, 58_720_256},
                 salt: s2k_salt
               },
               sym_key_algo: {7, "AES with 128-bit key [AES]"},
               sym_key_initial_vector: sym_key_iv,
               sym_key_size: 128,
               ciphertext: <<122, 114, 71, _::binary>>,
               secret_key_material: nil
             } = sk_packet_decoded

      assert "F831CDDF1B42A66D" = Base.encode16(s2k_salt)
      assert "36EB1D1342D9F9E9498F458E0A122A6A" = Base.encode16(sym_key_iv)
    end
  end

  describe ".decrypt/2" do
    @passphrase "passphrase"
    test "decrypts Secret-Key Packet given a valid passphrase" do
      assert [
               %Packet{tag: %PacketTag{tag: {5, "Secret-Key Packet"}}} = sk_packet
               | _
             ] = OpenPGP.list_packets(@rsa2048_priv)

      assert {%SecretKeyPacket{} = sk_packet_decoded, <<>>} =
               sk_packet
               |> Util.concat_body()
               |> SecretKeyPacket.decode()

      assert %SecretKeyPacket{secret_key_material: material} = SecretKeyPacket.decrypt(sk_packet_decoded, @passphrase)

      assert {secret_exp_d, prime_val_p, prime_val_q, secret_u} = material

      assert "0206152887DF8678CAC235EC5FD1ED537B2275D01242C306451EF7BFB005E2242F021BF46" <>
               "EA996A74683766DC792C2D01A8253098CDE7C9A2F64017C8814DE4A69E276D93581AC77" <>
               "CB81C672D442FEA242A03DC7C609FAC0F46B3C0755DE97D408BC7F41D4BE01D7252AD63" <>
               "7F901C3AF34FA13E44E12CDF5C63C46CED14A4C73B8A88D9B6278A995DB0F49778169E2" <>
               "AD4A774D7C33657617D7469594A02E5A54336766A804339AD4B5B27AC16660BA4584D4B" <>
               "7F7E1FE4246C2D1B204AF90E53D1EA60A20AF9CBEF476867B61F979D523773F15147D7E" <>
               "4E8A520F4FAA4FFFFC6CC5EAE8581DFF75BB05988A9B12D361893E4F754E964F3B6CA1E" <>
               "237AE0D479807" = Base.encode16(secret_exp_d)

      assert "E18852EA986485496F76F75A2EDA0891AC6E6D5A7859B59F5B1042D07C61B2CC526041D4C" <>
               "4E653EB78213504EE62412B98F45E254FC346FAE03E45F624EEFAD58B3034F678B845B0" <>
               "C84E9DEEA3D6E32B0D724620FC4DA3507107559432A61245EAA90B23C9730005FAD35D1" <>
               "CAE634F6E02BA74F630FFC4344A4CC59A72C6E8A3" = Base.encode16(prime_val_p)

      assert "FBA4A4B85E505D761A99078E4EA26B3673D8E6750447C90E324812155DE53EBDD9F6DF129" <>
               "E53DA03DCD2FDE97EA6FA3E34F0EF2338EB50383361E4B832D51BFF0BF28DBD71F95144" <>
               "F823D3711E1D8C6983D04FACD842AA7D706E69A2BB4827FAEE2319CB72C5DAA248FAFD0" <>
               "AEE4A05B39237ABAAE0C02AE2B66E7EE3988F58B3" = Base.encode16(prime_val_q)

      assert "49548DD97FC278ABDC1D67EEF641B84AD5225C34C19EB72C70FE548FD9E7CAAEF7B43013A" <>
               "BBF97C5FBE281A5C602CA7055641C7D3169B459CBB9DDE37164B17A3E7EAE7BAC3986C5" <>
               "239ED8B4E963E3C69DDDF8608DF11FBE1D2E97AE26D62B7882C045708E2BE8B684AF5F6" <>
               "EAF22450D96B244CA2873569C407AE3F9D2252428" = Base.encode16(secret_u)
    end

    test "raises error if passphrase invalid" do
      assert [
               %Packet{tag: %PacketTag{tag: {5, "Secret-Key Packet"}}} = sk_packet
               | _
             ] = OpenPGP.list_packets(@rsa2048_priv)

      assert {%SecretKeyPacket{} = sk_packet_decoded, <<>>} =
               sk_packet
               |> Util.concat_body()
               |> SecretKeyPacket.decode()

      expected_error =
        "Expected SecretKeyPacket checksum to be \"D243B4448D3EC2116BC163ED0CC4A5BD42C853EE\", got \"CF1B516FCC942C8796C20EAF2F045056835BF0CE\". Maybe incorrect passphrase?"

      assert_raise RuntimeError, expected_error, fn ->
        SecretKeyPacket.decrypt(sk_packet_decoded, "invalid")
      end
    end
  end
end
