defmodule OpenPGP.Radix64Test do
  use OpenPGP.Test.Case, async: true
  doctest OpenPGP.Radix64.CRC24

  alias OpenPGP.CompressedDataPacket
  alias OpenPGP.LiteralDataPacket
  alias OpenPGP.Packet
  alias OpenPGP.Packet.PacketTag
  alias OpenPGP.PublicKeyPacket
  alias OpenPGP.Radix64
  alias OpenPGP.SecretKeyPacket

  describe ".decode/1" do
    @payload """
    -----BEGIN PGP MESSAGE-----
    Version: OpenPrivacy 0.99

    yDgBO22WxBHv7O8X7O/jygAEzol56iUKiXmV+XmpCtmpqQUKiQrFqclFqUDBovzS
    vBSFjNSiVHsuAA==
    =njUN
    -----END PGP MESSAGE-----
    """
    test "reads armored payload" do
      assert [
               %Radix64.Entry{
                 crc: <<158, 53, 13>>,
                 data: <<200, 56, 1, 59, _::binary>> = data,
                 meta: [{"Version", "OpenPrivacy 0.99"}],
                 name: "PGP MESSAGE"
               }
             ] = Radix64.decode(@payload)

      assert [
               %CompressedDataPacket{
                 algo: {1, "ZIP [RFC1951]"},
                 data_deflated: _,
                 data_inflated: data_inflated
               }
             ] = data |> OpenPGP.list_packets() |> OpenPGP.cast_packets()

      assert [
               %LiteralDataPacket{
                 created_at: ~U[1970-01-01 00:00:00Z],
                 data: "Can't anyone keep a secret around here?\n",
                 file_name: "_CONSOLE",
                 format: {"b", :binary}
               }
             ] = data_inflated |> OpenPGP.list_packets() |> OpenPGP.cast_packets()
    end

    @payload File.read!("test/fixtures/rsa2048-priv.armor.pgp")
    test "reads armored payload 2" do
      assert [
               %Radix64.Entry{
                 crc: <<243, 9, 139>>,
                 data: <<149, 3, 198, 4, 101, _::binary>> = data,
                 meta: [],
                 name: "PGP PRIVATE KEY BLOCK"
               }
             ] = Radix64.decode(@payload)

      assert [
               %SecretKeyPacket{
                 public_key: %PublicKeyPacket{
                   algo: {1, "RSA (Encrypt or Sign) [HAC]"},
                   id: <<5, 46, 131, 129, 181, 195, 53, 218>>,
                   version: 4
                 }
               },
               %Packet{tag: %PacketTag{tag: {13, "User ID Packet"}}},
               %Packet{tag: %PacketTag{tag: {2, "Signature Packet"}}},
               %OpenPGP.SecretKeyPacket{
                 public_key: %PublicKeyPacket{
                   algo: {1, "RSA (Encrypt or Sign) [HAC]"},
                   id: <<184, 5, 16, 71, 78, 123, 136, 254>>,
                   version: 4
                 }
               },
               %Packet{tag: %PacketTag{tag: {2, "Signature Packet"}}}
             ] = data |> OpenPGP.list_packets() |> OpenPGP.cast_packets()
    end
  end
end
