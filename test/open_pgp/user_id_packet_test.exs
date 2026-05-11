defmodule OpenPGP.UserIdPacketTest do
  use OpenPGP.Test.Case, async: true
  doctest OpenPGP.UserIdPacket
  doctest OpenPGP.Encode.impl_for!(%OpenPGP.UserIdPacket{})

  alias OpenPGP.Encode
  alias OpenPGP.UserIdPacket

  test "decode/1 returns the input as id with empty remainder" do
    assert {%UserIdPacket{id: "John Doe <john@example.com>"}, <<>>} =
             UserIdPacket.decode("John Doe <john@example.com>")
  end

  test "cast_packets casts Tag 13 to UserIdPacket" do
    message = File.read!("test/fixtures/rsa2048-priv.pgp")
    [_sk, uid_pkt | _] = OpenPGP.list_packets(message)

    assert [%UserIdPacket{id: "John Doe (RSA2048) <john.doe@example.com>"}] = OpenPGP.cast_packets([uid_pkt])
  end

  describe "OpenPGP.Encode.encode/1,2" do
    test "encode/2 returns the id binary" do
      packet = %UserIdPacket{id: "Alice <alice@example.com>"}
      assert Encode.encode(packet) == "Alice <alice@example.com>"
    end

    test "tag/1 returns packet tag 13" do
      packet = %UserIdPacket{id: "Alice <alice@example.com>"}
      assert {13, "User ID Packet"} == Encode.tag(packet)
    end
  end
end
