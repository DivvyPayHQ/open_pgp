defmodule OpenPGP.Packet.PacketTagTest do
  use OpenPGP.Test.Case, async: true
  doctest OpenPGP.Packet.PacketTag

  alias OpenPGP.Packet.PacketTag

  describe ".decode/1" do
    test "decodes old packet format" do
      assert {%PacketTag{
                format: :old,
                tag: {5, "Secret-Key Packet"},
                length_type: {1, "two-octet"}
              }, ""} = PacketTag.decode(<<1::1, 0::1, 5::4, 1::2>>)
    end

    test "decodes new packet format" do
      assert {%PacketTag{
                format: :new,
                tag: {5, "Secret-Key Packet"},
                length_type: nil
              }, ""} = PacketTag.decode(<<1::1, 1::1, 5::6>>)
    end
  end

  describe ".encode/1" do
    test "encodes new packet format with integer" do
      assert <<1::1, 1::1, 1::6>> = PacketTag.encode(1)
    end

    test "encodes new packet format with tuple" do
      assert <<1::1, 1::1, 1::6>> = PacketTag.encode({1, "Public-Key Encrypted Session Key Packet"})
    end
  end
end
