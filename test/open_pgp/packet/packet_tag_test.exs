defmodule OpenPGP.Packet.PacketTagTest do
  use OpenPGP.Test.Case, async: true
  doctest OpenPGP.Packet.PacketTag
  doctest OpenPGP.Encode.impl_for!(%OpenPGP.Packet.PacketTag{})

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
end
