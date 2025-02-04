defmodule OpenPGP.ModificationDetectionCodePacketTest do
  use OpenPGP.Test.Case, async: true
  doctest OpenPGP.ModificationDetectionCodePacket

  alias OpenPGP.ModificationDetectionCodePacket

  describe ".validate!/2" do
    @mdc_header <<0xD3, 0x14>>
    test "returns :ok if SHA-1 match" do
      sha = :crypto.hash(:sha, "Hello!" <> @mdc_header)
      assert {"Hello!", ^sha} = ModificationDetectionCodePacket.validate!("Hello!" <> @mdc_header <> sha)
    end

    @expected_error "Failed to verify Modification Detection Code SHA-1: " <>
                      "expected <<0x18, 0x7C, 0xC0, 0xEE, 0x16, 0x5E, 0xDB, 0x92, 0x49, 0x3, 0xDC, 0x91, 0x82, 0x2, 0xB8, 0x3C, 0xF5, 0xE3, 0x2C, 0x11>>, " <>
                      "got <<0xCC, 0x63, 0x18, 0xDF, 0xBE, 0x6F, 0x4F, 0xAE, 0x27, 0xEA, 0xE, 0x74, 0x12, 0xFD, 0x60, 0x2, 0x49, 0x6, 0x42, 0xF4>>."
    test "raises error if SHA-1 does not match" do
      sha = :crypto.hash(:sha, "Hello!" <> @mdc_header)

      assert_raise RuntimeError, @expected_error, fn ->
        ModificationDetectionCodePacket.validate!("Bye!" <> @mdc_header <> sha)
      end
    end

    @expected_error "Failed to parse Modification Detection Code Packet."
    test "raises error if no Modification Detection Code packet" do
      assert_raise RuntimeError, @expected_error, fn ->
        ModificationDetectionCodePacket.validate!("Bye!")
      end
    end
  end
end
