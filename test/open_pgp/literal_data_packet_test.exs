defmodule OpenPGP.LiteralDataPacketTest do
  use OpenPGP.Test.Case, async: true
  doctest OpenPGP.LiteralDataPacket

  alias OpenPGP.LiteralDataPacket

  describe ".encode/2" do
    test "encode plaintext with default opts" do
      assert <<0x62, 0, unix_ts::32, "Hello">> = LiteralDataPacket.encode("Hello")
      assert_in_delta unix_ts, System.os_time(:second), 2
    end

    test "encode plaintext and set file name" do
      assert <<0x62, 8, "file.txt", _::32, "Hello">> = LiteralDataPacket.encode("Hello", file_name: "file.txt")
    end

    @ts 1_704_328_052
    test "encode plaintext and set timestamp" do
      assert <<0x62, 0, @ts::32, "Hello">> = LiteralDataPacket.encode("Hello", created_at: DateTime.from_unix!(@ts))
    end

    test "encode plaintext and set format" do
      assert <<0x62, 0, _::32, "Hello">> = LiteralDataPacket.encode("Hello", format: :binary)
      assert <<0x74, 0, _::32, "Hello">> = LiteralDataPacket.encode("Hello", format: :text)
      assert <<0x75, 0, _::32, "Hello">> = LiteralDataPacket.encode("Hello", format: :text_utf8)
    end

    @expected_error """
    Unknown Literal Data Packet format: :invalid.
    Known formats: [:binary, :text, :text_utf8]
    """
    test "raise when format not valid" do
      assert_raise RuntimeError, @expected_error, fn ->
        LiteralDataPacket.encode("Hello", format: :invalid)
      end
    end
  end
end
