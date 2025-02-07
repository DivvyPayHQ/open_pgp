defmodule OpenPGP.LiteralDataPacketTest do
  use OpenPGP.Test.Case, async: true
  doctest OpenPGP.LiteralDataPacket
  doctest OpenPGP.Encode.impl_for!(%OpenPGP.LiteralDataPacket{})

  alias OpenPGP.Encode
  alias OpenPGP.LiteralDataPacket

  describe "OpenPGP.Encode.encode/1,2" do
    test "encode plaintext with default opts" do
      packet = %LiteralDataPacket{data: "Hello"}
      assert <<0x62, 0, unix_ts::32, "Hello">> = Encode.encode(packet)
      assert_in_delta unix_ts, System.os_time(:second), 2
    end

    test "encode plaintext and set file name" do
      packet = %LiteralDataPacket{file_name: "file.txt", data: "Hello"}
      assert <<0x62, 8, "file.txt", _::32, "Hello">> = Encode.encode(packet)
    end

    @ts 1_704_328_052
    test "encode plaintext and set timestamp" do
      packet = %LiteralDataPacket{data: "Hello", created_at: DateTime.from_unix!(@ts)}
      assert <<0x62, 0, @ts::32, "Hello">> = Encode.encode(packet)
    end

    test "encode plaintext and set format" do
      assert <<0x62, 0, _::32, "Hello">> = Encode.encode(%LiteralDataPacket{data: "Hello", format: :binary})
      assert <<0x74, 0, _::32, "Hello">> = Encode.encode(%LiteralDataPacket{data: "Hello", format: :text})
      assert <<0x75, 0, _::32, "Hello">> = Encode.encode(%LiteralDataPacket{data: "Hello", format: :text_utf8})
    end

    @expected_error """
    Unknown Literal Data Packet format: :invalid.
    Known formats: [:binary, :text, :text_utf8]
    """
    test "raise when format not valid" do
      assert_raise RuntimeError, @expected_error, fn ->
        Encode.encode(%LiteralDataPacket{data: "Hello", format: :invalid})
      end
    end
  end
end
