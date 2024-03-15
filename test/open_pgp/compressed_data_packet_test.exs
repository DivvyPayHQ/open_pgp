defmodule OpenPGP.CompressedDataPacketTest do
  use OpenPGP.Test.Case, async: true
  doctest OpenPGP.CompressedDataPacket

  alias OpenPGP.CompressedDataPacket

  @deflated <<1, 59, 109, 150, 196, 17, 239, 236, 239, 23, 236, 239, 227, 202, 0, 4, 206, 137, 121, 234, 37, 10, 137,
              121, 149, 249, 121, 169, 10, 217, 169, 169, 5, 10, 137, 10, 197, 169, 201, 69, 169, 64, 193, 162, 252,
              210, 188, 20, 133, 140, 212, 162, 84, 123, 46, 0>>
  test "inflate ZIP compressed packet" do
    assert {%OpenPGP.CompressedDataPacket{
              algo: {1, "ZIP [RFC1951]"},
              data_deflated: <<59, 109, 150, 196, 17, _::binary>>,
              data_inflated: <<203, 54, 98, 8, 95, 67, 79, 78, _::binary>>
            }, <<>>} = CompressedDataPacket.decode(@deflated)
  end

  @deflated <<2, 120, 156, 243, 72, 205, 201, 201, 215, 81, 8, 207, 47, 202, 73, 81, 84, 84, 4, 0, 40, 213, 4, 172>>
  test "inflate ZLIB compressed packet" do
    assert {
             %CompressedDataPacket{
               algo: {2, "ZLIB [RFC1950]"},
               data_deflated: <<120, 156, 243, 72, 205, _::binary>>,
               data_inflated: "Hello, World!!!"
             },
             <<>>
           } = CompressedDataPacket.decode(@deflated)
  end

  @deflated <<0, 120, 156, 243, 72, 205, 201, 201, 215, 81, 8, 207, 47, 202, 73, 81, 84, 84, 4, 0, 40, 213, 4, 172>>
  test "raises error if not supported algo (Uncompressed)" do
    assert_raise RuntimeError, ~r/Unsupported compression algo {0, "Uncompressed"}. As of 0.5.x/, fn ->
      CompressedDataPacket.decode(@deflated)
    end
  end
end
