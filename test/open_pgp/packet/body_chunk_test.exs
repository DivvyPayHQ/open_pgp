defmodule OpenPGP.Packet.BodyChunkTest do
  use OpenPGP.Test.Case, async: true
  doctest OpenPGP.Packet.BodyChunk

  alias OpenPGP.Packet.BodyChunk, as: BChunk
  alias OpenPGP.Packet.PacketTag, as: PacketTag

  describe ".decode/2" do
    test "decodes one-octet length Old Format Packet Length Header" do
      packet_tag = %PacketTag{format: :old, length_type: {0, "one-octet"}}
      input = <<5::8, "Hello world!">>

      assert {%BChunk{data: "Hello", header_length: 1, chunk_length: {:fixed, 5}}, " world!"} =
               BChunk.decode(input, packet_tag)
    end

    test "decodes two-octet length Old Format Packet Length Header" do
      # We want two octets body length: 255 + 5 = 260
      # Generate 255 random octets and prepend with "Hello world!"

      packet_tag = %PacketTag{format: :old, length_type: {1, "two-octet"}}
      rand_bytes = :crypto.strong_rand_bytes(255)
      input = <<260::16, "Hello world!", rand_bytes::binary>>

      assert {%BChunk{data: data, header_length: 2, chunk_length: {:fixed, blen}}, rest} =
               BChunk.decode(input, packet_tag)

      assert blen == 260
      assert byte_size(data) == 260
      assert "Hello world!" <> pt1 = data
      assert pt1 <> rest == rand_bytes
    end

    test "decodes four-octet length Old Format Packet Length Header" do
      # We want four octets body length: (0xFF << 24) + (0xFF << 16) + (0xFF << 8) + 0x05= 0xFFFFFF05
      # It does not make sense to generate 0xFFFFFF05 random octets in test due to limited memory (~4Gb)
      # In general BodyChunk should blindly trust :chunk_length property, and take that many bytes.
      # As long as we use 4 octets to encode the chunk length, i.e. <<260::32>>

      packet_tag = %PacketTag{format: :old, length_type: {2, "four-octet"}}
      rand_bytes = :crypto.strong_rand_bytes(255)
      input = <<260::32, "Hello world!", rand_bytes::binary>>

      assert {%BChunk{data: data, header_length: 4, chunk_length: {:fixed, blen}}, rest} =
               BChunk.decode(input, packet_tag)

      assert blen == 260
      assert byte_size(data) == 260
      assert "Hello world!" <> pt1 = data
      assert pt1 <> rest == rand_bytes
    end

    test "decodes indeterminate length Old Format Packet Length Header" do
      # Per RFC 4880:
      # If the packet is in a file, this means that the packet extends until
      # the end of the file.
      # For test we will use five-octets long body.

      packet_tag = %PacketTag{format: :old, length_type: {3, "indeterminate"}}
      input = "Hello world!"

      assert {%BChunk{data: data, header_length: 0, chunk_length: {:indeterminate, blen}}, rest} =
               BChunk.decode(input, packet_tag)

      assert blen == byte_size(input)
      assert "Hello world!" = data
      assert "" = rest
    end

    test "decodes one-octet length New Format Packet Length Header (up to 191 octets)" do
      # Per RFC4880:
      # A one-octet Body Length header encodes a length of 0 to 191 octets.
      # This type of length header is recognized because the one octet value
      # is less than 192.  The body length is equal to:

      #     bodyLen = 1st_octet;

      packet_tag = %PacketTag{format: :new}
      input = <<5::8, "Hello world!">>

      assert {%BChunk{data: "Hello", header_length: 1, chunk_length: {:fixed, 5}}, " world!"} =
               BChunk.decode(input, packet_tag)
    end

    test "decodes two-octet length New Format Packet Length Header (192-8383 octets)" do
      # Per RFC4880:
      # A two-octet Body Length header encodes a length of 192 to 8383
      # octets.  It is recognized because its first octet is in the range 192
      # to 223.  The body length is equal to:
      #
      #     bodyLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192

      # We want two octets body length: ((192 - 192) << 8) + (68) + 192 = 260
      # That should be encoded as: <<192::8, 68::8>>

      packet_tag = %PacketTag{format: :new}
      rand_bytes = :crypto.strong_rand_bytes(255)
      input = <<192::8, 68::8, "Hello world!", rand_bytes::binary>>

      assert {%BChunk{data: data, header_length: 2, chunk_length: {:fixed, blen}}, rest} =
               BChunk.decode(input, packet_tag)

      assert blen == 260
      assert byte_size(data) == 260
      assert "Hello world!" <> pt1 = data
      assert pt1 <> rest == rand_bytes
    end

    test "decodes five-octet length New Format Packet Length Header (up to 4,294,967,295 octets)" do
      # Per RFC4880:
      # A five-octet Body Length header consists of a single octet holding
      # the value 255, followed by a four-octet scalar.  The body length is
      # equal to:

      #     bodyLen = (2nd_octet << 24) | (3rd_octet << 16) |
      #               (4th_octet << 8)  | 5th_octet

      # We want encode 260 in five octets as <<255::8, 0::8, 0::8, 260::16>>

      packet_tag = %PacketTag{format: :new}
      rand_bytes = :crypto.strong_rand_bytes(255)
      input = <<255::8, 0::8, 0::8, 260::16, "Hello world!", rand_bytes::binary>>

      assert {%BChunk{data: data, header_length: 5, chunk_length: {:fixed, blen}}, rest} =
               BChunk.decode(input, packet_tag)

      assert blen == 260
      assert byte_size(data) == 260
      assert "Hello world!" <> pt1 = data
      assert pt1 <> rest == rand_bytes
    end

    test "decodes partial body length New Format Packet Length Header (2 to the 30th power)" do
      # Per RFC4880:
      # A Partial Body Length header is one octet long and encodes the length
      # of only part of the data packet.  This length is a power of 2, from 1
      # to 1,073,741,824 (2 to the 30th power).  It is recognized by its one
      # octet value that is greater than or equal to 224, and less than 255.
      # The Partial Body Length is equal to:

      #     partialBodyLen = 1 << (1st_octet & 0x1F);

      # To understand this case, we need to look at 224-255 on a bit level:

      # 0x1F = 0b00011111
      # 224  = 0b11100000
      # 254  = 0b11111110 (255 is taken by five-octet length header)

      # The partial length header has all ones in the three most significant bits.
      # Then, whatever number we have in the five least significant bits will be
      # the power of two, according to the formula `1 << (1st_octet & 0x1F)`.

      # Example:

      # The encoded body length of 64 (2**6) in one octet partial length header on
      # a bit level will be <<0b11100110::8>> (which is 230).
      # To verify: `1 << (230 & 0x1F) = 64`

      packet_tag = %PacketTag{format: :new}
      rand_bytes = :crypto.strong_rand_bytes(255)
      input = <<0b11100110::8, "Hello world!", rand_bytes::binary>>

      assert {%BChunk{data: data, header_length: 1, chunk_length: {:partial, blen}}, rest} =
               BChunk.decode(input, packet_tag)

      assert blen == 64
      assert byte_size(data) == 64
      assert "Hello world!" <> pt1 = data
      assert pt1 <> rest == rand_bytes
    end
  end
end
