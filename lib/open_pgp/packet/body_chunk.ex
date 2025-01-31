defmodule OpenPGP.Packet.BodyChunk do
  @moduledoc """
  Packet data is represented as a list of body chunks. Each body
  chunk includes chunk length header information and chunk data.

  Most of the packets will have only one body chunk. Only packets with
  Partial Body Length expected to have more than one body chunk.

  The `OpenPGP.Util.concat_body/1` can be applied to a packet body or a
  list of body chunks to concatenate chunks into a binary to be further
  interpreted.
  ---

  ## [RFC4880](https://www.ietf.org/rfc/rfc4880.txt)

  #### 4.2.1.  Old Format Packet Lengths

  The meaning of the length-type in old format packets is:

  0 - The packet has a one-octet length.  The header is 2 octets long.

  1 - The packet has a two-octet length.  The header is 3 octets long.

  2 - The packet has a four-octet length.  The header is 5 octets long.

  3 - The packet is of indeterminate length.  The header is 1 octet
      long, and the implementation must determine how long the packet
      is.  If the packet is in a file, this means that the packet
      extends until the end of the file.  In general, an implementation
      SHOULD NOT use indeterminate-length packets except where the end
      of the data will be clear from the context, and even then it is
      better to use a definite length, or a new format header.  The new
      format headers described below have a mechanism for precisely
      encoding data of indeterminate length.

  ### 4.2.2.  New Format Packet Lengths

  New format packets have four possible ways of encoding length:

  1. A one-octet Body Length header encodes packet lengths of up to 191
    octets.

  2. A two-octet Body Length header encodes packet lengths of 192 to
    8383 octets.

  3. A five-octet Body Length header encodes packet lengths of up to
    4,294,967,295 (0xFFFFFFFF) octets in length.  (This actually
    encodes a four-octet scalar number.)

  4. When the length of the packet body is not known in advance by the
    issuer, Partial Body Length headers encode a packet of
    indeterminate length, effectively making it a stream.

  #### 4.2.2.1.  One-Octet Lengths

  A one-octet Body Length header encodes a length of 0 to 191 octets.
  This type of length header is recognized because the one octet value
  is less than 192.  The body length is equal to:

      bodyLen = 1st_octet;

  #### 4.2.2.2.  Two-Octet Lengths

  A two-octet Body Length header encodes a length of 192 to 8383
  octets.  It is recognized because its first octet is in the range 192
  to 223.  The body length is equal to:

      bodyLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192

  #### 4.2.2.3.  Five-Octet Lengths

  A five-octet Body Length header consists of a single octet holding
  the value 255, followed by a four-octet scalar.  The body length is
  equal to:

      bodyLen = (2nd_octet << 24) | (3rd_octet << 16) |
                (4th_octet << 8)  | 5th_octet

  This basic set of one, two, and five-octet lengths is also used
  internally to some packets.

  #### 4.2.2.4.  Partial Body Lengths

  A Partial Body Length header is one octet long and encodes the length
  of only part of the data packet.  This length is a power of 2, from 1
  to 1,073,741,824 (2 to the 30th power).  It is recognized by its one
  octet value that is greater than or equal to 224, and less than 255.
  The Partial Body Length is equal to:

      partialBodyLen = 1 << (1st_octet & 0x1F);

  Each Partial Body Length header is followed by a portion of the
  packet body data.  The Partial Body Length header specifies this
  portion's length.  Another length header (one octet, two-octet,
  five-octet, or partial) follows that portion.  The last length header
  in the packet MUST NOT be a Partial Body Length header.  Partial Body
  Length headers may only be used for the non-final parts of the
  packet.

  Note also that the last Body Length header can be a zero-length
  header.

  An implementation MAY use Partial Body Lengths for data packets, be
  they literal, compressed, or encrypted.  The first partial length
  MUST be at least 512 octets long.  Partial Body Lengths MUST NOT be
  used for any other packet types.
  """

  import Bitwise
  alias OpenPGP.Packet.PacketTag, as: PTag

  defstruct [:data, :header_length, :chunk_length]

  @type t :: %__MODULE__{
          header_length: header_length(),
          chunk_length: chunk_length(),
          data: binary()
        }
  @typedoc "The packet has a N-octet length header."
  @type header_length :: non_neg_integer()

  @typedoc "Chunk length in octets (bytes). Payload size."
  @type chunk_length :: {:fixed | :partial | :indeterminate, non_neg_integer()}

  @doc """
  Decode body chunk given input binary and packet tag.
  Return structured body chunk and remaining binary.
  Expect input to start with Body Length header octets.

  ### Example:

      iex> alias OpenPGP.Packet.{BodyChunk, PacketTag}
      iex> BodyChunk.decode(<<5, "Hello", " world!">>, %PacketTag{format: :old, length_type: {0, "one-octet"}})
      {%BodyChunk{data: "Hello", header_length: 1, chunk_length: {:fixed, 5}}, " world!"}
  """
  @spec decode(input :: binary(), PTag.t()) :: {t(), rest :: binary()}
  def decode("" <> _ = input, %PTag{} = ptag) do
    {header_length, {_, blen} = chunk_length, next} = length_header(input, ptag)

    <<data::bytes-size(blen), rest::binary>> = next
    chunk = %__MODULE__{data: data, header_length: header_length, chunk_length: chunk_length}

    {chunk, rest}
  end

  @doc """
  Encode body chunk given input binary. Always uses new packet format.
  Return encoded body chunk with the length header prefix.
  """
  @spec encode(input :: binary()) :: binary()
  def encode("" <> _ = input) do
    blen = byte_size(input)

    hlen =
      cond do
        blen in 0..191 ->
          <<blen::8>>

        blen in 192..8383 ->
          <<b1::8, b2::8>> = <<blen - 192::16>>
          <<b1 + 192::8, b2::8>>

        blen in 8384..0xFFFFFFFF ->
          <<255::8, blen::32>>

        true ->
          raise """
          Encoding of body chunks with length greater than 0xFFFFFFFF octets is not implemented.
          Consider implementing a Partial Body Length Header.
          """
      end

    hlen <> input
  end

  @spec length_header(data :: binary(), PTag.t()) ::
          {header_length(), chunk_length(), rest :: binary()}
  defp length_header(<<blength::8, rest::binary>>, %PTag{format: :old, length_type: {0, _}}) do
    {1, {:fixed, blength}, rest}
  end

  defp length_header(<<blength::16, rest::binary>>, %PTag{format: :old, length_type: {1, _}}) do
    {2, {:fixed, blength}, rest}
  end

  defp length_header(<<blength::32, rest::binary>>, %PTag{format: :old, length_type: {2, _}}) do
    {4, {:fixed, blength}, rest}
  end

  defp length_header(<<rest::binary>>, %PTag{format: :old, length_type: {3, _}}) do
    {0, {:indeterminate, byte_size(rest)}, rest}
  end

  defp length_header(<<blength::8, rest::binary>>, %PTag{format: :new}) when blength < 192 do
    {1, {:fixed, blength}, rest}
  end

  defp length_header(<<b1::8, b2::8, rest::binary>>, %PTag{format: :new}) when b1 in 192..223 do
    blength = ((b1 - 192) <<< 8) + b2 + 192
    {2, {:fixed, blength}, rest}
  end

  defp length_header(<<255::8, blength::32, rest::binary>>, %PTag{format: :new}) do
    {5, {:fixed, blength}, rest}
  end

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
  defp length_header(<<b1::8, rest::binary>>, %PTag{format: :new}) when b1 in 224..254 do
    plength = 1 <<< (b1 &&& 0x1F)
    {1, {:partial, plength}, rest}
  end
end
