defmodule OpenPGP.CompressedDataPacket do
  @v05x_note """
  As of 0.5.x Compressed Data Packet supports only:

    1. ZIP-style blocks (ID: 1)
    1. ZLIB-style blocks (ID: 2)
  """

  @moduledoc """
  Represents structured data for Compressed Data Packet.

  ### Example:

      iex> alias OpenPGP.CompressedDataPacket
      iex> deflated = <<120, 156, 243, 72, 205, 201, 201, 215, 81, 8,
      ...>     207, 47, 202, 73, 81, 84, 84, 4, 0, 40, 213, 4, 172>>
      iex> CompressedDataPacket.decode(<<2, deflated::binary>>)
      {
        %CompressedDataPacket{
          algo: {2, "ZLIB [RFC1950]"},
          data_deflated: deflated,
          data_inflated: "Hello, World!!!"},
        <<>>
      }

  > NOTE: #{@v05x_note}

  ---

  ## [RFC4880](https://www.ietf.org/rfc/rfc4880.txt)

  ### 5.6.  Compressed Data Packet (Tag 8)

  The Compressed Data packet contains compressed data.  Typically, this
  packet is found as the contents of an encrypted packet, or following
  a Signature or One-Pass Signature packet, and contains a literal data
  packet.

  The body of this packet consists of:

    - One octet that gives the algorithm used to compress the packet.

    - Compressed data, which makes up the remainder of the packet.

  A Compressed Data Packet's body contains an block that compresses
  some set of packets.  See section "Packet Composition" for details on
  how messages are formed.

  ZIP-compressed packets are compressed with raw RFC 1951 [RFC1951]
  DEFLATE blocks.  Note that PGP V2.6 uses 13 bits of compression.  If
  an implementation uses more bits of compression, PGP V2.6 cannot
  decompress it.

  ZLIB-compressed packets are compressed with RFC 1950 [RFC1950] ZLIB-
  style blocks.

  BZip2-compressed packets are compressed using the BZip2 [BZ2]
  algorithm.
  """

  @behaviour OpenPGP.Packet.Behaviour

  alias OpenPGP.Util

  defstruct [:algo, :data_deflated, :data_inflated]

  @type t :: %__MODULE__{
          algo: Util.compression_algo_tuple(),
          data_deflated: bitstring(),
          data_inflated: binary()
        }

  @doc """
  Decode Compressed Data Packet given input binary.
  Return structured packet and remaining binary (empty binary).
  """
  @impl OpenPGP.Packet.Behaviour
  @spec decode(binary()) :: {t(), <<>>}
  def decode(<<algo::8, deflated::bitstring>>) do
    window_bits =
      case algo do
        1 -> -15
        2 -> 15
        other -> raise("Unsupported compression algo #{inspect(Util.compression_algo_tuple(other))}. " <> @v05x_note)
      end

    inflated = inflate(deflated, window_bits)

    packet = %__MODULE__{
      algo: Util.compression_algo_tuple(algo),
      data_deflated: deflated,
      data_inflated: inflated
    }

    {packet, <<>>}
  end

  # A negative WindowBits value makes zlib ignore the zlib header
  # (and checksum) from the stream. Notice that the zlib source mentions
  # this only as a undocumented feature.
  @max_chunks 1024
  @spec inflate(binary(), window_bits :: integer()) :: binary()
  defp inflate(deflated, window_bits) do
    z = :zlib.open()

    try do
      :zlib.inflateInit(z, window_bits)

      Enum.reduce_while(1..@max_chunks, <<>>, fn _, acc ->
        case :zlib.safeInflate(z, deflated) do
          {:continue, [chunk]} -> {:cont, acc <> chunk}
          {:finished, [chunk]} -> {:halt, acc <> chunk}
          {:finished, []} -> {:halt, acc}
        end
      end)
    after
      :zlib.close(z)
    end
  end
end
