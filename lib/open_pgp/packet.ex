defmodule OpenPGP.Packet do
  @moduledoc """
  Packet struct represents a generic packet with a packet tag and a
  body as a list of body chunks (see `OpenPGP.Packet.BodyChunk`). This
  abstraction layer operates at Packet Tag and Packet Body level only.
  To interpret the contents of a packet, the packet body should be
  decoded at another abstraction layer with packet tag-specific
  decoders, for exampe `OpenPGP.LiteralDataPacket`

  ---

  ## [RFC4880](https://www.ietf.org/rfc/rfc4880.txt)

  ### 4.1.  Overview

  An OpenPGP message is constructed from a number of records that are
  traditionally called packets.  A packet is a chunk of data that has a
  tag specifying its meaning.  An OpenPGP message, keyring,
  certificate, and so forth consists of a number of packets.  Some of
  those packets may contain other OpenPGP packets (for example, a
  compressed data packet, when uncompressed, contains OpenPGP packets).

  Each packet consists of a packet header, followed by the packet body.
  The packet header is of variable length.
  """

  @behaviour OpenPGP.Packet.Behaviour

  alias __MODULE__.BodyChunk
  alias __MODULE__.PacketTag

  defstruct [:tag, :body]

  @type t :: %__MODULE__{
          tag: PacketTag.t(),
          body: [BodyChunk.t()] | binary()
        }

  @doc """
  Decode packet given input binary.
  Return structured packet and remaining binary.
  Expect input to start with the Packet Tag octet.

  ### Example:

      iex> alias OpenPGP.Packet
      iex> alias OpenPGP.Packet.PacketTag
      iex> alias OpenPGP.Packet.BodyChunk
      iex> Packet.decode(<<1::1, 0::1, 2::4, 0::2, 7::8, "Hello, World!!!">>)
      {
        %Packet{
          tag: %PacketTag{format: :old, length_type: {0, "one-octet"}, tag: {2, "Signature Packet"}},
          body: [%BodyChunk{chunk_length: {:fixed, 7}, data: "Hello, ", header_length: 1}]
        },
        "World!!!"
      }
  """
  @impl OpenPGP.Packet.Behaviour
  @spec decode(binary()) :: {t(), binary()}
  def decode("" <> _ = input) do
    {ptag, next} = PacketTag.decode(input)
    {chunks, rest} = collect_chunks(next, ptag, [])

    packet = %__MODULE__{tag: ptag, body: chunks}

    {packet, rest}
  end

  @spec collect_chunks(input :: binary(), PacketTag.t(), acc :: [BodyChunk.t()]) ::
          {[BodyChunk.t()], rest :: binary()}
  defp collect_chunks("" <> _ = input, %PacketTag{} = ptag, acc) when is_list(acc) do
    case BodyChunk.decode(input, ptag) do
      {%BodyChunk{chunk_length: {:fixed, _}} = chunk, rest} ->
        {Enum.reverse([chunk | acc]), rest}

      {%BodyChunk{chunk_length: {:indeterminate, _}} = chunk, rest} ->
        {Enum.reverse([chunk | acc]), rest}

      {%BodyChunk{chunk_length: {:partial, _}} = chunk, rest} ->
        collect_chunks(rest, ptag, [chunk | acc])
    end
  end
end
