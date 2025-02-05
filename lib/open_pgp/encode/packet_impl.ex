defimpl OpenPGP.Encode, for: OpenPGP.Packet do
  alias OpenPGP.Packet
  alias OpenPGP.Packet.BodyChunk

  def tag(_), do: raise(".tag/1 not supported by design for #{inspect(@for)}.")

  @doc """
  Encode a Packet.
  Return encoded packet binary - a packet header, followed by the packet body.

  ### Example:

      iex> ptag = %OpenPGP.Packet.PacketTag{format: :new, tag: {11, "Literal Data Packet"}}
      ...> OpenPGP.Encode.encode(%OpenPGP.Packet{tag: ptag, body: "Hello, World!!!"})
      <<1::1, 1::1, 11::6, 15::8, "Hello, World!!!">>
  """
  def encode(%Packet{} = packet, _opts) do
    encoded_body =
      case packet.body do
        nil -> <<0::8>>
        [] -> <<0::8>>
        "" <> _ = body -> @protocol.encode(%BodyChunk{data: body}, [])
        [%BodyChunk{} | _] = chunks -> Enum.reduce(chunks, "", fn chunk, acc -> acc <> @protocol.encode(chunk) end)
      end

    @protocol.encode(packet.tag) <> encoded_body
  end
end
