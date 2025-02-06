defimpl OpenPGP.Encode, for: OpenPGP.Packet.BodyChunk do
  alias OpenPGP.Packet.BodyChunk

  def tag(_), do: raise(".tag/1 not supported by design for #{inspect(@for)}.")

  @doc """
  Encode body chunk. Always uses new packet format.
  Return encoded body chunk with the length header prefix.

  ### Example:

  Encodes one-octet length New Format Packet Length Header (up to 191 octets)

      iex> OpenPGP.Encode.encode(%OpenPGP.Packet.BodyChunk{data: "Hello world!"})
      <<12::8, "Hello world!">>

  Encodes two-octet length New Format Packet Length Header (192-8383 octets)

      iex> rand_bytes = :crypto.strong_rand_bytes(255)
      ...> OpenPGP.Encode.encode(%OpenPGP.Packet.BodyChunk{data: rand_bytes})
      <<192::8, 63::8, rand_bytes::binary>>

  Encodes five-octet length New Format Packet Length Header (8384-4_294_967_295 (0xFFFFFFFF) octets)

      iex> rand_bytes = :crypto.strong_rand_bytes(8384)
      ...> OpenPGP.Encode.encode(%OpenPGP.Packet.BodyChunk{data: rand_bytes})
      <<255::8, 8384::32, rand_bytes::binary>>
  """
  @one_octet_length 0..191
  @two_octet_length 192..8383
  @five_octet_length 8384..0xFFFFFFFF
  def encode(%BodyChunk{data: "" <> _ = data}, _opts) do
    blen = byte_size(data)

    hlen =
      cond do
        blen in @one_octet_length ->
          <<blen::8>>

        blen in @two_octet_length ->
          <<b1::8, b2::8>> = <<blen - 192::16>>
          <<b1 + 192::8, b2::8>>

        blen in @five_octet_length ->
          <<255::8, blen::32>>

        true ->
          raise """
          Encoding of body chunks with length greater than 0xFFFFFFFF octets is not implemented.
          Consider implementing a Partial Body Length Header.
          """
      end

    hlen <> data
  end
end
