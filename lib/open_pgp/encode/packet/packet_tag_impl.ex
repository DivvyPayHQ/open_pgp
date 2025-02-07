defimpl OpenPGP.Encode, for: OpenPGP.Packet.PacketTag do
  alias OpenPGP.Packet.PacketTag

  def tag(_), do: raise(".tag/1 of protocol #{inspect(@protocol)} not supported by design for #{inspect(@for)}.")

  @doc """
  Encode packet tag. Always uses new packet format.
  Return encoded packet tag octet.

  ### Example:

      iex> ptag = %OpenPGP.Packet.PacketTag{format: :new, tag: {1, "Public-Key Encrypted Session Key Packet"}}
      ...> OpenPGP.Encode.encode(ptag)
      <<1::1, 1::1, 1::6>>

      iex> ptag = %OpenPGP.Packet.PacketTag{format: :new, tag: {2, "Signature Packet"}}
      ...> OpenPGP.Encode.encode(ptag)
      <<1::1, 1::1, 2::6>>
  """
  def encode(%PacketTag{format: :new, tag: {tag_id, _desc}}, _opts) when is_integer(tag_id) and tag_id in 0..63 do
    <<1::1, 1::1, tag_id::6>>
  end
end
