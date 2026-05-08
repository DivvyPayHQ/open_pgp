defimpl OpenPGP.Encode, for: OpenPGP.UserIdPacket do
  def tag(_), do: {13, "User ID Packet"}

  @doc """
  Encode User ID Packet.
  Return encoded packet body (the UTF-8 User ID string).

  ### Example:

      iex> OpenPGP.Encode.encode(%OpenPGP.UserIdPacket{id: "Alice <alice@example.com>"})
      "Alice <alice@example.com>"

  """
  def encode(%OpenPGP.UserIdPacket{id: id}, _opts), do: id
end
