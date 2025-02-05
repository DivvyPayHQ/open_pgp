defimpl OpenPGP.Encode, for: OpenPGP.IntegrityProtectedDataPacket do
  alias OpenPGP.IntegrityProtectedDataPacket

  def tag(_), do: {18, "Sym. Encrypted and Integrity Protected Data Packet"}

  @doc """
  Encode a Sym. Encrypted and Integrity Protected Data Packet.
  Return encoded packet body.

  ### Example:

      iex> packet = %OpenPGP.IntegrityProtectedDataPacket{ciphertext: "Ciphertext"}
      ...> OpenPGP.Encode.encode(packet)
      <<1::8, "Ciphertext">>
  """
  @version 1
  def encode(%IntegrityProtectedDataPacket{ciphertext: ciphertext}, _opts), do: <<@version::8, ciphertext::binary>>
end
