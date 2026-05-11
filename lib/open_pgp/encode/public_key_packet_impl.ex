defimpl OpenPGP.Encode, for: OpenPGP.PublicKeyPacket do
  alias OpenPGP.PublicKeyPacket
  alias OpenPGP.Util

  def tag(_), do: {6, "Public-Key Packet"}

  @doc """
  Encode Public-Key Packet.
  Return encoded packet body (version 4 only).

  ### Example:

      iex> packet = %OpenPGP.PublicKeyPacket{
      ...>   version: 4,
      ...>   created_at: ~U[2024-01-02 18:03:04Z],
      ...>   algo: {1, "RSA (Encrypt or Sign) [HAC]"},
      ...>   material: {<<0x01>>, <<0x01>>}
      ...> }
      iex> OpenPGP.Encode.encode(packet)
      <<4::8, 1704218584::32, 1::8, 0, 1, 1, 0, 1, 1>>

  """
  def encode(%PublicKeyPacket{version: 4} = packet, _opts) do
    {algo_id, _} = packet.algo
    ts = DateTime.to_unix(packet.created_at)

    encoded_material =
      for mpi <- Tuple.to_list(packet.material), reduce: "" do
        acc -> acc <> Util.encode_mpi(mpi)
      end

    <<4::8, ts::32, algo_id::8, encoded_material::binary>>
  end
end
