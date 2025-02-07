defimpl OpenPGP.Encode, for: OpenPGP.LiteralDataPacket do
  alias OpenPGP.LiteralDataPacket

  def tag(_), do: {11, "Literal Data Packet"}

  @format_map %{
    binary: <<0x62::8>>,
    text: <<0x74::8>>,
    text_utf8: <<0x75::8>>
  }
  @formats Map.keys(@format_map)

  @doc """
  Encode Literal Data Packet.
  Return encoded packet body.

  ### Example:

      iex> packet = %OpenPGP.LiteralDataPacket{
      ...>            format: :binary, 
      ...>            file_name: "file.txt", 
      ...>            created_at: ~U[2022-02-24 02:30:00Z],
      ...>            data: "Hello"
      ...>          }
      ...> OpenPGP.Encode.encode(packet)
      <<0x62, 8, "file.txt", 1645669800::32, "Hello">>

  """
  def encode(%LiteralDataPacket{data: "" <> _ = data} = packet, _opts) do
    format = packet.format || :binary

    format_byte =
      Map.get(@format_map, format) ||
        raise """
        Unknown Literal Data Packet format: #{inspect(packet.format)}.
        Known formats: #{inspect(@formats)}
        """

    fname_string =
      case packet.file_name do
        fname when is_binary(fname) and byte_size(fname) > 0 -> <<byte_size(fname)::8, fname::binary>>
        nil -> <<0::8>>
      end

    timestamp =
      case packet.created_at do
        %DateTime{} = date -> DateTime.to_unix(date)
        nil -> System.os_time(:second)
      end

    <<format_byte::binary, fname_string::binary, timestamp::32, data::binary>>
  end
end
