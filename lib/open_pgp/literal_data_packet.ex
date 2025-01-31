defmodule OpenPGP.LiteralDataPacket do
  @moduledoc """
  Represents structured data for Literal Data Packet.

  ### Example:

      iex> alias OpenPGP.LiteralDataPacket
      ...> data = <<0x62, 11, "example.txt", 1704328052::32, "Hello!">>
      ...> LiteralDataPacket.decode(data)
      {
        %LiteralDataPacket{
          created_at: ~U[2024-01-04 00:27:32Z],
          data: "Hello!",
          file_name: "example.txt",
          format: {<<0x62>>, :binary}
        },
        <<>>
      }

  ---

  ## [RFC4880](https://www.ietf.org/rfc/rfc4880.txt)

  ### 5.9.  Literal Data Packet (Tag 11)

  A Literal Data packet contains the body of a message; data that is
  not to be further interpreted.

  The body of this packet consists of:

    - A one-octet field that describes how the data is formatted.

  If it is a 'b' (0x62), then the Literal packet contains binary data.
  If it is a 't' (0x74), then it contains text data, and thus may need
  line ends converted to local form, or other text-mode changes.  The
  tag 'u' (0x75) means the same as 't', but also indicates that
  implementation believes that the literal data contains UTF-8 text.

  Early versions of PGP also defined a value of 'l' as a 'local' mode
  for machine-local conversions.  RFC 1991 [RFC1991] incorrectly stated
  this local mode flag as '1' (ASCII numeral one).  Both of these local
  modes are deprecated.

    - File name as a string (one-octet length, followed by a file
      name).  This may be a zero-length string.  Commonly, if the
      source of the encrypted data is a file, this will be the name of
      the encrypted file.  An implementation MAY consider the file name
      in the Literal packet to be a more authoritative name than the
      actual file name.

  If the special name "_CONSOLE" is used, the message is considered to
  be "for your eyes only".  This advises that the message data is
  unusually sensitive, and the receiving program should process it more
  carefully, perhaps avoiding storing the received data to disk, for
  example.

    - A four-octet number that indicates a date associated with the
      literal data.  Commonly, the date might be the modification date
      of a file, or the time the packet was created, or a zero that
      indicates no specific time.

    - The remainder of the packet is literal data.

      Text data is stored with <CR><LF> text endings (i.e., network-
      normal line endings).  These should be converted to native line
      endings by the receiving software.
  """

  @behaviour OpenPGP.Packet.Behaviour

  defstruct [:format, :file_name, :created_at, :data]

  @type t :: %__MODULE__{
          created_at: DateTime.t(),
          data: binary(),
          file_name: binary(),
          format: {<<_::8>>, :binary | :text | :text_utf8}
        }

  @formats %{
    <<0x62::8>> => :binary,
    <<0x74::8>> => :text,
    <<0x75::8>> => :text_utf8
  }
  @format_ids Map.keys(@formats)

  @doc """
  Decode Literal Data Packet given input binary.
  Return structured packet and remaining binary (empty binary).
  """
  @impl OpenPGP.Packet.Behaviour
  @spec decode(binary()) :: {t(), <<>>}
  def decode(<<format::bytes-size(1), fname_len::8, next::binary>>) when format in @format_ids do
    <<fname::bytes-size(fname_len), timestamp::32, data::binary>> = next

    created_at = DateTime.from_unix!(timestamp)

    packet = %__MODULE__{
      format: {format, @formats[format]},
      file_name: fname,
      created_at: created_at,
      data: data
    }

    {packet, ""}
  end

  @doc "See `encode/2`"
  @spec encode(data :: binary()) :: binary()
  def encode("" <> _ = data), do: encode(data, [])

  @doc """
  Encode Literal Data Packet given input binary.
  Return encoded binary.

  Options:

  - `:format` - describes how the encoded data is formatted. Valid values - `:binary`, `:text`, `:text_utf8`. Default: `:binary`
  - `:file_name` - the name of the encrypted file. Default: `nil`
  - `:created_at` - the date and time associated with the data. Default: `System.os_time(:second)`
  """
  @spec encode(data :: binary(), opts :: Keyword.t()) :: binary()
  def encode("" <> _ = data, opts) do
    formats = Map.new(@formats, fn {k, v} -> {v, k} end)
    format = Keyword.get(opts, :format, :binary)

    format_byte =
      Map.get(formats, format) ||
        raise """
        Unknown Literal Data Packet format: #{inspect(format)}.
        Known formats: #{inspect(Map.keys(formats))}
        """

    fname_string =
      case Keyword.get(opts, :file_name) do
        fname when is_binary(fname) and byte_size(fname) > 0 -> <<byte_size(fname)::8, fname::binary>>
        _ -> <<0::8>>
      end

    timestamp =
      case Keyword.get(opts, :created_at) do
        %DateTime{} = date -> DateTime.to_unix(date)
        nil -> System.os_time(:second)
      end

    <<format_byte::binary, fname_string::binary, timestamp::32, data::binary>>
  end
end
