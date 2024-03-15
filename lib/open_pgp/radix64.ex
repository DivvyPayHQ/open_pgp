defmodule OpenPGP.Radix64 do
  @moduledoc """
  Radix64 decoder, as per [RFC4880](https://www.ietf.org/rfc/rfc4880.txt)
  """

  alias OpenPGP.Radix64.CRC24
  alias OpenPGP.Radix64.Entry

  @spec decode(binary()) :: [Entry.t()]
  def decode("" <> _ = input) do
    input
    |> String.split("\n")
    |> Stream.chunk_while(%Entry{}, &chunk_fun/2, &after_fun/1)
    |> Enum.to_list()
  end

  @spec chunk_fun(binary(), Entry.t()) :: {:cont, Entry.t()} | {:cont, Entry.t(), Entry.t()}
  @header_lines [
    "PGP MESSAGE",
    "PGP PUBLIC KEY BLOCK",
    "PGP PRIVATE KEY BLOCK",
    "PGP SIGNATURE"
    # "PGP MESSAGE, PART X/Y"
    # "PGP MESSAGE, PART X"
  ]
  for hline <- @header_lines do
    defp chunk_fun("-----BEGIN #{unquote(hline)}-----" <> _, %Entry{}) do
      {:cont, %Entry{name: unquote(hline), data: <<>>}}
    end

    defp chunk_fun("-----END #{unquote(hline)}-----" <> _, %Entry{name: unquote(hline)} = entry) do
      {:cont, validate_checksum!(%{entry | data: Base.decode64!(entry.data)}), %Entry{}}
    end
  end

  @meta_keys ~w[Version Comment MessageID Hash Charset]
  for key <- @meta_keys do
    defp chunk_fun(unquote(key) <> ": " <> meta_value, %Entry{} = entry) do
      {:cont, %{entry | meta: [{unquote(key), String.trim(meta_value)} | entry.meta]}}
    end
  end

  defp chunk_fun("=" <> crc, %Entry{} = entry) do
    {:cont, %{entry | crc: Base.decode64!(String.trim(crc))}}
  end

  defp chunk_fun("" <> _ = line, %Entry{} = entry) do
    {:cont, %{entry | data: entry.data <> String.trim(line)}}
  end

  @spec after_fun(Entry.t()) :: {:cont, Entry.t()}
  defp after_fun(%Entry{name: nil, meta: [], data: <<>>} = entry), do: {:cont, entry}
  defp after_fun(%Entry{} = entry), do: raise("Nonempty state: #{inspect(entry)}")

  @spec validate_checksum!(Entry.t()) :: Entry.t()
  defp validate_checksum!(%Entry{} = entry) do
    actual_crc = CRC24.calc(entry.data)

    if actual_crc != entry.crc do
      msg =
        "CRC24 checksum for entry #{inspect(entry.name)} does not match. " <>
          "Expected #{inspect(entry.crc)}, got #{inspect(actual_crc)}."

      raise(msg)
    else
      entry
    end
  end
end
