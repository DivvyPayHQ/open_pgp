defmodule OpenPGP do
  @v05x_note """
  As of 0.5.x subset of RFC4880 Packet Tags can be casted. Other Packet
  tags remain as %Packet{} (not casted). Should not be considered as
  error.
  """

  @moduledoc """
  OpenPGP lib allows to inspect, decode and decrypt OpenPGP Message
  Format as per [RFC4880](https://www.ietf.org/rfc/rfc4880.txt)

  As of v0.5.x:

    1. Any valid OpenPGP message can be decoded via generic
       `OpenPGP.Packet` decoder. This abstraction layer provide Packet
       Tags and Body Chunks for packet envelope level evaluation.
    1. Some Packet Tag specific decoders implemented with limited
       feature support:
        1. `OpenPGP.LiteralDataPacket`
        1. `OpenPGP.PublicKeyEncryptedSessionKeyPacket`
        1. `OpenPGP.PublicKeyPacket` - support only V4 packets
        1. `OpenPGP.SecretKeyPacket` - support only V4 packets; Iterated
            and Salted String-to-Key (S2K) specifier (ID: 3); S2K usage
            convention octet of 254 only; S2K hashing algo SHA1; AES128
            symmetric encryption of secret key material
        1. `OpenPGP.CompressedDataPacket` - support only ZLIB- and ZIP-
            style blocks
        1. `OpenPGP.IntegrityProtectedDataPacket` - support Session Key
            algo 9 (AES with 256-bit key) in CFB mode; Modification
            Detection Code system is not supported

  At a high level `OpenPGP.list_packets/1` and `OpenPGP.cast_packets/1`
  serve as an entrypoint to OpenPGP Message decoding and extracting
  generic data. Packet specific decoders implement
  `OpenPGP.Packet.Behaviour`, which exposes `.decode/1` interface
  (including genric `OpenPGP.Packet`). Additionaly some of the packet
  specific decoders may provide interface for further packet processing,
  such as `OpenPGP.SecretKeyPacket.decrypt/2`.

  ### Examples:

  Decode message packets and then cast

      iex> message = <<160, 24, 2, 120, 156, 243, 72, 205, 201, 201, 215, 81, 8, 207, 47, 202, 73,
      ...>     81, 84, 84, 4, 0, 40, 213, 4, 172>>
      ...>
      iex> packets = OpenPGP.list_packets(message)
      [
        %OpenPGP.Packet{
          body: [
            %OpenPGP.Packet.BodyChunk{
              chunk_length: {:fixed, 24},
              data: <<2, 120, 156, 243, 72, 205, 201, 201, 215, 81, 8, 207, 47, 202, 73, 81, 84,
                  84, 4, 0, 40, 213, 4, 172>>,
              header_length: 1
            }
          ],
          tag: %OpenPGP.Packet.PacketTag{
            format: :old,
            length_type: {0, "one-octet"},
            tag: {8, "Compressed Data Packet"}
          }
        }
      ]
      iex> OpenPGP.cast_packets(packets)
      [
        %OpenPGP.CompressedDataPacket{
          algo: {2, "ZLIB [RFC1950]"},
          data_deflated: <<120, 156, 243, 72, 205, 201, 201, 215, 81, 8, 207, 47, 202, 73, 81, 84,
              84, 4, 0, 40, 213, 4, 172>>,
          data_inflated: "Hello, World!!!"
        }
      ]
  """

  alias __MODULE__.Encode
  alias __MODULE__.Packet
  alias __MODULE__.Packet.PacketTag
  alias __MODULE__.Util

  @type any_packet ::
          %OpenPGP.Packet{}
          | %OpenPGP.PublicKeyEncryptedSessionKeyPacket{}
          | %OpenPGP.SecretKeyPacket{}
          | %OpenPGP.PublicKeyPacket{}
          | %OpenPGP.CompressedDataPacket{}
          | %OpenPGP.IntegrityProtectedDataPacket{}
          | %OpenPGP.LiteralDataPacket{}
          | %OpenPGP.ModificationDetectionCodePacket{}

  @doc """
  Decode all packets in a message (input).
  Return a list of %Packet{} structs. Does not cast packets. To cast
  generic packets, use `.cast_packets/1` after `.list_packets/1`, i.e.
  <<...>> |> OpenPGP.list_packets() |> OpenPGP.cast_packets()

  This function extremely handy for inspection, when operating at PTag
  and BodyChunk level.
  """
  @spec list_packets(binary()) :: [Packet.t()]
  def list_packets("" <> _ = input), do: do_list_packets(input, [])

  @spec do_list_packets(input :: binary(), acc :: [Packet.t()]) :: [Packet.t()]
  defp do_list_packets("", acc), do: Enum.reverse(acc)

  defp do_list_packets("" <> _ = input, acc) do
    {packet, next} = Packet.decode(input)
    do_list_packets(next, [packet | acc])
  end

  @doc """
  Similar to `.cast_packet/1`, but operates on a list of generic
  packets.

  > NOTE: #{@v05x_note}
  """
  @spec cast_packets([Packet.t()]) :: [any_packet()]
  def cast_packets(packets) when is_list(packets), do: Enum.map(packets, &cast_packet/1)

  @tag_to_packet %{
    1 => OpenPGP.PublicKeyEncryptedSessionKeyPacket,
    5 => OpenPGP.SecretKeyPacket,
    6 => OpenPGP.PublicKeyPacket,
    7 => OpenPGP.SecretKeyPacket,
    8 => OpenPGP.CompressedDataPacket,
    11 => OpenPGP.LiteralDataPacket,
    14 => OpenPGP.PublicKeyPacket,
    18 => OpenPGP.IntegrityProtectedDataPacket
  }
  @tag_to_packet_ids Map.keys(@tag_to_packet)

  @doc """
  Cast a generic packet %Packet{} to a speicific struct with a packet
  specific data assigned.

  > NOTE: #{@v05x_note}
  """
  @spec cast_packet(Packet.t()) :: any_packet()
  def cast_packet(%Packet{} = packet) do
    case packet.tag do
      %PacketTag{tag: {tag_id, _}} when tag_id in @tag_to_packet_ids ->
        impl = Map.get(@tag_to_packet, tag_id)
        {casted, <<>>} = packet |> Util.concat_body() |> impl.decode()
        casted

      _ ->
        packet
    end
  end

  @doc "Encode any packet (except for %Packet{})."
  @spec encode_packet(any_packet()) :: binary()
  def encode_packet(%{} = packet) do
    tag = Encode.tag(packet)
    ptag = %PacketTag{format: :new, tag: tag}
    body = Encode.encode(packet)

    Encode.encode(%Packet{tag: ptag, body: body})
  end
end
