defmodule OpenPGP.Packet.PacketTag do
  @moduledoc """
  PacketTag struct represents a packet tag as per RFC4880.

  ---

  ## [RFC4880](https://www.ietf.org/rfc/rfc4880.txt)

  ### 4.2.  Packet Headers

  The first octet of the packet header is called the "Packet Tag".  It
  determines the format of the header and denotes the packet contents.
  Note that the most significant bit is the leftmost bit, called bit 7.
  A mask for this bit is 0x80 in hexadecimal.

            +---------------+
        PTag |7 6 5 4 3 2 1 0|
            +---------------+
        Bit 7 -- Always one
        Bit 6 -- New packet format if set

  Note that old format packets have four bits of
  packet tags, and new format packets have six; some features cannot be
  used and still be backward-compatible.

  Also note that packets with a tag greater than or equal to 16 MUST
  use new format packets.  The old format packets can only express tags
  less than or equal to 15.

  Old format packets contain:

        Bits 5-2 -- packet tag
        Bits 1-0 -- length-type

  New format packets contain:

        Bits 5-0 -- packet tag

  #### 4.2.1.  Old Format Packet Lengths

  The meaning of the length-type in old format packets is:

  0 - The packet has a one-octet length.  The header is 2 octets long.

  1 - The packet has a two-octet length.  The header is 3 octets long.

  2 - The packet has a four-octet length.  The header is 5 octets long.

  3 - The packet is of indeterminate length.  The header is 1 octet
      long, and the implementation must determine how long the packet
      is.  If the packet is in a file, this means that the packet
      extends until the end of the file.  In general, an implementation
      SHOULD NOT use indeterminate-length packets except where the end
      of the data will be clear from the context, and even then it is
      better to use a definite length, or a new format header.  The new
      format headers described below have a mechanism for precisely
      encoding data of indeterminate length.

  ### 4.3.  Packet Tags

  The packet tag denotes what type of packet the body holds.  Note that
  old format headers can only have tags less than 16, whereas new
  format headers can have tags as great as 63.  The defined tags (in
  decimal) are as follows:

      0        -- Reserved - a packet tag MUST NOT have this value
      1        -- Public-Key Encrypted Session Key Packet
      2        -- Signature Packet
      3        -- Symmetric-Key Encrypted Session Key Packet
      4        -- One-Pass Signature Packet
      5        -- Secret-Key Packet
      6        -- Public-Key Packet
      7        -- Secret-Subkey Packet
      8        -- Compressed Data Packet
      9        -- Symmetrically Encrypted Data Packet
      10       -- Marker Packet
      11       -- Literal Data Packet
      12       -- Trust Packet
      13       -- User ID Packet
      14       -- Public-Subkey Packet
      17       -- User Attribute Packet
      18       -- Sym. Encrypted and Integrity Protected Data Packet
      19       -- Modification Detection Code Packet
      60 to 63 -- Private or Experimental Values
  """

  defstruct [:format, :tag, :length_type]

  @type t :: %__MODULE__{
          format: :old | :new,
          tag: tag_tuple(),
          length_type: length_tuple() | nil
        }
  @type tag_tuple :: {non_neg_integer(), desc :: binary()}
  @type length_tuple :: {non_neg_integer(), desc :: binary()}

  @doc """
  Decode packet tag given input binary.
  Return structured packet tag and remaining binary.
  Expect input to start with the Packet Tag octet.

  ### Example:

      iex> alias OpenPGP.Packet.PacketTag
      iex> PacketTag.decode(<<1::1, 0::1, 2::4, 0::2, "data">>)
      {%PacketTag{format: :old, tag: {2, "Signature Packet"}, length_type: {0, "one-octet"}}, "data"}
  """
  @spec decode(data :: binary()) :: {t(), rest :: binary()}
  def decode(<<1::1, 0::1, tag::4, length_type::2, rest::binary>>) do
    ptag = %__MODULE__{
      format: :old,
      tag: tag_tuple(tag),
      length_type: length_type_tuple(length_type)
    }

    {ptag, rest}
  end

  def decode(<<1::1, 1::1, tag::6, rest::binary>>) do
    ptag = %__MODULE__{
      format: :new,
      tag: tag_tuple(tag)
    }

    {ptag, rest}
  end

  @doc """
  Encode packet tag. Always uses new packet format.
  Return encoded packet tag octet.

  ### Example:

      iex> OpenPGP.Packet.PacketTag.encode(1)
      <<1::1, 1::1, 1::6>>

      iex> OpenPGP.Packet.PacketTag.encode({2, "Signature Packet"})
      <<1::1, 1::1, 2::6>>
  """
  @spec encode(tag_tuple() | non_neg_integer()) :: <<_::8>>
  def encode({ptag, _name}), do: encode(ptag)
  def encode(ptag) when is_integer(ptag) and ptag in 0..63, do: <<1::1, 1::1, ptag::6>>

  @ptags %{
    0 => "Reserved - a packet tag MUST NOT have this value",
    1 => "Public-Key Encrypted Session Key Packet",
    2 => "Signature Packet",
    3 => "Symmetric-Key Encrypted Session Key Packet",
    4 => "One-Pass Signature Packet",
    5 => "Secret-Key Packet",
    6 => "Public-Key Packet",
    7 => "Secret-Subkey Packet",
    8 => "Compressed Data Packet",
    9 => "Symmetrically Encrypted Data Packet",
    10 => "Marker Packet",
    11 => "Literal Data Packet",
    12 => "Trust Packet",
    13 => "User ID Packet",
    14 => "Public-Subkey Packet",
    17 => "User Attribute Packet",
    18 => "Sym. Encrypted and Integrity Protected Data Packet",
    19 => "Modification Detection Code Packet",
    60 => "Private or Experimental Values",
    61 => "Private or Experimental Values",
    62 => "Private or Experimental Values",
    63 => "Private or Experimental Values"
  }

  @ptag_values Map.keys(@ptags)
  @spec tag_tuple(non_neg_integer()) :: tag_tuple()
  defp tag_tuple(tag) when tag in @ptag_values, do: {tag, @ptags[tag]}

  @plength %{
    0 => "one-octet",
    1 => "two-octet",
    2 => "four-octet",
    3 => "indeterminate"
  }

  @plength_values Map.keys(@plength)
  @spec length_type_tuple(non_neg_integer()) :: length_tuple()
  defp length_type_tuple(ltype) when ltype in @plength_values, do: {ltype, @plength[ltype]}
end
