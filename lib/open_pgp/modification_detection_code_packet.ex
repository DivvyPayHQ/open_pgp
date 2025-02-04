defmodule OpenPGP.ModificationDetectionCodePacket do
  @moduledoc """
  Represents structured data for Modification Detection Code Packet.

  ### Example:

      iex> alias OpenPGP.ModificationDetectionCodePacket
      ...> data = :crypto.hash(:sha, <<"Hello!", 0xD3, 0x14>>)
      ...> ModificationDetectionCodePacket.decode(data)
      {
        %ModificationDetectionCodePacket{
          sha: <<24, 124, 192, 238, 22, 94, 219, 146, 73, 3, 220, 145, 130, 2, 184, 60, 245, 227, 44, 17>>
        },
        <<>>
      }

  ---

  ## [RFC4880](https://www.ietf.org/rfc/rfc4880.txt)

  ### 5.14.  Modification Detection Code Packet (Tag 19)

  The Modification Detection Code packet contains a SHA-1 hash of
  plaintext data, which is used to detect message modification.  It is
  only used with a Symmetrically Encrypted Integrity Protected Data
  packet.  The Modification Detection Code packet MUST be the last
  packet in the plaintext data that is encrypted in the Symmetrically
  Encrypted Integrity Protected Data packet, and MUST appear in no
  other place.

  A Modification Detection Code packet MUST have a length of 20 octets.

  The body of this packet consists of:

    - A 20-octet SHA-1 hash of the preceding plaintext data of the
      Symmetrically Encrypted Integrity Protected Data packet,
      including prefix data, the tag octet (0xD3), and length octet of
      the Modification Detection Code packet (0x14).

  Note that the Modification Detection Code packet MUST always use a
  new format encoding of the packet tag, and a one-octet encoding of
  the packet length.  The reason for this is that the hashing rules for
  modification detection include a one-octet tag and one-octet length
  in the data hash. While this is a bit restrictive, it reduces
  complexity.
  """

  @behaviour OpenPGP.Packet.Behaviour

  defstruct [:sha]

  @type t :: %__MODULE__{
          sha: <<_::160>>
        }

  @mdc_header <<0xD3, 0x14>>
  @mdc_byte_size 20

  @doc """
  Decode packet given input binary.
  Returns structured packet and remaining binary (empty string).
  Expects input binary to be 20 octets long (the length of SHA-1).
  """
  @impl OpenPGP.Packet.Behaviour
  @spec decode(binary()) :: {t(), <<>>}
  def decode(<<sha::bytes-size(20)>>) do
    packet = %__MODULE__{
      sha: sha
    }

    {packet, ""}
  end

  @doc """
  Validates input binary/plaintext with a Modification Detection Code (MDC) Packet.
  Returns :ok on success. Raises on failure.
  Expect last 22 octets of payload to represent MDC Packet.
  """
  @spec validate!(payload :: binary()) :: {plaintext :: binary(), sha :: binary()}
  def validate!("" <> _ = payload) do
    plen = byte_size(payload) - byte_size(@mdc_header) - @mdc_byte_size

    {plaintext, sha_expected} =
      case payload do
        <<plaintext::bytes-size(plen), @mdc_header::binary, sha::bytes-size(@mdc_byte_size)>> -> {plaintext, sha}
        _ -> raise("Failed to parse Modification Detection Code Packet.")
      end

    sha_actual = :crypto.hash(:sha, plaintext <> @mdc_header)

    if sha_actual == sha_expected do
      {plaintext, sha_actual}
    else
      sha_expected_hex = inspect(sha_expected, base: :hex)
      sha_actual_hex = inspect(sha_actual, base: :hex)

      raise("Failed to verify Modification Detection Code SHA-1: expected #{sha_expected_hex}, got #{sha_actual_hex}.")
    end
  end

  @doc """
  Encode Modification Detection Code Packet given input binary.
  Returns encoded packet body.
  """
  @spec encode(input :: binary()) :: <<_::160>>
  def encode("" <> _ = input), do: :crypto.hash(:sha, input <> @mdc_header)

  @doc """
  Encode Modification Detection Code (MDC) Packet ad appends to the input binary.
  Returns binary with MDC appended.
  """
  @spec append_to(input :: binary()) :: binary()
  def append_to("" <> _ = input), do: input <> @mdc_header <> encode(input)
end
