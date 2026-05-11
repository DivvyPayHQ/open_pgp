defmodule OpenPGP.UserIdPacket do
  @moduledoc """
  Represents structured data for User ID Packet (Tag 13).

  ### Example:

      iex> OpenPGP.UserIdPacket.decode("Alice <alice@example.com>")
      {%OpenPGP.UserIdPacket{id: "Alice <alice@example.com>"}, <<>>}

  ---

  ## [RFC4880](https://www.ietf.org/rfc/rfc4880.txt)

  ### 5.11. User ID Packet (Tag 13)

  A User ID packet consists of UTF-8 text that is intended to represent
  the name and email address of the key holder. By convention, it
  includes an RFC 2822 mail name-addr, but there are no restrictions on
  its content. The packet length in the header specifies the length of
  the User ID.
  """

  @behaviour OpenPGP.Packet.Behaviour

  defstruct [:id]

  @type t :: %__MODULE__{id: binary()}

  @doc """
  Decode User ID Packet given input binary.
  Return structured packet and remaining binary (empty binary).
  """
  @impl OpenPGP.Packet.Behaviour
  @spec decode(binary()) :: {t(), <<>>}
  def decode("" <> _ = input), do: {%__MODULE__{id: input}, ""}
end
