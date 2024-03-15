defmodule OpenPGP.Packet.Behaviour do
  @moduledoc """
  All packet specific decoders must implement
  `OpenPGP.Packet.Behaviour`, which exposes `.decode/1` interface
  (including genric `OpenPGP.Packet`). Additionaly some of the packet
  specific decoders may provide interface for further packet processing,
  such as `OpenPGP.SecretKeyPacket.decrypt/2`.
  """

  @doc """
  This callback is widely used to provide a clear interface to decoding
  OpenPGP packets. All tag-specific packets implement this callback:
  accepting a binary input and returning a two element tuple with a
  decoded packet and a remainder of an input binary.
  """
  @callback decode(binary()) :: {OpenPGP.any_packet(), binary()}
end
