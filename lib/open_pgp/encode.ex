defprotocol OpenPGP.Encode do
  @spec tag(t) :: OpenPGP.Packet.PacketTag.tag_tuple()
  def tag(packet)

  @spec encode(t, opts :: Keyword.t()) :: binary()
  def encode(packet, opts \\ [])
end

# There is a "bug" in dialyxir on Elixir 1.13/OTP24 and Elixir1.14/OTP25
# https://github.com/elixir-lang/elixir/issues/7708#issuecomment-403422965

defimpl OpenPGP.Encode, for: [Atom, BitString, Float, Function, Integer, List, Map, PID, Port, Reference, Tuple] do
  def tag(subj), do: raise(Protocol.UndefinedError, protocol: @protocol, value: subj)
  def encode(subj, _), do: raise(Protocol.UndefinedError, protocol: @protocol, value: subj)
end
