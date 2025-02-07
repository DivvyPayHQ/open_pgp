defprotocol OpenPGP.Encrypt do
  @spec encrypt(t(), opts :: Keyword.t()) :: t()
  def encrypt(packet, opts \\ [])
end

# There is a "bug" in dialyxir on Elixir 1.13/OTP24 and Elixir1.14/OTP25
# https://github.com/elixir-lang/elixir/issues/7708#issuecomment-403422965

defimpl OpenPGP.Encrypt, for: [Atom, BitString, Float, Function, Integer, List, Map, PID, Port, Reference, Tuple] do
  def encrypt(subj, _), do: raise(Protocol.UndefinedError, protocol: @protocol, value: subj)
end
