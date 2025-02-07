defimpl OpenPGP.Encode, for: OpenPGP.PublicKeyEncryptedSessionKeyPacket do
  alias OpenPGP.PublicKeyEncryptedSessionKeyPacket, as: PKESK

  def tag(_), do: {1, "Public-Key Encrypted Session Key Packet"}

  @doc """
  Encode Public-Key Encrypted Session Key Packet.
  Return encoded packet body.

  ### Example

      iex> packet = %OpenPGP.PublicKeyEncryptedSessionKeyPacket{
      ...>            ciphertext: "Ciphertext",
      ...>            public_key_id: "6BAF2C48",
      ...>            public_key_algo: {16, "Elgamal (Encrypt-Only) [ELGAMAL] [HAC]"}
      ...>          }
      ...> OpenPGP.Encode.encode(packet)
      <<3::8, "6BAF2C48", 16::8, "Ciphertext">>
  """
  @version 3
  def encode(%PKESK{ciphertext: ciphertext, public_key_id: key_id, public_key_algo: {key_algo_id, _}}, _opts)
      when is_binary(ciphertext) and is_binary(key_id) and key_algo_id in 1..255 do
    <<@version::8, key_id::binary, key_algo_id::8, ciphertext::binary>>
  end
end
