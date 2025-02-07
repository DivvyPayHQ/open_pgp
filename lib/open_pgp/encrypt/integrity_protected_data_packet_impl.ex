defimpl OpenPGP.Encrypt, for: OpenPGP.IntegrityProtectedDataPacket do
  alias OpenPGP.ModificationDetectionCodePacket, as: MDC
  alias OpenPGP.IntegrityProtectedDataPacket, as: DataPacket
  alias OpenPGP.Util

  @doc """
  Encrypt Sym. Encrypted Integrity Protected Data Packet with a given sym.algo and session key.

  Require `OpenPGP.IntegrityProtectedDataPacket` fields:

    - `:plaintext` - a binary

  Accept options keyword list as a secont argument:

    - `:session_key` - a key for sym.algo (required)
    - `:session_key_algo` - a tuple representing sym.algo (required, see `t:Util.sym_algo_tuple()`)
    - `:use_mdc` - the Modification Detection Code Packet added if set to `true` (optional, default `true`)

  Return updated `OpenPGP.IntegrityProtectedDataPacket` with populated fields:

    - `:ciphertext`
  """
  def encrypt(%DataPacket{} = packet, opts) do
    session_key =
      Keyword.get(opts, :session_key) ||
        raise """
        Missing options key :session_key - a key for sym.algo
        """

    session_key_algo =
      Keyword.get(opts, :session_key_algo) ||
        raise """
        Missing options key :session_key_algo - a tuple representing sym.algo (see `t:Util.sym_algo_tuple()`)
        """

    crypto_cipher = Util.sym_algo_to_crypto_cipher(session_key_algo)
    null_iv = DataPacket.build_null_iv(session_key_algo)
    checksum = DataPacket.build_checksum(session_key_algo)

    data =
      if Keyword.get(opts, :use_mdc, true),
        do: MDC.append_to(checksum <> packet.plaintext),
        else: checksum <> packet.plaintext

    ciphertext = :crypto.crypto_one_time(crypto_cipher, session_key, null_iv, data, true)

    %{packet | ciphertext: ciphertext}
  end
end
