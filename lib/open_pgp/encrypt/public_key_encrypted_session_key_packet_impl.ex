defimpl OpenPGP.Encrypt, for: OpenPGP.PublicKeyEncryptedSessionKeyPacket do
  alias OpenPGP.PublicKeyPacket
  alias OpenPGP.PublicKeyEncryptedSessionKeyPacket, as: PKESK
  alias OpenPGP.Util

  @doc """
  Encrypt Public-Key Encrypted Session Key Packet with a given recipient's public key.

  Require `OpenPGP.PublicKeyEncryptedSessionKeyPacket` fields:

    - `:session_key_algo` - a valid sym.algo tuple (see `t:OpenPGP.Util.sym_algo_tuple()`)
    - `:session_key_material` - a valid sym.algo key material (typically a one-element tuple)

  Accept options keyword list as a secont argument:

    - `:recipient_public_key` - an `%OpenPGP.PublicKeyPacket{}` with non-empty `:algo` and `:material` fields (required)

  Return updated `%OpenPGP.PublicKeyEncryptedSessionKeyPacket{}` with populated fields:

    - `:public_key_id`
    - `:public_key_algo`
    - `:ciphertext`
  """
  def encrypt(%PKESK{} = packet, opts) do
    {session_key} =
      packet.session_key_material ||
        raise """
        Expected :session_key_material field to have a valid session_key_material (i.e. `{<<...>>}`). Got: #{inspect(packet.session_key_material)}.
        """

    session_key_algo =
      packet.session_key_algo ||
        raise """
        Expected :session_key_algo field to have a valid session_key_algo (i.e. `{9, "AES with 256-bit key"}`). Got: #{inspect(packet.session_key_algo)}.
        """

    %PublicKeyPacket{algo: public_key_algo, material: public_key_material, id: public_key_id} =
      Keyword.get(opts, :recipient_public_key) ||
        raise """
        Missing options key :recipient_public_key - a `%PublicKey{}` struct.
        """

    material = build_material(session_key, session_key_algo, public_key_material, public_key_algo)

    ciphertext =
      for el <- Tuple.to_list(material), reduce: "" do
        acc -> acc <> Util.encode_mpi(el)
      end

    %{packet | public_key_id: public_key_id, public_key_algo: public_key_algo, ciphertext: ciphertext}
  end

  defp build_material("" <> _ = session_key, session_key_algo, public_key_material, {16, _} = _public_key_algo) do
    {prime_p, group_g, value_y} = public_key_material
    {sym_algo_id, _} = session_key_algo

    {sender_pub_key, _private} = :crypto.generate_key(:dh, [prime_p, group_g])

    k = :binary.decode_unsigned(sender_pub_key)
    p = :binary.decode_unsigned(prime_p)
    g = :binary.decode_unsigned(group_g)
    y = :binary.decode_unsigned(value_y)

    checksum =
      for <<byte::8 <- session_key>>, reduce: 0 do
        acc -> rem(acc + byte, 65536)
      end

    value_m = Util.PKCS1.encode(:eme_pkcs1_v1_5, <<sym_algo_id::8, session_key::binary, checksum::16>>, sender_pub_key)
    m = :binary.decode_unsigned(value_m)

    g_k_mod_p = :crypto.mod_pow(g, k, p)
    y_k_mod_p = :crypto.mod_pow(y, k, p)
    m_y_k_mod_p = (m * :binary.decode_unsigned(y_k_mod_p)) |> rem(p) |> :binary.encode_unsigned()

    {g_k_mod_p, m_y_k_mod_p}
  end

  @v06x_note """
  As of 0.6.x the Public Key Encrypted Session Key Packet encrypts the session key only with "Elgamal (Encrypt-Only)" (algo 16)
  """
  defp build_material(_session_key, _session_key_algo, _public_key_material, public_key_algo) do
    raise("Unsupported PKESK encription algo #{inspect(public_key_algo)}. " <> @v06x_note)
  end
end
