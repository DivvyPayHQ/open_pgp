defmodule OpenPGP.Util.PKCS1 do
  @moduledoc """
  Utility functions for PKCS#1 encoding/decoding

  ## [RFC4880](https://www.ietf.org/rfc/rfc4880.txt)

  ### 13.1. PKCS#1 Encoding in OpenPGP

  This standard makes use of the PKCS#1 functions EME-PKCS1-v1_5 and
  EMSA-PKCS1-v1_5. However, the calling conventions of these functions
  has changed in the past. To avoid potential confusion and
  interoperability problems, we are including local copies in this
  document, adapted from those in PKCS#1 v2.1 [RFC3447]. RFC 3447
  should be treated as the ultimate authority on PKCS#1 for OpenPGP.
  Nonetheless, we believe that there is value in having a self-
  contained document that avoids problems in the future with needed
  changes in the conventions.
  """

  @doc """
  Encode message as described in PKCS#1 block encoding EME-PKCS1-v1_5
  in Section 7.2.1 of [RFC3447](https://www.ietf.org/rfc/rfc3447.txt)

  ### Example

      iex> key = :crypto.strong_rand_bytes(16)
      ...> em = OpenPGP.Util.PKCS1.encode(:eme_pkcs1_v1_5, "Hello", key)
      ...> <<0x00::8, 0x02::8, _::64, 0x00::8, "Hello">> = em 
      
      iex> key = :crypto.strong_rand_bytes(15)
      ...> OpenPGP.Util.PKCS1.encode(:eme_pkcs1_v1_5, "Hello", key)
      ** (RuntimeError) message too long

  See Section 13.1 of [RFC4880] for notes on OpenPGP's use of PKCS#1.

  ### 13.1.1.  EME-PKCS1-v1_5-ENCODE

  Input:
    k  = the length in octets of the key modulus
    M  = message to be encoded, an octet string of length mLen, where
         mLen <= k - 11

  Output:
    EM = encoded message, an octet string of length k
    Error:   "message too long"

    1. Length checking: If mLen > k - 11, output "message too long" and
       stop.

    2. Generate an octet string PS of length k - mLen - 3 consisting of
       pseudo-randomly generated nonzero octets.  The length of PS will
       be at least eight octets.

    3. Concatenate PS, the message M, and other padding to form an
       encoded message EM of length k octets as

       EM = 0x00 || 0x02 || PS || 0x00 || M.

    4. Output EM.
  """
  @spec encode(:eme_pkcs1_v1_5, message :: binary(), key :: binary()) :: encoded_message :: binary()
  def encode(:eme_pkcs1_v1_5, "" <> _ = message, "" <> _ = key) do
    mlen = byte_size(message)
    klen = byte_size(key)

    if mlen > klen - 11, do: raise("message too long")

    ps = generate_ps(klen - mlen - 3)

    <<0x00::8, 0x02::8, ps::binary, 0x00::8, message::binary>>
  end

  @spec generate_ps(len :: pos_integer()) :: padding_string :: binary()
  defp generate_ps(len) when is_integer(len) and len >= 8 do
    result = :crypto.strong_rand_bytes(len)
    has_zero = result |> :binary.bin_to_list() |> Enum.any?(&(&1 == 0))

    if has_zero,
      do: generate_ps(len),
      else: result
  end
end
