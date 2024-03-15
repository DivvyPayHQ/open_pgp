# credo:disable-for-next-line CredoNaming.Check.Consistency.ModuleFilename
defmodule OpenPGP.S2KSpecifier do
  @moduledoc """
  Represents structured data for String-to-Key specifier.

  ---

  ## [RFC4880](https://www.ietf.org/rfc/rfc4880.txt)

  ## 3.7.  String-to-Key (S2K) Specifiers

   String-to-key (S2K) specifiers are used to convert passphrase strings
   into symmetric-key encryption/decryption keys.  They are used in two
   places, currently: to encrypt the secret part of private keys in the
   private keyring, and to convert passphrases to encryption keys for
   symmetrically encrypted messages.

  ### 3.7.1.  String-to-Key (S2K) Specifier Types

   There are three types of S2K specifiers currently supported, and
   some reserved values:

       ID          S2K Type
       --          --------
       0           Simple S2K
       1           Salted S2K
       2           Reserved value
       3           Iterated and Salted S2K
       100 to 110  Private/Experimental S2K

   These are described in Sections 3.7.1.1 - 3.7.1.3.

  #### 3.7.1.1.  Simple S2K

   This directly hashes the string to produce the key data.  See below
   for how this hashing is done.

       Octet 0:        0x00
       Octet 1:        hash algorithm

   Simple S2K hashes the passphrase to produce the session key.  The
   manner in which this is done depends on the size of the session key
   (which will depend on the cipher used) and the size of the hash
   algorithm's output.  If the hash size is greater than the session key
   size, the high-order (leftmost) octets of the hash are used as the
   key.

   If the hash size is less than the key size, multiple instances of the
   hash context are created -- enough to produce the required key data.
   These instances are preloaded with 0, 1, 2, ... octets of zeros (that
   is to say, the first instance has no preloading, the second gets
   preloaded with 1 octet of zero, the third is preloaded with two
   octets of zeros, and so forth).

   As the data is hashed, it is given independently to each hash
   context.  Since the contexts have been initialized differently, they
   will each produce different hash output.  Once the passphrase is
   hashed, the output data from the multiple hashes is concatenated,
   first hash leftmost, to produce the key data, with any excess octets
   on the right discarded.

  #### 3.7.1.2.  Salted S2K

   This includes a "salt" value in the S2K specifier -- some arbitrary
   data -- that gets hashed along with the passphrase string, to help
   prevent dictionary attacks.

       Octet 0:        0x01
       Octet 1:        hash algorithm
       Octets 2-9:     8-octet salt value

   Salted S2K is exactly like Simple S2K, except that the input to the
   hash function(s) consists of the 8 octets of salt from the S2K
   specifier, followed by the passphrase.

  #### 3.7.1.3.  Iterated and Salted S2K

   This includes both a salt and an octet count.  The salt is combined
   with the passphrase and the resulting value is hashed repeatedly.
   This further increases the amount of work an attacker must do to try
   dictionary attacks.

       Octet  0:        0x03
       Octet  1:        hash algorithm
       Octets 2-9:      8-octet salt value
       Octet  10:       count, a one-octet, coded value
   The count is coded into a one-octet number using the following
   formula:

       #define EXPBIAS 6
           count = ((Int32)16 + (c & 15)) << ((c >> 4) + EXPBIAS);

   The above formula is in C, where "Int32" is a type for a 32-bit
   integer, and the variable "c" is the coded count, Octet 10.

   Iterated-Salted S2K hashes the passphrase and salt data multiple
   times.  The total number of octets to be hashed is specified in the
   encoded count in the S2K specifier.  Note that the resulting count
   value is an octet count of how many octets will be hashed, not an
   iteration count.

   Initially, one or more hash contexts are set up as with the other S2K
   algorithms, depending on how many octets of key data are needed.
   Then the salt, followed by the passphrase data, is repeatedly hashed
   until the number of octets specified by the octet count has been
   hashed.  The one exception is that if the octet count is less than
   the size of the salt plus passphrase, the full salt plus passphrase
   will be hashed even though that is greater than the octet count.
   After the hashing is done, the data is unloaded from the hash
   context(s) as with the other S2K algorithms.
  """
  import Bitwise

  @enforce_keys [:id]
  defstruct [:id, :algo, :salt, :protect_count]

  @type t :: %__MODULE__{
          id: {byte(), any()},
          algo: nil | {0 | 1 | 2 | 3 | 100..110, binary()},
          protect_count: nil | {byte(), pos_integer()},
          salt: nil | binary()
        }

  @doc """
  Decode String-to-Key specifier given input binary.
  Return structured specifier and remaining binary.
  """
  @spec decode(binary()) :: {t(), binary()}
  def decode(<<0::8, algo::8, rest::binary>>) do
    specifier = %__MODULE__{
      id: s2k_type_tuple(0),
      algo: hash_algo_tuple(algo)
    }

    {specifier, rest}
  end

  def decode(<<1::8, algo::8, salt::binary-size(8), rest::binary>>) do
    specifier = %__MODULE__{
      id: s2k_type_tuple(1),
      algo: hash_algo_tuple(algo),
      salt: salt
    }

    {specifier, rest}
  end

  def decode(<<3::8, algo::8, salt::binary-size(8), protect_count::8, rest::binary>>) do
    specifier = %__MODULE__{
      id: s2k_type_tuple(3),
      algo: hash_algo_tuple(algo),
      salt: salt,
      protect_count: {protect_count, decode_protect_count(protect_count)}
    }

    {specifier, rest}
  end

  def decode(<<id::8, rest::binary>>) when id == 2 or id in 100..110 do
    specifier = %__MODULE__{id: s2k_type_tuple(id)}
    {specifier, rest}
  end

  @spec build_session_key(t(), key_size :: pos_integer(), passphrase :: binary()) :: binary()
  def build_session_key(%__MODULE__{} = specifier, key_size, "" <> _ = passphrase)
      when is_integer(key_size) and key_size > 0 do
    %__MODULE__{
      id: {3, _},
      salt: salt,
      protect_count: {_, protect_count}
    } = specifier

    build_session_key(key_size, passphrase, salt, protect_count)
  end

  # [RFC4880](https://www.ietf.org/rfc/rfc4880.txt)
  #
  # ---
  #
  # ### 3.7.1.1.  Simple S2K
  # If the hash size is less than the key size, multiple instances of the
  # hash context are created -- enough to produce the required key data.
  # These instances are preloaded with 0, 1, 2, ... octets of zeros (that
  # is to say, the first instance has no preloading, the second gets
  # preloaded with 1 octet of zero, the third is preloaded with two
  # octets of zeros, and so forth).

  # As the data is hashed, it is given independently to each hash
  # context.  Since the contexts have been initialized differently, they
  # will each produce different hash output.  Once the passphrase is
  # hashed, the output data from the multiple hashes is concatenated,
  # first hash leftmost, to produce the key data, with any excess octets
  # on the right discarded.
  #
  # ...
  #
  # ### 3.7.1.3.  Iterated and Salted S2K
  #
  # ...
  #
  # Iterated-Salted S2K hashes the passphrase and salt data multiple
  # times.  The total number of octets to be hashed is specified in the
  # encoded count in the S2K specifier.  Note that the resulting count
  # value is an octet count of how many octets will be hashed, not an
  # iteration count.
  # Initially, one or more hash contexts are set up as with the other S2K
  # algorithms, depending on how many octets of key data are needed.
  # Then the salt, followed by the passphrase data, is repeatedly hashed
  # until the number of octets specified by the octet count has been
  # hashed.  The one exception is that if the octet count is less than
  # the size of the salt plus passphrase, the full salt plus passphrase
  # will be hashed even though that is greater than the octet count.
  # After the hashing is done, the data is unloaded from the hash
  # context(s) as with the other S2K algorithms.
  @max_hash_contexts 100
  @zero_octet <<0::8>>
  @spec build_session_key(
          key_bit_size :: non_neg_integer(),
          passphrase :: binary(),
          salt :: binary(),
          protect_count :: non_neg_integer()
        ) :: session_key :: binary()
  defp build_session_key(key_bit_size, "" <> _ = passphrase, "" <> _ = salt, protect_count) do
    salted_passphrase = salt <> passphrase
    iter_count = ceil(protect_count / byte_size(salted_passphrase))

    <<hash_input::bytes-size(protect_count), _::binary>> =
      Enum.reduce(1..iter_count, "", fn _, acc -> acc <> salted_passphrase end)

    iterated_s2k_hash =
      Enum.reduce_while(1..@max_hash_contexts, "", fn context_num, acc ->
        if bit_size(acc) < key_bit_size do
          prefix = String.pad_trailing("", context_num - 1, @zero_octet)
          {:cont, acc <> :crypto.hash(:sha, prefix <> hash_input)}
        else
          {:halt, acc}
        end
      end)

    <<key::size(key_bit_size), _::bits>> = iterated_s2k_hash
    <<key::size(key_bit_size)>>
  end

  # 3.7.1.  String-to-Key (S2K) Specifier Types

  # There are three types of S2K specifiers currently supported, and
  # some reserved values:

  #     ID          S2K Type
  #     --          --------
  #     0           Simple S2K
  #     1           Salted S2K
  #     2           Reserved value
  #     3           Iterated and Salted S2K
  #     100 to 110  Private/Experimental S2K

  @s2k_types %{
    0 => "Simple S2K",
    1 => "Salted S2K",
    2 => "Reserved value",
    3 => "Iterated and Salted S2K",
    100 => "Private/Experimental S2K",
    101 => "Private/Experimental S2K",
    102 => "Private/Experimental S2K",
    103 => "Private/Experimental S2K",
    104 => "Private/Experimental S2K",
    105 => "Private/Experimental S2K",
    106 => "Private/Experimental S2K",
    107 => "Private/Experimental S2K",
    108 => "Private/Experimental S2K",
    109 => "Private/Experimental S2K",
    110 => "Private/Experimental S2K"
  }

  @s2k_types_values Map.keys(@s2k_types)
  defp s2k_type_tuple(id) when id in @s2k_types_values, do: {id, @s2k_types[id]}

  # 9.4.  Hash Algorithms

  #   ID           Algorithm                             Text Name
  #   --           ---------                             ---------
  #   1          - MD5 [HAC]                             "MD5"
  #   2          - SHA-1 [FIPS180]                       "SHA1"
  #   3          - RIPE-MD/160 [HAC]                     "RIPEMD160"
  #   4          - Reserved
  #   5          - Reserved
  #   6          - Reserved
  #   7          - Reserved
  #   8          - SHA256 [FIPS180]                      "SHA256"
  #   9          - SHA384 [FIPS180]                      "SHA384"
  #   10         - SHA512 [FIPS180]                      "SHA512"
  #   11         - SHA224 [FIPS180]                      "SHA224"
  #   100 to 110 - Private/Experimental algorithm

  # Implementations MUST implement SHA-1.  Implementations MAY implement
  # other algorithms.  MD5 is deprecated.

  @hash_algos %{
    1 => "MD5 [HAC]",
    2 => "SHA-1 [FIPS180]",
    3 => "RIPE-MD/160 [HAC]",
    4 => "Reserved",
    5 => "Reserved",
    6 => "Reserved",
    7 => "Reserved",
    8 => "SHA256 [FIPS180]",
    9 => "SHA384 [FIPS180]",
    10 => "SHA512 [FIPS180]",
    11 => "SHA224 [FIPS180]",
    100 => "Private/Experimental algorithm",
    101 => "Private/Experimental algorithm",
    102 => "Private/Experimental algorithm",
    103 => "Private/Experimental algorithm",
    104 => "Private/Experimental algorithm",
    105 => "Private/Experimental algorithm",
    106 => "Private/Experimental algorithm",
    107 => "Private/Experimental algorithm",
    108 => "Private/Experimental algorithm",
    109 => "Private/Experimental algorithm",
    110 => "Private/Experimental algorithm"
  }
  @hash_algo_values Map.keys(@hash_algos)
  defp hash_algo_tuple(id) when id in @hash_algo_values, do: {id, @hash_algos[id]}

  # The count is coded into a one-octet number using the following
  # formula:

  #     #define EXPBIAS 6
  #         count = ((Int32)16 + (c & 15)) << ((c >> 4) + EXPBIAS);

  # The above formula is in C, where "Int32" is a type for a 32-bit
  # integer, and the variable "c" is the coded count, Octet 10.
  @expbias 6
  defp decode_protect_count(c), do: (16 + (c &&& 15)) <<< ((c >>> 4) + @expbias)
end
