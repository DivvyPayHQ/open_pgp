defmodule OpenPGP.Radix64.CRC24 do
  @moduledoc """
  CRC-24 implementation for Radix-64 checksum validation.

  ---

  ## [RFC4880](https://www.ietf.org/rfc/rfc4880.txt)

  ### 6.  Radix-64 Conversions

  The checksum is a 24-bit Cyclic Redundancy Check (CRC) converted to
  four characters of radix-64 encoding by the same MIME base64
  transformation, preceded by an equal sign (=).  The CRC is computed
  by using the generator 0x864CFB and an initialization of 0xB704CE.
  The accumulation is done on the data before it is converted to
  radix-64, rather than on the converted data.


  ### 6.1.  An Implementation of the CRC-24 in "C"

    ```
    #define CRC24_INIT 0xB704CEL
    #define CRC24_POLY 0x1864CFBL

    typedef long crc24;
    crc24 crc_octets(unsigned char *octets, size_t len)
    {
        crc24 crc = CRC24_INIT;
        int i;
        while (len--) {
            crc ^= (*octets++) << 16;
            for (i = 0; i < 8; i++) {
                crc <<= 1;
                if (crc & 0x1000000)
                    crc ^= CRC24_POLY;
            }
        }
        return crc & 0xFFFFFFL;
    }
    ```
  """
  import Bitwise

  @crc24_init 0xB704CE
  @crc24_poly 0x1864CFB

  @doc """
  Calculate CRC-24 of a given binary.

  ### Example:

      iex> OpenPGP.Radix64.CRC24.calc("Hello, world!!!")
      <<190, 125, 81>>
  """
  @spec calc(binary()) :: <<_::24>>
  def calc("" <> _ = input) do
    crc_sum =
      for <<octet::8 <- input>>, reduce: @crc24_init do
        acc -> running_sum(octet, acc)
      end

    <<band(crc_sum, 0xFFFFFF)::24>>
  end

  defp running_sum(octet, prev) do
    crc = bxor(prev, octet <<< 16)

    Enum.reduce(0..7, crc, fn _, acc ->
      acc = acc <<< 1
      if band(acc, 0x1000000) != 0, do: bxor(acc, @crc24_poly), else: acc
    end)
  end
end
