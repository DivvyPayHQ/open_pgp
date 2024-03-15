defmodule OpenPGP.Radix64.Entry do
  @moduledoc """
  Represents a block/entry in the PGP armored message.

  ## [RFC4880](https://www.ietf.org/rfc/rfc4880.txt)

  6.2.  Forming ASCII Armor

   When OpenPGP encodes data into ASCII Armor, it puts specific headers
   around the Radix-64 encoded data, so OpenPGP can reconstruct the data
   later.  An OpenPGP implementation MAY use ASCII armor to protect raw
   binary data.  OpenPGP informs the user what kind of data is encoded
   in the ASCII armor through the use of the headers.

   Concatenating the following data creates ASCII Armor:

     - An Armor Header Line, appropriate for the type of data

     - Armor Headers

     - A blank (zero-length, or containing only whitespace) line

     - The ASCII-Armored data

     - An Armor Checksum

     - The Armor Tail, which depends on the Armor Header Line

   An Armor Header Line consists of the appropriate header line text
   surrounded by five (5) dashes ('-', 0x2D) on either side of the
   header line text.  The header line text is chosen based upon the type
   of data that is being encoded in Armor, and how it is being encoded.
   Header line texts include the following strings:

   BEGIN PGP MESSAGE
       Used for signed, encrypted, or compressed files.

   BEGIN PGP PUBLIC KEY BLOCK
       Used for armoring public keys.

   BEGIN PGP PRIVATE KEY BLOCK
       Used for armoring private keys.

   BEGIN PGP MESSAGE, PART X/Y
       Used for multi-part messages, where the armor is split amongst Y
       parts, and this is the Xth part out of Y.

   BEGIN PGP MESSAGE, PART X
       Used for multi-part messages, where this is the Xth part of an
       unspecified number of parts.  Requires the MESSAGE-ID Armor
       Header to be used.

   BEGIN PGP SIGNATURE
       Used for detached signatures, OpenPGP/MIME signatures, and
       cleartext signatures.  Note that PGP 2.x uses BEGIN PGP MESSAGE
       for detached signatures.
  """

  defstruct name: nil, meta: [], data: <<>>, crc: nil

  @type t :: %__MODULE__{
          name: binary() | nil,
          meta: [{key :: binary(), value :: binary()}],
          data: binary(),
          crc: binary() | nil
        }
end
