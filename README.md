# OpenPGP

[![Build Status](https://github.com/DivvyPayHQ/open_pgp/workflows/CI/badge.svg)](https://github.com/DivvyPayHQ/open_pgp/actions?query=workflow%3ACI)
[![Hex pm](https://img.shields.io/hexpm/v/open_pgp.svg)](https://hex.pm/packages/open_pgp)
[![Hex Docs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/open_pgp/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

OpenPGP lib allows to inspect, decode and decrypt OpenPGP Message Format as per [RFC4880](https://www.ietf.org/rfc/rfc4880.html)

## Installation

Add `:open_pgp` to the list of dependencies in `mix.exs`:

```elixir
def deps() do
  [
    {:open_pgp, "~> 0.5"}
  ]
end
```

## OpenPGP Packet

The `OpenPGP.Packet` is a generic packet type. It has an essential purpose: split OpenPGP message in packets and decode packet tags.

An OpenPGP message is constructed from a number of records that are traditionally called packets. A packet is a chunk of data that has a tag specifying its meaning. An OpenPGP message, keyring, certificate, and so forth consists of a number of packets. Some of those packets may contain other OpenPGP packets (for example, a compressed data packet, when uncompressed, contains OpenPGP packets). Each packet consists of a packet header, followed by the packet body. For more details refer to [Packet Syntax chapter in RFC4880](https://www.ietf.org/rfc/rfc4880.html#section-4)

Once OpenPGP message split into generic packets, the higher order tag-specific packet decoders can be applied on its' data. Example:

```
{packet, _rest} = OpenPGP.Packet.decode("...")

{compressed_data_packet, <<>>} =
  packet |> OpenPGP.Util.concat_body() |> OpenPGP.CompressedDataPacket.decode()
```

More details can be found in `OpenPGP.Packet` and `OpenPGP.Packet.Behaviour`

## Examples

### List and cast packets

List packets in a message and then cast to specific packet types.

```
iex> message = <<160, 24, 2, 120, 156, 243, 72, 205, 201, 201, 215, 81, 8, 207, 47, 202, 73, 81, 84, 84, 4, 0, 40, 213, 4, 172>>
...>
iex> packets = OpenPGP.list_packets(message)
[
  %OpenPGP.Packet{
    body: [
      %OpenPGP.Packet.BodyChunk{
        chunk_length: {:fixed, 24},
        data: <<2, 120, 156, 243, 72, 205, 201, 201, 215, 81, 8, 207, 47, 202, 73, 81, 84, 84, 4, 0, 40, 213, 4, 172>>,
        header_length: 1
      }
    ],
    tag: %OpenPGP.Packet.PacketTag{
      format: :old,
      length_type: {0, "one-octet"},
      tag: {8, "Compressed Data Packet"}
    }
  }
]
iex> OpenPGP.cast_packets(packets)
[
  %OpenPGP.CompressedDataPacket{
    algo: {2, "ZLIB [RFC1950]"},
    data_deflated: <<120, 156, 243, 72, 205, 201, 201, 215, 81, 8, 207, 47, 202, 73, 81, 84, 84, 4, 0, 40, 213, 4, 172>>,
    data_inflated: "Hello, World!!!"
  }
]
```

### Decode Generic OpenPGP packet

In this example the packet tag specifies a Signature Packet with body length of 7 bytes. The remaining binary will be return as a second element in a two element tuple. More details in `OpenPGP.Packet.Behaviour`.

```
iex> alias OpenPGP.Packet
iex> alias OpenPGP.Packet.PacketTag
iex> alias OpenPGP.Packet.BodyChunk
iex> Packet.decode(<<1::1, 0::1, 2::4, 0::2, 7::8, "Hello, World!!!">>)
{
  %Packet{
    tag: %PacketTag{format: :old, length_type: {0, "one-octet"}, tag: {2, "Signature Packet"}},
    body: [%BodyChunk{chunk_length: {:fixed, 7}, data: "Hello, ", header_length: 1}]
  },
  "World!!!"
}
```

### Load private key and decrypt PGP file

This example assumes that the private key and encrypted message were exported in a raw binary format, which might not be the most common way of exporting PGP entries. If "armored" format ([Radix64](https://www.rfc-editor.org/rfc/rfc4880.html#section-6)) is used for exporting data (i.e., `gpg --armor --export ...`), you'll need to use `OpenPGP.Radix64.decode/1` first on file contents to get a list of entries and operate on its' `:data` attribute.

```
alias OpenPGP.Packet
alias OpenPGP.Packet.PacketTag
alias OpenPGP.CompressedDataPacket
alias OpenPGP.IntegrityProtectedDataPacket
alias OpenPGP.LiteralDataPacket
alias OpenPGP.PublicKeyPacket
alias OpenPGP.PublicKeyEncryptedSessionKeyPacket
alias OpenPGP.SecretKeyPacket

###################################
### Load encrypted message/file ###
###################################

encrypted_file = File.read!("test/fixtures/words.dict.gpg")

[
  %PublicKeyEncryptedSessionKeyPacket{} = pkesk_packet,
  %IntegrityProtectedDataPacket{} = ipdata_packet
] = encrypted_file |> OpenPGP.list_packets() |> OpenPGP.cast_packets()

%PublicKeyEncryptedSessionKeyPacket{public_key_id: public_key_id} = pkesk_packet

#######################
### Load secret key ###
#######################

private_key_file = File.read!("test/fixtures/rsa2048-priv.pgp")
passphrase = "passphrase"

keyring =
  [
    %SecretKeyPacket{},
    %Packet{tag: %PacketTag{tag: {13, "User ID Packet"}}},
    %Packet{tag: %PacketTag{tag: {2, "Signature Packet"}}},
    %SecretKeyPacket{},
    %Packet{tag: %PacketTag{tag: {2, "Signature Packet"}}}
  ] = private_key_file |> OpenPGP.list_packets() |> OpenPGP.cast_packets()

sk_packet =
  Enum.find_value(keyring, fn
    %SecretKeyPacket{public_key: %PublicKeyPacket{id: ^public_key_id}} = packet -> packet
    _ -> nil
  end)

sk_packet_decrypted = SecretKeyPacket.decrypt(sk_packet, passphrase)

################################
### Decode encrypted message ###
################################

pkesk_packet_decrypted = PublicKeyEncryptedSessionKeyPacket.decrypt(pkesk_packet, sk_packet_decrypted)

ipdata_packet_decrypted = IntegrityProtectedDataPacket.decrypt(ipdata_packet, pkesk_packet_decrypted)

%IntegrityProtectedDataPacket{
  version: 1,
  ciphertext: "" <> _,
  plaintext: plaintext
} = ipdata_packet_decrypted

[
  %CompressedDataPacket{
    algo: {2, "ZLIB [RFC1950]"},
    data_deflated: <<_::bitstring>>,
    data_inflated: data_inflated
  }
] = plaintext |> OpenPGP.list_packets() |> OpenPGP.cast_packets()

[
  %LiteralDataPacket{
    format: {<<0x62>>, :binary},
    file_name: "words.dict",
    created_at: ~U[2024-01-04 00:27:32Z],
    data: data
  }
] = data_inflated |> OpenPGP.list_packets() |> OpenPGP.cast_packets()

IO.puts(data)
```

### CompressedDataPacket

The `OpenPGP.CompressedDataPacket` will inflate data implicitly when decoded (also, data inflated implicitly when `OpenPGP.cast_packets/1` used).

```
iex> alias OpenPGP.CompressedDataPacket
iex> deflated = <<120, 156, 243, 72, 205, 201, 201, 215, 81, 8, 207, 47, 202, 73, 81, 84, 84, 4, 0, 40, 213, 4, 172>>
iex> CompressedDataPacket.decode(<<2, deflated::binary>>)
{
  %CompressedDataPacket{
    algo: {2, "ZLIB [RFC1950]"},
    data_deflated: deflated,
    data_inflated: "Hello, World!!!"},
  <<>>
}
```

### IntegrityProtectedDataPacket

The `OpenPGP.IntegrityProtectedDataPacket` does not decrypt its' data implicitly. The `OpenPGP.IntegrityProtectedDataPacket.decrypt/2` should be used to get plaintext. Please note that some packets have packet speicifc functions, such as `OpenPGP.IntegrityProtectedDataPacket.decrypt/2`.

```
iex> alias OpenPGP.IntegrityProtectedDataPacket
iex> alias OpenPGP.PublicKeyEncryptedSessionKeyPacket
...>
iex> key = <<38, 165, 130, 172, 168, 51, 184, 238, 96, 204, 88,
...>   134, 93, 25, 162, 22, 83, 211, 140, 176, 115, 113, 37, 201,
...>   171, 249, 115, 64, 94, 59, 35, 60>>
...>
iex> iv = <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>
iex> <<prefix::14*8, chsum::2*8>> = :crypto.strong_rand_bytes(16)
iex> plaintext = <<prefix::14*8, chsum::2*8, chsum::2*8, "Hello">>
...>
iex> ciphertext =
...>   :crypto.crypto_one_time(
...>    :aes_256_cfb128,
...>    key,
...>    iv,
...>    plaintext,
...>    true)
...>
iex> payload = <<1::8, ciphertext::binary>>
iex> {packet_decoded, <<>>} = IntegrityProtectedDataPacket.decode(payload)
{
  %IntegrityProtectedDataPacket{
    ciphertext: ciphertext,
    plaintext: nil,
    version: 1
  },
  <<>>
}
iex> pkesk = %PublicKeyEncryptedSessionKeyPacket{
...>   version: 3,
...>   session_key_algo: {9, "AES with 256-bit key"},
...>   session_key_material: {key}
...> }
...>
iex> IntegrityProtectedDataPacket.decrypt(packet_decoded, pkesk)
%IntegrityProtectedDataPacket{
  version: 1,
  plaintext: "Hello",
  ciphertext: ciphertext
}
```

### Radix64 / Armored format

```
payload = """
-----BEGIN PGP MESSAGE-----
Version: OpenPrivacy 0.99

yDgBO22WxBHv7O8X7O/jygAEzol56iUKiXmV+XmpCtmpqQUKiQrFqclFqUDBovzS
vBSFjNSiVHsuAA==
=njUN
-----END PGP MESSAGE-----
"""

[
  %Radix64.Entry{
    crc: <<158, 53, 13>>,
    data: <<200, 56, 1, 59, _::binary>> = data,
    meta: [{"Version", "OpenPrivacy 0.99"}],
    name: "PGP MESSAGE"
  }
] = OpenPGP.Radix64.decode(payload)
```

## Notes

As of **v0.5.x**:

1. Any valid OpenPGP message can be decoded via generic `OpenPGP.Packet` decoder. This abstraction layer provide Packet Tags and Body Chunks for packet envelope level evaluation.
1. Some Packet Tag specific decoders implemented with limited feature support:
   1. `OpenPGP.LiteralDataPacket`
   1. `OpenPGP.PublicKeyEncryptedSessionKeyPacket`
   1. `OpenPGP.PublicKeyPacket` - support only V4 packets
   1. `OpenPGP.SecretKeyPacket` - support only V4 packets; Iterated and Salted String-to-Key (S2K) specifier (ID: 3); S2K usage convention octet of 254 only; S2K hashing algo SHA1; AES128 symmetric encryption of secret key material
   1. `OpenPGP.CompressedDataPacket` - support only ZLIB- and ZIP-style blocks
   1. `OpenPGP.IntegrityProtectedDataPacket` - support Session Key algo 9 (AES with 256-bit key) in CFB mode; Modification Detection Code system is not supported

At a high level `OpenPGP.list_packets/1` and `OpenPGP.cast_packets/1` serve as an entrypoint to OpenPGP Message decoding and extracting generic data.

Packet specific decoders implement `OpenPGP.Packet.Behaviour`, which exposes `.decode/1` interface (including genric `OpenPGP.Packet`). Additionaly some of the packet specific decoders may provide interface for further packet processing, such as `OpenPGP.SecretKeyPacket.decrypt/2`.

Usage example of a comon use case can be found in `test/open_pgp/open_pgp_test.exs` in the test **"full integration: load private key and decrypt encrypted file"**

## Refs, Snippets, Misc

```console
# GPG commands
~$ gpg --list-keys
~$ gpg --list-secret-keys
~$ gpg --export-secret-key --armor john.doe@example.com > ./private.pgp
~$ gpg --list-packets --verbose example.txt.pgp
~$ gpg --encrypt --recipient F89B64F782254B03624FCF5C052E8381B5C335DA /usr/share/dict/words
~$ gpg --batch --passphrase "passphrase" --quick-generate-key "John Doe (RSA2048) <john.doe@example.com>" rsa2048 default never
~$ gpg --edit-key F89B64F782254B03624FCF5C052E8381B5C335DA

# Handy tools
~$ hexdump -vx ./words.pgp
~$ xxd -b ./words.pgp
~$ xxd -g 1
```
