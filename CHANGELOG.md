# Changelog

## v0.6.3

### Enhancements

* Updated `OpenPGP.SecretKeyPacket` to support unencrypted keys (no S2K specifier given, S2K usage byte of 0).
* Introduced `OpenPGP.Util.checksum/1` and refactored related codebase.

## v0.6.2

### Enhancements

* Better error message for:
  * `OpenPGP.Util.public_key_algo_tuple/1`
  * `OpenPGP.Util.sym_algo_tuple/1`
  * `OpenPGP.Util.sym_algo_cipher_block_size/1`
  * `OpenPGP.Util.sym_algo_key_size/1`
* Updated Elixir supported version to `~>1.14`

## v0.6.0

### Enhancements

* Introduced `OpenPGP.Encode` protocol with `.encode/1,2` and `.tag/1`.
* Add `OpenPGP.Encode` protocol implementation for:
  * `OpenPGP.PublicKeyEncryptedSessionKeyPacket`
  * `OpenPGP.IntegrityProtectedDataPacket`
  * `OpenPGP.LiteralDataPacket`
  * `OpenPGP.Packet`
  * `OpenPGP.Packet.PacketTag`
  * `OpenPGP.Packet.BodyChunk`
* Introduced `OpenPGP.Encrypt` protocol with `.encrypt/1,2`.
* Add `OpenPGP.Encrypt` protocol implementation for:
  * `OpenPGP.PublicKeyEncryptedSessionKeyPacket` with Elgamal (Public-Key algo 16).
  * `OpenPGP.IntegrityProtectedDataPacket` with AES-128, AES-192, AES-256 (Sym.algo 7,8,9).
* Added `OpenPGP.encode_packet/1` that delegate to `OpenPGP.Encode` protocol.
* Added `OpenPGP.encrypt_packet/1,2` that delegate to `OpenPGP.Encrypt` protocol.
* Add ElGamal algorithm support to `OpenPGP.PublicKeyPacket.decode/1`.
* Introduced `OpenPGP.ModificationDetectionCodePacket`.
* Introduced `OpenPGP.Util.PKCS1` with PKCS#1 block encoding EME-PKCS1-v1_5.
* Refactored `OpenPGP.Util.encode_mpi/1` and added exception for too long big-endian numbers (>65535 octets).
