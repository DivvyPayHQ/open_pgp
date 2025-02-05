# Changelog

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
* Added `OpenPGP.IntegrityProtectedDataPacket.ecrypt/3,4` with AES-128, AES-192, AES-256 (Sym.algo 7,8,9).
* Added `OpenPGP.PublicKeyEncryptedSessionKeyPacket.ecrypt/4` with Elgamal (Public-Key algo 16).
* Added `OpenPGP.encode_packet/1` that delegate to `OpenPGP.Encode` protocol.
* Add ElGamal algorithm support to `OpenPGP.PublicKeyPacket.decode/1`.
* Introduced `OpenPGP.ModificationDetectionCodePacket`.
* Introduced `OpenPGP.Util.PKCS1` with PKCS#1 block encoding EME-PKCS1-v1_5.
* Refactored `OpenPGP.Util.encode_mpi/1` and added exception for too long big-endian numbers (>65535 octets).
