# Changelog

## v0.6.0

### Enhancements

* Add encoding feature to:
  * `OpenPGP.IntegrityProtectedDataPacket.encode/1`
  * `OpenPGP.LiteralDataPacket.encode/1,2`
  * `OpenPGP.Packet.encode/1`
  * `OpenPGP.Packet.PacketTag.encode/1`
  * `OpenPGP.Packet.BodyChunk.encode/1`
* Added `OpenPGP.IntegrityProtectedDataPacket.ecrypt/2,3` with AES-128, AES-192, AES-256 (Sym.algo 7,8,9)
* Add ElGamal algorithm support to `OpenPGP.PublicKeyPacket.decode/1`.
* Introduced `OpenPGP.ModificationDetectionCodePacket`
* Refactored `OpenPGP.Util.encode_mpi/1` and added exception for too long big-endian numbers (>65535 octets).
