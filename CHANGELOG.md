# Changelog

## v0.6.0

### Enhancements

* Add encoding feature to:
  * `OpenPGP.LiteralDataPacket.encode/1,2`
  * `OpenPGP.Packet.encode/1`
  * `OpenPGP.Packet.PacketTag.encode/1`
  * `OpenPGP.Packet.BodyChunk.encode/1`
* Add ElGamal algorithm support to `OpenPGP.PublicKeyPacket.decode/1`.
* Refactored `OpenPGP.Util.encode_mpi/1` and added exception for too long big-endian numbers (>65535 octets).
