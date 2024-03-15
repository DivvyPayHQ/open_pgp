defmodule OpenPGP.PublicKeyPacketTest do
  use OpenPGP.Test.Case, async: true
  alias OpenPGP.Packet
  alias OpenPGP.Packet.PacketTag
  alias OpenPGP.PublicKeyPacket

  @rsa2048_priv File.read!("test/fixtures/rsa2048-priv.pgp")

  test ".decode/1 decodes RSA Public-Key packet" do
    assert [%Packet{body: chunks, tag: %PacketTag{tag: {5, "Secret-Key Packet"}}} | _] =
             OpenPGP.list_packets(@rsa2048_priv)

    data = OpenPGP.Util.concat_body(chunks)

    assert {%PublicKeyPacket{
              algo: {1, "RSA (Encrypt or Sign) [HAC]"},
              created_at: ~U[2024-01-02 18:03:04Z],
              expires: nil,
              material: {mod_n, exp_e},
              version: 4
            }, rest} = PublicKeyPacket.decode(data)

    assert <<254, 7, 3, 2, 248, 49, 205, 223, 27, 66, 166, 109, _::binary>> = rest

    assert "DDB1B5BEE3E4ECB4F0A0885311274C25F9A343B4458E186246E3C0DE69E0433AF6559B2F4" <>
             "86AAF0EABD3206E51B785E841AC52CC123B7F4DE80ECD474E5873598481C930A87BD65E" <>
             "1BB622F5B2AD66638C650997F104FEC7A4246BC00E461152D13A9C34344C6038CAE6BED" <>
             "89DF7E15CA3AF11CCB290B530E00A78C026C91119FC6DAA06C7E6CD44DA7A6C5D05E938" <>
             "4E91F7F0A8F4839144B321BE1EC6351142213F871B8807337FF4AF468DA22E7BAC94C51" <>
             "CE1B29B2A3971C6E4DC70A126D2812815C0829F4A3072AD4FDB4299CA01A4FC1996E56B" <>
             "7CE33CC3219ABB9B2BE063748BB428493E2DAD4D459A71E862B6E2CF23EB44EB5583F1F" <>
             "1FC385C19B1F9" == Base.encode16(mod_n)

    assert "010001" == Base.encode16(exp_e)
  end
end
