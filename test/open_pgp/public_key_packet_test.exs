defmodule OpenPGP.PublicKeyPacketTest do
  use OpenPGP.Test.Case, async: true
  alias OpenPGP.Packet
  alias OpenPGP.Packet.PacketTag
  alias OpenPGP.PublicKeyPacket

  @rsa2048_priv File.read!("test/fixtures/rsa2048-priv.pgp")
  @elg2048_pub File.read!("test/fixtures/elg2048-pub.pgp")

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

  test ".decode/1 decodes ELG Public-Key (sub-key) packet" do
    packet = @elg2048_pub |> OpenPGP.list_packets() |> Enum.at(3)

    assert %Packet{body: chunks, tag: %PacketTag{tag: {14, "Public-Subkey Packet"}}} = packet

    data = OpenPGP.Util.concat_body(chunks)

    assert {%PublicKeyPacket{
              algo: {16, "Elgamal (Encrypt-Only) [ELGAMAL] [HAC]"},
              created_at: ~U[2025-01-30 20:51:55Z],
              expires: nil,
              material: {prime_p, group_g, value_y},
              version: 4
            }, <<>>} = PublicKeyPacket.decode(data)

    assert "95288533E970D6FB1D923EEBBF723EA3CD52C4AB20EBDE0D9DC5E3E40FF609BC65BFA28EB65" <>
             "8EC5C44E08444B8C4AF67AA4B96457453CA773518766C1E536084AA1DCCEFC5006D670552" <>
             "EC704AFC4830DF50BF67AA14F0A1E8C6A8CBE27E5AEB64AC6FA264F802B8821B10302F627" <>
             "960AC39F4DA87A584A98F4D07341C3F1294FE99E18BAC766D464D98C96DE9F79CC462D4D7" <>
             "A8B6F818CB88DDF0BD100B97C7E38F37FCAAE231775EF03DC431A72C071EA0E86D2A1C73F" <>
             "3A74D2A9B977AD0FC44CDCCD09C54091879191757581AC095A56E7D8BD7F59B9F5C34139C" <>
             "E317C900D327F8601CC9ECF4A5F4073668D44C9A507A7624B06852DA20EF2C56A930EECF" ==
             Base.encode16(prime_p)

    assert "0B" == Base.encode16(group_g)

    assert "5D04024065BF1E52E7BCA39CCD6D4FE6BB0DA4E631094A84B0508014441AB8AE421FC87A7B9" <>
             "49B01269CA968653B237FD5BE3A9CB24BC3E86F2C88CA8738001184829DBBD2AB73B1B5EF" <>
             "BC6748F60A030C7B1257397786072541CBA2CD367627DE24E2B396027D156C38F786B71FD" <>
             "8D544DCA8F73E17339019E56B092445F9BBA373CE41435EA525EDA0356DB14886705195D7" <>
             "335859C9B16D3599DECA2C1070B9E2FEE983BF1A42CC4B48740A3903FA59762733384E17A" <>
             "BB918F06DB37877E594D6C04CC28BE1EF9D6011E0655716CA507DEABDCA6E23B08079F915" <>
             "2CAC73CCC53706BE856E26D02D0A7F1AB8122614E91000F5EB1B240F50C66D9048F861D3" ==
             Base.encode16(value_y)
  end
end
