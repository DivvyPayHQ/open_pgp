defmodule OpenPGP.PacketTest do
  use OpenPGP.Test.Case, async: true
  doctest OpenPGP.Packet
  doctest OpenPGP.Encode.impl_for!(%OpenPGP.Packet{})
end
