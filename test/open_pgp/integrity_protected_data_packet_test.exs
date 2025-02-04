defmodule OpenPGP.IntegrityProtectedDataPacketTest do
  use OpenPGP.Test.Case, async: true
  doctest OpenPGP.IntegrityProtectedDataPacket

  alias OpenPGP.IntegrityProtectedDataPacket, as: IPDPacket
  alias OpenPGP.PublicKeyEncryptedSessionKeyPacket, as: PKESK

  describe ".encrypt/2,3" do
    @algo {7, "AES with 128-bit key [AES]"}
    test "encrypt plaintext with AES-128" do
      assert {ciphertext, sym_key} = IPDPacket.encrypt("Hello!", @algo, use_mdc: true)

      assert %IPDPacket{plaintext: "Hello!"} =
               IPDPacket.decrypt(
                 %IPDPacket{ciphertext: ciphertext},
                 %PKESK{session_key_algo: @algo, session_key_material: {sym_key}},
                 use_mdc: true
               )
    end

    @algo {8, "AES with 192-bit key"}
    test "encrypt plaintext with AES-192" do
      assert {ciphertext, sym_key} = IPDPacket.encrypt("Hello!", @algo, use_mdc: true)

      assert %IPDPacket{plaintext: "Hello!"} =
               IPDPacket.decrypt(
                 %IPDPacket{ciphertext: ciphertext},
                 %PKESK{session_key_algo: @algo, session_key_material: {sym_key}},
                 use_mdc: true
               )
    end

    @algo {9, "AES with 256-bit key"}
    test "encrypt plaintext with AES-256" do
      assert {ciphertext, sym_key} = IPDPacket.encrypt("Hello!", @algo, use_mdc: true)

      assert %IPDPacket{plaintext: "Hello!"} =
               IPDPacket.decrypt(
                 %IPDPacket{ciphertext: ciphertext},
                 %PKESK{session_key_algo: @algo, session_key_material: {sym_key}},
                 use_mdc: true
               )
    end

    @algo {7, "AES with 128-bit key [AES]"}
    test "encrypt plaintext with AES-128 and no MDC" do
      assert {ciphertext, sym_key} = IPDPacket.encrypt("Hello!", @algo, use_mdc: false)

      assert %IPDPacket{plaintext: "Hello!"} =
               IPDPacket.decrypt(
                 %IPDPacket{ciphertext: ciphertext},
                 %PKESK{session_key_algo: @algo, session_key_material: {sym_key}},
                 use_mdc: false
               )
    end

    @algo {7, "AES with 128-bit key [AES]"}
    test "encrypt plaintext with AES-128 and no MDC (default behavior of .decrypt/2)" do
      assert {ciphertext, sym_key} = IPDPacket.encrypt("Hello!", @algo, use_mdc: false)

      assert %IPDPacket{plaintext: "Hello!"} =
               IPDPacket.decrypt(
                 %IPDPacket{ciphertext: ciphertext},
                 %PKESK{session_key_algo: @algo, session_key_material: {sym_key}}
               )
    end
  end
end
