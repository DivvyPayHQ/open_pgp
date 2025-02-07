defmodule OpenPGP.IntegrityProtectedDataPacketTest do
  use OpenPGP.Test.Case, async: true
  doctest OpenPGP.IntegrityProtectedDataPacket
  doctest OpenPGP.Encode.impl_for!(%OpenPGP.IntegrityProtectedDataPacket{})

  alias OpenPGP.Encrypt
  alias OpenPGP.IntegrityProtectedDataPacket, as: IPDPacket
  alias OpenPGP.PublicKeyEncryptedSessionKeyPacket, as: PKESK

  describe ".decrypt/2" do
    @expected_error "Failed to parse Modification Detection Code Packet."
    @algo {7, "AES with 128-bit key [AES]"}
    test "raise error if MDC is missing when `use_mdc: true`" do
      sym_key = :crypto.strong_rand_bytes(16)

      assert %IPDPacket{ciphertext: ciphertext} =
               Encrypt.encrypt(%IPDPacket{plaintext: "Hello!"},
                 session_key: sym_key,
                 session_key_algo: @algo,
                 use_mdc: false
               )

      assert_raise RuntimeError, @expected_error, fn ->
        %IPDPacket{plaintext: "Hello!"} =
          IPDPacket.decrypt(
            %IPDPacket{ciphertext: ciphertext},
            %PKESK{session_key_algo: @algo, session_key_material: {sym_key}},
            use_mdc: true
          )
      end
    end
  end

  describe "OpenPGP.Encrypt.encrypt/2" do
    @algo {7, "AES with 128-bit key [AES]"}
    test "encrypt plaintext with AES-128" do
      sym_key = :crypto.strong_rand_bytes(16)

      assert %IPDPacket{ciphertext: ciphertext} =
               Encrypt.encrypt(%IPDPacket{plaintext: "Hello!"},
                 session_key: sym_key,
                 session_key_algo: @algo,
                 use_mdc: true
               )

      assert %IPDPacket{plaintext: "Hello!"} =
               IPDPacket.decrypt(
                 %IPDPacket{ciphertext: ciphertext},
                 %PKESK{session_key_algo: @algo, session_key_material: {sym_key}},
                 use_mdc: true
               )
    end

    @algo {8, "AES with 192-bit key"}
    test "encrypt plaintext with AES-192" do
      sym_key = :crypto.strong_rand_bytes(24)

      assert %IPDPacket{ciphertext: ciphertext} =
               Encrypt.encrypt(%IPDPacket{plaintext: "Hello!"},
                 session_key: sym_key,
                 session_key_algo: @algo,
                 use_mdc: true
               )

      assert %IPDPacket{plaintext: "Hello!"} =
               IPDPacket.decrypt(
                 %IPDPacket{ciphertext: ciphertext},
                 %PKESK{session_key_algo: @algo, session_key_material: {sym_key}},
                 use_mdc: true
               )
    end

    @algo {9, "AES with 256-bit key"}
    test "encrypt plaintext with AES-256" do
      sym_key = :crypto.strong_rand_bytes(32)

      assert %IPDPacket{ciphertext: ciphertext} =
               Encrypt.encrypt(%IPDPacket{plaintext: "Hello!"},
                 session_key: sym_key,
                 session_key_algo: @algo,
                 use_mdc: true
               )

      assert %IPDPacket{plaintext: "Hello!"} =
               IPDPacket.decrypt(
                 %IPDPacket{ciphertext: ciphertext},
                 %PKESK{session_key_algo: @algo, session_key_material: {sym_key}},
                 use_mdc: true
               )
    end

    @algo {7, "AES with 128-bit key [AES]"}
    test "encrypt plaintext with AES-128 and no MDC" do
      sym_key = :crypto.strong_rand_bytes(16)

      assert %IPDPacket{ciphertext: ciphertext} =
               Encrypt.encrypt(%IPDPacket{plaintext: "Hello!"},
                 session_key: sym_key,
                 session_key_algo: @algo,
                 use_mdc: false
               )

      assert %IPDPacket{plaintext: "Hello!"} =
               IPDPacket.decrypt(
                 %IPDPacket{ciphertext: ciphertext},
                 %PKESK{session_key_algo: @algo, session_key_material: {sym_key}},
                 use_mdc: false
               )
    end

    @algo {7, "AES with 128-bit key [AES]"}
    test "encrypt plaintext with AES-128 and no MDC (default behavior of .decrypt/2)" do
      sym_key = :crypto.strong_rand_bytes(16)

      assert %IPDPacket{ciphertext: ciphertext} =
               Encrypt.encrypt(%IPDPacket{plaintext: "Hello!"},
                 session_key: sym_key,
                 session_key_algo: @algo,
                 use_mdc: false
               )

      assert %IPDPacket{plaintext: "Hello!"} =
               IPDPacket.decrypt(
                 %IPDPacket{ciphertext: ciphertext},
                 %PKESK{session_key_algo: @algo, session_key_material: {sym_key}}
               )
    end
  end
end
