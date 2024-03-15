# credo:disable-for-next-line CredoNaming.Check.Consistency.ModuleFilename
defmodule OpenPGP.S2KSpecifierTest do
  use OpenPGP.Test.Case, async: true
  alias OpenPGP.S2KSpecifier

  @salt "**SALT**"

  describe ".decode/1" do
    test "decodes Simple S2K (ID: 0)" do
      input = <<0::8, 2::8, "rest"::binary>>

      assert {%S2KSpecifier{
                id: {0, "Simple S2K"},
                algo: {2, "SHA-1 [FIPS180]"},
                protect_count: nil,
                salt: nil
              }, "rest"} = S2KSpecifier.decode(input)
    end

    test "decodes Salted S2K (ID: 1)" do
      input = <<1::8, 2::8, @salt, "rest"::binary>>

      assert {%S2KSpecifier{
                id: {1, "Salted S2K"},
                algo: {2, "SHA-1 [FIPS180]"},
                protect_count: nil,
                salt: @salt
              }, "rest"} = S2KSpecifier.decode(input)
    end

    @coded_protect_count 252
    test "decodes Iterated and Salted S2K (ID: 3)" do
      input = <<3::8, 2::8, @salt, @coded_protect_count::8, "rest"::binary>>

      assert {%S2KSpecifier{
                id: {3, "Iterated and Salted S2K"},
                algo: {2, "SHA-1 [FIPS180]"},
                protect_count: {@coded_protect_count, 58_720_256},
                salt: @salt
              }, "rest"} = S2KSpecifier.decode(input)
    end

    test "decodes Reserved value (ID: 2)" do
      input = <<2::8, "rest"::binary>>

      assert {%S2KSpecifier{
                id: {2, "Reserved value"},
                algo: nil,
                protect_count: nil,
                salt: nil
              }, "rest"} = S2KSpecifier.decode(input)
    end

    test "decodes Private/Experimental S2K (ID: 105)" do
      input = <<105::8, "rest"::binary>>

      assert {%S2KSpecifier{
                id: {105, "Private/Experimental S2K"},
                algo: nil,
                protect_count: nil,
                salt: nil
              }, "rest"} = S2KSpecifier.decode(input)
    end
  end

  describe ".build_session_key/3" do
    @s2k_specifier %S2KSpecifier{
      id: {3, "Iterated and Salted S2K"},
      algo: {2, "SHA-1 [FIPS180]"},
      protect_count: {252, 58_720_256},
      salt: @salt
    }

    test "builds 128 bits session key" do
      session_key = S2KSpecifier.build_session_key(@s2k_specifier, 128, "passphrase")
      assert bit_size(session_key) == 128
      assert "D291546EBA8ECB8242048C10FED0BC81" = Base.encode16(session_key)
    end

    test "builds 192 bits session key" do
      session_key = S2KSpecifier.build_session_key(@s2k_specifier, 192, "passphrase")
      assert bit_size(session_key) == 192
      assert "D291546EBA8ECB8242048C10FED0BC8156291EBDDB7ED000" = Base.encode16(session_key)
    end

    test "builds 256 bits session key" do
      session_key = S2KSpecifier.build_session_key(@s2k_specifier, 256, "passphrase")
      assert bit_size(session_key) == 256

      assert "D291546EBA8ECB8242048C10FED0BC8156291EBDDB7ED000EEBA925CF485D825" = Base.encode16(session_key)
    end
  end
end
