defmodule OpenPGP.Test.Case do
  @moduledoc false

  use ExUnit.CaseTemplate

  using do
    quote do
      import OpenPGP.Test.Case
    end
  end
end
