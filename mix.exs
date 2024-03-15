defmodule OpenPGP.MixProject do
  use Mix.Project

  @source_url "https://github.com/DivvyPayHQ/open_pgp"
  @version "0.5.0"
  @description "OpenPGP Message Format in Elixir - RFC4880"

  def project() do
    [
      app: :open_pgp,
      version: @version,
      elixir: "~> 1.13",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      description: @description,
      package: package(),
      deps: deps(),
      name: "OpenPGP",
      source_url: @source_url,
      consolidate_protocols: Mix.env() != :test,
      elixirc_paths: elixirc_paths(Mix.env()),
      dialyzer: dialyzer(),
      preferred_cli_env: [docs: :docs],
      docs: docs()
    ]
  end

  def application() do
    [
      extra_applications: [:crypto]
    ]
  end

  defp package do
    [
      maintainers: ["Pavel Tsiukhtsiayeu"],
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      source_url: @source_url,
      files: ["lib", "*.exs", "*.md"]
    ]
  end

  defp docs() do
    [
      source_ref: "v#{@version}",
      source_url: @source_url,
      canonical: "http://hexdocs.pm/open_pgp",
      main: "readme",
      name: "OpenPGP",
      extras: ["README.md", "LICENSE.md", "CODE_OF_CONDUCT.md", "CHANGELOG.md"],
      groups_for_modules: [
        "Generic Packet": [
          OpenPGP.Packet,
          OpenPGP.Packet.BodyChunk,
          OpenPGP.Packet.PacketTag
        ],
        "Tag Specific Packets": [
          OpenPGP.CompressedDataPacket,
          OpenPGP.IntegrityProtectedDataPacket,
          OpenPGP.LiteralDataPacket,
          OpenPGP.PublicKeyEncryptedSessionKeyPacket,
          OpenPGP.PublicKeyPacket,
          OpenPGP.SecretKeyPacket
        ],
        "Radix-64": [
          OpenPGP.Radix64,
          OpenPGP.Radix64.CRC24,
          OpenPGP.Radix64.Entry
        ]
      ]
    ]
  end

  defp deps() do
    [
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.30", only: [:docs], runtime: false}
    ]
  end

  defp dialyzer() do
    [
      ignore_warnings: ".dialyzer_ignore.exs",
      list_unused_filters: true,
      plt_add_apps: [:mix, :ex_unit]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end
