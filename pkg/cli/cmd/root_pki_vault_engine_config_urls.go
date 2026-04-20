package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewEngineConfigUrlsCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "urls",
		Short: "Configure CRL and CA URLs on a PKI engine",
		Long: `Configure the CRL Distribution Points and Issuing CA URLs on a PKI engine.

These URLs are embedded into every certificate issued by the engine.
Defaults to http://localhost:8280/v1/{engine}/crl and .../ca if no config provided.

Users can override with custom URLs for production (e.g., behind nginx with custom DNS).

Configuration is merged from three sources (lowest to highest priority):
  1. Defaults: auto-generated from engine name using localhost:8280
  2. Config file (--config-file / -f): overrides matching fields
  3. Inline config (--config): overrides matching fields`,
		Args: cobra.NoArgs,
		RunE: ctx.RunPkiVaultEngineConfigUrlsCmd,
	}

	core.RegisterFlags(cmd, core.FilterCliConfig(
		core.Secret,
		core.SecretPath,
		core.VaultRootTokenFile,
		core.EngineConfigFile,
		core.EngineConfig,
		core.EngineName,
		core.PkiCrlBaseUrl,
	)...)

	return cmd
}
