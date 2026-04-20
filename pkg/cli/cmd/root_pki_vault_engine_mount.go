package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewEngineMountCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mount <path>",
		Short: "Mount a PKI secret engine",
		Long: `Mount a PKI secret engine at the specified path in Vault.

This command requires a Vault root token for authentication.
The root token will be decrypted from an encrypted token file using AKASHIC_SECRET.
If the engine is already mounted at the specified path, the command succeeds with a message.

Configuration is merged from three sources (lowest to highest priority):
  1. Defaults: {"max_lease_ttl": "8760h"}
  2. Config file (--config-file / -f): overrides matching fields
  3. Inline config (--config): overrides matching fields`,
		Args: cobra.ExactArgs(1),
		RunE: ctx.RunPkiVaultEngineMountCmd,
	}

	core.RegisterFlags(cmd, core.FilterCliConfig(
		core.Secret,
		core.SecretPath,
		core.EngineDescription,
		core.EngineConfigFile,
		core.EngineConfig,
		core.VaultRootTokenFile,
	)...)

	return cmd
}
