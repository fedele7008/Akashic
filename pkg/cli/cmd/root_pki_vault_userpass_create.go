package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewVaultUserpassCreateCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <username>",
		Short: "Create a userpass account",
		Long: `Create a userpass account in Vault for human operator access.

The password can be provided via --password flag or AKASHIC_VAULT_PASSWORD env var.

Configuration is merged from three sources (lowest to highest priority):
  1. Defaults: {"token_policies": []}
  2. Config file (--config-file / -f): overrides matching fields
  3. Inline config (--config): overrides matching fields

If the user already exists, the command succeeds with a message.

Example:
  akashic-cli pki vault userpass create admin --password secret --config '{"token_policies":["admin"]}' -t token.enc`,
		Args: cobra.ExactArgs(1),
		RunE: ctx.RunPkiVaultUserpassCreateCmd,
	}

	core.RegisterFlags(cmd, core.FilterCliConfig(
		core.Secret,
		core.SecretPath,
		core.VaultRootTokenFile,
		core.EngineConfigFile,
		core.EngineConfig,
		core.UserpassPassword,
	)...)

	return cmd
}
