package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewVaultApproleCreateCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <role-name>",
		Short: "Create an AppRole role",
		Long: `Create an AppRole role with the specified configuration.

Configuration is merged from three sources (lowest to highest priority):
  1. Defaults: {"token_period": "768h", "secret_id_ttl": "0", "bind_secret_id": true}
  2. Config file (--config-file / -f): overrides matching fields
  3. Inline config (--config): overrides matching fields

If the role already exists, the command succeeds with a message.

Example:
  akashic-cli pki vault approle create cert-agent -f role-config.json -t token.enc
  akashic-cli pki vault approle create cert-agent --config '{"token_policies":["cert-issuer"]}' -t token.enc`,
		Args: cobra.ExactArgs(1),
		RunE: ctx.RunPkiVaultApproleCreateCmd,
	}

	core.RegisterFlags(cmd, core.FilterCliConfig(
		core.Secret,
		core.SecretPath,
		core.VaultRootTokenFile,
		core.EngineConfigFile,
		core.EngineConfig,
	)...)

	return cmd
}
