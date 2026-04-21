package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewVaultAuthEnableCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enable <auth-type>",
		Short: "Enable a Vault auth method",
		Long: `Enable a Vault authentication method at its default path.

If the auth method is already enabled, the command succeeds with a message.

Supported types: approle, token, userpass, ldap, etc.

Example:
  akashic-cli pki vault auth enable approle -t token.enc
  akashic-cli pki vault auth enable approle -t token.enc -d "AppRole for services"`,
		Args: cobra.ExactArgs(1),
		RunE: ctx.RunPkiVaultAuthEnableCmd,
	}

	core.RegisterFlags(cmd, core.FilterCliConfig(
		core.Secret,
		core.SecretPath,
		core.VaultRootTokenFile,
		core.EngineDescription,
	)...)

	return cmd
}
