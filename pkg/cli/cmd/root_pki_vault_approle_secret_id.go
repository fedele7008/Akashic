package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewVaultApproleSecretIdCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret-id <role-name>",
		Short: "Generate a secret-id for an AppRole",
		Long: `Generate a new secret-id for the specified AppRole role.

The secret-id acts like a "password" in the AppRole auth flow. Each call
generates a new secret-id. The secret-id can be written to a file with -o.

WARNING: The secret-id is sensitive. Protect it like a password.

Example:
  akashic-cli pki vault approle secret-id cert-agent -t token.enc
  akashic-cli pki vault approle secret-id cert-agent -t token.enc -o /path/to/secret-id`,
		Args: cobra.ExactArgs(1),
		RunE: ctx.RunPkiVaultApproleSecretIdCmd,
	}

	core.RegisterFlags(cmd, core.FilterCliConfig(
		core.Secret,
		core.SecretPath,
		core.VaultRootTokenFile,
		core.ApproleOutput,
	)...)

	return cmd
}
