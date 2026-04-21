package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewVaultApproleRoleIdCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "role-id <role-name>",
		Short: "Read the role-id for an AppRole",
		Long: `Read the role-id for the specified AppRole role.

The role-id is a stable identifier for the role. It acts like a "username"
in the AppRole auth flow. The role-id can be written to a file with -o.

Example:
  akashic-cli pki vault approle role-id cert-agent -t token.enc
  akashic-cli pki vault approle role-id cert-agent -t token.enc -o /path/to/role-id`,
		Args: cobra.ExactArgs(1),
		RunE: ctx.RunPkiVaultApproleRoleIdCmd,
	}

	core.RegisterFlags(cmd, core.FilterCliConfig(
		core.Secret,
		core.SecretPath,
		core.VaultRootTokenFile,
		core.ApproleOutput,
	)...)

	return cmd
}
