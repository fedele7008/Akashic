package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewVaultApproleCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approle",
		Short: "Manage Vault AppRole authentication",
		Long: `Manage Vault AppRole roles, role-ids, and secret-ids.

AppRole is a machine-oriented auth method that uses role-id and secret-id
credentials for authentication. This is the recommended method for automated
services like Vault Agent.`,
	}

	cmd.AddCommand(NewVaultApproleCreateCmd(ctx))
	cmd.AddCommand(NewVaultApproleRoleIdCmd(ctx))
	cmd.AddCommand(NewVaultApproleSecretIdCmd(ctx))

	return cmd
}
