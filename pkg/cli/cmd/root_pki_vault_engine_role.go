package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewEngineRoleCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "role",
		Short: "Manage PKI engine roles",
		Long:  "Manage roles on Vault PKI engines. Roles define certificate issuance policies.",
	}

	cmd.AddCommand(NewEngineRoleCreateCmd(ctx))

	return cmd
}
