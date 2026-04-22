package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewVaultUserpassCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "userpass",
		Short: "Manage Vault userpass authentication",
		Long:  "Create and manage Vault userpass accounts for human operators.",
	}

	cmd.AddCommand(NewVaultUserpassCreateCmd(ctx))

	return cmd
}
