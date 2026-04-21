package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewVaultAuthCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage Vault auth methods",
		Long:  "Enable and manage Vault authentication methods.",
	}

	cmd.AddCommand(NewVaultAuthEnableCmd(ctx))

	return cmd
}
