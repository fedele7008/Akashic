package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewPkiCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pki",
		Short: "Manage Akashic PKI certificates",
		Long:  `Manage Akashic PKI certificates using Hashicorp Vault.`,
	}

	// Add subcommands
	cmd.AddCommand(NewVaultCmd(ctx))
	cmd.AddCommand(NewTokenCmd(ctx))

	return cmd
}
