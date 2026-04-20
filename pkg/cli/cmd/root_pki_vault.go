package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewVaultCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Manage Akashic's PKI vault",
		Long:  "Manage Akashic's PKI vault using Hashicorp Vault.",
	}

	// Register persistent flags
	core.RegisterFlags(cmd, core.FilterCliConfig(
		core.VaultAddress,
		core.VaultCACert,
	)...)

	// Add subcommands
	cmd.AddCommand(NewVaultStatusCmd(ctx))
	cmd.AddCommand(NewVaultInitCmd(ctx))
	cmd.AddCommand(NewVaultUnsealCmd(ctx))
	cmd.AddCommand(NewEngineCmd(ctx))

	return cmd
}
