package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewVaultUnsealCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unseal",
		Short: "Unseal Vault",
		Long:  "Unseal Akashic's PKI vault using Hashicorp Vault.",
		Args:  cobra.ArbitraryArgs,
		RunE:  ctx.RunPkiVaultUnsealCmd,
	}
	// Register persistent flags
	core.RegisterFlags(cmd, core.FilterCliConfig(
		core.Secret,
		core.SecretPath,
		core.TokenFilesIn,
	)...)

	return cmd
}
