package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewVaultUnsealCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unseal",
		Short: "Unseal Vault with intelligent key discovery",
		Long: `Unseal Akashic's PKI vault using Hashicorp Vault with SAT-based intelligent key discovery.

This command uses Boolean satisfiability (SAT) solving to efficiently find valid unseal key
combinations. By learning from failed attempts, it dramatically reduces the number of vault
queries needed compared to brute-force searching.

Features:
  - Intelligent key discovery using PB-SAT (Pseudo-Boolean SAT) solver
  - Incremental learning from failed attempts to prune the search space
  - Backbone analysis to classify keys as definitely real, fake, or undetermined
  - Support for both auto-unseal mode (default) and manual once mode (--once)

The default mode uses SAT-based search to automatically find valid key combinations. Use
--once flag to disable intelligent search and test each key individually instead.`,
		Args: cobra.ArbitraryArgs,
		RunE: ctx.RunPkiVaultUnsealCmd,
	}
	// Register persistent flags
	core.RegisterFlags(cmd, core.FilterCliConfig(
		core.Secret,
		core.SecretPath,
		core.TokenFilesIn,
		core.VaultUnsealOnce,
	)...)

	return cmd
}
