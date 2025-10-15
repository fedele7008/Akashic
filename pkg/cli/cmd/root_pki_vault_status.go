package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewVaultStatusCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check Akashic's PKI vault",
		Long:  "Check Akashic's PKI vault using Hashicorp Vault.",
		RunE:  ctx.RunPkiVaultStatusCmd,
	}

	return cmd
}
