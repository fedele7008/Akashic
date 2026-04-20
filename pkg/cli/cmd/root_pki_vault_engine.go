package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewEngineCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "engine",
		Short: "Manage Vault secret engines",
		Long:  "Manage Akashic's PKI Vault secret engines.",
	}

	cmd.AddCommand(NewEngineMountCmd(ctx))
	cmd.AddCommand(NewEngineGenerateCmd(ctx))

	return cmd
}
