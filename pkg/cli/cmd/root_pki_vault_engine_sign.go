package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewEngineSignCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign certificates",
		Long:  "Sign certificates using Vault PKI engines.",
	}

	cmd.AddCommand(NewEngineSignIntermediateCmd(ctx))

	return cmd
}
