package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewEngineGenerateCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate certificates and CSRs",
		Long:  "Generate certificates and Certificate Signing Requests from Vault PKI engines.",
	}

	cmd.AddCommand(NewEngineGenerateCsrCmd(ctx))
	cmd.AddCommand(NewEngineGenerateRootCmd(ctx))

	return cmd
}
