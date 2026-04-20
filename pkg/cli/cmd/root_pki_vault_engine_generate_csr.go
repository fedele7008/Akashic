package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewEngineGenerateCsrCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "csr",
		Short: "Generate Certificate Signing Requests",
		Long:  "Generate Certificate Signing Requests (CSRs) from Vault PKI engines.",
	}

	cmd.AddCommand(NewEngineGenerateCsrInternalCmd(ctx))

	return cmd
}
