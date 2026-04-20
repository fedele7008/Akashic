package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewEngineGenerateRootCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "root",
		Short: "Generate self-signed root CA certificates",
		Long:  "Generate self-signed root CA certificates from Vault PKI engines.",
	}

	cmd.AddCommand(NewEngineGenerateRootInternalCmd(ctx))

	return cmd
}
