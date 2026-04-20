package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewEngineConfigCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Configure PKI engine settings",
		Long:  "Configure settings on Vault PKI engines.",
	}

	cmd.AddCommand(NewEngineConfigUrlsCmd(ctx))

	return cmd
}
