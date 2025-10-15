package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewTokenCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Manage Akashic's Secure Token",
		Long:  "Manage Akashic's Secure Token.",
	}

	// Add subcommands
	cmd.AddCommand(NewTokenInspectCmd(ctx))

	return cmd
}
