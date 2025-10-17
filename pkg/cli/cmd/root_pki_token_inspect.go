package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewTokenInspectCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect secure token",
		Long:  "Inspect secure token.",
		Args:  cobra.ArbitraryArgs,
		RunE:  ctx.RunTokenInspectCmd,
	}

	// Register persistent flags
	core.RegisterFlags(cmd, core.FilterCliConfig(
		core.Secret,
		core.SecretPath,
		core.TokenFilesIn,
		core.MinimumOutput,
	)...)

	return cmd
}
