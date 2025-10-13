package akashic

import (
	"akashic/akashic/pkg/command/akashic/core"
	"akashic/akashic/pkg/config"

	"github.com/spf13/cobra"
)

func NewRunCmd() *cobra.Command {
	app := core.NewAkashicApp()

	runCmd := &cobra.Command{
		Use:               RunCmd,
		Short:             RunCmdShort,
		Long:              RunCmdLong,
		PersistentPreRunE: app.Init,
		RunE:              app.Run,
	}

	// Register server-specific flags on run command
	config.RegisterFlags(runCmd)

	return runCmd
}
