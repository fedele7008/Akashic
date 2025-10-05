package command

import (
	"akashic/akashic/pkg/akashic"
	"akashic/akashic/pkg/config"

	"github.com/spf13/cobra"
)

func NewRunCmd() *cobra.Command {
	app := akashic.NewAkashicApp()

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
