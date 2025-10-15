package cmd

import (
	"akashic/akashic/pkg/akashic/core"
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

const (
	RunCmd      = "run"
	RunCmdShort = "Start the Akashic server"
	RunCmdLong  = `Start the Akashic server with auth and control plane endpoints.

The run command initializes and starts both the authentication server (OAuth/OIDC)
and the control server (management API). By default, both servers start automatically
unless the --no-auto-start flag is provided.`
)
