package cmd

import (
	"akashic/akashic/pkg/cli/core"
	"fmt"

	"github.com/spf13/cobra"
)

func NewRootCmd() *cobra.Command {
	ctx := core.NewCliContext()
	cmd := &cobra.Command{
		Use:               RootCmd,
		Short:             fmt.Sprintf(FmtRootCmdShort, Version),
		Long:              fmt.Sprintf(FmtRootCmdLong, Version),
		Version:           Version,
		Example:           FmtRootExamples,
		PersistentPreRunE: ctx.Init,
	}

	// Register persistent flags
	core.RegisterFlags(cmd, core.FilterCliConfig(core.Verbose)...)

	// Add subcommands
	cmd.AddCommand(NewPkiCmd(ctx))
	cmd.AddCommand(NewConfigureCmd(ctx))
	cmd.AddCommand(NewBootstrapCmd(ctx))

	// SilenceUsage: don't dump full help on every RunE error.
	// SilenceErrors: HandleExitError prints; cobra shouldn't double-print.
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	return cmd
}

const (
	RootCmd         = "akashic-cli"
	Version         = "0.0.2"
	FmtRootCmdShort = "Akashic CLI %s - Administrative tool for Akashic server"
	FmtRootCmdLong  = `Akashic CLI %s is a command-line tool for managing the Akashic server.

It connects to the Akashic control plane API (default: http://localhost:8081)
and allows you to perform administrative tasks such as:

- Bootstrap root user creation
- User management (create, list, disable, enable)
- Server control (start, stop, restart, status)
- Configuration management (view, reload)
`
	FmtRootExamples = `# Check bootstrap status
akashic-cli bootstrap status

# Create root user (during bootstrap)
akashic-cli bootstrap create-root --token <token> --username root --email root@example.com

# Create an admin user
akashic-cli user create --username admin --email admin@example.com --type admin

# List all users
akashic-cli user list

# Check server status
akashic-cli server status

# Restart auth server
akashic-cli server restart`
)
