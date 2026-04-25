package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

// NewBootstrapCmd is the parent of `akashic-cli bootstrap ...`.
// Subcommands talk to the control plane's /bootstrap/* endpoints using
// the active configure profile (or --profile <name>).
func NewBootstrapCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Manage Akashic's first-time bootstrap (root user creation)",
		Long: `Manage Akashic's first-time bootstrap (root user creation).

Bootstrap is a one-time process that creates the very first root user on a
fresh Akashic deployment. Once complete, these endpoints are permanently
closed; further admin-user creation goes through the regular admin UI.

A profile (added via 'akashic-cli configure add') is required so the CLI
knows where to connect and how to authenticate over mTLS.`,
	}
	// --profile is a persistent flag on the bootstrap command tree so
	// every subcommand picks it up the same way.
	cmd.PersistentFlags().String("profile", "", "configure profile to use (default: active)")
	cmd.AddCommand(NewBootstrapStatusCmd(ctx))
	cmd.AddCommand(NewBootstrapTokenCmd(ctx))
	cmd.AddCommand(NewBootstrapCreateRootCmd(ctx))
	return cmd
}
