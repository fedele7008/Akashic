package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

// NewConfigureCmd is the parent of the `akashic-cli configure ...` family.
// Subcommands manage ~/.akashic/config.yaml and the per-profile cert files
// under ~/.akashic/certs/<name>/.
func NewConfigureCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Manage akashic-cli connection profiles",
		Long: `Manage akashic-cli connection profiles.

A profile bundles the control-plane URL, CA cert, and mTLS client cert/key
so commands like 'akashic-cli bootstrap status' don't need them passed every
time. Profiles live in ~/.akashic/config.yaml; cert files are copied into
~/.akashic/certs/<profile-name>/ with strict permissions.`,
	}
	cmd.AddCommand(NewConfigureAddCmd(ctx))
	cmd.AddCommand(NewConfigureListCmd(ctx))
	cmd.AddCommand(NewConfigureShowCmd(ctx))
	cmd.AddCommand(NewConfigureUseCmd(ctx))
	cmd.AddCommand(NewConfigureRemoveCmd(ctx))
	return cmd
}
