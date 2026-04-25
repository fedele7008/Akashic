package cmd

import (
	"fmt"

	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

// NewConfigureUseCmd switches the active profile. Equivalent to opening
// ~/.akashic/config.yaml and editing `active_profile:`.
func NewConfigureUseCmd(ctx *core.CliContext) *cobra.Command {
	return &cobra.Command{
		Use:   "use <profile-name>",
		Short: "Set the active profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cfg, err := core.LoadProfileConfig()
			if err != nil {
				return err
			}
			if _, ok := cfg.Profiles[name]; !ok {
				return fmt.Errorf("profile %q not found; run `akashic-cli configure list` to see available profiles", name)
			}
			cfg.ActiveProfile = name
			if err := core.SaveProfileConfig(cfg); err != nil {
				return err
			}
			fmt.Printf("✓ Active profile is now %q\n", name)
			return nil
		},
	}
}
