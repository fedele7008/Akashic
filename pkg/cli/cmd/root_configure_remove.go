package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

// NewConfigureRemoveCmd deletes a profile from ~/.akashic/config.yaml and
// (optionally) wipes its cert directory ~/.akashic/certs/<name>/. The
// active-profile pointer is cleared if it points at the removed profile;
// the operator is then prompted to set a new active via `configure use`.
func NewConfigureRemoveCmd(ctx *core.CliContext) *cobra.Command {
	var keepCerts bool

	cmd := &cobra.Command{
		Use:   "remove <profile-name>",
		Short: "Remove a profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cfg, err := core.LoadProfileConfig()
			if err != nil {
				return err
			}
			if _, ok := cfg.Profiles[name]; !ok {
				return fmt.Errorf("profile %q not found", name)
			}
			delete(cfg.Profiles, name)
			if cfg.ActiveProfile == name {
				cfg.ActiveProfile = ""
			}
			if err := core.SaveProfileConfig(cfg); err != nil {
				return err
			}

			// Wipe cert dir unless --keep-certs was passed. The dir is
			// under ~/.akashic/certs/<name>/ so removing it doesn't touch
			// other profiles' certs.
			if !keepCerts {
				home, err := core.AkashicHomeDir()
				if err != nil {
					return err
				}
				certDir := filepath.Join(home, "certs", name)
				if err := os.RemoveAll(certDir); err != nil {
					return fmt.Errorf("remove cert dir %s: %w", certDir, err)
				}
			}

			fmt.Printf("✓ Profile %q removed\n", name)
			if cfg.ActiveProfile == "" && len(cfg.Profiles) > 0 {
				fmt.Println("Note: no active profile set. Run `akashic-cli configure use <name>` to set one.")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&keepCerts, "keep-certs", false, "do not delete the cert files in ~/.akashic/certs/<name>/")
	return cmd
}
