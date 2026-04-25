package cmd

import (
	"fmt"
	"sort"

	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

// NewConfigureListCmd lists all profiles in ~/.akashic/config.yaml,
// marking the active one. Outputs nothing-and-exits-cleanly when no
// profiles exist (avoids a confusing "header but no rows" display).
func NewConfigureListCmd(ctx *core.CliContext) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all configured profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := core.LoadProfileConfig()
			if err != nil {
				return err
			}
			if len(cfg.Profiles) == 0 {
				fmt.Println("No profiles configured. Run `akashic-cli configure add` to create one.")
				return nil
			}
			// Stable name order so the output is reproducible.
			names := make([]string, 0, len(cfg.Profiles))
			for n := range cfg.Profiles {
				names = append(names, n)
			}
			sort.Strings(names)

			fmt.Println("PROFILES")
			for _, n := range names {
				p := cfg.Profiles[n]
				marker := "  "
				if n == cfg.ActiveProfile {
					marker = "* "
				}
				fmt.Printf("%s%-20s → %s\n", marker, n, p.ControlURL)
			}
			fmt.Println("\n* = active profile")
			return nil
		},
	}
}
