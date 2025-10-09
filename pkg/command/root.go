package command

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:     RootCmd,
		Short:   fmt.Sprintf(FmtRootCmdShort, Version),
		Long:    fmt.Sprintf(FmtRootCmdLong, Version),
		Version: Version,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	// Add subcommands
	rootCmd.AddCommand(NewRunCmd())
	rootCmd.AddCommand(NewPKICmd())

	return rootCmd
}
