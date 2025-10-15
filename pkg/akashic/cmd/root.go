package cmd

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

	return rootCmd
}

const (
	RootCmd         = "akashic"
	Version         = "0.0.2"
	FmtRootCmdShort = "akashic %s"
	FmtRootCmdLong  = "akashic %s\nOAuth 2.0 + OIDC SSO Server"
)
