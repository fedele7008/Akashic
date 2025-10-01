package command

import (
	"akashic/akashic/pkg/akashic"
	"akashic/akashic/pkg/config"
	"fmt"

	"github.com/spf13/cobra"
)

func NewRootCmd() *cobra.Command {
	app := akashic.NewAkashicApp()

	rootCmd := &cobra.Command{
		Use:               RootCmd,
		Short:             fmt.Sprintf(FmtRootCmdShort, Version),
		Long:              fmt.Sprintf(FmtRootCmdLong, Version),
		Version:           Version,
		PersistentPreRunE: app.Init,
		RunE:              app.Run,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	config.RegisterFlags(rootCmd)

	return rootCmd
}
