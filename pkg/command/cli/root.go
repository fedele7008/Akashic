package cli

import (
	"akashic/akashic/pkg/command/cli/core"
	"fmt"

	"github.com/spf13/cobra"
)

func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:     RootCmd,
		Short:   fmt.Sprintf(FmtRootCmdShort, Version),
		Long:    fmt.Sprintf(FmtRootCmdLong, Version),
		Version: Version,
		Example: FmtRootExamples,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	// Add subcommands
	rootCmd.AddCommand(NewPkiCmd())

	return rootCmd
}

var (
	// Global flags
	controlURL string
	verbose    bool

	// Shared client instance
	client *core.Client
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "akashic-cli",
	Short: "Akashic CLI - Administrative tool for Akashic server",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Initialize client for all commands
		client = core.NewClient(controlURL, verbose)
	},
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVar(&controlURL, "url", "http://localhost:8081",
		"Akashic control plane URL")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"Enable verbose output (shows HTTP requests/responses)")

	// Add command groups
	rootCmd.AddCommand(bootstrapCmd)
	rootCmd.AddCommand(userCmd)
	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(versionCmd)
}

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of akashic-cli",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("akashic-cli v0.0.2")
	},
}
