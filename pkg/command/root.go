package command

import (
	"akashic/akashic/pkg/common"
	"fmt"

	"github.com/spf13/cobra"
)

func NewSubCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hello",
		Short: "A brief description of your command",
		Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			//return fmt.Errorf("Test err")
			fmt.Println("Hello World this is prerun")
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("hello called")
		},
	}
	return cmd
}

func NewRootCmd() *cobra.Command {
	branch, commit, err := common.GetGitInfo()
	if err != nil {
		return nil
	}

	rootCmd := &cobra.Command{
		Use:     "akashic",
		Short:   fmt.Sprintf(fmtRootCmdShort, fmt.Sprintf("%s (%s)", branch, commit)),
		Long:    fmt.Sprintf(fmtRootCmdLong, fmt.Sprintf("%s (%s)", branch, commit)),
		Version: branch,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Hello World")
			return nil
		},
	}

	rootCmd.Flags().BoolP("version", "v", false, "show version")
	rootCmd.AddCommand(NewSubCommand())
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	return rootCmd
}
