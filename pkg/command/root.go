package command

import (
	"akashic/akashic/pkg/common"
	"fmt"

	"github.com/spf13/cobra"
)

func NewRootCmd() *cobra.Command {
	branch, commit, err := common.GetGitInfo()
	if err != nil {
		return nil
	}

	cmd := &cobra.Command{
		Use:     "akashic",
		Short:   fmt.Sprintf(fmtRootCmdShort, fmt.Sprintf("%s (%s)", branch, commit)),
		Long:    fmt.Sprintf(fmtRootCmdLong, fmt.Sprintf("%s (%s)", branch, commit)),
		Version: branch,
	}

	return cmd
}
