package cli

import (
	"akashic/akashic/pkg/command/cli/core/pkicmd"

	"github.com/spf13/cobra"
)

func NewPkiCmd() *cobra.Command {
	ctx := pkicmd.NewPkiCmdContext()

	pkiCmd := &cobra.Command{
		Use:               PkiCmd,
		Short:             PkiCmdShort,
		Long:              PkiCmdLong,
		PersistentPreRunE: ctx.Init,
		RunE:              ctx.Run,
	}

	return pkiCmd
}
