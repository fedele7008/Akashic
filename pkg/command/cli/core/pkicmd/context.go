package pkicmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

type PkiCmdContext struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func NewPkiCmdContext() *PkiCmdContext {
	ctx, cancel := context.WithCancel(context.Background())
	return &PkiCmdContext{
		ctx:    ctx,
		cancel: cancel,
	}
}

func (cmdCtx *PkiCmdContext) Init(cmd *cobra.Command, args []string) error {
	fmt.Println("Initializing PKI commands")
	return nil
}

func (cmdCtx *PkiCmdContext) Run(cmd *cobra.Command, args []string) error {
	fmt.Println("Running PKI commands")
	return nil
}
