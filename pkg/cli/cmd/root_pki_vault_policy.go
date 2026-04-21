package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewVaultPolicyCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage Vault policies",
		Long:  "Create and manage Vault ACL policies.",
	}

	cmd.AddCommand(NewVaultPolicyCreateCmd(ctx))

	return cmd
}
