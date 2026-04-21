package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewVaultPolicyCreateCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <policy-name>",
		Short: "Create or update a Vault policy",
		Long: `Create or update a Vault ACL policy from an HCL file.

The policy file should contain HCL-formatted Vault policy rules.
If the policy already exists, it will be updated with the new rules.

Example:
  akashic-cli pki vault policy create cert-issuer -f policy.hcl -t token.enc`,
		Args: cobra.ExactArgs(1),
		RunE: ctx.RunPkiVaultPolicyCreateCmd,
	}

	core.RegisterFlags(cmd, core.FilterCliConfig(
		core.Secret,
		core.SecretPath,
		core.VaultRootTokenFile,
		core.PolicyFile,
	)...)

	return cmd
}
