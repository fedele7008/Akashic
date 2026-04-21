package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewEngineIssueCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "issue",
		Short: "Issue a certificate from a PKI engine",
		Long: `Issue a leaf certificate from a Vault PKI engine using a named role.

The role defines the issuance policy (allowed domains, key usage, TTL).
The issued certificate and private key are written to separate output files.

Configuration is merged from four sources (lowest to highest priority):
  1. Defaults: format=pem
  2. Config file (--config-file / -f): overrides matching fields
  3. Inline config (--config): overrides matching fields
  4. --cn flag: overrides common_name from any source`,
		Args: cobra.NoArgs,
		RunE: ctx.RunPkiVaultEngineIssueCmd,
	}

	core.RegisterFlags(cmd, core.FilterCliConfig(
		core.Secret,
		core.SecretPath,
		core.VaultRootTokenFile,
		core.EngineConfigFile,
		core.EngineConfig,
		core.EngineName,
		core.CsrOutput,
		core.CsrCommonName,
		core.IssueRole,
		core.IssueKeyOut,
	)...)

	return cmd
}
