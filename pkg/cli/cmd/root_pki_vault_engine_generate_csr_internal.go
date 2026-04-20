package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewEngineGenerateCsrInternalCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "internal",
		Short: "Generate CSR with internal key",
		Long: `Generate a Certificate Signing Request with the private key stored internally in Vault.

The private key is generated inside Vault and never leaves it (most secure option for CA keys).
The CSR can then be signed by a parent CA to create an intermediate certificate.

Configuration is merged from four sources (lowest to highest priority):
  1. Defaults: key_type=rsa, key_bits=4096, format=pem, org=Akashic
  2. Config file (--config-file / -f): overrides matching fields
  3. Inline config (--config): overrides matching fields
  4. --cn flag: overrides common_name from any source`,
		Args: cobra.NoArgs,
		RunE: ctx.RunPkiVaultEngineGenerateCsrInternalCmd,
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
	)...)

	return cmd
}
