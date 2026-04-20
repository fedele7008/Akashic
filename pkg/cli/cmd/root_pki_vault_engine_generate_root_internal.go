package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewEngineGenerateRootInternalCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "internal",
		Short: "Generate self-signed root CA with internal key",
		Long: `Generate a self-signed root CA certificate with the private key stored internally in Vault.

The private key is generated inside Vault and never leaves it (most secure option for CA keys).
The resulting certificate is self-signed and serves as the root of trust.

Configuration is merged from four sources (lowest to highest priority):
  1. Defaults: key_type=rsa, key_bits=4096, format=pem, ttl=87600h (10yr)
  2. Config file (--config-file / -f): overrides matching fields
  3. Inline config (--config): overrides matching fields
  4. --cn flag: overrides common_name from any source`,
		Args: cobra.NoArgs,
		RunE: ctx.RunPkiVaultEngineGenerateRootInternalCmd,
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
