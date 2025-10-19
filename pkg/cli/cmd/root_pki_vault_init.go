package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewVaultInitCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize Vault",
		Long: `Initialize Akashic's PKI vault using Hashicorp Vault.
		
This command will require passphrase to encrypt vault's secret keys and root token.
The secret will be first read from environment variable, AKASHIC_SECRET.
If secret is not found, then it will try to read from a file specified by -s or --secret-path flag, or from environment variable, AKASHIC_SECRET_PATH.
If secret is still not found, then it will prompt user to enter passphrase.

There's no security requirement for the passphrase, but it's recommended to use a strong, unique passphrase.`,
		RunE: ctx.RunPkiVaultInitCmd,
	}

	// Register persistent flags
	core.RegisterFlags(cmd, core.FilterCliConfig(
		core.Secret,
		core.SecretPath,
		core.VaultNumKeys,
		core.VaultNumThresholds,
		core.VaultInitKeyOutDir,
		core.VaultInitKeyOutFormat,
		core.VaultInitRootOut,
		core.VaultInitFileOverride,
	)...)

	return cmd
}
