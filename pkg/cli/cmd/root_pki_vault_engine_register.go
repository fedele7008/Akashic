package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewEngineRegisterCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a signed certificate into a PKI engine",
		Long: `Register (import) a signed intermediate CA certificate into its PKI engine.

This sets the signed certificate on the engine, activating it as a CA that can issue certificates.
Uses the Vault /pki/intermediate/set-signed endpoint.

The certificate file (--cert) should be the PEM-encoded signed certificate from the parent CA.
The target engine (--engine / -e) is the PKI engine that owns the corresponding private key.`,
		Args: cobra.NoArgs,
		RunE: ctx.RunPkiVaultEngineRegisterCmd,
	}

	core.RegisterFlags(cmd, core.FilterCliConfig(
		core.Secret,
		core.SecretPath,
		core.VaultRootTokenFile,
		core.EngineName,
		core.RegisterCertInput,
	)...)

	return cmd
}
