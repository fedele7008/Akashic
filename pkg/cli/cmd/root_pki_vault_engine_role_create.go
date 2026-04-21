package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

func NewEngineRoleCreateCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <role-name>",
		Short: "Create or update a PKI role",
		Long: `Create or update a role on a Vault PKI engine.

Roles define the certificate issuance policy: allowed domains, key usage,
TTL, and other constraints. Certificates are issued via roles.

Configuration must be provided via config file (--config-file / -f) and/or
inline config (--config). There are no defaults — the role policy must be
explicitly defined.`,
		Args: cobra.ExactArgs(1),
		RunE: ctx.RunPkiVaultEngineRoleCreateCmd,
	}

	core.RegisterFlags(cmd, core.FilterCliConfig(
		core.Secret,
		core.SecretPath,
		core.VaultRootTokenFile,
		core.EngineConfigFile,
		core.EngineConfig,
		core.EngineName,
	)...)

	return cmd
}
