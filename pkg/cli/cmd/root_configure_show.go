package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

// NewConfigureShowCmd prints details of one profile. By default, the named
// profile (or the active one if --profile is unset). The output mirrors the
// YAML structure but adds at-a-glance info that helps operators audit:
//   - Cert subject CN / Issuer / NotAfter (decoded from on-disk file)
//   - Permission status (good / drift detected)
//
// Private key is never printed -- only its on-disk path and mode.
func NewConfigureShowCmd(ctx *core.CliContext) *cobra.Command {
	var profileFlag string

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show details for a profile",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := core.LoadProfileConfig()
			if err != nil {
				return err
			}
			prof, name, err := core.ResolveProfile(cfg, profileFlag)
			if err != nil {
				return err
			}
			fmt.Printf("Profile: %s%s\n", name, activeMarker(cfg, name))
			fmt.Printf("  control_url: %s\n", prof.ControlURL)
			fmt.Printf("  ca_cert:     %s%s\n", prof.CACertPath, linkSuffix(prof.CACertPath))
			describeCert(prof.CACertPath, "    ")
			fmt.Printf("  client_cert: %s%s\n", prof.ClientCertPath, linkSuffix(prof.ClientCertPath))
			describeCert(prof.ClientCertPath, "    ")
			fmt.Printf("  client_key:  %s%s\n", prof.ClientKeyPath, linkSuffix(prof.ClientKeyPath))
			describeKeyPerms(prof.ClientKeyPath, "    ")
			return nil
		},
	}
	cmd.Flags().StringVar(&profileFlag, "profile", "", "profile to show (default: active)")
	return cmd
}

func activeMarker(cfg *core.ProfileConfig, name string) string {
	if cfg.ActiveProfile == name {
		return " (active)"
	}
	return ""
}

// describeCert decodes the cert at `path` and prints subject/issuer/expiry.
// On any decode error, prints a one-line warning and continues -- this is
// a diagnostic display, not load-bearing logic.
func describeCert(path, prefix string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("%s(could not read: %v)\n", prefix, err)
		return
	}
	block, _ := pem.Decode(data)
	if block == nil {
		fmt.Printf("%s(no PEM block found)\n", prefix)
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("%s(parse error: %v)\n", prefix, err)
		return
	}
	fmt.Printf("%sSubject:  %s\n", prefix, cert.Subject)
	fmt.Printf("%sIssuer:   %s\n", prefix, cert.Issuer)
	fmt.Printf("%sValidity: %s → %s\n", prefix,
		cert.NotBefore.Format("2006-01-02"),
		cert.NotAfter.Format("2006-01-02"))
}

// linkSuffix returns " [copy]" or " [symlink → <target>]" depending on
// whether the path is a regular file or a symlink. Used on the path lines
// in `configure show` so operators can tell at a glance whether they're
// looking at a frozen-at-add-time snapshot (copy) or a live pointer to
// a Vault-Agent-managed source (symlink).
//
// On any error reading the path, returns "" -- this annotation is a
// diagnostic nicety, not load-bearing, so we don't want to crash the
// whole show command if (say) the file was just deleted from underneath us.
func linkSuffix(path string) string {
	// Lstat does NOT follow symlinks, so we can detect the link itself.
	info, err := os.Lstat(path)
	if err != nil {
		return ""
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return "  [copy]"
	}
	target, err := os.Readlink(path)
	if err != nil {
		return "  [symlink]"
	}
	return fmt.Sprintf("  [symlink → %s]", target)
}

// describeKeyPerms prints the on-disk permissions of the private key.
// Marks "ok" if perms are exactly 0600, "INSECURE" otherwise.
func describeKeyPerms(path, prefix string) {
	info, err := os.Stat(path)
	if err != nil {
		fmt.Printf("%s(could not stat: %v)\n", prefix, err)
		return
	}
	perm := info.Mode().Perm()
	status := "INSECURE"
	if perm == 0o600 {
		status = "ok"
	}
	fmt.Printf("%sPermissions: %#o (%s)\n", prefix, perm, status)
}
