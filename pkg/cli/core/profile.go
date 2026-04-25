// Package core: profile management for akashic-cli.
//
// A "profile" is a named bundle of {control-plane URL, CA cert, client cert,
// client key} that lets the CLI talk to a specific Akashic deployment with
// one short flag (`--profile prod`) instead of four long ones every time.
//
// Layout on disk:
//
//	~/.akashic/
//	├── config.yaml           ← profile definitions, active_profile pointer
//	└── certs/
//	    ├── default/
//	    │   ├── ca.crt        (mode 0644)
//	    │   ├── client.crt    (mode 0644)
//	    │   └── client.key    (mode 0600)  ← strict
//	    └── prod/
//	        └── ...
//
// Permission discipline mirrors OpenSSH's ~/.ssh: the CLI refuses to load a
// profile whose private key is world-readable. This catches the operator
// who accidentally `chmod -R 0644`s their config dir.
package core

import (
	"fmt"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// Profile describes how to reach one Akashic deployment over mTLS.
type Profile struct {
	// ControlURL is the base URL of the control plane, e.g.
	// "https://127.0.0.1:8081" for a host-run dev instance or
	// "https://akashic.example.com:8081" for production.
	ControlURL string `yaml:"control_url"`

	// CACertPath is the trust bundle used to verify the control-server's
	// TLS cert. Typically the pki-mtls-akashic-ctrl CA.
	CACertPath string `yaml:"ca_cert"`

	// ClientCertPath is the mTLS client cert file path. Subject CN must be
	// in the server's allowed-clients list (typically "cli.akashic.local").
	ClientCertPath string `yaml:"client_cert"`

	// ClientKeyPath is the mTLS client private key. Must be 0600.
	ClientKeyPath string `yaml:"client_key"`
}

// ProfileConfig is the on-disk format of ~/.akashic/config.yaml.
type ProfileConfig struct {
	// ActiveProfile is the profile used when --profile / AKASHIC_CLI_PROFILE
	// are both unset. Empty if no profile has been added yet.
	ActiveProfile string `yaml:"active_profile"`

	// Profiles maps profile name → Profile definition.
	Profiles map[string]*Profile `yaml:"profiles"`
}

// AkashicHomeDir returns the absolute path to ~/.akashic, creating it
// (mode 0700) if it doesn't yet exist. The strict permissions are enforced
// on every call -- if the directory exists with looser perms, this is
// surfaced as an error (rather than auto-fixed) so operators notice the
// drift.
func AkashicHomeDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not determine $HOME: %w", err)
	}
	dir := filepath.Join(home, ".akashic")

	info, err := os.Stat(dir)
	switch {
	case os.IsNotExist(err):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("create %s: %w", dir, err)
		}
		return dir, nil
	case err != nil:
		return "", fmt.Errorf("stat %s: %w", dir, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s exists but is not a directory", dir)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		return "", fmt.Errorf("%s has insecure permissions %#o (expected 0700); fix with: chmod 0700 %s",
			dir, mode, dir)
	}
	return dir, nil
}

// ProfileConfigPath returns the absolute path to ~/.akashic/config.yaml.
// Does NOT verify the file exists; callers handle ENOENT explicitly so the
// "first run" case (no config yet) can be distinguished from "config corrupt".
func ProfileConfigPath() (string, error) {
	home, err := AkashicHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "config.yaml"), nil
}

// ProfileCertsDir returns the absolute path to ~/.akashic/certs/<name>,
// creating it (mode 0700) if it doesn't exist. This is where `configure
// add` copies cert files for the named profile.
func ProfileCertsDir(name string) (string, error) {
	home, err := AkashicHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, "certs", name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}
	// Defensive: the parent ~/.akashic/certs/ may already exist with looser
	// perms; tighten it explicitly. (MkdirAll preserves existing perms.)
	if err := os.Chmod(filepath.Dir(dir), 0o700); err != nil {
		return "", fmt.Errorf("chmod %s: %w", filepath.Dir(dir), err)
	}
	return dir, nil
}

// LoadProfileConfig reads ~/.akashic/config.yaml. Returns an empty ProfileConfig
// (not an error) when the file doesn't exist -- the "first run" case. Returns
// a real error for anything else (parse failure, permission denied, etc.).
func LoadProfileConfig() (*ProfileConfig, error) {
	path, err := ProfileConfigPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &ProfileConfig{Profiles: map[string]*Profile{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	cfg := &ProfileConfig{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]*Profile{}
	}
	return cfg, nil
}

// SaveProfileConfig writes ~/.akashic/config.yaml atomically (write to .tmp,
// then rename). Atomic replace prevents a torn read on a concurrent CLI
// invocation. The file is written with mode 0600 -- it doesn't contain
// secrets per se, but it does point at file paths whose ownership is
// security-sensitive, so leaking those paths to other users on a shared
// host is undesirable.
func SaveProfileConfig(cfg *ProfileConfig) error {
	path, err := ProfileConfigPath()
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
	}
	return nil
}

// ResolveProfile picks the profile the CLI should use for the current
// invocation. Precedence (highest → lowest):
//
//  1. explicit (the --profile flag, if non-empty)
//  2. AKASHIC_CLI_PROFILE env var
//  3. ProfileConfig.ActiveProfile
//
// Returns the profile and its name, or a clear error explaining what to do
// next (run `akashic-cli configure add ...`).
func ResolveProfile(cfg *ProfileConfig, explicit string) (*Profile, string, error) {
	name := explicit
	if name == "" {
		name = os.Getenv("AKASHIC_CLI_PROFILE")
	}
	if name == "" {
		name = cfg.ActiveProfile
	}
	if name == "" {
		return nil, "", fmt.Errorf("no profile configured; run `akashic-cli configure add --name <name> ...` to create one")
	}
	p, ok := cfg.Profiles[name]
	if !ok {
		return nil, "", fmt.Errorf("profile %q not found in ~/.akashic/config.yaml", name)
	}
	return p, name, nil
}

// VerifyProfilePerms checks that the cert files referenced by a profile
// have safe permissions (key=0600, certs=0644 or stricter). Run before
// every TLS dial -- catches the operator who accidentally loosened perms
// after `configure add`.
func VerifyProfilePerms(p *Profile) error {
	if err := verifyFileMode(p.ClientKeyPath, 0o600, "private key"); err != nil {
		return err
	}
	if err := verifyFileModeMax(p.CACertPath, 0o644, "CA cert"); err != nil {
		return err
	}
	if err := verifyFileModeMax(p.ClientCertPath, 0o644, "client cert"); err != nil {
		return err
	}
	return nil
}

// verifyFileMode requires an exact mode bitmask. Used for private keys
// (anything other than 0600 is wrong, even 0400).
func verifyFileMode(path string, want os.FileMode, label string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s %s: %w", label, path, err)
	}
	if got := info.Mode().Perm(); got != want {
		return fmt.Errorf("%s %s has insecure permissions %#o (expected %#o); fix with: chmod %#o %s",
			label, path, got, want, want, path)
	}
	return nil
}

// verifyFileModeMax allows the file to be MORE restrictive than `max`,
// just not LESS. Used for cert files where 0644 is typical but 0640 / 0600
// are also fine.
func verifyFileModeMax(path string, max os.FileMode, label string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s %s: %w", label, path, err)
	}
	got := info.Mode().Perm()
	// Reject any "world" or "group" bits beyond what `max` allows.
	if got & ^max != 0 {
		return fmt.Errorf("%s %s has insecure permissions %#o (max %#o); fix with: chmod %#o %s",
			label, path, got, max, max, path)
	}
	return nil
}
