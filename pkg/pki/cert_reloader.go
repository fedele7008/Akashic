// Package pki implements the Akashic PKI runtime helpers: cert reloading,
// certificate-authority bundle loading, and (optionally) a file-watcher that
// triggers a reload when Vault Agent rotates cert files on disk.
//
// This package is intentionally narrow. Cert issuance is Vault's job (via
// Vault Agent templates under services/vault-agent/templates/*.tpl). What
// lives here is the bit that makes the Akashic Go process notice those
// rotations without a restart.
package pki

import (
	"crypto/tls"
	"fmt"
	"sync/atomic"
)

// Reloader holds an atomic pointer to the current tls.Certificate and rebuilds
// it from disk on demand. Use Reloader.GetCertificate as the value of
// tls.Config.GetCertificate -- each TLS handshake reads the pointer, so
// rotation is zero-downtime for new connections.
//
// The zero value is not usable; construct with NewReloader.
type Reloader struct {
	name     string
	certPath string
	keyPath  string
	current  atomic.Pointer[tls.Certificate]
}

// NewReloader loads the cert/key pair from disk once, verifying that the
// pair is valid, and returns a Reloader primed with it. name is a human-
// readable label used in log messages ("control-server", "auth-server", ...).
func NewReloader(name, certPath, keyPath string) (*Reloader, error) {
	r := &Reloader{name: name, certPath: certPath, keyPath: keyPath}
	if err := r.Reload(); err != nil {
		return nil, fmt.Errorf("initial load for %s: %w", name, err)
	}
	return r, nil
}

// Reload re-reads the cert+key files and atomically swaps them into the
// live pointer. If the new files fail to parse (e.g. Vault Agent is mid-
// rotation and the .crt has updated but the .key hasn't yet), Reload
// returns an error and the previous cert stays active -- callers should
// treat the error as "try again later", not "the server is broken".
func (r *Reloader) Reload() error {
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("load keypair %s / %s: %w", r.certPath, r.keyPath, err)
	}
	r.current.Store(&cert)
	return nil
}

// GetCertificate satisfies tls.Config.GetCertificate. The *tls.ClientHelloInfo
// argument is ignored -- we don't do SNI-based cert selection; one reloader
// serves one cert at a time.
func (r *Reloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := r.current.Load()
	if c == nil {
		return nil, fmt.Errorf("pki: cert not loaded yet (%s)", r.name)
	}
	return c, nil
}

// Name returns the reloader's human-readable label, useful for log lines.
func (r *Reloader) Name() string { return r.name }

// CertPath and KeyPath expose the watched file paths, primarily so the
// optional fsnotify-based watcher (see cert_watcher.go) knows which
// directories to subscribe to.
func (r *Reloader) CertPath() string { return r.certPath }
func (r *Reloader) KeyPath() string  { return r.keyPath }
