package pki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"go.uber.org/zap"
)

// ServerTLSOptions holds the configuration for building a server TLS config.
type ServerTLSOptions struct {
	CertFile           string
	KeyFile            string
	CAFile             string
	ClientAuthRequired bool
}

// NewServerTLSConfig creates a tls.Config for a TLS server with automatic cert reloading.
// If CAFile is set and ClientAuthRequired is true, mutual TLS is enforced.
// Returns the tls.Config and the CertReloader (caller should Start() and later Stop() it).
func NewServerTLSConfig(opts ServerTLSOptions, logger *zap.Logger) (*tls.Config, *CertReloader, error) {
	reloader, err := NewCertReloader(opts.CertFile, opts.KeyFile, logger)
	if err != nil {
		return nil, nil, err
	}

	tlsConfig := &tls.Config{
		GetCertificate: reloader.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}

	if opts.CAFile != "" && opts.ClientAuthRequired {
		caPool, err := loadCAPool(opts.CAFile)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load CA file for client verification: %w", err)
		}
		tlsConfig.ClientCAs = caPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, reloader, nil
}

// ClientTLSOptions holds the configuration for building a client TLS config.
type ClientTLSOptions struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

// NewClientTLSConfig creates a tls.Config for a TLS client with automatic cert reloading.
// Used for mTLS connections where the client presents a certificate.
// Returns the tls.Config and the CertReloader (caller should Start() and later Stop() it).
func NewClientTLSConfig(opts ClientTLSOptions, logger *zap.Logger) (*tls.Config, *CertReloader, error) {
	var reloader *CertReloader

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Client certificate (for mTLS)
	if opts.CertFile != "" && opts.KeyFile != "" {
		var err error
		reloader, err = NewCertReloader(opts.CertFile, opts.KeyFile, logger)
		if err != nil {
			return nil, nil, err
		}
		tlsConfig.GetClientCertificate = reloader.GetClientCertificate
	}

	// CA for server verification
	if opts.CAFile != "" {
		caPool, err := loadCAPool(opts.CAFile)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load CA file for server verification: %w", err)
		}
		tlsConfig.RootCAs = caPool
	}

	return tlsConfig, reloader, nil
}

func loadCAPool(caFile string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file %s: %w", caFile, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate from %s", caFile)
	}

	return pool, nil
}
