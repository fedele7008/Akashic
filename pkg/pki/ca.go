package pki

import (
	"crypto/x509"
	"fmt"
	"os"
)

// LoadCAPool reads a PEM-encoded CA bundle from disk and returns an x509.CertPool
// suitable for use as tls.Config.ClientCAs or tls.Config.RootCAs.
//
// Returns an error (rather than silently proceeding with an empty pool) when the
// file is readable but contains no valid certificates -- a common operator mistake
// is pointing the path at the wrong file (e.g. a private key).
func LoadCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA bundle %s contained no valid PEM certificates", path)
	}
	return pool, nil
}
