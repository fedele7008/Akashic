package pki

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// SaveCA saves a CA certificate and private key to files
func SaveCA(ca *CA, certPath, keyPath string) error {
	if ca == nil {
		return fmt.Errorf("CA is nil")
	}

	// Save certificate
	certPEM, err := ca.ToPEM()
	if err != nil {
		return fmt.Errorf("failed to encode CA certificate: %v", err)
	}

	if err := SavePEMFile(certPEM, certPath, 0644); err != nil {
		return fmt.Errorf("failed to save CA certificate: %v", err)
	}

	// Save private key
	keyPEM, err := ca.PrivateKeyToPEM()
	if err != nil {
		return fmt.Errorf("failed to encode CA private key: %v", err)
	}

	if err := SavePEMFile(keyPEM, keyPath, 0400); err != nil {
		return fmt.Errorf("failed to save CA private key: %v", err)
	}

	return nil
}

// SaveCertificate saves a certificate and private key to files
func SaveCertificate(cert *Certificate, certPath, keyPath string) error {
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}

	// Save certificate
	certPEM, err := cert.ToPEM()
	if err != nil {
		return fmt.Errorf("failed to encode certificate: %v", err)
	}

	if err := SavePEMFile(certPEM, certPath, 0644); err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}

	// Save private key if present
	if cert.PrivateKey != nil {
		keyPEM, err := cert.PrivateKeyToPEM()
		if err != nil {
			return fmt.Errorf("failed to encode private key: %v", err)
		}

		if err := SavePEMFile(keyPEM, keyPath, 0400); err != nil {
			return fmt.Errorf("failed to save private key: %v", err)
		}
	}

	return nil
}

// SavePEMFile saves PEM-encoded data to a file with the specified permissions
func SavePEMFile(pemData []byte, path string, perm os.FileMode) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", dir, err)
	}

	// Write file with specified permissions
	if err := os.WriteFile(path, pemData, perm); err != nil {
		return fmt.Errorf("failed to write file %s: %v", path, err)
	}

	return nil
}

// LoadCAFromFiles loads a CA from certificate and key files
func LoadCAFromFiles(certPath, keyPath string) (*CA, error) {
	// Read certificate file
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate file: %v", err)
	}

	// Read key file
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA key file: %v", err)
	}

	// Load CA
	return LoadCA(certPEM, keyPEM)
}

// LoadCertificateFromFiles loads a certificate and private key from files
func LoadCertificateFromFiles(certPath, keyPath string) (*Certificate, error) {
	// Read certificate file
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %v", err)
	}

	// Read key file
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %v", err)
	}

	// Parse certificate and key
	return ParseCertificateWithKey(certPEM, keyPEM)
}

// LoadCertificateOnly loads a certificate from a file without the private key
func LoadCertificateOnly(certPath string) (*Certificate, error) {
	// Read certificate file
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %v", err)
	}

	// Parse certificate
	return ParseCertificate(certPEM)
}

// parseCertificatePEM parses a PEM-encoded certificate
func parseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE block, got %s", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

// parsePrivateKeyPEM parses a PEM-encoded private key
func parsePrivateKeyPEM(keyPEM []byte) (interface{}, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Try different key types
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		// PKCS8 format
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// EnsureDirectory ensures that a directory exists
func EnsureDirectory(path string, perm os.FileMode) error {
	if err := os.MkdirAll(path, perm); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", path, err)
	}
	return nil
}

// ValidateKeyPermissions checks if a key file has secure permissions (0400 or 0600)
func ValidateKeyPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat file: %v", err)
	}

	perm := info.Mode().Perm()

	// Check if permissions are too permissive
	if perm&0044 != 0 {
		return fmt.Errorf("key file has insecure permissions %o (should be 0400 or 0600)", perm)
	}

	return nil
}

// GetKeyType determines the key type from a private key
func GetKeyType(key interface{}) (KeyType, error) {
	switch key.(type) {
	case *rsa.PrivateKey:
		return KeyTypeRSA, nil
	case *ecdsa.PrivateKey:
		return KeyTypeECDSA, nil
	default:
		return "", fmt.Errorf("unsupported key type: %T", key)
	}
}

// GetKeySize returns the key size for RSA keys or curve name for ECDSA keys
func GetKeySize(key interface{}) (int, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k.N.BitLen(), nil
	case *ecdsa.PrivateKey:
		return k.Curve.Params().BitSize, nil
	default:
		return 0, fmt.Errorf("unsupported key type: %T", key)
	}
}
