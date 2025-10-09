package pki

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// GenerateCA generates a new self-signed Certificate Authority
func GenerateCA(opts *CAOptions) (*CA, error) {
	if opts == nil {
		opts = DefaultCAOptions()
	}

	// Validate options
	if opts.CommonName == "" {
		return nil, fmt.Errorf("CA common name is required")
	}
	if opts.ValidityYears <= 0 {
		return nil, fmt.Errorf("validity years must be positive")
	}

	// Generate key pair
	privateKey, err := GenerateKeyPair(opts.KeyType, opts.RSAKeySize, opts.ECDSACurve)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key pair: %v", err)
	}

	// Generate a random serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	// Set up certificate template
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         opts.CommonName,
			Organization:       []string{opts.Organization},
			OrganizationalUnit: []string{opts.OrganizationalUnit},
			Country:            []string{opts.Country},
			Province:           []string{opts.Province},
			Locality:           []string{opts.Locality},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(opts.ValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		MaxPathLenZero:        false,
	}

	// Get public key from private key
	var publicKey interface{}
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		publicKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		publicKey = &k.PublicKey
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %v", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	return &CA{
		Certificate: cert,
		PrivateKey:  privateKey,
	}, nil
}

// LoadCA loads a Certificate Authority from PEM-encoded certificate and key files
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	// Parse certificate
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	// Verify it's a CA certificate
	if !cert.IsCA {
		return nil, fmt.Errorf("certificate is not a CA certificate")
	}

	// Parse private key
	privateKey, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %v", err)
	}

	return &CA{
		Certificate: cert,
		PrivateKey:  privateKey,
	}, nil
}

// SignCertificate signs a certificate request and returns a signed certificate
func (ca *CA) SignCertificate(template *x509.Certificate, publicKey interface{}) (*x509.Certificate, error) {
	if ca.Certificate == nil || ca.PrivateKey == nil {
		return nil, fmt.Errorf("CA certificate or private key is nil")
	}

	if template == nil {
		return nil, fmt.Errorf("certificate template is nil")
	}

	if publicKey == nil {
		return nil, fmt.Errorf("public key is nil")
	}

	// Sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, publicKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %v", err)
	}

	// Parse the signed certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed certificate: %v", err)
	}

	return cert, nil
}

// VerifySignature verifies that a certificate was signed by this CA
func (ca *CA) VerifySignature(cert *x509.Certificate) error {
	if ca.Certificate == nil {
		return fmt.Errorf("CA certificate is nil")
	}

	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}

	// Create a cert pool with this CA
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)

	// Verify the certificate
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %v", err)
	}

	return nil
}

// IsExpired checks if the CA certificate has expired
func (ca *CA) IsExpired() bool {
	if ca.Certificate == nil {
		return true
	}
	return time.Now().After(ca.Certificate.NotAfter)
}

// IsExpiringSoon checks if the CA certificate expires within the given number of days
func (ca *CA) IsExpiringSoon(days int) bool {
	if ca.Certificate == nil {
		return true
	}
	return time.Until(ca.Certificate.NotAfter) < time.Duration(days)*24*time.Hour
}

// DaysUntilExpiry returns the number of days until the CA certificate expires
func (ca *CA) DaysUntilExpiry() int {
	if ca.Certificate == nil {
		return 0
	}
	duration := time.Until(ca.Certificate.NotAfter)
	return int(duration.Hours() / 24)
}
