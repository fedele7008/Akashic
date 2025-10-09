package pki

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"
)

// GenerateServerCertificate generates a server certificate signed by the provided CA
func GenerateServerCertificate(opts *ServerCertOptions) (*Certificate, error) {
	if opts == nil {
		return nil, fmt.Errorf("server certificate options are required")
	}

	if opts.CA == nil {
		return nil, fmt.Errorf("CA is required to sign server certificate")
	}

	if opts.CommonName == "" {
		return nil, fmt.Errorf("common name is required for server certificate")
	}

	if len(opts.DNSNames) == 0 {
		return nil, fmt.Errorf("at least one DNS name is required for server certificate")
	}

	// Generate key pair
	privateKey, err := GenerateKeyPair(opts.KeyType, opts.RSAKeySize, opts.ECDSACurve)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server key pair: %v", err)
	}

	// Get public key
	var publicKey interface{}
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		publicKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		publicKey = &k.PublicKey
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	// Parse IP addresses
	var ipAddresses []net.IP
	for _, ipStr := range opts.IPAddresses {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address: %s", ipStr)
		}
		ipAddresses = append(ipAddresses, ip)
	}

	// Create certificate template
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
		DNSNames:              opts.DNSNames,
		IPAddresses:           ipAddresses,
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, opts.ValidityDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Sign the certificate
	cert, err := opts.CA.SignCertificate(template, publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign server certificate: %v", err)
	}

	return &Certificate{
		X509Cert:   cert,
		PrivateKey: privateKey,
	}, nil
}

// GenerateClientCertificate generates a client certificate signed by the provided CA
func GenerateClientCertificate(opts *ClientCertOptions) (*Certificate, error) {
	if opts == nil {
		return nil, fmt.Errorf("client certificate options are required")
	}

	if opts.CA == nil {
		return nil, fmt.Errorf("CA is required to sign client certificate")
	}

	if opts.CommonName == "" {
		return nil, fmt.Errorf("common name is required for client certificate")
	}

	// Generate key pair
	privateKey, err := GenerateKeyPair(opts.KeyType, opts.RSAKeySize, opts.ECDSACurve)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client key pair: %v", err)
	}

	// Get public key
	var publicKey interface{}
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		publicKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		publicKey = &k.PublicKey
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	// Create certificate template
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
		NotAfter:              now.AddDate(0, 0, opts.ValidityDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Add email address if provided
	if opts.EmailAddress != "" {
		template.EmailAddresses = []string{opts.EmailAddress}
	}

	// Sign the certificate
	cert, err := opts.CA.SignCertificate(template, publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign client certificate: %v", err)
	}

	return &Certificate{
		X509Cert:   cert,
		PrivateKey: privateKey,
	}, nil
}

// ParseCertificate parses a PEM-encoded certificate
func ParseCertificate(certPEM []byte) (*Certificate, error) {
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return nil, err
	}

	return &Certificate{
		X509Cert:   cert,
		PrivateKey: nil, // No private key when parsing certificate only
	}, nil
}

// ParseCertificateWithKey parses a PEM-encoded certificate and private key
func ParseCertificateWithKey(certPEM, keyPEM []byte) (*Certificate, error) {
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	privateKey, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return &Certificate{
		X509Cert:   cert,
		PrivateKey: privateKey,
	}, nil
}
