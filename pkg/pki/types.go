package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// KeyType represents the type of cryptographic key
type KeyType string

const (
	KeyTypeRSA   KeyType = "rsa"
	KeyTypeECDSA KeyType = "ecdsa"
)

// KeySize represents RSA key sizes
type KeySize int

const (
	KeySize2048 KeySize = 2048
	KeySize4096 KeySize = 4096
)

// ECDSACurve represents ECDSA curve types
type ECDSACurve string

const (
	CurveP256 ECDSACurve = "P-256"
	CurveP384 ECDSACurve = "P-384"
)

// CA represents a Certificate Authority
type CA struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.PrivateKey
}

// Certificate represents an X.509 certificate with its private key
type Certificate struct {
	X509Cert   *x509.Certificate
	PrivateKey crypto.PrivateKey
}

// CAOptions contains options for generating a Certificate Authority
type CAOptions struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
	ValidityYears      int
	KeyType            KeyType
	RSAKeySize         KeySize
	ECDSACurve         elliptic.Curve
}

// ServerCertOptions contains options for generating a server certificate
type ServerCertOptions struct {
	CA                 *CA
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
	DNSNames           []string // Subject Alternative Names
	IPAddresses        []string // IP SANs
	ValidityDays       int
	KeyType            KeyType
	RSAKeySize         KeySize
	ECDSACurve         elliptic.Curve
}

// ClientCertOptions contains options for generating a client certificate
type ClientCertOptions struct {
	CA                 *CA
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
	EmailAddress       string
	ValidityDays       int
	KeyType            KeyType
	RSAKeySize         KeySize
	ECDSACurve         elliptic.Curve
}

// SignOptions contains options for signing a certificate
type SignOptions struct {
	ValidityDays int
	IsCA         bool
	KeyUsage     x509.KeyUsage
	ExtKeyUsage  []x509.ExtKeyUsage
}

// CertificateInfo contains human-readable certificate information
type CertificateInfo struct {
	Subject            string
	Issuer             string
	SerialNumber       string
	NotBefore          time.Time
	NotAfter           time.Time
	DNSNames           []string
	IPAddresses        []string
	KeyUsage           []string
	ExtKeyUsage        []string
	IsCA               bool
	SignatureAlgorithm string
	PublicKeyAlgorithm string
}

// DefaultCAOptions returns default options for CA generation
func DefaultCAOptions() *CAOptions {
	return &CAOptions{
		CommonName:    "Akashic Self-Signed CA",
		Organization:  "Akashic",
		Country:       "US",
		ValidityYears: 10,
		KeyType:       KeyTypeRSA,
		RSAKeySize:    KeySize4096,
	}
}

// DefaultServerCertOptions returns default options for server certificate generation
func DefaultServerCertOptions(ca *CA) *ServerCertOptions {
	return &ServerCertOptions{
		CA:           ca,
		Organization: "Akashic",
		Country:      "US",
		ValidityDays: 365,
		KeyType:      KeyTypeRSA,
		RSAKeySize:   KeySize2048,
	}
}

// DefaultClientCertOptions returns default options for client certificate generation
func DefaultClientCertOptions(ca *CA) *ClientCertOptions {
	return &ClientCertOptions{
		CA:           ca,
		Organization: "Akashic",
		Country:      "US",
		ValidityDays: 365,
		KeyType:      KeyTypeRSA,
		RSAKeySize:   KeySize2048,
	}
}

// ToPEM converts a certificate to PEM format
func (c *Certificate) ToPEM() ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.X509Cert.Raw,
	}), nil
}

// PrivateKeyToPEM converts a private key to PEM format
func (c *Certificate) PrivateKeyToPEM() ([]byte, error) {
	return encodePrivateKeyPEM(c.PrivateKey)
}

// ToPEM converts a CA certificate to PEM format
func (ca *CA) ToPEM() ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Certificate.Raw,
	}), nil
}

// PrivateKeyToPEM converts a CA private key to PEM format
func (ca *CA) PrivateKeyToPEM() ([]byte, error) {
	return encodePrivateKeyPEM(ca.PrivateKey)
}

// encodePrivateKeyPEM encodes a private key to PEM format
func encodePrivateKeyPEM(key crypto.PrivateKey) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}), nil
	case *ecdsa.PrivateKey:
		bytes, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ECDSA private key: %v", err)
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: bytes,
		}), nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", key)
	}
}

// GetInfo returns human-readable information about the certificate
func (c *Certificate) GetInfo() *CertificateInfo {
	return getCertificateInfo(c.X509Cert)
}

// GetInfo returns human-readable information about the CA certificate
func (ca *CA) GetInfo() *CertificateInfo {
	return getCertificateInfo(ca.Certificate)
}

// getCertificateInfo extracts information from an x509 certificate
func getCertificateInfo(cert *x509.Certificate) *CertificateInfo {
	info := &CertificateInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		DNSNames:           cert.DNSNames,
		IsCA:               cert.IsCA,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
	}

	// Convert IP addresses to strings
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}

	// Convert key usage to strings
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		info.KeyUsage = append(info.KeyUsage, "DigitalSignature")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		info.KeyUsage = append(info.KeyUsage, "KeyEncipherment")
	}
	if cert.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
		info.KeyUsage = append(info.KeyUsage, "KeyAgreement")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		info.KeyUsage = append(info.KeyUsage, "CertSign")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		info.KeyUsage = append(info.KeyUsage, "CRLSign")
	}

	// Convert extended key usage to strings
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			info.ExtKeyUsage = append(info.ExtKeyUsage, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			info.ExtKeyUsage = append(info.ExtKeyUsage, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			info.ExtKeyUsage = append(info.ExtKeyUsage, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			info.ExtKeyUsage = append(info.ExtKeyUsage, "EmailProtection")
		case x509.ExtKeyUsageTimeStamping:
			info.ExtKeyUsage = append(info.ExtKeyUsage, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			info.ExtKeyUsage = append(info.ExtKeyUsage, "OCSPSigning")
		}
	}

	return info
}

// IsExpiringSoon checks if the certificate expires within the given number of days
func (c *Certificate) IsExpiringSoon(days int) bool {
	return time.Until(c.X509Cert.NotAfter) < time.Duration(days)*24*time.Hour
}

// IsExpired checks if the certificate has expired
func (c *Certificate) IsExpired() bool {
	return time.Now().After(c.X509Cert.NotAfter)
}

// DaysUntilExpiry returns the number of days until the certificate expires
func (c *Certificate) DaysUntilExpiry() int {
	duration := time.Until(c.X509Cert.NotAfter)
	return int(duration.Hours() / 24)
}
