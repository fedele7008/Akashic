package pki

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"
)

// ValidateCertificate validates a certificate against a CA
func ValidateCertificate(cert *x509.Certificate, ca *CA) error {
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}

	if ca == nil {
		return fmt.Errorf("CA is nil")
	}

	// Check if certificate is expired
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid (NotBefore: %v)", cert.NotBefore)
	}

	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired (NotAfter: %v)", cert.NotAfter)
	}

	// Verify signature
	if err := ca.VerifySignature(cert); err != nil {
		return fmt.Errorf("signature verification failed: %v", err)
	}

	return nil
}

// VerifyCertChain verifies a certificate chain
func VerifyCertChain(cert *x509.Certificate, intermediates, roots *x509.CertPool) error {
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}

	opts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate chain verification failed: %v", err)
	}

	return nil
}

// CheckExpiration checks if a certificate is expired or expiring soon
// Returns (isExpiringSoon, daysUntilExpiry, error)
func CheckExpiration(cert *x509.Certificate, warningDays int) (bool, time.Duration, error) {
	if cert == nil {
		return false, 0, fmt.Errorf("certificate is nil")
	}

	now := time.Now()

	// Check if already expired
	if now.After(cert.NotAfter) {
		return true, 0, fmt.Errorf("certificate has already expired on %v", cert.NotAfter)
	}

	// Check if not yet valid
	if now.Before(cert.NotBefore) {
		return false, 0, fmt.Errorf("certificate is not yet valid (valid from %v)", cert.NotBefore)
	}

	// Calculate time until expiry
	timeUntilExpiry := time.Until(cert.NotAfter)
	warningThreshold := time.Duration(warningDays) * 24 * time.Hour

	isExpiringSoon := timeUntilExpiry < warningThreshold

	return isExpiringSoon, timeUntilExpiry, nil
}

// ValidateServerCertificate validates a server certificate for specific hostnames
func ValidateServerCertificate(cert *x509.Certificate, hostname string, ca *CA) error {
	// First, do general validation
	if err := ValidateCertificate(cert, ca); err != nil {
		return err
	}

	// Check if it has ServerAuth extended key usage
	hasServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}

	if !hasServerAuth {
		return fmt.Errorf("certificate does not have ServerAuth extended key usage")
	}

	// Verify hostname if provided
	if hostname != "" {
		if err := cert.VerifyHostname(hostname); err != nil {
			return fmt.Errorf("hostname verification failed: %v", err)
		}
	}

	return nil
}

// ValidateClientCertificate validates a client certificate
func ValidateClientCertificate(cert *x509.Certificate, ca *CA) error {
	// First, do general validation
	if err := ValidateCertificate(cert, ca); err != nil {
		return err
	}

	// Check if it has ClientAuth extended key usage
	hasClientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
			break
		}
	}

	if !hasClientAuth {
		return fmt.Errorf("certificate does not have ClientAuth extended key usage")
	}

	return nil
}

// ValidateCAConstraints validates CA-specific certificate constraints
func ValidateCAConstraints(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}

	if !cert.IsCA {
		return fmt.Errorf("certificate is not a CA certificate")
	}

	if !cert.BasicConstraintsValid {
		return fmt.Errorf("BasicConstraints extension is not valid")
	}

	// Check key usage
	requiredUsage := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if cert.KeyUsage&requiredUsage != requiredUsage {
		return fmt.Errorf("CA certificate missing required key usage (CertSign and CRLSign)")
	}

	return nil
}

// CheckKeyMatch verifies that a certificate's public key matches a private key
func CheckKeyMatch(cert *x509.Certificate, privateKey interface{}) error {
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}

	if privateKey == nil {
		return fmt.Errorf("private key is nil")
	}

	// Compare public keys
	certPubKey := cert.PublicKey

	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		certRSAPubKey, ok := certPubKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("certificate public key is not RSA")
		}
		if certRSAPubKey.N.Cmp(priv.PublicKey.N) != 0 || certRSAPubKey.E != priv.PublicKey.E {
			return fmt.Errorf("certificate public key does not match private key")
		}
	case *ecdsa.PrivateKey:
		certECDSAPubKey, ok := certPubKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("certificate public key is not ECDSA")
		}
		if certECDSAPubKey.X.Cmp(priv.PublicKey.X) != 0 || certECDSAPubKey.Y.Cmp(priv.PublicKey.Y) != 0 {
			return fmt.Errorf("certificate public key does not match private key")
		}
	default:
		return fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	return nil
}

// GetCertificateFingerprint returns the SHA-256 fingerprint of a certificate
func GetCertificateFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}

	// SHA-256 fingerprint
	return fmt.Sprintf("%X", cert.Signature)
}

// CompareCertificates checks if two certificates are identical
func CompareCertificates(cert1, cert2 *x509.Certificate) bool {
	if cert1 == nil || cert2 == nil {
		return false
	}

	return cert1.Equal(cert2)
}
