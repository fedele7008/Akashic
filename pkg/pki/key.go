package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// GenerateRSAKey generates an RSA private key with the specified bit size
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	if bits != 2048 && bits != 4096 {
		return nil, fmt.Errorf("unsupported RSA key size: %d (must be 2048 or 4096)", bits)
	}

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %v", err)
	}

	return key, nil
}

// GenerateECDSAKey generates an ECDSA private key with the specified curve
func GenerateECDSAKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	if curve == nil {
		return nil, fmt.Errorf("curve cannot be nil")
	}

	// Validate that it's a supported curve
	switch curve {
	case elliptic.P256(), elliptic.P384():
		// Supported curves
	default:
		return nil, fmt.Errorf("unsupported ECDSA curve (must be P-256 or P-384)")
	}

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %v", err)
	}

	return key, nil
}

// GetECDSACurve returns the elliptic curve for the given curve name
func GetECDSACurve(curveName ECDSACurve) (elliptic.Curve, error) {
	switch curveName {
	case CurveP256:
		return elliptic.P256(), nil
	case CurveP384:
		return elliptic.P384(), nil
	default:
		return nil, fmt.Errorf("unsupported ECDSA curve: %s", curveName)
	}
}

// GenerateKeyPair generates a public/private key pair based on the key type
func GenerateKeyPair(keyType KeyType, rsaKeySize KeySize, ecdsaCurve elliptic.Curve) (interface{}, error) {
	switch keyType {
	case KeyTypeRSA:
		if rsaKeySize == 0 {
			rsaKeySize = KeySize2048 // Default to 2048
		}
		return GenerateRSAKey(int(rsaKeySize))
	case KeyTypeECDSA:
		if ecdsaCurve == nil {
			ecdsaCurve = elliptic.P256() // Default to P-256
		}
		return GenerateECDSAKey(ecdsaCurve)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}
