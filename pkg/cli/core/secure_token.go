package core

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type EncAlg string
type SignAlg string
type ContentType string

const (
	NONE              EncAlg = "NONE"
	AES_128_GCM       EncAlg = "AES-128-GCM"
	AES_192_GCM       EncAlg = "AES-192-GCM"
	AES_256_GCM       EncAlg = "AES-256-GCM"
	AES_128_CBC       EncAlg = "AES-128-CBC"
	AES_192_CBC       EncAlg = "AES-192-CBC"
	AES_256_CBC       EncAlg = "AES-256-CBC"
	CHACHA20_POLY1305 EncAlg = "ChaCha20-Poly1305"
)

const (
	HMAC_SHA256 SignAlg = "HS256"
)

const (
	JSON   ContentType = "json"
	YAML   ContentType = "yaml"
	XML    ContentType = "xml"
	TEXT   ContentType = "text"
	BASE64 ContentType = "base64"
)

type TokenMeta struct {
	Enc EncAlg      `json:"enc"`
	Alg SignAlg     `json:"alg"`
	Sub string      `json:"sub"`
	Iss string      `json:"iss"`
	Cnt ContentType `json:"cnt"`
}

type FullTokenMeta struct {
	TokenMeta
	Iat int64 `json:"iat"`
}

func IssueSecureToken(data []byte, key string, meta TokenMeta) (string, error) {
	fullMeta := FullTokenMeta{
		TokenMeta: meta,
		Iat:       time.Now().UTC().UnixNano(),
	}
	jsonMeta, err := json.Marshal(fullMeta)
	if err != nil {
		return "", err
	}
	base64JsonMeta := base64.StdEncoding.EncodeToString(jsonMeta)

	base64Data := base64.StdEncoding.EncodeToString(data)
	var cipherData string
	if fullMeta.Enc == NONE {
		cipherData = base64Data
	} else {
		encAlg, err := GetEncryptionAlgorithm(fullMeta.Enc)
		if err != nil {
			return "", err
		}
		cipherData, err = encAlg.Encrypt(base64Data, key)
		if err != nil {
			return "", err
		}
	}

	sigContent := fmt.Sprintf("%s.%s.%s", key, base64JsonMeta, cipherData)
	signingAlg, err := GetSigningAlgorithm(fullMeta.Alg)
	if err != nil {
		return "", err
	}
	signature, err := signingAlg.Sign(sigContent, key)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s.%s.%s", base64JsonMeta, cipherData, signature), nil
}

const (
	InvalidTokenKeyError = "INVALID_TOKEN_KEY"
)

type SecureTokenError interface {
	error
	GetType() string
}

type SecureTokenInvalidKeyError struct {
	Message string
	Type    string
}

func (e *SecureTokenInvalidKeyError) Error() string {
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

func (e *SecureTokenInvalidKeyError) GetType() string {
	return e.Type
}

func NewInvalidTokenKeyError(msg string) *SecureTokenInvalidKeyError {
	return &SecureTokenInvalidKeyError{
		Message: msg,
		Type:    InvalidTokenKeyError,
	}
}

func IsSecureTokenError(err error) bool {
	if err == nil {
		return false
	}

	var secureTokenErr SecureTokenError
	return errors.As(err, &secureTokenErr)
}

func ReadSecureToken(token string, key string) (meta *FullTokenMeta, data []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("invalid token format")
	}

	base64Meta := parts[0]
	cipherData := parts[1]
	signature := parts[2]

	jsonMeta, err := base64.StdEncoding.DecodeString(base64Meta)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid base64: %v", err)
	}
	var fullMeta FullTokenMeta
	err = json.Unmarshal(jsonMeta, &fullMeta)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid JSON: %v", err)
	}

	sigContent := fmt.Sprintf("%s.%s.%s", key, base64Meta, cipherData)
	signingAlg, err := GetSigningAlgorithm(fullMeta.Alg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get signing algorithm: %v", err)
	}
	verified, err := signingAlg.Verify(sigContent, signature, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify signature: %v", err)
	}
	if !verified {
		return nil, nil, NewInvalidTokenKeyError("passphrase mismatch, unable to decrypt token")
	}

	var base64Data string
	if fullMeta.Enc == NONE {
		base64Data = cipherData
	} else {
		encAlg, err := GetEncryptionAlgorithm(fullMeta.Enc)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get encryption algorithm: %v", err)
		}

		base64Data, err = encAlg.Decrypt(cipherData, key)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt token: %v", err)
		}
	}
	data, err = base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode base64: %v", err)
	}

	return &fullMeta, data, nil
}

type EncryptionAlgorithm interface {
	Encrypt(text string, key string) (cipher string, err error)
	Decrypt(cipher string, key string) (text string, err error)
}

type SigningAlgorithm interface {
	Sign(content string, key string) (signature string, err error)
	Verify(content string, signature string, key string) (bool, error)
}

// GetEncryptionAlgorithm returns an EncryptionAlgorithm instance for the given algorithm
func GetEncryptionAlgorithm(alg EncAlg) (EncryptionAlgorithm, error) {
	switch alg {
	case AES_128_GCM:
		return NewAes128Gcm(), nil
	case AES_192_GCM:
		return NewAes192Gcm(), nil
	case AES_256_GCM:
		return NewAes256Gcm(), nil
	case AES_128_CBC:
		return NewAes128Cbc(), nil
	case AES_192_CBC:
		return NewAes192Cbc(), nil
	case AES_256_CBC:
		return NewAes256Cbc(), nil
	case CHACHA20_POLY1305:
		return NewChaCha20Poly1305(), nil
	case NONE:
		return nil, fmt.Errorf("NONE algorithm does not use encryption")
	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", alg)
	}
}

// GetSigningAlgorithm returns a SigningAlgorithm instance for the given algorithm
func GetSigningAlgorithm(alg SignAlg) (SigningAlgorithm, error) {
	switch alg {
	case HMAC_SHA256:
		return NewHmacSha256(), nil
	default:
		return nil, fmt.Errorf("unsupported signing algorithm: %s", alg)
	}
}
