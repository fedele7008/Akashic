package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
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
	Enc EncAlg      `json:"enc"` // Encryption algorithm
	Alg SignAlg     `json:"alg"` // Signing algorithm
	Sub string      `json:"sub"` // Subject
	Dtl string      `json:"dtl"` // Details
	Iss string      `json:"iss"` // Issuer
	Cnt ContentType `json:"cnt"` // Content type
}

type FullTokenMeta struct {
	TokenMeta
	Ver int    `json:"ver"` // Token format version (currently 1)
	Iat int64  `json:"iat"` // Issued at (Unix nano timestamp)
	Slt string `json:"slt"` // Base64-encoded random salt for key derivation
}

// Key derivation constants
const (
	pbkdf2Iterations = 600000 // OWASP 2023 recommendation for PBKDF2-SHA256
	saltSize         = 32     // 256 bits
	masterKeySize    = 32     // 256 bits for master key
	signingKeySize   = 32     // 256 bits for HMAC-SHA256
)

// Context-specific info strings for HKDF
var (
	hkdfInfoEncryption = []byte("akashic-token-encryption-v1")
	hkdfInfoSigning    = []byte("akashic-token-signing-v1")
)

// generateSalt generates a cryptographically secure random salt
func generateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}
	return salt, nil
}

// deriveMasterKey derives a master key from password using PBKDF2
func deriveMasterKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, pbkdf2Iterations, masterKeySize, sha256.New)
}

// deriveEncryptionKey derives an encryption key from master key using HKDF
func deriveEncryptionKey(masterKey []byte, salt []byte, keySize int) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, masterKey, salt, hkdfInfoEncryption)
	key := make([]byte, keySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %v", err)
	}
	return key, nil
}

// deriveSigningKey derives a signing key from master key using HKDF
func deriveSigningKey(masterKey []byte, salt []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, masterKey, salt, hkdfInfoSigning)
	key := make([]byte, signingKeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("failed to derive signing key: %v", err)
	}
	return key, nil
}

// getEncryptionKeySize returns the required key size for the encryption algorithm
func getEncryptionKeySize(alg EncAlg) (int, error) {
	switch alg {
	case AES_128_GCM, AES_128_CBC:
		return 16, nil
	case AES_192_GCM, AES_192_CBC:
		return 24, nil
	case AES_256_GCM, AES_256_CBC, CHACHA20_POLY1305:
		return 32, nil
	case NONE:
		return 0, nil // No encryption key needed
	default:
		return 0, fmt.Errorf("unsupported encryption algorithm: %s", alg)
	}
}

func IssueSecureToken(data []byte, key string, meta TokenMeta) (string, error) {
	// Step 1: Generate random salt
	salt, err := generateSalt()
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %v", err)
	}

	// Step 2: Derive master key from password
	masterKey := deriveMasterKey(key, salt)

	// Step 3: Derive encryption and signing keys from master key
	var encryptionKey []byte
	if meta.Enc != NONE {
		keySize, err := getEncryptionKeySize(meta.Enc)
		if err != nil {
			return "", err
		}
		encryptionKey, err = deriveEncryptionKey(masterKey, salt, keySize)
		if err != nil {
			return "", err
		}
	}

	signingKey, err := deriveSigningKey(masterKey, salt)
	if err != nil {
		return "", err
	}

	// Step 4: Build metadata with salt and version
	fullMeta := FullTokenMeta{
		TokenMeta: meta,
		Iat:       time.Now().UTC().UnixNano(),
		Slt:       base64.StdEncoding.EncodeToString(salt),
		Ver:       1, // Token format version
	}

	jsonMeta, err := json.Marshal(fullMeta)
	if err != nil {
		return "", fmt.Errorf("failed to marshal metadata: %v", err)
	}
	base64JsonMeta := base64.StdEncoding.EncodeToString(jsonMeta)

	// Step 5: Encrypt data with derived encryption key
	base64Data := base64.StdEncoding.EncodeToString(data)
	var cipherData string
	if fullMeta.Enc == NONE {
		cipherData = base64Data
	} else {
		encAlg, err := GetEncryptionAlgorithm(fullMeta.Enc)
		if err != nil {
			return "", err
		}
		cipherData, err = encAlg.Encrypt(base64Data, encryptionKey)
		if err != nil {
			return "", fmt.Errorf("encryption failed: %v", err)
		}
	}

	// Step 6: Sign with derived signing key
	sigContent := fmt.Sprintf("%s.%s", base64JsonMeta, cipherData)
	signingAlg, err := GetSigningAlgorithm(fullMeta.Alg)
	if err != nil {
		return "", err
	}
	signature, err := signingAlg.Sign(sigContent, signingKey)
	if err != nil {
		return "", fmt.Errorf("signing failed: %v", err)
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
	// Step 1: Parse token structure
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("invalid token format")
	}

	base64Meta := parts[0]
	cipherData := parts[1]
	signature := parts[2]

	// Step 2: Decode and parse metadata
	jsonMeta, err := base64.StdEncoding.DecodeString(base64Meta)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid base64 metadata: %v", err)
	}
	var fullMeta FullTokenMeta
	err = json.Unmarshal(jsonMeta, &fullMeta)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid metadata JSON: %v", err)
	}

	// Step 3: Extract salt from metadata
	if fullMeta.Slt == "" {
		return nil, nil, fmt.Errorf("missing salt in token metadata")
	}
	salt, err := base64.StdEncoding.DecodeString(fullMeta.Slt)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid salt encoding: %v", err)
	}

	// Step 4: Derive master key from password using stored salt
	masterKey := deriveMasterKey(key, salt)

	// Step 5: Derive encryption and signing keys from master key
	var encryptionKey []byte
	if fullMeta.Enc != NONE {
		keySize, err := getEncryptionKeySize(fullMeta.Enc)
		if err != nil {
			return nil, nil, err
		}
		encryptionKey, err = deriveEncryptionKey(masterKey, salt, keySize)
		if err != nil {
			return nil, nil, err
		}
	}

	signingKey, err := deriveSigningKey(masterKey, salt)
	if err != nil {
		return nil, nil, err
	}

	// Step 6: Verify signature with derived signing key
	sigContent := fmt.Sprintf("%s.%s", base64Meta, cipherData)
	signingAlg, err := GetSigningAlgorithm(fullMeta.Alg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get signing algorithm: %v", err)
	}
	verified, err := signingAlg.Verify(sigContent, signature, signingKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify signature: %v", err)
	}
	if !verified {
		return nil, nil, NewInvalidTokenKeyError("passphrase mismatch, unable to decrypt token")
	}

	// Step 7: Decrypt data with derived encryption key
	var base64Data string
	if fullMeta.Enc == NONE {
		base64Data = cipherData
	} else {
		encAlg, err := GetEncryptionAlgorithm(fullMeta.Enc)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get encryption algorithm: %v", err)
		}

		base64Data, err = encAlg.Decrypt(cipherData, encryptionKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt token: %v", err)
		}
	}
	data, err = base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode base64 data: %v", err)
	}

	return &fullMeta, data, nil
}

type EncryptionAlgorithm interface {
	Encrypt(text string, key []byte) (cipher string, err error)
	Decrypt(cipher string, key []byte) (text string, err error)
}

type SigningAlgorithm interface {
	Sign(content string, key []byte) (signature string, err error)
	Verify(content string, signature string, key []byte) (bool, error)
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
