package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

// PBKDF2 parameters for key derivation
const (
	pbkdf2Iterations = 100000 // OWASP recommended minimum
	pbkdf2SaltSize   = 32     // 256 bits
)

// Fixed salt for deterministic key derivation
// In production, you might want to generate and store this per-installation
var pbkdf2Salt = []byte("akashic-cli-v1-salt-do-not-change-or-lose")

// deriveKey derives a key of the specified length from a password using PBKDF2
func deriveKey(password string, keyLen int) []byte {
	return pbkdf2.Key([]byte(password), pbkdf2Salt, pbkdf2Iterations, keyLen, sha256.New)
}

// pkcs7Pad adds PKCS#7 padding to the data
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

// pkcs7Unpad removes PKCS#7 padding from the data
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	// Verify all padding bytes
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data)-padding], nil
}

// ===========================
// AES-GCM Implementations
// ===========================

// AesGcm implements EncryptionAlgorithm for AES-GCM mode
type AesGcm struct {
	keySize int // 16, 24, or 32 bytes for AES-128, AES-192, AES-256
}

// NewAes128Gcm creates an AES-128-GCM encrypter
func NewAes128Gcm() *AesGcm {
	return &AesGcm{keySize: 16}
}

// NewAes192Gcm creates an AES-192-GCM encrypter
func NewAes192Gcm() *AesGcm {
	return &AesGcm{keySize: 24}
}

// NewAes256Gcm creates an AES-256-GCM encrypter
func NewAes256Gcm() *AesGcm {
	return &AesGcm{keySize: 32}
}

// Encrypt encrypts plaintext using AES-GCM
// Output format: base64(nonce || ciphertext+tag)
//
// WARNING: Empty keys are allowed but provide NO security.
// Anyone can decrypt data encrypted with an empty key.
// Use Enc: NONE if encryption is not needed.
func (a *AesGcm) Encrypt(text string, key string) (string, error) {
	// Derive key of correct length
	derivedKey := deriveKey(key, a.keySize)

	// Create AES cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Encrypt and authenticate
	ciphertext := gcm.Seal(nil, nonce, []byte(text), nil)

	// Prepend nonce to ciphertext
	result := append(nonce, ciphertext...)

	// Encode to base64
	return base64.StdEncoding.EncodeToString(result), nil
}

// Decrypt decrypts ciphertext using AES-GCM
func (a *AesGcm) Decrypt(cipherBase64 string, key string) (string, error) {
	// Decode base64
	data, err := base64.StdEncoding.DecodeString(cipherBase64)
	if err != nil {
		return "", fmt.Errorf("invalid base64: %v", err)
	}

	// Derive key of correct length
	derivedKey := deriveKey(key, a.keySize)

	// Create AES cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	// Check minimum length (nonce + tag)
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	// Split nonce and ciphertext
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %v", err)
	}

	return string(plaintext), nil
}

// ===========================
// AES-CBC Implementations
// ===========================

// AesCbc implements EncryptionAlgorithm for AES-CBC mode
type AesCbc struct {
	keySize int // 16, 24, or 32 bytes for AES-128, AES-192, AES-256
}

// NewAes128Cbc creates an AES-128-CBC encrypter
func NewAes128Cbc() *AesCbc {
	return &AesCbc{keySize: 16}
}

// NewAes192Cbc creates an AES-192-CBC encrypter
func NewAes192Cbc() *AesCbc {
	return &AesCbc{keySize: 24}
}

// NewAes256Cbc creates an AES-256-CBC encrypter
func NewAes256Cbc() *AesCbc {
	return &AesCbc{keySize: 32}
}

// Encrypt encrypts plaintext using AES-CBC with PKCS#7 padding
// Output format: base64(IV || ciphertext)
//
// WARNING: Empty keys are allowed but provide NO security.
// Anyone can decrypt data encrypted with an empty key.
// Use Enc: NONE if encryption is not needed.
func (a *AesCbc) Encrypt(text string, key string) (string, error) {
	// Derive key of correct length
	derivedKey := deriveKey(key, a.keySize)

	// Create AES cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	// Add PKCS#7 padding
	plaintext := pkcs7Pad([]byte(text), aes.BlockSize)

	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to generate IV: %v", err)
	}

	// Encrypt using CBC mode
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	// Prepend IV to ciphertext
	result := append(iv, ciphertext...)

	// Encode to base64
	return base64.StdEncoding.EncodeToString(result), nil
}

// Decrypt decrypts ciphertext using AES-CBC
func (a *AesCbc) Decrypt(cipherBase64 string, key string) (string, error) {
	// Decode base64
	data, err := base64.StdEncoding.DecodeString(cipherBase64)
	if err != nil {
		return "", fmt.Errorf("invalid base64: %v", err)
	}

	// Derive key of correct length
	derivedKey := deriveKey(key, a.keySize)

	// Create AES cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	// Check minimum length (IV + at least one block)
	if len(data) < aes.BlockSize*2 {
		return "", fmt.Errorf("ciphertext too short")
	}

	// Check alignment
	if len(data)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext is not a multiple of block size")
	}

	// Split IV and ciphertext
	iv, ciphertext := data[:aes.BlockSize], data[aes.BlockSize:]

	// Decrypt using CBC mode
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS#7 padding
	plaintext, err = pkcs7Unpad(plaintext)
	if err != nil {
		return "", fmt.Errorf("invalid padding: %v", err)
	}

	return string(plaintext), nil
}

// ===========================
// ChaCha20-Poly1305 Implementation
// ===========================

// ChaCha20Poly1305 implements EncryptionAlgorithm for ChaCha20-Poly1305
type ChaCha20Poly1305 struct{}

// NewChaCha20Poly1305 creates a ChaCha20-Poly1305 encrypter
func NewChaCha20Poly1305() *ChaCha20Poly1305 {
	return &ChaCha20Poly1305{}
}

// Encrypt encrypts plaintext using ChaCha20-Poly1305
// Output format: base64(nonce || ciphertext+tag)
//
// WARNING: Empty keys are allowed but provide NO security.
// Anyone can decrypt data encrypted with an empty key.
// Use Enc: NONE if encryption is not needed.
func (c *ChaCha20Poly1305) Encrypt(text string, key string) (string, error) {
	// Derive 256-bit key
	derivedKey := deriveKey(key, chacha20poly1305.KeySize)

	// Create ChaCha20-Poly1305 AEAD
	aead, err := chacha20poly1305.New(derivedKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	// Generate random nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Encrypt and authenticate
	ciphertext := aead.Seal(nil, nonce, []byte(text), nil)

	// Prepend nonce to ciphertext
	result := append(nonce, ciphertext...)

	// Encode to base64
	return base64.StdEncoding.EncodeToString(result), nil
}

// Decrypt decrypts ciphertext using ChaCha20-Poly1305
func (c *ChaCha20Poly1305) Decrypt(cipherBase64 string, key string) (string, error) {
	// Decode base64
	data, err := base64.StdEncoding.DecodeString(cipherBase64)
	if err != nil {
		return "", fmt.Errorf("invalid base64: %v", err)
	}

	// Derive 256-bit key
	derivedKey := deriveKey(key, chacha20poly1305.KeySize)

	// Create ChaCha20-Poly1305 AEAD
	aead, err := chacha20poly1305.New(derivedKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	// Check minimum length
	nonceSize := aead.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	// Split nonce and ciphertext
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Decrypt and verify
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %v", err)
	}

	return string(plaintext), nil
}

// ===========================
// HMAC-SHA256 Implementation
// ===========================

// HmacSha256 implements SigningAlgorithm for HMAC-SHA256
type HmacSha256 struct{}

// NewHmacSha256 creates an HMAC-SHA256 signer
func NewHmacSha256() *HmacSha256 {
	return &HmacSha256{}
}

// Sign creates an HMAC-SHA256 signature
// Output: base64(HMAC-SHA256(key, content))
//
// WARNING: Empty keys are allowed but provide NO security.
// Anyone can forge signatures with an empty key.
func (h *HmacSha256) Sign(content string, key string) (string, error) {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(content))
	signature := mac.Sum(nil)

	return base64.StdEncoding.EncodeToString(signature), nil
}

// Verify verifies an HMAC-SHA256 signature using constant-time comparison
func (h *HmacSha256) Verify(content string, signatureBase64 string, key string) (bool, error) {
	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return false, fmt.Errorf("invalid base64 signature: %v", err)
	}

	// Compute expected signature
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(content))
	expectedSignature := mac.Sum(nil)

	// Constant-time comparison to prevent timing attacks
	return hmac.Equal(signature, expectedSignature), nil
}
