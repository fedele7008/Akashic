package core

import (
	"crypto/sha256"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// Test data
const (
	testPassword  = "my-secret-key-123"
	testPlaintext = "Hello, World! This is a test message with unicode: 你好世界 🌍"
	testLongText  = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " +
		"Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. " +
		"Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris."
)

// Test salt (fixed for deterministic tests)
var testSalt = []byte("test-salt-for-crypto-tests-12345")

// Pre-derived test keys for different key sizes
var (
	testKey16 = pbkdf2.Key([]byte(testPassword), testSalt, 10000, 16, sha256.New) // AES-128
	testKey24 = pbkdf2.Key([]byte(testPassword), testSalt, 10000, 24, sha256.New) // AES-192
	testKey32 = pbkdf2.Key([]byte(testPassword), testSalt, 10000, 32, sha256.New) // AES-256, ChaCha20, HMAC
)

// deriveTestKey derives a key from password for testing (simpler than production)
func deriveTestKey(password string, keySize int) []byte {
	return pbkdf2.Key([]byte(password), testSalt, 10000, keySize, sha256.New)
}

// ===========================
// AES-GCM Tests
// ===========================

func TestAes128Gcm_RoundTrip(t *testing.T) {
	cipher := NewAes128Gcm()
	testEncryptionRoundTrip(t, cipher, "AES-128-GCM", testKey16)
}

func TestAes192Gcm_RoundTrip(t *testing.T) {
	cipher := NewAes192Gcm()
	testEncryptionRoundTrip(t, cipher, "AES-192-GCM", testKey24)
}

func TestAes256Gcm_RoundTrip(t *testing.T) {
	cipher := NewAes256Gcm()
	testEncryptionRoundTrip(t, cipher, "AES-256-GCM", testKey32)
}

func TestAesGcm_EmptyKey(t *testing.T) {
	cipher := NewAes256Gcm()

	// Empty keys should work (but are insecure)
	encrypted, err := (func() (string, error) { emptyKey := make([]byte, 32); return cipher.Encrypt(testPlaintext, emptyKey) })()
	if err != nil {
		t.Fatalf("Encryption with empty key failed: %v", err)
	}

	// Should be able to decrypt with the same empty key
	decrypted, err := cipher.Decrypt(encrypted, make([]byte, 32))
	if err != nil {
		t.Fatalf("Decryption with empty key failed: %v", err)
	}

	if decrypted != testPlaintext {
		t.Errorf("Round-trip with empty key failed: got %q, want %q", decrypted, testPlaintext)
	}

	// Different empty key encryptions should still have different nonces
	encrypted2, _ := (func() (string, error) { emptyKey := make([]byte, 32); return cipher.Encrypt(testPlaintext, emptyKey) })()
	if encrypted == encrypted2 {
		t.Error("Expected different ciphertexts even with empty key (different nonces)")
	}
}

func TestAesGcm_InvalidCiphertext(t *testing.T) {
	cipher := NewAes256Gcm()

	// Test invalid base64
	_, err := cipher.Decrypt("not-valid-base64!!!", testKey32)
	if err == nil {
		t.Error("Expected error with invalid base64, got nil")
	}

	// Test too short ciphertext
	_, err = cipher.Decrypt("YWJj", testKey32) // "abc" in base64 - too short
	if err == nil {
		t.Error("Expected error with too short ciphertext, got nil")
	}

	// Test wrong key
	encrypted, _ := cipher.Encrypt(testPlaintext, testKey32)
	_, err = cipher.Decrypt(encrypted, deriveTestKey("wrong-key", 32))
	if err == nil {
		t.Error("Expected error with wrong key, got nil")
	}
}

func TestAesGcm_DifferentNoncesEachTime(t *testing.T) {
	cipher := NewAes256Gcm()

	// Encrypt the same plaintext multiple times
	encrypted1, err := cipher.Encrypt(testPlaintext, testKey32)
	if err != nil {
		t.Fatalf("Encryption 1 failed: %v", err)
	}

	encrypted2, err := cipher.Encrypt(testPlaintext, testKey32)
	if err != nil {
		t.Fatalf("Encryption 2 failed: %v", err)
	}

	// Ciphertexts should be different (different nonces)
	if encrypted1 == encrypted2 {
		t.Error("Expected different ciphertexts with different nonces")
	}

	// But both should decrypt to the same plaintext
	plaintext1, _ := cipher.Decrypt(encrypted1, testKey32)
	plaintext2, _ := cipher.Decrypt(encrypted2, testKey32)

	if plaintext1 != testPlaintext || plaintext2 != testPlaintext {
		t.Error("Decryption failed to produce original plaintext")
	}
}

// ===========================
// AES-CBC Tests
// ===========================

func TestAes128Cbc_RoundTrip(t *testing.T) {
	cipher := NewAes128Cbc()
	testEncryptionRoundTrip(t, cipher, "AES-128-CBC", testKey16)
}

func TestAes192Cbc_RoundTrip(t *testing.T) {
	cipher := NewAes192Cbc()
	testEncryptionRoundTrip(t, cipher, "AES-192-CBC", testKey24)
}

func TestAes256Cbc_RoundTrip(t *testing.T) {
	cipher := NewAes256Cbc()
	testEncryptionRoundTrip(t, cipher, "AES-256-CBC", testKey32)
}

func TestAesCbc_EmptyKey(t *testing.T) {
	cipher := NewAes256Cbc()

	// Empty keys should work (but are insecure)
	encrypted, err := (func() (string, error) { emptyKey := make([]byte, 32); return cipher.Encrypt(testPlaintext, emptyKey) })()
	if err != nil {
		t.Fatalf("Encryption with empty key failed: %v", err)
	}

	// Should be able to decrypt with the same empty key
	decrypted, err := cipher.Decrypt(encrypted, make([]byte, 32))
	if err != nil {
		t.Fatalf("Decryption with empty key failed: %v", err)
	}

	if decrypted != testPlaintext {
		t.Errorf("Round-trip with empty key failed: got %q, want %q", decrypted, testPlaintext)
	}
}

func TestAesCbc_InvalidCiphertext(t *testing.T) {
	cipher := NewAes256Cbc()

	// Test invalid base64
	_, err := cipher.Decrypt("not-valid-base64!!!", testKey32)
	if err == nil {
		t.Error("Expected error with invalid base64, got nil")
	}

	// Test too short ciphertext
	_, err = cipher.Decrypt("YWJj", testKey32) // "abc" in base64 - too short
	if err == nil {
		t.Error("Expected error with too short ciphertext, got nil")
	}

	// Test wrong key
	encrypted, _ := cipher.Encrypt(testPlaintext, testKey32)
	_, err = cipher.Decrypt(encrypted, deriveTestKey("wrong-key", 32))
	if err == nil {
		t.Error("Expected error with wrong key (padding error), got nil")
	}
}

func TestAesCbc_Padding(t *testing.T) {
	cipher := NewAes256Cbc()

	// Test various text lengths to ensure padding works correctly
	testTexts := []string{
		"a",                                    // 1 byte
		"ab",                                   // 2 bytes
		"0123456789abcdef",                     // 16 bytes (exact block)
		"0123456789abcdefg",                    // 17 bytes
		"0123456789abcdef0123456789abcdef",     // 32 bytes (2 exact blocks)
		"0123456789abcdef0123456789abcdef012", // 35 bytes
	}

	for _, text := range testTexts {
		encrypted, err := cipher.Encrypt(text, testKey32)
		if err != nil {
			t.Errorf("Encryption failed for %d-byte text: %v", len(text), err)
			continue
		}

		decrypted, err := cipher.Decrypt(encrypted, testKey32)
		if err != nil {
			t.Errorf("Decryption failed for %d-byte text: %v", len(text), err)
			continue
		}

		if decrypted != text {
			t.Errorf("Round-trip failed for %d-byte text: got %q, want %q", len(text), decrypted, text)
		}
	}
}

// ===========================
// ChaCha20-Poly1305 Tests
// ===========================

func TestChaCha20Poly1305_RoundTrip(t *testing.T) {
	cipher := NewChaCha20Poly1305()
	testEncryptionRoundTrip(t, cipher, "ChaCha20-Poly1305", testKey32)
}

func TestChaCha20Poly1305_EmptyKey(t *testing.T) {
	cipher := NewChaCha20Poly1305()

	// Empty keys should work (but are insecure)
	encrypted, err := (func() (string, error) { emptyKey := make([]byte, 32); return cipher.Encrypt(testPlaintext, emptyKey) })()
	if err != nil {
		t.Fatalf("Encryption with empty key failed: %v", err)
	}

	// Should be able to decrypt with the same empty key
	decrypted, err := cipher.Decrypt(encrypted, make([]byte, 32))
	if err != nil {
		t.Fatalf("Decryption with empty key failed: %v", err)
	}

	if decrypted != testPlaintext {
		t.Errorf("Round-trip with empty key failed: got %q, want %q", decrypted, testPlaintext)
	}
}

func TestChaCha20Poly1305_InvalidCiphertext(t *testing.T) {
	cipher := NewChaCha20Poly1305()

	// Test invalid base64
	_, err := cipher.Decrypt("not-valid-base64!!!", testKey32)
	if err == nil {
		t.Error("Expected error with invalid base64, got nil")
	}

	// Test too short ciphertext
	_, err = cipher.Decrypt("YWJj", testKey32) // "abc" in base64 - too short
	if err == nil {
		t.Error("Expected error with too short ciphertext, got nil")
	}

	// Test wrong key
	encrypted, _ := cipher.Encrypt(testPlaintext, testKey32)
	_, err = cipher.Decrypt(encrypted, deriveTestKey("wrong-key", 32))
	if err == nil {
		t.Error("Expected error with wrong key, got nil")
	}
}

// ===========================
// HMAC-SHA256 Tests
// ===========================

func TestHmacSha256_SignAndVerify(t *testing.T) {
	signer := NewHmacSha256()

	// Sign
	signature, err := signer.Sign(testPlaintext, testKey32)
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}

	// Verify with correct key
	valid, err := signer.Verify(testPlaintext, signature, testKey32)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
	if !valid {
		t.Error("Signature verification failed with correct key")
	}

	// Verify with wrong key
	valid, err = signer.Verify(testPlaintext, signature, deriveTestKey("wrong-key", 32))
	if err != nil {
		t.Fatalf("Verification error: %v", err)
	}
	if valid {
		t.Error("Signature verification succeeded with wrong key")
	}

	// Verify with modified content
	valid, err = signer.Verify(testPlaintext+"modified", signature, testKey32)
	if err != nil {
		t.Fatalf("Verification error: %v", err)
	}
	if valid {
		t.Error("Signature verification succeeded with modified content")
	}
}

func TestHmacSha256_EmptyKey(t *testing.T) {
	signer := NewHmacSha256()

	// Empty keys should work (but are insecure)
	signature, err := signer.Sign(testPlaintext, make([]byte, 32))
	if err != nil {
		t.Fatalf("Signing with empty key failed: %v", err)
	}

	// Should be able to verify with the same empty key
	valid, err := signer.Verify(testPlaintext, signature, make([]byte, 32))
	if err != nil {
		t.Fatalf("Verification with empty key failed: %v", err)
	}

	if !valid {
		t.Error("Signature verification failed with empty key")
	}

	// Anyone can forge signatures with empty key
	forgedSig, _ := signer.Sign("modified content", make([]byte, 32))
	valid, _ = signer.Verify("modified content", forgedSig, make([]byte, 32))
	if !valid {
		t.Error("Should be able to forge signatures with known empty key")
	}
}

func TestHmacSha256_InvalidSignature(t *testing.T) {
	signer := NewHmacSha256()

	// Test invalid base64
	_, err := signer.Verify(testPlaintext, "not-valid-base64!!!", testKey32)
	if err == nil {
		t.Error("Expected error with invalid base64 signature, got nil")
	}
}

func TestHmacSha256_DeterministicSignature(t *testing.T) {
	signer := NewHmacSha256()

	// Sign the same content multiple times
	sig1, _ := signer.Sign(testPlaintext, testKey32)
	sig2, _ := signer.Sign(testPlaintext, testKey32)

	// Signatures should be identical (HMAC is deterministic)
	if sig1 != sig2 {
		t.Error("Expected identical signatures for same content and key")
	}
}

// ===========================
// Factory Function Tests
// ===========================

func TestGetEncryptionAlgorithm(t *testing.T) {
	tests := []struct {
		alg       EncAlg
		shouldErr bool
	}{
		{AES_128_GCM, false},
		{AES_192_GCM, false},
		{AES_256_GCM, false},
		{AES_128_CBC, false},
		{AES_192_CBC, false},
		{AES_256_CBC, false},
		{CHACHA20_POLY1305, false},
		{NONE, true}, // Should error
		{"INVALID", true},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			cipher, err := GetEncryptionAlgorithm(tt.alg)
			if tt.shouldErr {
				if err == nil {
					t.Errorf("Expected error for algorithm %s, got nil", tt.alg)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for algorithm %s, got: %v", tt.alg, err)
				}
				if cipher == nil {
					t.Errorf("Expected non-nil cipher for algorithm %s", tt.alg)
				}
			}
		})
	}
}

func TestGetSigningAlgorithm(t *testing.T) {
	tests := []struct {
		alg       SignAlg
		shouldErr bool
	}{
		{HMAC_SHA256, false},
		{"INVALID", true},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			signer, err := GetSigningAlgorithm(tt.alg)
			if tt.shouldErr {
				if err == nil {
					t.Errorf("Expected error for algorithm %s, got nil", tt.alg)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for algorithm %s, got: %v", tt.alg, err)
				}
				if signer == nil {
					t.Errorf("Expected non-nil signer for algorithm %s", tt.alg)
				}
			}
		})
	}
}

// ===========================
// Helper Functions
// ===========================

func testEncryptionRoundTrip(t *testing.T, cipher EncryptionAlgorithm, name string, key []byte) {
	t.Helper()

	testCases := []struct {
		name      string
		plaintext string
	}{
		{"Basic text", testPlaintext},
		{"Long text", testLongText},
		{"Empty string", ""},
		{"Single character", "x"},
		{"Special characters", "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			encrypted, err := cipher.Encrypt(tc.plaintext, key)
			if err != nil {
				t.Fatalf("%s encryption failed: %v", name, err)
			}

			// Basic validation
			if encrypted == "" {
				t.Fatalf("%s produced empty ciphertext", name)
			}

			// Decrypt
			decrypted, err := cipher.Decrypt(encrypted, key)
			if err != nil {
				t.Fatalf("%s decryption failed: %v", name, err)
			}

			// Verify
			if decrypted != tc.plaintext {
				t.Errorf("%s round-trip failed: got %q, want %q", name, decrypted, tc.plaintext)
			}
		})
	}
}

// ===========================
// Key Derivation Tests
// ===========================
// Note: Key derivation is now handled in secure_token.go using PBKDF2 + HKDF.
// These tests verify the test helper function used in this file.

func TestDeriveTestKey_DifferentLengths(t *testing.T) {
	// Test that deriveTestKey produces keys of different lengths correctly
	key16 := deriveTestKey(testPassword, 16)
	key24 := deriveTestKey(testPassword, 24)
	key32 := deriveTestKey(testPassword, 32)

	if len(key16) != 16 {
		t.Errorf("Expected 16-byte key, got %d bytes", len(key16))
	}
	if len(key24) != 24 {
		t.Errorf("Expected 24-byte key, got %d bytes", len(key24))
	}
	if len(key32) != 32 {
		t.Errorf("Expected 32-byte key, got %d bytes", len(key32))
	}
}

func TestDeriveTestKey_Deterministic(t *testing.T) {
	// Same password should produce same key (for testing purposes)
	key1 := deriveTestKey(testPassword, 32)
	key2 := deriveTestKey(testPassword, 32)

	if string(key1) != string(key2) {
		t.Error("Test key derivation should be deterministic")
	}
}

func TestDeriveTestKey_DifferentPasswords(t *testing.T) {
	// Different passwords should produce different keys
	key1 := deriveTestKey("password1", 32)
	key2 := deriveTestKey("password2", 32)

	if string(key1) == string(key2) {
		t.Error("Different passwords should produce different keys")
	}
}

// ===========================
// PKCS#7 Padding Tests
// ===========================

func TestPkcs7Padding(t *testing.T) {
	blockSize := 16

	testCases := []struct {
		name string
		data string
	}{
		{"Empty", ""},
		{"1 byte", "a"},
		{"15 bytes", strings.Repeat("a", 15)},
		{"16 bytes (exact block)", strings.Repeat("a", 16)},
		{"17 bytes", strings.Repeat("a", 17)},
		{"31 bytes", strings.Repeat("a", 31)},
		{"32 bytes (2 exact blocks)", strings.Repeat("a", 32)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			original := []byte(tc.data)

			// Pad
			padded := pkcs7Pad(original, blockSize)

			// Check padding is correct
			if len(padded)%blockSize != 0 {
				t.Errorf("Padded data is not block-aligned: length=%d", len(padded))
			}

			// Unpad
			unpadded, err := pkcs7Unpad(padded)
			if err != nil {
				t.Fatalf("Unpadding failed: %v", err)
			}

			// Verify
			if string(unpadded) != tc.data {
				t.Errorf("Round-trip failed: got %q, want %q", string(unpadded), tc.data)
			}
		})
	}
}

func TestPkcs7Unpad_Invalid(t *testing.T) {
	// Test invalid padding detection
	_, err := pkcs7Unpad([]byte{})
	if err == nil {
		t.Error("Expected error for empty data")
	}

	_, err = pkcs7Unpad([]byte{0, 0, 0, 16}) // Invalid padding
	if err == nil {
		t.Error("Expected error for invalid padding")
	}

	_, err = pkcs7Unpad([]byte{1, 2, 3, 5}) // Last byte says 5 but only 4 bytes total
	if err == nil {
		t.Error("Expected error for padding larger than data")
	}
}
