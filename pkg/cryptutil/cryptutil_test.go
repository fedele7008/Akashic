package cryptutil

import (
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	c, err := New([]byte("test-secret"), "test-purpose")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cases := []string{
		"SG.aXEjJUKyT8GJB-mh.SXrJg2yU3kIeLR8a4u_yz1Iw3qFJxOVwj-NkOhFwK0",
		"hello",
		"a", // shortest non-empty
		strings.Repeat("x", 4096), // long
	}
	for _, plaintext := range cases {
		ct, err := c.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", plaintext, err)
		}
		if ct == "" {
			t.Fatalf("Encrypt(%q): got empty ciphertext", plaintext)
		}
		got, err := c.Decrypt(ct)
		if err != nil {
			t.Fatalf("Decrypt(...): %v", err)
		}
		if got != plaintext {
			t.Fatalf("Decrypt: got %q, want %q", got, plaintext)
		}
	}
}

func TestEncryptEmpty(t *testing.T) {
	c, _ := New([]byte("s"), "p")
	got, err := c.Encrypt("")
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}
	if got != "" {
		t.Fatalf("Encrypt empty: got %q, want \"\"", got)
	}
}

func TestDifferentPurposesDeriveDifferentKeys(t *testing.T) {
	// Same master secret, different purpose tags → ciphertexts MUST
	// fail to decrypt under the other key. Defends against accidental
	// key reuse across column families.
	c1, _ := New([]byte("master"), "purpose-a")
	c2, _ := New([]byte("master"), "purpose-b")
	ct, err := c1.Encrypt("secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := c2.Decrypt(ct); err == nil {
		t.Fatal("Decrypt under wrong purpose should fail; got success")
	}
}

func TestDifferentSecretsDeriveDifferentKeys(t *testing.T) {
	// Same purpose, different master secrets → ciphertexts MUST fail
	// to decrypt under the other secret. Defends against operator
	// secret-rotation bugs.
	c1, _ := New([]byte("master-a"), "purpose")
	c2, _ := New([]byte("master-b"), "purpose")
	ct, err := c1.Encrypt("secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := c2.Decrypt(ct); err == nil {
		t.Fatal("Decrypt under wrong master secret should fail; got success")
	}
}

func TestNonceUniqueness(t *testing.T) {
	// Same input encrypted twice MUST produce different ciphertexts
	// (random nonce). Identical ciphertexts would mean nonce reuse —
	// catastrophic for AES-GCM security.
	c, _ := New([]byte("s"), "p")
	plaintext := "the same input"
	ct1, _ := c.Encrypt(plaintext)
	ct2, _ := c.Encrypt(plaintext)
	if ct1 == ct2 {
		t.Fatal("identical ciphertexts for same input — nonce isn't random")
	}
	// Both must still decrypt to the original.
	if got, _ := c.Decrypt(ct1); got != plaintext {
		t.Fatalf("Decrypt ct1: got %q", got)
	}
	if got, _ := c.Decrypt(ct2); got != plaintext {
		t.Fatalf("Decrypt ct2: got %q", got)
	}
}

func TestNewRejectsEmptyInputs(t *testing.T) {
	if _, err := New(nil, "p"); err == nil {
		t.Fatal("New with empty secret should error")
	}
	if _, err := New([]byte("s"), ""); err == nil {
		t.Fatal("New with empty info should error")
	}
}

func TestDecryptRejectsTampering(t *testing.T) {
	// Flipping a bit in the ciphertext must cause GCM auth tag
	// verification to fail. Defends against a tampered DB row.
	c, _ := New([]byte("s"), "p")
	ct, _ := c.Encrypt("important data")
	// Flip the last char (almost certainly inside the auth tag).
	tampered := ct[:len(ct)-1] + flipChar(ct[len(ct)-1])
	if _, err := c.Decrypt(tampered); err == nil {
		t.Fatal("Decrypt of tampered ciphertext should fail")
	}
}

func TestIsPlaintext(t *testing.T) {
	c, _ := New([]byte("s"), "p")

	// Real ciphertext should NOT be classified as plaintext.
	ct, _ := c.Encrypt("a SendGrid-style key SG.xxxxxxxxxx")
	if IsPlaintext(ct) {
		t.Fatal("real ciphertext mis-classified as plaintext")
	}

	// SendGrid-style key (contains dots) — not valid base64, should
	// be classified as plaintext.
	if !IsPlaintext("SG.aXEjJUKyT8GJB-mh.SXrJg2yU3kIeLR8a4u_yz1Iw3qFJxOVwj-NkOhFwK0") {
		t.Fatal("SendGrid-style key should be classified as plaintext")
	}

	// Empty input — neither plaintext nor ciphertext.
	if IsPlaintext("") {
		t.Fatal("empty string should not be classified as plaintext")
	}

	// Short base64 (decodes but too short for real ciphertext).
	if !IsPlaintext("YQ==") { // base64 of "a"
		t.Fatal("short base64 should be classified as plaintext")
	}
}

func flipChar(b byte) string {
	if b == 'A' {
		return "B"
	}
	return "A"
}
