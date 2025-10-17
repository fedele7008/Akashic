# Secure Token System

## Table of Contents

1. [Introduction](#introduction)
2. [Security Architecture](#security-architecture)
3. [Cryptographic Specifications](#cryptographic-specifications)
4. [Threat Model](#threat-model)
5. [Token Structure](#token-structure)
6. [Key Derivation Hierarchy](#key-derivation-hierarchy)
7. [Token Lifecycle](#token-lifecycle)
8. [Security Analysis](#security-analysis)
9. [Best Practices](#best-practices)
10. [Code Examples](#code-examples)
11. [References](#references)

---

## Introduction

### Purpose

The Akashic Secure Token System provides a cryptographically secure method for storing sensitive project secrets (such as Vault unseal keys and root tokens) on disk, encrypted with a user-provided passphrase. This system is designed to meet the following security objectives:

1. **Confidentiality**: Secrets remain encrypted at rest
2. **Integrity**: Tampering with tokens is detectable
3. **Authentication**: Only holders of the correct passphrase can decrypt
4. **Forward Secrecy**: Each token is cryptographically independent

### Use Cases

#### Primary Use Case: Vault Token Storage

The Akashic project uses HashiCorp Vault for PKI management. During vault initialization:

- **Root Token**: Superuser access to all Vault operations
- **Unseal Keys**: 5 keys generated using Shamir's Secret Sharing (threshold: 3)

These highly sensitive credentials must be stored securely on disk. The secure token system encrypts them using a passphrase (`AKASHIC_SECRET`) before writing to `./.secrets/vault/`.

#### Other Use Cases

- Configuration secrets
- API keys and credentials
- Sensitive metadata
- Any data requiring passphrase-protected storage

### Design Philosophy

The secure token system follows these principles:

1. **Defense in Depth**: Multiple layers of cryptographic protection
2. **Best Practices**: OWASP and NIST recommended algorithms and parameters
3. **Flexibility**: Support for multiple encryption algorithms
4. **Future-Proof**: Versioning for algorithm upgrades
5. **Transparency**: Open design, auditable implementation

---

## Security Architecture

### High-Level Overview

```ASCII
┌─────────────────────────────────────────────────────────────┐
│                  User-Provided Passphrase                   │
│                    (any length string)                      │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ├─► Random Salt Generation (32 bytes)
                       │
                       ▼
            ┌──────────────────────┐
            │    PBKDF2-SHA256     │
            │ (600,000 iterations) │
            └──────────┬───────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │      Master Key      │
            │      (32 bytes)      │
            └──────────┬───────────┘
                       │
            ┌──────────┴───────────┐
            │      HKDF-SHA256     │
            │  (context-specific)  │
            └──────┬──────────┬────┘
                   │          │
                   ▼          ▼
       ┌────────────────┐  ┌────────────────┐
       │ Encryption Key │  │   Signing Key  │
       │  (16/24/32 B)  │  │   (32 bytes)   │
       │                │  |   HMAC-SHA256  │
       └────────┬───────┘  └────────┬───────┘
                │                   │
                ▼                   ▼
      ┌──────────────────┐  ┌──────────────┐
      │ AES-GCM/CBC      │  │ HMAC-SHA256  │
      │ ChaCha20-Poly1305│  │ Signature    │
      └──────────────────┘  └──────────────┘
```

### Token Format

Tokens follow a **JWT-inspired** structure with three parts separated by dots:

```ASCII
BASE64(metadata).BASE64(encrypted_data).BASE64(hmac_signature)
```

**Example:**

```ASCII
eyJ2ZXIiOjEsImVuYyI6IkFFUy0yNTYtR0NNIiwiYWxnIjoiSFMyNTYiLCJzdWIiOiJ2YXVsdC1yb290LXRva2VuIiwiaXNzIjoiYWthc2hpYy1jbGkiLCJjbnQiOiJ0ZXh0Iiwic2x0IjoiY1daYllXRmhZV0ZoWVdGaFlXRmhZV0ZoWVdGaFlXRmhZV0U9IiwiaWF0IjoxNzI5MjEwNDAwMDAwMDAwfQ.ZnNkZmpoc2RqZmhzZGpm...SkRmaHNkamZoc2RqZmhzZGpm.c2RmaHNkamZoc2RqZmhzZGpm...
```

---

## Cryptographic Specifications

### 1. Random Salt Generation

**Algorithm**: Cryptographically secure random number generator (`crypto/rand`)

**Parameters:**

- **Salt Size**: 32 bytes (256 bits)
- **Uniqueness**: New random salt generated for **every token**

**Why Random Salt Per Token?**

❌ **Fixed Salt Problem:**

```ASCII
Same Password + Fixed Salt = Same Master Key
  → Rainbow tables can precompute password→key mappings
  → Attacker can build one table and attack all tokens
```

✅ **Random Salt Solution:**

```ASCII
Same Password + Random Salt₁ = Master Key₁
Same Password + Random Salt₂ = Master Key₂
  → Each token has unique cryptographic properties
  → Precomputation attacks become infeasible
  → Cost: O(n) per token instead of O(1) for all tokens
```

**Security Impact:**

- Prevents rainbow table attacks
- Prevents detection of duplicate passphrases across tokens
- Forces attackers to brute-force each token individually

**Storage:**

- Salt is stored in token metadata (`slt` field)
- Encoded as Base64 for JSON compatibility
- NOT secret (salts are public values in KDF design)

---

### 2. PBKDF2-SHA256 (Password-Based Key Derivation)

**Full Name**: Password-Based Key Derivation Function 2
**Hash Function**: SHA-256
**Iterations**: 600,000

**Purpose:**
Convert variable-length passphrase → fixed-length master key

**Parameters:**

```go
const (
    pbkdf2Iterations = 600000  // OWASP 2023 recommendation
    masterKeySize    = 32      // 256 bits
)

masterKey := pbkdf2.Key(
    []byte(passphrase),
    salt,              // 32-byte random salt
    600000,            // iterations
    32,                // output length
    sha256.New,        // PRF
)
```

**Why 600,000 Iterations?**

**OWASP Evolution:**

- 2017: 100,000 iterations (deprecated)
- 2023: **600,000 iterations** (current recommendation)

**Attack Cost Analysis:**

Assuming attacker has:

- Modern GPU (RTX 4090 as of October 2025)
- ~10 billion PBKDF2-SHA256 hashes/second

| Iterations | Time per Password | 1 Billion Passwords |
|------------|-------------------|---------------------|
| 100,000    | ~1 second         | ~31 years           |
| 600,000    | **~6 seconds**    | **~190 years**      |

**Key Point**: 6× increase in iterations = 6× increase in attacker cost, but only marginal impact on legitimate users (who compute once).

**Why Not More Iterations?**

Balance between security and usability:

- **600K iterations**: ~100ms on modern CPUs (acceptable for CLI usage)
- **6M iterations**: ~1 second (noticeable delay, frustrating UX)

For memory-hard alternatives, see [Future Improvements](#future-improvements).

---

### 3. HKDF-SHA256 (HMAC-Based Key Derivation)

**Full Name**: HMAC-based Extract-and-Expand Key Derivation Function \
**Hash Function**: SHA-256 \
**RFC**: 5869

**Purpose:**
Derive **cryptographically independent** encryption and signing keys from the master key

**Why Separate Keys?**

❌ **Single Key Problem:**

```ASCII
Same Key for Encryption + Signing = Reduced Security
  → Key reuse weakens cryptographic guarantees
  → Compromising one operation may affect the other
```

✅ **Separate Keys (HKDF):**

```ASCII
Master Key ──HKDF──> Encryption Key (for AES/ChaCha20)
          └──HKDF──> Signing Key (for HMAC)
  → Cryptographically independent
  → Defense in depth: compromise one ≠ compromise both
```

**Implementation:**

```go
// Encryption key derivation
encKey := HKDF(
    masterKey,
    salt,
    []byte("akashic-token-encryption-v1"),  // Context-specific info
    keySize,  // 16, 24, or 32 bytes
)

// Signing key derivation
sigKey := HKDF(
    masterKey,
    salt,
    []byte("akashic-token-signing-v1"),  // Different context
    32,  // Always 32 bytes for HMAC-SHA256
)
```

**Context-Specific Info Strings:**

The info parameter provides **domain separation**:

- Different info strings → Different derived keys
- Even if master key leaks, each domain remains isolated
- Version suffix (`-v1`) allows future algorithm upgrades

**Security Properties:**

- **Key Independence**: Knowing `encKey` reveals nothing about `sigKey`
- **Forward Secrecy**: Compromising one token doesn't help with others
- **Domain Separation**: Encryption and authentication are cryptographically isolated

---

### 4. Encryption Algorithms

The system supports **7 encryption algorithms** across 3 families:

#### 4.1 AES-GCM (Galois/Counter Mode)

**Supported Key Sizes:**

- **AES-128-GCM**: 16-byte key (128 bits)
- **AES-192-GCM**: 24-byte key (192 bits)
- **AES-256-GCM**: 32-byte key (256 bits) **[Recommended]**

**Properties:**

- **AEAD**: Authenticated Encryption with Associated Data
- **Nonce**: 12-byte random nonce per encryption
- **Tag**: 16-byte authentication tag (automatically appended)

**Why AES-GCM?**

**Advantages:**

- Provides both confidentiality **and** authenticity in one operation
- Hardware acceleration (AES-NI on modern CPUs)
- NIST-approved (SP 800-38D)
- Parallelizable (fast on multi-core systems)

**Nonce Requirements:**

- **MUST** be unique for each encryption with the same key
- Our implementation: Random nonce via `crypto/rand` (collision probability: negligible)

**Output Format:**

```ASCII
base64(nonce || ciphertext+tag)
```

#### 4.2 AES-CBC (Cipher Block Chaining)

**Supported Key Sizes:**

- **AES-128-CBC**: 16-byte key
- **AES-192-CBC**: 24-byte key
- **AES-256-CBC**: 32-byte key

**Properties:**

- **Padding**: PKCS#7 (aligns data to 16-byte blocks)
- **IV**: 16-byte random initialization vector
- **Authentication**: Provided by separate HMAC (not built-in)

**Why Provide CBC?**

- Compatibility with legacy systems
- Simpler implementation (no AEAD complexity)
- Well-understood security model

**CBC Limitations:**

- Requires padding (slightly larger ciphertext)
- Vulnerable to padding oracle attacks (mitigated by HMAC-then-Encrypt in our design)
- Not parallelizable (slower than GCM on multi-core)

**Recommendation**: Use AES-GCM instead unless compatibility requires CBC.

#### 4.3 ChaCha20-Poly1305

**Properties:**

- **Key Size**: 32 bytes (256 bits)
- **Nonce**: 12-byte random nonce
- **Tag**: 16-byte Poly1305 authentication tag
- **AEAD**: Authenticated encryption

**Why ChaCha20-Poly1305?**

**Advantages:**

- Software-friendly (no hardware acceleration needed)
- Faster than AES on CPUs without AES-NI
- Designed by Daniel J. Bernstein (renowned cryptographer)
- Used in TLS 1.3, WireGuard, SSH

**Use Case:**

- Embedded systems without AES-NI
- ARM processors (mobile, IoT)
- Preference for software-only crypto

**Security:**

- **IETF Standard**: RFC 8439
- **Proven Security**: Extensive analysis, no known practical attacks
- **Constant-Time**: Resistant to timing attacks

---

### 5. HMAC-SHA256 (Authentication)

**Full Name**: Hash-based Message Authentication Code using SHA-256 \
**Key Size**: 32 bytes (256 bits) \
**Output**: 32 bytes (256 bits)

**Purpose:**
Authenticate token integrity and detect tampering

#### Why HMAC?

**Properties:**

- **Integrity**: Any modification changes the HMAC
- **Authentication**: Only holders of the signing key can generate valid HMACs
- **Deterministic**: Same input → same HMAC (reproducible)

**Constant-Time Verification:**

```go
// ❌ VULNERABLE: Timing attack
if signature == expectedSignature {
    return true
}

// ✅ SECURE: Constant-time comparison
return hmac.Equal(signature, expectedSignature)
```

**Why Constant-Time?**

Byte-by-byte comparison leaks information through timing:

```ASCII
Expected: [A B C D E F]
Attempt:  [A B C X Y Z]
           ↑ ↑ ↑ STOP here (3 iterations)

Expected: [A B C D E F]
Attempt:  [A B C D X Z]
           ↑ ↑ ↑ ↑ ↑ STOP here (5 iterations)
```

Attacker can measure response time to guess bytes one-by-one.

**Our Implementation:**

```go
return hmac.Equal(signature, expectedSignature)
  → Compares all bytes regardless of mismatches
  → Timing is independent of where differences occur
```

**Security:**

- **NIST-Approved**: FIPS 198-1
- **Proven Security**: Based on collision resistance of SHA-256
- **Widely Used**: TLS, JWT, OAuth, HMAC-based OTP

---

### 6. Version Field

**Purpose**: Enable forward-compatible algorithm upgrades

**Current Version**: `1`

**Structure:**

```json
{
  "ver": 1,
  "enc": "AES-256-GCM",
  "alg": "HS256",
  "slt": "base64_salt",
  ...
}
```

**Future Upgrade Path:**

```ASCII
Version 1 (Current):
  - PBKDF2-SHA256 (600K iterations)
  - HKDF-SHA256
  - AES-GCM / ChaCha20-Poly1305
  - HMAC-SHA256

Version 2 (Future):
  - Argon2id (memory-hard KDF)
  - HKDF-BLAKE3
  - AES-GCM-SIV (nonce-misuse resistant)
  - BLAKE3-keyed

Migration Strategy:
  1. Implement v2 algorithms alongside v1
  2. Reader checks "ver" field and uses appropriate decoder
  3. Gradual migration: re-encrypt tokens with v2 on access
  4. Deprecate v1 after migration period
```

**Why Versioning?**

Cryptographic algorithms age:

- **Today**: SHA-256 is secure
- **2030+**: Quantum computers may threaten SHA-256
- **Versioning**: Enables smooth transition to post-quantum crypto

---

## Threat Model

### What We Protect Against

✅ **Offline Brute-Force Attacks**

- **Threat**: Attacker steals encrypted token files, tries millions of passphrases
- **Mitigation**: 600,000 PBKDF2 iterations makes each guess expensive (~6 seconds)
- **Result**: 10-character random password ≈ 190 years to crack with modern GPU

✅ **Rainbow Table Attacks**

- **Threat**: Precomputed password→hash tables
- **Mitigation**: Random salt per token (32 bytes) makes precomputation infeasible
- **Result**: Attacker must brute-force each token individually

✅ **Timing Attacks (Side-Channel)**

- **Threat**: Measure verification time to leak information
- **Mitigation**: Constant-time HMAC comparison (`hmac.Equal`)
- **Result**: Timing is independent of signature correctness

✅ **Key Reuse Attacks**

- **Threat**: Using same key for encryption and signing weakens both
- **Mitigation**: HKDF derives separate keys for each purpose
- **Result**: Encryption key compromise doesn't affect authentication

✅ **Tampering / Forgery**

- **Threat**: Modify encrypted data without detection
- **Mitigation**: HMAC-SHA256 signature over metadata + ciphertext
- **Result**: Any modification invalidates the token

✅ **Replay Attacks** (Limited)

- **Threat**: Reuse old valid tokens
- **Mitigation**: Each token has unique random nonce (prevents ciphertext reuse)
- **Note**: Application-layer replay protection (timestamps, nonces) may be needed

✅ **Nonce Reuse (AEAD)**

- **Threat**: Using same nonce twice with AES-GCM leaks plaintext
- **Mitigation**: Random nonce per encryption (96 bits, collision probability: 2^-96)
- **Result**: Practical security for billions of tokens

### What We Do NOT Protect Against

❌ **Weak Passphrases**

- If user chooses `passphrase = "password123"`, no KDF can save them
- **Recommendation**: Minimum 16 characters, random/high-entropy

❌ **Physical Access to Running Process**

- Passphrases and derived keys exist in memory during encryption/decryption
- **Threat**: Memory dumps, debuggers, swap files
- **Mitigation** (Future): Memory locking, key erasure, HSM integration

❌ **Keyloggers / Malware**

- If attacker captures passphrase as user types it, encryption is moot
- **Mitigation**: Endpoint security, secure boot, attestation

❌ **Passphrase Stored Insecurely**

- If `AKASHIC_SECRET` is hardcoded in scripts or `.env` files committed to Git
- **Recommendation**: Environment variables, secret managers, hardware tokens

❌ **Quantum Computer Attacks** (Future Threat)

- Current algorithms (AES-256, SHA-256, HMAC) have reduced but not zero security against quantum computers
- **Mitigation** (Future): Post-quantum key encapsulation (CRYSTALS-Kyber), signatures (Dilithium)

❌ **Side-Channel Attacks (Advanced)**

- Power analysis, electromagnetic emanation, cache-timing
- **Context**: Our threat model assumes software-level attacks, not physical attacks on hardware

---

## Token Structure

### Metadata (Header)

**Encoding**: Base64(JSON)

**Fields:**

```json
{
  "ver": 1,                     // Token format version
  "enc": "AES-256-GCM",         // Encryption algorithm
  "alg": "HS256",               // Signing algorithm (HMAC-SHA256)
  "sub": "vault/root/token",    // Subject (what this token contains)
  "dtl": "production vault",    // Details (optional description)
  "iss": "akashic-cli",         // Issuer (who created this token)
  "cnt": "text",                // Content type (text, json, yaml, base64)
  "slt": "cWZiYWFhYW...",       // Base64-encoded random salt (32 bytes)
  "iat": 1729210400000000000    // Issued at (Unix nanoseconds)
}
```

**Field Descriptions:**

| Field | Type   | Description                                      | Example               |
|-------|--------|--------------------------------------------------|-----------------------|
| `ver` | int    | Token format version (current: 1)                | `1`                   |
| `enc` | string | Encryption algorithm identifier                  | `"AES-256-GCM"`       |
| `alg` | string | Signing algorithm identifier                     | `"HS256"`             |
| `sub` | string | Subject - what this token represents             | `"vault/unseal/key"`  |
| `dtl` | string | Details - optional human-readable description    | `"key 3 of 5"`        |
| `iss` | string | Issuer - who/what created this token             | `"akashic-cli"`       |
| `cnt` | string | Content type of encrypted data                   | `"text"`, `"json"`    |
| `slt` | string | Base64-encoded random salt (32 bytes)            | `"cWZiYWFh..."`       |
| `iat` | int64  | Issued at timestamp (Unix nanoseconds)           | `1729210400000000000` |

**Why Unix Nanoseconds for `iat`?**

- Precision for token lifecycle tracking
- Collision prevention for high-frequency issuance
- Compatible with Go's `time.Now().UnixNano()`

### Payload (Encrypted Data)

**Encoding**: Base64(encryption_output)

**Format** (Algorithm-Dependent):

**AES-GCM / ChaCha20-Poly1305:**

```ASCII
nonce || ciphertext || tag
```

**AES-CBC:**

```ASCII
IV || ciphertext
```

**Example (Conceptual):**

```ASCII
Original Data: "hvs.XXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
Base64 Encode: "aHZzLlhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWA=="
AES-256-GCM:   nonce(12) + encrypt("aHZz...") + tag(16)
Base64 Result: "ZnNkZmpoc2RqZmhzZGpm..."
```

### Signature (HMAC)

**Encoding**: Base64(HMAC-SHA256_output)

**Signed Content:**

```ASCII
base64(metadata).base64(encrypted_data)
```

**Purpose:**

- Ensure metadata hasn't been altered
- Ensure encrypted data hasn't been tampered with
- Authenticate the entire token structure

**Security Property:**

- Changing a single bit in metadata or ciphertext invalidates the signature
- Only holders of the signing key can generate valid signatures

### Complete Token Example

```ASCII
eyJ2ZXIiOjEsImVuYyI6IkFFUy0yNTYtR0NNIiwiYWxnIjoiSFMyNTYiLCJzdWIiOiJ2YXVsdC1yb290LXRva2VuIiwiZHRsIjoicHJvZHVjdGlvbiB2YXVsdCIsImlzcyI6ImFrYXNoaWMtY2xpIiwiY250IjoidGV4dCIsInNsdCI6ImNXWmlZV0ZoWVdGaFlXRmhZV0ZoWVdGaFlXRmhZV0ZoWVdGaFlXRT0iLCJpYXQiOjE3MjkyMTA0MDAwMDAwMDAwMDB9
.
ZnNkZmpoc2RqZmhzZGpmaHNka2Zqc2Rma2poc2RrZmpoc2Rma2poc2Rma2poc2Rma2poc2Rma2poc2Rma2poc2Rma2poc2Rma2pzZGhma3Nqc2Rma2poc2Rma2pzZGZramhzZGZramhzZGZramhzZGtqZmhzZGtqZmhzZGtmaGo=
.
c2RmaHNkamZoc2RqZmhzZGpmaHNka2ZqaHNka2ZqaHNka2ZqaHNka2ZqaHNka2ZqaHNka2ZqaHNka2ZqaHNka2Y=
```

**Breakdown:**

1. **Metadata** (first part): Version, algorithms, subject, salt, timestamps
2. **Payload** (second part): Encrypted secret data
3. **Signature** (third part): HMAC-SHA256 authenticating parts 1 & 2

---

## Key Derivation Hierarchy

### Step-by-Step Process

```ASCII
┌─────────────────────────────────────────────────────────────┐
│ Step 1: User Input                                          │
│   Passphrase: "my-super-secret-passphrase-2024"             │
│   (any length, UTF-8 encoded)                               │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 2: Random Salt Generation                              │
│   salt = random(32 bytes)  ← crypto/rand                    │
│   Example: [0x3f, 0xa2, 0x..., 0xb4] (32 bytes)             │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 3: PBKDF2-SHA256                                       │
│   masterKey = PBKDF2(passphrase, salt, 600000, 32, SHA256)  │
│   Output: 32-byte master key                                │
│   Time Cost: ~100ms on modern CPU                           │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 4: HKDF-SHA256 (Encryption Key)                        │
│   encKey = HKDF(                                            │
│     ikm    = masterKey,                                     │
│     salt   = salt,                                          │
│     info   = "akashic-token-encryption-v1",                 │
│     length = 16/24/32  ← depends on algorithm               │
│   )                                                         │
│   Output: AES-128 (16), AES-192 (24), AES-256/ChaCha (32)   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 5: HKDF-SHA256 (Signing Key)                           │
│   sigKey = HKDF(                                            │
│     ikm    = masterKey,                                     │
│     salt   = salt,                                          │
│     info   = "akashic-token-signing-v1",                    │
│     length = 32  ← always 32 for HMAC-SHA256                │
│   )                                                         │
│   Output: 32-byte HMAC key                                  │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 6: Use Derived Keys                                    │
│   Encryption:  AES-GCM(data, encKey, random_nonce)          │
│   Signing:     HMAC-SHA256(metadata || ciphertext, sigKey)  │
└─────────────────────────────────────────────────────────────┘
```

### Security Properties of This Hierarchy

1. **Salt Randomness**: Each token has unique cryptographic properties
2. **Slow Derivation**: 600K iterations slow down brute-force attacks
3. **Key Independence**: `encKey` and `sigKey` are cryptographically independent
4. **Domain Separation**: HKDF info strings ensure keys aren't reused across contexts
5. **Forward Secrecy**: Compromising one token doesn't help with others (different salts)

---

## Token Lifecycle

### Issuance Process (6 Steps)

**Function**: `IssueSecureToken(data []byte, key string, meta TokenMeta)`

```go
// Step 1: Generate random salt
salt := random(32)  // crypto/rand

// Step 2: Derive master key from password
masterKey := PBKDF2(password, salt, 600000, 32, SHA256)

// Step 3: Derive encryption and signing keys
encKey := HKDF(masterKey, salt, "akashic-token-encryption-v1", keySize)
sigKey := HKDF(masterKey, salt, "akashic-token-signing-v1", 32)

// Step 4: Build metadata with salt and version
metadata := {
  ver: 1,
  enc: "AES-256-GCM",
  alg: "HS256",
  slt: base64(salt),
  iat: now(),
  ...
}

// Step 5: Encrypt data with derived encryption key
ciphertext := AES_GCM(base64(data), encKey, random_nonce())

// Step 6: Sign with derived signing key
signature := HMAC_SHA256(base64(metadata) + "." + ciphertext, sigKey)

// Return: base64(metadata).ciphertext.signature
return metadata + "." + ciphertext + "." + signature
```

### Verification Process (7 Steps)

**Function**: `ReadSecureToken(token string, key string)`

```go
// Step 1: Parse token structure
parts := split(token, ".")  // [metadata, ciphertext, signature]

// Step 2: Decode and parse metadata
metadata := JSON.parse(base64_decode(parts[0]))

// Step 3: Extract salt from metadata
salt := base64_decode(metadata.slt)

// Step 4: Derive master key from password using stored salt
masterKey := PBKDF2(password, salt, 600000, 32, SHA256)

// Step 5: Derive encryption and signing keys
encKey := HKDF(masterKey, salt, "akashic-token-encryption-v1", keySize)
sigKey := HKDF(masterKey, salt, "akashic-token-signing-v1", 32)

// Step 6: Verify signature with derived signing key
expected_sig := HMAC_SHA256(parts[0] + "." + parts[1], sigKey)
if !constant_time_compare(parts[2], expected_sig) {
  return error("invalid passphrase or corrupted token")
}

// Step 7: Decrypt data with derived encryption key
plaintext := AES_GCM_decrypt(parts[1], encKey)
return base64_decode(plaintext)
```

### Error Handling

**Common Errors:**

| Error                        | Cause                                    | Mitigation                     |
|------------------------------|------------------------------------------|--------------------------------|
| Invalid passphrase           | Wrong `AKASHIC_SECRET`                   | Verify passphrase, check typos |
| Corrupted token              | File modified, disk error                | Restore from backup            |
| Unsupported version          | Token created with future version        | Upgrade software               |
| Decryption failed            | Tampering, wrong key                     | Restore from backup            |
| Missing salt                 | Legacy token (pre-v1)                    | Re-encrypt with current system |

---

## Security Analysis

### Cost to Crack Passwords

**Assumptions:**

- Attacker has RTX 4090 GPU (~10 billion PBKDF2-SHA256/sec)
- Attacker obtained encrypted token file
- No rate limiting (offline attack)

**Passphrase Strength Analysis:**

| Passphrase Type          | Entropy  | Combinations          | Time to Crack      |
|--------------------------|----------|-----------------------|--------------------|
| 8 lowercase chars        | 37 bits  | 2.1 trillion          | **3 minutes**      |
| 10 random alphanumeric   | 60 bits  | 1 quintillion         | **190 years**      |
| 16 random mixed          | 95 bits  | 40 nonillion          | **10^19 years**    |
| 20 random mixed          | 119 bits | 6.6 quinquagintillion | **10^24 years** |

**Recommendation:**

- **Minimum**: 16 characters, random (uppercase + lowercase + numbers + symbols)
- **Better**: 20+ characters or passphrase from dice rolls (Diceware)
- **Best**: Hardware security module (HSM) or TPM-backed keys

### Defense in Depth Layers

Our secure token system has **5 layers of defense**:

```ASCII
┌─────────────────────────────────────────────────────────┐
│ Layer 1: Passphrase Requirement                         │
│   Cannot decrypt without user-provided passphrase       │
└─────────────────────────────────────────────────────────┘
          ↓ Attacker has token file
┌─────────────────────────────────────────────────────────┐
│ Layer 2: Slow Key Derivation (PBKDF2 600K)              │
│   Each guess takes ~6 seconds on GPU                    │
└─────────────────────────────────────────────────────────┘
          ↓ Attacker brute-forces passphrase
┌─────────────────────────────────────────────────────────┐
│ Layer 3: Random Salt (Rainbow Table Mitigation)         │
│   Precomputation attacks infeasible                     │
└─────────────────────────────────────────────────────────┘
          ↓ Attacker cracks passphrase
┌─────────────────────────────────────────────────────────┐
│ Layer 4: HKDF Key Separation (Enc ≠ Sig Keys)           │
│   Compromising encryption doesn't break authentication  │
└─────────────────────────────────────────────────────────┘
          ↓ Attacker obtains encryption key
┌─────────────────────────────────────────────────────────┐
│ Layer 5: AEAD Authentication (GCM/Poly1305)             │
│   Tampering detectable even with encryption key         │
└─────────────────────────────────────────────────────────┘
```

### Comparison to Alternatives

| Feature                  | Akashic Secure Token | JWT (HMAC) | Fernet | age      |
|--------------------------|----------------------|------------|--------|----------|
| Passphrase-based         | ✅                   | ❌         | ❌     | ✅       |
| Random salt per token    | ✅                   | ❌         | ❌     | ✅       |
| Key derivation (KDF)     | PBKDF2 (600K)        | None       | None   | scrypt   |
| Key separation           | ✅ HKDF              | ❌         | ❌     | ✅       |
| Authenticated encryption | ✅ AEAD              | ✅ HMAC    | ✅ HMAC| ✅ AEAD  |
| Algorithm flexibility    | ✅ 7 algorithms      | Limited    | Fixed  | Fixed    |
| Version field            | ✅                   | ❌         | ✅     | ✅       |
| Use case                 | Secret storage       | Sessions   | Tokens | Files    |

**Why Not JWT?**

- No key derivation (expects pre-shared key)
- No random salt (same secret → same key)
- Optimized for session tokens, not long-term storage

**Why Not Fernet?**

- No key derivation from passphrase
- Fixed algorithm (no AES-256, no ChaCha20)
- Python ecosystem (limited Go support)

**Why Not age?**

- Designed for file encryption (not structured tokens)
- Public key based (different threat model)
- No HMAC (relies solely on AEAD)

**Our Choice**: Build custom system optimized for **passphrase-encrypted token storage** with defense in depth.

---

## Best Practices

### Passphrase Requirements

✅ **Strong Passphrases:**

- **Length**: Minimum 16 characters, recommended 20+
- **Complexity**: Mix uppercase, lowercase, numbers, symbols
- **Randomness**: Use password manager or Diceware
- **Uniqueness**: Don't reuse across systems

❌ **Weak Passphrases:**

- Dictionary words (`password`, `admin`, `akashic`)
- Keyboard patterns (`qwerty`, `12345678`)
- Personal info (`john1990`, `company2024`)
- Short passphrases (`SecRet!`)

**Example Strong Passphrases:**

```bash
# Generated by password manager (20 chars, random)
export AKASHIC_SECRET='X7#mK9$pL2@qW5!nR8^f'

# Diceware (6 words)
export AKASHIC_SECRET="correct horse battery staple garage unicorn"

# Base64-encoded random bytes (24 bytes → 32 chars)
export AKASHIC_SECRET=$(openssl rand -base64 24)
```

### Secure Storage Locations

✅ **Good Storage:**

- Environment variables (not committed to Git)
- OS keychain (macOS Keychain, Windows Credential Manager)
- Secret managers (HashiCorp Vault, AWS Secrets Manager)
- Hardware security modules (HSM, TPM, YubiKey)

❌ **Bad Storage:**

- Hardcoded in source code
- `.env` files committed to version control
- Plain text files in home directory
- Shell history (avoid `export AKASHIC_SECRET=...` in scripts)

**Recommended Workflow:**

```bash
# Option 1: Environment variable (manual)
read -s AKASHIC_SECRET  # -s hides input
export AKASHIC_SECRET

# Option 2: .env file (gitignored)
echo "AKASHIC_SECRET=..." >> .env
source .env

# Option 3: Secret manager (if you have local vault running)
export AKASHIC_SECRET=$(vault kv get -field=passphrase secret/akashic)

# Option 4: macOS Keychain
security add-generic-password -a "$USER" -s "akashic-secret" -w
export AKASHIC_SECRET=$(security find-generic-password -a "$USER" -s "akashic-secret" -w)
```

### Backup Strategies

**What to Backup:**

1. Encrypted token files (`./.secrets/vault/root-token.enc`, etc.)
2. Passphrase (stored separately, securely)

**Backup Best Practices:**

✅ **Recommended:**

- **3-2-1 Rule**: 3 copies, 2 different media, 1 offsite
- **Encrypted backups**: Use separate passphrase for backup encryption
- **Multiple locations**: Cloud + local + offline
- **Regular testing**: Verify restoration procedure monthly

❌ **Avoid:**

- Single copy (SPOF - Single Point of Failure)
- Unencrypted cloud storage (e.g., Google Drive without encryption)
- Same passphrase for backups and primary storage

**Example Backup Script:**

```bash
#!/bin/bash
# Backup script for Akashic secrets

BACKUP_DIR="/secure/backup/akashic-$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Copy encrypted tokens
cp -r ./.secrets/vault "$BACKUP_DIR/"

# Encrypt backup with different passphrase
tar czf - "$BACKUP_DIR" | \
  openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -out \
  "$BACKUP_DIR.tar.gz.enc"

# Upload to secure cloud storage
rclone copy "$BACKUP_DIR.tar.gz.enc" remote:akashic-backups/

# Verify backup integrity
sha256sum "$BACKUP_DIR.tar.gz.enc" >> backup-checksums.txt
```

### Key Rotation Considerations

**When to Rotate:**

- Suspected passphrase compromise
- Compliance requirements (e.g., annual rotation)
- Personnel changes (admin leaves team)
- After security incident

**How to Rotate:**

```bash
# 1. Decrypt with old passphrase
export AKASHIC_SECRET_OLD="old-passphrase"
akashic-cli token inspect -i ./.secrets/vault/root-token.enc > /tmp/plaintext

# 2. Re-encrypt with new passphrase
export AKASHIC_SECRET_NEW="new-passphrase"
akashic-cli token issue -i /tmp/plaintext -o ./.secrets/vault/root-token.enc

# 3. Securely erase plaintext
shred -u /tmp/plaintext

# 4. Update environment
export AKASHIC_SECRET="$AKASHIC_SECRET_NEW"
unset AKASHIC_SECRET_OLD
```

**Automation:**

```go
// Rotate all tokens in a directory
func RotateTokens(dir string, oldPass string, newPass string) error {
    tokens := filepath.Glob(dir + "/*.enc")
    for _, tokenFile := range tokens {
        // Read with old passphrase
        meta, data, err := ReadSecureToken(tokenFile, oldPass)

        // Re-issue with new passphrase (new salt generated automatically)
        newToken, err := IssueSecureToken(data, newPass, meta.TokenMeta)

        // Atomic write
        ioutil.WriteFile(tokenFile, []byte(newToken), 0600)
    }
    return nil
}
```

### Operational Security

**Development Environment:**

- Use separate passphrases for dev vs production
- Never use production passphrases in development
- Rotate dev passphrases regularly (lower security requirements)

**Production Environment:**

- Strong passphrases (20+ characters, random)
- Hardware security modules (HSM) for key storage
- Audit logging for token access
- Principle of least privilege (limit who knows passphrase)

**Disaster Recovery:**

- Document passphrase recovery procedure
- Escrow passphrases with trusted parties (split using Shamir's Secret Sharing)
- Test recovery procedure regularly

---

## Code Examples

### Example 1: Issuing a Token

```go
package main

import (
    "fmt"
    "os"

    "akashic/akashic/pkg/cli/core"
)

func main() {
    // Sensitive data to encrypt
    vaultToken := "hvs.XXXXXXXXXXXXXXXXXXXXXXXXXX"

    // Passphrase from environment
    passphrase := os.Getenv("AKASHIC_SECRET")
    if passphrase == "" {
        panic("AKASHIC_SECRET environment variable not set")
    }

    // Token metadata
    meta := core.TokenMeta{
        Enc: core.AES_256_GCM,      // Use AES-256-GCM
        Alg: core.HMAC_SHA256,      // Use HMAC-SHA256
        Sub: "vault-root-token",    // Subject
        Dtl: "production vault",    // Details
        Iss: "akashic-cli",         // Issuer
        Cnt: core.TEXT,             // Content type
    }

    // Issue secure token
    token, err := core.IssueSecureToken(
        []byte(vaultToken),
        passphrase,
        meta,
    )
    if err != nil {
        panic(err)
    }

    // Write to file
    err = os.WriteFile("./.secrets/vault/root-token.enc", []byte(token), 0600)
    if err != nil {
        panic(err)
    }

    fmt.Println("Token encrypted and saved successfully")
}
```

### Example 2: Reading a Token

```go
package main

import (
    "fmt"
    "os"

    "akashic/akashic/pkg/cli/core"
)

func main() {
    // Read encrypted token from file
    tokenBytes, err := os.ReadFile("./.secrets/vault/root-token.enc")
    if err != nil {
        panic(err)
    }

    // Passphrase from environment
    passphrase := os.Getenv("AKASHIC_SECRET")
    if passphrase == "" {
        panic("AKASHIC_SECRET environment variable not set")
    }

    // Read and decrypt token
    meta, data, err := core.ReadSecureToken(
        string(tokenBytes),
        passphrase,
    )
    if err != nil {
        // Check for specific error types
        if core.IsSecureTokenError(err) {
            fmt.Println("Wrong passphrase or corrupted token")
            os.Exit(1)
        }
        panic(err)
    }

    // Use decrypted data
    fmt.Printf("Subject: %s\n", meta.Sub)
    fmt.Printf("Issued: %d\n", meta.Iat)
    fmt.Printf("Token: %s\n", string(data))
}
```

### Example 3: Inspecting Token Metadata (Without Decryption)

```go
package main

import (
    "encoding/base64"
    "encoding/json"
    "fmt"
    "os"
    "strings"

    "akashic/akashic/pkg/cli/core"
)

func main() {
    // Read token
    tokenBytes, _ := os.ReadFile("./.secrets/vault/root-token.enc")
    token := string(tokenBytes)

    // Parse structure (metadata.payload.signature)
    parts := strings.Split(token, ".")
    if len(parts) != 3 {
        panic("invalid token format")
    }

    // Decode metadata (Base64 → JSON)
    metadataJSON, _ := base64.StdEncoding.DecodeString(parts[0])

    // Parse JSON
    var meta core.FullTokenMeta
    json.Unmarshal(metadataJSON, &meta)

    // Display metadata (no passphrase needed!)
    fmt.Printf("Version: %d\n", meta.Ver)
    fmt.Printf("Encryption: %s\n", meta.Enc)
    fmt.Printf("Signing: %s\n", meta.Alg)
    fmt.Printf("Subject: %s\n", meta.Sub)
    fmt.Printf("Issued: %d\n", meta.Iat)
    fmt.Printf("Salt: %s (32 bytes)\n", meta.Slt[:16]+"...")

    // Note: Cannot decrypt data without passphrase
}
```

### Example 4: Error Handling

```go
package main

import (
    "errors"
    "fmt"

    "akashic/akashic/pkg/cli/core"
)

func DecryptToken(token string, passphrase string) ([]byte, error) {
    meta, data, err := core.ReadSecureToken(token, passphrase)

    if err != nil {
        // Check for specific error types
        var invalidKeyErr *core.SecureTokenInvalidKeyError
        if errors.As(err, &invalidKeyErr) {
            return nil, fmt.Errorf("wrong passphrase: %v", err)
        }

        // Generic error (corrupted token, parsing error, etc.)
        return nil, fmt.Errorf("token decryption failed: %v", err)
    }

    // Validate metadata
    if meta.Ver != 1 {
        return nil, fmt.Errorf("unsupported token version: %d", meta.Ver)
    }

    return data, nil
}
```

---

## Future Improvements

### 1. Argon2id (Memory-Hard KDF)

**Current**: PBKDF2-SHA256 (CPU-bound)
**Upgrade**: Argon2id (CPU + memory-bound)

**Why Argon2id?**

- **Memory-Hard**: Requires significant RAM (e.g., 64 MB), resistant to GPU/ASIC attacks
- **Winner**: Password Hashing Competition (2015)
- **Tunable**: Adjust time cost, memory cost, parallelism

**Migration Path:**

```ASCII
Version 2:
  - KDF: Argon2id (time=3, memory=64MB, threads=4)
  - Everything else stays the same

Backward compatibility:
  - Check "ver" field
  - Use PBKDF2 for v1, Argon2id for v2
```

### 2. Post-Quantum Cryptography

**Threat**: Quantum computers (future) can break current asymmetric crypto
**Impact on Our System**: Minimal (we use symmetric crypto)

**Quantum-Resistant Upgrades:**

- **KDF**: SHA-256 → SHA3-256 or BLAKE3 (quantum-safe hashes)
- **Encryption**: AES-256 remains secure (Grover's algorithm: 256 bits → 128-bit effective security)
- **HMAC**: SHA-256 → SHA3-256

**Timeline**: Monitor NIST post-quantum standardization (ongoing)

### 3. Hardware Security Module (HSM) Integration

**Current**: Keys exist in software memory
**Upgrade**: Store keys in hardware (TPM, HSM, YubiKey)

**Benefits:**

- Keys never leave hardware
- Resistant to memory dumps, malware
- Tamper-resistant

**Implementation:**

```go
type HSMKeyStore interface {
    DeriveKey(passphrase string, salt []byte) (keyID string, err error)
    Encrypt(keyID string, plaintext []byte) ([]byte, error)
    Decrypt(keyID string, ciphertext []byte) ([]byte, error)
}
```

### 4. Key Rotation Automation

**Current**: Manual rotation process
**Upgrade**: Automatic re-encryption on access

**Design:**

```go
type TokenStore struct {
    currentVersion int
    legacyVersions []int
}

func (t *TokenStore) Read(token string, pass string) ([]byte, error) {
    meta, data, err := ReadSecureToken(token, pass)

    // Check if using old version
    if meta.Ver < t.currentVersion {
        // Transparently upgrade to new version
        newToken, _ := IssueSecureToken(data, pass, meta)
        t.WriteBack(newToken)  // Atomic write
    }

    return data, nil
}
```

### 5. Multi-Factor Authentication (MFA)

**Current**: Single passphrase
**Upgrade**: Passphrase + hardware token (FIDO2, YubiKey)

**Design:**

```ASCII
Encryption Key = KDF(passphrase) ⊕ HardwareToken.DeriveKey()
  → Requires both passphrase AND physical token
```

---

## References

### Standards and Specifications

1. **PBKDF2**
   - RFC 8018: *Password-Based Cryptography Specification Version 2.1*
   - [https://tools.ietf.org/html/rfc8018](https://tools.ietf.org/html/rfc8018)

2. **HKDF**
   - RFC 5869: *HMAC-based Extract-and-Expand Key Derivation Function*
   - [https://tools.ietf.org/html/rfc5869](https://tools.ietf.org/html/rfc5869)

3. **AES-GCM**
   - NIST SP 800-38D: *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)*
   - [https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)

4. **ChaCha20-Poly1305**
   - RFC 8439: *ChaCha20 and Poly1305 for IETF Protocols*
   - [https://tools.ietf.org/html/rfc8439](https://tools.ietf.org/html/rfc8439)

5. **HMAC**
   - RFC 2104: *HMAC: Keyed-Hashing for Message Authentication*
   - FIPS 198-1: *The Keyed-Hash Message Authentication Code (HMAC)*
   - [https://tools.ietf.org/html/rfc2104](https://tools.ietf.org/html/rfc2104)

### Security Guidelines

1. **OWASP Password Storage Cheat Sheet**
   - Recommends PBKDF2 with 600,000 iterations (2023)
   - [https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

2. **NIST SP 800-132**
   - *Recommendation for Password-Based Key Derivation*
   - [https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)

3. **NIST SP 800-175B**
   - *Guideline for Using Cryptographic Standards: Cryptographic Mechanisms*
   - [https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175Br1.pdf](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175Br1.pdf)

### Academic Papers

1. **"Password Hashing Competition"** (2015)
   - Argon2 winner announcement and analysis
   - [https://www.password-hashing.net/](https://www.password-hashing.net/)

2. **Colin Percival: "Stronger Key Derivation via Sequential Memory-Hard Functions"** (2009)
    - scrypt design and rationale
    - [http://www.tarsnap.com/scrypt/scrypt.pdf](http://www.tarsnap.com/scrypt/scrypt.pdf)

### Related Documentation

1. **HashiCorp Vault Documentation**
    - Vault initialization and unsealing
    - [https://developer.hashicorp.com/vault/docs/concepts/seal](https://developer.hashicorp.com/vault/docs/concepts/seal)

2. **Go Cryptography Packages**
    - `golang.org/x/crypto/pbkdf2`
    - `golang.org/x/crypto/hkdf`
    - `golang.org/x/crypto/chacha20poly1305`
    - [https://pkg.go.dev/golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto)

---

## Appendix: Quick Reference

### Cryptographic Parameters Summary

| Component                | Algorithm        | Parameters                     |
|--------------------------|------------------|--------------------------------|
| **Salt**                 | crypto/rand      | 32 bytes (256 bits)            |
| **Key Derivation (KDF)** | PBKDF2-SHA256    | 600,000 iterations             |
| **Key Separation**       | HKDF-SHA256      | Context-specific info strings  |
| **Encryption (GCM)**     | AES-256-GCM      | 32-byte key, 12-byte nonce     |
| **Encryption (CBC)**     | AES-256-CBC      | 32-byte key, 16-byte IV, PKCS#7|
| **Encryption (ChaCha)**  | ChaCha20-Poly1305| 32-byte key, 12-byte nonce     |
| **Authentication**       | HMAC-SHA256      | 32-byte key                    |
| **Version**              | Integer          | 1 (current)                    |

### Token Format Cheat Sheet

```ASCII
Structure:
  BASE64(metadata).BASE64(ciphertext).BASE64(signature)

Metadata (JSON):
  {
    "ver": 1,
    "enc": "AES-256-GCM",
    "alg": "HS256",
    "sub": "subject",
    "dtl": "details",
    "iss": "issuer",
    "cnt": "text",
    "slt": "base64_salt",
    "iat": 1729210400000000000
  }

Ciphertext Format:
  AES-GCM:   nonce(12) + ciphertext + tag(16)
  AES-CBC:   IV(16) + ciphertext (PKCS#7 padded)
  ChaCha20:  nonce(12) + ciphertext + tag(16)

Signature:
  HMAC-SHA256(metadata + "." + ciphertext)
```

### CLI Commands

```bash
# Issue a token
akashic-cli token issue \
  --input plaintext.txt \
  --output token.enc \
  --subject "vault-root-token" \
  --encryption AES-256-GCM

# Read a token
akashic-cli token inspect \
  --input token.enc

# Rotate passphrase
akashic-cli token rotate \
  --input token.enc \
  --output token-new.enc \
  --old-passphrase "$OLD_SECRET" \
  --new-passphrase "$NEW_SECRET"
```

---

**Document Version**: 1.0 \
**Last Updated**: 2024-10-16 \
