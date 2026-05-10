package auth

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// GenerateTempPassword returns a random strong password suitable
// for one-time admin-issued reset (Phase 9d).
//
// Composition:
//   - 24 characters total
//   - At least 1 uppercase, 1 lowercase, 1 digit, 1 special
//   - No ambiguous characters (`I 1 l O 0`) — the password may be
//     read out over a phone or copy-pasted from an email a user
//     transcribes manually; reducing visual ambiguity prevents
//     "is that an O or a zero" support tickets.
//
// crypto/rand-derived; no PRNG, no time-based seed. Defends against
// attackers predicting from RNG output.
//
// The generated password is deliberately strong enough that it
// satisfies any reasonable tenant policy without checking. The
// caller still calls `policy.Validate(...)` defensively — if a
// custom-policy deployment ever required a longer minimum than 24
// or banned a character class we use, the validate would catch it
// at the boundary.
func GenerateTempPassword() (string, error) {
	const (
		uppers   = "ABCDEFGHJKLMNPQRSTUVWXYZ"   // no I, O
		lowers   = "abcdefghijkmnpqrstuvwxyz"   // no l, o
		digits   = "23456789"                   // no 0, 1
		specials = "!@#$%^&*-_=+?"
		// All categories combined for the bulk fill — same set as
		// the per-category guarantees above so the result satisfies
		// every category check.
		all = uppers + lowers + digits + specials

		length = 24
	)

	// Build the password as a byte slice we'll shuffle at the end
	// (so the guaranteed-category chars aren't always at the same
	// positions).
	out := make([]byte, length)

	// 1 from each category (4 chars guaranteed).
	categories := []string{uppers, lowers, digits, specials}
	for i, cat := range categories {
		c, err := pickRandom(cat)
		if err != nil {
			return "", err
		}
		out[i] = c
	}

	// Remaining (length-4) chars from the combined set.
	for i := len(categories); i < length; i++ {
		c, err := pickRandom(all)
		if err != nil {
			return "", err
		}
		out[i] = c
	}

	// Fisher-Yates shuffle so the four guaranteed-category chars
	// are randomly distributed. Without this, position [0] is
	// always uppercase, [1] always lowercase, etc. — predictable
	// and reduces the search space for an attacker who knows the
	// generator's structure.
	for i := length - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		j := int(jBig.Int64())
		out[i], out[j] = out[j], out[i]
	}

	return string(out), nil
}

// pickRandom returns a uniformly random byte from the input string,
// drawing from crypto/rand. Errors only if rand.Reader fails (vanishingly
// rare on a healthy system).
func pickRandom(s string) (byte, error) {
	if s == "" {
		return 0, errors.New("temp password: empty character set")
	}
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(s))))
	if err != nil {
		return 0, err
	}
	return s[idx.Int64()], nil
}

