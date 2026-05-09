// Package userregistration consolidates the self-service user-creation
// primitive shared between:
//
//   - api-server's POST /users/register (bearer-auth-irrelevant: it's
//     a public endpoint; bearer not required because there's no user
//     to authenticate as yet)
//   - auth-server's POST /signup/submit (form-driven, hosted on the
//     auth surface so signup works out of the box without operators
//     needing to register a separate tenant portal first)
//
// Both surfaces had identical validation + LDAP-then-postgres
// dual-create logic — diverging only on the HTTP shape (JSON body vs.
// form-encoded, JSON envelope vs. HTML redirect). This package owns
// the domain operation; the handlers stay focused on translating
// HTTP ↔ domain.
//
// Pure domain logic: no http.ResponseWriter, no JSON envelopes, no
// CSRF / session handling. Errors are typed so each handler can map
// them to whichever wire-level error code its caller expects.
package userregistration

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"akashic/akashic/pkg/auth"
	"akashic/akashic/pkg/ldap"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/repository"
)

// Deps bundles the dependencies the registration flow needs. Both
// the auth-server and api-server already own these; passing them
// through keeps userregistration unaware of which Server type holds
// them.
type Deps struct {
	LDAP     *ldap.Client
	UserRepo *repository.UserRepository
	Policy   *auth.PasswordPolicy
}

// Params describes the user to register. Caller is responsible for
// providing already-trimmed values; this package validates shape and
// uniqueness but doesn't sanitize whitespace.
//
// Email + Password are required; everything else is optional and
// auto-generated when omitted:
//   - Username (the id-base) → derived from email's local part
//   - Tag → 4-char base36 random
//   - DisplayName → defaults to email's local part
//
// When the caller supplies Username and/or Tag, we validate the
// shape AND check the resulting `<id>#<tag>` combination is free.
// When the user didn't supply a tag, we auto-retry on collision
// (up to 8 times) before giving up.
//
// The bootstrap path (which wants a memorable uid like "admin"
// for the operator's root account) uses pkg/bootstrap/ directly,
// not this package, so it's unaffected by these rules.
type Params struct {
	Email       string
	Password    string
	DisplayName string

	// Username, if non-empty, becomes the id-base of the resulting
	// tagged uid. Sanitised + validated to 2-32 chars after
	// sanitisation. When empty, derived from email's local part.
	Username string

	// Tag, if non-empty, becomes the tag suffix. Must be 4 chars
	// base36 (0-9a-z, case-insensitive — lowercased server-side).
	// When empty, auto-generated with collision retry.
	Tag string
}

// Sentinel errors. Handlers `errors.Is` to map these to wire codes.
// All carry a wrapped detail message via fmt.Errorf("%w: …") so the
// handler's response can include the specific reason (which password
// rule failed, which field's email format is wrong) without parsing
// the message.
var (
	ErrFieldRequired          = errors.New("required field is empty")
	ErrEmailInvalid           = errors.New("email format is invalid")
	ErrPasswordPolicyViolated = errors.New("password does not satisfy the policy")
	// ErrEmailTaken fires when another user already owns the email.
	// Email is the primary identity (password reset, email
	// verification, email-as-login all assume 1:1 mapping), so
	// duplicates are rejected at registration time.
	ErrEmailTaken = errors.New("email is already registered to another account")
	// ErrIDInvalid fires when a user-supplied Username is malformed
	// after sanitisation — empty, too short (<2 chars), or too long
	// (>32 chars). The sanitiser drops disallowed characters
	// silently before length-checking.
	ErrIDInvalid = errors.New("id format is invalid")
	// ErrTagInvalid fires when a user-supplied Tag isn't exactly
	// 4 characters of base36 (0-9a-z). Case is normalised to
	// lowercase before validation, so uppercase input is accepted.
	ErrTagInvalid = errors.New("tag format is invalid")
	// ErrUIDTaken fires when the user supplied an explicit
	// id+tag combination AND that exact combination is already
	// in use. Distinct from ErrUsernameUnavailable (which fires
	// when the auto-generation retry loop exhausts) because the
	// caller intent is different — they wanted THIS specific
	// combination, and we tell them it's not available.
	ErrUIDTaken = errors.New("that id+tag combination is already in use")
	// ErrUsernameUnavailable is the safety-valve for the rare case
	// where the tag-collision-retry loop exhausts its budget. With
	// 4-char base36 tags (~1.7M per id-base) and 8 retry attempts,
	// hitting this requires multiple millions of pre-existing users
	// sharing the same id-base — pathological in practice.
	ErrUsernameUnavailable = errors.New("could not generate a unique uid for this id-base")
	ErrInternal            = errors.New("internal error during registration")
)

// Register validates the input, ensures the username is free, and
// creates the user in BOTH LDAP and postgres atomically (LDAP first;
// on postgres failure, LDAP entry persists and gets cleaned up by
// the deprovisioning service after the configured grace period —
// see pkg/ldap/deprovisioning.go).
//
// Returns the created *models.User on success, or a typed error
// wrapping one of the package-level sentinels.
func Register(ctx context.Context, d Deps, p Params) (*models.User, error) {
	if d.LDAP == nil || d.UserRepo == nil || d.Policy == nil {
		return nil, fmt.Errorf("%w: missing dependency", ErrInternal)
	}

	// Email + password are required. There's no user-facing ID
	// concept anymore — every signup gets a stable internal uid
	// derived from a UUID. Display surfaces use email.
	if p.Email == "" || p.Password == "" {
		return nil, fmt.Errorf("%w: email and password are required", ErrFieldRequired)
	}
	if !looksLikeEmail(p.Email) {
		return nil, fmt.Errorf("%w: %s", ErrEmailInvalid, p.Email)
	}

	if err := d.Policy.Validate(p.Password); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrPasswordPolicyViolated, err.Error())
	}

	// Email-uniqueness gate. Email is the primary identity for
	// password reset, verification, change-confirmation, and
	// login disambiguation; rejecting duplicates here is the
	// foundational fix that unblocks all of those.
	emailTaken, err := d.LDAP.EmailExists(p.Email)
	if err != nil {
		return nil, fmt.Errorf("%w: LDAP email-exists check: %v", ErrInternal, err)
	}
	if emailTaken {
		return nil, fmt.Errorf("%w: %s", ErrEmailTaken, p.Email)
	}

	uid, err := ResolveUID(d.LDAP, p.Email, p.Username, p.Tag, "")
	if err != nil {
		return nil, err
	}

	createReq := &models.CreateUserRequest{
		Username:    uid,
		Email:       p.Email,
		Password:    p.Password,
		UserType:    models.UserTypeUser,
		DisplayName: p.DisplayName,
	}
	user, err := d.UserRepo.CreateUser(ctx, createReq, p.Password)
	if err != nil {
		return nil, fmt.Errorf("%w: persist user: %v", ErrInternal, err)
	}
	return user, nil
}

// ResolveUID produces the final Discord-style `<id>#<tag>` LDAP uid
// from the four input cases:
//
//	supplied? id  tag  → behaviour
//	          no  no   → both auto-derived, tag has retry budget
//	          yes no   → id sanitised+validated, tag auto-generated
//	          no  yes  → id from email, supplied tag validated, exact
//	                     combo must be unique (no retry)
//	          yes yes  → both validated, exact combo must be unique
//
// The retry-budget vs. exact-must-be-unique distinction matters:
// when the caller supplies a specific tag, they want THAT tag —
// regenerating to "fix" a collision would silently produce a uid
// they didn't ask for. So we surface ErrUIDTaken instead.
//
// `currentUID` is the existing uid the caller is renaming FROM. When
// non-empty, candidates that match it are treated as not-taken (the
// caller is allowed to "rename to themselves" — useful for the
// PATCH /users/me/uid no-op short-circuit). Pass "" for registration
// where there's no existing uid to exclude.
//
// `#` is RFC-4514-safe mid-RDN-value, RFC-4515-safe in filters, and
// percent-encodes correctly in URL query strings. See the design
// note in the package doc-comment for the full layer-by-layer audit.
func ResolveUID(client *ldap.Client, email, suppliedID, suppliedTag, currentUID string) (string, error) {
	// Resolve id-base.
	var idBase string
	if suppliedID = strings.TrimSpace(suppliedID); suppliedID != "" {
		cleaned, err := sanitizeAndValidateID(suppliedID)
		if err != nil {
			return "", err
		}
		idBase = cleaned
	} else {
		idBase = sanitizeIDBase(emailLocalPart(email))
		if idBase == "" {
			// Email's local part was all-special-chars after
			// sanitising (e.g. `+++@example.com`). Fall back to
			// "user" so we still produce a valid uid; the tag
			// disambiguates anyway.
			idBase = "user"
		}
	}

	// Resolve tag.
	if suppliedTag = strings.TrimSpace(suppliedTag); suppliedTag != "" {
		tag, err := validateTag(suppliedTag)
		if err != nil {
			return "", err
		}
		candidate := idBase + "#" + tag
		// `currentUID` short-circuit: when the caller is renaming
		// from `currentUID` and lands on the same value, treat as
		// "free for me to claim" so PATCH /users/me/uid handlers
		// can detect a no-op cleanly.
		if candidate == currentUID {
			return candidate, nil
		}
		exists, err := client.UserExists(candidate)
		if err != nil {
			return "", fmt.Errorf("%w: LDAP lookup: %v", ErrInternal, err)
		}
		if exists {
			// User picked a specific id+tag; tell them it's taken
			// rather than silently substituting a different tag.
			return "", fmt.Errorf("%w: %s", ErrUIDTaken, candidate)
		}
		return candidate, nil
	}

	// Auto-generate tag with collision retry. 4-char base36 ≈ 1.7M
	// tags per id-base — birthday collision at 1% with ~180
	// pre-existing same-base users. 8 retries covers the tail.
	for attempt := 0; attempt < 8; attempt++ {
		tag, err := randomTag()
		if err != nil {
			return "", fmt.Errorf("%w: tag generation: %v", ErrInternal, err)
		}
		candidate := idBase + "#" + tag
		// Same currentUID exclusion as the explicit-tag branch — a
		// caller renaming to themselves shouldn't fail uniqueness.
		// In the auto-generate path this is much rarer (random
		// tag would have to match the existing tag) but the short-
		// circuit is uniform.
		if candidate == currentUID {
			return candidate, nil
		}
		exists, err := client.UserExists(candidate)
		if err != nil {
			return "", fmt.Errorf("%w: LDAP lookup: %v", ErrInternal, err)
		}
		if !exists {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%w: %s", ErrUsernameUnavailable, idBase)
}

// sanitizeAndValidateID applies the id-base sanitiser to a user-
// supplied ID and enforces length bounds. Returns the cleaned form
// or ErrIDInvalid with a wrapped reason. The 2-char floor avoids
// near-empty `a#xxxx` uids that look like typos; the 32-char ceiling
// keeps display tables clean.
func sanitizeAndValidateID(s string) (string, error) {
	cleaned := sanitizeIDBase(s)
	if len(cleaned) < 2 {
		return "", fmt.Errorf("%w: id must be at least 2 characters (got %q after sanitising)", ErrIDInvalid, cleaned)
	}
	if len(cleaned) > 32 {
		return "", fmt.Errorf("%w: id must be at most 32 characters (got %d)", ErrIDInvalid, len(cleaned))
	}
	return cleaned, nil
}

// validateTag normalises and validates a user-supplied tag. The
// canonical stored form is UPPERCASE (`A8F3`), which gives a
// distinct visual silhouette vs. id-bases (which are lowercase)
// and reads cleanly in display surfaces. Input is case-insensitive
// — `a8f3`, `A8F3`, `A8f3` all yield `A8F3`.
//
// Returns ErrTagInvalid with a specific reason on any shape failure.
func validateTag(s string) (string, error) {
	s = strings.ToUpper(s)
	if len(s) != 4 {
		return "", fmt.Errorf("%w: tag must be exactly 4 characters (got %d)", ErrTagInvalid, len(s))
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z')) {
			return "", fmt.Errorf("%w: tag may only contain 0-9 and A-Z (got %q)", ErrTagInvalid, s)
		}
	}
	return s, nil
}

// sanitizeIDBase reduces an email local part to LDAP-uid-friendly
// characters: lowercase alphanumeric plus `.`, `_`, `-`. Strips
// `#` (our delimiter), `+` (LDAP RDN multi-value separator), spaces,
// and anything else outside the allowed set. Trims leading/trailing
// punctuation so the result is a clean readable id.
//
//	`Alice.Smith+tag` → `alice.smith.tag` is wrong here — the `+` is
//	dropped, not converted. Result: `alicesmithtag` → trimmed to
//	`alice.smith` (the `.tag` after the dropped `+` becomes part of
//	a continuous run; final result is what's between cleaners).
//
// Actually because we DROP rather than collapse-to-`.`, we get:
//
//	`Alice.Smith+tag`  → `alicesmith.tag` … wait, the `+` is between
//	`smith` and `tag`. We drop `+`. Result: `alicesmithtag` (the
//	`.` before `tag` is gone too because… hmm).
//
// Let me just be precise: we KEEP allowed chars, DROP everything
// else, then trim. `Alice.Smith+tag` → `alice.smithtag` (drop `+`,
// keep `.`). `bob_42` → `bob_42` (already clean).
// `a.b.c+x.y` → `a.b.cx.y`. `___` → `` (all special, gets trimmed).
func sanitizeIDBase(s string) string {
	s = strings.ToLower(s)
	out := strings.Builder{}
	out.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			out.WriteRune(r)
		}
	}
	return strings.Trim(out.String(), "._-")
}

// NormalizeUIDInput uppercases the tag portion of a uid-style login
// input. If `s` contains a `#`, treats everything after the LAST
// occurrence as the tag and uppercases it. Strings without `#`
// (emails, legacy untagged uids like the bootstrap "admin") pass
// through unchanged.
//
// Used at handler-input boundaries where a user might type a uid
// like `alice#a8f3` — the canonical stored form is `alice#A8F3`,
// and we want logs / audit / displays to use the canonical form
// regardless of what the user typed.
//
// LastIndex (rather than Index) is defensive against malformed
// inputs with multiple `#` — our sanitiser strips `#` from id-base
// so we never produce such uids, but a stray-input safeguard
// costs nothing.
func NormalizeUIDInput(s string) string {
	at := strings.LastIndex(s, "#")
	if at < 0 || at == len(s)-1 {
		return s
	}
	return s[:at+1] + strings.ToUpper(s[at+1:])
}

// emailLocalPart returns the part of an email before the `@`. Empty
// when the email has no `@` (looksLikeEmail rejects those before
// reaching this code path, but defensive).
func emailLocalPart(email string) string {
	at := strings.IndexByte(email, '@')
	if at <= 0 {
		return ""
	}
	return email[:at]
}

// randomTag returns 4 base36 characters (0-9, A-Z) generated from
// crypto/rand. Uppercase is the canonical stored form; user input
// is normalised to match. Modulo bias is negligible at this length
// (~14% bias on individual character distribution) and uniformity
// isn't a security property here — we just need tags hard to guess
// in advance for a given id-base.
func randomTag() (string, error) {
	const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, 4)
	for i, x := range b {
		out[i] = charset[int(x)%len(charset)]
	}
	return string(out), nil
}

// looksLikeEmail does the same minimal check the api-server's
// users_handlers used to do inline. RFC 5322 grammar is
// over-the-top for this case; we just want to reject obvious
// typos and have the actual address validity verified later via
// email-confirmation flow (Phase 9).
func looksLikeEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return false
	}
	if strings.IndexByte(s[at+1:], '.') < 0 {
		return false
	}
	if strings.IndexByte(s, ' ') >= 0 {
		return false
	}
	return true
}
