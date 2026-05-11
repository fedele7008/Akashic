// Package mfa owns the Phase 9f email-MFA workflow:
//
//   - IsRequired: live computation of whether a given login attempt
//     must clear MFA (per-user opt-in OR per-client require_mfa).
//   - IssueCode: generate a 6-digit code, store hash in Redis, email
//     the plaintext to the user.
//   - VerifyCode: consume-on-match against the stored hash.
//   - Trusted-device cookie helpers: mint/check/revoke "remember
//     this device" rows so trusted browsers skip the MFA prompt.
//
// The package stays pure-domain — no HTTP, no template rendering
// in handler-shape — so the auth-server's /login handlers and the
// api-server's /users/me/mfa endpoints can drive it the same way.
//
// Three deliberate design choices:
//
//  1. *Codes are session-keyed.* The Redis key is the partial
//     session id, not the user id. This scopes a code to one
//     specific in-flight login attempt; parallel logins on
//     different devices each get their own code without stomping.
//
//  2. *Trusted-device cookies are SHA-256 hashed at-rest.* The
//     plaintext only ever lives in the user's browser. A DB dump
//     plus the bcrypt'd password hashes plus the trusted-device
//     hashes still doesn't yield a forged session — the cookie
//     itself is required, and the random 32-byte token has 256
//     bits of entropy.
//
//  3. *No-mailer = silent skip, not silent grant.* When the mailer
//     isn't configured AND a user has mfa_enabled=true (or a client
//     requires MFA), we fall through to a regular session — there's
//     no path to deliver the code, and locking the user out forever
//     is worse than degrading. The admin web's UI greys out the
//     toggles in that case so this state shouldn't be reached in
//     practice; the runtime fall-through is belt-and-braces.
package mfa

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"akashic/akashic/pkg/email"
	"akashic/akashic/pkg/mailer"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/policy"
	"akashic/akashic/pkg/repository"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// TrustedCookieBytes is the random-token length for the
// "remember this device" cookie. 32 bytes → 256 bits → no realistic
// brute-force.
const TrustedCookieBytes = 32

// CookieName is the trusted-device cookie name. Host-scoped (per
// design decision D5) so a leak to one tenant doesn't ride into
// another.
const CookieName = "akashic_mfa_trusted"

// Service bundles the runtime dependencies. Held by the auth-server
// (login flow) and the api-server (user-side widget endpoints).
// Methods are concurrent-safe — each goroutine has its own ctx and
// the underlying db / redis are concurrent-safe.
type Service struct {
	users   *repository.UserRepository
	clients clientLookup
	devices *repository.MFATrustedDeviceRepository
	codes   *email.MFACodeStore
	policy  *policy.Service
	mailer  mailer.Mailer
	logger  *zap.Logger
}

// clientLookup is the minimal client-lookup surface this package
// needs (`require_mfa` per client_id). Wrapping `*gorm.DB` so we
// don't have to drag the whole DB plus the clientservice package
// in here.
type clientLookup interface {
	RequireMFAFor(ctx context.Context, clientID string) (bool, error)
}

// Deps is the field bag NewService accepts.
type Deps struct {
	Users   *repository.UserRepository
	Clients clientLookup
	Devices *repository.MFATrustedDeviceRepository
	Codes   *email.MFACodeStore
	Policy  *policy.Service
	Mailer  mailer.Mailer
	Logger  *zap.Logger
}

func NewService(d Deps) *Service {
	return &Service{
		users:   d.Users,
		clients: d.Clients,
		devices: d.Devices,
		codes:   d.Codes,
		policy:  d.Policy,
		mailer:  d.Mailer,
		logger:  d.Logger,
	}
}

// IsRequired returns true iff the login attempt must clear MFA.
// Combines two signals:
//   - User opt-in: `users.mfa_enabled = true`
//   - Client requirement: `client_services.require_mfa = true`
//     when `clientID` is non-empty (login originated from /authorize).
//
// Returns false when the mailer isn't configured — there's no
// runtime path to deliver codes, so silently skipping MFA keeps
// users from being locked out. The admin web's UI greys out the
// toggles in that case to make the latent state visible.
func (s *Service) IsRequired(ctx context.Context, user *models.User, clientID string) (bool, error) {
	if s.mailer == nil || !s.mailer.IsConfigured() {
		return false, nil
	}
	if user.MFAEnabled {
		return true, nil
	}
	if clientID != "" && s.clients != nil {
		need, err := s.clients.RequireMFAFor(ctx, clientID)
		if err != nil {
			return false, fmt.Errorf("read client require_mfa: %w", err)
		}
		if need {
			return true, nil
		}
	}
	return false, nil
}

// ─── Trusted-device cookie ────────────────────────────────────────

// HashCookieValue is the canonical "cookie plaintext → DB hash"
// transform. Exported so handlers that need to *check* a cookie
// without holding a Service can hash on their own (the read-side
// is pure).
func HashCookieValue(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// IsTrustedDevice checks whether the supplied cookie value matches
// an active trusted-device row for the given user. Returns:
//   - (true, nil) — match; LastUsedAt has been bumped.
//   - (false, nil) — no match (no row, revoked, expired, or row
//     belongs to a different user).
//   - (false, err) — repo error.
//
// The user-scope check is critical: a leaked cookie shouldn't be
// usable by a different user logging in even if the hash collides
// (essentially impossible at SHA-256 strengths, but the user_id
// equality check makes it definitive).
func (s *Service) IsTrustedDevice(ctx context.Context, userID uuid.UUID, cookieValue string) (bool, error) {
	if cookieValue == "" {
		return false, nil
	}
	hash := HashCookieValue(cookieValue)
	row, err := s.devices.FindActiveByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, repository.ErrTrustedDeviceNotFound) {
			return false, nil
		}
		return false, err
	}
	if row.UserID != userID {
		return false, nil
	}
	// Bump last_used so the user surface can show recency. Best-
	// effort: a failure here doesn't change the trusted-device
	// answer.
	if err := s.devices.BumpLastUsed(ctx, row.ID); err != nil {
		s.logger.Warn("mfa: bump LastUsedAt failed",
			zap.String("device_id", row.ID.String()),
			zap.Error(err))
	}
	return true, nil
}

// RememberDevice mints a fresh trusted-device row. `requestedDays`
// is what the user picked on the MFA challenge page; it's clamped
// to the tenant policy's `mfa_trusted_device_max_days`. Returns
// the cookie plaintext (caller sets the cookie).
func (s *Service) RememberDevice(
	ctx context.Context,
	userID uuid.UUID,
	requestedDays int,
	label string,
) (cookieValue string, err error) {
	pol, err := s.policy.Get(ctx)
	if err != nil {
		return "", fmt.Errorf("read policy: %w", err)
	}
	days := requestedDays
	if days <= 0 {
		days = pol.MFATrustedDeviceMaxDays
	}
	if days > pol.MFATrustedDeviceMaxDays {
		days = pol.MFATrustedDeviceMaxDays
	}

	buf := make([]byte, TrustedCookieBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	cookieValue = base64.RawURLEncoding.EncodeToString(buf)

	now := time.Now().UTC()
	row := &models.MFATrustedDevice{
		UserID:          userID,
		CookieTokenHash: HashCookieValue(cookieValue),
		Label:           strings.TrimSpace(label),
		ExpiresAt:       now.Add(time.Duration(days) * 24 * time.Hour),
		LastUsedAt:      now,
	}
	if err := s.devices.Create(ctx, row); err != nil {
		return "", err
	}
	return cookieValue, nil
}

// RevokeDevice revokes a single trusted-device row, gated on
// user-id ownership. Used by the user-side <akashic-mfa-settings>
// widget's "Revoke" buttons.
func (s *Service) RevokeDevice(ctx context.Context, userID, deviceID uuid.UUID) error {
	return s.devices.RevokeByID(ctx, deviceID, userID)
}

// ListDevices returns every trusted-device row for a user. The
// widget filters/sorts client-side; the repo layer doesn't pre-cut.
func (s *Service) ListDevices(ctx context.Context, userID uuid.UUID) ([]*models.MFATrustedDevice, error) {
	return s.devices.ListForUser(ctx, userID)
}

// ─── Code issuance + verification ─────────────────────────────────

// IssueCode generates a fresh 6-digit code, stores its hash keyed
// by the partial session id, and emails the plaintext to the user.
// Returns (issued=true, nil) on success; (false, ErrMFARateLimited)
// when the per-user rate limit fires; (false, err) on any other
// failure.
//
// The code's session-keying means the caller MUST hold a partial
// session before calling this — the auth-server's /login/submit
// creates the session with MFAPending=true, then calls IssueCode
// with the new sid.
//
// Email send failures DO surface as errors here (unlike approval
// emails in 9e): the user has no other channel to obtain the code,
// so a silent fail would lock them out. The handler maps this to a
// generic "couldn't send code, please try again" UI.
func (s *Service) IssueCode(
	ctx context.Context,
	user *models.User,
	sessionID string,
	emailAddr string,
	displayName string,
) error {
	if s.mailer == nil || !s.mailer.IsConfigured() {
		// Defensive: IsRequired should have already returned false.
		// If we got here, log and refuse — the admin shouldn't have
		// enabled MFA without a mailer, but if they did, we won't
		// pretend a code went out.
		return errors.New("mfa: no mailer configured")
	}
	rawCode, err := s.codes.Create(ctx, sessionID, user.ID.String())
	if err != nil {
		return err
	}

	dn := displayName
	if dn == "" {
		dn = emailAddr
		if at := strings.IndexByte(dn, '@'); at > 0 {
			dn = dn[:at]
		}
	}
	msg, rerr := mailer.Render("mfa_code", map[string]any{
		"TenantName":       "Akashic",
		"DisplayName":      dn,
		"Code":             rawCode,
		"ExpiresInMinutes": int(email.MFACodeLifetime.Minutes()),
	})
	if rerr != nil {
		// Already-issued code is now orphaned — it'll TTL out in 10
		// min. We don't bother deleting; the user can retry, which
		// just supersedes the row.
		return fmt.Errorf("render mfa_code template: %w", rerr)
	}
	msg.To = emailAddr
	if err := s.mailer.Send(ctx, msg); err != nil {
		return fmt.Errorf("send mfa code: %w", err)
	}
	s.logger.Info("mfa code issued",
		zap.String("user_id", user.ID.String()),
		zap.String("session_id", sessionID))
	return nil
}

// VerifyCode is a thin pass-through to the store. Kept here so the
// handler doesn't reach into pkg/email directly — gives us a single
// place to add cross-cutting concerns later (e.g., rate-limit
// metrics, security-channel audit logging on excessive failures).
func (s *Service) VerifyCode(ctx context.Context, sessionID, supplied string) error {
	return s.codes.Verify(ctx, sessionID, supplied)
}

// AbortPendingCode deletes the in-flight code for a partial session
// — used when the partial session is torn down (logout, password-
// reset detour) so a stale row doesn't sit in Redis until TTL.
func (s *Service) AbortPendingCode(ctx context.Context, sessionID string) {
	if err := s.codes.Delete(ctx, sessionID); err != nil {
		s.logger.Warn("mfa: abort pending code failed",
			zap.String("session_id", sessionID),
			zap.Error(err))
	}
}

// ─── Errors re-exported for handler convenience ──────────────────

var (
	ErrMFACodeInvalid    = email.ErrMFACodeInvalid
	ErrMFARateLimited    = email.ErrMFARateLimited
	ErrTrustedNotFound   = repository.ErrTrustedDeviceNotFound
)
