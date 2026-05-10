// Package mailer is the outbound-email abstraction. Phase 9.
//
// Email is OPTIONAL: tenants without a SendGrid account (or any
// SMTP provider) deploy with `AKASHIC_SENDGRID_API_KEY` unset, and
// every email-dependent feature gracefully degrades. The product
// surfaces (admin web, widgets, auth-server) consult `IsConfigured()`
// to decide whether to render or grey out features like email
// verification, "forgot password" emails, MFA-via-email, and
// login-notification emails.
//
// Design choice: the `Mailer` value is NEVER nil at the call site.
// When SendGrid isn't configured, we hand callers a `nopMailer`
// whose `Send` returns `ErrNotConfigured`. Callers branch on the
// error type when they need to gate UX (a "verification sent"
// banner becomes a "contact admin" message). Keeping the type
// stable removes nil-checking sprawl and makes "is email
// available" a single source of truth.
package mailer

import (
	"context"
	"errors"
)

// ErrNotConfigured is returned by `Send` when no provider is
// configured. Callers check `errors.Is(err, ErrNotConfigured)` and
// either degrade UX (show "contact administrator") or skip the
// send silently (e.g., login notifications when the user opted in
// but the operator removed the API key — we don't fail the login).
var ErrNotConfigured = errors.New("mailer not configured (no provider key)")

// Message is the wire shape for an outgoing email. Plain HTML +
// optional plain-text body — anti-spam best practice is to send
// both. The plain-text version SHOULD be a sensible fallback (not
// just stripped HTML) but we don't enforce that — caller decides.
//
// We don't expose attachments yet; the four Phase 9 use cases
// (verification, forgot-password code, MFA code, login notification)
// are all body-only.
type Message struct {
	// To is the recipient's email address. We send one email per
	// recipient; bulk sends aren't a use case for an IDP.
	To string
	// Subject is the rendered subject line. Caller is responsible
	// for any per-tenant prefix (e.g., "[Acme] Verify your email").
	Subject string
	// HTML is the rendered HTML body. Required.
	HTML string
	// Text is the rendered plain-text body. Optional but strongly
	// recommended — clients without HTML rendering, accessibility
	// readers, and spam filters all use it.
	Text string
}

// Mailer is the outbound-email interface. Implementations:
//   - sendgridMailer (this package, sendgrid.go) — production
//   - nopMailer (this file, below) — when not configured
//   - test fakes (created per-test by callers as needed)
type Mailer interface {
	// Send delivers a Message. Returns ErrNotConfigured if the
	// implementation is the nop variant; other errors propagate
	// from the underlying provider. Callers SHOULD log non-
	// ErrNotConfigured errors via the App channel and let the
	// caller decide whether the higher-level operation fails.
	Send(ctx context.Context, msg Message) error

	// IsConfigured reports whether the mailer is the real,
	// provider-backed variant. Used by handlers to render
	// degraded UI (greyed-out toggles, "contact administrator"
	// fallbacks) without calling Send first.
	IsConfigured() bool
}

// Config is what callers (akashic core context) pass to New().
// Fields are read from akashic's main config; we copy them here
// rather than pulling pkg/config to keep this package importable
// from anywhere without dependency cycles.
//
// Provider is the explicit driver switch (decision D1 in
// doc/phase-9-plan.md). The provider is selected by NAME rather
// than auto-detection from "which API keys are set" — prevents
// silent routing through a stale provider's keys after a switch.
// Operators see the active driver in startup logs.
type Config struct {
	// Provider names the active driver. Recognised values:
	//   ""         → nopMailer (email disabled; default)
	//   "sendgrid" → sendgridMailer
	//   (future)   → "smtp", "postmark", "resend", "ses"
	// Unknown values fall through to nopMailer with a soft error.
	Provider string

	// FromAddress is the envelope-from + header-from address.
	// Required when Provider is non-empty.
	FromAddress string
	// FromName is the human-readable display name pre-pended to
	// FromAddress in the From header. Optional; defaults to "Akashic".
	FromName string

	// Provider-specific keys. Drivers consult only the field(s)
	// they need; unrecognised fields stay zero. Adding a new
	// provider is a new field here + a new case in New().

	// SendGridAPIKey is required when Provider == "sendgrid".
	SendGridAPIKey string
}

// New constructs the appropriate Mailer for the given config.
//
// Selection logic:
//   - Provider == ""               → nopMailer (no error)
//   - Provider == "sendgrid" + key → sendgridMailer
//   - Provider set but misconfig   → nopMailer + soft error
//     (caller logs warning; deploy continues in degraded mode)
//   - Unknown Provider             → nopMailer + soft error
func New(cfg Config) (Mailer, error) {
	if cfg.Provider == "" {
		return nopMailer{}, nil
	}
	if cfg.FromAddress == "" {
		return nopMailer{}, errors.New(
			"mailer: `email_from_address` is required when a provider is configured; " +
				"running in degraded mode (emails will not be sent)")
	}
	fromName := cfg.FromName
	if fromName == "" {
		fromName = "Akashic"
	}
	switch cfg.Provider {
	case "sendgrid":
		if cfg.SendGridAPIKey == "" {
			return nopMailer{}, errors.New(
				"mailer: provider=sendgrid but `sendgrid_api_key` is empty; " +
					"running in degraded mode")
		}
		return newSendGridMailer(cfg.SendGridAPIKey, cfg.FromAddress, fromName), nil
	default:
		return nopMailer{}, errors.New(
			"mailer: unknown provider " + cfg.Provider +
				"; running in degraded mode (recognised: \"\", \"sendgrid\")")
	}
}

// nopMailer is the "email not configured" variant. Every Send
// returns ErrNotConfigured; IsConfigured returns false. Callers
// gate UI on IsConfigured; backend code that calls Send unguarded
// gets a typed error to branch on.
type nopMailer struct{}

func (nopMailer) Send(_ context.Context, _ Message) error { return ErrNotConfigured }
func (nopMailer) IsConfigured() bool                       { return false }
