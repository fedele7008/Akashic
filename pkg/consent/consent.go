// Package consent is the policy layer for OAuth consent decisions —
// "should /authorize prompt this user before issuing a code for this
// client?" Phase 7.
//
// The hybrid policy this package implements:
//   - Built-in clients (server-managed, e.g. akashic-admin): never
//     prompt. They're shipped by the operator alongside akashic
//     itself; consent is implicit.
//   - First-party clients (`IsTenantPortal=true`): never prompt.
//     The operator owns these and trust is implicit. This is
//     Google's pattern — Gmail signing into your Google account
//     doesn't show a consent screen.
//   - Third-party clients (anything else): prompt on first grant
//     and whenever the requested scope set isn't a subset of the
//     stored grant. Subsequent re-authorizations for the same or
//     narrower scopes are silently approved.
package consent

import (
	"context"
	"sort"
	"strings"

	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/repository"

	"github.com/google/uuid"
)

// Decision captures the output of Required for the auth-server's
// branching logic. Could be replaced by a bare bool, but the
// explicit type makes call sites self-documenting and lets us
// extend with a Reason field later if we want telemetry.
type Decision struct {
	// Required is true when the auth-server should redirect to
	// /consent before minting a code. False means the existing
	// grant covers the request.
	Required bool
	// Reason is a short string suitable for security audit logs
	// ("first-party", "previously-granted", "scope-superset", etc.).
	// Not user-facing.
	Reason string
}

// Required answers the policy question. Repo may be nil — that
// means consent storage isn't wired up yet, in which case we
// fail-open (treat all access as previously consented). Same
// fail-open posture the bootstrap and signup gates take: better
// to allow a flow during a transient outage than hard-lock every
// OAuth client.
func Required(
	ctx context.Context,
	repo *repository.OAuthConsentRepository,
	client *models.ClientService,
	userID uuid.UUID,
	requestedScope string,
) Decision {
	if client == nil {
		return Decision{Required: false, Reason: "no-client"}
	}
	if client.BuiltIn {
		return Decision{Required: false, Reason: "builtin"}
	}
	if client.IsTenantPortal {
		return Decision{Required: false, Reason: "first-party"}
	}
	if repo == nil {
		return Decision{Required: false, Reason: "consent-repo-unwired"}
	}

	row, err := repo.Get(ctx, userID, client.ClientID)
	if err != nil {
		if repository.IsNotFound(err) {
			return Decision{Required: true, Reason: "no-prior-consent"}
		}
		// Real DB error. Fail-CLOSED (require prompt) — better to
		// inconvenience the user once than to silently issue a
		// token under uncertain consent state.
		return Decision{Required: true, Reason: "consent-lookup-error"}
	}
	if row.RevokedAt != nil {
		return Decision{Required: true, Reason: "previously-revoked"}
	}
	if !scopesIncluded(requestedScope, row.Scopes) {
		// Client is asking for a scope not in the stored grant.
		// Re-prompt so the user sees the new scope explicitly.
		return Decision{Required: true, Reason: "scope-superset"}
	}
	return Decision{Required: false, Reason: "previously-granted"}
}

// scopesIncluded returns true iff every scope in `requested` is
// present in `granted`. Both inputs are space-separated; order
// doesn't matter. Empty `requested` returns true (no scopes ⊆
// any set).
func scopesIncluded(requested, granted string) bool {
	gset := map[string]bool{}
	for _, s := range strings.Fields(granted) {
		gset[s] = true
	}
	for _, s := range strings.Fields(requested) {
		if !gset[s] {
			return false
		}
	}
	return true
}

// NormalizeScopes returns the input scope string with whitespace
// collapsed and tokens sorted. Used by the consent handler when
// writing the row, so the stored representation is canonical and
// the audit log lines are stable.
func NormalizeScopes(s string) string {
	tokens := strings.Fields(s)
	sort.Strings(tokens)
	return strings.Join(tokens, " ")
}
