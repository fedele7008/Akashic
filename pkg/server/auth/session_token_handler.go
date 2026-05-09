package auth

import (
	"encoding/json"
	"net/http"
	"time"

	"akashic/akashic/pkg/oauth"
	"akashic/akashic/pkg/server/response"

	"go.uber.org/zap"
)

// handleSessionToken serves POST /session/token — the Phase 8b
// bearer-exchange endpoint for first-party widgets.
//
// Flow (per phase-8b-pivot-plan.md, Step 4):
//
//   1. Tenant page on `<tenant>` mounts a widget that needs to call
//      `api.<tenant>` with bearer auth.
//   2. Widget POSTs to `auth.<tenant>/session/token` with
//      `credentials: 'include'`.
//   3. The request carries the host-scoped session cookie set by
//      /login (cookie travels via SameSite=Lax cross-origin same-site).
//   4. We validate the session against the same store /authorize uses.
//   5. We mint a short-lived (15 min) access-token JWT signed by the
//      OAuth keystore — same shape as bearers from /oauth/token, so
//      the api-server's existing bearer middleware accepts it
//      uniformly.
//   6. Widget caches the bearer in JS memory (NOT localStorage) and
//      uses it on subsequent api-server calls. Refreshes via this
//      same endpoint when near expiry.
//
// Why not cookie-auth on api-server: see phase-8b-pivot-plan.md.
// Short version — `Domain=<parent>` cookie scoping would leak the
// session to every subdomain of the tenant's eTLD+1 (including ones
// outside Akashic's deployment). Host-scoped cookie + bearer-exchange
// keeps the session cookie strictly on auth.<tenant>.
//
// Method: POST only (state-conserving, but conventional for bearer
// exchange — easier to argue with caching proxies).
//
// Auth: requires the host-scoped session cookie. Returns 401 if the
// cookie is missing/expired/idle-timed-out — widgets render a sign-in
// CTA on this signal.
//
// CORS: gated by `AKASHIC_PORTAL_TENANT_ORIGINS` allowlist. Without
// CORS allowance, a malicious origin could trigger the exchange
// (cookies travel) but couldn't read the response — but we close
// that hole by refusing the response entirely for unallowlisted
// origins.
func (s *Server) handleSessionToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"only POST on /session/token", nil))
		return
	}

	s.mu.RLock()
	keyStore := s.oauthKeyStore
	sessionStore := s.sessionStore
	s.mu.RUnlock()
	if keyStore == nil || sessionStore == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("AUTH_NOT_READY",
				"auth server not yet fully initialized", nil))
		return
	}

	// Bootstrap gate. Mirrors /login — until the operator has set up
	// a root user, no end-user surface should mint bearers.
	if s.bootstrapBlocked(r.Context()) {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("BOOTSTRAP_INCOMPLETE",
				"this deployment is still being set up by its operator", nil))
		return
	}

	// Read + validate the host-scoped session cookie.
	sid := readCookie(r, authSessionCookie)
	if sid == "" {
		response.WriteJSON(w, http.StatusUnauthorized,
			response.Fail("NO_SESSION",
				"no auth session cookie present", nil))
		return
	}
	sess, err := sessionStore.Touch(r.Context(), sid)
	if err != nil {
		// Idle-timed-out, expired, or otherwise gone. Same surface as
		// "no cookie" — widget should render a sign-in CTA.
		response.WriteJSON(w, http.StatusUnauthorized,
			response.Fail("NO_SESSION",
				"session expired or invalid", nil))
		return
	}

	// Mint a short-lived bearer. 15 min — matches OAuth /token's
	// access-token TTL by default, so the api-server can't tell the
	// difference between session-bearer and OAuth-bearer.
	cfg := s.config.GetConfig()
	now := time.Now().UTC()
	mintIn := oauth.MintInput{
		Issuer:    cfg.OAuth.Issuer,
		Subject:   sess.UserID,
		// Audience: the dedicated first-party marker. The api-server's
		// `requireFirstPartyBearer` wrapper enforces aud == this on
		// every sensitive endpoint, so a third-party OAuth-flow bearer
		// cannot reach (e.g.) /users/me/uid even with a valid signature
		// + openid scope.
		Audience:  oauth.SessionTokenAudience,
		IssuedAt:  now,
		ExpiresIn: cfg.OAuth.AccessTokenTTL,
	}
	// Always grant "openid" — the api-server's requireBearer asserts
	// this scope on every protected route. First-party widgets are
	// implicitly trusted with the user's identity.
	scope := "openid"
	bearer, err := oauth.MintAccessToken(keyStore, mintIn, scope, sess.UserType)
	if err != nil {
		s.logger.App.Error("session/token: mint failed", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("MINT_FAILED", "could not mint bearer", nil))
		return
	}

	// Successful exchange. Return RAW JSON (NOT the {success,data}
	// envelope) so the response shape matches OAuth /token — widgets
	// can parse it identically regardless of bearer source.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": bearer,
		"token_type":   "Bearer",
		"expires_in":   int(cfg.OAuth.AccessTokenTTL.Seconds()),
	})
}
