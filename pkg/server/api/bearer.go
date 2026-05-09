package api

import (
	"net/http"
	"strings"

	"akashic/akashic/pkg/oauth"
	"akashic/akashic/pkg/server/response"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// requireBearer wraps a handler that needs a verified OAuth access
// token. The token comes from `Authorization: Bearer <token>` and is
// validated against the in-process keystore — same crypto verification
// the auth server's /userinfo does. On success, the user's UUID
// (parsed from the `sub` claim) is passed to the handler. On failure,
// returns 401 with a WWW-Authenticate header per RFC 6750 §3.
//
// Phase 8 is coarse: any valid token with the `openid` scope is good
// enough. Future-phase scope-gating (e.g. require `clients:manage`
// for /clients/*) is a one-line addition — see the scope-includes
// helper at the bottom of this file.
func (s *Server) requireBearer(next func(http.ResponseWriter, *http.Request, uuid.UUID, *oauth.AccessTokenClaims)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		ks := s.keyStore
		s.mu.RUnlock()
		if ks == nil {
			// Server not yet fully wired. Distinct from "bad token" —
			// the caller should retry; their token isn't the problem.
			response.WriteJSON(w, http.StatusServiceUnavailable,
				response.Fail("API_NOT_READY",
					"API server keystore not yet initialized", nil))
			return
		}

		token, ok := bearerToken(r)
		if !ok {
			writeBearerError(w, http.StatusUnauthorized, "invalid_request",
				"missing or malformed Authorization: Bearer header")
			return
		}

		// Pass empty audience — Phase 8 doesn't bind tokens to a
		// specific resource server audience. If we ever do (e.g.
		// `aud=akashic-api`), pass that here.
		claims, err := oauth.VerifyAccessToken(ks, token, "")
		if err != nil {
			s.logger.Security.Warn("api: bearer verification failed",
				zap.Error(err))
			writeBearerError(w, http.StatusUnauthorized, "invalid_token", err.Error())
			return
		}

		// `sub` claim is the user's postgres UUID (set by oauth.MintAccessToken).
		uid, perr := uuid.Parse(claims.Subject)
		if perr != nil {
			writeBearerError(w, http.StatusUnauthorized, "invalid_token",
				"token subject is not a valid user UUID")
			return
		}

		// Phase 8 minimum: token must include `openid` scope. Any
		// token issued via the standard /authorize flow includes it
		// because the portal always requests `openid profile email`.
		if !scopeIncludes(claims.Scope, "openid") {
			writeBearerError(w, http.StatusForbidden, "insufficient_scope",
				"token lacks required scope: openid")
			return
		}

		next(w, r, uid, claims)
	}
}

// bearerToken extracts the Bearer-prefixed token value from the
// Authorization header. Returns ("", false) if the header is missing,
// malformed, or doesn't use the Bearer scheme. Same shape as
// pkg/server/auth/oauth_flow_handlers.go's bearerToken — duplicated
// here to keep the api package free of cross-package handler imports.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	return strings.TrimSpace(h[len(prefix):]), true
}

// writeBearerError emits the RFC 6750 §3 error pattern: a WWW-
// Authenticate header naming the error code + description, plus a
// JSON body for client convenience. The header is what makes a
// 401 "OAuth-bearer-correct"; the body is the niceness on top.
func writeBearerError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("WWW-Authenticate",
		`Bearer error="`+code+`", error_description="`+description+`"`)
	response.WriteJSON(w, status,
		response.Fail("BEARER_"+strings.ToUpper(code), description, nil))
}

// scopeIncludes returns true iff the space-separated scope list
// contains the target scope. Mirrors the same helper in the auth
// package — kept local here to avoid cross-package handler coupling.
func scopeIncludes(scopes, target string) bool {
	for _, s := range strings.Fields(scopes) {
		if s == target {
			return true
		}
	}
	return false
}

// requirePublic is a no-op wrapper for endpoints that explicitly
// don't require a bearer token (e.g. /users/register before the
// user has an account, /users/forgot-password-help). Naming it
// requirePublic instead of "no middleware" makes it visible at the
// route table level that this is an UNAUTHENTICATED endpoint by
// design — not an oversight.
func requirePublic(next http.HandlerFunc) http.HandlerFunc {
	return next
}

// requireFirstPartyBearer wraps `requireBearer` with an additional
// check: the bearer's `aud` claim must equal `oauth.SessionTokenAudience`.
//
// Only auth-server `/session/token` mints with that audience, and that
// endpoint requires the host-scoped first-party session cookie + the
// tenant-origin CORS allowlist. So a token with this audience proves
// "the call is on behalf of a user who is signed in to a first-party
// portal" — which is the trust boundary we need for sensitive flows
// like changing account ID, mutating profile fields, registering or
// deleting OAuth clients, and revoking other apps' consents.
//
// Tokens minted via the OAuth `/oauth/token` flow carry their
// requesting client's `client_id` as `aud` and therefore fail this
// check. They keep working on the read-only endpoints (e.g.
// `GET /users/me`) that wrap with `requireBearer` directly.
//
// Failure mode: 403 with `error="insufficient_scope"`. We use 403,
// not 401, because the token IS valid — it just isn't trusted enough
// for this operation. RFC 6750 §3.1 reserves "insufficient_scope" for
// exactly this shape ("the request requires higher privileges than
// provided by the access token"); we reuse it for our audience-based
// gate since the semantic match is closer than any other listed code.
func (s *Server) requireFirstPartyBearer(next func(http.ResponseWriter, *http.Request, uuid.UUID, *oauth.AccessTokenClaims)) http.HandlerFunc {
	return s.requireBearer(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID, claims *oauth.AccessTokenClaims) {
		if !claims.VerifyAudience(oauth.SessionTokenAudience) {
			s.logger.Security.Warn(
				"api: third-party bearer rejected on first-party-only endpoint",
				zap.String("path", r.URL.Path),
				zap.String("user_id", uid.String()),
				zap.Strings("token_audience", claims.Audience))
			writeBearerError(w, http.StatusForbidden, "insufficient_scope",
				"this endpoint is restricted to first-party portal sessions")
			return
		}
		next(w, r, uid, claims)
	})
}
