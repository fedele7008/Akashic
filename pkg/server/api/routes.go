package api

import (
	"net/http"

	"akashic/akashic/pkg/oauth"

	"github.com/google/uuid"
)

// registerRoutes wires the API server's HTTP routes.
//
// PUBLIC (no token required):
//   POST /users/register
//   GET  /users/forgot-password-help
//   GET  /users/password-policy
//
// BEARER (any valid OAuth access token; `sub` claim = user identity):
//   GET  /users/me                      — read profile basics
//
// FIRST-PARTY BEARER (token must have aud == oauth.SessionTokenAudience):
//   PATCH  /users/me                    — mutate profile fields
//   POST   /users/me/password           — change password (still requires old)
//   PATCH  /users/me/uid                — rotate id#TAG
//   GET    /users/me/consents           — list connected apps
//   DELETE /users/me/consents/<id>      — revoke a connected app
//   GET    /clients/mine, POST /clients
//   GET, PATCH, DELETE /clients/<id>
//   POST   /clients/<id>/rotate-secret
//
// META:
//   GET /health  liveness
//   GET /ready   readiness (deps wired?)
//
// Wrapper semantics (defined in bearer.go):
//   requirePublic           — no-op; endpoint is intentionally unauth.
//   requireBearer           — verifies signature + openid scope; any aud.
//   requireFirstPartyBearer — requireBearer + asserts aud equals the
//                             session-token audience minted by
//                             auth-server `/session/token`. Blocks
//                             third-party OAuth bearers from reaching
//                             account-mutation surfaces.
func (s *Server) registerRoutes(mux *http.ServeMux) {
	// Liveness / readiness.
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/ready", s.handleReady)

	// Public user-management.
	mux.HandleFunc("/users/register",
		requirePublic(s.handleRegisterUser))
	mux.HandleFunc("/users/forgot-password-help",
		requirePublic(s.handleForgotPasswordHelp))
	mux.HandleFunc("/users/password-policy",
		requirePublic(s.handlePasswordPolicy))
	// Phase B portal-side: tenant-allowed-client-scopes is read by
	// the <akashic-clients> widget at register/edit time so the
	// scope matrix renders against the tenant's ceiling.
	mux.HandleFunc("/allowed-client-scopes",
		requirePublic(s.handleAllowedClientScopes))

	// Bearer-authenticated /users/me. Method-split: GET is open to any
	// valid bearer (a third-party app the user has consented to may
	// legitimately want to read profile basics, mirroring /userinfo);
	// PATCH is first-party only because changing email/display_name is
	// an account-takeover step (attacker → account-recovery email →
	// password reset). The audience check is INSIDE the dispatcher
	// rather than at the wrapper layer because http.ServeMux is one-
	// handler-per-pattern; we can't have two wrappers on one path.
	mux.HandleFunc("/users/me",
		s.requireBearer(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID, claims *oauth.AccessTokenClaims) {
			switch r.Method {
			case http.MethodGet:
				s.handleGetMe(w, r, uid, claims)
			case http.MethodPatch:
				if !claims.VerifyAudience(oauth.SessionTokenAudience) {
					writeBearerError(w, http.StatusForbidden, "insufficient_scope",
						"PATCH /users/me is restricted to first-party portal sessions")
					return
				}
				s.handlePatchMe(w, r, uid, claims)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
		}))
	mux.HandleFunc("/users/me/password",
		s.requireFirstPartyBearer(s.handleChangePassword))
	mux.HandleFunc("/users/me/uid",
		s.requireFirstPartyBearer(s.handleChangeUID))
	// Phase 9b: resend a verification email to the user's current
	// LDAP-stored email. First-party only (the regular bearer-
	// audience gate); refuses with EMAIL_NOT_AVAILABLE when the
	// mailer is in nop mode.
	mux.HandleFunc("/users/me/send-verification-email",
		s.requireFirstPartyBearer(s.handleSendVerificationEmail))

	// Phase 9f: per-user MFA management. First-party only — the
	// toggle is account-takeover-grade. GET returns the user's
	// current state + trusted-device history; POST toggles the
	// `users.mfa_enabled` flag. Trusted-device revoke nests under
	// /users/me/mfa/trusted-devices/<id>/revoke.
	mux.HandleFunc("/users/me/mfa", s.requireFirstPartyBearer(
		func(w http.ResponseWriter, r *http.Request, uid uuid.UUID, claims *oauth.AccessTokenClaims) {
			switch r.Method {
			case http.MethodGet:
				s.handleGetMyMFA(w, r, uid, claims)
			case http.MethodPost:
				s.handlePatchMyMFA(w, r, uid, claims)
			default:
				writeBearerError(w, http.StatusMethodNotAllowed,
					"method_not_allowed",
					"GET or POST only on /users/me/mfa")
			}
		}))
	mux.HandleFunc("/users/me/mfa/trusted-devices/",
		s.requireFirstPartyBearer(s.handleRevokeMyTrustedDevice))

	// Phase 9g: per-user notification preferences. First-party only.
	mux.HandleFunc("/users/me/notification-preferences",
		s.requireFirstPartyBearer(s.handleMyNotificationPrefs))

	// Phase 7.5: end-user consent management.
	//   GET    /users/me/consents       → list active grants
	//   DELETE /users/me/consents/<id>  → revoke a specific grant
	// First-party only: the listing discloses *which* third-party apps
	// the user has connected, and a malicious third-party shouldn't see
	// other third parties the user uses. Revocation is mutation, also
	// first-party only.
	mux.HandleFunc("/users/me/consents",
		s.requireFirstPartyBearer(s.handleListMyConsents))
	mux.HandleFunc("/users/me/consents/",
		s.requireFirstPartyBearer(s.handleRevokeMyConsent))

	// /clients/* — OAuth client registration is a privileged operation
	// (a malicious app could create a phishing client in the user's
	// name). All of /clients/* is first-party only.
	mux.HandleFunc("/clients/mine",
		s.requireFirstPartyBearer(s.handleListMyClients))
	mux.HandleFunc("/clients",
		s.requireFirstPartyBearer(s.handleCreateClient))
	mux.HandleFunc("/clients/",
		s.requireFirstPartyBearer(s.handleClientByID))

	// Phase 9e: client-registration qualification.
	//   GET  /client-registration-eligibility   live policy + user state
	//   POST /client-registration-requests      user submits an approval req
	//   GET  /client-registration-requests/mine user's request history
	// All first-party — same trust posture as /clients/*.
	mux.HandleFunc("/client-registration-eligibility",
		s.requireFirstPartyBearer(s.handleClientRegistrationEligibility))
	mux.HandleFunc("/client-registration-requests",
		s.requireFirstPartyBearer(s.handleClientRegistrationRequests))
	mux.HandleFunc("/client-registration-requests/mine",
		s.requireFirstPartyBearer(s.handleListMyClientRegistrationRequests))

	// Phase 8b: embeddable widget bundle hosting. Public, cacheable
	// static assets — see widgets_handler.go for the full rationale.
	mux.HandleFunc("/widgets/", s.handleWidgetAsset)
}
