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
//
// BEARER (token's `sub` claim = user identity):
//   GET, PATCH /users/me
//   POST /users/me/password
//   GET /clients/mine, POST /clients (mine + create)
//   GET, PATCH, DELETE /clients/:id
//   POST /clients/:id/rotate-secret
//
// META:
//   GET /health  liveness
//   GET /ready   readiness (deps wired?)
//
// `requirePublic` is a no-op wrapper that explicitly marks endpoints
// as unauthenticated by design (vs. an oversight). `requireBearer`
// validates the access token + extracts the user UUID.
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

	// Bearer-authenticated /users/me (method-dispatched).
	mux.HandleFunc("/users/me",
		s.requireBearer(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID, claims *oauth.AccessTokenClaims) {
			switch r.Method {
			case http.MethodGet:
				s.handleGetMe(w, r, uid, claims)
			case http.MethodPatch:
				s.handlePatchMe(w, r, uid, claims)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
		}))
	mux.HandleFunc("/users/me/password",
		s.requireBearer(s.handleChangePassword))

	// Phase 7.5: end-user consent management.
	//   GET    /users/me/consents       → list active grants
	//   DELETE /users/me/consents/<id>  → revoke a specific grant
	mux.HandleFunc("/users/me/consents",
		s.requireBearer(s.handleListMyConsents))
	mux.HandleFunc("/users/me/consents/",
		s.requireBearer(s.handleRevokeMyConsent))

	// Bearer-authenticated /clients/*.
	mux.HandleFunc("/clients/mine",
		s.requireBearer(s.handleListMyClients))
	mux.HandleFunc("/clients",
		s.requireBearer(s.handleCreateClient))
	mux.HandleFunc("/clients/",
		s.requireBearer(s.handleClientByID))

	// Phase 8b: embeddable widget bundle hosting. Public, cacheable
	// static assets — see widgets_handler.go for the full rationale.
	mux.HandleFunc("/widgets/", s.handleWidgetAsset)
}
