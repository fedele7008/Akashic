package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"akashic/akashic/pkg/clientregistration"
	"akashic/akashic/pkg/oauth"
	"akashic/akashic/pkg/server/response"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Phase 9e v2: client-registration qualification — user-facing.
//
//   GET  /client-registration-eligibility   live policy + user state
//   POST /client-registration-requests      submit client params + reason
//   GET  /client-registration-requests/mine user's request history
//
// All first-party only. The eligibility endpoint is technically a
// pure read, but it discloses tenant-policy state and the user's
// pending-request reason text — both belong to the portal, not to
// consenting third parties.

func (s *Server) handleClientRegistrationEligibility(w http.ResponseWriter, r *http.Request, uid uuid.UUID, _ *oauth.AccessTokenClaims) {
	if r.Method != http.MethodGet {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, "GET only", nil))
		return
	}
	s.mu.RLock()
	svc := s.clientRegSvc
	s.mu.RUnlock()
	if svc == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("SERVICE_UNAVAILABLE",
				"client-registration service not yet wired", nil))
		return
	}
	out, err := svc.CheckEligibility(r.Context(), uid)
	if err != nil {
		s.logger.App.Error("client-registration eligibility failed",
			zap.String("user_id", uid.String()), zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not compute eligibility", nil))
		return
	}
	response.WriteJSON(w, http.StatusOK, response.Success(out))
}

// submitClientRegistrationRequestBody mirrors the create-client
// shape (`createClientRequest`) plus a reason. The widget posts the
// same form here when the tenant policy requires approval; the
// server stores the params on a pending row, and the materialized
// client_services row is created on approve.
type submitClientRegistrationRequestBody struct {
	Reason         string `json:"reason"`
	Name           string `json:"name"`
	Description    string `json:"description,omitempty"`
	HomepageURL    string `json:"homepage_url,omitempty"`
	ClientType     string `json:"client_type"`
	RedirectURIs   string `json:"redirect_uris"`
	RequiredScopes string `json:"required_scopes,omitempty"`
	OptionalScopes string `json:"optional_scopes,omitempty"`
	RequirePKCE    *bool  `json:"require_pkce,omitempty"`
}

// handleClientRegistrationRequests dispatches POST on
// /client-registration-requests.
func (s *Server) handleClientRegistrationRequests(w http.ResponseWriter, r *http.Request, uid uuid.UUID, _ *oauth.AccessTokenClaims) {
	switch r.Method {
	case http.MethodPost:
		s.submitClientRegistrationRequest(w, r, uid)
	default:
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, "POST only", nil))
	}
}

// handleListMyClientRegistrationRequests is GET-only on
// /client-registration-requests/mine.
func (s *Server) handleListMyClientRegistrationRequests(w http.ResponseWriter, r *http.Request, uid uuid.UUID, _ *oauth.AccessTokenClaims) {
	if r.Method != http.MethodGet {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, "GET only", nil))
		return
	}
	s.mu.RLock()
	svc := s.clientRegSvc
	s.mu.RUnlock()
	if svc == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("SERVICE_UNAVAILABLE",
				"client-registration service not yet wired", nil))
		return
	}
	rows, err := svc.ListByUser(r.Context(), uid)
	if err != nil {
		s.logger.App.Error("list-my client-registration requests failed",
			zap.String("user_id", uid.String()), zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not list requests", nil))
		return
	}
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"requests": rows,
	}))
}

func (s *Server) submitClientRegistrationRequest(w http.ResponseWriter, r *http.Request, uid uuid.UUID) {
	s.mu.RLock()
	svc := s.clientRegSvc
	s.mu.RUnlock()
	if svc == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("SERVICE_UNAVAILABLE",
				"client-registration service not yet wired", nil))
		return
	}
	var body submitClientRegistrationRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST", "could not parse request body", nil))
		return
	}
	defer r.Body.Close()

	requirePKCE := true
	if body.RequirePKCE != nil {
		requirePKCE = *body.RequirePKCE
	}

	row, err := svc.Submit(r.Context(), clientregistration.SubmitParams{
		UserID:         uid,
		Reason:         body.Reason,
		Name:           body.Name,
		Description:    body.Description,
		HomepageURL:    body.HomepageURL,
		ClientType:     body.ClientType,
		RedirectURIs:   body.RedirectURIs,
		RequiredScopes: body.RequiredScopes,
		OptionalScopes: body.OptionalScopes,
		RequirePKCE:    requirePKCE,
	})
	switch {
	case errors.Is(err, clientregistration.ErrCapReached):
		response.WriteJSON(w, http.StatusConflict,
			response.Fail("CAP_REACHED",
				"you have reached your client-registration cap "+
					"(existing + pending); delete an existing client "+
					"or contact your administrator for a higher cap", nil))
		return
	case errors.Is(err, clientregistration.ErrInvalidRequest):
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED", err.Error(), nil))
		return
	case err != nil:
		s.logger.App.Error("submit client-registration request failed",
			zap.String("user_id", uid.String()), zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not submit request", nil))
		return
	}
	response.WriteJSON(w, http.StatusCreated, response.Success(map[string]any{
		"request": row,
	}))
}
