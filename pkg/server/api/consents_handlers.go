package api

import (
	"net/http"
	"strings"

	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/oauth"
	"akashic/akashic/pkg/server/response"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// /users/me/consents — Phase 7.5.
//
// Bearer-authenticated end-user surface for managing OAuth grants:
//
//   GET    /users/me/consents
//     → {consents: [{client_id, client_name, homepage_url, scopes,
//                    granted_at, updated_at}]}
//
//   DELETE /users/me/consents/<client_id>
//     → {revoked: true}
//
// The auth-server's /authorize gate consults the same repository, so
// a successful revoke here makes the next /authorize for that
// client+user combo prompt the consent screen again.

// consentView is the wire shape for one row in the list response.
// Joins client metadata onto the consent record so the widget can
// render the client's name + homepage without a second round-trip.
type consentView struct {
	ClientID    string `json:"client_id"`
	ClientName  string `json:"client_name"`
	HomepageURL string `json:"homepage_url,omitempty"`
	Scopes      string `json:"scopes"`
	GrantedAt   string `json:"granted_at"`
	UpdatedAt   string `json:"updated_at"`
}

// handleListMyConsents serves GET /users/me/consents.
func (s *Server) handleListMyConsents(w http.ResponseWriter, r *http.Request, uid uuid.UUID, _ *oauth.AccessTokenClaims) {
	if r.Method != http.MethodGet {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"only GET is allowed", nil))
		return
	}
	if s.consentRepo == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("API_NOT_READY",
				"consent repository not yet wired", nil))
		return
	}

	rows, err := s.consentRepo.ListForUser(r.Context(), uid)
	if err != nil {
		s.logger.App.Error("listMyConsents: repo", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not load consents", nil))
		return
	}
	if len(rows) == 0 {
		response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
			"consents": []consentView{},
		}))
		return
	}

	// Bulk-fetch the client metadata in one query rather than
	// per-row. Bounded by how many third-party apps a user has
	// ever consented to — a handful in practice.
	clientIDs := make([]string, 0, len(rows))
	for _, row := range rows {
		clientIDs = append(clientIDs, row.ClientID)
	}
	var clients []models.ClientService
	if err := s.db.WithContext(r.Context()).
		Where("client_id IN ?", clientIDs).
		Find(&clients).Error; err != nil {
		s.logger.App.Error("listMyConsents: client metadata", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not load client metadata", nil))
		return
	}
	byID := make(map[string]models.ClientService, len(clients))
	for _, c := range clients {
		byID[c.ClientID] = c
	}

	out := make([]consentView, 0, len(rows))
	for _, row := range rows {
		c := byID[row.ClientID]
		// If the client_services row is gone (operator deleted it
		// after the user granted consent), surface the consent
		// anyway with the client_id as the display name — better
		// than hiding it. Lets the user revoke a stale grant.
		name := c.Name
		if name == "" {
			name = row.ClientID
		}
		out = append(out, consentView{
			ClientID:    row.ClientID,
			ClientName:  name,
			HomepageURL: c.HomepageURL,
			Scopes:      row.Scopes,
			GrantedAt:   row.GrantedAt.UTC().Format("2006-01-02T15:04:05Z"),
			UpdatedAt:   row.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"consents": out,
	}))
}

// handleRevokeMyConsent serves DELETE /users/me/consents/<client_id>.
// Mounted at /users/me/consents/ (trailing slash); the per-id parse
// happens here.
func (s *Server) handleRevokeMyConsent(w http.ResponseWriter, r *http.Request, uid uuid.UUID, _ *oauth.AccessTokenClaims) {
	if r.Method != http.MethodDelete {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"only DELETE is allowed", nil))
		return
	}
	if s.consentRepo == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("API_NOT_READY",
				"consent repository not yet wired", nil))
		return
	}

	clientID := strings.TrimPrefix(r.URL.Path, "/users/me/consents/")
	if clientID == "" || strings.Contains(clientID, "/") {
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("NOT_FOUND", "missing or malformed client_id", nil))
		return
	}

	if err := s.consentRepo.Revoke(r.Context(), uid, clientID); err != nil {
		s.logger.App.Error("revokeConsent: repo",
			zap.String("client_id", clientID),
			zap.String("user_id", uid.String()),
			zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not revoke consent", nil))
		return
	}
	s.logger.Security.Info("oauth consent revoked",
		zap.String("user_id", uid.String()),
		zap.String("client_id", clientID))

	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"revoked": true,
	}))
}
