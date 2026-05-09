package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/oauth"
	"akashic/akashic/pkg/repository"

	"go.uber.org/zap"
)

// Refresh-token grant — Phase 9 prep. Companion to handleToken in
// oauth_flow_handlers.go. Lives in its own file because the
// rotation-and-replay logic is intricate enough to deserve focus,
// and oauth_flow_handlers.go is already long.
//
// Flow per OAuth 2.1 §6.1 (refresh-token rotation):
//   1. Caller already passed grant_type dispatch in handleToken,
//      and client authentication has already succeeded.
//   2. Look up the presented refresh_token by its hash.
//      - Not found / expired → invalid_grant
//      - Already consumed/revoked → REPLAY → revoke whole chain,
//        return invalid_grant
//   3. Verify the row's client_id matches the authenticated client.
//      Mismatch → invalid_grant (and revoke the chain — a refresh
//      token presented to the wrong client is at minimum a serious
//      misconfiguration, at worst a credential-stuffing probe).
//   4. Re-validate the user is still enabled.
//   5. Honor scope-narrowing: if the request specified `scope=`, it
//      MUST be a subset of the original. Any superset → invalid_scope.
//      Absent → reuse the original scope.
//   6. Resolve current TTLs (live policy + client overrides — so a
//      shortened ceiling clamps the rotation immediately).
//   7. Mint new access token + new refresh token, persist the new
//      RT row in the same chain (parent_id = old, chain_id = old).
//      Atomic via the repository's Rotate transaction.
//   8. Return the new pair (no ID token on refresh — OIDC §12 says
//      it's optional; we keep it simple for now).

// handleRefreshGrant runs after handleToken has validated the
// client. The form is already parsed.
func (s *Server) handleRefreshGrant(w http.ResponseWriter, r *http.Request, client *models.ClientService) {
	s.mu.RLock()
	keyStore := s.oauthKeyStore
	rtRepo := s.refreshTokenRepo
	db := s.db
	s.mu.RUnlock()
	if keyStore == nil || rtRepo == nil || db == nil {
		writeTokenError(w, http.StatusServiceUnavailable, "server_error",
			"Auth server not yet fully initialized for refresh grant.")
		return
	}

	presented := r.PostForm.Get("refresh_token")
	if presented == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request",
			"refresh_token is required.")
		return
	}

	hash := oauth.HashRefreshToken(presented)
	now := time.Now().UTC()
	row, err := rtRepo.FindForExchange(r.Context(), hash, now)
	switch {
	case errors.Is(err, repository.ErrRefreshTokenReplay):
		// Replay detected. Revoke the WHOLE chain so the
		// attacker's most-recently-rotated RT also dies. The
		// presented token's row is already revoked; this catches
		// the rest. Log loudly via the security channel — this
		// IS a security event.
		if _, rbErr := rtRepo.RevokeChain(r.Context(), row.ChainID, "replay_detected"); rbErr != nil {
			s.logger.App.Error("revoke chain on replay", zap.Error(rbErr))
		}
		s.logger.Security.Warn("refresh token replay detected; chain revoked",
			zap.String("chain_id", row.ChainID.String()),
			zap.String("user_id", row.UserID.String()),
			zap.String("client_id", row.ClientID))
		writeTokenError(w, http.StatusBadRequest, "invalid_grant",
			"Refresh token is invalid or expired.")
		return
	case errors.Is(err, repository.ErrRefreshTokenInvalid):
		// Either not found or expired. Spec mandates we don't
		// distinguish these to the caller (info-leak prevention).
		writeTokenError(w, http.StatusBadRequest, "invalid_grant",
			"Refresh token is invalid or expired.")
		return
	case err != nil:
		s.logger.App.Error("refresh: lookup", zap.Error(err))
		writeTokenError(w, http.StatusInternalServerError, "server_error",
			"Could not validate refresh token.")
		return
	}

	// Step 3: client must match. Refresh tokens are bound to the
	// client they were issued to. A mismatch is suspicious — revoke
	// the chain defensively.
	if row.ClientID != client.ClientID {
		if _, rbErr := rtRepo.RevokeChain(r.Context(), row.ChainID, "client_mismatch"); rbErr != nil {
			s.logger.App.Error("revoke chain on client mismatch", zap.Error(rbErr))
		}
		s.logger.Security.Warn("refresh token presented to wrong client; chain revoked",
			zap.String("chain_id", row.ChainID.String()),
			zap.String("token_client_id", row.ClientID),
			zap.String("auth_client_id", client.ClientID))
		writeTokenError(w, http.StatusBadRequest, "invalid_grant",
			"Refresh token is invalid or expired.")
		return
	}

	// Step 4: user still enabled. Same check the auth-code branch
	// runs — a user disabled mid-session shouldn't keep extending.
	var user models.User
	if err := db.WithContext(r.Context()).Where("id = ?", row.UserID).First(&user).Error; err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant",
			"User no longer exists.")
		return
	}
	if user.IsDisabled {
		// Revoke the chain — disabled users keep generating refresh
		// failures forever otherwise.
		if _, rbErr := rtRepo.RevokeChain(r.Context(), row.ChainID, "user_disabled"); rbErr != nil {
			s.logger.App.Error("revoke chain on user-disabled", zap.Error(rbErr))
		}
		s.logger.Security.Warn("refresh denied; user disabled",
			zap.String("user_id", row.UserID.String()),
			zap.String("client_id", row.ClientID))
		writeTokenError(w, http.StatusUnauthorized, "invalid_grant",
			"User is disabled.")
		return
	}

	// Step 5: scope narrowing. If the request includes `scope=`, it
	// MUST be a subset of the original; otherwise reuse the
	// original. Refresh exchange MUST NOT widen scope (RFC 6749 §6).
	requestedScope := r.PostForm.Get("scope")
	effectiveScope := row.Scope
	if requestedScope != "" {
		if !isScopeSubset(requestedScope, row.Scope) {
			writeTokenError(w, http.StatusBadRequest, "invalid_scope",
				"Requested scope exceeds the original grant.")
			return
		}
		effectiveScope = requestedScope
	}

	// Step 6: resolve TTLs against live policy + per-client override.
	// We re-resolve every rotation so a tightened ceiling propagates
	// immediately — operators tweaking the testing knob mid-flow get
	// what they expect.
	ttls, err := s.resolveTokenTTLs(r.Context(), client)
	if err != nil {
		s.logger.App.Error("refresh: resolve TTLs", zap.Error(err))
		writeTokenError(w, http.StatusInternalServerError, "server_error",
			"Could not resolve token lifetimes.")
		return
	}

	// Step 7: mint new pair + persist rotation atomically. The repo's
	// Rotate is a transaction: consume parent + insert child. If
	// concurrent rotation hits the same parent, exactly one wins;
	// the loser sees ErrRefreshTokenInvalid and we surface as
	// invalid_grant.
	cfg := s.config.GetConfig()
	mintIn := oauth.MintInput{
		Issuer:    cfg.OAuth.Issuer,
		Subject:   row.UserID.String(),
		Audience:  client.ClientID,
		IssuedAt:  now,
		ExpiresIn: ttls.Access,
	}
	newAccess, err := oauth.MintAccessToken(keyStore, mintIn, effectiveScope, string(user.UserType))
	if err != nil {
		s.logger.App.Error("refresh: mint access token", zap.Error(err))
		writeTokenError(w, http.StatusInternalServerError, "server_error",
			"Could not mint access token.")
		return
	}
	newRaw, newHash, err := oauth.MintRefreshTokenValue()
	if err != nil {
		s.logger.App.Error("refresh: mint refresh value", zap.Error(err))
		writeTokenError(w, http.StatusInternalServerError, "server_error",
			"Could not mint refresh token.")
		return
	}
	// Carry forward the (possibly narrowed) scope onto the new RT
	// row — narrowing is permanent within a chain, callers can't
	// re-widen on a subsequent refresh.
	parent := *row
	parent.Scope = effectiveScope
	child, err := rtRepo.Rotate(r.Context(), &parent, newHash, now, ttls.RefreshSliding)
	if err != nil {
		if errors.Is(err, repository.ErrRefreshTokenInvalid) {
			// Race: the parent got consumed between FindForExchange
			// and Rotate. From the caller's perspective this is the
			// same as any other "invalid" refresh token.
			writeTokenError(w, http.StatusBadRequest, "invalid_grant",
				"Refresh token is invalid or expired.")
			return
		}
		s.logger.App.Error("refresh: rotate", zap.Error(err))
		writeTokenError(w, http.StatusInternalServerError, "server_error",
			"Could not persist refresh-token rotation.")
		return
	}

	resp := map[string]any{
		"access_token":             newAccess,
		"token_type":               "Bearer",
		"expires_in":               int(ttls.Access.Seconds()),
		"refresh_token":            newRaw,
		"refresh_token_expires_in": int(ttls.RefreshSliding.Seconds()),
		"scope":                    effectiveScope,
	}

	s.logger.Security.Info("refresh token rotated",
		zap.String("chain_id", child.ChainID.String()),
		zap.String("client_id", client.ClientID),
		zap.String("user_id", row.UserID.String()),
		zap.String("old_token_id", row.ID.String()),
		zap.String("new_token_id", child.ID.String()))

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(resp)
}

// resolveTokenTTLs reads the tenant policy ceiling row and the
// client's override values, then runs the pure resolution function
// in pkg/oauth. Used by both the auth-code branch and the
// refresh-grant branch of /token, so a per-client override applies
// to BOTH initial issuance and rotation.
//
// Pulled out as a method on Server so tests can stub it via
// dependency injection if needed; today it just reads from the
// wired DB + policy service.
func (s *Server) resolveTokenTTLs(ctx context.Context, client *models.ClientService) (oauth.TokenTTLPolicy, error) {
	s.mu.RLock()
	policySvc := s.policySvc
	s.mu.RUnlock()
	if policySvc == nil {
		return oauth.TokenTTLPolicy{}, errors.New("policy service not wired")
	}
	pol, err := policySvc.Get(ctx)
	if err != nil {
		return oauth.TokenTTLPolicy{}, err
	}
	return oauth.ResolveTokenTTLs(oauth.TokenTTLInputs{
		CeilingAccessSeconds:           pol.AccessTokenTTLSeconds,
		CeilingRefreshSlidingSeconds:   pol.RefreshTokenSlidingTTLSeconds,
		CeilingRefreshAbsoluteSeconds:  pol.RefreshTokenAbsoluteTTLSeconds,
		OverrideAccessSeconds:          client.AccessTokenTTLSecondsOverride,
		OverrideRefreshSlidingSeconds:  client.RefreshTokenSlidingTTLSecondsOverride,
		OverrideRefreshAbsoluteSeconds: client.RefreshTokenAbsoluteTTLSecondsOverride,
	}), nil
}

// isScopeSubset reports whether every space-separated scope token
// in `requested` also appears in `granted`. Used by refresh-grant
// to enforce the "may narrow but not widen" rule from RFC 6749 §6.
//
// Whitespace-tolerant: extra spaces or tabs in either string are
// ignored. Empty `requested` returns true (callers handle the
// empty-string case as "use the original" before calling this).
func isScopeSubset(requested, granted string) bool {
	want := scopeSet(requested)
	have := scopeSet(granted)
	for s := range want {
		if _, ok := have[s]; !ok {
			return false
		}
	}
	return true
}

func scopeSet(s string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, tok := range strings.Fields(s) {
		out[tok] = struct{}{}
	}
	return out
}
