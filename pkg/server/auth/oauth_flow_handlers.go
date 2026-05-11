package auth

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"akashic/akashic/pkg/consent"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/oauth"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// /authorize, /token, /userinfo — the three core OAuth flow endpoints.
//
// Discovery and JWKS live in oauth_handlers.go; login UI lives in
// login_handlers.go. This file is just the flow itself, with the
// validation + minting logic broken out per RFC 6749 / 7636 / OIDC
// Core spec sections.

// ─── /authorize ────────────────────────────────────────────────────

// handleAuthorize implements GET /authorize per RFC 6749 §4.1.1.
//
// Flow:
//   1. Validate query params (response_type, client_id, redirect_uri,
//      code_challenge, scope, state)
//   2. Look up client; verify redirect_uri exact-match
//   3. Check session cookie. No session → redirect to /login with
//      return_to set so we re-enter here after successful auth
//   4. Generate authorization code, store binding in Redis
//   5. 302 to redirect_uri?code=...&state=...
//
// Error handling distinguishes:
//   - Errors BEFORE redirect_uri is validated → render /error
//     (we can't trust the supplied redirect_uri yet)
//   - Errors AFTER redirect_uri is validated → redirect to it with
//     ?error=... per the spec
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()

	// Required params per RFC 6749 §4.1.1
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	scope := q.Get("scope")
	state := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	nonce := q.Get("nonce") // optional, OIDC

	// Up-front sanity checks for params we need to validate the
	// redirect_uri itself.
	if clientID == "" || redirectURI == "" {
		s.renderAuthorizeError(w, http.StatusBadRequest,
			"Invalid request",
			"client_id and redirect_uri are required.")
		return
	}

	// Look up client and validate redirect_uri exact match BEFORE
	// any other checks. RFC 6749 §3.1.2.4: if redirect_uri doesn't
	// match, MUST NOT redirect to it (could be attacker-controlled).
	s.mu.RLock()
	db := s.db
	s.mu.RUnlock()
	if db == nil {
		s.renderAuthorizeError(w, http.StatusServiceUnavailable,
			"OAuth not ready",
			"The auth server is not yet fully initialized. Please retry shortly.")
		return
	}

	var client models.ClientService
	err := db.WithContext(r.Context()).Where("client_id = ?", clientID).First(&client).Error
	if err == gorm.ErrRecordNotFound {
		s.renderAuthorizeError(w, http.StatusBadRequest,
			"Unknown client",
			"The client_id is not registered with this Akashic deployment.")
		return
	}
	if err != nil {
		s.logger.App.Error("authorize: client lookup failed", zap.Error(err))
		s.renderAuthorizeError(w, http.StatusInternalServerError,
			"Server error", "Could not validate the client. Please retry.")
		return
	}

	if !redirectURIAllowed(redirectURI, client.RedirectURIs) {
		s.logger.Security.Warn("authorize: redirect_uri mismatch",
			zap.String("client_id", clientID),
			zap.String("requested", redirectURI),
			zap.String("allowed", client.RedirectURIs))
		s.renderAuthorizeError(w, http.StatusBadRequest,
			"Redirect mismatch",
			"The redirect_uri does not match any registered for this client.")
		return
	}

	// From here on, we have a validated redirect_uri. OAuth-spec
	// errors get redirected with ?error=... so the client's UI can
	// surface them.

	if responseType != "code" {
		redirectWithError(w, r, redirectURI, state,
			"unsupported_response_type",
			"Only response_type=code is supported.")
		return
	}

	// Scope validation: every requested scope must be in the client's
	// allowlist. Empty scope is allowed (treated as default).
	if scope != "" && !scopesPermitted(scope, client.AllowedScopes) {
		redirectWithError(w, r, redirectURI, state,
			"invalid_scope",
			"Requested scope is not permitted for this client.")
		return
	}
	if scope == "" {
		scope = "openid"
	}
	// Phase C: auto-include the client's RequiredScopes if any are
	// missing from the request. The client owner declared these as
	// mandatory at registration time; the consent screen will lock
	// their checkboxes so the user must grant them. Auto-adding
	// here keeps sloppy client SDKs working — they'd otherwise need
	// to list every required scope explicitly to avoid silently
	// missing them. Legacy rows where RequiredScopes is empty fall
	// back to the legacy AllowedScopes (everything required) per
	// `oauth.EffectiveRequiredScopes`.
	effectiveRequired := oauth.EffectiveRequiredScopes(client.RequiredScopes, client.AllowedScopes)
	scope = oauth.UnionScopes(scope, effectiveRequired)

	// Grant-type check: the client must be authorized to use
	// authorization_code (its AuthTypes column must include it).
	if !grantTypeAllowed(client.AuthTypes, string(models.AuthTypeAuthorizationCode)) {
		redirectWithError(w, r, redirectURI, state,
			"unauthorized_client",
			"This client is not authorized to use the authorization_code grant.")
		return
	}

	// PKCE gating depends on the client's RequirePKCE flag:
	//   - Public clients (SPA/native) and built-ins: RequirePKCE is
	//     always true; code_challenge is mandatory. RFC 7636 §4.4 +
	//     OAuth 2.1 mandate this.
	//   - Confidential clients (BFF/server-side): RequirePKCE is
	//     operator-configurable. When false, code_challenge is
	//     optional but, if supplied, MUST still be S256 + valid —
	//     a half-broken PKCE attempt would be a sign of misconfig
	//     rather than something to silently ignore.
	if codeChallenge == "" {
		if client.RequirePKCE {
			redirectWithError(w, r, redirectURI, state,
				"invalid_request",
				"code_challenge is required (PKCE).")
			return
		}
		// PKCE not required and not supplied — skip method/format
		// validation entirely.
	} else {
		if codeChallengeMethod == "" {
			codeChallengeMethod = "plain" // explicit so we reject below
		}
		if codeChallengeMethod != oauth.PKCEMethodS256 {
			redirectWithError(w, r, redirectURI, state,
				"invalid_request",
				"Only S256 code_challenge_method is supported.")
			return
		}
		if err := oauth.ValidateChallenge(codeChallenge); err != nil {
			redirectWithError(w, r, redirectURI, state,
				"invalid_request",
				"code_challenge is malformed.")
			return
		}
	}

	// Session check. No session → /login with return_to = this URL.
	s.mu.RLock()
	sessionStore := s.sessionStore
	codeStore := s.codeStore
	s.mu.RUnlock()
	if sessionStore == nil || codeStore == nil {
		s.renderAuthorizeError(w, http.StatusServiceUnavailable,
			"OAuth not ready",
			"The auth server is not yet fully initialized. Please retry shortly.")
		return
	}

	sid := readCookie(r, authSessionCookie)
	if sid == "" {
		s.redirectToLogin(w, r)
		return
	}
	sess, err := sessionStore.Touch(r.Context(), sid)
	if err != nil {
		// Session expired, idle-timed-out, or otherwise gone. Send
		// the user to /login again.
		s.redirectToLogin(w, r)
		return
	}

	// Phase 9d: forced-reset gate. A partial session can't drive
	// /authorize; bounce to the reset page preserving the full
	// /authorize URL as return_to so the user lands back on the
	// OAuth flow once they finish picking a new password.
	if sess.ResetRequired {
		http.Redirect(w, r,
			forcedResetURLWithReturnTo(r.URL.RequestURI(), ""),
			http.StatusSeeOther)
		return
	}

	// Phase 9f: MFA-pending gate. Same shape as the forced-reset
	// gate above — a session in MFAPending state can't yet authorize.
	// Bounce to /login/mfa, which has its own returnTo embedded in
	// the partial session's PendingReturnTo, so we don't need to
	// re-thread it here.
	if sess.MFAPending {
		http.Redirect(w, r, mfaURLWithReturnTo(""), http.StatusSeeOther)
		return
	}

	// Phase 7: consent gate. Built-ins and first-party clients
	// (IsTenantPortal=true) skip; everyone else is prompted unless
	// the user has previously granted these scopes (or a superset).
	// On approval, /consent/submit redirects back here, the gate
	// re-evaluates, and the second pass mints the code as normal.
	userID, parseErr := uuid.Parse(sess.UserID)
	if parseErr != nil {
		// Session row had a malformed user_id. Shouldn't happen,
		// but if it does we'd loop forever in /consent. Fail the
		// flow visibly.
		s.logger.App.Error("authorize: malformed session user_id",
			zap.String("sid", sid), zap.String("user_id", sess.UserID))
		redirectWithError(w, r, redirectURI, state,
			"server_error", "Session is in an inconsistent state.")
		return
	}
	decision := consent.Required(r.Context(), s.consentRepo, &client, userID, scope)
	if decision.Required {
		s.logger.Security.Info("consent prompt required",
			zap.String("client_id", clientID),
			zap.String("user_id", sess.UserID),
			zap.String("scope", scope),
			zap.String("reason", decision.Reason))
		s.redirectToConsent(w, r)
		return
	}

	// Mint authorization code.
	code, err := codeStore.Generate(r.Context(), &oauth.AuthorizationCode{
		ClientID:            clientID,
		UserID:              sess.UserID,
		LDAPDN:              sess.LDAPDN,
		RedirectURI:         redirectURI,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Nonce:               nonce,
		SessionID:           sid,
		UserType:            sess.UserType,
		Username:            sess.Username,
		Email:               sess.Email,
	})
	if err != nil {
		s.logger.App.Error("generate auth code", zap.Error(err))
		redirectWithError(w, r, redirectURI, state,
			"server_error", "Could not issue authorization code.")
		return
	}

	s.logger.Security.Info("authorization code issued",
		zap.String("client_id", clientID),
		zap.String("user_id", sess.UserID),
		zap.String("scope", scope))

	// Redirect with code + state.
	finalURL, _ := url.Parse(redirectURI)
	qs := finalURL.Query()
	qs.Set("code", code)
	if state != "" {
		qs.Set("state", state)
	}
	finalURL.RawQuery = qs.Encode()
	http.Redirect(w, r, finalURL.String(), http.StatusFound)
}

// renderAuthorizeError renders the error.html.tmpl page. Used for
// errors that occur BEFORE we've validated the redirect_uri — at
// that point we can't trust the supplied URI and must keep the user
// on the auth server.
func (s *Server) renderAuthorizeError(w http.ResponseWriter, status int, title, msg string) {
	renderTemplate(w, "error.html.tmpl", status, map[string]any{
		"Title":   title,
		"Message": msg,
		"Detail":  "",
	})
}

// redirectWithError sends the OAuth-spec error redirect (RFC 6749
// §4.1.2.1) — used after redirect_uri is validated. The client's
// UI then displays the error.
func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	qs := u.Query()
	qs.Set("error", code)
	qs.Set("error_description", description)
	if state != "" {
		qs.Set("state", state)
	}
	u.RawQuery = qs.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// redirectToLogin sends the user to /login with return_to set so the
// auth flow resumes after credentials are verified.
func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	loginURL := "/login?return_to=" + url.QueryEscape(r.URL.RequestURI())
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// redirectToConsent sends the user to /consent with return_to set
// to the original /authorize URL. After Approve, /consent/submit
// redirects back here; the consent gate re-evaluates and now finds
// a stored grant, so the flow proceeds to code mint normally.
//
// Phase 7. Same return_to pattern /login uses — the consent page
// doesn't need to know the full OAuth state, just where to bounce
// back to.
func (s *Server) redirectToConsent(w http.ResponseWriter, r *http.Request) {
	consentURL := "/consent?return_to=" + url.QueryEscape(r.URL.RequestURI())
	http.Redirect(w, r, consentURL, http.StatusFound)
}

// redirectURIAllowed performs exact-string comparison per RFC 6749 §3.1.2.
// allowedCSV is comma-separated; trims whitespace around each entry.
func redirectURIAllowed(requested, allowedCSV string) bool {
	for _, allowed := range strings.Split(allowedCSV, ",") {
		if strings.TrimSpace(allowed) == requested {
			return true
		}
	}
	return false
}

// scopesPermitted checks every requested scope is in the allowlist.
// Both args are space-separated.
func scopesPermitted(requested, allowed string) bool {
	allow := map[string]bool{}
	for _, s := range strings.Fields(allowed) {
		allow[s] = true
	}
	for _, s := range strings.Fields(requested) {
		if !allow[s] {
			return false
		}
	}
	return true
}

// grantTypeAllowed checks if `grant` is in the client's space-separated
// AuthTypes list.
func grantTypeAllowed(authTypesCSV, grant string) bool {
	for _, g := range strings.Fields(authTypesCSV) {
		if g == grant {
			return true
		}
	}
	return false
}

// ─── /token ────────────────────────────────────────────────────────

// handleToken implements POST /token per RFC 6749 §4.1.3.
//
// Steps:
//   1. Authenticate client (Basic auth header OR form params)
//   2. Validate grant_type=authorization_code
//   3. Look up + atomically consume the code from Redis
//   4. Verify code's bound client_id == authenticated client_id
//   5. Verify code's bound redirect_uri == request's redirect_uri
//   6. Verify PKCE: SHA256(code_verifier) == stored code_challenge
//   7. Verify user is still enabled (catches mid-flow disable)
//   8. Mint access + ID tokens
//   9. Return token response JSON
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request",
			"Could not parse request body.")
		return
	}

	// Step 1: client authentication
	clientID, clientSecret, ok := getClientCredentials(r)
	if !ok {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client",
			"Client credentials are missing or malformed.")
		return
	}

	s.mu.RLock()
	db := s.db
	codeStore := s.codeStore
	keyStore := s.oauthKeyStore
	s.mu.RUnlock()
	if db == nil || codeStore == nil || keyStore == nil {
		writeTokenError(w, http.StatusServiceUnavailable, "server_error",
			"Auth server not yet fully initialized.")
		return
	}

	var client models.ClientService
	err := db.WithContext(r.Context()).Where("client_id = ?", clientID).First(&client).Error
	if err == gorm.ErrRecordNotFound {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client",
			"Unknown client.")
		return
	}
	if err != nil {
		s.logger.App.Error("token: client lookup", zap.Error(err))
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Lookup failed.")
		return
	}
	// Public client (no stored secret) — only allowed when PKCE is
	// required, because the code_verifier check that runs later
	// provides the proof-of-legitimacy that client_secret would have.
	// Standard SPA OAuth pattern (RFC 7636). Dispatches on the
	// explicit Public flag rather than hash-empty so that a future
	// auth method that authenticates without a stored secret (mTLS,
	// JWT bearer assertion) doesn't accidentally fall into this
	// branch.
	if client.Public {
		if !client.RequirePKCE {
			s.logger.Security.Warn("token: public client without PKCE requirement — refusing",
				zap.String("client_id", clientID))
			writeTokenError(w, http.StatusUnauthorized, "invalid_client",
				"Public clients must require PKCE.")
			return
		}
		// No secret check; the code_verifier validation below is the auth.
	} else {
		if bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(clientSecret)) != nil {
			s.logger.Security.Warn("token: bad client secret", zap.String("client_id", clientID))
			writeTokenError(w, http.StatusUnauthorized, "invalid_client",
				"Client authentication failed.")
			return
		}
	}

	// Step 2: grant_type
	grant := r.PostForm.Get("grant_type")
	switch grant {
	case "authorization_code":
		if !grantTypeAllowed(client.AuthTypes, grant) {
			writeTokenError(w, http.StatusBadRequest, "unauthorized_client",
				"Client not authorized for this grant_type.")
			return
		}
	case "refresh_token":
		// Refresh tokens fall under the same client-allowed-grants
		// gate as authorization_code — issuing a refresh token at
		// auth-code time only made sense for clients allowed to use
		// the auth-code grant in the first place, so the rotation
		// path mirrors that authorization. We don't require operators
		// to add a separate "refresh_token" entry to AuthTypes.
		if !grantTypeAllowed(client.AuthTypes, "authorization_code") {
			writeTokenError(w, http.StatusBadRequest, "unauthorized_client",
				"Client not authorized for refresh-token grants.")
			return
		}
		s.handleRefreshGrant(w, r, &client)
		return
	default:
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type",
			"Only authorization_code and refresh_token are supported.")
		return
	}

	// Step 3: consume code
	code := r.PostForm.Get("code")
	if code == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "code is required.")
		return
	}
	authCode, err := codeStore.Consume(r.Context(), code)
	if err != nil {
		// Could be expired, never existed, or already consumed.
		// Spec says return invalid_grant for all of these — don't
		// distinguish (info leak prevention).
		writeTokenError(w, http.StatusBadRequest, "invalid_grant",
			"Authorization code is invalid or expired.")
		return
	}

	// Step 4: code's client_id == authenticated client_id
	if subtle.ConstantTimeCompare([]byte(authCode.ClientID), []byte(clientID)) != 1 {
		s.logger.Security.Warn("token: code/client mismatch",
			zap.String("code_client", authCode.ClientID),
			zap.String("auth_client", clientID))
		writeTokenError(w, http.StatusBadRequest, "invalid_grant",
			"Code was not issued for this client.")
		return
	}

	// Step 5: redirect_uri match
	requestedRedirect := r.PostForm.Get("redirect_uri")
	if requestedRedirect != authCode.RedirectURI {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant",
			"redirect_uri mismatch.")
		return
	}

	// Step 6: PKCE
	//
	// PKCE on the token side mirrors the /authorize gate: required iff
	// a challenge was actually stored alongside the auth code. Cases:
	//   - challenge stored, verifier supplied → must match (current path).
	//   - challenge stored, verifier missing  → 400 (the client started
	//     a PKCE flow and is now trying to skip the proof).
	//   - no challenge stored, verifier missing → fine (BFF non-PKCE).
	//   - no challenge stored, verifier supplied → 400 (sender has a
	//     verifier without anything to verify against — almost
	//     certainly a misconfig or attempted downgrade).
	verifier := r.PostForm.Get("code_verifier")
	if authCode.CodeChallenge == "" {
		if verifier != "" {
			s.logger.Security.Warn("token: code_verifier supplied for non-PKCE code",
				zap.String("client_id", clientID))
			writeTokenError(w, http.StatusBadRequest, "invalid_request",
				"code_verifier supplied but no PKCE challenge was bound to this code.")
			return
		}
		// No PKCE was used; nothing to verify. Fall through.
	} else if verifier == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request",
			"code_verifier is required.")
		return
	} else if err := oauth.VerifyChallenge(verifier, authCode.CodeChallenge); err != nil {
		s.logger.Security.Warn("token: PKCE mismatch",
			zap.String("client_id", clientID))
		writeTokenError(w, http.StatusBadRequest, "invalid_grant",
			"PKCE verification failed.")
		return
	}

	// Step 7: user still enabled
	var user models.User
	err = db.WithContext(r.Context()).Where("id = ?", authCode.UserID).First(&user).Error
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant",
			"User no longer exists.")
		return
	}
	if user.IsDisabled {
		s.logger.Security.Warn("token: user disabled",
			zap.String("user_id", authCode.UserID))
		writeTokenError(w, http.StatusUnauthorized, "invalid_grant",
			"User is disabled.")
		return
	}

	// Step 8: resolve TTLs (per-client overrides clamped to tenant
	// ceilings, see pkg/oauth/refresh.go for the resolution rule).
	ttls, err := s.resolveTokenTTLs(r.Context(), &client)
	if err != nil {
		s.logger.App.Error("token: resolve TTLs", zap.Error(err))
		writeTokenError(w, http.StatusInternalServerError, "server_error",
			"Could not resolve token lifetimes.")
		return
	}
	cfg := s.config.GetConfig()
	now := time.Now().UTC()

	mintIn := oauth.MintInput{
		Issuer:    cfg.OAuth.Issuer,
		Subject:   authCode.UserID,
		Audience:  clientID,
		IssuedAt:  now,
		ExpiresIn: ttls.Access,
	}

	accessToken, err := oauth.MintAccessToken(keyStore, mintIn, authCode.Scope, authCode.UserType)
	if err != nil {
		s.logger.App.Error("mint access token", zap.Error(err))
		writeTokenError(w, http.StatusInternalServerError, "server_error",
			"Could not mint access token.")
		return
	}

	resp := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(ttls.Access.Seconds()),
		"scope":        authCode.Scope,
	}

	// Refresh-token issuance (Phase 9 prep): only when the auth code
	// carried `offline_access` AND the refresh-token repo is wired.
	// Without the scope we're an OAuth 2.0 access-token-only flow;
	// without the repo we treat the scope as a no-op.
	if scopeIncludes(authCode.Scope, oauth.RefreshScopeOfflineAccess) {
		s.mu.RLock()
		rtRepo := s.refreshTokenRepo
		s.mu.RUnlock()
		if rtRepo != nil {
			rawRT, hash, err := oauth.MintRefreshTokenValue()
			if err != nil {
				s.logger.App.Error("mint refresh token", zap.Error(err))
				writeTokenError(w, http.StatusInternalServerError, "server_error",
					"Could not mint refresh token.")
				return
			}
			userUUID, perr := uuid.Parse(authCode.UserID)
			if perr != nil {
				// authCode.UserID came from the session; it's already
				// a parsed-and-formatted UUID upstream. Treat any
				// failure here as a server-error (don't expose to the
				// caller).
				s.logger.App.Error("token: parse user uuid for RT",
					zap.String("raw", authCode.UserID), zap.Error(perr))
				writeTokenError(w, http.StatusInternalServerError, "server_error",
					"Could not persist refresh token.")
				return
			}
			row, err := rtRepo.CreateInitial(r.Context(), hash, userUUID,
				clientID, authCode.Scope, now, ttls.RefreshSliding, ttls.RefreshAbsolute)
			if err != nil {
				s.logger.App.Error("token: persist initial refresh token", zap.Error(err))
				writeTokenError(w, http.StatusInternalServerError, "server_error",
					"Could not persist refresh token.")
				return
			}
			resp["refresh_token"] = rawRT
			resp["refresh_token_expires_in"] = int(ttls.RefreshSliding.Seconds())
			s.logger.Security.Info("refresh token issued (initial)",
				zap.String("client_id", clientID),
				zap.String("user_id", authCode.UserID),
				zap.String("chain_id", row.ChainID.String()))
		}
	}

	// ID token if openid scope was granted (OIDC core §3.1.3.3)
	if scopeIncludes(authCode.Scope, "openid") {
		idIn := oauth.IDTokenInput{
			MintInput: oauth.MintInput{
				Issuer:    cfg.OAuth.Issuer,
				Subject:   authCode.UserID,
				Audience:  clientID,
				IssuedAt:  now,
				ExpiresIn: cfg.OAuth.IDTokenTTL,
			},
			Nonce:    authCode.Nonce,
			UserType: authCode.UserType,
		}
		// profile/email scopes add the corresponding claims. The auth
		// code carries snapshot values from /authorize time; we use
		// those rather than re-fetching LDAP on the token-mint hot
		// path. See AuthorizationCode.Username/Email for the
		// captured-at-login rationale.
		if scopeIncludes(authCode.Scope, "profile") {
			username := authCode.Username
			if username == "" {
				// Defensive: a code minted before this field was
				// added (e.g. an in-flight code spanning a deploy)
				// won't have it. Derive from DN as a fallback.
				username = deriveUsernameFromDN(authCode.LDAPDN)
			}
			idIn.PreferredUsername = username
			idIn.Name = username
		}
		if scopeIncludes(authCode.Scope, "email") {
			idIn.Email = authCode.Email
		}
		idToken, err := oauth.MintIDToken(keyStore, idIn)
		if err != nil {
			s.logger.App.Error("mint id token", zap.Error(err))
			writeTokenError(w, http.StatusInternalServerError, "server_error",
				"Could not mint ID token.")
			return
		}
		resp["id_token"] = idToken
	}

	s.logger.Security.Info("token issued",
		zap.String("client_id", clientID),
		zap.String("user_id", authCode.UserID),
		zap.String("scope", authCode.Scope))

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(resp)
}

// scopeIncludes returns true if a space-separated scope string
// includes the given scope.
func scopeIncludes(scopes, target string) bool {
	for _, s := range strings.Fields(scopes) {
		if s == target {
			return true
		}
	}
	return false
}

// getClientCredentials extracts client_id and client_secret from
// either the Authorization: Basic header (RFC 6749 §2.3.1, the
// recommended form) or POST body params (also permitted, less
// preferred). Returns empty strings + false if neither is present.
func getClientCredentials(r *http.Request) (string, string, bool) {
	if id, secret, ok := r.BasicAuth(); ok {
		return id, secret, true
	}
	id := r.PostForm.Get("client_id")
	secret := r.PostForm.Get("client_secret")
	if id == "" {
		return "", "", false
	}
	return id, secret, true
}

// writeTokenError emits the standard OAuth /token error envelope
// (RFC 6749 §5.2): {error: ..., error_description: ...}.
func writeTokenError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// ─── /userinfo ─────────────────────────────────────────────────────

// handleUserInfo implements GET /userinfo per OIDC core §5.3.
//
// Verifies the bearer token, looks up the user, returns claims
// filtered by the token's scope. Used by clients that want to
// confirm a token is still valid (e.g., the admin-bff calls this
// to verify the user's session is still active).
func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tokenStr, ok := bearerToken(r)
	if !ok {
		writeUserInfoError(w, http.StatusUnauthorized, "invalid_token",
			"Bearer token missing or malformed.")
		return
	}

	s.mu.RLock()
	db := s.db
	keyStore := s.oauthKeyStore
	s.mu.RUnlock()
	if db == nil || keyStore == nil {
		writeUserInfoError(w, http.StatusServiceUnavailable, "server_error",
			"Auth server not yet ready.")
		return
	}

	claims, err := oauth.VerifyAccessToken(keyStore, tokenStr, "")
	if err != nil {
		writeUserInfoError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}

	var user models.User
	if err := db.WithContext(r.Context()).Where("id = ?", claims.Subject).First(&user).Error; err != nil {
		writeUserInfoError(w, http.StatusUnauthorized, "invalid_token",
			"User no longer exists.")
		return
	}
	if user.IsDisabled {
		writeUserInfoError(w, http.StatusUnauthorized, "invalid_token",
			"User is disabled.")
		return
	}

	resp := map[string]any{
		"sub":       user.ID.String(),
		"user_type": string(user.UserType),
	}
	scope := claims.Scope
	if scopeIncludes(scope, "profile") {
		resp["preferred_username"] = deriveUsernameFromDN(user.LdapDN)
		resp["name"] = resp["preferred_username"]
	}
	// email scope deferred to Phase 8 (needs LDAP fetch on the hot path)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	return strings.TrimSpace(h[len(prefix):]), true
}

func writeUserInfoError(w http.ResponseWriter, status int, code, description string) {
	// /userinfo errors go in WWW-Authenticate per RFC 6750 §3
	w.Header().Set("WWW-Authenticate",
		`Bearer error="`+code+`", error_description="`+description+`"`)
	w.WriteHeader(status)
}

// Compile-time check that errors-package import is needed
var _ = errors.New
