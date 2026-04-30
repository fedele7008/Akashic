package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"akashic/akashic/pkg/auth"
	"akashic/akashic/pkg/userregistration"

	"go.uber.org/zap"
)

// Auth-server-hosted self-service registration. Mirrors the
// /login + /login/submit pair: GET /signup serves the form, POST
// /signup/submit validates + creates the user. On success, the user
// is redirected to /login with their username pre-filled and the
// original return_to preserved — they finish authentication on the
// next screen, which resumes whatever OAuth flow they came from.
//
// Why hosted on the auth server (not delegated to the tenant portal):
// the very first user-creation use case (the tenant operator setting
// up their own portal) shouldn't require pre-existing portal
// infrastructure. Auth-server-hosted /signup gives every deployment
// a working signup flow out of the box.

// handleSignupPage serves GET /signup.
//
// Same return_to semantics as /login: the caller (typically a redirect
// from /login's "Create account" link) passes through the OAuth
// /authorize URL so the user resumes that flow after sign-in.
func (s *Server) handleSignupPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.bootstrapBlocked(r.Context()) {
		s.renderBootstrapPending(w)
		return
	}

	csrf := s.ensureLoginCSRF(w, r)
	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))

	renderTemplate(w, "signup.html.tmpl", http.StatusOK, s.signupTemplateData(map[string]any{
		"CSRFToken":   csrf,
		"ReturnTo":    returnTo,
		"Username":    "",
		"Email":       "",
		"DisplayName": "",
		"Error":       "",
	}))
}

// signupTemplateData augments per-render data with the shared,
// dynamically-derived fields. PolicyHint is a one-line description
// of the operator-configured password policy, surfaced above the
// form so users see the rules before typing.
func (s *Server) signupTemplateData(extra map[string]any) map[string]any {
	extra["PolicyHint"] = passwordPolicyHint(s.passwordPolicy())
	return extra
}

// passwordPolicy reads the operator-configured policy from akashic
// config. Mirrors api-server's policyFromConfig() — same shape, same
// "RequireLowercase always-true" invariant. Could be extracted into
// the auth package itself in a future cleanup.
func (s *Server) passwordPolicy() *auth.PasswordPolicy {
	cfg := s.config.GetConfig().Bootstrap.Password
	return &auth.PasswordPolicy{
		MinLength:        cfg.MinLength,
		RequireUppercase: cfg.RequireUppercase,
		RequireLowercase: true,
		RequireNumber:    cfg.RequireNumber,
		RequireSpecial:   cfg.RequireSpecial,
	}
}

// passwordPolicyHint formats a policy as a single-line natural-
// language hint. Matches the format the <akashic-signup> widget
// renders client-side, so the auth-server-hosted UI and widget-
// hosted UI describe the rules the same way.
func passwordPolicyHint(p *auth.PasswordPolicy) string {
	parts := []string{fmt.Sprintf("At least %d characters", p.MinLength)}
	required := []string{}
	if p.RequireUppercase {
		required = append(required, "uppercase")
	}
	if p.RequireLowercase {
		required = append(required, "lowercase")
	}
	if p.RequireNumber {
		required = append(required, "number")
	}
	if p.RequireSpecial {
		required = append(required, "special character")
	}
	if len(required) > 0 {
		parts = append(parts, "with "+strings.Join(required, ", "))
	}
	return "Password requirements: " + strings.Join(parts, " ") + "."
}

// handleSignupSubmit serves POST /signup/submit.
//
// Validation flow mirrors the /login/submit handler: CSRF first, then
// form parsing, then domain logic via the shared userregistration
// package. On success, redirect to /login (with username pre-filled
// + the original return_to preserved) so the user signs in to
// complete their OAuth round-trip.
func (s *Server) handleSignupSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.bootstrapBlocked(r.Context()) {
		s.renderBootstrapPending(w)
		return
	}

	if err := r.ParseForm(); err != nil {
		s.renderSignupError(w, r, "Could not parse the form. Please retry.", "", "", "")
		return
	}
	if !s.verifyLoginCSRF(r) {
		// `verifyLoginCSRF` returns false on any failure (no cookie,
		// no field, mismatch). Sharing the helper with /login/submit
		// keeps both flows on the same double-submit pattern.
		s.renderSignupError(w, r, "Form expired. Please retry.", "", "", "")
		return
	}

	username := strings.TrimSpace(r.PostForm.Get("username"))
	email := strings.TrimSpace(r.PostForm.Get("email"))
	displayName := strings.TrimSpace(r.PostForm.Get("display_name"))
	password := r.PostForm.Get("password")
	passwordConfirm := r.PostForm.Get("password_confirm")
	returnTo := safeReturnTo(r.PostForm.Get("return_to"))

	if password != passwordConfirm {
		s.renderSignupError(w, r, "Passwords don't match.", username, email, displayName)
		return
	}

	user, err := userregistration.Register(r.Context(), userregistration.Deps{
		LDAP:     s.authService.LDAPClient(),
		UserRepo: s.authService.UserRepository(),
		Policy:   s.passwordPolicy(),
	}, userregistration.Params{
		Username:    username,
		Email:       email,
		Password:    password,
		DisplayName: displayName,
	})
	switch {
	case errors.Is(err, userregistration.ErrFieldRequired):
		s.renderSignupError(w, r,
			"Username, email, and password are all required.",
			username, email, displayName)
		return
	case errors.Is(err, userregistration.ErrEmailInvalid):
		s.renderSignupError(w, r,
			"That doesn't look like a valid email address.",
			username, email, displayName)
		return
	case errors.Is(err, userregistration.ErrPasswordPolicyViolated):
		// Pull the policy detail out of the wrapped error for a
		// specific message. Wrap layout: "<sentinel>: <detail>".
		detail := strings.TrimPrefix(err.Error(),
			"password does not satisfy the policy: ")
		s.renderSignupError(w, r, detail, username, email, displayName)
		return
	case errors.Is(err, userregistration.ErrUsernameTaken):
		s.renderSignupError(w, r,
			"That username is already taken. Try another.",
			"", email, displayName)
		return
	case err != nil:
		s.logger.App.Error("signup: userregistration.Register",
			zap.String("username", username), zap.Error(err))
		s.renderSignupError(w, r,
			"Something went wrong creating your account. Please try again.",
			username, email, displayName)
		return
	}

	s.logger.Security.Info("user registered (auth-server self-service)",
		zap.String("user_id", user.ID.String()),
		zap.String("username", username),
		zap.String("ldap_dn", user.LdapDN))

	// Success: redirect to /login with the username pre-filled and
	// the original return_to preserved. The user's next action
	// (typing password + clicking Sign in) finishes the OAuth flow.
	loginURL := "/login"
	q := url.Values{}
	q.Set("username", username)
	if returnTo != "" {
		q.Set("return_to", returnTo)
	}
	http.Redirect(w, r, loginURL+"?"+q.Encode(), http.StatusSeeOther)
}

// renderSignupError re-renders the signup form with an inline error
// message and the user's typed fields preserved (so they don't lose
// what they entered when fixing one bad field).
func (s *Server) renderSignupError(w http.ResponseWriter, r *http.Request,
	msg, username, email, displayName string) {
	csrf := s.ensureLoginCSRF(w, r)
	returnTo := ""
	if r.PostForm != nil {
		returnTo = safeReturnTo(r.PostForm.Get("return_to"))
	}
	renderTemplate(w, "signup.html.tmpl", http.StatusOK, s.signupTemplateData(map[string]any{
		"CSRFToken":   csrf,
		"ReturnTo":    returnTo,
		"Username":    username,
		"Email":       email,
		"DisplayName": displayName,
		"Error":       msg,
	}))
}

