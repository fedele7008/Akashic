package auth

import (
	"context"
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
	if !s.signupEnabled(r.Context()) {
		s.renderSignupDisabled(w)
		return
	}

	csrf := s.ensureLoginCSRF(w, r)
	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))

	renderTemplate(w, "signup.html.tmpl", http.StatusOK, s.signupTemplateData(r.Context(), map[string]any{
		"CSRFToken":   csrf,
		"ReturnTo":    returnTo,
		"Username":    "",
		"Tag":         "",
		"Email":       "",
		"DisplayName": "",
		"Error":       "",
	}))
}

// signupEnabled returns whether the operator-configured policy
// allows self-service signup. Defaults to TRUE when the policy
// service isn't wired or the DB read fails — mirrors the
// "fail-open during transient outage" stance the bootstrapBlocked
// gate takes. Operators who genuinely want signup off MUST have
// the DB row reachable for the gate to bite.
func (s *Server) signupEnabled(ctx context.Context) bool {
	if s.policySvc == nil {
		return true
	}
	enabled, err := s.policySvc.SignupEnabled(ctx)
	if err != nil {
		return true
	}
	return enabled
}

// renderSignupDisabled serves a friendly 403 explaining that
// self-service signup has been disabled by the operator. Distinct
// from the bootstrap-pending page (different cause, different
// recovery — operator must re-enable in the admin UI).
func (s *Server) renderSignupDisabled(w http.ResponseWriter) {
	renderTemplate(w, "error.html.tmpl", http.StatusForbidden, map[string]any{
		"Title":   "Signup is disabled",
		"Message": "This deployment doesn't currently allow self-service signup.",
		"Detail":  "Contact your deployment operator to request an account.",
	})
}

// signupTemplateData augments per-render data with the shared,
// dynamically-derived fields. PolicyHint is a one-line description
// of the operator-configured password policy, surfaced above the
// form so users see the rules before typing.
func (s *Server) signupTemplateData(ctx context.Context, extra map[string]any) map[string]any {
	extra["PolicyHint"] = passwordPolicyHint(s.passwordPolicy(ctx))
	return extra
}

// passwordPolicy reads the active password policy. Phase 8c.6
// switched this from cfg-derived (YAML) to DB-backed: edits made
// through the admin web's Policy page take effect on the next
// request without a restart.
//
// Falls back to a hard-coded MinLength=8 + lowercase-required
// policy if the policy service isn't wired or the DB read fails
// — better to enforce SOMETHING than to silently accept any
// password during a transient outage.
func (s *Server) passwordPolicy(ctx context.Context) *auth.PasswordPolicy {
	if s.policySvc != nil {
		if p, err := s.policySvc.PasswordPolicy(ctx); err == nil {
			return p
		}
	}
	return &auth.PasswordPolicy{MinLength: 8, RequireLowercase: true}
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
	if !s.signupEnabled(r.Context()) {
		s.renderSignupDisabled(w)
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

	email := strings.TrimSpace(r.PostForm.Get("email"))
	displayName := strings.TrimSpace(r.PostForm.Get("display_name"))
	wantedID := strings.TrimSpace(r.PostForm.Get("username"))
	wantedTag := strings.TrimSpace(r.PostForm.Get("tag"))
	password := r.PostForm.Get("password")
	passwordConfirm := r.PostForm.Get("password_confirm")
	returnTo := safeReturnTo(r.PostForm.Get("return_to"))

	if password != passwordConfirm {
		s.renderSignupError(w, r, "Passwords don't match.", wantedID, email, displayName)
		return
	}

	user, err := userregistration.Register(r.Context(), userregistration.Deps{
		LDAP:     s.authService.LDAPClient(),
		UserRepo: s.authService.UserRepository(),
		Policy:   s.passwordPolicy(r.Context()),
	}, userregistration.Params{
		Email:       email,
		Password:    password,
		DisplayName: displayName,
		Username:    wantedID,
		Tag:         wantedTag,
	})
	switch {
	case errors.Is(err, userregistration.ErrFieldRequired):
		s.renderSignupError(w, r,
			"Email and password are required.",
			wantedID, email, displayName)
		return
	case errors.Is(err, userregistration.ErrEmailInvalid):
		s.renderSignupError(w, r,
			"That doesn't look like a valid email address.",
			wantedID, email, displayName)
		return
	case errors.Is(err, userregistration.ErrPasswordPolicyViolated):
		// Pull the policy detail out of the wrapped error for a
		// specific message. Wrap layout: "<sentinel>: <detail>".
		detail := strings.TrimPrefix(err.Error(),
			"password does not satisfy the policy: ")
		s.renderSignupError(w, r, detail, wantedID, email, displayName)
		return
	case errors.Is(err, userregistration.ErrEmailTaken):
		s.renderSignupError(w, r,
			"An account with that email already exists. Sign in instead, or use a different email.",
			wantedID, "", displayName)
		return
	case errors.Is(err, userregistration.ErrIDInvalid):
		s.renderSignupError(w, r,
			"ID must be 2–32 characters of letters, digits, dots, hyphens or underscores.",
			"", email, displayName)
		return
	case errors.Is(err, userregistration.ErrTagInvalid):
		s.renderSignupError(w, r,
			"Tag must be exactly 4 characters using 0–9 and a–z.",
			wantedID, email, displayName)
		return
	case errors.Is(err, userregistration.ErrUIDTaken):
		s.renderSignupError(w, r,
			"That ID + tag combination is already taken. Try a different tag, or leave it blank to auto-pick.",
			wantedID, email, displayName)
		return
	case errors.Is(err, userregistration.ErrUsernameUnavailable):
		s.renderSignupError(w, r,
			"Could not generate a unique account ID. Please try again or pick an explicit tag.",
			wantedID, email, displayName)
		return
	case err != nil:
		s.logger.App.Error("signup: userregistration.Register",
			zap.String("email", email), zap.Error(err))
		s.renderSignupError(w, r,
			"Something went wrong creating your account. Please try again.",
			wantedID, email, displayName)
		return
	}

	// Derive the actual stored uid from the LDAP DN's leftmost RDN.
	// Auto-generated uids use the `<id>#<tag>` form; we pre-fill
	// the login form with the email since that's the user-facing
	// identity post-Phase-7.5.
	s.logger.Security.Info("user registered (auth-server self-service)",
		zap.String("user_id", user.ID.String()),
		zap.String("ldap_dn", user.LdapDN),
		zap.String("email", email))

	// Success: redirect to /login with email pre-filled and the
	// original return_to preserved. UserLoginFilter accepts email
	// or uid, so the user types the email they just registered.
	loginURL := "/login"
	q := url.Values{}
	q.Set("username", email) // form field is named "username" but accepts email too
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
	tag := ""
	if r.PostForm != nil {
		returnTo = safeReturnTo(r.PostForm.Get("return_to"))
		// Preserve the tag the user typed so they don't have to
		// re-enter it after fixing another field's error.
		tag = strings.TrimSpace(r.PostForm.Get("tag"))
	}
	renderTemplate(w, "signup.html.tmpl", http.StatusOK, s.signupTemplateData(r.Context(), map[string]any{
		"CSRFToken":   csrf,
		"ReturnTo":    returnTo,
		"Username":    username,
		"Tag":         tag,
		"Email":       email,
		"DisplayName": displayName,
		"Error":       msg,
	}))
}

