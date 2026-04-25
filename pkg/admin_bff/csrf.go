package admin_bff

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
)

// CSRF protection via the double-submit cookie pattern.
//
// On first request to /api/* we set a cookie named akashic_csrf with
// a random value. The cookie is HttpOnly=false BY DESIGN: the React
// FE needs to read it and echo it back in the X-Akashic-CSRF header
// on every state-changing request. The middleware compares the cookie
// value with the header value; they must match exactly.
//
// Why this works: cross-origin attackers can cause the browser to send
// the cookie (cookies travel automatically), but they CANNOT read the
// cookie value to set the matching header (cookies are scoped to the
// origin). Same-origin code reads the cookie + sets the header; cross-
// origin code can do neither. So matching cookie+header proves same-
// origin.
//
// SameSite=Strict on the cookie is a belt-and-suspenders second line
// of defense -- in modern browsers the cookie wouldn't be sent on
// cross-site requests at all, but older browsers / some embed
// scenarios benefit from the explicit cookie comparison.
const (
	csrfCookieName = "akashic_csrf"
	csrfHeaderName = "X-Akashic-CSRF"
	csrfTokenBytes = 32 // 256 bits, hex-encoded → 64 chars
)

// csrfMiddleware enforces double-submit cookie validation on
// state-changing methods (POST/PUT/DELETE/PATCH). Idempotent methods
// (GET/HEAD/OPTIONS) skip the check but still get the cookie set if
// it's missing — that's how the React FE bootstraps its CSRF state on
// initial load.
func (s *Server) csrfMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Always ensure the cookie exists; for idempotent methods that's
		// the entirety of our work here.
		s.ensureCSRFCookie(w, r)

		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next(w, r)
			return
		}

		// State-changing method: enforce match.
		c, err := r.Cookie(csrfCookieName)
		if err != nil || c.Value == "" {
			s.auditLog(r, "csrf_no_cookie", map[string]any{"path": r.URL.Path})
			writeError(w, http.StatusForbidden, "CSRF_FAILED",
				"CSRF cookie missing. Reload the page and try again.")
			return
		}
		header := r.Header.Get(csrfHeaderName)
		if header == "" {
			s.auditLog(r, "csrf_no_header", map[string]any{"path": r.URL.Path})
			writeError(w, http.StatusForbidden, "CSRF_FAILED",
				"CSRF header missing. The page may be out of date; refresh and try again.")
			return
		}

		// Constant-time comparison to defeat timing attacks. Even
		// though equality of two ~64-char strings is cheap, doing it
		// in constant time costs nothing extra and removes a class of
		// side-channel concern.
		if subtle.ConstantTimeCompare([]byte(header), []byte(c.Value)) != 1 {
			s.auditLog(r, "csrf_mismatch", map[string]any{"path": r.URL.Path})
			writeError(w, http.StatusForbidden, "CSRF_FAILED",
				"CSRF token mismatch. Reload the page and try again.")
			return
		}

		next(w, r)
	}
}

// ensureCSRFCookie sets a fresh CSRF cookie if the request doesn't
// already have one. The value is 32 random bytes, hex-encoded.
//
// HttpOnly=false: by design, the FE must read this cookie value in
// JavaScript to echo it in the X-Akashic-CSRF header. SameSite=Strict
// + Secure gives us most of the protection HttpOnly would offer
// against XSS-driven cookie theft.
//
// Secure flag handling: ALWAYS true when the original request was HTTPS
// (production), and false when the original request was plain HTTP
// (local dev hitting the docker proxy directly without a host-nginx in
// front). We can't unconditionally set Secure=true because browsers
// silently drop Secure cookies on non-HTTPS responses, which would
// break dev access without TLS.
func (s *Server) ensureCSRFCookie(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(csrfCookieName); err == nil && c.Value != "" {
		return
	}
	buf := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		// rand.Read on Linux/macOS doesn't fail in practice; if it
		// does, we're in deep trouble and should fail closed.
		writeError(w, http.StatusInternalServerError, "INTERNAL",
			"Could not generate CSRF token; please retry.")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    hex.EncodeToString(buf),
		Path:     "/",
		Secure:   isHTTPS(r),
		HttpOnly: false, // FE needs JS access to echo in header
		SameSite: http.SameSiteStrictMode,
	})
}

// isHTTPS detects whether the original client request was HTTPS, even
// when the BFF itself only speaks HTTP (i.e., when fronted by a
// TLS-terminating proxy). The proxy sets X-Forwarded-Proto; we trust
// it because by the time a request reaches the BFF, the X-Forwarded-*
// trust chain (Phase 6 plan §7.6) has already been validated by the
// docker-level proxy honoring `set_real_ip_from` for its upstream.
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return r.Header.Get("X-Forwarded-Proto") == "https"
}
