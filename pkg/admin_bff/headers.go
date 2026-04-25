package admin_bff

import "net/http"

// securityHeadersMiddleware sets the standard set of HTTP security
// headers on every response. Settings are deliberately tight (defense-
// in-depth, not just legal-minimum compliance):
//
//   - HSTS with preload: tells browsers to never accept plain HTTP
//     for this hostname for the next year, including for subdomains.
//     Preload directive is fine even though we're not actually on
//     the preload list yet — operators who want preload can submit
//     their domain to the HSTS preload list later.
//
//   - CSP: only same-origin scripts/images/styles. 'unsafe-inline'
//     for styles is required by Vite's default CSS-in-JS output;
//     Phase 7 can tighten with nonces if it's worth the complexity.
//     frame-ancestors 'none' prevents clickjacking.
//
//   - X-Frame-Options DENY: redundant with CSP frame-ancestors but
//     older browsers don't honor frame-ancestors; this is the
//     belt+suspenders approach.
//
//   - X-Content-Type-Options nosniff: prevents the browser from
//     "helpfully" guessing a different content type than we set.
//     Critical for any endpoint that returns JSON — without this,
//     an attacker who could control even part of the JSON body
//     could potentially trigger HTML/JS interpretation.
//
//   - Referrer-Policy strict-origin-when-cross-origin: don't leak
//     the path/query of admin URLs to external sites.
//
//   - Permissions-Policy: explicitly deny camera/mic/geolocation
//     since we don't need them and not denying them gives any
//     XSS-injected code free access.
//
// These headers are set unconditionally for every /api/* and FE
// asset response. Setting them globally is a single-place change;
// applying them per-handler is begging for someone to forget.
func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security",
			"max-age=31536000; includeSubDomains; preload")
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"font-src 'self' data:; "+
				"connect-src 'self'; "+
				"form-action 'self'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'self'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy",
			"camera=(), microphone=(), geolocation=(), payment=()")
		// Cache control on API responses — never cache anything from
		// /api/*; the FE bundle does its own cache-busting via Vite's
		// content-hashed filenames.
		if len(r.URL.Path) >= 5 && r.URL.Path[:5] == "/api/" {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}
