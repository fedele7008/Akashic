package auth

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
)

// Auth-server's HTML templates + static assets, embedded at compile
// time. Same pattern as admin-bff embedding the React FE: one Go
// binary contains everything.
//
//go:embed web
var webAssets embed.FS

// templates holds the parsed HTML templates. Loaded once at server
// startup; concurrent reads are safe because html/template's Execute
// is goroutine-safe after parsing.
var templates *template.Template

// initTemplates parses every *.tmpl file in web/. Called from server
// startup; panic on error since a missing template means the binary
// is broken (not an operational issue).
func initTemplates() error {
	t, err := template.ParseFS(webAssets, "web/*.html.tmpl")
	if err != nil {
		return fmt.Errorf("parse auth templates: %w", err)
	}
	templates = t
	return nil
}

// renderTemplate executes a named template with the given data and
// writes the result to w. Sets Content-Type and the security headers
// the auth surface always returns.
//
// On execution error (rare; usually a typo in a template field
// reference), writes 500 plus a minimal text fallback so the user
// at least knows something happened.
func renderTemplate(w http.ResponseWriter, name string, status int, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	// Tight CSP for login pages. Login pages are SUPER security-critical:
	//
	//   - script-src 'none' — login template has zero JS, so no script
	//     injection attacks are possible.
	//   - style-src 'self' — only the embedded stylesheet at /static/.
	//   - img-src 'self' data: — for any small inline brand assets.
	//   - frame-ancestors 'none' — clickjacking-proof.
	//   - base-uri 'self' — block <base href="evil.com"> tricks.
	//
	// form-action: this is the subtle one. The login form posts to
	// /login/submit (same-origin), but the SUCCESS path issues a 303
	// → /authorize → 302 → <client redirect_uri>, where the client's
	// redirect_uri is by design a different origin (e.g. the admin-bff
	// at admin.akashic.example.com). Per the CSP spec, form-action
	// is enforced against EVERY URL in the redirect chain, not just
	// the initial POST target. With `form-action 'self'` the browser
	// silently blocks step 3 and the user gets stuck on the login page.
	//
	// We allow `https:` (any HTTPS origin) for form-action. The actual
	// redirect_uri is still validated against the registered client's
	// redirect_uris in client_services.redirect_uris (see /authorize's
	// redirectURIAllowed() — exact-string match, no wildcards), so the
	// CSP loosening doesn't open a new attack surface — the auth-server
	// itself refuses to redirect to anything not registered. Combined
	// with `script-src 'none'` (which prevents anyone from rewriting
	// <form action="..."> in the page), this is safe.
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; "+
			"script-src 'none'; "+
			"style-src 'self'; "+
			"img-src 'self' data:; "+
			"form-action 'self' https:; "+
			"frame-ancestors 'none'; "+
			"base-uri 'self'")
	w.WriteHeader(status)
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		// Already wrote headers; can only append plain text now.
		_, _ = fmt.Fprintf(w, "<!-- template error: %v -->", err)
	}
}

// staticAssets returns an http.Handler that serves files under web/.
// Used by the /static/ route for CSS (the only static asset right
// now). Keeps templates and assets in the same embed FS for
// deployment simplicity.
func staticAssets() http.Handler {
	sub, err := fs.Sub(webAssets, "web")
	if err != nil {
		panic("auth web assets missing: " + err.Error())
	}
	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}
