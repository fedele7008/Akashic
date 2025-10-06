package middleware

import (
	"net/http"
)

// SecurityHeadersConfig holds configuration for security headers
type SecurityHeadersConfig struct {
	// HSTSMaxAge is the max-age for HSTS header (in seconds)
	// Only applied if HTTPS is detected. 0 disables HSTS
	HSTSMaxAge int

	// ContentSecurityPolicy defines the CSP header value
	// Empty string means no CSP header
	ContentSecurityPolicy string

	// RemoveServerHeader determines if Server header should be removed
	RemoveServerHeader bool

	// CustomHeaders allows adding additional custom security headers
	CustomHeaders map[string]string
}

// DefaultSecurityHeadersConfig returns sensible defaults
func DefaultSecurityHeadersConfig() *SecurityHeadersConfig {
	return &SecurityHeadersConfig{
		HSTSMaxAge:            31536000, // 1 year
		ContentSecurityPolicy: "default-src 'self'",
		RemoveServerHeader:    true,
		CustomHeaders:         make(map[string]string),
	}
}

// SecurityHeaders creates a middleware that adds security headers to responses
func SecurityHeaders(config *SecurityHeadersConfig) Middleware {
	if config == nil {
		config = DefaultSecurityHeadersConfig()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Disable browser to guess the content-type
			w.Header().Set("X-Content-Type-Options", "nosniff")
			// Disable my web server's content is displayed in iframes
			w.Header().Set("X-Frame-Options", "DENY")
			// For old browsers, use XSS filter feature if they still support it - blocks loading html if it contains suspicious script
			w.Header().Set("X-XSS-Protection", "1; mode=block")

			// Add HSTS only for HTTPS requests
			if config.HSTSMaxAge > 0 && r.TLS != nil {
				w.Header().Set("Strict-Transport-Security",
					"max-age="+string(rune(config.HSTSMaxAge))+"; includeSubDomains")
			}

			// Add CSP if configured
			if config.ContentSecurityPolicy != "" {
				w.Header().Set("Content-Security-Policy", config.ContentSecurityPolicy)
			}

			// Remove Server header to avoid fingerprinting
			if config.RemoveServerHeader {
				w.Header().Del("Server")
			}

			// Add custom headers
			for key, value := range config.CustomHeaders {
				w.Header().Set(key, value)
			}

			next.ServeHTTP(w, r)
		})
	}
}
