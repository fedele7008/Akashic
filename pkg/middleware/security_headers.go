package middleware

import (
	"fmt"
	"net/http"
)

// SecurityHeadersConfig holds configuration for security headers
type SecurityHeadersConfig struct {
	// XFrameOptions defines the X-Frame-Options policy
	XFrameOptions XFrameOptions

	// XSSProtection defines the X-XSS-Protection policy
	XSSProtection XSSProtectionPolicy

	// HSTSMaxAge is the max-age for HSTS header (in seconds)
	// Only applied if HTTPS is detected. 0 disables HSTS
	HSTSMaxAge int

	// HSTSIncludeSubDomains determines if HSTS applies to subdomains
	HSTSIncludeSubDomains bool

	// HSTSPreload determines if HSTS preload directive is included
	HSTSPreload bool

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
		XFrameOptions:         XFrameOptionsDeny,
		XSSProtection:         XSSProtectionBlock,
		HSTSMaxAge:            31536000, // 1 year
		HSTSIncludeSubDomains: true,
		HSTSPreload:           false, // Must be manually enabled after adding to preload list
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
			// X-Content-Type-Options: prevent MIME type sniffing
			w.Header().Set("X-Content-Type-Options", "nosniff")

			// X-Frame-Options: control framing policy
			w.Header().Set("X-Frame-Options", config.XFrameOptions.String())

			// X-XSS-Protection: enable XSS filtering for legacy browsers
			w.Header().Set("X-XSS-Protection", config.XSSProtection.String())

			// HSTS: enforce HTTPS (only for HTTPS requests)
			if config.HSTSMaxAge > 0 && r.TLS != nil {
				hstsValue := fmt.Sprintf("max-age=%d", config.HSTSMaxAge)
				if config.HSTSIncludeSubDomains {
					hstsValue += "; includeSubDomains"
				}
				if config.HSTSPreload {
					hstsValue += "; preload"
				}
				w.Header().Set("Strict-Transport-Security", hstsValue)
			}

			// Content-Security-Policy: control resource loading
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

// Validate validates the security headers configuration
func (c *SecurityHeadersConfig) Validate() error {
	if err := c.XFrameOptions.Validate(); err != nil {
		return fmt.Errorf("security headers config: %v", err)
	}
	if err := c.XSSProtection.Validate(); err != nil {
		return fmt.Errorf("security headers config: %v", err)
	}
	if c.HSTSMaxAge < 0 {
		return fmt.Errorf("security headers config: HSTS max age cannot be negative")
	}
	return nil
}
