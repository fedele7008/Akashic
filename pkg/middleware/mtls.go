package middleware

import (
	"context"
	"crypto/x509"
	"net/http"
)

// MTLSConfig holds configuration for mTLS validation
type MTLSConfig struct {
	// RequireClientCert determines if client certificate is required
	RequireClientCert bool

	// TrustedCAs is a pool of trusted certificate authorities
	TrustedCAs *x509.CertPool

	// AllowLoopbackWithoutCert allows loopback connections without client cert
	AllowLoopbackWithoutCert bool

	// ExtractDN determines if the certificate DN should be extracted to context
	ExtractDN bool
}

// DefaultMTLSConfig returns sensible defaults
func DefaultMTLSConfig() *MTLSConfig {
	return &MTLSConfig{
		RequireClientCert:        true,
		TrustedCAs:               nil, // Must be set
		AllowLoopbackWithoutCert: true,
		ExtractDN:                true,
	}
}

// MTLSValidator creates a middleware that validates mTLS client certificates
func MTLSValidator(config *MTLSConfig) Middleware {
	if config == nil {
		config = DefaultMTLSConfig()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if this is a loopback connection
			isLoopback := false
			if r.RemoteAddr != "" {
				// Simple check for loopback
				if r.RemoteAddr[:9] == "127.0.0.1" || r.RemoteAddr[:3] == "::1" || r.RemoteAddr[:11] == "[::1]" {
					isLoopback = true
				}
			}

			// Allow loopback without cert if configured
			if isLoopback && config.AllowLoopbackWithoutCert {
				next.ServeHTTP(w, r)
				return
			}

			// Check if TLS is being used
			if r.TLS == nil {
				if config.RequireClientCert {
					http.Error(w, "TLS Required", http.StatusBadRequest)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Check if client certificate is present
			if len(r.TLS.PeerCertificates) == 0 {
				if config.RequireClientCert {
					http.Error(w, "Client Certificate Required", http.StatusUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Get client certificate
			clientCert := r.TLS.PeerCertificates[0]

			// Verify against trusted CAs if provided
			if config.TrustedCAs != nil {
				opts := x509.VerifyOptions{
					Roots:     config.TrustedCAs,
					KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				}

				if _, err := clientCert.Verify(opts); err != nil {
					http.Error(w, "Invalid Client Certificate", http.StatusUnauthorized)
					return
				}
			}

			// Extract DN to context if configured
			if config.ExtractDN {
				dn := clientCert.Subject.String()
				ctx := context.WithValue(r.Context(), ClientCertDNKey, dn)
				r = r.WithContext(ctx)

				// Also add to response header for debugging
				w.Header().Set("X-Client-Cert-DN", dn)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetClientCertDN extracts the client certificate DN from the context
func GetClientCertDN(r *http.Request) string {
	if dn := r.Context().Value(ClientCertDNKey); dn != nil {
		return dn.(string)
	}
	return ""
}

// RequireMTLS creates a simple mTLS middleware that requires valid client cert
func RequireMTLS(trustedCAs *x509.CertPool) Middleware {
	return MTLSValidator(&MTLSConfig{
		RequireClientCert:        true,
		TrustedCAs:               trustedCAs,
		AllowLoopbackWithoutCert: true,
		ExtractDN:                true,
	})
}
