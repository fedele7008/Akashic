package middleware

import (
	"net/http"
	"strconv"
	"strings"
)

// CORSConfig holds CORS configuration
type CORSConfig struct {
	// AllowedOrigins is a list of allowed origins
	// Use ["*"] to allow all origins (not recommended for production)
	AllowedOrigins []string

	// AllowedMethods is a list of allowed HTTP methods
	AllowedMethods []string

	// AllowedHeaders is a list of allowed request headers
	AllowedHeaders []string

	// ExposedHeaders is a list of headers exposed to the client
	ExposedHeaders []string

	// AllowCredentials indicates whether credentials are allowed
	AllowCredentials bool

	// MaxAge is the preflight cache duration in seconds
	MaxAge int
}

// DefaultAuthServerCORSConfig returns default CORS config for Auth Server
func DefaultAuthServerCORSConfig() *CORSConfig {
	return &CORSConfig{
		AllowedOrigins:   []string{}, // Empty - must be configured
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization", "X-Request-ID"},
		ExposedHeaders:   []string{"X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           3600, // 1 hour
	}
}

// DefaultControlServerCORSConfig returns default CORS config for Control Server
func DefaultControlServerCORSConfig() *CORSConfig {
	return &CORSConfig{
		AllowedOrigins:   []string{}, // Empty - must be configured
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization", "X-Request-ID", "X-Client-Cert-DN"},
		ExposedHeaders:   []string{"X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           7200, // 2 hours
	}
}

// CORS creates a CORS middleware with the given configuration
func CORS(config *CORSConfig) Middleware {
	if config == nil {
		config = DefaultAuthServerCORSConfig()
	}

	// Pre-compute header values for performance
	allowedMethodsStr := strings.Join(config.AllowedMethods, ", ")
	allowedHeadersStr := strings.Join(config.AllowedHeaders, ", ")
	exposedHeadersStr := strings.Join(config.ExposedHeaders, ", ")
	maxAgeStr := strconv.Itoa(config.MaxAge)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Check if origin is allowed
			if origin != "" && isOriginAllowed(origin, config.AllowedOrigins) {
				// Set CORS headers
				w.Header().Set("Access-Control-Allow-Origin", origin)

				if config.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}

				// Handle preflight request
				if r.Method == http.MethodOptions {
					w.Header().Set("Access-Control-Allow-Methods", allowedMethodsStr)
					w.Header().Set("Access-Control-Allow-Headers", allowedHeadersStr)
					w.Header().Set("Access-Control-Max-Age", maxAgeStr)

					if exposedHeadersStr != "" {
						w.Header().Set("Access-Control-Expose-Headers", exposedHeadersStr)
					}

					w.WriteHeader(http.StatusNoContent)
					return
				}

				// For actual requests, set expose headers
				if exposedHeadersStr != "" {
					w.Header().Set("Access-Control-Expose-Headers", exposedHeadersStr)
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isOriginAllowed checks if an origin is in the allowed list
func isOriginAllowed(origin string, allowedOrigins []string) bool {
	for _, allowed := range allowedOrigins {
		if allowed == "*" {
			return true
		}
		if allowed == origin {
			return true
		}
		// Support wildcard subdomains (e.g., "*.example.com")
		if strings.HasPrefix(allowed, "*.") {
			domain := allowed[2:] // Remove "*."
			if strings.HasSuffix(origin, domain) {
				return true
			}
		}
	}
	return false
}

// CORSWithValidator creates a CORS middleware with custom origin validation
func CORSWithValidator(config *CORSConfig, validator func(origin string) bool) Middleware {
	if config == nil {
		config = DefaultAuthServerCORSConfig()
	}

	allowedMethodsStr := strings.Join(config.AllowedMethods, ", ")
	allowedHeadersStr := strings.Join(config.AllowedHeaders, ", ")
	exposedHeadersStr := strings.Join(config.ExposedHeaders, ", ")
	maxAgeStr := strconv.Itoa(config.MaxAge)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Use custom validator if origin is present
			if origin != "" && validator(origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)

				if config.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}

				if r.Method == http.MethodOptions {
					w.Header().Set("Access-Control-Allow-Methods", allowedMethodsStr)
					w.Header().Set("Access-Control-Allow-Headers", allowedHeadersStr)
					w.Header().Set("Access-Control-Max-Age", maxAgeStr)

					if exposedHeadersStr != "" {
						w.Header().Set("Access-Control-Expose-Headers", exposedHeadersStr)
					}

					w.WriteHeader(http.StatusNoContent)
					return
				}

				if exposedHeadersStr != "" {
					w.Header().Set("Access-Control-Expose-Headers", exposedHeadersStr)
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
