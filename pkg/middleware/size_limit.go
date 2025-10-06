package middleware

import (
	"net/http"
)

// SizeLimitConfig holds configuration for request size limiting
type SizeLimitConfig struct {
	// MaxBytes is the maximum allowed request body size in bytes
	// Default is 5MB
	MaxBytes int64

	// SkipFunc determines if size limiting should be skipped for a request
	SkipFunc func(r *http.Request) bool
}

// DefaultSizeLimitConfig returns sensible defaults
func DefaultSizeLimitConfig() *SizeLimitConfig {
	return &SizeLimitConfig{
		MaxBytes: 5 * 1024 * 1024, // 5MB
		SkipFunc: nil,
	}
}

// RequestSizeLimit creates a middleware that limits request body size
func RequestSizeLimit(config *SizeLimitConfig) Middleware {
	if config == nil {
		config = DefaultSizeLimitConfig()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if should skip
			if config.SkipFunc != nil && config.SkipFunc(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Limit request body size
			r.Body = http.MaxBytesReader(w, r.Body, config.MaxBytes)

			next.ServeHTTP(w, r)
		})
	}
}

// RequestSizeLimitBytes creates a middleware with a specific byte limit
func RequestSizeLimitBytes(maxBytes int64) Middleware {
	config := &SizeLimitConfig{
		MaxBytes: maxBytes,
		SkipFunc: nil,
	}
	return RequestSizeLimit(config)
}
