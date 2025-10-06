package middleware

import (
	"net/http"
	"time"
)

// Middleware is a function that wraps an http.Handler
type Middleware func(http.Handler) http.Handler

// Chain builds a middleware chain by wrapping handlers
// Middlewares are applied in order: first middleware wraps second, etc.
// The outermost middleware (first in slice) executes first on request,
// and last on response
func Chain(middlewares ...Middleware) Middleware {
	return func(final http.Handler) http.Handler {
		// Apply middlewares in reverse order so first middleware wraps all others
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}

// ResponseWriter is a wrapper around http.ResponseWriter that captures status code
type ResponseWriter struct {
	http.ResponseWriter
	statusCode    int
	bytesWritten  int
	wroteHeader   bool
}

// NewResponseWriter creates a new ResponseWriter
func NewResponseWriter(w http.ResponseWriter) *ResponseWriter {
	return &ResponseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK, // default to 200
	}
}

// WriteHeader captures the status code
func (rw *ResponseWriter) WriteHeader(statusCode int) {
	if !rw.wroteHeader {
		rw.statusCode = statusCode
		rw.wroteHeader = true
		rw.ResponseWriter.WriteHeader(statusCode)
	}
}

// Write captures bytes written
func (rw *ResponseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += n
	return n, err
}

// StatusCode returns the captured status code
func (rw *ResponseWriter) StatusCode() int {
	return rw.statusCode
}

// BytesWritten returns the number of bytes written
func (rw *ResponseWriter) BytesWritten() int {
	return rw.bytesWritten
}

// ContextKey is a type for context keys to avoid collisions
type ContextKey string

const (
	// RequestIDKey is the context key for request ID
	RequestIDKey ContextKey = "request_id"

	// StartTimeKey is the context key for request start time
	StartTimeKey ContextKey = "start_time"

	// ClientCertDNKey is the context key for client certificate DN
	ClientCertDNKey ContextKey = "client_cert_dn"
)

// RateLimiterStore is an interface for rate limiting storage
type RateLimiterStore interface {
	// Allow checks if a request is allowed based on key and limit
	Allow(key string, limit int, window time.Duration) bool
}
