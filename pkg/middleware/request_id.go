package middleware

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	mathrand "math/rand"
	"net/http"
	"os"
	"time"
)

const (
	// RequestIDHeader is the header name for request ID
	RequestIDHeader = "X-Request-ID"
)

// RequestID creates a middleware that generates or extracts request IDs
// It checks for existing X-Request-ID header, generates one if missing,
// adds it to response headers, and stores it in request context
func RequestID() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if request already has an ID
			requestID := r.Header.Get(RequestIDHeader)

			// Generate new ID if not present
			if requestID == "" {
				requestID = generateRequestID()
			}

			// Add to response headers
			w.Header().Set(RequestIDHeader, requestID)

			// Add to request context
			ctx := context.WithValue(r.Context(), RequestIDKey, requestID)

			// Call next handler with updated context
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// generateRequestID creates a random 16-byte hex string as request ID
func generateRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback: combine timestamp + PID + math/rand for uniqueness
		// This should almost never execute, but ensures we still get unique IDs
		fallback := make([]byte, 16)

		// Bytes 0-7: Current timestamp in nanoseconds (time-based uniqueness)
		binary.BigEndian.PutUint64(fallback[0:8], uint64(time.Now().UnixNano()))

		// Bytes 8-11: Process ID (cross-process uniqueness)
		binary.BigEndian.PutUint32(fallback[8:12], uint32(os.Getpid()))

		// Bytes 12-15: Math random
		binary.BigEndian.PutUint32(fallback[12:16], mathrand.Uint32())

		return hex.EncodeToString(fallback)
	}
	return hex.EncodeToString(b)
}

// GetRequestID extracts the request ID from the context
func GetRequestID(r *http.Request) string {
	if reqID := r.Context().Value(RequestIDKey); reqID != nil {
		return reqID.(string)
	}
	return ""
}
