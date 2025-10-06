package middleware

import (
	"context"
	"net/http"
	"time"
)

// TimeoutConfig holds configuration for request timeout
type TimeoutConfig struct {
	// Timeout is the maximum duration for a request
	Timeout time.Duration

	// Message is the error message to return on timeout
	Message string

	// SkipFunc determines if timeout should be skipped for a request
	SkipFunc func(r *http.Request) bool
}

// DefaultTimeoutConfig returns sensible defaults
func DefaultTimeoutConfig() *TimeoutConfig {
	return &TimeoutConfig{
		Timeout:  30 * time.Second,
		Message:  "Request Timeout",
		SkipFunc: nil,
	}
}

// Timeout creates a middleware that enforces request timeout
func Timeout(config *TimeoutConfig) Middleware {
	if config == nil {
		config = DefaultTimeoutConfig()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if should skip
			if config.SkipFunc != nil && config.SkipFunc(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Create context with timeout
			ctx, cancel := context.WithTimeout(r.Context(), config.Timeout)
			defer cancel()

			// Create channel to signal completion
			done := make(chan struct{})
			panicChan := make(chan any, 1)

			// Run handler in goroutine
			go func() {
				defer func() {
					if p := recover(); p != nil {
						panicChan <- p
					}
				}()

				next.ServeHTTP(w, r.WithContext(ctx))
				close(done)
			}()

			// Wait for either completion or timeout
			select {
			case p := <-panicChan:
				// Re-panic so recovery middleware can handle it
				panic(p)
			case <-done:
				// Request completed successfully
				return
			case <-ctx.Done():
				// Timeout occurred
				if ctx.Err() == context.DeadlineExceeded {
					http.Error(w, config.Message, http.StatusRequestTimeout)
				}
				return
			}
		})
	}
}

// TimeoutWithDuration creates a timeout middleware with a specific duration
func TimeoutWithDuration(timeout time.Duration) Middleware {
	config := &TimeoutConfig{
		Timeout:  timeout,
		Message:  "Request Timeout",
		SkipFunc: nil,
	}
	return Timeout(config)
}
