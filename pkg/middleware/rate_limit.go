package middleware

import (
	"net/http"
	"sync"
	"time"
)

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	// RequestsPerWindow is the max number of requests allowed in the time window
	RequestsPerWindow int

	// Window is the time window for rate limiting
	Window time.Duration

	// KeyFunc extracts the key for rate limiting (e.g., IP address, client ID)
	// Default is to use remote IP address
	KeyFunc func(r *http.Request) string

	// SkipFunc determines if rate limiting should be skipped for a request
	SkipFunc func(r *http.Request) bool
}

// DefaultRateLimitConfig returns sensible defaults
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		RequestsPerWindow: 100,
		Window:            time.Minute,
		KeyFunc:           defaultKeyFunc,
		SkipFunc:          nil,
	}
}

// defaultKeyFunc extracts IP address as the key
func defaultKeyFunc(r *http.Request) string {
	// Try X-Forwarded-For first (if behind proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// InMemoryRateLimiter is a simple in-memory rate limiter
type InMemoryRateLimiter struct {
	mu      sync.RWMutex
	buckets map[string]*bucket
	config  *RateLimitConfig
}

// bucket tracks request counts and window
type bucket struct {
	count     int
	resetTime time.Time
}

// NewInMemoryRateLimiter creates a new in-memory rate limiter
func NewInMemoryRateLimiter(config *RateLimitConfig) *InMemoryRateLimiter {
	if config == nil {
		config = DefaultRateLimitConfig()
	}

	limiter := &InMemoryRateLimiter{
		buckets: make(map[string]*bucket),
		config:  config,
	}

	// Start cleanup goroutine to remove expired buckets
	go limiter.cleanup()

	return limiter
}

// Allow checks if a request should be allowed
func (rl *InMemoryRateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Get or create bucket
	b, exists := rl.buckets[key]
	if !exists || now.After(b.resetTime) {
		// Create new bucket
		rl.buckets[key] = &bucket{
			count:     1,
			resetTime: now.Add(rl.config.Window),
		}
		return true
	}

	// Check if under limit
	if b.count < rl.config.RequestsPerWindow {
		b.count++
		return true
	}

	// Over limit
	return false
}

// GetRetryAfter returns seconds until the bucket resets
func (rl *InMemoryRateLimiter) GetRetryAfter(key string) int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	b, exists := rl.buckets[key]
	if !exists {
		return 0
	}

	seconds := int(time.Until(b.resetTime).Seconds())
	if seconds < 0 {
		return 0
	}
	return seconds
}

// cleanup removes expired buckets periodically
func (rl *InMemoryRateLimiter) cleanup() {
	ticker := time.NewTicker(rl.config.Window)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, b := range rl.buckets {
			if now.After(b.resetTime) {
				delete(rl.buckets, key)
			}
		}
		rl.mu.Unlock()
	}
}

// RateLimit creates a rate limiting middleware
func RateLimit(limiter *InMemoryRateLimiter) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if should skip
			if limiter.config.SkipFunc != nil && limiter.config.SkipFunc(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Get key for this request
			key := limiter.config.KeyFunc(r)

			// Check if allowed
			if !limiter.Allow(key) {
				// Rate limited
				retryAfter := limiter.GetRetryAfter(key)
				w.Header().Set("Retry-After", string(rune(retryAfter)))
				w.Header().Set("X-RateLimit-Limit", string(rune(limiter.config.RequestsPerWindow)))
				w.Header().Set("X-RateLimit-Remaining", "0")
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitWithConfig creates a rate limiting middleware with the given config
func RateLimitWithConfig(config *RateLimitConfig) Middleware {
	limiter := NewInMemoryRateLimiter(config)
	return RateLimit(limiter)
}
