package control

import (
	"net/http"
	"strconv"
	"time"

	"akashic/akashic/pkg/middleware"
	"akashic/akashic/pkg/server/response"

	"go.uber.org/zap"
)

// Bootstrap-specific rate limit. Per-CN, in-memory, resets on server restart.
//
// The bootstrap window is small (default 1h TTL) and the keyspace is enormous
// (32 random bytes), so brute-force is infeasible by construction. The point
// of this limiter isn't to defeat brute-force; it's to make a noisy attacker
// stand out in security logs and avoid filling them with junk attempts that
// drown real signals.
//
// Defaults: 5 attempts per minute per client CN. The 6th gets 429 + a
// security-channel log line. After the window expires, the bucket resets.
const (
	bootstrapMaxAttemptsPerWindow = 5
	bootstrapRateLimitWindow      = time.Minute
)

// newBootstrapRateLimiter constructs an InMemoryRateLimiter keyed by client
// cert CN. CNs are stable across browser reloads / TCP reconnects, unlike
// IP addresses which can shift behind NAT. We fall back to RemoteAddr when
// no peer cert is present — but in practice every request reaching this
// middleware has already passed requireClientIdentity, so PeerCertificates
// should always be populated.
func newBootstrapRateLimiter() *middleware.InMemoryRateLimiter {
	return middleware.NewInMemoryRateLimiter(&middleware.RateLimitConfig{
		RequestsPerWindow: bootstrapMaxAttemptsPerWindow,
		Window:            bootstrapRateLimitWindow,
		KeyFunc: func(r *http.Request) string {
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				return "cn:" + r.TLS.PeerCertificates[0].Subject.CommonName
			}
			return "ip:" + r.RemoteAddr
		},
	})
}

// rateLimitBootstrap wraps a handler with the per-CN rate limit. On 429, it
// emits a security-channel log line so SOC dashboards see attacker probing
// without having to grep general request logs.
func (s *Server) rateLimitBootstrap(limiter *middleware.InMemoryRateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := "ip:" + r.RemoteAddr
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			key = "cn:" + r.TLS.PeerCertificates[0].Subject.CommonName
		}
		if !limiter.Allow(key) {
			retryAfter := limiter.GetRetryAfter(key)
			s.logger.Security.Warn("bootstrap endpoint rate-limited",
				zap.String("key", key),
				zap.Int("retry_after_seconds", retryAfter),
				zap.String("path", r.URL.Path),
			)
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			response.WriteJSON(w, http.StatusTooManyRequests,
				response.Fail("RATE_LIMITED",
					"too many bootstrap attempts; please wait before retrying",
					map[string]any{
						"retry_after_seconds": retryAfter,
						"window":              bootstrapRateLimitWindow.String(),
						"max_attempts":        bootstrapMaxAttemptsPerWindow,
					}))
			return
		}
		next(w, r)
	}
}
