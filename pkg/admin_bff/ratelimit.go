package admin_bff

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// rateLimiter is a per-source-IP token bucket. Fixed window (not
// sliding) — when the window expires, the bucket resets in full.
//
// Sized for the bootstrap surface specifically: 5 attempts per IP per
// minute on /api/bootstrap/create-root, with a separate (more
// permissive) bucket for /api/bootstrap/status which is idempotent.
//
// Why per-IP rather than per-CN like Phase 5's control-plane limiter:
// the BFF presents ONE cert (CN bff.akashic.local) to the control
// plane on behalf of all browser users. If we only had the per-CN
// bucket, a single attacker browser could DoS the legitimate
// operator. The per-IP layer is what prevents that.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	limit   int
	window  time.Duration

	// trustedProxies is the list of CIDR ranges from which we honor
	// X-Forwarded-For. Outside that list we fall back to RemoteAddr.
	// See Phase 6 plan §7.6 for the full trust-chain story.
	trustedNets []*net.IPNet
}

type bucket struct {
	count     int
	resetAt   time.Time
}

func newRateLimiter(limit int, window time.Duration, trustedCIDRs []string) *rateLimiter {
	rl := &rateLimiter{
		buckets: make(map[string]*bucket),
		limit:   limit,
		window:  window,
	}
	for _, c := range trustedCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			rl.trustedNets = append(rl.trustedNets, n)
		}
	}
	go rl.gc()
	return rl
}

// Allow returns (allowed, retryAfterSeconds). retryAfter is 0 when
// allowed; otherwise the caller surfaces it in a Retry-After header.
func (rl *rateLimiter) Allow(key string) (bool, int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok || now.After(b.resetAt) {
		rl.buckets[key] = &bucket{count: 1, resetAt: now.Add(rl.window)}
		return true, 0
	}
	if b.count < rl.limit {
		b.count++
		return true, 0
	}
	retry := int(b.resetAt.Sub(now).Seconds())
	if retry < 1 {
		retry = 1
	}
	return false, retry
}

// gc periodically purges expired buckets so memory stays bounded
// even under sustained scanning. Runs every two windows; rarely
// finds anything to delete except after a burst.
func (rl *rateLimiter) gc() {
	t := time.NewTicker(rl.window * 2)
	defer t.Stop()
	for range t.C {
		rl.mu.Lock()
		now := time.Now()
		for k, b := range rl.buckets {
			if now.After(b.resetAt) {
				delete(rl.buckets, k)
			}
		}
		rl.mu.Unlock()
	}
}

// clientIP extracts the source IP for rate-limiting purposes,
// honoring X-Forwarded-For ONLY when the immediate peer is in
// trustedProxies. Otherwise we use the socket peer IP.
//
// This is the BFF end of the X-Forwarded-For trust chain documented
// in Phase 6 plan §7.6. Misconfiguring trustedProxies (e.g.,
// including 0.0.0.0/0) lets any client spoof X-Forwarded-For and
// bypass the rate limit.
func (rl *rateLimiter) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil {
		return host
	}
	// Only honor X-Forwarded-For if the IMMEDIATE peer is trusted.
	trusted := false
	for _, n := range rl.trustedNets {
		if n.Contains(peer) {
			trusted = true
			break
		}
	}
	if !trusted {
		return host
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the leftmost entry (the original client) per RFC 7239.
		// Strip whitespace because nginx can leave it after commas.
		for i, c := range xff {
			if c == ',' {
				return trimSpace(xff[:i])
			}
		}
		return trimSpace(xff)
	}
	return host
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// rateLimitMiddleware wraps a handler with per-IP throttling. On
// rejection: 429 + Retry-After header + audit log line (Step 4
// audit.go writes the "rate-limited" event).
func (s *Server) rateLimitMiddleware(rl *rateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := rl.clientIP(r)
		ok, retry := rl.Allow(ip)
		if !ok {
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			s.auditLog(r, "rate_limited", map[string]any{
				"ip":             ip,
				"path":           r.URL.Path,
				"retry_after":    retry,
			})
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"success": false,
				"error": map[string]any{
					"code":    "RATE_LIMITED",
					"message": "Too many attempts. Please wait and try again.",
					"details": map[string]any{
						"retry_after_seconds": retry,
					},
				},
			})
			return
		}
		next(w, r)
	}
}
