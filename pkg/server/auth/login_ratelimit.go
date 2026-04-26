package auth

import (
	"sync"
	"time"
)

// Login rate limiter — narrowly scoped to /login/submit. Per source
// IP, 5 attempts per minute, in-memory, resets on server restart.
//
// Distinct from any global rate-limit middleware: the login endpoint
// has different semantics (a single failed login is a real security
// signal, not just rate-tunable noise) and benefits from its own
// counter that's easy to reason about during incident response.
//
// In-memory is fine because the auth server is single-node today;
// the Phase 8+ multi-node story will move this to Redis (alongside
// the auth-server session store, which is already Redis-backed).

const (
	loginRateLimitMaxPerMinute = 5
	loginRateLimitWindow       = time.Minute
)

type loginAttempts struct {
	count   int
	resetAt time.Time
}

var (
	loginRateMu sync.Mutex
	loginRate   = map[string]*loginAttempts{}
)

// loginRateLimitAllow records an attempt from the given key (IP)
// and returns true if it's under the per-window cap.
//
// The check + record are intentionally in one function: if we
// separated them, a fast attacker could fire many requests between
// "check" and "record" and slip through. As one critical section,
// it's atomic.
func (s *Server) loginRateLimitAllow(key string) bool {
	loginRateMu.Lock()
	defer loginRateMu.Unlock()

	now := time.Now()
	a, ok := loginRate[key]
	if !ok || now.After(a.resetAt) {
		loginRate[key] = &loginAttempts{count: 1, resetAt: now.Add(loginRateLimitWindow)}
		return true
	}
	if a.count < loginRateLimitMaxPerMinute {
		a.count++
		return true
	}
	return false
}
