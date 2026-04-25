package admin_bff

import (
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"time"
)

// Audit logging for the BFF. Every state-changing or security-relevant
// action emits a structured JSON line to the security stream. By
// default that's stdout (which docker captures into its logs and the
// Akashic Loki stack can scrape); operators can override to a file
// path via AKASHIC_BFF_AUDIT_LOG_PATH.
//
// Critical discipline: this logger uses an EXPLICIT FIELD ALLOWLIST,
// not a denylist. Caller-supplied details are filtered through that
// allowlist before being written. This prevents accidents where some
// future handler logs the bootstrap token or password "for debugging".
// You CANNOT add a new field to an audit log line without updating
// allowlist below; that's by design.

var auditFieldAllowlist = map[string]struct{}{
	// Set by the audit middleware on every entry.
	"timestamp":      {}, // RFC3339Nano
	"request_id":     {}, // currently not generated; placeholder for Phase 7
	"action":         {}, // "bootstrap_create_root", "rate_limited", etc.
	"path":           {}, // r.URL.Path (limited PII risk)
	"method":         {}, // GET / POST / etc.
	"remote_ip":      {}, // resolved client IP (post-trust-chain)
	"user_agent":     {}, // r.Header.Get("User-Agent") — informational
	"referer":        {}, // r.Header.Get("Referer") — when present

	// Caller-supplied fields. Each maps to a specific audit context.
	"outcome":             {}, // "success", "fail", "rate_limited"
	"control_status":      {}, // upstream HTTP status code
	"control_error_code":  {}, // upstream error envelope's code field
	"duration_ms":         {}, // wall-clock duration of the BFF op
	"retry_after":         {}, // when outcome=rate_limited, the seconds
	"username":            {}, // bootstrap-created user's username (NOT password)
	"email":               {}, // bootstrap-created user's email
	"forced":              {}, // for /token/regenerate-style operations
	"ip":                  {}, // legacy compat with rate limiter; same as remote_ip
}

// AuditWriter is where audit lines get written. Defaults to os.Stdout;
// rare to override outside tests.
type AuditWriter struct {
	mu  sync.Mutex
	out interface {
		Write([]byte) (int, error)
	}
}

func newAuditWriter() *AuditWriter {
	return &AuditWriter{out: os.Stdout}
}

// auditLog emits a single audit line to the BFF's security stream.
// Caller passes the raw http.Request and a map of additional fields.
// Fields not in the allowlist are dropped silently.
//
// The drop-on-mismatch policy is deliberate: an attacker who somehow
// got code execution and tried to log a secret would have that field
// silently filtered. The non-debug behavior favors safety over
// developer convenience.
func (s *Server) auditLog(r *http.Request, action string, fields map[string]any) {
	if s.audit == nil {
		// Defensive: server may emit audit events before middleware
		// is fully initialized in tests. No-op rather than panic.
		return
	}

	entry := map[string]any{
		"timestamp":  time.Now().UTC().Format(time.RFC3339Nano),
		"action":     action,
		"path":       r.URL.Path,
		"method":     r.Method,
		"remote_ip":  s.resolveAuditIP(r),
		"user_agent": r.UserAgent(),
	}
	if ref := r.Referer(); ref != "" {
		entry["referer"] = ref
	}
	for k, v := range fields {
		if _, ok := auditFieldAllowlist[k]; ok {
			entry[k] = v
		}
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return // never block on a logging failure
	}

	s.audit.mu.Lock()
	defer s.audit.mu.Unlock()
	_, _ = s.audit.out.Write(append(data, '\n'))
}

// resolveAuditIP mirrors rateLimiter.clientIP -- both honor the same
// trusted-proxies chain. Defined separately because audit events can
// happen before the rate-limit middleware would have run (e.g.,
// CSRF rejections that audit before their middleware enforces).
func (s *Server) resolveAuditIP(r *http.Request) string {
	if s.rateLimiter == nil {
		return r.RemoteAddr
	}
	return s.rateLimiter.clientIP(r)
}
