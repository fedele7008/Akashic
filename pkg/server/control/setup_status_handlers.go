package control

import (
	"net/http"

	"akashic/akashic/pkg/server/response"

	"go.uber.org/zap"
)

// handleSetupStatus is GET /admin/setup-status — a small snapshot of
// the deployment's "did you finish setting things up?" gates. The
// admin UI calls this on every page load to render an actionable
// banner ("bootstrap not done yet", "no tenant portal registered",
// etc.) so an operator never has to dig through logs to discover
// missing setup steps.
//
// Why this lives on the control plane (not the api server): every
// signal aggregated here is operator-state. The natural caller is
// the admin-bff, already mTLS-authenticated against the control
// plane. Putting it here means one round trip per banner render
// and no new authentication surface.
//
// Failure mode: each subsystem probe is independent and nil-tolerant.
// If LDAP is down or the DB hiccups, the corresponding field is
// `false` (with a logged warning) instead of 500ing the whole call.
// Status pages must never fail the page they're on.
func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		response.WriteJSON(w, response.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"GET only on /admin/setup-status", nil))
		return
	}

	out := map[string]any{
		"bootstrap_complete":       false,
		"tenant_portal_registered": false,
		"ldap_ok":                  false,
	}

	// Bootstrap: invert NeedsBootstrap. If the manager isn't wired
	// (shouldn't happen post-init but defensive), report incomplete
	// — safer than optimistically claiming done.
	if s.bootstrapMgr != nil {
		needs, err := s.bootstrapMgr.NeedsBootstrap(r.Context())
		if err == nil {
			out["bootstrap_complete"] = !needs
		} else {
			s.logger.App.Warn("setup-status: NeedsBootstrap failed",
				zap.Error(err))
		}
	}

	// Tenant portal: any client_services row with is_tenant_portal=true.
	// Pre-bootstrap the table is empty, so this naturally returns
	// false until the operator runs `clients create --tenant-portal`
	// post-bootstrap. Count() rather than First() avoids a
	// "record not found" sentinel we'd then have to translate.
	if s.db != nil {
		var n int64
		err := s.db.WithContext(r.Context()).
			Table("client_services").
			Where("is_tenant_portal = ?", true).
			Count(&n).Error
		if err == nil {
			out["tenant_portal_registered"] = n > 0
		} else {
			s.logger.App.Warn("setup-status: tenant_portal query failed",
				zap.Error(err))
		}
	}

	// LDAP: a base-scope search via TestConnection. Cheap; if it
	// fails the whole stack is broken since auth depends on LDAP,
	// so the operator absolutely needs to see that on the banner.
	if s.ldapClient != nil {
		if err := s.ldapClient.TestConnection(); err == nil {
			out["ldap_ok"] = true
		} else {
			s.logger.App.Warn("setup-status: LDAP TestConnection failed",
				zap.Error(err))
		}
	}

	response.WriteJSON(w, response.StatusOK, response.Success(out))
}
