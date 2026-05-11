package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"akashic/akashic/pkg/mailer"
	"akashic/akashic/pkg/models"

	"go.uber.org/zap"
)

// Phase 9g: login-notification fan-out.
//
// Fires after a successful login finalises a fully-authenticated
// session (i.e., AFTER any forced-password-reset and AFTER any
// MFA challenge — the goal is one email per actually-logged-in
// event, not per intermediate step). Best-effort: a send failure
// must never fail the login itself.
//
// Three preconditions gate the send:
//   1. User opted in (`users.login_notifications_enabled = true`).
//   2. Mailer is configured (`emailSvc.IsConfigured()`).
//   3. User has an email address on file. (Without one, no delivery
//      target — silently skip rather than logging churn on every
//      login by users without email.)
//
// Content carries the timestamp, source IP, best-effort UA-derived
// device label, and (when the login originated from /authorize) the
// client name being authorized. The body explicitly tells the user
// how to revoke trusted devices and change passwords if they don't
// recognise the activity — that's the anti-takeover hint.

// fireLoginNotification kicks off the email send asynchronously so
// the redirect path latency isn't impacted by SMTP turnaround.
// The launched goroutine uses context.Background() because the
// request context is canceled the moment the redirect lands — and
// the email is a courtesy that should outlive the HTTP request.
func (s *Server) fireLoginNotification(
	r *http.Request,
	user *models.User,
	emailAddr string,
	displayName string,
	clientID string,
) {
	if !user.LoginNotificationsEnabled {
		return
	}
	if emailAddr == "" {
		return
	}

	s.mu.RLock()
	emailSvc := s.emailSvc
	db := s.db
	s.mu.RUnlock()
	if emailSvc == nil || !emailSvc.IsConfigured() {
		return
	}

	// Snapshot the request-derived fields BEFORE launching the
	// goroutine — by the time we send, the request may be gone.
	ip := clientIPFromRequest(r)
	device := bestEffortDeviceLabel(r.UserAgent())
	timestamp := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")

	// Resolve client name (best-effort) so the email can show
	// "Application: Acme Portal" instead of an opaque client_id.
	clientName := ""
	if clientID != "" && db != nil {
		var c models.ClientService
		if err := db.WithContext(r.Context()).
			Select("name").
			Where("client_id = ?", clientID).
			First(&c).Error; err == nil {
			clientName = c.Name
		}
	}

	dn := displayName
	if dn == "" {
		dn = emailAddr
		if at := strings.IndexByte(dn, '@'); at > 0 {
			dn = dn[:at]
		}
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		msg, err := mailer.Render("login_notification", map[string]any{
			"TenantName":  "Akashic",
			"DisplayName": dn,
			"Timestamp":   timestamp,
			"IPAddress":   ip,
			"Device":      device,
			"ClientName":  clientName,
		})
		if err != nil {
			s.logger.App.Warn("login-notification: render failed",
				zap.String("user_id", user.ID.String()), zap.Error(err))
			return
		}
		msg.To = emailAddr
		if err := emailSvc.Send(ctx, msg); err != nil {
			s.logger.App.Warn("login-notification: send failed",
				zap.String("user_id", user.ID.String()), zap.Error(err))
			return
		}
		s.logger.Security.Info("login notification emailed",
			zap.String("user_id", user.ID.String()),
			zap.String("ip", ip),
			zap.String("client_name", clientName))
	}()
}

// clientIPFromRequest extracts the most-trustworthy IP from the
// request. The auth-server sits behind an optional reverse proxy
// (the docker-compose nginx in dev); X-Forwarded-For is consulted
// when present, falling back to RemoteAddr otherwise. For login-
// notification purposes a slightly-wrong IP is OK — the goal is
// "tell the user where the login came from", not "ironclad audit".
func clientIPFromRequest(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// First entry in XFF is the originating client.
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if r.RemoteAddr == "" {
		return "unknown"
	}
	// RemoteAddr is host:port; strip the port.
	if i := strings.LastIndexByte(r.RemoteAddr, ':'); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}
