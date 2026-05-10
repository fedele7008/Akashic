// Package email is the runtime accessor + editor for the
// deployment's outbound-email configuration. Phase 9 (revised:
// DB-backed instead of env-var-driven so operators can configure
// from the admin web without restarting the server).
//
// The Service plays two roles:
//
//  1. *Mailer-interface implementation* — `Send` / `IsConfigured`
//     proxy to a cached `mailer.Mailer` constructed from the latest
//     DB row. Existing callers (auth-server, api-server) hold the
//     Service as a `mailer.Mailer` and don't know about the DB at
//     all; their call sites stay unchanged.
//
//  2. *Live-config admin surface* — `Get`, `Update`, `Reload`,
//     `EnsureSingleton`. Same shape as `policy.Service`. The
//     admin-web PATCH handler updates the row + calls `Reload`
//     so the new mailer takes effect on the next Send without a
//     server restart.
//
// Concurrency: the cached driver is protected by an RWMutex.
// Sends grab the read lock (cheap, lots of concurrent Sends are
// fine); reloads grab the write lock briefly to swap the pointer.
package email

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"akashic/akashic/pkg/mailer"
	"akashic/akashic/pkg/models"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// ErrInvalidConfig fires on per-field validity failures. Wrapped
// with the specific reason. Handlers `errors.Is`-check it to map
// to VALIDATION_FAILED.
var ErrInvalidConfig = errors.New("invalid email config")

// Service is the DB-backed email-config editor + Mailer adapter.
// Constructed once at startup; methods are safe for concurrent
// use. Implements the `mailer.Mailer` interface so existing
// servers can hold it where they previously held a static
// `mailer.Mailer`.
type Service struct {
	db     *gorm.DB
	logger *zap.Logger

	// current is the live mailer driver, rebuilt on Reload. Always
	// non-nil after Reload has been called at least once (which
	// EnsureSingleton triggers at startup). Initial value before
	// the first Reload is `nopMailer` so a Send before init still
	// returns a typed error rather than panicking.
	mu      sync.RWMutex
	current mailer.Mailer
}

// NewService constructs the service with an initial nopMailer.
// Caller MUST call `EnsureSingleton` (which seeds + reloads) at
// startup before serving requests; until then `Send` returns
// ErrNotConfigured and `IsConfigured` returns false.
func NewService(db *gorm.DB, logger *zap.Logger) *Service {
	return &Service{
		db:      db,
		logger:  logger,
		current: nopUntilReloaded{},
	}
}

// Send implements mailer.Mailer.Send. Proxies to the cached
// driver under a read lock.
func (s *Service) Send(ctx context.Context, msg mailer.Message) error {
	s.mu.RLock()
	m := s.current
	s.mu.RUnlock()
	return m.Send(ctx, msg)
}

// IsConfigured implements mailer.Mailer.IsConfigured. Cheap
// snapshot check; UI code uses this to gate render of features.
func (s *Service) IsConfigured() bool {
	s.mu.RLock()
	m := s.current
	s.mu.RUnlock()
	return m.IsConfigured()
}

// Get returns the singleton config row. Returns
// gorm.ErrRecordNotFound when the row hasn't been seeded yet —
// callers should treat that as a "config service not ready"
// 503, since it means startup wiring didn't run.
func (s *Service) Get(ctx context.Context) (*models.EmailConfig, error) {
	var cfg models.EmailConfig
	if err := s.db.WithContext(ctx).
		Where("id = ?", 1).First(&cfg).Error; err != nil {
		return nil, err
	}
	return &cfg, nil
}

// EnsureSingleton seeds an empty singleton row if none exists,
// then reloads the cached driver from DB. Idempotent on subsequent
// calls (the seed happens at most once; Reload always runs).
// Called from app startup.
//
// The seeded row has all fields blank — the resulting cached driver
// is `nopMailer`, so the deployment runs in degraded-email mode by
// default. Operators configure provider + credentials through the
// admin web's "Email" page; the PATCH handler calls Reload after
// persisting, so the new driver takes effect immediately on save.
//
// Phase 9 (revised) deliberately removed the env-var-seeding path
// that earlier drafts had — admin web is the single source of
// truth. Existing deployments that had AKASHIC_EMAIL_* env vars
// set before this change will have their config preserved in DB
// from the previous version's first-run seed; nothing is lost.
func (s *Service) EnsureSingleton(ctx context.Context) error {
	var n int64
	if err := s.db.WithContext(ctx).
		Model(&models.EmailConfig{}).Count(&n).Error; err != nil {
		return fmt.Errorf("count email_configs: %w", err)
	}
	if n == 0 {
		row := models.EmailConfig{ID: 1}
		if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
			return fmt.Errorf("seed email_configs: %w", err)
		}
		s.logger.Info("email_configs row created (empty); configure via admin web's Email page")
	}
	return s.Reload(ctx)
}

// Reload reads the singleton row + reconstructs the cached driver.
// Called by the admin PATCH handler after `Update` so the new
// settings take effect on the next Send without a server restart.
//
// On config error (e.g., provider=sendgrid but key empty), Reload
// installs a `nopMailer` and returns the soft error so the caller
// can log a warning. The server keeps running in degraded mode.
func (s *Service) Reload(ctx context.Context) error {
	cfg, err := s.Get(ctx)
	if err != nil {
		return fmt.Errorf("read email_configs: %w", err)
	}
	newMailer, mailerErr := mailer.New(mailer.Config{
		Provider:       cfg.Provider,
		FromAddress:    cfg.FromAddress,
		FromName:       cfg.FromName,
		SendGridAPIKey: cfg.SendGridAPIKey,
	})
	s.mu.Lock()
	s.current = newMailer
	s.mu.Unlock()

	if mailerErr != nil {
		s.logger.Warn("email config reload: degraded mode",
			zap.Error(mailerErr))
	} else if newMailer.IsConfigured() {
		s.logger.Info("email mailer (re)configured",
			zap.String("provider", cfg.Provider),
			zap.String("from_address", cfg.FromAddress))
	} else {
		s.logger.Info("email mailer disabled (no provider configured)")
	}
	return nil
}

// VerifyURLBase returns the externally-reachable URL prefix used
// in verification email links. Read live from the DB on each call
// (cheap; same pattern as Send). Empty when not configured.
//
// Why not cache like the mailer: VerifyURLBase doesn't drive a
// connection or expensive driver build; reading it directly on
// each send keeps the operator-edit-takes-effect-immediately
// promise without an extra reload step.
func (s *Service) VerifyURLBase(ctx context.Context) string {
	cfg, err := s.Get(ctx)
	if err != nil {
		return ""
	}
	return cfg.VerifyURLBase
}

// UpdateParams is the partial-update shape, mirroring policy.UpdateParams.
// Pointer fields preserve "leave unchanged" (omitted) vs. "set to
// empty" (explicit).
type UpdateParams struct {
	Provider       *string
	FromAddress    *string
	FromName       *string
	SendGridAPIKey *string
	VerifyURLBase  *string
	CallerID       uuid.UUID
}

// Update applies the diff + invariant checks to the singleton row,
// then triggers Reload so the new config takes effect on the next
// Send. Returns the post-update row (with the SendGrid key
// preserved on the return — callers that want to mask render
// through a separate view type, see pkg/server/control/email_config_handlers.go).
//
// Validation:
//   - Provider must be one of: "" | "sendgrid"
//   - When Provider is non-empty, FromAddress must be non-empty
//   - When Provider == "sendgrid", SendGridAPIKey must be non-empty
//     (note: when caller supplies nil for the key field AND the
//      stored value is non-empty, we preserve the stored value
//      rather than failing — lets operators tweak provider/from
//      without re-typing the key)
func (s *Service) Update(ctx context.Context, p UpdateParams) (*models.EmailConfig, error) {
	current, err := s.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("read current config: %w", err)
	}
	// Build the prospective post-update state for cross-field validation.
	next := *current
	if p.Provider != nil {
		next.Provider = *p.Provider
	}
	if p.FromAddress != nil {
		next.FromAddress = *p.FromAddress
	}
	if p.FromName != nil {
		next.FromName = *p.FromName
	}
	if p.SendGridAPIKey != nil {
		next.SendGridAPIKey = *p.SendGridAPIKey
	}
	if p.VerifyURLBase != nil {
		next.VerifyURLBase = *p.VerifyURLBase
	}

	// Cross-field validation.
	switch next.Provider {
	case "":
		// Disabled — anything else is allowed (operator can keep
		// the API key around for re-enabling later).
	case "sendgrid":
		if next.FromAddress == "" {
			return nil, fmt.Errorf("%w: from_address is required when provider is set",
				ErrInvalidConfig)
		}
		if next.SendGridAPIKey == "" {
			return nil, fmt.Errorf("%w: sendgrid_api_key is required when provider is sendgrid",
				ErrInvalidConfig)
		}
	default:
		return nil, fmt.Errorf("%w: unknown provider %q (recognised: \"\", \"sendgrid\")",
			ErrInvalidConfig, next.Provider)
	}

	// Build the updates map. Only include fields the caller actually
	// touched — preserves stored values for fields they didn't.
	updates := map[string]any{}
	if p.Provider != nil {
		updates["provider"] = *p.Provider
	}
	if p.FromAddress != nil {
		updates["from_address"] = *p.FromAddress
	}
	if p.FromName != nil {
		updates["from_name"] = *p.FromName
	}
	if p.SendGridAPIKey != nil {
		// Column name is GORM's default snake_case of `SendGridAPIKey`,
		// which inserts an underscore at lowercase→uppercase
		// boundaries: `send_grid_api_key`. The wire-format JSON
		// uses `sendgrid_api_key` (no underscore between send+grid)
		// because the BFF + admin UI side uses explicit JSON tags;
		// the two namespaces are independent.
		updates["send_grid_api_key"] = *p.SendGridAPIKey
	}
	if p.VerifyURLBase != nil {
		updates["verify_url_base"] = *p.VerifyURLBase
	}
	if p.CallerID != uuid.Nil {
		updates["updated_by"] = p.CallerID
	}

	if len(updates) == 0 {
		return current, nil
	}

	if err := s.db.WithContext(ctx).
		Model(&models.EmailConfig{}).
		Where("id = ?", 1).
		Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("update email_configs: %w", err)
	}

	// Reload the cached driver so the new config takes effect on
	// the very next Send. We don't roll back on Reload error —
	// the DB was updated; if the new config has a misconfig
	// detected only at Reload time, the cached driver becomes
	// nopMailer and the operator sees the warning in logs.
	if err := s.Reload(ctx); err != nil {
		s.logger.Warn("email config reload after update failed; mailer in degraded mode",
			zap.Error(err))
	}

	return s.Get(ctx)
}

// nopUntilReloaded is the initial mailer the service holds before
// EnsureSingleton runs. Distinct from the "operator unset" nop
// driver only in its log-able name — operators reading audit
// logs can tell "we never even reloaded" apart from "we reloaded
// and ended up with no provider configured."
type nopUntilReloaded struct{}

func (nopUntilReloaded) Send(_ context.Context, _ mailer.Message) error {
	return mailer.ErrNotConfigured
}
func (nopUntilReloaded) IsConfigured() bool { return false }
