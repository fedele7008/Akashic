// Package policy is the runtime accessor and editor for the
// deployment's tenable tenant policy (password rules, signup-enabled
// flag — see pkg/models/tenant_policy.go for the catalog). Phase 8c.6.
//
// Read pattern: callers Get() per-request. Cheap (a single SELECT on
// a one-row table) and consistency-correct — when an operator
// tightens password rules, the next signup attempt sees the new
// rule with no cache-invalidation footwork.
//
// Write pattern: Update() takes a partial-update params struct
// (pointer fields = "leave unchanged") and returns the updated row.
// Validation lives here, not in the model — the model is a dumb
// schema; this package owns the invariants.
package policy

import (
	"context"
	"errors"
	"fmt"

	"akashic/akashic/pkg/auth"
	"akashic/akashic/pkg/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Sentinel errors. Handlers errors.Is()-check to map them to
// surface-appropriate codes.
var (
	// ErrInvalidPolicy fires on per-field validity failures — non-
	// positive min length, etc. Wrapped with the specific reason.
	ErrInvalidPolicy = errors.New("invalid policy")
)

// Service is the policy accessor + editor. Constructed once at
// startup; methods are safe for concurrent use (every call is a
// fresh DB op).
type Service struct {
	db *gorm.DB
}

func NewService(db *gorm.DB) *Service {
	return &Service{db: db}
}

// Get returns the singleton policy row. Returns gorm.ErrRecordNotFound
// when the row hasn't been EnsureSingleton-populated yet — handlers
// should treat that as a configuration error and surface a 503,
// since it means startup wiring didn't run.
func (s *Service) Get(ctx context.Context) (*models.TenantPolicy, error) {
	var p models.TenantPolicy
	if err := s.db.WithContext(ctx).
		Where("id = ?", 1).First(&p).Error; err != nil {
		return nil, err
	}
	return &p, nil
}

// PasswordPolicy returns the password-policy fields shaped as the
// auth package's PasswordPolicy struct. Convenience for callers
// that previously read from cfg.Bootstrap.Password — drop-in shape.
//
// RequireLowercase is hard-coded true to match the existing
// invariant (every password must contain at least one lowercase
// character). Operators don't get to disable that — it's not in
// the editable surface; same as the API server's policyFromConfig.
func (s *Service) PasswordPolicy(ctx context.Context) (*auth.PasswordPolicy, error) {
	p, err := s.Get(ctx)
	if err != nil {
		return nil, err
	}
	return &auth.PasswordPolicy{
		MinLength:        p.PasswordMinLength,
		RequireUppercase: p.PasswordRequireUppercase,
		RequireLowercase: true,
		RequireNumber:    p.PasswordRequireNumber,
		RequireSpecial:   p.PasswordRequireSpecial,
	}, nil
}

// SignupEnabled returns whether self-service signup is currently
// allowed. Convenience for the two signup paths (auth-server
// /signup and api-server /users/register) so neither has to know
// about the policy struct shape.
func (s *Service) SignupEnabled(ctx context.Context) (bool, error) {
	p, err := s.Get(ctx)
	if err != nil {
		return false, err
	}
	return p.SignupEnabled, nil
}

// EnsureSingleton creates the singleton row from `defaults` if it
// doesn't already exist. Idempotent: subsequent calls do nothing
// when the row is present. Called from app startup right after
// AutoMigrate so by the time bootstrap or any signup flow runs,
// the row is guaranteed to be there.
//
// `defaults` is read from YAML's `Bootstrap.Password.*` plus the
// in-code default for SignupEnabled (true). After first run, those
// YAML values are no longer consulted at runtime — they remain
// only as bootstrap-defaults documentation.
func (s *Service) EnsureSingleton(ctx context.Context, defaults *models.TenantPolicy) error {
	var n int64
	if err := s.db.WithContext(ctx).
		Model(&models.TenantPolicy{}).Count(&n).Error; err != nil {
		return fmt.Errorf("count tenant_policies: %w", err)
	}
	if n > 0 {
		return nil
	}
	row := *defaults
	row.ID = 1
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		return fmt.Errorf("seed tenant_policies: %w", err)
	}
	return nil
}

// UpdateParams is the partial-update shape. Pointer fields preserve
// "leave unchanged" (omitted) vs "set to false/zero" (explicit).
// CallerID populates the audit `updated_by` column.
type UpdateParams struct {
	PasswordMinLength        *int
	PasswordRequireUppercase *bool
	PasswordRequireNumber    *bool
	PasswordRequireSpecial   *bool
	SignupEnabled            *bool
	UIDChangeCooldownDays    *int
	CallerID                 uuid.UUID
}

// Update applies field changes + invariant checks. Returns the
// post-update row.
//
// Validation:
//   - MinLength must be in [4, 256]. Below 4 is meaningless;
//     above 256 is unreasonable for any practical password.
//
// We deliberately don't validate "at least one rule must be on" —
// some deployments ship password-only auth with no complexity
// requirements (relying on length + breach-list checks elsewhere)
// and locking that out would be a paternalism trap.
func (s *Service) Update(ctx context.Context, p UpdateParams) (*models.TenantPolicy, error) {
	if p.PasswordMinLength != nil {
		if *p.PasswordMinLength < 4 || *p.PasswordMinLength > 256 {
			return nil, fmt.Errorf("%w: password_min_length must be between 4 and 256",
				ErrInvalidPolicy)
		}
	}
	if p.UIDChangeCooldownDays != nil {
		if *p.UIDChangeCooldownDays < 0 || *p.UIDChangeCooldownDays > 365 {
			return nil, fmt.Errorf("%w: uid_change_cooldown_days must be between 0 and 365",
				ErrInvalidPolicy)
		}
	}

	updates := map[string]any{}
	if p.PasswordMinLength != nil {
		updates["password_min_length"] = *p.PasswordMinLength
	}
	if p.PasswordRequireUppercase != nil {
		updates["password_require_uppercase"] = *p.PasswordRequireUppercase
	}
	if p.PasswordRequireNumber != nil {
		updates["password_require_number"] = *p.PasswordRequireNumber
	}
	if p.PasswordRequireSpecial != nil {
		updates["password_require_special"] = *p.PasswordRequireSpecial
	}
	if p.SignupEnabled != nil {
		updates["signup_enabled"] = *p.SignupEnabled
	}
	if p.UIDChangeCooldownDays != nil {
		updates["uid_change_cooldown_days"] = *p.UIDChangeCooldownDays
	}
	if p.CallerID != uuid.Nil {
		updates["updated_by"] = p.CallerID
	}

	if len(updates) == 0 {
		return s.Get(ctx)
	}

	if err := s.db.WithContext(ctx).
		Model(&models.TenantPolicy{}).
		Where("id = ?", 1).
		Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("update tenant_policies: %w", err)
	}
	return s.Get(ctx)
}
