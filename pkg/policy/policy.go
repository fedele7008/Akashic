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
	"akashic/akashic/pkg/oauth"

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

	// Phase 9 prep: tenant-level token-lifetime ceilings. Per-client
	// rows on `client_services` may override DOWN, never UP — see
	// pkg/clientservice for the override-against-ceiling validation.
	AccessTokenTTLSeconds          *int
	RefreshTokenSlidingTTLSeconds  *int
	RefreshTokenAbsoluteTTLSeconds *int

	// AllowedClientScopes is the tenant-wide ceiling on what scopes
	// any client may request. Per-client `RequiredScopes` +
	// `OptionalScopes` must each be a subset. Validated at write
	// time as a non-empty space-separated set of valid scope tokens.
	AllowedClientScopes *string

	CallerID uuid.UUID
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

	// Token-lifetime ceilings: validated as a triple because the
	// absolute-vs-sliding ordering is cross-field. Read the current
	// row first so a partial update (e.g. only access_ttl) inherits
	// the unchanged sliding/absolute values for the cross-check.
	if p.AccessTokenTTLSeconds != nil ||
		p.RefreshTokenSlidingTTLSeconds != nil ||
		p.RefreshTokenAbsoluteTTLSeconds != nil {
		current, err := s.Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("read policy for ttl validation: %w", err)
		}
		access := current.AccessTokenTTLSeconds
		sliding := current.RefreshTokenSlidingTTLSeconds
		absolute := current.RefreshTokenAbsoluteTTLSeconds
		if p.AccessTokenTTLSeconds != nil {
			access = *p.AccessTokenTTLSeconds
		}
		if p.RefreshTokenSlidingTTLSeconds != nil {
			sliding = *p.RefreshTokenSlidingTTLSeconds
		}
		if p.RefreshTokenAbsoluteTTLSeconds != nil {
			absolute = *p.RefreshTokenAbsoluteTTLSeconds
		}
		if err := oauth.ValidateCeilings(access, sliding, absolute); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidPolicy, err.Error())
		}
	}

	if p.AllowedClientScopes != nil {
		// Validate the proposed ceiling.  Empty is rejected — a
		// tenant with no allowed scopes is a stuck deployment.
		trimmed := *p.AllowedClientScopes
		if oauth.ParseScopeSet(trimmed).IsEmpty() {
			return nil, fmt.Errorf("%w: allowed_client_scopes cannot be empty",
				ErrInvalidPolicy)
		}
		if err := oauth.ValidateScopeString(trimmed); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidPolicy, err.Error())
		}
		// `openid` MUST be in the allowed set — Akashic is an OIDC
		// IDP, and dropping it would render every client unable to
		// request an id_token. Surface the issue with a clear message
		// rather than letting clients fail at /authorize time.
		if !oauth.ParseScopeSet(trimmed).Contains("openid") {
			return nil, fmt.Errorf("%w: allowed_client_scopes must include 'openid'",
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
	if p.AccessTokenTTLSeconds != nil {
		updates["access_token_ttl_seconds"] = *p.AccessTokenTTLSeconds
	}
	if p.RefreshTokenSlidingTTLSeconds != nil {
		updates["refresh_token_sliding_ttl_seconds"] = *p.RefreshTokenSlidingTTLSeconds
	}
	if p.RefreshTokenAbsoluteTTLSeconds != nil {
		updates["refresh_token_absolute_ttl_seconds"] = *p.RefreshTokenAbsoluteTTLSeconds
	}
	if p.AllowedClientScopes != nil {
		// Canonicalise on write so the stored form is sorted +
		// deduped — saves comparison churn on subsequent reads.
		updates["allowed_client_scopes"] = oauth.ParseScopeSet(*p.AllowedClientScopes).String()
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
