package models

import (
	"time"

	"github.com/google/uuid"
)

// TenantPolicy is the deployment's tunable runtime policy. Phase 8c.6.
//
// Singleton row: id=1, enforced at the application layer (the
// pkg/policy.Service.EnsureSingleton call creates the row at first
// run; Update never inserts new rows). Operators edit through the
// admin web's Policy page; reads come from this row at request time
// — no caching, since the read frequency is low (signup, password-
// change, register-client) and the consistency guarantee from a
// fresh fetch matters more than micro-perf.
//
// Why explicit columns rather than `key/value JSONB`: only five
// fields exist today, all known and type-stable. Type-safe columns
// give us GORM's normal Update path with no JSON serialization, and
// adding a new field is one migration alongside one Go field — same
// cost as a new key in a JSONB schema, with better ergonomics.
//
// Bootstrap-defaults relationship: at first run,
// `policy.Service.EnsureSingleton` populates this row from YAML
// `Bootstrap.Password.*` defaults. After that, YAML becomes
// bootstrap-only (its values are no longer consulted at runtime).
// Operators who want to change the active policy edit this row.
type TenantPolicy struct {
	// ID is fixed at 1 — the singleton constraint, enforced at
	// the application layer (policy.Service.EnsureSingleton sets
	// row.ID = 1 before db.Create; Update operates on WHERE id=1).
	//
	// No `default` tag because GORM maps `uint`+`primaryKey` to
	// Postgres `bigserial`, which already carries a sequence-based
	// default; layering an extra `DEFAULT 1` on top makes Postgres
	// reject the CREATE TABLE with "multiple default values
	// specified for column id". The bigserial sequence stays in
	// place but is effectively unused — every insert sets ID=1
	// explicitly via EnsureSingleton, and the count-then-insert
	// pattern blocks a second row.
	ID uint `gorm:"primaryKey" json:"-"`

	// ─── Password policy ──────────────────────────────────────
	// Validated against on /signup, /users/register, and the
	// password-change endpoints. Existing stored passwords are
	// NOT re-validated when policy tightens — only new passwords
	// going forward.
	PasswordMinLength        int  `gorm:"not null;default:8" json:"password_min_length"`
	PasswordRequireUppercase bool `gorm:"not null;default:false" json:"password_require_uppercase"`
	PasswordRequireNumber    bool `gorm:"not null;default:false" json:"password_require_number"`
	PasswordRequireSpecial   bool `gorm:"not null;default:false" json:"password_require_special"`

	// ─── Signup ───────────────────────────────────────────────
	// SignupEnabled gates both the auth-server-hosted /signup
	// surface AND the api-server's /users/register endpoint
	// (used by the <akashic-signup> widget). When false, both
	// return a friendly "signup is disabled" response — the
	// admin-bff's /api/users path stays available for operator-
	// initiated user creation (Phase 9 territory; not yet built).
	SignupEnabled bool `gorm:"not null;default:true" json:"signup_enabled"`

	// ─── UID rotation ─────────────────────────────────────────
	// UIDChangeCooldownDays is the minimum elapsed time between
	// successive PATCH /users/me/uid calls per user. Default 30
	// — discourages rotation-as-impersonation (changing an id to
	// match someone else's, then changing back). 0 disables the
	// cooldown entirely; values >365 are pointless in practice
	// but the policy.Service.Update validation caps at 365 to
	// keep the cooldown explicable in operator UI.
	UIDChangeCooldownDays int `gorm:"not null;default:30" json:"uid_change_cooldown_days"`

	// ─── Token lifetimes (ceilings) ───────────────────────────
	// Tenant-level ceilings on access + refresh token TTLs. Per-
	// client overrides on `client_services` may reduce these but
	// never exceed them — `pkg/clientservice` validates that
	// `client.*TTLOverride <= policy.*TTLSeconds` at write time,
	// and `oauth.ResolveTokenTTLs` belt-and-braces with a
	// `min(override, ceiling)` at mint time.
	//
	// Defaults: 15 min access / 30 day sliding refresh / 90 day
	// absolute refresh — the OAuth-2.1 conventional shape.
	// Floors enforced by policy.Service.Update: access ≥ 30s,
	// sliding ≥ 60s, absolute ≥ sliding.
	AccessTokenTTLSeconds          int `gorm:"not null;default:900" json:"access_token_ttl_seconds"`
	RefreshTokenSlidingTTLSeconds  int `gorm:"not null;default:2592000" json:"refresh_token_sliding_ttl_seconds"`
	RefreshTokenAbsoluteTTLSeconds int `gorm:"not null;default:7776000" json:"refresh_token_absolute_ttl_seconds"`

	// ─── Scope policy ─────────────────────────────────────────
	// AllowedClientScopes is the operator's tenant-wide ceiling
	// on scopes any client may request. Per-client RequiredScopes
	// + OptionalScopes must each be a subset of this set.
	//
	// Default: "openid profile email" — the OIDC standard set.
	// `offline_access` is intentionally NOT in the default; it's
	// a "special scope" that requires per-client approval via the
	// scope-request workflow (Phase B). Operators who explicitly
	// allow it tenant-wide can add it here, but the per-client
	// approval step is still recommended for audit.
	//
	// Format: space-separated. Validated to non-empty + every
	// token URL-safe at write time.
	AllowedClientScopes string `gorm:"type:text;not null;default:'openid profile email'" json:"allowed_client_scopes"`

	UpdatedAt time.Time  `gorm:"autoUpdateTime;not null" json:"updated_at"`
	UpdatedBy *uuid.UUID `gorm:"type:uuid" json:"updated_by,omitempty"`
}

// TableName fixes the table name regardless of GORM's pluralization
// guess (which would produce "tenant_policies").
func (TenantPolicy) TableName() string { return "tenant_policies" }
