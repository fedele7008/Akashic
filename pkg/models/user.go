package models

import (
	"time"

	"github.com/google/uuid"
)

// UserType represents the permission level of a user
type UserType string

const (
	UserTypeRoot  UserType = "root"  // Highest permission, un-deletable
	UserTypeAdmin UserType = "admin" // Full administrative access
	UserTypeUser  UserType = "user"  // Regular user with limited permissions
)

// String returns the string representation of UserType
func (ut UserType) String() string {
	return string(ut)
}

// IsValid checks if the UserType is valid
func (ut UserType) IsValid() bool {
	switch ut {
	case UserTypeRoot, UserTypeAdmin, UserTypeUser:
		return true
	default:
		return false
	}
}

// User represents a user account in the system.
//
// Identity information (username, email, password, display name) is
// stored in LDAP — uid, mail, userPassword, and cn respectively.
// This postgres row holds only Akashic-specific metadata that LDAP
// has no natural place for. Display name is intentionally NOT here;
// it lives in LDAP cn (see doc/phase-8-plan.md "On display names"
// for the rule this follows: anything LDAP can naturally express
// stays in LDAP).
type User struct {
	ID                   uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"uid"`
	LdapDN               string     `gorm:"uniqueIndex;not null;size:512" json:"ldap_dn"` // Distinguished Name in LDAP
	UserType             UserType   `gorm:"type:varchar(50);not null;index" json:"user_type"`
	IsDisabled           bool       `gorm:"default:false;not null;index" json:"is_disabled"`
	DisabledAt           *time.Time `gorm:"index" json:"disabled_at,omitempty"`
	DisabledBy           *uuid.UUID `gorm:"type:uuid" json:"disabled_by,omitempty"`
	MissingIdentity      bool       `gorm:"default:false;not null;index" json:"missing_identity"`        // True if LDAP entry not found
	MissingIdentitySince *time.Time `gorm:"index" json:"missing_identity_since,omitempty"`               // When LDAP entry was first detected missing

	// Phase 8: email-verification tracking. The flag stays false in
	// Phase 8 (no email infrastructure yet) — Phase 9 wires the flow
	// that sets it true. Schema added now so Phase 9 layers cleanly
	// without a migration.
	EmailVerified   bool       `gorm:"default:false;not null;index" json:"email_verified"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`

	// Phase 8: tracks the most recent successful authentication for
	// session/security UI ("last seen N days ago"). Updated by the
	// auth-server on every successful /login/submit. Indexed so admin
	// queries like "users inactive for 90 days" stay cheap.
	LastLoginAt *time.Time `gorm:"index" json:"last_login_at,omitempty"`

	// LastUIDChangedAt tracks the most recent successful uid (id+tag)
	// rotation via PATCH /users/me/uid. nil means the user has never
	// rotated their uid since signup. Used by the cooldown check —
	// the policy table's UIDChangeCooldownDays gives the minimum
	// elapsed time before another change is allowed. Indexed so
	// future "users who changed in the last week" admin queries
	// stay cheap.
	LastUIDChangedAt *time.Time `gorm:"index" json:"last_uid_changed_at,omitempty"`

	// Phase 9d: admin-initiated temporary-password-reset gate.
	// When true, the auth-server's /login flow detects the flag
	// after password verify and routes the user through a forced
	// password-change page instead of issuing a regular session;
	// every other user-facing endpoint (re-)redirects there until
	// the user picks a new password. Cleared on successful reset.
	//
	// The set→reset lifecycle is initiated by an admin through
	// `POST /users/<id>/reset-password` on the control plane.
	PasswordResetRequired bool `gorm:"default:false;not null;index" json:"password_reset_required"`

	// Phase 9e (v2): per-user offset applied to the tenant policy's
	// `default_max_clients`. Signed: positive grants extra slots to
	// power users, negative tightens trusted-but-restricted users.
	// The user's effective cap is computed live as
	// `max(0, policy.default_max_clients + client_count_offset)`,
	// counted against (existing clients) + (pending registration
	// requests) so a flood of pending submissions can't bypass it.
	//
	// Edited only by admins via PATCH /users/<id>; there is no
	// widget-side surface for users to request a higher cap. Default
	// 0 means "use the tenant default exactly".
	ClientCountOffset int `gorm:"default:0;not null" json:"client_count_offset"`

	// Phase 9f: per-user MFA opt-in. When true, every login goes
	// through the email-code MFA flow unless a trusted-device cookie
	// is presented for this user. OR'd with the per-client
	// `require_mfa` flag at login time — either "true" trips the gate.
	// User-toggled via the <akashic-mfa-settings> widget; admin-
	// readable but not edited from the admin surface.
	//
	// MFA is silently bypassed when no mailer is configured (the
	// widget greys-out the toggle and the login path short-circuits)
	// — there's no path to deliver codes without email, and a stuck
	// deployment would lock users out.
	MFAEnabled   bool       `gorm:"default:false;not null;index" json:"mfa_enabled"`
	MFAEnabledAt *time.Time `json:"mfa_enabled_at,omitempty"`

	CreatedAt time.Time `gorm:"autoCreateTime;not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime;not null" json:"updated_at"`
}

// TableName specifies the table name for GORM
func (User) TableName() string {
	return "users"
}

// CreateUserRequest represents a request to create a new user.
//
// Used by both the bootstrap path (root user creation) and Phase 8's
// public self-service registration path. The two callers differ only
// in the UserType they pass and whether they supply a DisplayName.
type CreateUserRequest struct {
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Password string   `json:"password"` // Plain text password (will be hashed by LDAP)
	UserType UserType `json:"user_type"`

	// DisplayName populates LDAP `cn`. Optional — empty falls back to
	// Username, which keeps the bootstrap path's existing behavior
	// (cn == uid when the operator doesn't specify otherwise).
	// Phase 8 self-service registration supplies it from a form field.
	DisplayName string `json:"display_name,omitempty"`
}

// Validate validates the create user request
func (r *CreateUserRequest) Validate() error {
	if r.Username == "" {
		return ErrUsernameRequired
	}
	if r.Email == "" {
		return ErrEmailRequired
	}
	if r.Password == "" {
		return ErrPasswordRequired
	}
	if !r.UserType.IsValid() {
		return ErrInvalidUserType
	}
	return nil
}

// UpdatePasswordRequest represents a request to update a user's password
type UpdatePasswordRequest struct {
	UserID      uuid.UUID `json:"user_id"`
	OldPassword string    `json:"old_password"`
	NewPassword string    `json:"new_password"`
}

// DisableUserRequest represents a request to disable a user
type DisableUserRequest struct {
	UserID     uuid.UUID `json:"user_id"`
	DisabledBy uuid.UUID `json:"disabled_by"`
	Reason     string    `json:"reason,omitempty"`
}

// Common user-related errors
var (
	ErrUsernameRequired     = NewValidationError("username is required")
	ErrEmailRequired        = NewValidationError("email is required")
	ErrPasswordRequired     = NewValidationError("password is required")
	ErrInvalidUserType      = NewValidationError("invalid user type")
	ErrUserNotFound         = NewNotFoundError("user not found")
	ErrUserAlreadyExists    = NewConflictError("user already exists")
	ErrRootUserExists       = NewConflictError("root user already exists")
	ErrRootUserCannotDelete = NewForbiddenError("root user cannot be deleted")
	ErrInvalidCredentials   = NewUnauthorizedError("invalid credentials")
	ErrUserDisabled         = NewForbiddenError("user account is disabled")
)

// ValidationError represents a validation error
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

func NewValidationError(msg string) *ValidationError {
	return &ValidationError{Message: msg}
}

// NotFoundError represents a not found error
type NotFoundError struct {
	Message string
}

func (e *NotFoundError) Error() string {
	return e.Message
}

func NewNotFoundError(msg string) *NotFoundError {
	return &NotFoundError{Message: msg}
}

// ConflictError represents a conflict error
type ConflictError struct {
	Message string
}

func (e *ConflictError) Error() string {
	return e.Message
}

func NewConflictError(msg string) *ConflictError {
	return &ConflictError{Message: msg}
}

// ForbiddenError represents a forbidden error
type ForbiddenError struct {
	Message string
}

func (e *ForbiddenError) Error() string {
	return e.Message
}

func NewForbiddenError(msg string) *ForbiddenError {
	return &ForbiddenError{Message: msg}
}

// UnauthorizedError represents an unauthorized error
type UnauthorizedError struct {
	Message string
}

func (e *UnauthorizedError) Error() string {
	return e.Message
}

func NewUnauthorizedError(msg string) *UnauthorizedError {
	return &UnauthorizedError{Message: msg}
}
