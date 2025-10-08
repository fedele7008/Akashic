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

// User represents a user account in the system
// Identity information (username, email, password) is stored in LDAP
// This table only stores Akashic-specific metadata and authorization data
type User struct {
	ID                   uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"uid"`
	LdapDN               string     `gorm:"uniqueIndex;not null;size:512" json:"ldap_dn"` // Distinguished Name in LDAP
	UserType             UserType   `gorm:"type:varchar(50);not null;index" json:"user_type"`
	IsDisabled           bool       `gorm:"default:false;not null;index" json:"is_disabled"`
	DisabledAt           *time.Time `gorm:"index" json:"disabled_at,omitempty"`
	DisabledBy           *uuid.UUID `gorm:"type:uuid" json:"disabled_by,omitempty"`
	MissingIdentity      bool       `gorm:"default:false;not null;index" json:"missing_identity"`           // True if LDAP entry not found
	MissingIdentitySince *time.Time `gorm:"index" json:"missing_identity_since,omitempty"`                   // When LDAP entry was first detected missing
	CreatedAt            time.Time  `gorm:"autoCreateTime;not null" json:"created_at"`
	UpdatedAt            time.Time  `gorm:"autoUpdateTime;not null" json:"updated_at"`
}

// TableName specifies the table name for GORM
func (User) TableName() string {
	return "users"
}

// CreateUserRequest represents a request to create a new user
type CreateUserRequest struct {
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Password string   `json:"password"` // Plain text password (will be hashed)
	UserType UserType `json:"user_type"`
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
