package auth

import (
	"fmt"
	"regexp"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

const (
	// bcryptCost is the computational cost for hashing
	// Cost 12 provides strong security while maintaining reasonable performance
	bcryptCost = 12

	// Default password policy settings
	DefaultMinLength        = 12
	DefaultRequireUppercase = true
	DefaultRequireNumber    = true
	DefaultRequireSpecial   = true
)

// HashPassword hashes a plain text password using bcrypt
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword compares a hashed password with a plain text password
func VerifyPassword(hash, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return ErrInvalidPassword
		}
		return fmt.Errorf("failed to verify password: %w", err)
	}
	return nil
}

// PasswordPolicy defines password complexity requirements
type PasswordPolicy struct {
	MinLength        int  `json:"min_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireNumber    bool `json:"require_number"`
	RequireSpecial   bool `json:"require_special"`
}

// DefaultPasswordPolicy returns the default password policy
func DefaultPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:        DefaultMinLength,
		RequireUppercase: DefaultRequireUppercase,
		RequireLowercase: true, // Always require lowercase
		RequireNumber:    DefaultRequireNumber,
		RequireSpecial:   DefaultRequireSpecial,
	}
}

// Validate validates a password against the policy
func (p *PasswordPolicy) Validate(password string) error {
	if len(password) < p.MinLength {
		return &PasswordPolicyError{
			Field:   "min_length",
			Message: fmt.Sprintf("password must be at least %d characters long", p.MinLength),
		}
	}

	if p.RequireUppercase && !hasUppercase(password) {
		return &PasswordPolicyError{
			Field:   "uppercase",
			Message: "password must contain at least one uppercase letter",
		}
	}

	if p.RequireLowercase && !hasLowercase(password) {
		return &PasswordPolicyError{
			Field:   "lowercase",
			Message: "password must contain at least one lowercase letter",
		}
	}

	if p.RequireNumber && !hasNumber(password) {
		return &PasswordPolicyError{
			Field:   "number",
			Message: "password must contain at least one number",
		}
	}

	if p.RequireSpecial && !hasSpecial(password) {
		return &PasswordPolicyError{
			Field:   "special",
			Message: "password must contain at least one special character",
		}
	}

	// Check for common weak passwords
	if isCommonPassword(password) {
		return &PasswordPolicyError{
			Field:   "common",
			Message: "password is too common, please choose a more secure password",
		}
	}

	return nil
}

// Helper functions for password validation

func hasUppercase(s string) bool {
	for _, r := range s {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

func hasLowercase(s string) bool {
	for _, r := range s {
		if unicode.IsLower(r) {
			return true
		}
	}
	return false
}

func hasNumber(s string) bool {
	return regexp.MustCompile(`[0-9]`).MatchString(s)
}

func hasSpecial(s string) bool {
	return regexp.MustCompile(`[^a-zA-Z0-9]`).MatchString(s)
}

// isCommonPassword checks against a list of commonly used passwords
func isCommonPassword(password string) bool {
	// Common weak passwords (case-insensitive)
	commonPasswords := []string{
		"password", "password123", "123456", "12345678", "qwerty",
		"abc123", "monkey", "letmein", "trustno1", "dragon",
		"baseball", "iloveyou", "master", "sunshine", "ashley",
		"bailey", "passw0rd", "shadow", "123123", "654321",
		"superman", "qazwsx", "michael", "football", "welcome",
	}

	lowered := regexp.MustCompile(`(?i)`).ReplaceAllString(password, "")
	for _, common := range commonPasswords {
		if lowered == common {
			return true
		}
	}
	return false
}

// ValidateEmail validates an email address format
func ValidateEmail(email string) error {
	if email == "" {
		return ErrEmailRequired
	}

	// RFC 5322 compliant email regex (simplified)
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return ErrInvalidEmail
	}

	return nil
}

// ValidateUsername validates a username format
func ValidateUsername(username string) error {
	if username == "" {
		return ErrUsernameRequired
	}

	// Username: 3-255 characters, alphanumeric, underscore, hyphen
	if len(username) < 3 || len(username) > 255 {
		return &ValidationError{
			Field:   "username",
			Message: "username must be between 3 and 255 characters",
		}
	}

	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)
	if !usernameRegex.MatchString(username) {
		return &ValidationError{
			Field:   "username",
			Message: "username can only contain letters, numbers, underscores, and hyphens",
		}
	}

	return nil
}

// Error types

// PasswordPolicyError represents a password policy violation
type PasswordPolicyError struct {
	Field   string
	Message string
}

func (e *PasswordPolicyError) Error() string {
	return e.Message
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

// Common auth-related errors
var (
	ErrInvalidPassword   = &ValidationError{Field: "password", Message: "invalid password"}
	ErrEmailRequired     = &ValidationError{Field: "email", Message: "email is required"}
	ErrUsernameRequired  = &ValidationError{Field: "username", Message: "username is required"}
	ErrInvalidEmail      = &ValidationError{Field: "email", Message: "invalid email format"}
)
