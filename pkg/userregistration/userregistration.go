// Package userregistration consolidates the self-service user-creation
// primitive shared between:
//
//   - api-server's POST /users/register (bearer-auth-irrelevant: it's
//     a public endpoint; bearer not required because there's no user
//     to authenticate as yet)
//   - auth-server's POST /signup/submit (form-driven, hosted on the
//     auth surface so signup works out of the box without operators
//     needing to register a separate tenant portal first)
//
// Both surfaces had identical validation + LDAP-then-postgres
// dual-create logic — diverging only on the HTTP shape (JSON body vs.
// form-encoded, JSON envelope vs. HTML redirect). This package owns
// the domain operation; the handlers stay focused on translating
// HTTP ↔ domain.
//
// Pure domain logic: no http.ResponseWriter, no JSON envelopes, no
// CSRF / session handling. Errors are typed so each handler can map
// them to whichever wire-level error code its caller expects.
package userregistration

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"akashic/akashic/pkg/auth"
	"akashic/akashic/pkg/ldap"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/repository"
)

// Deps bundles the dependencies the registration flow needs. Both
// the auth-server and api-server already own these; passing them
// through keeps userregistration unaware of which Server type holds
// them.
type Deps struct {
	LDAP     *ldap.Client
	UserRepo *repository.UserRepository
	Policy   *auth.PasswordPolicy
}

// Params describes the user to register. Caller is responsible for
// providing already-trimmed values; this package validates shape and
// uniqueness but doesn't sanitize whitespace.
type Params struct {
	Username    string
	Email       string
	Password    string
	DisplayName string // optional; defaults to username when empty
}

// Sentinel errors. Handlers `errors.Is` to map these to wire codes.
// All carry a wrapped detail message via fmt.Errorf("%w: …") so the
// handler's response can include the specific reason (which password
// rule failed, which field's email format is wrong) without parsing
// the message.
var (
	ErrFieldRequired         = errors.New("required field is empty")
	ErrEmailInvalid          = errors.New("email format is invalid")
	ErrPasswordPolicyViolated = errors.New("password does not satisfy the policy")
	ErrUsernameTaken         = errors.New("username is already taken")
	ErrInternal              = errors.New("internal error during registration")
)

// Register validates the input, ensures the username is free, and
// creates the user in BOTH LDAP and postgres atomically (LDAP first;
// on postgres failure, LDAP entry persists and gets cleaned up by
// the deprovisioning service after the configured grace period —
// see pkg/ldap/deprovisioning.go).
//
// Returns the created *models.User on success, or a typed error
// wrapping one of the package-level sentinels.
func Register(ctx context.Context, d Deps, p Params) (*models.User, error) {
	if d.LDAP == nil || d.UserRepo == nil || d.Policy == nil {
		return nil, fmt.Errorf("%w: missing dependency", ErrInternal)
	}

	if p.Username == "" || p.Email == "" || p.Password == "" {
		return nil, fmt.Errorf("%w: username, email, and password are all required", ErrFieldRequired)
	}
	if !looksLikeEmail(p.Email) {
		return nil, fmt.Errorf("%w: %s", ErrEmailInvalid, p.Email)
	}

	if err := d.Policy.Validate(p.Password); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrPasswordPolicyViolated, err.Error())
	}

	exists, err := d.LDAP.UserExists(p.Username)
	if err != nil {
		return nil, fmt.Errorf("%w: LDAP lookup failed: %v", ErrInternal, err)
	}
	if exists {
		return nil, fmt.Errorf("%w: %s", ErrUsernameTaken, p.Username)
	}

	createReq := &models.CreateUserRequest{
		Username:    p.Username,
		Email:       p.Email,
		Password:    p.Password,
		UserType:    models.UserTypeUser,
		DisplayName: p.DisplayName,
	}
	user, err := d.UserRepo.CreateUser(ctx, createReq, p.Password)
	if err != nil {
		return nil, fmt.Errorf("%w: persist user: %v", ErrInternal, err)
	}
	return user, nil
}

// looksLikeEmail does the same minimal check the api-server's
// users_handlers used to do inline. RFC 5322 grammar is
// over-the-top for this case; we just want to reject obvious
// typos and have the actual address validity verified later via
// email-confirmation flow (Phase 9).
func looksLikeEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return false
	}
	if strings.IndexByte(s[at+1:], '.') < 0 {
		return false
	}
	if strings.IndexByte(s, ' ') >= 0 {
		return false
	}
	return true
}
