package auth

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"akashic/akashic/pkg/ldap"
	"akashic/akashic/pkg/logging"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/repository"
)

// Service handles authentication and user management
type Service struct {
	ldapClient     *ldap.Client
	rbacService    *ldap.RBACService
	userRepository *repository.UserRepository
	logger         *logging.Logger
}

// NewService creates a new authentication service
func NewService(
	ldapClient *ldap.Client,
	rbacService *ldap.RBACService,
	userRepository *repository.UserRepository,
	logger *logging.Logger,
) *Service {
	return &Service{
		ldapClient:     ldapClient,
		rbacService:    rbacService,
		userRepository: userRepository,
		logger:         logger,
	}
}

// LDAPClient returns the LDAP client this service holds. Exposed
// so callers (currently the auth-server's /signup handler) can
// build a userregistration.Deps without re-injecting ldap config
// from scratch.
func (s *Service) LDAPClient() *ldap.Client {
	return s.ldapClient
}

// UserRepository returns the user repository this service holds.
// Exposed for the same reason as LDAPClient — letting handlers
// build domain-package Deps without parallel injection paths.
func (s *Service) UserRepository() *repository.UserRepository {
	return s.userRepository
}

// AuthenticateResult contains the result of authentication
type AuthenticateResult struct {
	User        *models.User
	LDAPInfo    *ldap.UserInfo
	IsNewUser   bool // True if user was JIT provisioned
	WasRestored bool // True if user was previously missing but now restored
}

// Authenticate verifies user credentials and performs JIT provisioning if needed
// This is the primary entry point for user authentication
func (s *Service) Authenticate(ctx context.Context, username, password string) (*AuthenticateResult, error) {
	// Step 1: Authenticate against LDAP
	s.logger.Security.Info("authenticating user against LDAP",
		zap.String("username", username),
	)

	userDN, err := s.ldapClient.Authenticate(username, password)
	if err != nil {
		s.logger.Security.Warn("LDAP authentication failed",
			zap.String("username", username),
			zap.Error(err),
		)
		return nil, models.ErrInvalidCredentials
	}

	s.logger.Security.Info("LDAP authentication successful",
		zap.String("username", username),
		zap.String("dn", userDN),
	)

	// Step 2: Get user information from LDAP
	ldapInfo, err := s.ldapClient.GetUserByDN(userDN)
	if err != nil {
		s.logger.App.Error("failed to retrieve LDAP user info after authentication",
			zap.String("username", username),
			zap.String("dn", userDN),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to retrieve user information")
	}

	// Step 3: Check if user exists in PostgreSQL
	user, err := s.userRepository.GetUserByLdapDN(ctx, userDN)
	if err != nil {
		// Check if it's a "not found" error
		if err == models.ErrUserNotFound {
			// JIT Provisioning: User exists in LDAP but not in PostgreSQL
			s.logger.App.Info("user not found in database, performing JIT provisioning",
				zap.String("username", username),
				zap.String("ldap_dn", userDN),
			)

			user, err = s.jitProvisionUser(ctx, userDN, ldapInfo)
			if err != nil {
				s.logger.App.Error("JIT provisioning failed",
					zap.String("username", username),
					zap.String("ldap_dn", userDN),
					zap.Error(err),
				)
				return nil, fmt.Errorf("failed to provision user account")
			}

			s.logger.Security.Info("user provisioned via JIT",
				zap.String("user_id", user.ID.String()),
				zap.String("username", username),
				zap.String("ldap_dn", userDN),
			)

			return &AuthenticateResult{
				User:        user,
				LDAPInfo:    ldapInfo,
				IsNewUser:   true,
				WasRestored: false,
			}, nil
		}

		// Some other database error
		s.logger.App.Error("failed to query user from database",
			zap.String("username", username),
			zap.String("ldap_dn", userDN),
			zap.Error(err),
		)
		return nil, fmt.Errorf("database error during authentication")
	}

	// Step 4: Check if user was marked as missing and restore them
	wasRestored := false
	if user.MissingIdentity {
		s.logger.App.Info("user was marked as missing, restoring identity",
			zap.String("user_id", user.ID.String()),
			zap.String("ldap_dn", userDN),
		)

		// Restore user identity
		if err := s.userRepository.RestoreIdentity(ctx, user.ID); err != nil {
			s.logger.App.Error("failed to restore user identity",
				zap.String("user_id", user.ID.String()),
				zap.Error(err),
			)
			// Continue anyway - don't block authentication
		} else {
			user.MissingIdentity = false
			user.MissingIdentitySince = nil
			wasRestored = true

			s.logger.Security.Info("user identity restored",
				zap.String("user_id", user.ID.String()),
				zap.String("username", username),
			)
		}
	}

	// Step 5: Check if user is disabled
	if user.IsDisabled {
		s.logger.Security.Warn("disabled user attempted to authenticate",
			zap.String("user_id", user.ID.String()),
			zap.String("username", username),
		)
		return nil, models.ErrUserDisabled
	}

	// Step 6: Authentication successful
	s.logger.Security.Info("user authenticated successfully",
		zap.String("user_id", user.ID.String()),
		zap.String("username", username),
	)

	return &AuthenticateResult{
		User:        user,
		LDAPInfo:    ldapInfo,
		IsNewUser:   false,
		WasRestored: wasRestored,
	}, nil
}

// jitProvisionUser creates a new user in PostgreSQL from LDAP information
func (s *Service) jitProvisionUser(ctx context.Context, ldapDN string, ldapInfo *ldap.UserInfo) (*models.User, error) {
	// Determine user type based on LDAP group membership
	userType, err := s.rbacService.DetermineUserType(ldapDN)
	if err != nil {
		s.logger.App.Error("failed to determine user type from LDAP groups",
			zap.String("ldap_dn", ldapDN),
			zap.String("username", ldapInfo.Username),
			zap.Error(err))
		return nil, fmt.Errorf("failed to determine user type: %v", err)
	}

	s.logger.App.Info("determined user type for JIT provisioning",
		zap.String("ldap_dn", ldapDN),
		zap.String("username", ldapInfo.Username),
		zap.String("user_type", string(userType)))

	// Create user in PostgreSQL
	user, err := s.userRepository.CreateFromLDAP(ctx, ldapDN, userType)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	s.logger.Audit.Info("user created via JIT provisioning",
		zap.String("user_id", user.ID.String()),
		zap.String("ldap_dn", ldapDN),
		zap.String("username", ldapInfo.Username),
		zap.String("email", ldapInfo.Email),
	)

	return user, nil
}

// GetUserInfo retrieves complete user information (PostgreSQL + LDAP)
func (s *Service) GetUserInfo(ctx context.Context, userID string) (map[string]interface{}, error) {
	// This would be implemented to fetch user from PostgreSQL and enrich with LDAP data
	// Left as placeholder for future implementation
	return nil, fmt.Errorf("not yet implemented")
}
