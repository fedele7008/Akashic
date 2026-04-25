package bootstrap

import (
	"akashic/akashic/pkg/auth"
	"akashic/akashic/pkg/ldap"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/repository"
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// Manager orchestrates the bootstrap process
type Manager struct {
	bootstrapRepo  *repository.BootstrapRepository
	userRepo       *repository.UserRepository
	tokenMgr       *TokenManager
	passwordPolicy *auth.PasswordPolicy
	rbacService    *ldap.RBACService
	logger         *zap.Logger
}

// NewManager creates a new bootstrap manager
func NewManager(
	bootstrapRepo *repository.BootstrapRepository,
	userRepo *repository.UserRepository,
	tokenMgr *TokenManager,
	passwordPolicy *auth.PasswordPolicy,
	rbacService *ldap.RBACService,
	logger *zap.Logger,
) *Manager {
	return &Manager{
		bootstrapRepo:  bootstrapRepo,
		userRepo:       userRepo,
		tokenMgr:       tokenMgr,
		passwordPolicy: passwordPolicy,
		rbacService:    rbacService,
		logger:         logger,
	}
}

// NeedsBootstrap checks if the system requires bootstrap
func (m *Manager) NeedsBootstrap(ctx context.Context) (bool, error) {
	status, err := m.bootstrapRepo.GetStatus(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check bootstrap status: %v", err)
	}

	needs := !status.IsComplete
	if needs {
		m.logger.Debug("Bootstrap required - root user not configured")
	}

	return needs, nil
}

// InitializeBootstrap generates a new bootstrap token
// This should be called during server startup if bootstrap is needed
func (m *Manager) InitializeBootstrap(ctx context.Context) (string, error) {
	needs, err := m.NeedsBootstrap(ctx)
	if err != nil {
		return "", err
	}

	if !needs {
		m.logger.Debug("Bootstrap not needed - already completed")
		return "", fmt.Errorf("bootstrap already completed")
	}

	// Generate new token (replaces any existing token)
	token, err := m.tokenMgr.Generate(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to generate bootstrap token: %v", err)
	}

	m.logger.Info("Bootstrap initialized successfully")
	return token, nil
}

// AttemptContext carries forensic-audit data for a CreateRootUser call.
// The handler populates this from the HTTP request before invoking the
// manager; the manager threads it into bootstrap_status on success.
type AttemptContext struct {
	// ClientCN is the Subject CN of the mTLS client cert. Empty when called
	// from a non-mTLS path (e.g. internal callers, tests).
	ClientCN string
	// RemoteIP is the source IP the request came from.
	RemoteIP string
	// AttemptsBeforeSuccess is the number of failed POSTs that preceded this
	// one (counted by a rate-limit middleware or similar). 0 if unknown.
	AttemptsBeforeSuccess int
}

// CreateRootUser creates the root user and completes the bootstrap process.
// attempt may be nil for callers without audit context (e.g. tests).
func (m *Manager) CreateRootUser(ctx context.Context, token string, req *models.CreateUserRequest, attempt *AttemptContext) (*models.User, error) {
	// Step 1: Validate token
	valid, err := m.tokenMgr.Validate(ctx, token)
	if err != nil {
		m.logger.Error("Token validation error", zap.Error(err))
		return nil, fmt.Errorf("token validation failed: %v", err)
	}

	if !valid {
		m.logger.Warn("Invalid or expired bootstrap token attempt",
			zap.String("username", req.Username),
			zap.String("email", req.Email))
		return nil, fmt.Errorf("invalid or expired bootstrap token")
	}

	// Step 2: Check bootstrap status (double-check to prevent race conditions)
	needs, err := m.NeedsBootstrap(ctx)
	if err != nil {
		return nil, err
	}

	if !needs {
		m.logger.Warn("Bootstrap already completed, rejecting root user creation attempt",
			zap.String("username", req.Username))
		return nil, fmt.Errorf("bootstrap already completed")
	}

	// Step 3: Validate username
	if err := auth.ValidateUsername(req.Username); err != nil {
		m.logger.Warn("Invalid username in root user creation",
			zap.String("username", req.Username),
			zap.Error(err))
		return nil, fmt.Errorf("username validation failed: %v", err)
	}

	// Step 4: Validate email
	if err := auth.ValidateEmail(req.Email); err != nil {
		m.logger.Warn("Invalid email in root user creation",
			zap.String("email", req.Email),
			zap.Error(err))
		return nil, fmt.Errorf("email validation failed: %v", err)
	}

	// Step 5: Validate password against policy
	if err := m.passwordPolicy.Validate(req.Password); err != nil {
		m.logger.Warn("Password policy violation in root user creation",
			zap.String("username", req.Username),
			zap.Error(err))
		return nil, fmt.Errorf("password policy violation: %v", err)
	}

	// Step 6: Force user type to root
	req.UserType = models.UserTypeRoot

	// Step 7: Create user in LDAP and database
	// Note: Password is passed in plaintext to the repository, which will
	// pass it to LDAP. LDAP will hash and store it securely.
	user, err := m.userRepo.CreateUser(ctx, req, req.Password)
	if err != nil {
		m.logger.Error("Failed to create root user",
			zap.String("username", req.Username),
			zap.String("email", req.Email),
			zap.Error(err))
		return nil, fmt.Errorf("failed to create root user: %v", err)
	}

	// Step 8: Assign root user to RBAC group
	if err := m.rbacService.AssignUserType(user.LdapDN, models.UserTypeRoot); err != nil {
		m.logger.Error("Failed to assign root user to RBAC group",
			zap.String("user_id", user.ID.String()),
			zap.String("ldap_dn", user.LdapDN),
			zap.Error(err))
		// Log warning but don't fail - user was created successfully
		// They can be manually added to the group later if needed
		m.logger.Warn("Root user created but not added to RBAC group - manual intervention may be required")
	} else {
		m.logger.Info("Root user assigned to RBAC group",
			zap.String("user_id", user.ID.String()),
			zap.String("ldap_dn", user.LdapDN),
			zap.String("user_type", string(models.UserTypeRoot)))
	}

	// Step 9: Mark bootstrap as complete (with audit context if provided)
	var audit *models.BootstrapCompletionAudit
	if attempt != nil {
		audit = &models.BootstrapCompletionAudit{
			Source:                attempt.ClientCN,
			IP:                    attempt.RemoteIP,
			AttemptsBeforeSuccess: attempt.AttemptsBeforeSuccess,
		}
	}
	if err := m.bootstrapRepo.MarkComplete(ctx, user.ID, audit); err != nil {
		m.logger.Error("Failed to mark bootstrap complete - root user created but bootstrap status not updated",
			zap.String("user_id", user.ID.String()),
			zap.Error(err))
		// Don't return error - user was created successfully
		// The system can continue operating, admin can manually fix bootstrap status if needed
	}

	// Step 10: Delete bootstrap token (no longer needed)
	if err := m.tokenMgr.Delete(ctx); err != nil {
		m.logger.Warn("Failed to delete bootstrap token after root user creation",
			zap.Error(err))
		// Don't return error - not critical
	}

	m.logger.Info("Root user created successfully - bootstrap complete",
		zap.String("user_id", user.ID.String()),
		zap.String("ldap_dn", user.LdapDN),
		zap.String("username", req.Username),
		zap.String("email", req.Email))

	// Log to security channel
	m.logger.Info("SECURITY: Root account created",
		zap.String("user_id", user.ID.String()),
		zap.String("ldap_dn", user.LdapDN),
		zap.String("username", req.Username))

	return user, nil
}

// GetBootstrapStatus returns detailed bootstrap status information
func (m *Manager) GetBootstrapStatus(ctx context.Context) (map[string]any, error) {
	status, err := m.bootstrapRepo.GetStatus(ctx)
	if err != nil {
		return nil, err
	}

	result := map[string]any{
		"is_complete": status.IsComplete,
		"created_at":  status.CreatedAt,
	}

	if status.IsComplete {
		if status.CompletedAt != nil {
			result["completed_at"] = *status.CompletedAt
		}
		if status.RootUserID != nil {
			result["root_user_id"] = status.RootUserID.String()
		}
	} else {
		// Check if token exists
		tokenExists, err := m.tokenMgr.Exists(ctx)
		if err == nil {
			result["token_exists"] = tokenExists
			if tokenExists {
				ttl, err := m.tokenMgr.GetTTL(ctx)
				if err == nil {
					result["token_ttl_seconds"] = int(ttl.Seconds())
				}
			}
		}
	}

	return result, nil
}

// RegenerateToken generates a new bootstrap token, replacing any existing
// one. The force parameter guards against accidental rotation: when force
// is false and a valid token already exists, the call returns an error
// instead of clobbering the live token. Pass force=true to override (the
// CLI exposes this via `--force`).
//
// Why this guard exists: an attacker who briefly compromises the control
// plane could rotate the token out from under a legitimate operator,
// effectively locking them out for the TTL window. Requiring an explicit
// force flag turns "regenerate" from a silent overwrite into an audit-
// loggable operator action.
func (m *Manager) RegenerateToken(ctx context.Context, force bool) (string, error) {
	needs, err := m.NeedsBootstrap(ctx)
	if err != nil {
		return "", err
	}

	if !needs {
		return "", fmt.Errorf("bootstrap already completed, cannot regenerate token")
	}

	if !force {
		exists, err := m.tokenMgr.Exists(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to check existing token: %v", err)
		}
		if exists {
			return "", fmt.Errorf("bootstrap token already exists; pass force=true to overwrite")
		}
	}

	token, err := m.tokenMgr.Generate(ctx)
	if err != nil {
		return "", err
	}

	m.logger.Warn("Bootstrap token regenerated - old token invalidated",
		zap.Bool("forced", force))

	return token, nil
}

// GetToken retrieves the current bootstrap token
func (m *Manager) GetToken(ctx context.Context) (string, error) {
	return m.tokenMgr.Get(ctx)
}

// GetTokenTTL returns the remaining time-to-live for the token
func (m *Manager) GetTokenTTL(ctx context.Context) (time.Duration, error) {
	return m.tokenMgr.GetTTL(ctx)
}
