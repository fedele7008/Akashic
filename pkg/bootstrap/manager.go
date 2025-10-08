package bootstrap

import (
	"akashic/akashic/pkg/auth"
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
	logger         *zap.Logger
}

// NewManager creates a new bootstrap manager
func NewManager(
	bootstrapRepo *repository.BootstrapRepository,
	userRepo *repository.UserRepository,
	tokenMgr *TokenManager,
	passwordPolicy *auth.PasswordPolicy,
	logger *zap.Logger,
) *Manager {
	return &Manager{
		bootstrapRepo:  bootstrapRepo,
		userRepo:       userRepo,
		tokenMgr:       tokenMgr,
		passwordPolicy: passwordPolicy,
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

// CreateRootUser creates the root user and completes the bootstrap process
func (m *Manager) CreateRootUser(ctx context.Context, token string, req *models.CreateUserRequest) (*models.User, error) {
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

	// Step 7: Hash password
	passwordHash, err := auth.HashPassword(req.Password)
	if err != nil {
		m.logger.Error("Failed to hash password", zap.Error(err))
		return nil, fmt.Errorf("failed to hash password: %v", err)
	}

	// Step 8: Create user in database
	user, err := m.userRepo.CreateUser(ctx, req, passwordHash)
	if err != nil {
		m.logger.Error("Failed to create root user",
			zap.String("username", req.Username),
			zap.String("email", req.Email),
			zap.Error(err))
		return nil, fmt.Errorf("failed to create root user: %v", err)
	}

	// Step 9: Mark bootstrap as complete
	if err := m.bootstrapRepo.MarkComplete(ctx, user.ID); err != nil {
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
		zap.String("username", user.Username),
		zap.String("email", user.Email))

	// Log to security channel
	m.logger.Info("SECURITY: Root account created",
		zap.String("user_id", user.ID.String()),
		zap.String("username", user.Username))

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

// RegenerateToken generates a new bootstrap token (replaces the old one)
func (m *Manager) RegenerateToken(ctx context.Context) (string, error) {
	needs, err := m.NeedsBootstrap(ctx)
	if err != nil {
		return "", err
	}

	if !needs {
		return "", fmt.Errorf("bootstrap already completed, cannot regenerate token")
	}

	token, err := m.tokenMgr.Generate(ctx)
	if err != nil {
		return "", err
	}

	m.logger.Warn("Bootstrap token regenerated - old token invalidated")

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
