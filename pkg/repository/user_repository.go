package repository

import (
	"akashic/akashic/pkg/database/gormdb"
	"akashic/akashic/pkg/models"
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// UserRepository handles user data access
type UserRepository struct {
	db     *gormdb.DB
	logger *zap.Logger
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *gormdb.DB, logger *zap.Logger) *UserRepository {
	return &UserRepository{
		db:     db,
		logger: logger,
	}
}

// CreateUser creates a new user in the database
func (r *UserRepository) CreateUser(ctx context.Context, req *models.CreateUserRequest, passwordHash string) (*models.User, error) {
	user := &models.User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: passwordHash,
		UserType:     req.UserType,
		IsActive:     true,
		IsDisabled:   false,
	}

	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	r.logger.Info("User created successfully",
		zap.String("user_id", user.ID.String()),
		zap.String("username", user.Username),
		zap.String("user_type", string(user.UserType)))

	return user, nil
}

// GetUserByID retrieves a user by ID
func (r *UserRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	var user models.User
	if err := r.db.WithContext(ctx).First(&user, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, models.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetUserByUsername retrieves a user by username
func (r *UserRepository) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	if err := r.db.WithContext(ctx).Where("username = ?", username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, models.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetUserByEmail retrieves a user by email
func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	if err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, models.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetRootUser retrieves the root user (if exists)
func (r *UserRepository) GetRootUser(ctx context.Context) (*models.User, error) {
	var user models.User
	if err := r.db.WithContext(ctx).
		Where("user_type = ? AND is_active = ?", models.UserTypeRoot, true).
		First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil // No root user exists (not an error during bootstrap)
		}
		return nil, fmt.Errorf("failed to get root user: %w", err)
	}

	return &user, nil
}

// UpdatePassword updates a user's password
func (r *UserRepository) UpdatePassword(ctx context.Context, userID uuid.UUID, newPasswordHash string) error {
	result := r.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", userID).
		Update("password_hash", newPasswordHash)

	if result.Error != nil {
		return fmt.Errorf("failed to update password: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return models.ErrUserNotFound
	}

	r.logger.Info("Password updated successfully", zap.String("user_id", userID.String()))
	return nil
}

// DisableUser disables a user account
func (r *UserRepository) DisableUser(ctx context.Context, userID uuid.UUID, disabledBy uuid.UUID) error {
	now := time.Now()
	result := r.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ? AND is_disabled = ?", userID, false).
		Updates(map[string]interface{}{
			"is_disabled": true,
			"disabled_at": &now,
			"disabled_by": &disabledBy,
		})

	if result.Error != nil {
		return fmt.Errorf("failed to disable user: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return models.ErrUserNotFound
	}

	r.logger.Warn("User disabled",
		zap.String("user_id", userID.String()),
		zap.String("disabled_by", disabledBy.String()))

	return nil
}

// EnableUser enables a previously disabled user account
func (r *UserRepository) EnableUser(ctx context.Context, userID uuid.UUID) error {
	result := r.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ? AND is_disabled = ?", userID, true).
		Updates(map[string]interface{}{
			"is_disabled": false,
			"disabled_at": nil,
			"disabled_by": nil,
		})

	if result.Error != nil {
		return fmt.Errorf("failed to enable user: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("user not found or already enabled")
	}

	r.logger.Info("User enabled", zap.String("user_id", userID.String()))
	return nil
}

// ListUsers lists all users (with pagination)
func (r *UserRepository) ListUsers(ctx context.Context, limit, offset int) ([]*models.User, error) {
	var users []*models.User

	if err := r.db.WithContext(ctx).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&users).Error; err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	return users, nil
}
