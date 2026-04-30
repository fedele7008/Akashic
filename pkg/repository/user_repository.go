package repository

import (
	"akashic/akashic/pkg/database/akashic_postgres"
	"akashic/akashic/pkg/ldap"
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
	db         *akashic_postgres.DB
	ldapClient *ldap.Client
	logger     *zap.Logger
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *akashic_postgres.DB, ldapClient *ldap.Client, logger *zap.Logger) *UserRepository {
	return &UserRepository{
		db:         db,
		ldapClient: ldapClient,
		logger:     logger,
	}
}

// CreateFromLDAP creates a user from LDAP information (JIT provisioning)
// This is called during first login when user exists in LDAP but not in PostgreSQL
func (r *UserRepository) CreateFromLDAP(ctx context.Context, ldapDN string, userType models.UserType) (*models.User, error) {
	user := &models.User{
		LdapDN:          ldapDN,
		UserType:        userType,
		IsDisabled:      false,
		MissingIdentity: false,
	}

	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		return nil, fmt.Errorf("failed to create user from LDAP: %v", err)
	}

	r.logger.Info("User created from LDAP (JIT provisioning)",
		zap.String("user_id", user.ID.String()),
		zap.String("ldap_dn", ldapDN),
		zap.String("user_type", string(user.UserType)))

	return user, nil
}

// CreateUser creates a user in both LDAP and PostgreSQL.
//
// Used by:
//   - Bootstrap (root-user creation), via pkg/bootstrap/manager.go
//   - Phase 8 self-service registration (Step 1.5's POST /users/register)
//
// The flow is the same in both cases: create the LDAP entry first
// (so the entry exists before any postgres row that references its
// DN), then create the postgres metadata row. If the second step
// fails the LDAP entry is left orphaned for the deprovisioning
// service to clean up — see the rollback note below.
//
// The user_type and display name come from the request; password is
// passed in plaintext and is hashed by LDAP internally (Akashic
// never persists a hash). Empty req.DisplayName falls back to the
// username so the LDAP `cn` attribute is always populated (LDAP
// requires it on inetOrgPerson entries).
func (r *UserRepository) CreateUser(ctx context.Context, req *models.CreateUserRequest, password string) (*models.User, error) {
	// Step 1: Create user in LDAP first
	r.logger.Info("Creating user in LDAP",
		zap.String("username", req.Username),
		zap.String("email", req.Email))

	displayName := req.DisplayName
	if displayName == "" {
		// LDAP requires `cn` on inetOrgPerson; default to username
		// when the caller hasn't supplied a friendlier name.
		displayName = req.Username
	}
	ldapDN, err := r.ldapClient.CreateUser(req.Username, req.Email, displayName, password)
	if err != nil {
		return nil, fmt.Errorf("failed to create user in LDAP: %w", err)
	}

	r.logger.Info("User created in LDAP successfully",
		zap.String("username", req.Username),
		zap.String("ldap_dn", ldapDN))

	// Step 2: Create PostgreSQL record with the LDAP DN
	user := &models.User{
		LdapDN:          ldapDN,
		UserType:        req.UserType,
		IsDisabled:      false,
		MissingIdentity: false,
	}

	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		// TODO: Consider rolling back LDAP creation
		// For now, we leave the LDAP entry and fail the operation
		// The deprovisioning service will eventually clean it up
		r.logger.Error("Failed to create user in database after LDAP creation",
			zap.String("username", req.Username),
			zap.String("ldap_dn", ldapDN),
			zap.Error(err))
		return nil, fmt.Errorf("failed to create user in database: %w", err)
	}

	r.logger.Info("User created successfully in both LDAP and database",
		zap.String("user_id", user.ID.String()),
		zap.String("username", req.Username),
		zap.String("ldap_dn", ldapDN),
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
		return nil, fmt.Errorf("failed to get user: %v", err)
	}

	return &user, nil
}

// GetUserByLdapDN retrieves a user by their LDAP Distinguished Name
func (r *UserRepository) GetUserByLdapDN(ctx context.Context, ldapDN string) (*models.User, error) {
	var user models.User
	if err := r.db.WithContext(ctx).Where("ldap_dn = ?", ldapDN).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, models.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by LDAP DN: %v", err)
	}

	return &user, nil
}

// GetRootUser retrieves the root user (if exists)
func (r *UserRepository) GetRootUser(ctx context.Context) (*models.User, error) {
	var user models.User
	if err := r.db.WithContext(ctx).
		Where("user_type = ? AND is_disabled = ?", models.UserTypeRoot, false).
		First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil // No root user exists (not an error during bootstrap)
		}
		return nil, fmt.Errorf("failed to get root user: %v", err)
	}

	return &user, nil
}

// Note: Password management is handled by LDAP, not by this repository
// Passwords are stored in LDAP and updated through LDAP operations

// RestoreIdentity clears the MissingIdentity flags for a user
// This is called when a user who was marked as missing is found again in LDAP
func (r *UserRepository) RestoreIdentity(ctx context.Context, userID uuid.UUID) error {
	updateData := map[string]interface{}{
		"missing_identity":       false,
		"missing_identity_since": nil,
	}

	result := r.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", userID).
		Updates(updateData)

	if result.Error != nil {
		return fmt.Errorf("failed to restore user identity: %v", result.Error)
	}

	if result.RowsAffected == 0 {
		return models.ErrUserNotFound
	}

	r.logger.Info("User identity restored",
		zap.String("user_id", userID.String()))

	return nil
}

// DisableUser disables a user account
func (r *UserRepository) DisableUser(ctx context.Context, userID uuid.UUID, disabledBy uuid.UUID) error {
	now := time.Now()
	result := r.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ? AND is_disabled = ?", userID, false).
		Updates(map[string]any{
			"is_disabled": true,
			"disabled_at": &now,
			"disabled_by": &disabledBy,
		})

	if result.Error != nil {
		return fmt.Errorf("failed to disable user: %v", result.Error)
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
		Updates(map[string]any{
			"is_disabled": false,
			"disabled_at": nil,
			"disabled_by": nil,
		})

	if result.Error != nil {
		return fmt.Errorf("failed to enable user: %v", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("user not found or already enabled")
	}

	r.logger.Info("User enabled", zap.String("user_id", userID.String()))
	return nil
}

// DeleteUser removes a user's PG row by id. Phase 8c.2 hard-delete
// path: callers are expected to remove the LDAP entry first via
// pkg/ldap.Client.DeleteUserByDN, then call this to drop the
// metadata row. The deprovisioning loop is the orthogonal reaper
// for the "user disappeared from LDAP silently" case.
//
// gorm.ErrRecordNotFound on missing id is wrapped to
// models.ErrUserNotFound so the upstream sentinel-error pattern
// stays consistent across the repo surface.
func (r *UserRepository) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	res := r.db.WithContext(ctx).Where("id = ?", userID).Delete(&models.User{})
	if res.Error != nil {
		return fmt.Errorf("delete user: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return models.ErrUserNotFound
	}
	return nil
}

// UpdateUserType changes a user's role (root / admin / user). The
// caller is responsible for any cross-row invariants (e.g., "don't
// demote the last root") — the repo enforces only the per-row
// validity of the new value via the UserType.IsValid check.
func (r *UserRepository) UpdateUserType(ctx context.Context, userID uuid.UUID, newType models.UserType) error {
	if !newType.IsValid() {
		return fmt.Errorf("invalid user_type %q", newType)
	}
	res := r.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", userID).
		Update("user_type", string(newType))
	if res.Error != nil {
		return fmt.Errorf("update user_type: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return models.ErrUserNotFound
	}
	return nil
}

// CountByUserType returns the number of users with the given role.
// Used by usermanagement to enforce the "last root" invariant
// before demoting or deleting a root user.
func (r *UserRepository) CountByUserType(ctx context.Context, userType models.UserType) (int64, error) {
	var n int64
	if err := r.db.WithContext(ctx).Model(&models.User{}).
		Where("user_type = ?", string(userType)).
		Count(&n).Error; err != nil {
		return 0, fmt.Errorf("count by user_type: %w", err)
	}
	return n, nil
}

// ListWithFilters returns a page of users matching optional filters
// plus the total matching count (so a caller can render a pager
// without a second round-trip). Filters are AND-combined when set.
//
// Phase 8c.2 (admin user-management). The simpler unfiltered
// ListUsers stays in place for the deprovisioning loop, which has
// no use for filters.
func (r *UserRepository) ListWithFilters(
	ctx context.Context,
	limit, offset int,
	userType models.UserType,
	isDisabled *bool,
	missingIdentity *bool,
) ([]*models.User, int64, error) {
	tx := r.db.WithContext(ctx).Model(&models.User{})
	if userType != "" {
		tx = tx.Where("user_type = ?", string(userType))
	}
	if isDisabled != nil {
		tx = tx.Where("is_disabled = ?", *isDisabled)
	}
	if missingIdentity != nil {
		tx = tx.Where("missing_identity = ?", *missingIdentity)
	}

	var total int64
	if err := tx.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}

	var users []*models.User
	if err := tx.Order("created_at DESC").
		Limit(limit).Offset(offset).
		Find(&users).Error; err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}
	return users, total, nil
}

// ListUsers lists all users (with pagination)
func (r *UserRepository) ListUsers(ctx context.Context, limit, offset int) ([]*models.User, error) {
	var users []*models.User

	if err := r.db.WithContext(ctx).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&users).Error; err != nil {
		return nil, fmt.Errorf("failed to list users: %v", err)
	}

	return users, nil
}
