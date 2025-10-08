package ldap

import (
	"fmt"

	"akashic/akashic/pkg/models"
	"go.uber.org/zap"
)

// RBACService provides role-based access control functionality using LDAP groups
type RBACService struct {
	client *Client
	logger *zap.Logger
}

// NewRBACService creates a new RBAC service
func NewRBACService(client *Client, logger *zap.Logger) *RBACService {
	return &RBACService{
		client: client,
		logger: logger,
	}
}

// DetermineUserType determines the user type based on LDAP group membership
// Priority order: root > admin > user
// Returns the default type if no group membership is found
func (r *RBACService) DetermineUserType(userDN string) (models.UserType, error) {
	// Get all groups the user is a member of
	groups, err := r.client.GetUserGroups(userDN)
	if err != nil {
		r.logger.Error("failed to get user groups for RBAC",
			zap.String("user_dn", userDN),
			zap.Error(err))
		return "", fmt.Errorf("failed to get user groups: %w", err)
	}

	r.logger.Debug("checking RBAC group membership",
		zap.String("user_dn", userDN),
		zap.Int("group_count", len(groups)),
		zap.Strings("groups", groups))

	// Check group membership in priority order
	// Root has highest priority
	if contains(groups, r.client.config.RBAC.RootGroup) {
		r.logger.Info("user identified as root via RBAC",
			zap.String("user_dn", userDN),
			zap.String("group", r.client.config.RBAC.RootGroup))
		return models.UserTypeRoot, nil
	}

	// Admin has second priority
	if contains(groups, r.client.config.RBAC.AdminGroup) {
		r.logger.Info("user identified as admin via RBAC",
			zap.String("user_dn", userDN),
			zap.String("group", r.client.config.RBAC.AdminGroup))
		return models.UserTypeAdmin, nil
	}

	// User group check (may be empty if not configured)
	if r.client.config.RBAC.UserGroup != "" && contains(groups, r.client.config.RBAC.UserGroup) {
		r.logger.Info("user identified as regular user via RBAC",
			zap.String("user_dn", userDN),
			zap.String("group", r.client.config.RBAC.UserGroup))
		return models.UserTypeUser, nil
	}

	// No group membership found - use default type
	defaultType := models.UserType(r.client.config.RBAC.DefaultType)
	r.logger.Warn("no RBAC group membership found, using default type",
		zap.String("user_dn", userDN),
		zap.String("default_type", string(defaultType)),
		zap.Int("groups_checked", len(groups)))

	// Validate default type
	if !isValidUserType(defaultType) {
		r.logger.Error("invalid default user type in configuration",
			zap.String("default_type", string(defaultType)))
		return models.UserTypeUser, fmt.Errorf("invalid default user type: %s", defaultType)
	}

	return defaultType, nil
}

// AssignUserType assigns a user to the appropriate LDAP group based on their user type
func (r *RBACService) AssignUserType(userDN string, userType models.UserType) error {
	var groupDN string

	switch userType {
	case models.UserTypeRoot:
		groupDN = r.client.config.RBAC.RootGroup
	case models.UserTypeAdmin:
		groupDN = r.client.config.RBAC.AdminGroup
	case models.UserTypeUser:
		// User group is optional
		if r.client.config.RBAC.UserGroup != "" {
			groupDN = r.client.config.RBAC.UserGroup
		} else {
			r.logger.Debug("user group not configured, skipping group assignment",
				zap.String("user_dn", userDN))
			return nil
		}
	default:
		return fmt.Errorf("invalid user type: %s", userType)
	}

	r.logger.Info("assigning user to RBAC group",
		zap.String("user_dn", userDN),
		zap.String("user_type", string(userType)),
		zap.String("group_dn", groupDN))

	if err := r.client.AddUserToGroup(userDN, groupDN); err != nil {
		return fmt.Errorf("failed to add user to group: %w", err)
	}

	return nil
}

// contains checks if a slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// isValidUserType checks if a user type is valid
func isValidUserType(userType models.UserType) bool {
	switch userType {
	case models.UserTypeRoot, models.UserTypeAdmin, models.UserTypeUser:
		return true
	default:
		return false
	}
}
