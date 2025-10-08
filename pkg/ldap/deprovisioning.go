package ldap

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"akashic/akashic/pkg/config"
	"akashic/akashic/pkg/logging"
	"akashic/akashic/pkg/models"
)

// DeprovisioningService manages automatic user deprovisioning
type DeprovisioningService struct {
	ldapClient    *Client
	rbacService   *RBACService
	db            *gorm.DB
	bootstrapRepo BootstrapRepository
	logger        *logging.Logger
	config        *config.LDAPDeprovisioningConfig

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// BootstrapRepository defines the interface for bootstrap operations
type BootstrapRepository interface {
	MarkComplete(ctx context.Context, rootUserID uuid.UUID) error
	Reset(ctx context.Context) error
}

// NewDeprovisioningService creates a new deprovisioning service
func NewDeprovisioningService(
	ldapClient *Client,
	rbacService *RBACService,
	db *gorm.DB,
	bootstrapRepo BootstrapRepository,
	logger *logging.Logger,
	deprovConfig *config.LDAPDeprovisioningConfig,
) *DeprovisioningService {
	return &DeprovisioningService{
		ldapClient:    ldapClient,
		rbacService:   rbacService,
		db:            db,
		bootstrapRepo: bootstrapRepo,
		logger:        logger,
		config:        deprovConfig,
	}
}

// Start begins the deprovisioning service
func (s *DeprovisioningService) Start() error {
	if !s.config.Enabled {
		s.logger.App.Info("deprovisioning service is disabled")
		return nil
	}

	s.ctx, s.cancel = context.WithCancel(context.Background())

	s.logger.App.Info("starting deprovisioning service",
		zap.Duration("sync_interval", s.config.SyncInterval),
		zap.Duration("root_deletion_threshold", s.config.RootDeletionThreshold),
		zap.Duration("admin_deletion_threshold", s.config.AdminDeletionThreshold),
		zap.Duration("user_deletion_threshold", s.config.UserDeletionThreshold),
	)

	// Run initial sync
	if err := s.Reconcile(); err != nil {
		s.logger.App.Warn("initial deprovisioning sync failed",
			zap.Error(err),
		)
	}

	// Start periodic sync
	s.wg.Add(1)
	go s.syncLoop()

	return nil
}

// Stop gracefully stops the deprovisioning service
func (s *DeprovisioningService) Stop() error {
	if s.cancel != nil {
		s.logger.App.Info("stopping deprovisioning service")
		s.cancel()
		s.wg.Wait()
		s.logger.App.Info("deprovisioning service stopped")
	}
	return nil
}

// syncLoop runs the periodic reconciliation
func (s *DeprovisioningService) syncLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if err := s.Reconcile(); err != nil {
				s.logger.App.Error("deprovisioning sync failed",
					zap.Error(err),
				)
			}
		}
	}
}

// ReconcileResult contains statistics from a reconciliation run
type ReconcileResult struct {
	TotalUsers         int
	NewlyMissing       int
	Restored           int
	Deleted            int
	Errors             int
	Duration           time.Duration
	DeletionCandidates int
}

// Reconcile performs a full reconciliation between LDAP and PostgreSQL
func (s *DeprovisioningService) Reconcile() error {
	startTime := time.Now()
	result := &ReconcileResult{}

	s.logger.App.Info("starting deprovisioning reconciliation")

	// Fetch all users from LDAP
	ldapUsers, err := s.ldapClient.ListUsers()
	if err != nil {
		return fmt.Errorf("failed to list LDAP users: %v", err)
	}

	s.logger.App.Info("fetched LDAP users",
		zap.Int("count", len(ldapUsers)),
	)

	// Fetch all users from PostgreSQL
	var dbUsers []models.User
	if err := s.db.Find(&dbUsers).Error; err != nil {
		return fmt.Errorf("failed to fetch database users: %v", err)
	}

	result.TotalUsers = len(dbUsers)
	s.logger.App.Info("fetched database users",
		zap.Int("count", result.TotalUsers),
	)

	// Process each database user
	for _, user := range dbUsers {
		if err := s.reconcileUser(&user, ldapUsers, result); err != nil {
			s.logger.App.Error("failed to reconcile user",
				zap.String("user_id", user.ID.String()),
				zap.String("ldap_dn", user.LdapDN),
				zap.Error(err),
			)
			result.Errors++
		}
	}

	// Check for root users in LDAP that aren't in the database (reverse provisioning)
	if err := s.provisionRootUsersFromLDAP(ldapUsers, dbUsers, result); err != nil {
		s.logger.App.Error("failed to provision root users from LDAP",
			zap.Error(err))
		result.Errors++
	}

	// Log summary
	result.Duration = time.Since(startTime)
	s.logger.App.Info("deprovisioning reconciliation complete",
		zap.Int("total_users", result.TotalUsers),
		zap.Int("newly_missing", result.NewlyMissing),
		zap.Int("restored", result.Restored),
		zap.Int("deletion_candidates", result.DeletionCandidates),
		zap.Int("deleted", result.Deleted),
		zap.Int("errors", result.Errors),
		zap.Duration("duration", result.Duration),
	)

	if result.Deleted > 0 {
		s.logger.Audit.Info("deprovisioning deleted users",
			zap.Int("count", result.Deleted),
		)
	}

	return nil
}

// reconcileUser reconciles a single user against LDAP
func (s *DeprovisioningService) reconcileUser(
	user *models.User,
	ldapUsers map[string]*UserInfo,
	result *ReconcileResult,
) error {
	// Check if user exists in LDAP
	_, existsInLDAP := ldapUsers[user.LdapDN]

	// Case 1: User exists in LDAP
	if existsInLDAP {
		// If user was marked as missing, restore them
		if user.MissingIdentity {
			s.logger.App.Info("restoring user found in LDAP",
				zap.String("user_id", user.ID.String()),
				zap.String("ldap_dn", user.LdapDN),
			)

			if err := s.db.Model(user).Updates(map[string]interface{}{
				"missing_identity":       false,
				"missing_identity_since": nil,
			}).Error; err != nil {
				return fmt.Errorf("failed to restore user: %v", err)
			}

			result.Restored++

			s.logger.Security.Info("user identity restored",
				zap.String("user_id", user.ID.String()),
				zap.String("ldap_dn", user.LdapDN),
			)
		}
		return nil
	}

	// Case 2: User does NOT exist in LDAP
	now := time.Now()

	// If not already marked as missing, mark them now
	if !user.MissingIdentity {
		s.logger.App.Warn("user missing from LDAP",
			zap.String("user_id", user.ID.String()),
			zap.String("ldap_dn", user.LdapDN),
		)

		if err := s.db.Model(user).Updates(map[string]interface{}{
			"missing_identity":       true,
			"missing_identity_since": now,
		}).Error; err != nil {
			return fmt.Errorf("failed to mark user as missing: %v", err)
		}

		result.NewlyMissing++

		s.logger.Security.Warn("user identity missing",
			zap.String("user_id", user.ID.String()),
			zap.String("ldap_dn", user.LdapDN),
		)

		// Update in-memory user object to reflect database changes
		user.MissingIdentity = true
		user.MissingIdentitySince = &now

		// Don't return early - continue to check deletion threshold
		// This is especially important for root users with 0s threshold
	}

	// Check if deletion threshold reached
	if user.MissingIdentitySince == nil {
		// This shouldn't happen, but handle gracefully
		s.logger.App.Warn("user marked missing but no timestamp",
			zap.String("user_id", user.ID.String()),
		)
		return nil
	}

	timeMissing := now.Sub(*user.MissingIdentitySince)
	result.DeletionCandidates++

	// Determine deletion threshold based on user type
	var deletionThreshold time.Duration
	switch user.UserType {
	case models.UserTypeRoot:
		deletionThreshold = s.config.RootDeletionThreshold
	case models.UserTypeAdmin:
		deletionThreshold = s.config.AdminDeletionThreshold
	case models.UserTypeUser:
		deletionThreshold = s.config.UserDeletionThreshold
	default:
		// Unknown user type - use user threshold as safe default
		deletionThreshold = s.config.UserDeletionThreshold
		s.logger.App.Warn("unknown user type, using user deletion threshold",
			zap.String("user_id", user.ID.String()),
			zap.String("user_type", string(user.UserType)))
	}

	// Check if deletion threshold exceeded
	if timeMissing >= deletionThreshold {
		s.logger.App.Warn("deleting user - missing for too long",
			zap.String("user_id", user.ID.String()),
			zap.String("ldap_dn", user.LdapDN),
			zap.String("user_type", string(user.UserType)),
			zap.Duration("missing_duration", timeMissing),
			zap.Duration("threshold", deletionThreshold),
		)

		// Delete the user
		if err := s.db.Delete(user).Error; err != nil {
			return fmt.Errorf("failed to delete user: %v", err)
		}

		result.Deleted++

		// If this was a root user, reset bootstrap status
		if user.UserType == models.UserTypeRoot {
			s.logger.Security.Warn("root user deleted - resetting bootstrap status",
				zap.String("user_id", user.ID.String()),
				zap.String("ldap_dn", user.LdapDN))

			ctx := context.Background()
			if err := s.bootstrapRepo.Reset(ctx); err != nil {
				s.logger.App.Error("failed to reset bootstrap status after root user deletion",
					zap.Error(err))
				// Don't fail the entire reconciliation, but log the error
			} else {
				s.logger.Security.Info("bootstrap status reset - system requires new root user")
			}
		}

		s.logger.Audit.Warn("user deleted due to missing identity",
			zap.String("user_id", user.ID.String()),
			zap.String("ldap_dn", user.LdapDN),
			zap.String("user_type", string(user.UserType)),
			zap.Duration("missing_duration", timeMissing),
			zap.Duration("threshold", deletionThreshold),
		)
	} else {
		s.logger.App.Debug("user still missing, waiting for deletion threshold",
			zap.String("user_id", user.ID.String()),
			zap.String("user_type", string(user.UserType)),
			zap.Duration("missing_duration", timeMissing),
			zap.Duration("threshold", deletionThreshold),
			zap.Duration("remaining", deletionThreshold-timeMissing),
		)
	}

	return nil
}

// provisionRootUsersFromLDAP checks for root users in LDAP that don't exist in the database
// and provisions them (reverse JIT provisioning for root users only)
func (s *DeprovisioningService) provisionRootUsersFromLDAP(
	ldapUsers map[string]*UserInfo,
	dbUsers []models.User,
	result *ReconcileResult,
) error {
	ctx := context.Background()

	// Build a map of existing DB user DNs for quick lookup
	dbUserDNs := make(map[string]bool)
	for _, user := range dbUsers {
		dbUserDNs[user.LdapDN] = true
	}

	// Check each LDAP user
	for dn, ldapUser := range ldapUsers {
		// Skip if user already exists in database
		if dbUserDNs[dn] {
			continue
		}

		// Check if this LDAP user is in the root group
		userType, err := s.rbacService.DetermineUserType(dn)
		if err != nil {
			s.logger.App.Warn("failed to determine user type for LDAP user",
				zap.String("ldap_dn", dn),
				zap.String("username", ldapUser.Username),
				zap.Error(err))
			continue
		}

		// Only auto-provision root users
		if userType != models.UserTypeRoot {
			continue
		}

		// Root user found in LDAP but not in DB - provision them
		s.logger.Security.Warn("root user found in LDAP but missing from database - auto-provisioning",
			zap.String("ldap_dn", dn),
			zap.String("username", ldapUser.Username))

		// Create user in database
		newUser := &models.User{
			LdapDN:          dn,
			UserType:        models.UserTypeRoot,
			IsDisabled:      false,
			MissingIdentity: false,
		}

		if err := s.db.WithContext(ctx).Create(newUser).Error; err != nil {
			s.logger.App.Error("failed to provision root user from LDAP",
				zap.String("ldap_dn", dn),
				zap.String("username", ldapUser.Username),
				zap.Error(err))
			return fmt.Errorf("failed to provision root user: %v", err)
		}

		// Mark bootstrap as complete
		if err := s.bootstrapRepo.MarkComplete(ctx, newUser.ID); err != nil {
			s.logger.App.Error("failed to mark bootstrap complete after provisioning root user",
				zap.String("user_id", newUser.ID.String()),
				zap.String("ldap_dn", dn),
				zap.Error(err))
			// Don't fail - user was created successfully
		}

		s.logger.Security.Info("root user auto-provisioned from LDAP",
			zap.String("user_id", newUser.ID.String()),
			zap.String("ldap_dn", dn),
			zap.String("username", ldapUser.Username))

		s.logger.Audit.Info("root user provisioned from LDAP - bootstrap marked complete",
			zap.String("user_id", newUser.ID.String()),
			zap.String("ldap_dn", dn),
			zap.String("username", ldapUser.Username))
	}

	return nil
}
