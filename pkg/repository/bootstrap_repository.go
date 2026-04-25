package repository

import (
	"akashic/akashic/pkg/database/akashic_postgres"
	"akashic/akashic/pkg/models"
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// BootstrapStatus represents the bootstrap completion status
type BootstrapStatus struct {
	IsComplete  bool
	CompletedAt *time.Time
	RootUserID  *uuid.UUID
	CreatedAt   time.Time
}

// BootstrapRepository handles bootstrap status data access
type BootstrapRepository struct {
	db     *akashic_postgres.DB
	logger *zap.Logger
}

// NewBootstrapRepository creates a new bootstrap repository
func NewBootstrapRepository(db *akashic_postgres.DB, logger *zap.Logger) *BootstrapRepository {
	return &BootstrapRepository{
		db:     db,
		logger: logger,
	}
}

// GetStatus retrieves the current bootstrap status
func (r *BootstrapRepository) GetStatus(ctx context.Context) (*BootstrapStatus, error) {
	var status models.BootstrapStatus
	if err := r.db.WithContext(ctx).
		Where("id = ?", true).
		First(&status).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			r.logger.Error("Bootstrap status row not found - database may not be initialized")
			return nil, fmt.Errorf("bootstrap status not found - run migrations first")
		}
		return nil, fmt.Errorf("failed to get bootstrap status: %v", err)
	}

	return &BootstrapStatus{
		IsComplete:  status.IsComplete,
		CompletedAt: status.CompletedAt,
		RootUserID:  status.RootUserID,
		CreatedAt:   status.CreatedAt,
	}, nil
}

// MarkComplete marks the bootstrap process as completed.
// This is an idempotent operation - safe to call multiple times.
// audit may be nil for callers without forensic context (e.g. tests);
// in that case the audit columns are left at their zero values.
//
// The audit type lives in pkg/models because both pkg/repository and
// pkg/ldap need to reference it (pkg/ldap's deprovisioning service also
// calls MarkComplete during JIT root provisioning). pkg/ldap can't
// import pkg/repository (would be a cycle), so the shared type lives
// in models, which neither side imports for anything other than data.
func (r *BootstrapRepository) MarkComplete(ctx context.Context, rootUserID uuid.UUID, audit *models.BootstrapCompletionAudit) error {
	now := time.Now()
	updates := map[string]any{
		"is_complete":  true,
		"completed_at": &now,
		"root_user_id": &rootUserID,
	}
	if audit != nil {
		updates["completion_source"] = audit.Source
		updates["completion_ip"] = audit.IP
		updates["attempts_before_success"] = audit.AttemptsBeforeSuccess
	}
	result := r.db.WithContext(ctx).
		Model(&models.BootstrapStatus{}).
		Where("id = ? AND is_complete = ?", true, false).
		Updates(updates)

	if result.Error != nil {
		return fmt.Errorf("failed to mark bootstrap complete: %v", result.Error)
	}

	if result.RowsAffected == 0 {
		// Check if already completed
		status, err := r.GetStatus(ctx)
		if err != nil {
			return fmt.Errorf("failed to verify bootstrap status: %v", err)
		}

		if status.IsComplete {
			r.logger.Warn("Bootstrap already completed",
				zap.Time("completed_at", *status.CompletedAt),
				zap.String("root_user_id", status.RootUserID.String()))
			return fmt.Errorf("bootstrap already completed")
		}

		return fmt.Errorf("failed to update bootstrap status")
	}

	logFields := []zap.Field{zap.String("root_user_id", rootUserID.String())}
	if audit != nil {
		logFields = append(logFields,
			zap.String("source", audit.Source),
			zap.String("ip", audit.IP),
			zap.Int("attempts_before_success", audit.AttemptsBeforeSuccess))
	}
	r.logger.Info("Bootstrap marked as complete", logFields...)

	return nil
}

// IsComplete checks if bootstrap has been completed
func (r *BootstrapRepository) IsComplete(ctx context.Context) (bool, error) {
	status, err := r.GetStatus(ctx)
	if err != nil {
		return false, err
	}
	return status.IsComplete, nil
}

// Reset resets the bootstrap status (DANGEROUS - only for testing/recovery)
func (r *BootstrapRepository) Reset(ctx context.Context) error {
	r.logger.Warn("DANGEROUS: Resetting bootstrap status")

	if err := r.db.WithContext(ctx).
		Model(&models.BootstrapStatus{}).
		Where("id = ?", true).
		Updates(map[string]any{
			"is_complete":  false,
			"completed_at": nil,
			"root_user_id": nil,
		}).Error; err != nil {
		return fmt.Errorf("failed to reset bootstrap status: %v", err)
	}

	r.logger.Warn("Bootstrap status reset successfully")
	return nil
}
