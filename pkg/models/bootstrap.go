package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// BootstrapStatus tracks whether the initial bootstrap process has been completed
type BootstrapStatus struct {
	ID          bool       `gorm:"primaryKey;default:true" json:"id"`
	IsComplete  bool       `gorm:"default:false;not null" json:"is_complete"`
	CompletedAt *time.Time `gorm:"index" json:"completed_at,omitempty"`
	RootUserID  *uuid.UUID `gorm:"type:uuid;index" json:"root_user_id,omitempty"`
	CreatedAt   time.Time  `gorm:"autoCreateTime;not null" json:"created_at"`
}

// TableName specifies the table name for GORM
func (BootstrapStatus) TableName() string {
	return "bootstrap_status"
}

// BeforeCreate hook ensures only one row with id=true exists
func (b *BootstrapStatus) BeforeCreate(tx *gorm.DB) error {
	b.ID = true
	return nil
}
