package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// BootstrapStatus tracks whether the initial bootstrap process has been completed.
// The audit columns (CompletionSource, CompletionIP, AttemptsBeforeSuccess) are
// for forensic review if a bootstrap goes wrong; they are populated by
// MarkComplete() and otherwise unused. Phase 5.1.4.
type BootstrapStatus struct {
	ID          bool       `gorm:"primaryKey;default:true" json:"id"`
	IsComplete  bool       `gorm:"default:false;not null" json:"is_complete"`
	CompletedAt *time.Time `gorm:"index" json:"completed_at,omitempty"`
	RootUserID  *uuid.UUID `gorm:"type:uuid;index" json:"root_user_id,omitempty"`
	CreatedAt   time.Time  `gorm:"autoCreateTime;not null" json:"created_at"`

	// Audit columns -- populated when IsComplete flips to true.
	// CompletionSource records the client CN that drove the successful bootstrap
	// (e.g. "cli.akashic.local", "bff.akashic.local"). Empty in pre-Phase-5
	// rows; new rows always set it.
	CompletionSource string `gorm:"size:255" json:"completion_source,omitempty"`
	// CompletionIP records the source IP at completion time. Stored as TEXT
	// (rather than INET) to avoid driver-specific type wrangling and to
	// permit IPv6 representations natively.
	CompletionIP string `gorm:"size:64" json:"completion_ip,omitempty"`
	// AttemptsBeforeSuccess counts the number of failed POST /bootstrap/root
	// attempts (rate-limit denials, validation failures, etc.) that preceded
	// the successful one. A high value suggests an attacker was probing.
	AttemptsBeforeSuccess int `gorm:"default:0;not null" json:"attempts_before_success"`
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

// BootstrapCompletionAudit captures forensic context about who/what
// completed the bootstrap process. Lives in pkg/models so both
// pkg/repository and pkg/ldap can refer to it without creating an
// import cycle (pkg/repository already imports pkg/ldap).
type BootstrapCompletionAudit struct {
	// Source identifies the caller: client cert CN for human-driven
	// bootstrap (e.g. "cli.akashic.local", "bff.akashic.local"), or a
	// system tag like "deprovisioning-service" for auto-reconciliation.
	Source string

	// IP records the source IP at completion time. May be empty for
	// system-initiated calls.
	IP string

	// AttemptsBeforeSuccess counts failed POST /bootstrap/root attempts
	// (rate-limit denials, validation failures, etc.) preceding the
	// successful one. 0 for system-initiated calls.
	AttemptsBeforeSuccess int
}
