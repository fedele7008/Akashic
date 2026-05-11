package mfa

import (
	"context"
	"errors"
	"fmt"

	"akashic/akashic/pkg/models"

	"gorm.io/gorm"
)

// DBClientLookup is the production clientLookup that reads
// `client_services.require_mfa` from the same gorm.DB that backs
// the rest of the application. Tests can plug a fake clientLookup
// directly without going through the DB.
type DBClientLookup struct {
	db *gorm.DB
}

// NewDBClientLookup wires the client-table reader.
func NewDBClientLookup(db *gorm.DB) *DBClientLookup {
	return &DBClientLookup{db: db}
}

// RequireMFAFor returns the per-client `require_mfa` bool. When the
// client_id can't be resolved (unknown client), returns (false, nil)
// — an unknown client at the auth gate isn't this layer's problem
// to surface; whoever called us with a bad client_id will fail in
// their own way at /authorize. We don't escalate to error so the
// MFA gate doesn't accidentally block legitimate logins on a
// transient lookup blip.
func (l *DBClientLookup) RequireMFAFor(ctx context.Context, clientID string) (bool, error) {
	var row models.ClientService
	err := l.db.WithContext(ctx).
		Select("require_mfa").
		Where("client_id = ?", clientID).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read client require_mfa: %w", err)
	}
	return row.RequireMFA, nil
}
