// Package usermanagement is the domain layer for operator-side user
// CRUD — list, view, update (role / disabled flag), and delete users.
// Mirrors the shape of pkg/clientservice: typed sentinel errors,
// cross-row invariant enforcement, no HTTP awareness. Handlers in
// pkg/server/control/users_handlers.go and pkg/admin_bff translate
// the sentinels to surface-appropriate codes.
//
// Why a separate package (rather than putting this on UserRepository
// directly): the cross-row invariants ("can't demote the last root")
// span LDAP + Postgres + a count query, which doesn't fit the
// per-row repository style. Keeping this here lets repository stay
// a thin SQL surface and gives one obvious place to look for
// "what happens when an operator tries to delete a user."
package usermanagement

import (
	"context"
	"errors"
	"fmt"

	"akashic/akashic/pkg/ldap"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/repository"

	"github.com/google/uuid"
)

// Sentinel errors. Handlers errors.Is()-check to map them to
// surface-appropriate codes (HTTP 4xx, CLI exit codes, etc.).
var (
	// ErrLastRoot blocks any operation that would leave the
	// deployment with zero `root` users — demote of the last root
	// or delete of the last root. Operators can't recover from a
	// rootless deployment without re-bootstrapping, so we treat
	// this as a hard cross-row invariant rather than a "are you
	// sure?" UI gate.
	ErrLastRoot = errors.New("operation would leave the deployment with no root users")

	// ErrSelfDemotion blocks an operator from demoting their own
	// account (admin → user, root → admin/user). Self-demotion is
	// a footgun: the operator might lose access to the admin UI
	// and not realize until the next session expiry. The recovery
	// path is "ask another admin to demote you" — at the cost of
	// requiring two-operator coordination, which is the right
	// trade for a rare action.
	ErrSelfDemotion = errors.New("you cannot demote your own account")

	// ErrSelfDeletion blocks an operator from deleting their own
	// account. Same reasoning as ErrSelfDemotion plus the obvious:
	// the session would terminate mid-request.
	ErrSelfDeletion = errors.New("you cannot delete your own account")
)

// Deps bundles the I/O dependencies shared by every operation —
// keeps individual function signatures short and lets callers
// (handlers, CLI) wire dependencies once.
type Deps struct {
	UserRepo *repository.UserRepository
	LDAP     *ldap.Client
}

// ListParams controls List() — pagination + simple filters. Cursor
// pagination is intentionally not implemented yet; offset is fine
// at moderate user counts. Filters are AND-combined when set.
type ListParams struct {
	// Limit caps the page size. Default 50; capped at 200 to keep
	// admin UI rendering responsive.
	Limit int
	// Offset is the row offset for paging. 0 = first page.
	Offset int
	// UserType, if non-empty, restricts the result to that role.
	UserType models.UserType
	// IsDisabled, if non-nil, filters by the disabled flag.
	IsDisabled *bool
	// MissingIdentity, if non-nil, filters to users whose LDAP
	// entry has gone missing (per the deprovisioning loop).
	MissingIdentity *bool
}

const (
	defaultListLimit = 50
	maxListLimit     = 200
)

// ListResult bundles a page of users with the total count, so the
// admin UI can show "showing X of Y" without a second query.
type ListResult struct {
	Users []*models.User
	Total int64
}

// List returns a page of users matching the filters. Total reflects
// the total matching the filters (NOT the unfiltered total) so the
// pager math is consistent with what the user sees.
func List(ctx context.Context, d Deps, p ListParams) (*ListResult, error) {
	if p.Limit <= 0 {
		p.Limit = defaultListLimit
	} else if p.Limit > maxListLimit {
		p.Limit = maxListLimit
	}
	users, total, err := d.UserRepo.ListWithFilters(ctx,
		p.Limit, p.Offset, p.UserType, p.IsDisabled, p.MissingIdentity)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return &ListResult{Users: users, Total: total}, nil
}

// Get fetches a single user by id.
func Get(ctx context.Context, d Deps, userID uuid.UUID) (*models.User, error) {
	return d.UserRepo.GetUserByID(ctx, userID)
}

// UpdateParams controls Update() — only fields the admin surface
// can change are exposed here. Pointer types so the caller can
// distinguish "leave unchanged" (nil) from "set to false" (&false).
type UpdateParams struct {
	UserType   *models.UserType
	IsDisabled *bool
	// ClientCountOffset is the per-user adjustment applied to the
	// tenant's `default_max_clients`. Signed; admin-only.
	// Phase 9e v2.
	ClientCountOffset *int
	// MFAEnabled lets admins flip the per-user email-MFA opt-in.
	// Phase 9f. Same gate as the user-side widget — caller is
	// expected to have refused enabling without a configured
	// mailer; the repo write itself doesn't enforce that here
	// because the control plane handler does the check (it has
	// the email service handle; this domain layer doesn't).
	MFAEnabled *bool
	// CallerID is the ID of the operator making the change. Used
	// for the self-demotion check and for audit (DisableUser
	// records this in disabled_by). Must be supplied for any
	// non-CLI surface; the CLI passes uuid.Nil to skip
	// self-protection (CLI has no concept of "self").
	CallerID uuid.UUID
}

// Update applies field changes + invariant checks. Order of checks
// matters: per-row validity → self-protection → last-root → write.
//
// Returns the updated user. Sentinel errors on invariant failure;
// generic wrapped errors otherwise.
func Update(ctx context.Context, d Deps, userID uuid.UUID, p UpdateParams) (*models.User, error) {
	target, err := d.UserRepo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Self-demotion guard. Only fires when the caller is changing
	// their own user_type AND the new type is "lower" than current.
	// Lower = root>admin>user. We don't block self-disable — that's
	// rare but recoverable (another admin re-enables).
	if p.UserType != nil && p.CallerID != uuid.Nil && p.CallerID == target.ID {
		if isDemotion(target.UserType, *p.UserType) {
			return nil, ErrSelfDemotion
		}
	}

	// Last-root guard. Fires when we'd remove the only root user
	// via either a type change away from root OR a disable on the
	// only root user. Disable-of-last-root is a softer footgun
	// (re-enable recovers) but still blocked: a deployment with
	// zero usable roots is broken regardless of whether the row
	// physically exists.
	willRemoveRoot := target.UserType == models.UserTypeRoot &&
		((p.UserType != nil && *p.UserType != models.UserTypeRoot) ||
			(p.IsDisabled != nil && *p.IsDisabled && !target.IsDisabled))
	if willRemoveRoot {
		count, err := d.UserRepo.CountByUserType(ctx, models.UserTypeRoot)
		if err != nil {
			return nil, fmt.Errorf("check root count: %w", err)
		}
		// Active-root count = total roots minus this row if it's
		// already disabled. Off-by-one matters: enabling the only
		// root then demoting it should be allowed only if a
		// SECOND root exists.
		activeRoots := count
		if target.IsDisabled {
			activeRoots-- // this row doesn't count toward "active"
		}
		if activeRoots <= 1 {
			return nil, ErrLastRoot
		}
	}

	// Apply changes. Each field uses its dedicated repo method so
	// the timestamps + audit columns (disabled_at, disabled_by)
	// stay populated by the existing logic.
	if p.UserType != nil && *p.UserType != target.UserType {
		if err := d.UserRepo.UpdateUserType(ctx, userID, *p.UserType); err != nil {
			return nil, fmt.Errorf("update user_type: %w", err)
		}
	}
	if p.IsDisabled != nil && *p.IsDisabled != target.IsDisabled {
		if *p.IsDisabled {
			if err := d.UserRepo.DisableUser(ctx, userID, p.CallerID); err != nil {
				return nil, fmt.Errorf("disable user: %w", err)
			}
		} else {
			if err := d.UserRepo.EnableUser(ctx, userID); err != nil {
				return nil, fmt.Errorf("enable user: %w", err)
			}
		}
	}
	if p.ClientCountOffset != nil && *p.ClientCountOffset != target.ClientCountOffset {
		if err := d.UserRepo.SetClientCountOffset(ctx, userID, *p.ClientCountOffset); err != nil {
			return nil, fmt.Errorf("set client_count_offset: %w", err)
		}
	}
	if p.MFAEnabled != nil && *p.MFAEnabled != target.MFAEnabled {
		if err := d.UserRepo.SetMFAEnabled(ctx, userID, *p.MFAEnabled); err != nil {
			return nil, fmt.Errorf("set mfa_enabled: %w", err)
		}
	}

	return d.UserRepo.GetUserByID(ctx, userID)
}

// Delete removes a user from both LDAP and Postgres. Order matters:
// LDAP first so a half-deleted state is "PG row exists, LDAP entry
// missing" — already a meaningful state the deprovisioning loop
// reasons about. The reverse order would leave "LDAP exists, PG
// missing" which JIT provisioning would then re-create.
//
// callerID is the operator's user_id (uuid.Nil from CLI) and gates
// the self-deletion check. Last-root check applies independently.
func Delete(ctx context.Context, d Deps, userID, callerID uuid.UUID) error {
	if callerID != uuid.Nil && callerID == userID {
		return ErrSelfDeletion
	}
	target, err := d.UserRepo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if target.UserType == models.UserTypeRoot {
		count, err := d.UserRepo.CountByUserType(ctx, models.UserTypeRoot)
		if err != nil {
			return fmt.Errorf("check root count: %w", err)
		}
		if count <= 1 {
			return ErrLastRoot
		}
	}

	// LDAP delete first (idempotent — Client.DeleteUserByDN treats
	// "no such object" as success). If LDAP errors with anything
	// else, abort: better to leave a stale PG row than orphan an
	// LDAP entry the operator thought was gone.
	if d.LDAP != nil && target.LdapDN != "" {
		if err := d.LDAP.DeleteUserByDN(target.LdapDN); err != nil {
			return fmt.Errorf("delete LDAP entry: %w", err)
		}
	}
	if err := d.UserRepo.DeleteUser(ctx, userID); err != nil {
		return fmt.Errorf("delete PG row: %w", err)
	}
	return nil
}

// isDemotion returns true when newType is strictly lower than oldType
// in the role hierarchy root > admin > user. Same-rank changes (which
// shouldn't normally happen, since the caller short-circuits on
// equality) and promotions return false.
func isDemotion(oldType, newType models.UserType) bool {
	return rank(oldType) > rank(newType)
}

func rank(ut models.UserType) int {
	switch ut {
	case models.UserTypeRoot:
		return 3
	case models.UserTypeAdmin:
		return 2
	case models.UserTypeUser:
		return 1
	}
	return 0
}
