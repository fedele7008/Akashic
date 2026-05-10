// Package clientregistration owns the Phase 9e v2 qualification
// workflow:
//
//   - Eligibility: live computation of "may this user register
//     another client right now", combining the verified-email gate,
//     the per-user effective cap (tenant default + user offset),
//     and an `approval_required` route flag for the widget.
//   - Submission: when the tenant policy requires approval, the
//     widget POSTs the proposed client params here; the service
//     stores them on a pending `client_registration_requests` row.
//   - Approval/rejection: an admin reviews. On approve, the service
//     atomically materializes a `client_services` row from the
//     stored params and stamps the request as approved. On reject,
//     no client is created; the row stays for audit.
//
// Two key design choices:
//
//  1. Approval is a *router*, not a *gate*. With approval enabled,
//     the user can always start the flow — they just submit
//     through the request endpoint instead of /clients. The
//     service's `Eligible` field reflects whether the user could
//     act *at all* (not over cap, email verified if required) —
//     route choice is a separate `ApprovalRequired` field the
//     widget reads independently.
//
//  2. Pending requests count against the cap. Effective cap =
//     `max(0, policy.default_max_clients + user.client_count_offset)`.
//     Eligibility compares it against (existing clients) + (pending
//     requests). Without this, an approval-required deployment
//     would let a user queue 1000 pending rows and DoS the
//     reviewer.
package clientregistration

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"akashic/akashic/pkg/clientservice"
	"akashic/akashic/pkg/mailer"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/oauth"
	"akashic/akashic/pkg/policy"
	"akashic/akashic/pkg/repository"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Eligibility is the wire shape returned by GET
// /client-registration-eligibility. Read by the widget to decide
// whether to render the create form, the cap-reached stub, the
// verify-email stub, and (orthogonally) whether to POST to /clients
// or to /client-registration-requests.
type Eligibility struct {
	// VerifiedEmailRequired reflects the live tenant policy AND the
	// mailer state — it's reported true ONLY when the policy bool
	// is on AND a mailer is configured. With no mailer, the gate
	// has no path to satisfy, so eligibility silently treats it as
	// off; we surface that by reporting `false` here so the widget
	// doesn't render a confusing "verify your email" stub.
	VerifiedEmailRequired bool `json:"verified_email_required"`

	// ApprovalRequired reflects the live tenant policy. The widget
	// uses this to decide whether to POST the create form to
	// /clients (immediate) or /client-registration-requests
	// (pending review). Independent of `Eligible` — a user can be
	// eligible to *start* a registration while the registration
	// itself routes through approval.
	ApprovalRequired bool `json:"approval_required"`

	// Eligible answers "may this user start a client-registration
	// flow right now". True when verify-email gate passes (or is
	// inactive) AND the user is below their effective cap.
	// `ApprovalRequired` does NOT figure into Eligible.
	Eligible bool `json:"eligible"`

	// Missing is the list of stable string codes the widget keys
	// off to render specific stubs. Recognised:
	//   "email_verified" — verified-email required and unverified
	//   "cap_reached"    — at or above the effective cap
	// Empty when Eligible is true.
	Missing []string `json:"missing,omitempty"`

	// EffectiveMaxClients is the user's live cap:
	// `max(0, policy.default_max_clients + user.client_count_offset)`.
	// Surfaced so the widget can render "5 of 25 used".
	EffectiveMaxClients int `json:"effective_max_clients"`

	// CurrentClientCount is the number of clients_services rows
	// the user already owns.
	CurrentClientCount int64 `json:"current_client_count"`

	// PendingRequestCount is the number of pending requests the
	// user has. (Existing + Pending) is what the cap is compared
	// against. Surfaced so the widget can show "3 pending review"
	// alongside the current count.
	PendingRequestCount int64 `json:"pending_request_count"`

	// MailerConfigured tells the widget whether to expect approval/
	// rejection emails — drives copy on the request-submitted panel
	// ("we'll email you" vs "ask your admin").
	MailerConfigured bool `json:"mailer_configured"`
}

// SubmitParams is the user-facing submission shape. Mirrors
// `clientservice.CreateParams` minus the owner (which the service
// fills from the bearer token) and minus IsTenantPortal (operator-
// only; never threaded through the user-facing path).
type SubmitParams struct {
	UserID         uuid.UUID
	Reason         string
	Name           string
	Description    string
	HomepageURL    string
	ClientType     string // "WEB" | "SPA"
	RedirectURIs   string
	RequiredScopes string
	OptionalScopes string
	RequirePKCE    bool
}

// Service bundles the workflow's dependencies. Held by both the
// api-server (eligibility + submit) and the control-server
// (approve/reject). Methods are safe for concurrent use.
type Service struct {
	db        *gorm.DB
	requests  *repository.ClientRegistrationRequestRepository
	users     *repository.UserRepository
	policySvc *policy.Service
	mailer    mailer.Mailer
	logger    *zap.Logger

	// loginURLBase resolves the externally-reachable login URL
	// prefix, used in approval/rejection emails. Optional; nil
	// just omits the link from the email.
	loginURLBase func(context.Context) string
}

// Deps is the field bag NewService accepts.
type Deps struct {
	DB           *gorm.DB
	Requests     *repository.ClientRegistrationRequestRepository
	Users        *repository.UserRepository
	PolicySvc    *policy.Service
	Mailer       mailer.Mailer
	Logger       *zap.Logger
	LoginURLBase func(context.Context) string
}

func NewService(d Deps) *Service {
	return &Service{
		db:           d.DB,
		requests:     d.Requests,
		users:        d.Users,
		policySvc:    d.PolicySvc,
		mailer:       d.Mailer,
		logger:       d.Logger,
		loginURLBase: d.LoginURLBase,
	}
}

// ─── Eligibility ──────────────────────────────────────────────────

// CheckEligibility computes the user's current eligibility state.
// Pure read; no side effects. Safe to poll.
func (s *Service) CheckEligibility(ctx context.Context, userID uuid.UUID) (*Eligibility, error) {
	pol, err := s.policySvc.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("read tenant policy: %w", err)
	}
	user, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("read user: %w", err)
	}

	count, err := s.countOwnedClients(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("count owned clients: %w", err)
	}
	pendingCount, err := s.requests.CountPendingForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("count pending requests: %w", err)
	}

	effectiveCap := pol.DefaultMaxClients + user.ClientCountOffset
	if effectiveCap < 0 {
		effectiveCap = 0
	}

	mailerOn := s.mailer != nil && s.mailer.IsConfigured()

	out := &Eligibility{
		// Surface "required" only when the gate would actually
		// fire (policy on AND mailer present). With no mailer the
		// gate is silently bypassed — telling the widget it's
		// required would just produce a stuck "verify email" stub.
		VerifiedEmailRequired: pol.RequireVerifiedEmailForClientRegistration && mailerOn,
		ApprovalRequired:      pol.RequireApprovalForClientRegistration,
		EffectiveMaxClients:   effectiveCap,
		CurrentClientCount:    count,
		PendingRequestCount:   pendingCount,
		MailerConfigured:      mailerOn,
	}

	missing := []string{}
	if out.VerifiedEmailRequired && !user.EmailVerified {
		missing = append(missing, "email_verified")
	}
	if count+pendingCount >= int64(effectiveCap) {
		missing = append(missing, "cap_reached")
	}
	out.Missing = missing
	out.Eligible = len(missing) == 0
	return out, nil
}

func (s *Service) countOwnedClients(ctx context.Context, userID uuid.UUID) (int64, error) {
	var n int64
	err := s.db.WithContext(ctx).
		Model(&models.ClientService{}).
		Where("owner_user_id = ?", userID).
		Count(&n).Error
	return n, err
}

// ListByUser returns the user's request history.
func (s *Service) ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.ClientRegistrationRequest, error) {
	return s.requests.ListByUser(ctx, userID)
}

// ─── Submission ───────────────────────────────────────────────────

// ErrInvalidRequest fires on per-field validity failures; wrapped
// with a specific reason. Handlers errors.Is-check it to map to
// VALIDATION_FAILED.
var ErrInvalidRequest = errors.New("invalid client-registration request")

// ErrCapReached fires when the user is already at their effective
// cap (current + pending). Handlers map to 409 CAP_REACHED.
var ErrCapReached = errors.New("client cap reached")

// Submit creates a pending `client_registration_requests` row with
// the user's proposed client params + reason. Caller (api-server)
// is responsible for ensuring the bearer is first-party; this
// service layer validates the params shape and the cap.
//
// Validation here re-runs the cap check (so a race between two
// concurrent submits can't both squeak through) plus the param
// shape check that POST /clients also runs in the direct path.
func (s *Service) Submit(ctx context.Context, p SubmitParams) (*models.ClientRegistrationRequest, error) {
	reason := strings.TrimSpace(p.Reason)
	if reason == "" {
		return nil, fmt.Errorf("%w: reason is required", ErrInvalidRequest)
	}
	if len(reason) > 2048 {
		return nil, fmt.Errorf("%w: reason exceeds 2048 characters", ErrInvalidRequest)
	}
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalidRequest)
	}
	clientType := strings.ToUpper(strings.TrimSpace(p.ClientType))
	if clientType != "WEB" && clientType != "SPA" {
		return nil, fmt.Errorf("%w: client_type must be 'WEB' or 'SPA'", ErrInvalidRequest)
	}
	redirects := strings.TrimSpace(p.RedirectURIs)
	if redirects == "" {
		return nil, fmt.Errorf("%w: redirect_uris is required", ErrInvalidRequest)
	}

	// Re-check cap so two concurrent submits can't both pass.
	elig, err := s.CheckEligibility(ctx, p.UserID)
	if err != nil {
		return nil, fmt.Errorf("recheck eligibility: %w", err)
	}
	for _, m := range elig.Missing {
		if m == "cap_reached" {
			return nil, ErrCapReached
		}
	}

	row := &models.ClientRegistrationRequest{
		UserID:         p.UserID,
		Reason:         reason,
		Name:           name,
		Description:    p.Description,
		HomepageURL:    p.HomepageURL,
		ClientType:     clientType,
		RedirectURIs:   redirects,
		RequiredScopes: oauth.ParseScopeSet(p.RequiredScopes).String(),
		OptionalScopes: oauth.ParseScopeSet(p.OptionalScopes).String(),
		RequirePKCE:    p.RequirePKCE,
	}
	if err := s.requests.Create(ctx, row); err != nil {
		return nil, err
	}
	s.logger.Info("client-registration request submitted",
		zap.String("user_id", p.UserID.String()),
		zap.String("name", name),
		zap.String("client_type", clientType))
	return row, nil
}

// ─── Review ───────────────────────────────────────────────────────

// ApproveParams is the reviewer-facing approval body. There's no
// "edit-on-approve" — the reviewer accepts the proposed params
// as-is or rejects with a note instructing the user to resubmit.
// Keeping this surface narrow simplifies the audit trail (the
// stored params on the request row are exactly what was applied).
type ApproveParams struct {
	RequestID            uuid.UUID
	ReviewerID           uuid.UUID
	DecisionNote         string
	RequesterEmail       string
	RequesterDisplayName string
}

// RejectParams is the reviewer-facing rejection body.
type RejectParams struct {
	RequestID            uuid.UUID
	ReviewerID           uuid.UUID
	DecisionNote         string
	RequesterEmail       string
	RequesterDisplayName string
}

// Approve atomically materializes the proposed client and marks
// the request approved.
//
// Order of operations (intentional):
//  1. Read the pending row. (Pre-check; saves a wasted client
//     create if the row is gone or already reviewed.)
//  2. Create the `client_services` row owned by the requester.
//     Public clients have no secret; confidential clients return
//     a one-time secret on the response — but we DON'T surface
//     that secret to the reviewer (it's the requester's data).
//     The requester rotates via the /rotate-secret endpoint after
//     approval if they need a new secret.
//  3. Atomic UPDATE the request row from pending → approved with
//     the new client_id stored. If the UPDATE matches zero rows
//     (concurrent reviewer beat us), we DELETE the just-created
//     client to avoid orphaning a client the requester didn't
//     intend.
//
// Step 3's rollback isn't strictly transactional (we'd need a
// cross-table txn), but the failure mode is rare enough (two
// reviewers approving the same request simultaneously) and the
// orphan-cleanup is straightforward. If the cleanup fails we log
// loudly so an operator can reconcile.
func (s *Service) Approve(ctx context.Context, p ApproveParams) (*models.ClientRegistrationRequest, error) {
	pre, err := s.requests.Get(ctx, p.RequestID)
	if err != nil {
		return nil, err
	}
	if pre.Status != models.ClientRegRequestPending {
		return nil, repository.ErrClientRegRequestNotFound
	}

	owner := pre.UserID
	createParams := clientservice.CreateParams{
		Name:           pre.Name,
		Description:    pre.Description,
		HomepageURL:    pre.HomepageURL,
		Public:         pre.ClientType == "SPA",
		RequirePKCE:    pre.RequirePKCE,
		RedirectURIs:   pre.RedirectURIs,
		AllowedScopes:  oauth.UnionScopes(pre.RequiredScopes, pre.OptionalScopes),
		RequiredScopes: pre.RequiredScopes,
		OptionalScopes: pre.OptionalScopes,
		OwnerUserID:    &owner,
	}
	created, err := clientservice.Create(ctx, s.db, createParams)
	if err != nil {
		return nil, fmt.Errorf("materialize client from request: %w", err)
	}

	row, err := s.requests.ApprovePending(ctx, p.RequestID, p.ReviewerID,
		p.DecisionNote, created.Client.ClientID)
	if err != nil {
		// Concurrent reviewer beat us. Drop the orphan client to
		// keep ownership consistent with the surviving request row.
		if delErr := s.db.WithContext(ctx).
			Where("client_id = ?", created.Client.ClientID).
			Delete(&models.ClientService{}).Error; delErr != nil {
			s.logger.Error("approve race: orphan client delete failed",
				zap.String("client_id", created.Client.ClientID),
				zap.Error(delErr))
		}
		return nil, err
	}

	s.logger.Info("client-registration request approved",
		zap.String("user_id", row.UserID.String()),
		zap.String("request_id", row.ID.String()),
		zap.String("reviewer_id", p.ReviewerID.String()),
		zap.String("created_client_id", created.Client.ClientID))

	s.sendDecisionEmail(ctx, "client_registration_approved",
		p.RequesterEmail, p.RequesterDisplayName,
		map[string]any{
			"DecisionNote": p.DecisionNote,
			"ClientName":   pre.Name,
		})
	return row, nil
}

// Reject transitions the request to `rejected` and (best-effort)
// emails the user. No client row is created.
func (s *Service) Reject(ctx context.Context, p RejectParams) (*models.ClientRegistrationRequest, error) {
	row, err := s.requests.RejectPending(ctx, p.RequestID, p.ReviewerID, p.DecisionNote)
	if err != nil {
		return nil, err
	}
	s.logger.Info("client-registration request rejected",
		zap.String("user_id", row.UserID.String()),
		zap.String("request_id", row.ID.String()),
		zap.String("reviewer_id", p.ReviewerID.String()))
	s.sendDecisionEmail(ctx, "client_registration_rejected",
		p.RequesterEmail, p.RequesterDisplayName,
		map[string]any{
			"DecisionNote": p.DecisionNote,
			"ClientName":   row.Name,
		})
	return row, nil
}

// sendDecisionEmail renders + dispatches the approval or rejection
// template. Best-effort: failures log at App-Warn but never surface
// because the state change is the contract; the email is courtesy.
func (s *Service) sendDecisionEmail(ctx context.Context, template, toEmail, displayName string, extra map[string]any) {
	if s.mailer == nil || !s.mailer.IsConfigured() {
		return
	}
	if toEmail == "" {
		s.logger.Info("client-registration: skipping decision email — no recipient",
			zap.String("template", template))
		return
	}
	dn := displayName
	if dn == "" {
		dn = toEmail
		if at := strings.IndexByte(dn, '@'); at > 0 {
			dn = dn[:at]
		}
	}
	loginURL := ""
	if s.loginURLBase != nil {
		if base := s.loginURLBase(ctx); base != "" {
			loginURL = strings.TrimRight(base, "/") + "/login"
		}
	}
	data := map[string]any{
		"TenantName":  "Akashic",
		"DisplayName": dn,
		"LoginURL":    loginURL,
	}
	for k, v := range extra {
		data[k] = v
	}
	msg, err := mailer.Render(template, data)
	if err != nil {
		s.logger.Warn("client-registration: render decision email failed",
			zap.String("template", template), zap.Error(err))
		return
	}
	msg.To = toEmail
	if err := s.mailer.Send(ctx, msg); err != nil {
		s.logger.Warn("client-registration: send decision email failed",
			zap.String("template", template),
			zap.String("to", toEmail), zap.Error(err))
		return
	}
}
