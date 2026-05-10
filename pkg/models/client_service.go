package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AuthType identifies an OAuth 2.x grant type a client is authorized
// to use. Values are the canonical OAuth spec strings (RFC 6749 §1.3,
// §4.1-§4.4) — these are the literal values clients send as
// `grant_type=` in /token requests.
//
// Phase 7 only enables AuthTypeAuthorizationCode. The other constants
// are reserved so the schema and validation logic accept them without
// migration when later phases add support.
type AuthType string

const (
	// AuthTypeAuthorizationCode — the redirect-based "code flow"
	// (RFC 6749 §4.1). Only enabled grant type in Phase 7. Used by
	// browsers, CLIs (via the device-redirect dance), and any client
	// that can hold a session.
	AuthTypeAuthorizationCode AuthType = "authorization_code"

	// AuthTypeClientCredentials — back-channel grant for service-to-
	// service auth (RFC 6749 §4.4). No user involved; the client
	// authenticates with its secret and gets a token bound to itself
	// rather than a user. Deferred to Phase 8+; useful for tenants'
	// backend-to-backend integrations.
	AuthTypeClientCredentials AuthType = "client_credentials"

	// AuthTypePassword — Resource Owner Password Credentials, "ROPC"
	// (RFC 6749 §4.3). Client collects the user's password and
	// trades it for a token. Tightly coupled to a user-trusts-client
	// relationship; OAuth 2.1 deprecates it. Deferred; we may
	// continue to refuse to implement it — under review.
	AuthTypePassword AuthType = "password"

	// AuthTypeImplicit — token returned directly in the redirect URL
	// (RFC 6749 §4.2). Deprecated in OAuth 2.1; modern guidance is
	// to use authorization-code with PKCE instead. Listed here so
	// the schema can accept a stored value even if we never enable
	// the flow.
	AuthTypeImplicit AuthType = "implicit"
)

// IsKnown reports whether s is one of the values this codebase
// recognizes. Useful at registration time to reject typos.
func (s AuthType) IsKnown() bool {
	switch s {
	case AuthTypeAuthorizationCode,
		AuthTypeClientCredentials,
		AuthTypePassword,
		AuthTypeImplicit:
		return true
	default:
		return false
	}
}

// IsEnabledInPhase7 reports whether this grant type is currently
// implemented by the auth server. Used to reject /token requests for
// grant types that the schema accepts but the code path doesn't yet
// handle. Update this list as more grants are implemented.
func (s AuthType) IsEnabledInPhase7() bool {
	return s == AuthTypeAuthorizationCode
}

// ClientService represents a registered OAuth 2.1 / OIDC client.
//
// Naming note: in Akashic terminology, an OAuth client is a "client
// service" — i.e., a service registered with the IdP that wants to
// authenticate users via Akashic. This matches the operator's mental
// model better than the OAuth-spec term "client" (which is overloaded
// with HTTP-client and many other meanings in the codebase).
//
// Two kinds of client services exist:
//
//  1. **Built-in** (BuiltIn=true): managed by akashic-server itself,
//     re-upserted on every startup. Examples (Phase 7+):
//     - akashic-admin           (admin.akashic.<domain> admin console)
//     - akashic-sample-nextjs   (Next.js reference sample; Phase 8)
//     - akashic-sample-static   (static-HTML PKCE-only sample; Phase 8b)
//     The plaintext client secret for these lives in Vault KV; only
//     its bcrypt hash is stored here.
//
//  2. **Tenant-registered** (BuiltIn=false): created via the tenant
//     management UI (Phase 8+). The client secret is generated once
//     at registration and shown to the operator; only the hash
//     persists.
//
// Phase 7 implements only built-in client services. The schema
// accommodates both shapes so Phase 8 can add tenant clients
// without migration.
type ClientService struct {
	// ClientID is the public identifier (URL-safe, immutable, e.g.
	// "akashic-admin"). Used as primary key — operators reference
	// client services by this name in audit logs and tenant configs.
	ClientID string `gorm:"primaryKey;size:255" json:"client_id"`

	// ClientSecretHash is bcrypt(client_secret). Plaintext is never
	// stored. For built-ins, the plaintext lives in Vault KV at
	// kv/akashic/oauth/clients/<client_id> and is fetched by the BFF
	// on its startup. For tenant-registered, the operator captures
	// the plaintext at creation time and stores it in their own
	// secret manager.
	ClientSecretHash string `gorm:"size:255" json:"-"`

	// Name is operator-readable; used in consent UI (Phase 8+) and
	// audit log lines.
	Name string `gorm:"size:255;not null" json:"name"`

	// RedirectURIs is the allowlist of redirect_uri values accepted
	// by /authorize. Stored as a comma-separated string for
	// simplicity; switch to a join table if we ever need >5 URIs
	// per client service.
	//
	// Match is **exact-string** per RFC 6749 §3.1.2 (no fuzzy
	// matching of paths or query strings). Mismatched URIs are
	// rejected at /authorize before ever issuing a code.
	RedirectURIs string `gorm:"type:text;not null" json:"redirect_uris"`

	// AllowedScopes is the space-separated set of scopes this client
	// service may request. Defaults to "openid profile email" — the
	// OIDC minimum. Tenant clients can request only what's listed
	// here; scopes outside this set get filtered (or rejected at
	// /authorize per the spec).
	//
	// **Maintained as the union of `RequiredScopes` and
	// `OptionalScopes`** by the create/update path — readers can
	// continue using this field as the legacy "all permitted scopes"
	// list while new code that cares about the required-vs-optional
	// distinction reads the split fields directly. See
	// `oauth.UnionScopes` for the helper.
	AllowedScopes string `gorm:"type:text;not null;default:'openid profile email'" json:"allowed_scopes"`

	// RequiredScopes is the subset of scopes this client ALWAYS
	// requests at /authorize, AND that the consent screen renders
	// as locked checkboxes (the user must grant them to sign in).
	// Empty in legacy rows → the consent rework treats AllowedScopes
	// as required for backwards compatibility.
	//
	// Invariant: RequiredScopes ⊆ tenant policy `AllowedClientScopes`.
	// Validated at create/update time; mid-flight policy tightening
	// doesn't auto-clamp existing rows but new /authorize calls do
	// re-check.
	RequiredScopes string `gorm:"type:text;not null;default:''" json:"required_scopes"`

	// OptionalScopes is the subset of scopes the client requests AND
	// the consent screen renders as user-toggleable checkboxes.
	// Granted scope set per-user = required ∪ user-checked optionals.
	//
	// Invariant: OptionalScopes ⊆ tenant `AllowedClientScopes`,
	// AND RequiredScopes ∩ OptionalScopes = ∅ (a scope is either
	// mandatory or à-la-carte; never both).
	OptionalScopes string `gorm:"type:text;not null;default:''" json:"optional_scopes"`

	// AuthTypes is the space-separated list of grant types this
	// client service is authorized to use (corresponds to OAuth's
	// `grant_type` parameter values; see the AuthType constants).
	//
	// Stored as a string for the same reason as RedirectURIs: keeps
	// the schema portable, easy to edit by hand for built-ins. Phase
	// 7 only accepts "authorization_code"; rejecting anything else
	// at registration time prevents stale rows accumulating values
	// the runtime can't honor.
	//
	// /token handler must verify (a) the requested grant_type is in
	// this list AND (b) the requested grant_type is currently
	// enabled in the codebase (AuthType.IsEnabledInPhase7).
	AuthTypes string `gorm:"type:text;not null;default:'authorization_code'" json:"auth_types"`

	// BuiltIn marks the client service as managed by akashic-server
	// itself. Built-ins are:
	//  - re-upserted on every server startup (so config changes apply)
	//  - undeletable via the tenant management API
	//  - exempt from per-tenant scope/role policy (they ARE the policy)
	BuiltIn bool `gorm:"not null;default:false" json:"built_in"`

	// RoleAllowlist, when non-empty, restricts which user_types may
	// complete an authorization flow for this client. Format is
	// space- or comma-separated user types. Empty = any authenticated
	// user may use this client service.
	//
	// Note: the auth server itself does NOT enforce this — it issues
	// tokens to anyone who passes LDAP authentication. The CLIENT
	// (e.g., admin-bff) inspects the user_type claim and decides
	// whether to set a session. This separation keeps the auth
	// server generic and lets each client service enforce its own
	// access policy.
	//
	// We persist it here anyway so it's auditable and discoverable.
	// For akashic-admin: "root,admin".
	RoleAllowlist string `gorm:"size:255" json:"role_allowlist,omitempty"`

	// RequirePKCE forces PKCE (RFC 7636) on all auth flows for this
	// client service. /authorize gates `code_challenge` on this flag.
	//
	// Invariants enforced by BeforeCreate / BeforeUpdate:
	//   - Public=true   → RequirePKCE=true (PKCE is mandatory for
	//                     public clients per OAuth 2.1 / RFC 8252).
	//   - BuiltIn=true  → RequirePKCE=true (defense-in-depth for
	//                     server-managed clients).
	//   - Public=false + BuiltIn=false (a tenant-registered BFF):
	//                     operator-configurable. Default true (best
	//                     practice); operator can opt out per-client.
	RequirePKCE bool `gorm:"not null;default:true" json:"require_pkce"`

	// Public marks the client as a public OAuth client (RFC 6749
	// §2.1) — no client_secret stored. Public clients MUST use PKCE
	// (the code_verifier check substitutes for the missing shared
	// secret). Used by browser-based SPAs and native apps that have
	// no secure place to keep a credential.
	//
	// Concrete shapes:
	//   - Public=true   (SPA, native): ClientSecretHash MUST be ""
	//                   and RequirePKCE MUST be true. /token accepts
	//                   the request without client_secret provided
	//                   PKCE verifies.
	//   - Public=false  (BFF, server-side): ClientSecretHash holds
	//                   bcrypt(secret); /token requires client_secret.
	//                   PKCE recommended but optional.
	//
	// Why this is an explicit column rather than derived from
	// `ClientSecretHash == ""`: the semantic intent ("this client
	// has no secure credential storage") is what matters for OAuth
	// flow decisions, not the accident of whether a secret happens
	// to be empty. Future auth methods (mTLS-bound clients, JWT
	// bearer assertions) may also be confidential without a stored
	// secret hash; making Public an explicit field future-proofs.
	Public bool `gorm:"not null;default:false" json:"public"`

	// Phase 8: ownership and self-service metadata for tenant-
	// registered clients. Built-in clients (BuiltIn=true) leave
	// OwnerUserID NULL — they have no human "owner."
	//
	// OwnerUserID is the user who registered the client and can
	// edit/delete/rotate-secret on it. The control plane enforces
	// this in the Phase 8 client CRUD handlers: an action is
	// allowed iff requester.id == OwnerUserID OR requester is admin
	// or root.
	//
	// Description is free-form; shown in the developer dashboard
	// and on consent screens.
	//
	// HomepageURL is optional; shown to end-users on consent screens
	// so they can recognize legitimate integrations and click
	// through to the registering app's site.
	OwnerUserID *uuid.UUID `gorm:"type:uuid;index" json:"owner_user_id,omitempty"`
	Description string     `gorm:"type:text" json:"description,omitempty"`
	HomepageURL string     `gorm:"type:text" json:"homepage_url,omitempty"`

	// IsTenantPortal marks this client as the tenant's primary
	// portal — the deployment's main consumer of Akashic, where
	// end users land for sign-up / sign-in. At most one row in
	// client_services may have this flag set; the constraint is
	// enforced by the clientservice package's create/update path
	// (pkg/clientservice) rather than via SQL, so the rejection
	// surfaces as a typed Go error with a clear message instead
	// of a generic constraint violation.
	//
	// Operator-set only — the akashic-cli `clients create
	// --tenant-portal` flag and the admin-bff create form expose
	// the toggle. The bearer-authenticated api-server endpoint
	// (used by tenant developers via the <akashic-clients> widget)
	// does NOT accept this field; developers can't self-promote
	// one of their integrations to "first-party / operator-owned."
	//
	// **Any number of rows may carry the flag** — a deployment
	// that ships multiple first-party apps (mail, calendar, drive,
	// account-management) is expected to flag each one. The
	// "primary singularity" rule that originally constrained this
	// to at-most-one was tied to the now-removed SignUpURL
	// override; with that gone, the flag is purely a trust-
	// boundary marker (first-party vs third-party).
	//
	// Today the flag drives a "first-party" badge in the admin UI
	// / CLI / widget so operators can tell their own apps apart
	// from third-party developer integrations at a glance. Phase
	// 7 (consent screen) will consume the flag as one input to
	// the consent policy — exact rule (skip-first-party vs
	// remember-on-first-grant) is a Chapter 7 design decision.
	IsTenantPortal bool `gorm:"not null;default:false;index" json:"is_tenant_portal"`

	// Per-client TTL overrides (Phase 9 prep). Nullable — nil means
	// "inherit the tenant-policy ceiling." Validated against the
	// ceiling at write time (pkg/clientservice rejects values that
	// exceed `tenant_policies.*_ttl_seconds`). At mint time
	// `oauth.ResolveTokenTTLs` takes `min(override, ceiling)` so a
	// late ceiling drop instantly clamps any pre-existing override
	// without an admin sweep across rows.
	//
	// Primary use case is testing: an operator sets a client to
	// 30-second access tokens + 90-second sliding refresh + 5-min
	// absolute refresh, and the full rotation+replay-detection
	// dance plays out in three minutes instead of three months.
	AccessTokenTTLSecondsOverride          *int `gorm:"" json:"access_token_ttl_seconds_override,omitempty"`
	RefreshTokenSlidingTTLSecondsOverride  *int `gorm:"" json:"refresh_token_sliding_ttl_seconds_override,omitempty"`
	RefreshTokenAbsoluteTTLSecondsOverride *int `gorm:"" json:"refresh_token_absolute_ttl_seconds_override,omitempty"`

	// SecretResetRequired is true when the row was created with a
	// confidential secret the requester has never seen plaintext for.
	// Phase 9e v2: approval-gated registration mints the secret at
	// approve-time inside `clientregistration.Approve`; the plaintext
	// can't be surfaced to the reviewer (it belongs to the requester),
	// so the requester needs to obtain it via the rotate-secret
	// endpoint after approval. This flag drives the widget's button
	// label switch ("Get client secret" vs "Rotate secret") and a
	// contextual hint on the clients list. Cleared on the first
	// successful rotate (the user has now seen a usable secret).
	//
	// Always false for SPA/public clients (no secret exists) and for
	// clients created via the direct POST /clients path (the secret
	// is shown on the response, so the user already saw it).
	SecretResetRequired bool `gorm:"not null;default:false" json:"secret_reset_required"`

	CreatedAt time.Time `gorm:"autoCreateTime;not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime;not null" json:"updated_at"`
}

// TableName specifies the table name for GORM. We're explicit so the
// table reflects Akashic's "client service" terminology (rather than
// GORM's default "client_services" — which actually matches, but
// being explicit prevents future model renames from quietly drifting
// the table name).
func (ClientService) TableName() string {
	return "client_services"
}

// BeforeCreate / BeforeUpdate enforce the cross-field invariants
// described on the Public + RequirePKCE fields. We could express
// these as a CHECK constraint, but a hook keeps the error path in
// Go (clearer messages) and the schema portable.
func (c *ClientService) BeforeCreate(tx *gorm.DB) error {
	c.normalize()
	return nil
}

func (c *ClientService) BeforeUpdate(tx *gorm.DB) error {
	c.normalize()
	return nil
}

func (c *ClientService) normalize() {
	// Public clients MUST use PKCE (OAuth 2.1 / RFC 8252).
	if c.Public {
		c.RequirePKCE = true
		c.ClientSecretHash = "" // public clients have no shared secret
	}
	// Built-ins always require PKCE (defense-in-depth, server-managed).
	if c.BuiltIn {
		c.RequirePKCE = true
	}
}
