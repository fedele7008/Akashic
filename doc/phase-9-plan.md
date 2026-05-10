# Phase 9 — Email Infrastructure

## Overview

Phase 9 adds outbound email and the four user-visible features it
unlocks. Email is **optional**: tenants without a SendGrid/SMTP
provider deploy with no email knobs set, every email-dependent
feature gracefully degrades, and the rest of Akashic keeps working
unchanged.

The four features:

1. **Email verification** — confirm a user owns their claimed
   email address. Surfaces a `User.EmailVerified` flag the rest
   of the system can gate on.
2. **Forgot-password** — login-page link, sends a 6-digit code
   with a 15-minute window, lets the user reset without contacting
   support. (Password change while signed in stays as it is —
   old-password gated, no email needed.)
3. **MFA via email** — second factor on top of password. Per-user
   opt-in AND per-client requirement; "remember this device for N
   days" with N as tenant policy. If user opts in, MFA on every
   sign-in; if a client requires MFA, MFA regardless of user opt-in.
4. **Login notifications** — per-user opt-in email when their
   account signs in.

Plus one workflow that uses email-verified-status but isn't itself
email machinery:

5. **Client-registration qualification policy** — admin can require
   developers to (a) be email-verified and/or (b) submit an approval
   request before they can register OAuth clients. Approval form
   asks for max-clients-requested + reason, mirroring the
   scope-request workflow shape.

And one related operator capability that exists regardless of email:

6. **Admin temporary password reset** — admin button on user rows
   that sets a random strong password + flips
   `User.PasswordResetRequired = true`. If email is configured, the
   temp password is mailed; if not, it's shown once in an admin
   modal. On next login, the user is forced through a password-
   reset page before any other endpoint works.

## Design principles

- **One mailer interface, many providers.** `pkg/mailer.Mailer`
  is the abstraction; SendGrid is the first concrete driver;
  SMTP/Postmark/Resend/SES slot in via a config-driven switch.
- **`nil` mailer is never observed at call sites.** When email is
  not configured, callers receive a `nopMailer` whose `Send`
  returns `ErrNotConfigured`. UX gating happens via
  `Mailer.IsConfigured()`; backend code branches on the typed error.
- **Hashed-at-rest tokens, plaintext in email only.** Verification
  tokens, password-reset codes, and MFA codes all follow the
  refresh-token pattern: SHA-256 hash stored, opaque value sent.
- **No retries at the mailer layer.** SendGrid's SDK + their server
  retry transient failures. We log + return; callers decide the
  user-visible behavior (verification: best-effort, signup
  succeeds; password-reset: hard-fail, "try again later").
- **Email is best-effort within signup.** Signup succeeds even when
  the mail send fails — we don't roll back account creation. User
  sees "we tried to email you, please use the resend button if
  you didn't receive it."
- **Conditional UX is uniform.** Every email-dependent toggle
  greys out + forces off when `mailer.IsConfigured() == false`.
  The pattern: server sends `email_configured: false` in the relevant
  endpoint; UI disables + tooltips "email service not configured."

## Mailer abstraction (Phase 9a)

### Interface

```go
type Mailer interface {
    Send(ctx context.Context, msg Message) error
    IsConfigured() bool
}

type Message struct {
    To      string
    Subject string
    HTML    string
    Text    string
}
```

### Drivers

| Driver | When | Status |
|---|---|---|
| `nopMailer` | No `EMAIL_PROVIDER` configured (or recognised) | ✅ shipped (scaffolding) |
| `sendgridMailer` | `EMAIL_PROVIDER=sendgrid` + `SENDGRID_API_KEY` set | ✅ shipped (scaffolding) |
| `smtpMailer` | `EMAIL_PROVIDER=smtp` + `SMTP_*` set | ⏳ future, easy add |
| `postmarkMailer`, `resendMailer`, `sesMailer` | future | ⏳ future, easy add |

### Configuration (env vars)

```
# Required for any provider
AKASHIC_EMAIL_PROVIDER=sendgrid          # or "smtp", "postmark", "" (= disabled)
AKASHIC_EMAIL_FROM_ADDRESS=noreply@example.com
AKASHIC_EMAIL_FROM_NAME=Acme             # optional; defaults to "Akashic"

# SendGrid-specific
AKASHIC_SENDGRID_API_KEY=SG.xxxxx        # required when PROVIDER=sendgrid

# (future) SMTP-specific
# AKASHIC_SMTP_HOST=...
# AKASHIC_SMTP_PORT=587
# AKASHIC_SMTP_USERNAME=...
# AKASHIC_SMTP_PASSWORD=...
# AKASHIC_SMTP_TLS=true
```

### Templates

Each logical email ships as a pair: `<name>.html.tmpl` +
`<name>.txt.tmpl`. Subject is the first `Subject: …` line of the
text template (Go's stdlib mail convention). Both are loaded via
`embed.FS` in `pkg/mailer/templates.go`. Templates we'll need:

- `verification` — Phase 9b
- `password_reset_code` — Phase 9c
- `temp_password` — Phase 9d
- `client_registration_approved` / `client_registration_rejected` — Phase 9e
- `mfa_code` — Phase 9f
- `login_notification` — Phase 9g

## Database schema additions

### Per-user columns (`users`)

| Column | Type | Default | Phase |
|---|---|---|---|
| `email_verified` | bool | false | (already shipped) |
| `email_verified_at` | timestamp nullable | nil | (already shipped) |
| `password_reset_required` | bool | false | 9d |
| `mfa_enabled` | bool | false | 9f |
| `login_notifications_enabled` | bool | false | 9g |
| `client_count_offset` | int (signed) | 0 | 9e v2 |

### Per-client columns (`client_services`)

| Column | Type | Default | Phase |
|---|---|---|---|
| `require_mfa` | bool | false | 9f |

### Per-tenant policy columns (`tenant_policies`)

| Column | Type | Default | Phase |
|---|---|---|---|
| `require_verified_email_for_client_registration` | bool | true | 9e v2 |
| `require_approval_for_client_registration` | bool | false | 9e v2 |
| `default_max_clients` | int | 25 | 9e v2 |
| `mfa_trusted_device_max_days` | int | 30 | 9f |

### New tables

| Table | Purpose | Phase |
|---|---|---|
| `email_verifications` | Hashed verification token, supersede-on-resend | ✅ 9b (scaffolded) |
| `password_reset_codes` | 6-digit code, hashed, 15-min TTL, attempt counter | 9c |
| `mfa_email_codes` | 6-digit code, per (user, login-attempt), short TTL | 9f |
| `mfa_trusted_devices` | Hashed device cookie, user_id, expires_at | 9f |
| `client_registration_requests` | user_id, reason, proposed client params (name/type/redirect_uris/scopes/etc.), status, reviewer fields, created_client_id | 9e v2 |

## Sub-phase split

| Phase | Feature | Roughly | Status |
|---|---|---|---|
| **9a** | Mailer foundation + templates infrastructure | ~500 LOC | ✅ shipped |
| **9a-revised** | DB-backed email config service + admin web "Email" page | ~900 LOC | ✅ shipped |
| **9b** | Email verification (send-on-signup + landing + resend + banner) | ~700 LOC | ✅ shipped |
| **9b-revised** | Verifications moved to Redis; SendGrid key encrypted at-rest | ~500 LOC | ✅ shipped |
| **9c** | Forgot-password code flow (login-page link + 6-digit + reset) | ~900 LOC | ✅ shipped |
| **9d** | Admin temporary password reset (admin button + force-reset flow) | ~600 LOC |
| **9e** | Client-registration qualification (verified-email gate + approval workflow) | ~1000 LOC |
| **9f** | MFA via email (per-user + per-client + trusted-device cookie) | ~1200 LOC |
| **9g** | Login notifications | ~300 LOC |

Total: ~5000 LOC across 7 sub-turns. Each turn is independently
testable + deployable; later turns layer additively without
rewriting earlier surfaces.

## Phase-by-phase detail

### 9a — Mailer foundation

**Goal**: every dependent feature can call `mailer.Send(ctx, msg)`
or check `mailer.IsConfigured()` without each one re-implementing
the SendGrid plumbing or the not-configured branch.

**Already on disk** (scaffolding):
- `pkg/mailer/mailer.go` — interface, nopMailer, New() factory
- `pkg/mailer/sendgrid.go` — SendGrid driver (handles ctx
  cancellation via goroutine + select)
- `pkg/mailer/templates.go` — embed.FS template renderer
- `pkg/mailer/templates/verification.{html,txt}.tmpl`
- `go.mod` — `sendgrid-go` dep added

**Still TODO**:
- Config wiring in `pkg/config/types.go` — `Email` section
- Akashic context construction wires the Mailer into both servers
- Auth-server + API-server fields + `SetMailer` setters
- Provider switch in `New()` — currently only branches on key
  presence; need to extend to switch on `Provider` field
- Startup-warning log if `Provider=sendgrid` but key empty
- `.env.example` documentation block

### 9b — Email verification

**Goal**: confirm user owns the email they signed up with. Sets
`User.EmailVerified=true`. Other features (Phase 9e) gate on this.

**Already on disk** (scaffolding):
- `pkg/models/email_verification.go` — token row schema
- `pkg/repository/email_verification_repository.go` — Create with
  supersede-on-resend, Consume with atomic CAS
- AutoMigrate registration

**Still TODO**:
- Email template (already drafted)
- Send on signup — hook into `pkg/userregistration.Register` (best-
  effort; signup doesn't fail if send fails)
- Auth-server `GET /verify-email?token=…` — landing page that
  consumes the token, flips `User.EmailVerified`, renders success/
  error template
- API-server `POST /users/me/send-verification-email` — bearer-auth
  resend; rate-limited; only allowed when `EmailVerified=false`
- Widget: `<akashic-signup>` post-success state shows "check your
  email" + a button to switch to the resend widget
- Widget: `<akashic-verify-email-banner>` (new) — renders only when
  user is signed in AND email-not-verified, offers a resend button
- Mount the banner in both reference portals (Next.js + static)

**Conditional UX**: when `mailer.IsConfigured() == false`:
- Signup completes but no email sent (silent — user sees no banner)
- "Resend verification" button hidden
- The `EmailVerified` flag stays false; downstream features (Phase
  9e) handle the not-configured branch on their side

### 9c — Forgot-password (6-digit code, 15-min TTL)

**Goal**: signed-out password reset for users who can't access
the in-profile change-password flow.

**New table**: `password_reset_codes`
- `id` (uuid PK)
- `user_id` (uuid, indexed)
- `code_hash` (bytea, SHA-256 of the 6-digit code)
- `email_sent_to` (snapshot at issue time)
- `expires_at` (timestamp, +15m)
- `attempt_count` (int, default 0; lock after N attempts)
- `consumed_at` (timestamp nullable)
- `issued_at` (timestamp)

**Auth-server flow**:
- `GET /forgot-password` — form (email input)
- `POST /forgot-password/submit` — validates email, issues code,
  sends email; supersedes any existing code (sets consumed_at on
  the prior). Always returns the same "if that email exists, we
  sent a code" message — info-leak prevention.
- `GET /forgot-password/verify` — form (code input + email pre-fill)
- `POST /forgot-password/verify-submit` — validates code, increments
  attempt_count on miss, redirects to new-password form on hit
- `GET /forgot-password/reset` — form (new password input)
- `POST /forgot-password/reset-submit` — updates LDAP, revokes all
  active refresh-token chains for the user, force-logout

**Login page**: `[Forgot password?]` link added below the password
field. Client-side: GET `/login/email-configured` (or include in
existing /login render context) to know whether to show the link
or replace it with "contact administrator."

**Rate limiting**:
- Per-IP: 3/hour on `/forgot-password/submit`
- Per-email: 5/day (prevents email-bombing a user)
- Per-code: 5 attempts then auto-consume (prevents brute force of
  the 6-digit space — 1M possibilities, 5 attempts ≈ negligible)

**Conditional UX**: when `mailer.IsConfigured() == false`:
- `/forgot-password` is not registered (404), OR registered but
  shows the "contact administrator" page
- Login page link reads "Need help signing in?" → links to the
  contact-admin page

### 9d — Admin temporary password reset

**Goal**: out-of-band password reset for any user (broken email,
locked-out admin, etc.). Always available regardless of mailer
state.

**New User column**: `password_reset_required bool` (default false)

**Admin web flow**:
- New "Reset password" button on user row in UsersPage
- Confirmation modal: "Generate a temporary password for {email}?"
- On confirm: control-plane endpoint generates random strong
  password (e.g. 24 chars, mixed-class), updates LDAP, sets
  `password_reset_required=true`, returns the plaintext
- If `mailer.IsConfigured()`: emails the temp password to user,
  modal shows "Sent to {email}" (no plaintext displayed)
- If not: modal shows the plaintext ONCE with copy-to-clipboard
  button + "this is your only chance to capture this" warning

**Auth-server flow** (forced reset):
- On successful password verify, before issuing session: check
  `User.PasswordResetRequired`. If true, redirect to
  `/forced-password-reset` page (new); session is partially
  established (cookie set with a "reset-required" claim) so the
  forced-reset page can authenticate the user.
- `/forced-password-reset` form: new password input + confirm
- On submit: updates LDAP, clears `password_reset_required`,
  upgrades the partial session to a full one. Revokes any
  existing refresh tokens for the user (defensive).
- All other auth-server / api-server endpoints check the flag
  and 403 redirect to `/forced-password-reset` until clear.

**API-server gating**: bearer-auth endpoints check the user's
`password_reset_required` flag. If true, return 403 with a
distinct error code so the widget can redirect to the auth-server's
forced-reset page.

### 9e v2 — Client-registration qualification

**Goal**: tenant-wide cap on per-user OAuth client registration,
plus an optional admin-approval router. Three knobs:
1. **default_max_clients** (int, default 25) — tenant-wide cap.
2. **require_verified_email** (bool, default true) — gate skipped
   silently when no mailer is configured.
3. **require_approval** (bool, default false) — when on, every
   client registration goes through per-attempt admin review.

**New TenantPolicy fields**:
- `require_verified_email_for_client_registration bool` (default true)
- `require_approval_for_client_registration bool` (default false)
- `default_max_clients int` (default 25)

**New User field**:
- `client_count_offset int` (signed; default 0) — admin-only
  override; effective cap = `max(0, default_max_clients + offset)`.

**Repurposed table**: `client_registration_requests` — each row
maps to ONE proposed client, holding the full create-client params
(name, type, redirect_uris, scopes, require_pkce, etc.) plus a
reason. On approve, the row's params materialize a `client_services`
row owned by the requester; the new client_id is stored on the
request for audit. Multiple pending rows per user are allowed; cap
enforcement counts (existing clients) + (pending requests).

**Workflow** (approval-required):
1. User clicks "Register a new client" in the widget.
2. Widget GET /client-registration-eligibility, opens the create
   form with a "Reason" textarea when approval is required.
3. User fills the form; submit POSTs to
   `POST /client-registration-requests`.
4. Admin reviews on the Client requests page; approve → client
   row materialized, requester emailed; reject → no client created,
   requester emailed with the decision note.

**Workflow** (approval-NOT-required):
1. Same widget; reason field hidden.
2. Submit POSTs to `POST /clients` (immediate creation).

**Cap enforcement**: `POST /clients` AND
`POST /client-registration-requests` both consult eligibility,
which compares `existing_clients + pending_requests` against
`max(0, policy.default_max_clients + user.client_count_offset)`.

**Admin web**:
- "Client registration requests" page lists the proposed client
  params per row; approve = "as proposed" (no field editing), reject
  with note for resubmit.
- Tenant Policy page: number input for `default_max_clients`,
  checkbox for `require_verified_email` (greyed when no mailer; the
  stored value is preserved so the gate becomes active automatically
  when email is later configured), checkbox for `require_approval`.
- Users page edit dialog: signed `client_count_offset` field.

**Conditional UX**: verified-email gate is silently bypassed when
no mailer is configured (the stored intent is preserved, just
inactive). Approval emails only send when configured.

### 9f — MFA via email

**Goal**: optional second factor. Per-user opt-in OR per-client
requirement (OR'd at login time). Trusted-device cookie remembers
the user's browser for N days.

**New User column**: `mfa_enabled bool`

**New ClientService column**: `require_mfa bool`

**New TenantPolicy column**: `mfa_trusted_device_max_days int`
(default 30; valid 1-365)

**New tables**:

`mfa_email_codes`:
- `id` (uuid PK)
- `user_id` (uuid)
- `client_id` (string, indexed) — which client triggered the MFA
- `code_hash` (bytea, SHA-256 of 6-digit code)
- `email_sent_to`
- `expires_at` (timestamp; +10m)
- `attempt_count` (int)
- `consumed_at` (timestamp nullable)
- `device_fingerprint_hash` (bytea, optional — links code to a
  specific browser session via the same hash trusted_devices uses)

`mfa_trusted_devices`:
- `id` (uuid PK)
- `user_id` (uuid, indexed)
- `cookie_token_hash` (bytea, SHA-256 of the cookie value)
- `label` (string; "Chrome on macOS · 10.0.0.5") — best-effort UA
  parse for the user's profile UI
- `issued_at`
- `expires_at` (timestamp; user-pickable up to policy max)
- `last_used_at` (timestamp; updated on cookie consume)
- `revoked_at` (timestamp nullable)

**Login flow rework**:
1. Existing: user submits username/password → /login validates →
   issues session → redirects to /authorize
2. New: after password validation, before issuing session:
   `mfaRequired = user.mfa_enabled || client.require_mfa`
3. If not required → existing flow
4. If required:
   a. Read trusted-device cookie (HttpOnly, Secure, SameSite=Lax)
   b. If cookie present + matches an unrevoked, unexpired
      `mfa_trusted_devices` row → bump `last_used_at`, skip MFA
   c. Else: generate code, send email, store hashed; return
      `/login/mfa` page with code-input form. (Partial session
      cookie established with "mfa-pending" claim.)
   d. User submits code → validate; on hit → optionally store
      trusted-device cookie if "remember this device" checked →
      finalise session
5. After session is full → continue OAuth flow

**User profile widget**:
- New `<akashic-mfa-settings>` widget — toggle MFA on/off
- Lists trusted devices with revoke-each + revoke-all buttons
- Greyed out when mailer not configured

**Admin web**:
- Client edit page: new "Require MFA" toggle. Per **D2**: greyed
  out when `mailer.IsConfigured() == false`, AND PATCH attempts
  to set `require_mfa=true` while no mailer exists are rejected
  with `MFA_REQUIRES_MAILER`. Existing rows with `require_mfa=true`
  in a deployment that lost its mailer fail closed at login with
  a clear error rather than silent confusion.
- Tenant Policy page: `mfa_trusted_device_max_days` input
  (greyed when no mailer)

**Conditional UX**: when no mailer, every MFA toggle greys out +
forces off. The login flow short-circuits the MFA branch entirely
(no code sends).

### 9g — Login notifications

**Goal**: opt-in "you signed in" email — anti-account-takeover hint.

**New User column**: `login_notifications_enabled bool`

**Hook**: after successful login (post-MFA), if
`user.login_notifications_enabled` AND `mailer.IsConfigured()`,
send a notification email asynchronously (best-effort; we do NOT
fail the login if send fails). Email body includes:
- Date/time
- Source IP (with reverse-DNS hostname when available)
- User-agent (best-effort device label)
- Client (which OAuth client was authenticating)
- "If this wasn't you, change your password and revoke trusted
  devices: <link to profile>"

**User profile widget**: opt-in checkbox; greyed out when no
mailer.

## Conditional behavior matrix

| Surface | Mailer configured | Mailer not configured |
|---|---|---|
| Signup → verification email | Sent (best-effort) | Skipped silently |
| User profile: "Verify email" banner | Shown until verified | Hidden (no path forward) |
| User profile: MFA toggle | Editable | Greyed off |
| User profile: Login-notification toggle | Editable | Greyed off |
| Login page: "Forgot password?" link | Active flow | "Contact administrator" stub |
| Login page: MFA prompt (when required) | Active flow | Login fails with explicit error |
| Admin: Reset-password button | Sends email | Shows once in modal |
| Admin Policy: Require-verified-email toggle | Editable | Greyed off |
| Admin Policy: Require-approval toggle | Editable | Editable (works without email) |
| Admin Policy: MFA trusted-device max days | Editable | Greyed off |
| Admin Client edit: Require-MFA toggle | Editable | Greyed off |
| Approval-workflow notification emails | Sent on approve/reject | Skipped silently |

## Resolved design decisions

The six design forks have been pinned. These are the chosen
defaults; later phases inherit them without re-litigation.

### D1 — Multi-provider switch shape: **explicit `EMAIL_PROVIDER` env var**

Decision: a single explicit env var
`AKASHIC_EMAIL_PROVIDER=sendgrid|smtp|postmark|...|""`
selects the driver. Empty string (or unset) → `nopMailer`. Each
driver consults its own additional env vars (e.g. SendGrid reads
`AKASHIC_SENDGRID_API_KEY`; future SMTP reads `AKASHIC_SMTP_*`).

Rationale: prevents the silent-routing bug where a stale
provider's env vars are still set after a switch. The explicit
switch surfaces operator intent at config-load time and makes
the active driver self-evident in logs (`mailer: sendgrid driver
active`). Auto-detect would have been forgiving but ambiguous.

Validation: `New(Config)` returns a soft error + `nopMailer` when
`Provider` is set but the driver-specific keys are missing.
Operator sees a startup warning; deploy continues in degraded mode.

### D2 — Per-client `require_mfa` when no mailer: **grey out the toggle**

Decision: when `mailer.IsConfigured() == false`, the per-client
`require_mfa` checkbox is disabled in admin web AND PATCH
attempts to set it to `true` are rejected with
`MFA_REQUIRES_MAILER`. Servers serializing existing rows with
`require_mfa=true` continue to honor them at login time, but
that login fails closed with a clear "MFA is required for this
client but the email service is not configured — contact
administrator" message rather than silent confusion.

Rationale: editable-but-broken creates a window where an
operator enables MFA on a client, removes the SendGrid key
later, and nobody can sign in. Greying out at the policy edit
surface is the simplest safe default.

### D3 — Force-reset flow session cookie: **partial-session cookie**

Decision: when password verify succeeds against a row with
`password_reset_required=true`, the auth-server issues a
restricted session cookie carrying a `mfa_pending=false,
reset_required=true` claim. The forced-reset page authenticates
via this cookie; on successful reset the cookie is upgraded to a
full session in-place (rotated session ID, claim cleared). Every
other endpoint checks the claim and 403-redirects to
`/forced-password-reset`.

Rationale: makes the forced-reset page self-contained — the user
doesn't have to re-enter the temp password. The
narrowly-scoped cookie can ONLY reach `/forced-password-reset`;
other routes that observe the claim refuse and redirect.

### D4 — Signup verification gate: **NOT added; verified-email is informational**

Decision: signup remains immediately usable (post-LDAP-bind, no
verification gate). The `User.EmailVerified` flag is set
asynchronously by the user clicking the verification link.
Phase 9e's `require_verified_email_for_client_registration`
policy is the only gate that consults the flag. There is no
`require_verified_email_for_signup` policy in this phase.

Rationale: keeps the sign-up UX low-friction by default
(matches "immediately usable" Phase 8 promise). Operators
needing strict verification can layer it as a Phase 9+
extension when there's actual demand. Today's "soft"
verification is enough for the four primary features.

### D5 — MFA trusted-device cookie scope: **host-scoped to `auth.<tenant>`**

Decision: cookie attributes:
- `Domain` = host-scoped to auth-server only (no `Domain` attribute
  set, so the browser uses the host)
- `Path` = `/` (auth-server endpoints only since the cookie isn't
  scoped beyond auth-server)
- `HttpOnly` = true
- `Secure` = true (HTTPS only)
- `SameSite` = Lax (same as the existing auth-server session cookie)

Rationale: matches the existing auth-server session cookie's
scope. A compromised first-party portal can't read this cookie
because it's never sent to portal hosts. The trade-off is that
the cookie is scoped per-tenant — operators running multiple
auth-servers would issue separate trusted-device cookies per
tenant, which is the right boundary anyway.

### D6 — Client-registration request UI: **widget submits, admin web reviews**

Decision: developers submit client-registration requests through
the portal-side `<akashic-clients>` widget (consistent with the
Phase B fix where developer-side surfaces live in widgets);
admins review pending requests through the admin-web's "Client
registration requests" page (mirrors the existing
"Scope requests" page).

Rationale: developers (client owners) hold the operational
context for the request (why they need it, how many clients);
admins (operators) hold policy authority for review.
Consistent with the role-boundary fix from Phase B and with the
existing scope-request workflow shape.

## File-by-file impact estimate

(approximate; detail finalised at each sub-phase's start)

### Phase 9a (foundation; mostly scaffolded)

- `pkg/mailer/{mailer,sendgrid,templates}.go` ✅
- `pkg/mailer/templates/*.tmpl` ✅ (verification only; rest by sub-phase)
- `pkg/config/types.go` — `EmailConfig` struct
- `pkg/akashic/core/context.go` — construct mailer; wire to servers
- `pkg/server/auth/server.go` + `pkg/server/api/server.go` — Mailer
  field + setter
- `.env.example` + `configs/config.yaml` — documented knobs

### Phase 9b (email verification)

- `pkg/models/email_verification.go` ✅
- `pkg/repository/email_verification_repository.go` ✅
- `pkg/server/auth/email_verification_handlers.go` (new) — landing
  page handler
- `pkg/server/auth/web/verify_email_result.html.tmpl` (new) —
  success/expired result page
- `pkg/server/api/email_verification_handlers.go` (new) — resend
- `pkg/server/auth/routes.go` — `/verify-email` route
- `pkg/server/api/routes.go` — `/users/me/send-verification-email`
- `pkg/userregistration/userregistration.go` — best-effort send
  on signup
- `web/widgets/src/components/akashic-signup.ts` — post-success
  shows "check your email" + resend button
- `web/widgets/src/components/akashic-verify-email-banner.ts`
  (new) — banner mounted on profile pages, drives resend

### Phase 9c (forgot password)

- `pkg/models/password_reset_code.go` (new)
- `pkg/repository/password_reset_repository.go` (new)
- `pkg/server/auth/forgot_password_handlers.go` (new) — 4-step flow
- 3 new templates (`forgot_password.html.tmpl`, `verify.html.tmpl`,
  `reset.html.tmpl`) + 1 email template (`password_reset_code`)
- Login page template — add link
- `pkg/auth/service.go` — revoke RTs on password change

### Phase 9d (admin temp password reset)

- `pkg/models/user.go` — `password_reset_required` field
- `pkg/server/control/users_handlers.go` — `POST /users/<id>/reset-password`
- `pkg/server/auth/forced_reset_handlers.go` (new) — partial-session
  + reset page
- All bearer-auth endpoints — check the flag, return 403 with a
  distinct code so widgets redirect
- `web/admin/src/components/UsersPage.tsx` — Reset button + modal
- 1 email template (`temp_password`)

### Phase 9e (client-registration qualification)

- `pkg/models/{user,tenant_policy,client_registration_request}.go`
- `pkg/repository/client_registration_request_repository.go` (new)
- `pkg/policy/policy.go` — UpdateParams new fields
- `pkg/server/control/policy_handlers.go` — bridge new fields
- `pkg/server/control/client_registration_handlers.go` (new) —
  list + approve + reject (mirrors scope_requests_handlers.go)
- `pkg/server/api/client_registration_handlers.go` (new) — submit +
  list-mine + eligibility
- `pkg/server/api/clients_handlers.go` — gate POST /clients on
  approval + max-cap; new GET `/client-registration-eligibility`
- `pkg/admin_bff/{client.go,handlers.go,server.go}` — DTOs +
  proxy handlers + routes
- `web/admin/src/components/ClientRegistrationRequestsPage.tsx` (new)
- `web/admin/src/components/PolicyPage.tsx` — qualification panel
- `web/widgets/src/components/akashic-clients.ts` — eligibility
  fetch; replace register button with request form when needed
- 2 email templates (approved + rejected notifications)

### Phase 9f (MFA via email)

- `pkg/models/{user,client_service,tenant_policy,mfa_email_code,mfa_trusted_device}.go`
- `pkg/repository/mfa_repository.go` (new)
- `pkg/server/auth/login_handlers.go` — branch into MFA flow
- `pkg/server/auth/mfa_handlers.go` (new) — code prompt + verify
- `pkg/server/auth/web/mfa_prompt.html.tmpl` (new)
- `pkg/server/api/mfa_handlers.go` (new) — user-side trusted-device
  list + revoke
- `pkg/policy/policy.go` — UpdateParams.MFATrustedDeviceMaxDays
- `web/admin/src/components/{ClientsEdit,PolicyPage}.tsx` — toggles
- `web/widgets/src/components/akashic-mfa-settings.ts` (new)
- 1 email template (`mfa_code`)

### Phase 9g (login notifications)

- `pkg/models/user.go` — `login_notifications_enabled` field
- `pkg/server/auth/login_handlers.go` — post-success send
- `web/widgets/src/components/akashic-profile.ts` — opt-in toggle
- 1 email template (`login_notification`)

## Verification & demo plan (per sub-phase)

Each sub-phase should ship with:

1. Build clean (`go build ./...`, TS `tsc --noEmit`, Vite builds)
2. Unit tests for pure logic (token gen/hash, code rate limits,
   eligibility computation)
3. End-to-end manual verify recipe in the sub-phase summary
   (which envs, which UI flow, expected emails)
4. Plan-doc update marking the sub-phase shipped

## Out of scope for Phase 9

- WebAuthn / TOTP MFA (Phase 9+)
- SAML federation (Phase 10+)
- Email DKIM/SPF documentation (operator's responsibility per
  their domain registrar; we just give them a from-address)
- Internationalised email content (single-language for now;
  template structure makes it easy to extend later)
- Per-tenant template customisation (Phase 9+; needs admin UI for
  template editing)
