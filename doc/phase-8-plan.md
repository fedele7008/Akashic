# Phase 8 Plan — Public Tenant Portal (Next.js)

> **Status**: planning. This document is the design/intent for Phase
> 8 work; revisions get captured in `phase-8-revision.md` after the
> phase ships.
>
> **Predecessor**: Phase 7 shipped a complete OAuth 2.1 + OIDC IdP plus
> an admin-only management surface (admin-bff). Phase 8 adds the
> *tenant-side* user-facing surface: where people sign up, manage
> their profile, and (if they're developers) register OAuth clients
> to integrate with the deployment.
>
> **Big-picture sentence**: by the end of Phase 8, the deployment will
> have a public website at the **root domain** (e.g.
> `akashic.<your-domain>.com`) where end-users register and manage
> themselves, and where developers register OAuth clients to integrate
> their apps.

## Goals & Non-goals

### Goals

1. **Public self-service user registration** — anyone visiting the
   portal can create an account (subject to operator policy).
2. **User profile management** — change email, password, display
   name, view/manage active sessions.
3. **Self-service OAuth client registration** — a developer registers
   an OAuth client through a web form, gets a `client_id` + secret,
   and can integrate their app immediately.
4. **Same-Akashic SSO** — clicking "Sign in" on the portal authenticates
   via the same auth-server that other OAuth clients use; the portal
   itself is an OAuth client like any other.
5. **Modern stack** — Next.js (App Router) + TypeScript + Tailwind, or
   equivalent. Server-side rendering for the public surface.

### Non-goals (deferred to Phase 9+)

- **Email infrastructure & email-driven flows** — verification on
  signup, forgot-password, email-change confirmation. All deferred to
  Phase 9 along with an SMTP/transactional-email driver. The schema
  for these flows IS prepared in Phase 8 (an `email_verified` flag
  stays unset, no token tables yet) so Phase 9 layers cleanly on top.
- **MFA / TOTP / WebAuthn** — Phase 10+ concern. Phase 8 is
  password-only.
- **Multi-tenancy inside one Akashic** — Akashic is *single-tenant
  per deployment* by design. One Akashic deployment = one tenant.
  Think Google: Google itself is the tenant; services using "Login
  with Google" are clients. No "organization" hierarchy in Phase 8.
- **Refresh tokens / long-lived OAuth sessions** — Phase 7 deferred
  these; Phase 8 inherits the deferral.
- **Other OAuth grant types** — Phase 8 stays with **authorization
  code + PKCE only**, same as Phase 7. No ROPC, implicit, or
  client_credentials. The schema for `auth_types` already supports
  future expansion without migration.
- **Bulk user import / SCIM provisioning** — operator tooling, not
  user-facing.
- **Social login (Google, GitHub)** — out of scope. Akashic is itself
  the IdP, not a federation broker.

## Architecture overview

### What's new

> **Mid-phase architecture pivot (2026-04-27).** The original Phase 8
> design colocated end-user-facing endpoints (`/users/me`, `/clients/*`,
> registration) on the control plane behind mTLS, with the portal
> holding an mTLS client cert. Mid-implementation we split those
> endpoints onto a **third dedicated listener** — the bearer-token
> "resource API server" on port 8082 — and removed the portal's mTLS
> footprint entirely. The portal now talks to the api server with the
> user's own access token, the same way any third-party OAuth client
> would. Rationale: aligns with OAuth's authorization-server vs.
> resource-server partition, gives each surface one trust mechanism,
> and shrinks the portal's privileged-trust footprint to zero.
>
> The Files Summary at the bottom reflects what shipped under this
> three-server model. Chapter 3 below has been rewritten accordingly.

```
                                  ┌──────────────────────┐
                                  │  akashic.<domain>    │   ← NEW (Phase 8)
   admin.akashic.*  ◄─────────────┤  Next.js portal      │
   (Phase 6 admin)                │  (browser session +  │
                                  │   bearer-token API   │
                                  │   client; NO mTLS)   │
                                  └──────────┬───────────┘
                                             │ OAuth to auth listener (8080)
                                             │ Bearer to api listener   (8082)
                                             ▼
                                  ┌──────────────────────┐
                                  │  akashic server      │
                                  │  three listeners:    │
                                  │   • auth   (8080)    │ ← OIDC IdP
                                  │   • api    (8082)    │ ← bearer resource
                                  │   • ctrl   (8081)    │ ← mTLS admin only
                                  └──────────────────────┘
                                             │
                                  ┌──────────┼───────────┐
                                  ▼          ▼           ▼
                              postgres    redis    ldap
```

### What's the same

- The **akashic server** — same Go process, same dual-listener model.
  We *add* control-plane endpoints; we don't change the auth listener
  significantly (just `client_services` row management gets self-service).
- **Postgres / Redis / LDAP** — same stores. Postgres gets new columns
  on `users` and `client_services`; LDAP gets self-service users (not
  just root-bootstrapped ones).
- **Vault PKI / TLS-everywhere** — unchanged. After the three-server
  pivot the portal does **not** need an mTLS client cert; it
  authenticates to the api server with bearer tokens. (The api
  server itself still gets a server cert from `pki-internal/server`
  — `api.akashic.local`.)
- **The admin-bff** — unchanged. It stays root/admin-only. End-users
  and developers never visit it.

### Why a separate portal instead of merging into admin-bff

Three reasons:

1. **Different audiences, different security postures.** The admin-bff
   is intentionally locked down (role allowlist `root,admin`). The
   portal must be *publicly accessible* (signup) — opposite policy.
2. **Different UX needs.** Admin UIs prioritize density and shortcuts;
   public portals prioritize clarity and discoverability. Different
   design systems.
3. **Independent deployment story.** Tenants who want to BYO-portal
   (their own web property) can swap our portal for theirs without
   disturbing the admin surface. Keeping them separate makes that
   substitution clean.

### The Google analogy (worth internalizing)

The mental model the project is built around:

| Google's world | Akashic's world |
|---|---|
| Google is the IdP | One Akashic deployment is the IdP |
| Google has employees / users (people with Google accounts) | The deployment has *its* users (LDAP entries) |
| Third-party services use "Login with Google" | Third-party services register as OAuth clients |
| Google has a developer portal at console.cloud.google.com | The Phase 8 portal is the developer portal |
| Google has accounts.google.com for end-users | The Phase 8 portal is also the end-user portal |

The portal serves both audiences (end-users and developers) on one
domain. Different sections of the same site, role-gated by who you
are once you log in.

## Domain-model deltas

The data shape changes are minimal — Phase 7 set up most of what's
needed.

### `users` table additions

| Column | Type | Purpose |
|---|---|---|
| `email_verified` | bool | Stays `false` for now — Phase 9 wires the flow that sets it |
| `email_verified_at` | timestamp | (set by Phase 9) |
| `last_login_at` | timestamp | For session/security UI |

LDAP keeps holding the canonical email + password hash. Postgres just
adds metadata Akashic specifically cares about.

The `email_verified` flag is added in Phase 8 even though Phase 8
never sets it to true — keeping it in the schema means Phase 9 can
add verification flows without a migration.

**On display names — deliberately NOT a postgres column.** Each
user already has three distinct name attributes in LDAP:
`uid` (login identifier), `mail` (email, secondary login
identifier per Phase 7's filter), and `cn` (common name —
RFC 2798 `inetOrgPerson`'s standard "display name" field). Adding
a fourth `display_name` in postgres would compete with `cn` and
create a "which name do I trust?" hazard. The portal uses `cn` as
the display name throughout — registration form's "Display name"
input writes to `cn`, profile edit updates `cn` directly. The
existing `pkg/ldap/client.go`'s `CreateUser` already takes a
`displayName` argument that becomes `cn`, so no plumbing changes
are needed.

**The deeper rule that produced this decision**: anything that
already exists in LDAP's standard schema should NOT get a parallel
postgres field. Postgres is for Akashic-specific metadata LDAP
can't naturally express (e.g., `email_verified` — LDAP has no
"verified" concept; `last_login_at` — LDAP doesn't track that).
Display name is express-able in LDAP. So it lives in LDAP.

### `client_services` table additions

| Column | Type | Purpose |
|---|---|---|
| `owner_user_id` | uuid (foreign key → users.id, nullable) | The user who registered & manages this client. NULL for built-in clients. |
| `description` | text | Free-form, shown in the developer dashboard |
| `homepage_url` | text | Optional; shown to end-users on consent screens |

### New tables

None for Phase 8. Token tables (`email_verification_tokens`,
`password_reset_tokens`) are a Phase 9 addition tied to email.

### User-type policy

Phase 7 has `user_type ∈ {root, admin, user}`. Phase 8 keeps that
unchanged: any authenticated user can register clients. Admins +
roots can manage *anyone's* clients. The "developer" role distinction
is a Phase 9+ refinement if it turns out the simple model lets too
many people register.

---

# Chapters & Steps

## Chapter 1 — Domain model & resource-API surface

> **Architecture-pivot note.** Steps 1.5–1.8 originally targeted the
> control plane (port 8081, mTLS-only). Mid-Phase 8 those endpoints
> moved to the dedicated bearer-authenticated **api server** (port
> 8082). The "Control-plane endpoint" wording in the step titles
> below is the as-planned artefact; the as-built location is the api
> server. See Files Summary.

The akashic server gets new endpoints that the portal will call. All
on the **control plane** (mTLS-only). The portal's BFF authenticates
to the control plane using its own mTLS client cert, just like
admin-bff does.

### Step 1.1 — Migration: users table additions

Add `email_verified`, `email_verified_at`, `last_login_at` to
`pkg/models/user.go`. GORM AutoMigrate handles the SQL. Display
name is intentionally NOT added — see the "On display names" note
in the Domain-model deltas section above; it lives in LDAP `cn`,
which is already there.

### Step 1.2 — Migration: client_services table additions

Add `owner_user_id`, `description`, `homepage_url` to
`pkg/models/client_service.go`. Foreign-key constraint on
`owner_user_id`.

### Step 1.3 — Public user-creation in the akashic auth service

Today `pkg/repository/user_repository.go`'s `CreateUser` is only
called during bootstrap (root user). Refactor so it accepts a
`user_type` argument and is callable for regular signups. New
caller: a public registration handler.

### Step 1.4 — LDAP password-change support

`pkg/ldap/client.go` doesn't currently support changing a user's
password. Add `ChangePassword(userDN, oldPassword, newPassword)` —
typically an LDAP Modify operation on `userPassword` after
re-authenticating as the user.

### Step 1.5 — Control-plane endpoint: POST /users/register

Body: `{username, email, password, display_name}` — note
`display_name` here is just the request-body field name; on the
backend it's written to LDAP's `cn` attribute, not stored in a
postgres `display_name` column. Validates input (password policy,
username uniqueness, email format), creates the LDAP entry +
postgres row, returns the new user. The user is immediately
usable — no email verification gate. (Phase 9 changes this.)

### Step 1.6 — Control-plane endpoints: GET / PATCH /users/me

GET: reads the user (joined from LDAP+postgres), returns a unified
profile. The `display_name` in the response comes from LDAP `cn`.
PATCH: updates the user's `cn` (when "display_name" is in the
request body) and `mail`. Email change takes effect immediately in
Phase 8 (Phase 9 adds re-verification on top).

### Step 1.7 — Control-plane endpoint: POST /users/me/password

Body: `{old_password, new_password}`. Validates against password
policy (`pkg/auth.PasswordPolicy`), calls `ldap.ChangePassword`.

### Step 1.8 — Control-plane endpoints: client_services CRUD

- `GET /clients/mine` — list clients owned by the requesting user
  (resolved from session at the BFF layer)
- `POST /clients` — create
- `GET /clients/:id`
- `PATCH /clients/:id` — update
- `DELETE /clients/:id`
- `POST /clients/:id/rotate-secret` — generate a new secret, return it
  once

Authorization: an action on a client_services row is allowed iff
the requester is its `owner_user_id` OR the requester has user_type
`admin` or `root`.

### Step 1.9 — Audit logs for everything

Every user-affecting action emits a `Security` channel audit line:
`user_registered`, `user_password_changed`, `client_created`,
`client_updated`, `client_secret_rotated`, `client_deleted`, etc.
Mirror the existing allowlist pattern from admin-bff.

### Step 1.10 — Phase-8-aware `/forgot-password` stub

Since email is deferred, the portal will surface a "contact your
administrator" message instead of a self-service password reset.
Add a stub control-plane endpoint `GET /users/forgot-password-help`
that returns the operator-configured contact info (from a config
key like `portal.support_contact_email`). This way the portal page
exists and shows useful information; Phase 9 replaces the stub with
the real forgot-password flow.

---

## Chapter 2 — Next.js portal scaffold

Stand up the Next.js project structure. No business logic yet; just
the bones.

### Step 2.1 — Pick stack pieces

- **Next.js 15+** with App Router
- **TypeScript** (strict mode)
- **Tailwind CSS** for styling
- **Lucide icons** (lightweight)
- **shadcn/ui** for accessible primitives (or Radix directly)
- **react-hook-form** + **zod** for form handling and validation

### Step 2.2 — Project layout under `web/portal/`

```
web/portal/
├── app/                  # Next.js App Router
│   ├── (public)/         # routes accessible logged-out
│   │   ├── page.tsx      # landing
│   │   ├── signup/
│   │   ├── signin/
│   │   └── forgot/       # informational page in Phase 8
│   ├── (authenticated)/  # routes requiring auth
│   │   ├── profile/
│   │   ├── clients/
│   │   └── sessions/
│   ├── api/              # Next.js API routes (the BFF)
│   │   ├── auth/
│   │   ├── users/
│   │   └── clients/
│   ├── layout.tsx
│   └── globals.css
├── components/           # shared React components
├── lib/                  # client-side helpers
├── server/               # server-only modules (mTLS client, etc.)
├── public/
├── tsconfig.json
├── tailwind.config.ts
├── next.config.ts
└── package.json
```

### Step 2.3 — Build pipeline

`next build --output=standalone` produces a self-contained Node
bundle. Run it in a Node-based container. Simpler and more idiomatic
than embedding into a Go binary (the admin-bff pattern works for
React-only SPAs but doesn't fit Next.js's SSR model).

### Step 2.4 — Dockerfile + compose service

New service `portal` in compose. Profile: none (always
runs, like admin-bff). Container exposes 3000 (Next.js default).

### Step 2.5 — nginx-proxy server block

Add `services/proxy/nginx.conf`'s **root-domain server block** (no
subdomain regex prefix; matches the bare deployment domain
configured via env). Proxies to `portal:3000`.

### Step 2.6 — ~~Vault Agent template for portal mTLS client cert~~

> **Removed by architecture pivot.** The portal no longer needs an
> mTLS client cert — it talks to the api server (8082) with bearer
> tokens. The `portal-client.tpl` template that was briefly present
> in the repo has been deleted. This step is left in the plan only
> as a historical marker; nothing here needs to be done.

### Step 2.7 — Compose extra_hosts

Same pattern as admin-bff: `extra_hosts: host-gateway` for
`auth.akashic.local`, `ctrl.akashic.local`, etc.

### Step 2.8 — Health endpoint

`/api/health` in Next.js, used by docker for liveness probes.

---

## Chapter 3 — Portal session, OAuth, bearer-token API client

> **Revised post-architecture-pivot.** The original Step 3.1 (mTLS
> control client) is gone — the portal makes no mTLS calls. In its
> place, Step 3.1 builds a bearer-token client to the api server.
> Steps 3.2–3.6 carry over with minor adjustments.

The plumbing for "portal as OAuth client + bearer-token API caller."

### Step 3.1 — Bearer-token API client

`web/portal/server/akashic-api-client.ts`. Server-side helper that
calls `https://api.akashic.local:8082` with the user's access token
(read from the encrypted session cookie). Implements:

- `apiFetch(req, path, init)` — adds `Authorization: Bearer <token>`,
  forwards to api.akashic.local, returns parsed envelope.
- Trust: validates the api server's TLS cert against the system
  trust store (issued from `pki-internal/server`, which the portal
  container has rooted via `update-ca-certificates` at build time).
  No client cert.
- 401 handling: clears the session cookie, redirects to `/sign-in`.
  No silent token refresh in Phase 8 (no refresh tokens).

This replaces the original mTLS-control-client step entirely.

### Step 3.2 — OAuth client integration

The portal *is* an OAuth client: when a user clicks "Sign in", we
redirect them to the akashic auth server's `/authorize`, then
receive the code at `/api/auth/callback`. Same flow as admin-bff,
just in TypeScript and with PKCE.

> **Superseded by Phase 8b.3 Stage 4.** The original plan
> registered the Next.js sample as a built-in row in
> `EnsureBuiltInClients` (same secret-on-disk pattern as
> `akashic-admin`). The Phase 8b.3 clients-registration roadmap
> moved sample registration to the operator: only `akashic-admin`
> remains a built-in, and the Next.js sample's `client_id` +
> `client_secret` come from a JSON file written by
> `akashic-cli clients create --save-credentials-to
> .secrets/sample/nextjs.json`. The sample reads the file at
> OAuth-call time (`web/portal/server/oauth.ts`'s
> `resolveCredentials`) — no built-in row, no env-var secret.

### Step 3.3 — Session management

Redis-backed (same Redis instance as everything else, new logical
DB index — DB 2 — for the portal). Session cookie:
`akashic_portal_session`, HttpOnly + Secure + SameSite=Lax.
The session value is an opaque ID; the Redis-backed payload holds
the access token, refresh metadata, and user identity claims.
RedisInsight provisioning gets a third connection card for DB 2
(matching the existing pattern from Phase 7's polish work).

### Step 3.4 — CSRF: double-submit cookie pattern

Same pattern as admin-bff. Token in cookie + header. Next.js
middleware applies it on state-changing API routes.

### Step 3.5 — Lazy OAuth init

Same pattern as admin-bff (Phase 7's lazy `ensureOAuth`). The
portal must tolerate akashic-server being briefly down without
losing its ability to start up — discovery is fetched on first
need, not at process boot.

### Step 3.6 — Audit logging

Mirror admin-bff's allowlist-based audit writer in TypeScript.
Portal-side events: `portal.signin.success`, `portal.signin.failure`,
`portal.signup.success`, `portal.api.bearer_rejected`. The api
server itself emits server-side audit lines for the resource-level
operations (`user.password_changed`, `client.created`, …).

---

## Chapter 4 — Public surface (no auth required)

The pages a visitor sees before logging in.

### Step 4.1 — Landing page

Marketing-y top page: what is this deployment, who is it for,
buttons for "Sign up" and "Sign in."

> **Superseded by Phase 8b.5.** The original plan exposed brand
> copy as env vars (`AKASHIC_PORTAL_BRAND_NAME`, `_TAGLINE`,
> `_DESCRIPTION`, `_SUPPORT_EMAIL`, `_SESSION_SECRET`). The Phase
> 8b cleanup moved all of those to hardcoded literals in
> `web/portal/lib/env.ts`'s `brand` object. The Next.js project
> is now treated as reference-sample code: tenants who want to
> rebrand fork the repo and edit the strings rather than fighting
> with runtime env that conflates akashic-server config with
> sample-product config.

### Step 4.2 — Sign-up form

`/signup` page. Fields: username, email, password (with strength
indicator), display name (optional), accept-terms checkbox. Form
validation via zod. CAPTCHA (Cloudflare Turnstile) gating to
discourage bot signups.

### Step 4.3 — Sign-up submission

> **Superseded by Phase 8b.1 (widget pivot).** The original plan
> routed signup through the portal's BFF: browser → portal API
> route → mTLS to akashic-server's `/users/register`. After the
> Web Components pivot the portal owns no signup logic; the
> `<akashic-signup>` widget runs in the browser and calls the
> akashic api-server's `POST /users/register` directly. The
> portal's BFF is no longer involved on the signup path. (mTLS
> from the portal is gone entirely — the original plan's
> "portal-as-mTLS-client" footprint was removed in the
> three-server architecture pivot already noted at the top of
> Chapter 3.)
>
> On success the widget emits an `akashic-signup-success`
> CustomEvent; the embedding page redirects to its sign-in flow.
> Same end-state as the original plan ("automatically initiate
> sign-in"), different mechanism. Phase 8 still has no email
> verification gate; Phase 9 will add the "check your email"
> page in front of sign-in.

### Step 4.4 — Sign-in initiation

`/signin` is a redirect handler — initiates OAuth flow:
generates state+verifier, sets pre-session cookie, redirects to
akashic `/authorize`. Same pattern as admin-bff's `/login`.

### Step 4.5 — Sign-in callback

`/api/auth/callback` — receives `?code=&state=`, validates state,
exchanges code, verifies ID token, creates portal session,
redirects to `/profile`.

### Step 4.6 — Forgot-password informational page

`/forgot` is **informational only** in Phase 8. It shows: "Forgot
your password? Contact your administrator at
`<operator-configured-email>` for a reset." The form is *not* a
self-service reset (no email channel yet). Phase 9 replaces this
with the real flow.

### Step 4.7 — Public client list (optional)

`/apps` or `/integrations` — a directory of registered OAuth
clients with their `name`, `description`, and `homepage_url`. Helps
end-users recognize legitimate integrations. Operator-toggleable
(default: off — disclose-by-default isn't right for every
deployment).

---

## Chapter 5 — Authenticated user surface

Logged-in user pages.

### Step 5.1 — Authenticated layout

Header with user menu, sidebar nav. Layout component verifies the
session cookie via Next.js middleware on every request to
`(authenticated)/*`. Unauthenticated visits get redirected to
`/signin`.

### Step 5.2 — Profile view

`/profile` — shows:
- **Username** (read-only) — LDAP `uid`
- **Email** — LDAP `mail`
- **Display name** (editable) — LDAP `cn`
- **Last login** — postgres `last_login_at`
- **Account creation date** — postgres `created_at`

Email-verified badge omitted in Phase 8 since the flag is always
false for self-registered users.

### Step 5.3 — Edit profile

Forms for each editable field. `PATCH /users/me` is the backing
endpoint. Editing "display name" updates LDAP `cn`. Editing email
updates LDAP `mail` and takes effect immediately in Phase 8 (no
re-verification yet).

### Step 5.4 — Change password

`/profile/password` — old password + new password + confirm.
Validates against password policy. Rotates LDAP password.

### Step 5.5 — Active sessions list

`/profile/sessions` — lists all active portal sessions for the
user. Allows "log out other sessions" (revokes all other Redis
session IDs).

This needs an akashic-side endpoint:
`GET /users/me/sessions` and `DELETE /users/me/sessions/:sid`.

### Step 5.6 — Logout

RP-Initiated Logout (same pattern as admin-bff). Clears portal
session + redirects through akashic's `/logout` to kill the IdP
session.

### Step 5.7 — Account deletion (optional, gated)

`/profile/delete` — confirmation flow. Marks the user
`is_disabled = true` and `deletion_requested_at = now()`. Admin
review queue (Phase 9+) handles actual purge.

---

## Chapter 6 — Developer surface (OAuth client management)

Self-service registration & management of OAuth clients.

### Step 6.1 — "My clients" dashboard

`/clients` (authenticated) — table of clients owned by the current
user. Columns: name, client_id, created, last-used (deferred),
actions.

### Step 6.2 — Register a client

`/clients/new` — form: name, description, homepage URL, redirect
URIs (multi-input), allowed scopes (multi-select),
**client_type: WEB | SPA**, `auth_types` (read-only — always
`authorization_code` in Phase 8). Submit → `POST /clients` →
returns `client_id` + plaintext secret (shown ONCE, must be
copied) for WEB; just the `client_id` for SPA.

> **Updated by Phase 8b.3 Stage 1 + Stage 3.** The original plan
> made `require_pkce` always-on and read-only. The 8b roadmap
> split clients into WEB (confidential / server-side) and SPA
> (public / browser-only): SPA still forces PKCE (operator can't
> disable); WEB makes `require_pkce` operator-configurable
> (defaults true, recommended on, but checkable-off via the form).
> The `<akashic-clients>` widget that implements this step (Step
> 6.2 = Phase 8b.3 Stage 3, ✅ shipped) surfaces the WEB/SPA radio
> toggle and the disambiguation copy mirrored from the admin-web
> `ClientsCreate.tsx`. Edit-form support depends on api-server
> `PATCH /clients/:id`, which is Phase 8c.4.

### Step 6.3 — Client detail page

`/clients/:id` — shows config, redirect URIs, scopes, owner. "Edit"
and "Delete" buttons.

### Step 6.4 — Edit client

`PATCH /clients/:id`. Restrictions:
- `client_id` is immutable
- `built_in` clients can't be edited from the portal
- Owner-only (or admin/root)

### Step 6.5 — Rotate secret

`POST /clients/:id/rotate-secret` — issues new secret, returns
plaintext once. Old secret immediately invalid.

### Step 6.6 — Delete client

Confirmation flow. Sets `deleted_at = now()` (soft-delete in
postgres) + emits audit event. Hard-delete deferred to a periodic
job.

### Step 6.7 — Integration docs

`/clients/:id/docs` — auto-generated quickstart with the user's
client_id pre-filled: discovery URL, /authorize URL pattern,
example /token call (with PKCE since it's the only flow), token
verification snippet. This matters a lot for adoption — the
faster a developer can paste working code into their app, the
more likely they integrate.

### Step 6.8 — Client testing helper

`/clients/:id/test` — a "dry-run my OAuth flow" button that
initiates an `/authorize` redirect for the client and shows what
came back. Helps developers debug without writing code first.

---

## Chapter 7 — OAuth consent screen

> **Execution gated on Phase 8c.** Chapter 7 work begins only
> after the admin-console expansion (Phase 8c, defined below the
> Phase 8b section) lands. Rationale: consent is public-facing
> UX with a high polish budget; admin work is internal tooling
> with a lower polish budget. Doing admin first exercises the
> admin-bff harder before committing to the consent-screen polish
> work, and the two share session/CSRF infrastructure so the
> later phase rides on patterns proven in the earlier one.

Separate from sign-in: the *consent* step where a user explicitly
agrees to share their identity with a third-party OAuth client.

### Step 7.1 — Consent policy ✅

**Hybrid policy** shipped in `pkg/consent/consent.go`:
- **Built-ins** (`BuiltIn=true`, e.g. akashic-admin): never
  prompt. Operator-shipped, consent implicit.
- **First-party** (`IsTenantPortal=true`): never prompt. The
  operator owns these and trust is implicit. Google's pattern —
  Gmail signing into your Google account doesn't show a prompt.
- **Third-party** (everything else): prompt on first grant,
  prompt again whenever requested scopes ⊄ stored scopes.
  Subset re-authorizations silently approved.

Fail-open when consent repo isn't wired (treat as previously
consented). Fail-CLOSED on a real DB error mid-lookup (require
prompt) — better one extra prompt than a token under uncertain
consent state.

### Step 7.2 — `oauth_consents` table ✅

`pkg/models/oauth_consent.go` + `pkg/repository/oauth_consent_repository.go`:
columns `(id uuid, user_id uuid, client_id, scopes, granted_at,
updated_at, revoked_at)`. Composite unique on `(user_id,
client_id)` — one row per pair, re-grants UPDATE in place.
Soft-delete via `revoked_at` so the audit history of a
previously-consented relationship survives revocation. Repo
exposes `Get`, `Upsert` (single ON CONFLICT round-trip),
`Revoke`, `ListForUser` (for 7.5).

### Step 7.3 — Auth-server consent redirect ✅

`pkg/server/auth/oauth_flow_handlers.go` gained a single branch
between "session valid" and "mint code":
`consent.Required(ctx, repo, &client, userID, scope)`. When the
decision says required, `redirectToConsent` bounces to
`/consent?return_to=<full /authorize URL>`. Same return-to
strategy `/login` already uses — stateless, the consent page
doesn't need its own server-side state mint. Consented decisions
proceed straight to code mint with no behavioural change for
built-ins / first-party clients.

### Step 7.4 — Consent UI ✅

`pkg/server/auth/consent_handlers.go` (`handleConsentPage` +
`handleConsentSubmit`) plus `web/consent.html.tmpl`. Same CSRF
double-submit cookie /login + /signup use; same bootstrap-gate
short-circuit. Approve writes consent row synchronously then
302s to `return_to` (the original /authorize URL); /authorize's
gate re-evaluates and now finds a stored grant → code minted.
Deny extracts `redirect_uri` + `state` from `return_to` and
redirects there with `?error=access_denied` per RFC 6749
§4.1.2.1. Scopes rendered in plain English via a hand-curated
`code → description` table; unknown scopes still show with their
code so a custom scope isn't silently hidden.

### Pre-Phase-9: email-as-identity foundation ✅

A bug fix shipped between Phase 7 and Phase 9: the registration
flow allowed two different users to claim the same email address.
LDAP's `mail` attribute is not unique by default in the
`inetOrgPerson` schema, and `pkg/userregistration/Register`
checked username uniqueness but never email. This block all of
Phase 9's email-driven flows (verification, password reset,
email change confirmation), all of which assume 1:1 email→user
mapping.

**As-shipped:**
- New `LDAPClient.EmailExists(email)` (`pkg/ldap/client.go`) —
  search for `(mail=<email>)`, returns bool. Idempotent
  read-only check.
- New sentinel `userregistration.ErrEmailTaken`. `Register`
  now performs the email-uniqueness check before persisting.
- New sentinel `userregistration.ErrUsernameUnavailable` for
  the pathological case where tag-collision retry exhausts.
- **Optional user-supplied ID + tag at signup**:
  `userregistration.Params` accepts both `Username` and `Tag`
  as optional fields. The combinations are:
  - **Neither** → both auto-generated (`<derived-id>#<random-tag>`)
  - **ID only** → tag auto-generated, retried on collision
  - **Tag only** → id derived from email, exact `<id>#<tag>`
    must be free or 409 `UID_TAKEN`
  - **Both** → both validated, exact combo must be free
  - The retry-budget vs. exact-must-be-unique distinction
    matters: when the caller supplies a specific tag, they
    want THAT tag — regenerating to "fix" a collision would
    silently produce a uid they didn't ask for.
- The Discord-style **`<id>#<tag>`** format applies regardless:
  - `<id>` = lowercase alphanumeric + `.`, `_`, `-`. Sanitised
    from email's local part if not supplied; validated to 2–32
    chars after sanitisation if supplied.
  - `<tag>` = exactly 4 chars base36 stored as **UPPERCASE**
    (`0-9A-Z`). Case-insensitive on input — `a8f3`, `A8F3`,
    `A8f3` all normalise to `A8F3`. Visual contrast with the
    lowercase id-base makes tagged uids read cleanly: `alice#A8F3`.
    Auto-generated from `crypto/rand` if not supplied.
  - **Login-input normalisation**: when a user types a uid-style
    login like `alice#a8f3` at the auth-server's
    `/login/submit`, `userregistration.NormalizeUIDInput`
    uppercases the tag portion before the LDAP search runs.
    No-op for emails or untagged legacy uids. Defense-in-depth
    on top of LDAP's `caseIgnoreMatch` — keeps logs / audit /
    displays uniform on the canonical form.
  - Universal tagging — every uid gets a tag, even the first
    user with a given id-base. Avoids the "first user is
    special" feeling of `-N` suffixing.
  - Collision retry on auto-generated tags: 8 attempts (36⁴ ≈
    1.7M tags per id-base, birthday collision at ~180 same-base
    users).
- Verified `#` is RFC-4514 mid-RDN safe, RFC-4515 filter-safe,
  and percent-encodes correctly in URL query strings. No code
  paths put the LDAP uid in URL paths today; future ones must
  use `url.PathEscape`.
- Auth-server `web/signup.html.tmpl` and `<akashic-signup>` widget
  drop the username field entirely. Email is the only user-
  visible identity input.
- Both registration handlers gained the `EMAIL_TAKEN` +
  `USERNAME_UNAVAILABLE` error code mappings; widget translates
  to inline errors.
- API-server response reports the actual stored uid (extracted
  from the LDAP DN's leftmost RDN) so clients can log it for
  diagnostics, but email is the user-facing identity going
  forward.
- **Login form unchanged**: still labels the field "Username
  or email" since `UserLoginFilter` ORs uid + mail. Legacy
  users with custom uids (the bootstrap root) continue to work;
  new users sign in by email.
- **Defense-in-depth deferred**: a future hardening pass should
  enable OpenLDAP's `slapo-unique` overlay on `mail` for race-
  window protection. App-level catches >99% of cases; the
  overlay closes a sub-millisecond window between two
  simultaneous registrations of the same email.

**Admin Users page now displays email.** Backend
`pkg/server/control/users_handlers.go` adds an `email` field
to `userView`, populated via per-row LDAP fetch
(`s.lookupEmail(ldap_dn)` — bounded by page size, max 200
queries per render, acceptable for an operator UI). Frontend
`UsersPage.tsx` shows the email as the primary identity line
with the uid as a smaller muted second line. When LDAP is
unreachable mid-render, falls back to uid-only display so the
row stays legible. Edit-dialog title and delete-confirm body
both use email (with uid in parentheses); the type-to-confirm
phrase stays as the uid since it's shorter and stable.

**Default display name uses id-base (no tag).** When a user
registers without specifying a `display_name`, the LDAP `cn`
falls back to the uid's id-base — everything before the `#`.
For tagged uids like `alice#a8f3`, this produces the readable
display name `alice` rather than the full `alice#a8f3`.
Untagged uids (the bootstrap "admin", any pre-tag-design
rows) get a no-op strip since there's no `#` to find.

**UID-rotation foundation (B-1, B-2, C-1 of 3 follow-up sub-steps shipped):**
- New `User.LastUIDChangedAt *time.Time` (indexed) tracks the
  most recent successful PATCH /users/me/uid call per user;
  nil means the user has never rotated their uid.
- New `TenantPolicy.UIDChangeCooldownDays int` (default 30,
  validated to `[0, 365]`) — the minimum elapsed time between
  successive uid rotations per user. 0 disables; 30 is the
  default; values >365 are rejected as nonsensical.
- Policy service `Update` accepts the new field; `EnsureSingleton`
  seeds the default 30 on first run.
- Control plane `PATCH /policy` + admin-bff proxy + admin web
  Policy page all carry the new field through. Operator can
  tune from the "Account ID rotation" section of the Policy
  page; changes take effect for the next /users/me/uid call.
- **B-2 — `PATCH /users/me/uid` endpoint shipped**
  (`pkg/server/api/uid_change_handler.go`, route wired in
  `pkg/server/api/routes.go`). Body
  `{ "username"?, "tag"? }` (at least one required). Missing
  `username` defaults to the user's CURRENT id-base extracted
  from their LDAP DN — so a user named `alice` who only
  rotates the tag stays as `alice#<new>`, rather than getting
  re-derived from their email's local part. Missing `tag`
  triggers the same 4-char base36 auto-generation + collision
  retry as registration. Cooldown enforced against
  `User.LastUIDChangedAt` + `policy.UIDChangeCooldownDays`
  (0 disables; nil-LastUIDChangedAt always passes); a 409
  `UID_CHANGE_COOLDOWN_ACTIVE` carries `next_allowed_at`,
  `cooldown_days`, `last_changed_at` so the UI can show a
  countdown. No-op short-circuit (resolved newUID matches
  current) returns `changed: false` without burning the
  cooldown. Atomicity: LDAP `modrdn` first, PG update second,
  best-effort LDAP rollback if PG fails — and a loud Security-
  channel error log if BOTH fail (manual operator fix needed,
  rare). Audit log on success via the Security channel records
  user_id + old_uid + new_uid.

- **B-3 — Profile widget UI shipped**
  (`web/widgets/src/components/akashic-change-id.ts`). New
  `<akashic-change-id>` Lit element: fetches `/users/me` on mount
  to display the user's CURRENT uid in a read-only card, then
  exposes side-by-side "New ID" + "New Tag" inputs with the same
  side-by-side layout as `<akashic-signup>` (the same `field-row`
  parts, the same 6rem tag cell, the same `align-items: flex-end`
  baseline trick). Submit is permissive — leaving either field
  blank lets the server keep the corresponding half (matches the
  endpoint's "missing username = keep id-base, missing tag =
  auto-generate" semantics). Maps every error code the handler
  returns: `UID_CHANGE_COOLDOWN_ACTIVE` (formatted with
  `details.next_allowed_at` into a "you can change again on
  <localized date> (in about N days)" sentence), `ID_INVALID`,
  `TAG_INVALID`, `UID_TAKEN`, `USERNAME_UNAVAILABLE`,
  `VALIDATION_FAILED`, plus the standard `NO_SESSION` →
  `akashic-needs-signin` event. Server-`changed: false` (no-op
  short-circuit) is rendered as an info banner rather than a
  success — preserves the "didn't burn the cooldown" signal in
  the UI. On real success, dispatches `akashic-uid-changed`
  CustomEvent (detail = `{ uid, ldap_dn }`) so the embedder page
  can refresh any cached display. Mounted in both reference
  portals: `web/portal/app/(authenticated)/profile/change-id`
  (Next.js) and `services/sample-static/html/change-id.html`
  (plain HTML), plus card links from each `/profile` page.

The uid-rotation milestone is now fully end-to-end usable: the
operator tunes the cooldown on the admin Policy page, the user
rotates from `/profile/change-id` in either sample portal, the
api-server enforces the cooldown + performs the LDAP+PG dance,
and the audit log records every successful rotation.

**First-party gate on account-mutation endpoints.** The api-server
previously accepted any valid OAuth access token (signature OK +
`openid` scope) on every authenticated route, including the
account-mutation surfaces. That meant a third-party OAuth client
that a user had legitimately granted consent to could call
`PATCH /users/me`, `PATCH /users/me/uid`, `POST /clients`,
`DELETE /users/me/consents/<id>`, etc. — taking actions the user
never visually authorized.

The half-built defense was already in the codebase: auth-server
`/session/token` mints with a dedicated audience claim
(`oauth.SessionTokenAudience = "akashic-session"`) specifically
to distinguish first-party widget bearers from OAuth-flow
bearers. The api-server's `requireBearer` was passing empty-
string for `expectedAudience` to `oauth.VerifyAccessToken`,
intentionally skipping the check (with a TODO comment marking
it as future work). This now enforces the check via a new
`requireFirstPartyBearer` wrapper:

- `requireBearer` (unchanged): signature + `openid` scope; any
  audience accepted. Used for read-only `GET /users/me`.
- `requireFirstPartyBearer`: builds on `requireBearer` and asserts
  `claims.VerifyAudience(oauth.SessionTokenAudience)` —
  guaranteeing the token was minted for a first-party portal
  session. Failures get HTTP 403 with
  `error="insufficient_scope"` (RFC 6750 §3.1) and a Security-
  channel audit log entry recording the rejected
  path + user_id + audience.

Route table now splits accordingly: `GET /users/me` stays open to
any valid bearer (so a third-party app can read profile basics
just like /userinfo), while every mutation surface
(`PATCH /users/me`, password, uid, all `/clients/*`, all
consent endpoints — list and revoke alike) is locked to
first-party.

Why audience and not scope: scopes are user-grantable through
the OAuth consent screen; an attacker could trick a user into
granting `account:manage` if we defined one. Audience is set by
the issuer at mint time and is not user-grantable — a third-
party client cannot obtain a token with `aud=akashic-session`
because the only mint path that produces it is gated by the
host-scoped first-party session cookie + the
`AKASHIC_PORTAL_TENANT_ORIGINS` CORS allowlist. This matches the
"zone of trust" pattern from RFC 9068 (JWT Profile for OAuth
Access Tokens) §5.

Tests in `pkg/server/api/bearer_test.go`: 5 cases over
`AccessTokenClaims.VerifyAudience` covering session-bearer,
third-party client_id audience, empty audience, near-miss
literal, and multi-audience tokens; plus a non-empty constant
guard that catches the obvious-but-catastrophic regression
where someone defines `SessionTokenAudience = ""` (which would
make `VerifyAudience` accept every token).

Login-by-email already worked at the LDAP filter layer
(`UserLoginFilter` defaults to `(|(uid={login})(mail={login}))`);
the email-uniqueness fix is what makes it actually disambiguate.

### Step 7.5 — Revoke-consent UI ✅

End-user surface for managing OAuth grants:
- Two new bearer-authenticated api-server endpoints (`pkg/server/api/consents_handlers.go`):
  - `GET /users/me/consents` → joins consent rows with
    `client_services` for client name/homepage; bulk-fetches
    metadata in one IN-query rather than per-row to avoid N+1.
    A grant whose `client_services` row was deleted post-grant
    surfaces with the bare `client_id` as display name (so the
    user can still revoke a stale entry).
  - `DELETE /users/me/consents/<client_id>` → marks the row
    revoked via `OAuthConsentRepository.Revoke` (soft-delete
    via `revoked_at`). Idempotent.
- New `<akashic-connected-apps>` widget
  (`web/widgets/src/components/akashic-connected-apps.ts`) —
  same shape as `<akashic-clients>`. List rows + per-row
  inline-confirm revoke + dispatch of `akashic-consent-revoked`
  event for embedder pages. Open shadow DOM with `::part(...)`
  hooks for tenant CSS, mirroring the rest of the widget bundle.
- Wiring: `consentRepo` plumbed into `api.Server` via new
  `SetConsentRepo`, hooked up in `pkg/akashic/core/context.go`
  alongside the auth-server's existing wire (single repo serves
  both surfaces).
- **Sample portal surfaces**: the widget is mounted in both
  reference samples for parity:
  - `web/portal/app/(authenticated)/profile/connected-apps/page.tsx`
    (Next.js sample) — thin shell around `<akashic-connected-apps>`,
    plus a "Connected apps" card on `/profile` linking to it.
  - `services/sample-static/html/connected-apps.html` (static
    sample) — same shape, plus an extra link from `profile.html`.
    nginx's existing `try_files $uri $uri.html` rule routes
    `/connected-apps` to the new file with no config change.
  - JSX type declarations updated in
    `web/portal/types/widgets.d.ts` so the Next.js portal's
    TypeScript accepts the new element.

**Revoke takes effect immediately.** The auth-server's `/authorize`
gate consults the same repo, so the next sign-in attempt by the
client+user pair finds the row marked revoked and re-prompts
consent. No cache invalidation needed.

---

## Chapter 8 — Verification, polish, deployment

### Step 8.1 — End-to-end test: signup → login → register-a-client → use-the-client

The canonical happy path. From a fresh deployment:
1. Operator runs `docker compose up -d`
2. Person visits the root domain (`akashic.<your-domain>`)
3. Signs up
4. Logs in (immediately — no verification gate in Phase 8)
5. Registers a client
6. Uses the client (via a separate test app, or the integrated
   testing helper from Step 6.8) to sign in

### Step 8.2 — Failure-mode tests

- Signup with existing email/username
- Signup with weak password
- Sign-in with wrong password
- OAuth client edit by non-owner (must 403)
- Secret rotation by non-owner (must 403)
- Forgot-password page renders the contact-administrator message
  correctly (Phase 9 replaces with real flow)
- Consent denial returns the user to the originating client with
  `error=access_denied`

### Step 8.3 — Rate-limiting

Per-IP buckets on signup (5/min), client-register (5/min). Mirrors
admin-bff patterns. Consent posts get the looser bucket since
they're not directly attacker-controllable.

### Step 8.4 — CAPTCHA / Turnstile integration

Cloudflare Turnstile widget on the signup page. Server-side
validation in the signup API route. Operator-toggleable (sites
running on isolated networks may not need it).

### Step 8.5 — Update study guide

Add `doc/study/10-portal.md` covering the portal's
architecture, similar in structure to `05-admin-bff.md`. Update
chapter 00 (architecture map) and 09 (reference glossary) to
include the portal.

### Step 8.6 — Phase 8 revision doc

Replace this plan with `phase-8-revision.md` capturing actual
decisions, deviations, and the as-built command set.

---

## Phase 8b — Mid-Plan Pivot & Additions

The original plan above (Chapters 1–8) framed the portal as a
server-rendered Next.js app that owns its own UI. Mid-implementation
we pivoted: tenants integrate Akashic into their products via
embeddable Web Components, the Next.js project becomes one sample
consumer among several, and OAuth client registration becomes an
operator action rather than a built-in. This section consolidates the
mid-plan additions that didn't fit the original chapter structure so
the plan reflects the actual delivered scope.

Status legend: ✅ done · 🟡 in flight · ⏳ not started

### 8b.1 — Widget pivot (Web Components) ✅

Replaces the assumption that pages own their UI. The akashic-server
now ships an embeddable widget bundle (`/widgets/akashic.js` +
`/widgets/akashic-default.css`) built from `web/widgets/` (Lit-based
custom elements). Tenants drop `<akashic-signup>`, `<akashic-signin>`,
`<akashic-profile>`, etc. into their own pages. The Next.js project
in `web/portal/` becomes a reference consumer; the static-HTML
project in `services/sample-static/` is the no-backend counterpart.

- **Net effect on Chapters 4–6**: pages become thin shells that mount
  widgets rather than owning forms and submission logic.
- **Net effect on Chapter 1**: the `/users/*` and `/clients/*` API
  endpoints stay where they were planned, but their primary callers
  shift from "the portal's BFF" to "the widget bundle running on
  arbitrary tenant origins" — see 8b.5 for the CORS knock-ons.

### 8b.2 — Static-HTML sample (no backend) ✅

`services/sample-static/` — nginx-served HTML + `_oauth.js`
implementing Authorization Code Flow + PKCE entirely in the browser.
Counterpart to the Next.js sample for tenants without a server-side
component.

- Mutually exclusive with the Next.js sample at runtime (shared
  `sample-portal` network alias; only one can hold it).
- Profile: `--profile sample-static`.
- Used as the proof-of-correctness for the WEB-vs-SPA OAuth split.

### 8b.3 — Clients-registration roadmap

Operator-driven OAuth client registration replacing the built-in
clients model. Four stages:

#### Stage 1 — Data model + API + /authorize ✅

- `ClientService.Public bool` column with `normalize()` invariants
  (Public ⇒ RequirePKCE + empty hash; BuiltIn ⇒ RequirePKCE).
- `client_type: "WEB"|"SPA"` on `POST /clients` (case-insensitive
  parse, canonical uppercase response).
- `/authorize` PKCE check now conditional on `client.RequirePKCE`
  (was always-required); WEB clients can be registered with PKCE
  optional.
- `/token` PKCE check handles four cases explicitly (challenge ±
  verifier ±) so non-PKCE WEB flows succeed and downgrade attempts
  on stored-PKCE codes are rejected.
- Public-client check switched from implicit `ClientSecretHash == ""`
  to explicit `client.Public`.

#### Stage 2 — Bootstrap-time portal registration ✅

- `akashic-cli clients create --type WEB|SPA --name … --redirect-uri
  … [--save-credentials-to <path>] [--no-pkce]` — control-plane
  endpoint at `pkg/server/control/clients_handlers.go`, mTLS-gated
  via `requireClientIdentity("cli.akashic.local",
  "bff.akashic.local")` + `requireBootstrapComplete`.
- Admin-web `POST /api/clients` (session-gated to admin/root,
  CSRF-enforced) → control-plane proxy at
  `pkg/admin_bff/handlers.go::handleCreateClient`.
- React form at `web/admin/src/components/ClientsCreate.tsx` with
  the WEB/SPA disambiguation copy and the secret-shown-once panel.
- `BOOTSTRAP_INCOMPLETE` gate (HTTP 409) prevents `clients create`
  before bootstrap completes; CLI maps it to a friendly "run
  bootstrap create-root first" message.
- Post-bootstrap "next step" hint printed by `bootstrap create-root`
  on success.

#### Stage 3 — `<akashic-clients>` developer widget ✅

The original Chapter 6 work, repurposed as a widget. Tenant
developers (NOT operators) manage their own OAuth clients against
the bearer-authenticated `/clients/*` endpoints (already built in
Stage 1). Owner-scoped via `/clients/mine` + `canManage()`.

- Lit component at `web/widgets/src/components/akashic-clients.ts`.
- List + create + delete + rotate-secret in one widget. Edit form
  pending api-server `PATCH /clients/:id` (Phase 8c.4).
- Mirrors the admin-web's `ClientsCreate.tsx` UX but uses bearer
  tokens (from `/session/token`) instead of mTLS-via-control-plane.

#### Stage 4 — Sample adaptation ✅

- `akashic-sample-nextjs` and `akashic-sample-static` removed from
  `EnsureBuiltInClients` candidates. Operator registers them via
  `clients create --save-credentials-to .secrets/sample/<name>.json`.
- `AKASHIC_OAUTH_BUILTIN_CLIENTS` replaced with single boolean
  `AKASHIC_OAUTH_ADMIN_BFF_ENABLED` (only `akashic-admin` remains
  as a built-in).
- Next.js sample reads credentials JSON from `/secrets/sample/nextjs.json`
  at OAuth-call time (Node `readFileSync` in `web/portal/server/oauth.ts`).
- Static sample fetches `/akashic-config.json` from nginx (which
  aliases `.secrets/sample/static.json`) before /authorize so
  freshly-registered SPA clients work without a container restart.

### 8b.4 — Naming alignment ✅

Mid-plan rename to clean up "portal" overloading and align WEB/SPA
labels with operator vocabulary:

| Old | New |
|-----|-----|
| `akashic-portal` (built-in) | `akashic-sample-nextjs` |
| `akashic-static-sample` (built-in) | `akashic-sample-static` |
| `client_type: "bff"` / `"spa"` | `"WEB"` / `"SPA"` (uppercase, op-friendly) |
| `AKASHIC_OAUTH_PORTAL_REDIRECT_URI` | `AKASHIC_OAUTH_SAMPLE_NEXTJS_REDIRECT_URI` |
| `AKASHIC_OAUTH_BUILTIN_CLIENTS=admin,…` | `AKASHIC_OAUTH_ADMIN_BFF_ENABLED=true` (boolean) |
| `AKASHIC_PORTAL_BRAND_NAME`/`_TAGLINE`/`_SESSION_SECRET` | hardcoded in `web/portal/lib/env.ts` |

### 8b.5 — Cross-cutting UX + ops additions ✅

- **CORS on /token + /userinfo + /session/token** (`pkg/server/auth/routes.go`)
  via `tenantCORS()` middleware seeded from `AKASHIC_PORTAL_TENANT_ORIGINS`
  — required for SPA OAuth + bearer-exchange from arbitrary tenant origins.
- **RP-Initiated Logout** for both samples (`/logout?post_logout_redirect_uri=…&id_token_hint=…`)
  with origin-allowlist check against registered `redirect_uris`.
- **`<akashic-signup>` confirm-password field + live policy fetch** —
  fetches `GET /users/password-policy` on connectedCallback; client-side
  pre-validates against the same rules the server applies.
- **Public `GET /users/password-policy`** endpoint exposes the active
  policy; widget reads it; admin-bff bootstrap form could read it too
  (currently uses hardcoded defaults).
- **Dynamic credential consumption** — Next.js sample reads JSON file
  at request time (no caching of secret); discovery cached separately.
- **`./logs:/app/logs` mount** on `--profile app` so file-based logs
  are visible on the host alongside `docker compose logs`.
- **`.env` cleanup** — collapsed verbose comments, removed sample
  cosmetic envs (BRAND_NAME, TAGLINE, SESSION_SECRET, DESCRIPTION,
  SUPPORT_EMAIL — all hardcoded in sample source now).
- **Auth-server-hosted self-service signup**
  (`pkg/server/auth/signup_handlers.go`) — `/signup` and
  `/signup/submit` mirror the existing /login pair using the same
  CSRF/template infrastructure plus the shared `pkg/userregistration/`
  domain package. Eliminates the chicken-and-egg of needing a
  registered tenant portal before end-users can create accounts.
  The `<akashic-signup>` widget remains the embeddable counterpart
  for tenants who want signup inside their own product UI.
- **`IsTenantPortal` flag on `client_services`** — operator-set
  marker for "this client is first-party (operator-owned)" rather
  than developer-registered (third-party). Drives the admin UI's
  "first-party" badge today and feeds Chapter 7's "skip consent"
  predicate (the tenant trusts itself). **Any number of rows may
  carry the flag** — a deployment that ships multiple first-party
  apps (mail, calendar, drive, account-management) flags each
  one. The original "at most one" rule was tied to an earlier
  `SignUpURL` operator-override which has since been removed; the
  rule was relaxed on 2026-04-30 to match the multi-product
  reality (Google's analogy: Gmail/Maps/Drive are all separate
  OAuth clients, all first-party). The api-server's bearer-
  authenticated /clients endpoint refuses the field on input, so
  developers can't self-promote through that surface.
- **`return_to` propagation through /login → /signup → /login** —
  the /login page's "Create account" link carries `return_to`
  forward; the /signup form preserves it; on success the user lands
  back on /login with both their username pre-filled and the
  OAuth `return_to` intact, so the original /authorize flow resumes
  cleanly. Earlier bug: lost `return_to` caused a post-signup 404
  at `/`. The fix uses a server-computed `SignUpHref` so the
  template stays free of `?` vs `&` join logic.
- **"Signed-in" landing on direct /login submits without a
  return_to** — replaces the previous unsafe fallback redirect to
  `/` (which 404'd, since the auth server has no GET / route) with
  a friendly status page rendered through `error.html.tmpl`.
- **Public surface pages shipped on the Next.js sample portal**
  (commit 61b648c) — landing, sign-in, sign-up, and forgot-password
  pages. The forgot page is the Phase-8 informational stub from
  Step 4.6 (Phase 9 replaces it with a real flow).

### 8b.6 — Open items (now closed)

All items closed during Phase 8b work. Admin-web client edit /
detail page rolled into Phase 8c.4 to consolidate with the broader
client-management UI work happening there.

| Item | Status |
|---|---|
| CLI `clients list / show / delete / rotate-secret` | ✅ |
| Admin web client list + delete + rotate UI | ✅ |
| Admin web client edit + detail | → Phase 8c.4 |
| Stage 3 widget (`<akashic-clients>`) | ✅ |
| Server-side password policy from operator config | ✅ |
| Refactor duplicated client-create logic into `pkg/clientservice/` | ✅ |
| Static sample graceful 404 on `/akashic-config.json` | ✅ |

### 8b.7 — Phasing notes

The 8b additions fold into the original chapter ordering as follows:

```
Chapter 1 (data model)               ← extended by 8b.3 Stage 1
    ↓
Chapter 2-3 (Next.js scaffold + auth) ← repurposed by 8b.1 (sample, not portal)
    ↓
Chapter 4-5 (public + authed surface) ← rebuilt as widget consumers (8b.1)
    ↓
Chapter 6 (developer surface)         ← becomes 8b.3 Stage 3
    ↓
Chapter 7-8 (consent + verification)  ← unchanged
```

What this means in practice: someone reading the plan today should
read Chapters 1–8 for the conceptual shape, then read Phase 8b for
what was actually delivered and what remains.

---

## Phase 8c — Admin Console Expansion

> **Status**: planned (added 2026-04-30). Inserts before Chapter
> 7 in execution order. The original Chapter 7 (consent screen)
> work begins once 8c lands.
>
> **Why this order**: consent is public-facing UX and demands a
> high polish budget; admin work is internal tooling that tolerates
> rougher edges. Building admin first exercises the admin-bff
> harder before we spend the polish budget on the public consent
> screen. Both surfaces share session + CSRF infrastructure, so
> the later phase rides on top of patterns proven in the earlier
> one.

### 8c.1 — Setup-status banner ✅

A banner at the top of every admin page surfacing "what still
needs doing" — bootstrap complete? tenant portal registered?
LDAP healthy? Each incomplete item shows remediation copy.

**As-shipped scope:**
- Control-plane handler `GET /admin/setup-status`
  (`pkg/server/control/setup_status_handlers.go`). mTLS-gated to
  `bff.akashic.local` + `cli.akashic.local`. NOT gated by
  `requireBootstrapComplete` — the banner is what tells the
  operator bootstrap is incomplete; gating it would hide it
  exactly when it's most useful.
- Each subsystem probe is independent and nil-tolerant: a failed
  probe sets that field to `false` (with a server-side warning
  log) rather than 500ing the whole call. Status pages must
  never break the page they're on.
- Wiring: new `Server.ldapClient` field + `SetLDAP()` method
  mirroring the existing `SetDB()` pattern;
  `pkg/akashic/core/context.go` calls it during init.
- Admin-bff proxy at `GET /api/admin/setup-status`, session-
  gated to admin/root.
- React `<SetupStatusBanner>` (`web/admin/src/components/`)
  renders only when at least one gate fails. Bootstrap is
  surfaced exclusively when it's the failing gate (downstream
  noise like "LDAP not OK" would swamp the actionable signal
  "you haven't run bootstrap yet"). Failure of the status fetch
  itself silently renders nothing — a status check that errors
  shouldn't be more disruptive than what it surfaces.
- Amber/warn palette + warning-triangle icon, distinct from
  `.error` red so the operator reads "fixable, not broken."

**Deferred to follow-up:**
- Vault sealed/unsealed probe. The akashic server has no
  Vault-HTTP touchpoints (Vault Agent writes certs to disk;
  akashic just reads them), so adding a Vault probe would mean
  a new client + auth plumbing. Out of scope for the banner v1.
- Health-ping refresh / live update. v1 fetches once per
  Dashboard mount; sufficient for an operator who navigates
  between pages.

### 8c.2 — User management ✅

Operator-side CRUD over user accounts: list, view, role/disabled
toggle, hard-delete. Cross-row invariants enforced at the domain
layer; self-protection enforced at the BFF (the only layer with
session context).

**As-shipped scope:**
- New shared package `pkg/usermanagement/` (mirrors
  `pkg/clientservice/`). Sentinel errors: `ErrLastRoot`,
  `ErrSelfDemotion`, `ErrSelfDeletion`. Cross-row invariants:
  - The last active `root` can't be demoted or deleted. The
    "active" count subtracts disabled rows so "enable then
    demote the only root" is also blocked unless a second
    root exists.
  - A user can't demote or delete themselves through this
    surface (BFF-side check, with control-plane defense in
    depth via `caller_user_id`). Disable-self stays allowed —
    recoverable by another admin.
- Repository additions: `DeleteUser`, `UpdateUserType`,
  `CountByUserType`, `ListWithFilters` (which returns total
  count alongside the page so pagination doesn't need a second
  query).
- LDAP addition: `DeleteUserByDN` — idempotent on `LDAPResultNoSuchObject`
  so the operator-facing flow doesn't fail if the entry is
  already gone.
- Endpoints (control plane, mTLS-gated, `requireBootstrapComplete`):
  - `GET /users` — paginated, filterable by `user_type`,
    `is_disabled`, `missing_identity`. Returns `{users, total}`.
  - `GET /users/<id>`
  - `PATCH /users/<id>` — body: `{user_type?, is_disabled?, caller_user_id?}`;
    pointer fields preserve the "leave unchanged" / "set to false"
    distinction.
  - `DELETE /users/<id>?caller_user_id=<uuid>` — hard-deletes
    LDAP entry **then** PG row (intentional order; reverse would
    let JIT provisioning re-create the row).
- Admin-bff: typed `UsersApi` + `handleListUsers`, `handleUserByID`
  dispatcher (GET/PATCH/DELETE on `/api/users/<id>`). BFF
  resolves `caller_user_id` from the session and overrides any
  client-supplied value — the FE doesn't get to claim identity.
- Frontend: `<UsersPage>` with role/status filters, paginated
  table, edit modal (role + disabled), and a type-to-confirm
  delete modal where the confirm phrase is the user's `uid` so
  the operator has to look at the row they're deleting. "You"
  badge on your own row + actions hidden; the empty state
  reads "manage another admin to change you".
- Audit: every PATCH and DELETE logs to the security channel
  with `user_id`, `caller_user_id`, and the changed fields.

**Resolved Open Question 2** (user-deletion semantics): hard
delete (LDAP + PG removed immediately). Reasoning: soft-delete
already exists as `is_disabled = true` (reversible, intent: "lock
this account"). DELETE is the explicit "operator wants this gone
now" action; the 90-day deprovisioning loop covers the orthogonal
"user left silently" case.

### 8c.3 — Server control panel ✅

A "Server" sidebar entry surfacing the control plane's existing
lifecycle / reload endpoints with appropriate confirm gating on
state-changing actions.

**As-shipped scope:**
- Pure proxy: no new control-plane endpoints. The BFF wraps the
  ten existing routes (`GET /status`, `POST /{auth,api}/{start,stop,restart}`,
  `POST /server/quit`, `POST /config/reload`, `POST /tls/reload`)
  via a shared `proxyServerAction` helper.
- Backend: typed `ServerApi` on the BFF + a single `PostAction`
  helper on the control client. State-machine error codes
  (`AUTH_SERVER_ALREADY_RUNNING`, `API_NOT_WIRED`, etc.) pass
  through with their upstream message verbatim — the control
  plane's wording is already user-facing-grade.
- Frontend: `<ServerPage>` with three sections —
  status snapshot (auth/control state badges, address, uptime,
  PID), per-subsystem action rows (start / restart / stop), and
  a card grid for reload-config / reload-TLS / shut-down.
- New reusable `<ConfirmModal>` component with optional
  type-to-confirm phrase input. Closes on Escape, backdrop
  click, or Cancel; the parent decides when to close on a
  successful Confirm. Supports a busy state so the modal stays
  open with "Working…" while an action runs.
- Confirm-gating policy:
  - **Type-to-confirm** (`STOP AUTH SERVER`, `STOP API SERVER`,
    `SHUTDOWN AKASHIC`): actions that affect *other users* — auth
    stop breaks sign-in for everyone; api stop breaks bearer auth
    for everyone; quit shuts the whole deployment down.
  - **Yes/no confirm**: restart actions (brief outage but
    self-recovering) and reload actions (non-disruptive when
    successful, no-op when validation fails).
  - **No confirm**: start actions (recovery; no-op if already
    running, returns 409).
- New `button.destructive` CSS class — same shape as `.primary`
  but red — distinct from inline `.error` message styling.
- New `.success` peer of `.error` for the action-completed banner;
  auto-clears 5s after a success but stays until next-action on
  errors.

### 8c.4 — Client services: detail + edit ✅

Operator-side `GET` / `PATCH` for OAuth client rows. Edit form
mirrors the create form's structure with immutable fields shown
read-only.

**As-shipped scope:**
- Control plane: extended `handleAdminClientByID` dispatcher to
  handle GET + PATCH (alongside the existing DELETE and
  rotate-secret). New `handleAdminGetClient` returns the same
  view shape the list endpoint emits; `handleAdminPatchClient`
  accepts the operator-superset (`name`, `description`,
  `homepage_url`, `redirect_uris`, `allowed_scopes`,
  `role_allowlist`, `require_pkce`, `is_tenant_portal`).
- Built-ins reject all PATCH with `BUILTIN_IMMUTABLE` (mirrors
  delete and rotate). SPA + `require_pkce=false` is sharply
  rejected with `VALIDATION_FAILED` — public clients have no
  secret, so disabling PKCE removes their only credential
  mechanism.
- `is_tenant_portal` is mutable post-relaxation (multiple
  flagged rows allowed). The SetupStatusBanner copy explicitly
  promised this in-place toggle would land here; it now does.
- Api-server side already had GET + PATCH from earlier work
  (owner-scoped, refuses operator-only fields on input). The
  `<akashic-clients>` widget can wire its edit form against it
  whenever someone implements the UI.
- BFF: typed `ClientGet`, `ClientUpdate` + `getClient`,
  `patchClient` handlers. Per-id dispatcher now branches on
  GET / PATCH / DELETE inside `case ""`.
- Admin web: new `ClientsEdit` component matching the
  `ClientsCreate` shape; immutable fields surfaced in a "Immutable"
  panel at the top so operators don't think they're missing.
  Only-changed-fields PATCH semantics — sending the diff matches
  the server's pointer-field "leave unchanged" contract and
  avoids re-bumping `updated_at` for no-op saves.
- Domain-layer `Update()` deferred — both surfaces use inline
  updates today; refactoring both to a shared method is a
  separate cleanup task.

### 8c.5 — External tool links ✅

A "Tools" sidebar entry linking out to Grafana, Adminer,
RedisInsight, Vault UI, phpLDAPadmin. Card grid; cards render only
for tools with a configured URL.

**As-shipped scope:**
- Per-tool env vars on the admin-bff process (resolved Open
  Question 4 toward individual env vars over a single JSON map):
  `AKASHIC_BFF_TOOLS_GRAFANA_URL`, `…_ADMINER_URL`,
  `…_REDISINSIGHT_URL`, `…_VAULT_URL`, `…_PHPLDAPADMIN_URL`.
  Each defaults to empty.
- Backend: `pkg/admin_bff/handlers.go::handleAdminTools` returns
  `{tools: [{key, label, url}, ...]}` filtered to non-empty URLs.
  Session-gated to admin/root.
- Frontend: `<ToolsPage>` in `web/admin/src/components/`,
  rendered from a new `'tools'` entry in the sidebar's `Page`
  union. Hand-rolled SVG icons (Grafana bars, database cylinder,
  cube, lock, directory tree); no vendor logo licensing involved.
- Each card is an `<a target="_blank" rel="noopener">` styled
  to match `.panel.interactive` for clickable affordance, with
  an external-link glyph that brightens on hover.
- `.env.example` carries commented-out localhost defaults so the
  dev-mode experience works out of the box; `docker-compose.yml`
  forwards each env var to the admin-bff service with `:-` empty
  fallbacks so missing tools naturally elide.

**Why individual env vars over JSON:** each tool already has a
hardcoded label + icon on the FE (you can't render a meaningful
card without those), so the "operator can add arbitrary tools"
flexibility a JSON map would offer doesn't actually buy anything.
Individual vars are also easier to set in compose, easier to
template via Vault, and surface as discoverable keys in a
`docker compose config` dump.

**Deferred:**
- Health-ping coloring (green/yellow/red dots per tool). The FE
  can't reliably ping these directly (CORS), so it'd require a
  BFF-side prober. Marginal value — operators already see "tool
  down" the moment they click the link.
- "Add custom tool" UX. Falls into "design for hypothetical
  requirements" — every tool we'd want to surface is already in
  the catalog.

### 8c.6 — Policy management ✅

DB-backed singleton table `tenant_policies` holding the
deployment's runtime-tunable policy: password rules and the
self-service signup gate. Operator edits via the admin web's
Policy page; signup / register / password-policy-hint reads go
live to the DB row, so changes take effect on the next request
without a restart.

**As-shipped scope:**
- Schema: new `pkg/models/tenant_policy.go` with explicit columns
  (singleton `id=1`). Migration via AutoMigrate. First-run
  population in `pkg/akashic/core/context.go::Init` after
  migrations: `policy.Service.EnsureSingleton` reads YAML
  `Bootstrap.Password.*` defaults and inserts the row only if
  the table is empty. After first run, YAML's password section
  becomes bootstrap-only-defaults; runtime reads come from DB.
- Domain: `pkg/policy/policy.go` with `Service.Get`,
  `Service.PasswordPolicy` (auth-package shape adapter),
  `Service.SignupEnabled`, `Service.Update`. Sentinel
  `ErrInvalidPolicy` on per-field validity failures
  (MinLength must be in `[4, 256]`).
- Migrated callers: auth-server's `/signup` flow (template hint
  + submit validation) and api-server's `/users/register`
  + `/users/password-policy` now read live from DB. Bootstrap
  manager intentionally stays YAML-snapshot at construction
  (one-time deployment action; the DB row is created by
  EnsureSingleton during startup, before bootstrap can run).
- New `SIGNUP_DISABLED` gate on both signup paths:
  auth-server `/signup` + `/signup/submit` render a friendly
  403 page; api-server `/users/register` returns 403 with a
  distinct error code so the widget can render its own copy.
  Distinct from `BOOTSTRAP_INCOMPLETE` — different cause,
  different recovery path (admin UI vs CLI bootstrap-create-root).
- Control plane: `GET /policy` and `PATCH /policy` (singleton —
  no `:id`). NOT gated by `requireBootstrapComplete`, since the
  singleton row exists from app startup regardless of bootstrap.
  Audit logs to security channel with `caller_user_id` +
  `changed_fields`.
- Admin-bff: typed `PolicyGet`, `PolicyUpdate` + handlers +
  routes (`GET/PATCH /api/policy`). BFF resolves `caller_user_id`
  from the session and threads it through.
- Admin web: new `<PolicyPage>` mounted on a sidebar entry
  (shield icon). One form, only-changed-fields PATCH semantics
  (mirrors ClientsEdit / EditUserDialog), explicit help text
  noting that existing stored passwords are NOT re-validated
  against tighter rules — only new passwords going forward.
- Fail-open posture on the read path: when `policySvc` is nil
  or the DB read fails, callers fall back to a minimal
  MinLength=8 + lowercase-required policy and `SignupEnabled=true`.
  Consistent with the bootstrap-gate stance — better to keep
  signups working during a transient outage than to lock
  everyone out.

**Resolved Open Question 1** (tenant-policy storage model):
DB-backed table populated from YAML on first run. YAML becomes
bootstrap-only-defaults; subsequent edits go through the UI.
Hybrid (DB overrides YAML) was rejected — two-source-of-truth
drift is historically painful; one source plus first-run seeding
is cleaner.

### 8c.7 — Phasing notes

| Step | Size | Risk | Notes |
|---|---|---|---|
| 8c.1 banner | Small | Low | Pure aggregation; no schema work |
| 8c.5 tool links | Small | Low | Mostly env wiring + a card grid |
| 8c.3 server control | Small-Medium | Medium | Confirm-modal UX matters |
| 8c.2 user management | Large | Medium | Schema-clean but invariants are subtle |
| 8c.4 client edit/detail | Medium | Low | "More of the same shape" |
| 8c.6 policy management | Large | High | Storage-model decision required first |

**Suggested execution order**: 8c.1 → 8c.5 → 8c.3 → 8c.2 → 8c.4
→ 8c.6. Front-loads visibility and small wins before tackling
the schema-changing pieces.

### 8c.8 — Open questions (must resolve before starting)

1. **Tenant-policy storage** ✅ **resolved** (Phase 8c.6 shipped):
   DB-backed `tenant_policies` table populated from YAML on first
   run via `policy.Service.EnsureSingleton`. YAML's password
   section becomes bootstrap-only-defaults; subsequent edits go
   through the admin web's Policy page. Hybrid (DB overrides
   YAML) was rejected — two-source-of-truth drift is historically
   painful.
2. **User-deletion semantics** ✅ **resolved** (Phase 8c.2
   shipped with hard delete): DELETE removes the LDAP entry
   then the PG row; soft-delete is the orthogonal `is_disabled`
   flag. The 90-day deprovisioning loop is the reaper for the
   "user left silently" case; manual delete is the operator's
   explicit "gone now" action.
3. **"Type to confirm" gating threshold** ✅ **resolved** (Phase
   8c.3 shipped using this rule): type-to-confirm for actions
   that affect *other users* (auth stop, api stop, server quit,
   delete user, demote root); simple yes/no confirm for restart
   and reload actions; no confirm for start and pure-read
   actions. Confirm phrase is the literal action name in caps
   (`STOP AUTH SERVER`, `SHUTDOWN AKASHIC`) — AWS's pattern,
   easier to implement correctly than "type the hostname" and
   harder to do accidentally.
4. **Tool-link configuration shape** ✅ **resolved**: individual
   env vars per tool (`AKASHIC_BFF_TOOLS_*_URL`). Reasoning: each
   tool needs a hardcoded label + icon on the FE anyway, so the
   "JSON map for arbitrary tools" flexibility doesn't buy
   anything. Individual vars are also easier to set in compose
   and surface as discoverable keys in a `docker compose config`
   dump.

---

## Risks & open questions

| Risk | Mitigation |
|---|---|
| Spam signups | CAPTCHA on /signup; rate limits (Step 8.3); operator can disable public signup via env var |
| Users register accounts and immediately forget passwords (no email reset in Phase 8) | Forgot-password page is informational with operator contact. Admins can reset passwords via admin-bff. |
| Secret-rotation-by-malicious-owner attack on a popular client | Audit log every rotation; admin-bff override to disable a user account |
| Next.js choice ages out | App Router is stable as of Next.js 15; SSR + API routes are standard React patterns that translate to other frameworks if needed |
| Two BFFs (admin-bff in Go, portal in TS) drift apart | Shared docs (Step 8.5); shared config conventions; same audit-log allowlist pattern |
| LDAP password change semantics differ across LDAP servers | Test against OpenLDAP (our default) + AD; document the exact LDAP operations used; provide a fallback path that re-binds to verify |
| OAuth consent UX confusing for end-users | Iterate on copy; revisit with real users in Phase 9 |
| Rendering at the bare root domain conflicts with operator DNS conventions | Operator overrides the public hostnames via the existing public-URL envs (`AKASHIC_PORTAL_API_BASE_URL`, `AKASHIC_OAUTH_*_REDIRECT_URI`) and the proxy's nginx config — there is no dedicated `AKASHIC_PORTAL_DOMAIN` knob. |

## Files Summary (planned)

### New backend code

| Path | Purpose |
|---|---|
| `pkg/server/control/users_handlers.go` | New control-plane endpoints |
| `pkg/server/control/clients_handlers.go` | New control-plane endpoints |
| `pkg/server/control/consent_handlers.go` | (if Chapter 7 lands) |
| `pkg/models/oauth_consent.go` | (if Chapter 7 lands) |

### Modified backend code

| Path | Change |
|---|---|
| `pkg/models/user.go` | Add email_verified, email_verified_at, last_login_at (display name lives in LDAP cn, NOT postgres) |
| `pkg/models/client_service.go` | Add owner_user_id, description, homepage_url. **8b.3 Stage 1: also adds `Public bool` + `normalize()` invariants.** |
| `pkg/repository/user_repository.go` | Generalize CreateUser beyond bootstrap |
| `pkg/ldap/client.go` | Add ChangePassword |
| ~~`pkg/oauth/builtin.go`~~ | ~~Add `akashic-sample-nextjs` built-in client~~ — **REVERSED by 8b.3 Stage 4.** Sample is operator-registered, not a built-in. The only built-in now is `akashic-admin`, gated by `cfg.OAuth.AdminBFFEnabled`. |
| ~~`pkg/middleware/mtls.go`~~ | ~~Allowlist `portal.akashic.local` CN~~ — **REVERSED by the three-server architecture pivot.** The portal makes no mTLS calls. |
| `configs/config.yaml` | New portal section + support contact info |
| ~~`services/vault-agent/templates/portal-client.tpl`~~ | ~~New cert template~~ — **REVERSED with the mTLS removal above; portal has no client cert.** |
| ~~`services/vault-agent/config.hcl`~~ | ~~Register the new template~~ — **REVERSED, same reason.** |
| `services/proxy/nginx.conf` | New root-domain server block |
| `services/redisinsight/docker-entrypoint.sh` | Add DB 2 connection for portal sessions |
| `docker-compose.yml` | Add `portal` service |
| `.env.example` | ~~New AKASHIC_PORTAL_* vars~~ — **8b.5: most AKASHIC_PORTAL_* runtime envs were removed.** Surviving ones: `AKASHIC_PORTAL_API_BASE_URL` (widget URL), `AKASHIC_PORTAL_TENANT_ORIGINS` (CORS allowlist). New: `AKASHIC_OAUTH_ADMIN_BFF_ENABLED` (replaces `AKASHIC_OAUTH_BUILTIN_CLIENTS`). |

### New portal code (everything under `web/portal/`)

Whole new subtree — see Chapter 2, Step 2.2 for the layout.

### New docs

| Path | Purpose |
|---|---|
| `doc/phase-8-revision.md` | Eventual as-built doc |
| `doc/study/10-portal.md` | Study-guide chapter |

---

## Out-of-band notes

Things to address before starting Chapter 1:

1. **Pick the Next.js version**: 14 LTS or 15 latest. Recommendation:
   15 (App Router stable, server actions stable).

2. **Pick a styling system**: Tailwind only, or Tailwind + shadcn/ui,
   or full design system. Recommendation: Tailwind + shadcn/ui (good
   defaults, full customization).

3. **Decide on consent screen scope**: Phase 8 (full implementation,
   Chapter 7) vs Phase 9 (defer). Recommendation: include in Phase 8
   for any non-built-in client; built-ins skip consent.

4. **Decide on captcha integration**: Cloudflare Turnstile vs
   hCaptcha vs none. Recommendation: Turnstile (free, privacy-friendly,
   trivial integration). Operator-toggleable.

5. **Decide on the support-contact email/URL** that the
   forgot-password page will display, and where the operator sets
   it (env var `AKASHIC_PORTAL_SUPPORT_CONTACT`).

These decisions should be made *before* Chapter 1 starts so the
data model + endpoints can be shaped around them.

---

## Phasing of this Phase 8

Even within Phase 8, the chapters have natural dependencies:

```
Chapter 1 (data model + control-plane API)
    ↓
Chapter 2 (Next.js scaffold) — independent of 1 in theory, but
                                BFF wiring needs API contracts
    ↓
Chapter 3 (portal session, auth, mTLS) — depends on 2
    ↓
Chapter 4 (public surface) — depends on 1, 3
    ↓
Chapter 5 (user profile) — depends on 4 (need to be logged in first)
    ↓
Chapter 6 (developer surface) — depends on 5
    ↓
Phase 8b (mid-plan pivot — already shipped)
    ↓
Phase 8c (admin console expansion — NEW, before consent)
    ↓
Chapter 7 (consent — if included)
    ↓
Chapter 8 (verification + polish)
```

Recommended approach: build chapter 1 first (backend), then 2+3
(frontend scaffold), then 4 (signup) end-to-end, then 5/6 in
parallel, then 8b (already done), then 8c (admin console
expansion), then 7 if scoped in, then 8. Keeps "always have a
deployable thing at every milestone" — after chapter 4 you've got a
working signup-and-login flow even if profile/clients aren't yet
done.

Estimated complexity (rough):

| Chapter | Lines of new Go | Lines of new TS | Notes |
|---|---|---|---|
| 1 | ~1500 | — | API surface + models + auth checks |
| 2 | — | ~500 | Scaffold, no logic |
| 3 | — | ~800 | mTLS + OAuth + session machinery |
| 4 | — | ~1500 | Public pages + flows |
| 5 | — | ~1000 | Authenticated profile |
| 6 | — | ~1500 | Developer client management |
| 8c | ~1200 | ~1500 | Admin console expansion (banner, users, server control, client edit, tool links, policy mgmt) |
| 7 | ~400 | ~400 | Consent (optional) |
| 8 | ~200 | ~200 | Tests + docs |

Phase 8 is roughly **1.5×–2× the scope of Phase 7** in raw code volume.
Email infrastructure being deferred to Phase 9 cuts roughly 600 LOC
of Go + the Mailpit/SMTP container churn out of this phase, so the
remaining work is more concentrated on the frontend than Phase 7
was.
