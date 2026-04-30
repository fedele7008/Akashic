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

### Step 7.1 — Consent policy

Decide when consent is required:
- **Built-in clients** (`akashic-admin` only — see Phase 8b.3
  Stage 4 for why the samples are no longer built-ins): no
  consent.
- **First-party tenant clients** (registered via CLI or admin
  web — including the samples post-pivot): consent on first
  authorization, remembered thereafter.

Recommended: consent on first authorization per (user, client),
remembered in postgres `oauth_consents` table.

### Step 7.2 — `oauth_consents` table

`(user_id, client_id, scopes, granted_at)`. Lookup during /authorize.

### Step 7.3 — Auth-server consent redirect

When `/authorize` finds a logged-in user but no consent record for
this (user, client, scopes) tuple → redirect to portal's
`/consent?...`. The portal renders the consent screen, user clicks
Approve/Deny, portal POSTs back to akashic to record consent →
akashic completes the flow.

### Step 7.4 — Consent UI

Page showing the client's name, description, homepage URL, and the
scopes being requested in plain English. Two buttons: Approve,
Cancel.

### Step 7.5 — Revoke-consent UI

`/profile/connected-apps` — lists apps the user has granted consent
to, with revoke buttons. Revoking deletes the consent row +
invalidates any active sessions for that (user, client).

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
- **`IsTenantPortal` flag on `client_services`** — purely a label
  for visual distinction in admin UI / CLI list output, marking the
  operator's own portal client apart from third-party developer
  integrations. Cross-row constraint enforced at the domain layer
  (`pkg/clientservice/`): at most one row may set it. An
  earlier-considered companion `SignUpURL` operator-override was
  added then removed once the auth-server-hosted /signup made it
  redundant — see commit history around 2026-04-29 for the cleanup.
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

### 8c.1 — Setup-status banner ⏳

A sticky banner across every admin page surfacing "what still
needs doing" — bootstrap complete? tenant portal registered? LDAP
healthy? Vault unsealed? Each item links to a one-click "go fix
it" path.

- Backend: `GET /admin/setup-status` returns
  `{bootstrap_complete, tenant_portal_registered, ldap_ok, vault_ok}`.
  Aggregator queries each subsystem; subsystem failures degrade
  gracefully (the banner surfaces "unknown" rather than 500ing
  the page).
- Frontend: `<SetupStatusBanner>` rendered above the topbar,
  hidden when all checks pass. Each incomplete item shows
  remediation copy + a deep link to the matching admin action.

Why first: several other 8c features depend on these gates (no
user management before bootstrap; no scoped roles before a tenant
portal exists). Building the visualization first makes the rest
of 8c's UX coherent.

### 8c.2 — User management ⏳

The biggest gap. Today the admin-bff has zero user-management
UI; operators bootstrap the root user via CLI and that's the
entire story. This step adds full CRUD with the safety invariants
user management actually needs.

- New shared package `pkg/usermanagement/` (mirrors
  `pkg/clientservice/`). Sentinel errors: `ErrLastRoot`,
  `ErrSelfDemotion`, `ErrSelfDeletion`. Cross-row invariants
  enforced at the domain layer:
  - The last `root` user can't be demoted or deleted (would
    permanently brick the deployment).
  - A user can't demote or delete themselves through this surface
    (forces an out-of-band confirmation path).
- Endpoints (api-server, bearer-gated to `admin`/`root`):
  - `GET /users` — paginated, filterable by `user_type`,
    `is_disabled`, `missing_identity`.
  - `GET /users/:id`
  - `PATCH /users/:id` — fields: `user_type`, `is_disabled`.
  - `DELETE /users/:id` — semantics depend on Open Question 2.
- LDAP plumbing: deletion needs to delete the LDAP entry too.
  Today we soft-delete in PG and let the deprovisioning loop
  catch up — fine for "user left the org" but wrong for
  "operator wants this account gone now."
- Frontend: list page with search + filters, detail/edit modal,
  promote/demote buttons gated behind a confirm dialog.

### 8c.3 — Server control panel ⏳

Mostly proxy work — the control server already exposes
`/auth/{start,stop,restart}`, `/server/quit`, `/status`, and
`/config/reload`. Surface them in the admin UI.

- Backend: thin admin-bff routes that proxy each control
  endpoint. No new control-plane endpoints needed.
- Frontend: a "Server" page with a status badge per subsystem and
  action buttons. Destructive actions (`server quit`, `auth stop`)
  gated behind a "type the deployment hostname to confirm" modal,
  matching the AWS pattern for production deletions.

### 8c.4 — Client services: detail + edit ⏳

Round out the client-management surface. Today: list + create +
delete + rotate-secret. Missing: detail view, edit form, audit
log of who-changed-what.

- Backend: `GET /clients/:id` and `PATCH /clients/:id` on both
  the api-server (owner-scoped) and control-plane (operator-
  scoped). Editable fields: `name`, `description`, `homepage_url`,
  `redirect_uris`, `allowed_scopes`, `role_allowlist`,
  `require_pkce` (WEB only). Immutable: `client_id`,
  `client_type`, `built_in`, `is_tenant_portal`, `owner_user_id`.
- Domain: extend `pkg/clientservice/` with `Update()` — same
  shape as `Create()`, same sentinel-error pattern. Enforces
  the immutability rules above.
- Frontend: replace the current "click-row → no-op" with a real
  detail page; edit form with the same WEB/SPA disambiguation
  copy used by the create form.
- The `<akashic-clients>` widget (8b.3 Stage 3) gains its edit
  surface for free once the api-server `PATCH` exists.

### 8c.5 — External tool links ⏳

Cheap and useful. A "Tools" section linking out to Grafana,
Adminer, RedisInsight, Vault UI, phpLDAPadmin, Loki.

- URLs **must** be operator-configurable — these run on
  different hosts in production. New env vars (concrete shape
  pending Open Question 4):
  `AKASHIC_ADMIN_TOOL_GRAFANA_URL`, `AKASHIC_ADMIN_TOOL_ADMINER_URL`,
  etc., or a single JSON map.
- Frontend: link grid that only renders entries with a configured
  URL — no broken cards in production where (e.g.) Adminer isn't
  deployed.
- v1 ships static cards. Health-ping coloring (green/yellow/red
  dots) deferred.

### 8c.6 — Policy management ⏳

The architecturally weighty piece. Today policy lives in two
places:
- **Tenant-level** (password rules, session TTL, default scopes)
  in YAML config, hot-reloadable via `/config/reload`.
- **Per-client** (`redirect_uris`, `allowed_scopes`,
  `role_allowlist`, `require_pkce`) in `client_services` rows.

Per-client policy is mostly already there — the create form
exposes most fields and 8c.4's edit form completes that surface.
So 8c.6 is **predominantly tenant-level policy**: choose the
storage model (Open Question 1), build the UI, and decide which
config keys move into the editable surface.

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

1. **Tenant-policy storage** — DB-backed table, read-only-config,
   or hybrid (DB overrides YAML)? Hybrid is most flexible but
   historically painful (two sources of truth that drift).
   Leaning recommendation: DB-backed table populated from YAML
   on first run; subsequent edits go through the UI; YAML
   becomes bootstrap-only-defaults.
2. **User-deletion semantics** — Hard delete (PG row + LDAP
   entry gone immediately) or soft-delete with grace period
   (mirrors the existing 90-day deprovisioning behavior)? Soft
   is safer; hard matches operator intuition.
3. **"Type to confirm" gating threshold** — Which actions
   warrant it? Default proposal: anything affecting *other users*
   (delete user, demote root) or *shared state* (server quit,
   auth stop). Plain client edits and tool-link clicks don't.
4. **Tool-link configuration shape** — Individual env vars per
   tool (`AKASHIC_ADMIN_TOOL_*_URL`) or a single JSON map
   (`AKASHIC_ADMIN_TOOLS={"grafana":"...","adminer":"..."}`)?
   Individual is simpler to set in compose; JSON is easier to
   extend without code changes.

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
