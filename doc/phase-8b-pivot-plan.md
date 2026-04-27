# Phase 8b — Widget Pivot Plan

> **Status**: Plan, pending approval. Replaces the original Chapter 6
> work in `phase-8-plan.md`; chapters 1–5 stand as shipped.

## Context

The original Phase 8 design treated the Next.js portal as the
primary product surface: tenants pulling Akashic deploy our portal
and end users land on it. After investigating how tenants actually
integrate identity providers, we're pivoting:

**Akashic ships widgets + APIs. The portal is sample code, not core.**

Tenants who pull Akashic will integrate identity into *their own
existing product*. They want to embed Akashic's surfaces — signup,
profile, password change, OAuth client management — inside their
product UI, styled with their own design system, not run a separate
Akashic-branded site alongside their own.

The portal we built in chapters 1–5 is genuinely useful as a
**reference implementation** that exercises every API and proves
the whole stack works end-to-end. Demoting it to opt-in sample
status (`--profile sample`) preserves that value while making the
"Akashic is widgets, not a portal" framing the default.

## Goals

1. **Akashic core is the widget bundle, not the portal.** The new
   first-class deliverable is a small JS file tenants drop into
   their product (`<script src="https://auth.<tenant>/widgets/akashic.js">`),
   plus the api/auth servers behind it.
2. **Headless components, tenant-styled.** Web Components with
   `::part()` exposure and CSS custom properties; tenants bring
   their own CSS.
3. **The Next.js portal becomes a sample.** Gated behind `--profile sample`
   in compose. Stops being on the critical path. Heavily decoupled
   from Akashic internals — it consumes the public widget surface
   the same way any tenant would, demonstrating the integration
   story.
4. **Auth-server hosted pages stay first-class.** `/login`,
   `/signup` (hosted), `/consent`, `/logout` are full-page surfaces
   reached by OAuth redirect; tenants can't reach them with CSS
   from across the redirect, so they get a tenant-supplied
   stylesheet URL via env.

## Non-goals

- Building an admin-panel theme editor (collapsed out — tenants
  bring their own CSS).
- Migrating admin-bff's UI to widgets (admin-bff is operator-
  facing, separate concern, stays).
- Public OAuth clients with PKCE-only mode (useful for
  fully-frontend tenants but not blocking the widget pivot;
  tracked as a follow-up).

## Architecture changes

### Before (current state)

```
Tenant deploys Akashic
└── Next.js portal at akashic.<tenant>      ← THE product surface
    ├── Server-side BFF routes (/api/auth/*, /api/users/me, /api/clients/*)
    ├── Iron-session sealed cookie + Redis DB 2 backend
    ├── Portal proxies api-server calls with bearer token
    └── End users sign up / manage profile / register OAuth clients HERE
```

### After (target state)

```
Tenant deploys Akashic
├── Auth server  (auth.<tenant>:8080)        ← Pure OIDC + /session/token bearer-exchange
│                                              for first-party widgets
├── API server   (api.<tenant>:8082)         ← Resource API + widget bundle hosting
│                                              (bearer-only — bearer comes from /oauth/token
│                                              for Clients, /session/token for widgets)
├── Control      (ctrl.<tenant>:8081, mTLS)  ← Operator/admin-bff plane (unchanged)
└── Sample portal at <tenant> (root domain)  ← --profile sample, OFF by default
                                              (real tenants put their own product here)

Tenant's own product (acme.com — root domain)
├── <script src="https://api.acme.com/widgets/akashic.js"></script>
├── Tenant's stylesheet (or shipped akashic-default.css)
└── <akashic-signup>, <akashic-profile>, <akashic-change-password>,
    <akashic-clients>, <akashic-forgot-help>     ← integrated natively

Auth flow for widgets (host-scoped cookie + bearer exchange):
  1. User logs in on auth.acme.com/login → host-scoped session cookie
     set on auth.acme.com (NOT visible to other subdomains)
  2. Widget on acme.com mounts → POST auth.acme.com/session/token
     with credentials: 'include' (cookie travels via same-site SameSite=Lax)
  3. auth.acme.com validates cookie, returns {access_token, expires_in: 900}
  4. Widget caches bearer in module-scoped JS variable (NOT localStorage)
  5. Widget calls api.acme.com/* with Authorization: Bearer <token>
  6. On 401 or near-expiry, widget re-fetches /session/token

Security properties:
  - Session cookie host-scoped to auth.acme.com only (legacy.acme.com etc. cannot see it)
  - Bearer is short-lived (15 min) and in-memory only (XSS exposure is page-lifetime)
  - HttpOnly on cookie (JS can't steal it)
  - CORS allowlist gates which origins can call /session/token at all
  - Bearer pattern is naturally CSRF-resistant (Authorization header not auto-sent)
```

### What gets demoted

| Component | Status change |
|-----------|---------------|
| `services/portal/` (compose service) | Add `profiles: [sample]`. Off by default. |
| `web/portal/` (Next.js codebase) | Becomes a *consumer* of the public widget surface. Most internals deleted. |
| Portal's BFF API routes (`app/api/users/me`, `app/api/auth/signup`, etc.) | **Deleted**. Widgets call api-server directly. |
| Portal's iron-session + Redis DB 2 | **Deleted**. Auth-server holds the session; widgets read it via cookie. |
| Portal's CSRF middleware | **Deleted**. Widgets handle their own CSRF (same-origin to auth.<tenant>). |
| Portal's bearer-token api client (`server/api-client.ts`) | **Deleted**. |

### What gets added

| Component | Purpose |
|-----------|---------|
| `web/widgets/` | New Lit-based Web Component package. Builds to `dist/akashic.js` (single bundle, ~25 KB). |
| `web/widgets/styles/akashic-default.css` | Default stylesheet. Optional for tenants. |
| `web/widgets/docs/parts.md` | Catalogue of every `::part()` and `--akashic-*` CSS variable. The styling API. |
| **API-server static asset routes** | `GET /widgets/akashic.js` and `GET /widgets/akashic-default.css` serve the compiled bundle + stylesheet. Built into the akashic-server image. **Hosted on api.<tenant>**, not auth.<tenant>, to keep auth-server pure-OIDC. |
| `AKASHIC_PORTAL_THEME_CSS_URL` env | Optional. If set, auth-server's `/login`, `/signup` (hosted), `/consent` include it via `<link rel="stylesheet">`. |
| **Auth-server `POST /session/token` endpoint** | The bearer-exchange endpoint. Widget POSTs from tenant origin with `credentials: 'include'`; auth-server validates the host-scoped session cookie via SameSite=Lax cross-origin send, mints a short-lived bearer JWT (15 min, signed by the OAuth keystore), returns `{access_token, expires_in}`. CORS-restricted to operator-configured tenant origins. |
| **Widget runtime token cache** | `getAccessToken()` helper in the widget bundle. Caches a bearer in JS module scope, fetches `/session/token` on miss or near-expiry, exposes `Authorization: Bearer` for API calls. Bearer is in-memory only — never localStorage (XSS-safe). |
| CORS config | Operator-configured origin allowlist (`AKASHIC_TENANT_ORIGINS`) — list of tenant-product origins permitted to call api.<tenant> *and* auth.<tenant>/session/token with credentials. Enforced on both servers. |
| `doc/widgets-integration.md` | Tenant-facing integration guide. Three tiers (default stylesheet / CSS-variable overrides / full custom). |

**NOT added** (alternatives considered and rejected):

- `AKASHIC_COOKIE_DOMAIN` env / parent-scoped session cookie — would leak the session cookie to every subdomain of the tenant's eTLD+1, including ones outside Akashic's deployment. Replaced by the host-scoped cookie + bearer-exchange pattern (Option C in the design discussion).
- API-server cookie auth middleware — no longer needed. API-server stays bearer-only; bearers come from either `/oauth/token` (SSO Clients) or `/session/token` (first-party widgets). Single auth path, multiple bearer sources.

### What stays unchanged

- All work in chapters 1–5 of `phase-8-plan.md` — domain model, api-server,
  auth-server, OAuth flow, control plane, bootstrap gate, three-server architecture.
- Admin-bff (operator surface, separate concern).
- The auth-server's `/login`, `/signup` (hosted variant), `/consent`, `/logout`
  pages — they keep their server-rendered template; we just add a tenant-CSS hook.
- OpenAPI specs in `services/api-docs/`.

## Implementation steps

### Step 1 — Compose pivot (low risk, zero functional change)

1. `docker-compose.yml` — add `profiles: [sample]` to the `portal:` service.
   The portal stops coming up by default; `docker compose up -d` brings up
   only the auth/api/ctrl + infra. Operators who want the sample run
   `docker compose --profile sample up -d`.
2. Update top-level docs (README, `.env.example`, `doc/phase-8-plan.md`)
   to reflect the new default.

This step alone clarifies framing without touching any code.

### Step 2 — Widget bundle scaffolding

1. Create `web/widgets/` with Vite + Lit + TypeScript setup.
2. Build pipeline: `npm run build` produces `dist/akashic.js` and
   `dist/akashic-default.css`. Tree-shaken, minified, source-mapped.
3. Bake the build artefacts into the `akashic` image at build time
   (`services/akashic/Dockerfile` runs the widget build before
   compiling the Go binary, copies artefacts into `/usr/local/share/akashic-widgets/`).
4. **API-server adds two static-file handlers** — `GET /widgets/akashic.js`
   and `GET /widgets/akashic-default.css` — that read from the
   baked-in directory. (Auth-server intentionally NOT involved —
   widgets co-locate with the API they call, not with the OIDC
   server.)

### Step 3 — First widget end-to-end (`<akashic-signup>`)

The smallest end-to-end slice that validates the whole architecture.

1. Implement `<akashic-signup>` as a Lit component with open Shadow DOM:
   form, validation, `::part()` exposure on every styleable region,
   POST to api-server's `/users/register`.
2. Default stylesheet rules for the signup widget — visually
   matches the current portal's signup page.
3. CORS config on api-server: read `AKASHIC_API_CORS_ORIGINS` env var,
   apply on `/users/register` and other public endpoints.
4. End-to-end test: a static HTML page in `web/widgets/example/`
   that imports the bundle, drops in `<akashic-signup>`, posts to
   the running api-server.

### Step 4 — Bearer-exchange for first-party widgets

The blocker for authenticated widgets (`<akashic-profile>`, `<akashic-change-password>`,
`<akashic-clients>`). They need a bearer token to call the api-server, but
they don't have an OAuth flow (no BFF in the picture). The host-scoped
session cookie + bearer-exchange pattern (Option C from the design
discussion) gives us this without leaking session cookies across
subdomains.

1. **Auth-server `POST /session/token` endpoint.**
   - Reads the host-scoped session cookie set by `/login` (cookie has
     `SameSite=Lax`, so it travels on cross-origin same-site POSTs from
     `acme.com` to `auth.acme.com` — same eTLD+1 counts as same-site
     for the cookie's send-policy purposes).
   - Validates the cookie against the session store (Redis DB 0) — same
     check `/authorize` uses.
   - Mints a short-lived (15 min) JWT bearer signed by the OAuth
     keystore. Same shape as `/oauth/token` access tokens — same
     issuer, same audience, same scope claims.
   - Returns `{access_token, expires_in, token_type: "Bearer"}`.
   - 401 if no valid session cookie — widget renders sign-in CTA.

2. **CORS on /session/token.** Only origins in `AKASHIC_TENANT_ORIGINS`
   are allowed to receive the response. This is the access control —
   prevents `evil.com` from silently exchanging a victim's auth.<tenant>
   cookie for a bearer.

3. **Widget runtime token cache.** A small helper in the widget
   bundle:
   ```ts
   let cached: { token: string; expiresAt: number } | null = null;

   async function getAccessToken(): Promise<string | null> {
     if (cached && cached.expiresAt > Date.now() + 30_000) {
       return cached.token;
     }
     const res = await fetch("https://auth.<tenant>/session/token", {
       method: "POST",
       credentials: "include",
     });
     if (!res.ok) return null;
     const { access_token, expires_in } = await res.json();
     cached = { token: access_token, expiresAt: Date.now() + expires_in * 1000 };
     return access_token;
   }
   ```
   - In-memory only — never localStorage, never cookie. XSS exposure
     is bounded to the page's lifetime, not the session's.
   - Refreshes 30 seconds before expiry to avoid race-with-clock.

4. **API-server stays bearer-only.** No new auth middleware needed. The
   bearer from `/session/token` validates the same way as bearers from
   `/oauth/token` — same JWKS, same middleware, same handler logic.
   The api-server doesn't even know whether a given bearer came from
   a widget or an SSO Client.

5. **CSRF.** Inherent in the bearer pattern. Cross-origin attackers
   cannot forge an `Authorization` header on the victim's browser,
   and cannot read responses to credentialed cross-origin calls
   without a permissive CORS allowlist (which we don't grant to
   arbitrary origins). No double-submit cookie dance needed.

### Step 5 — Authenticated widgets

Replicate the Step 3 pattern for the post-auth surfaces:

1. `<akashic-profile>` — read view; calls `GET /users/me`.
2. `<akashic-profile-editor>` — edit view; calls `PATCH /users/me`.
3. `<akashic-change-password>` — calls `POST /users/me/password`.
4. `<akashic-forgot-help>` — calls `GET /users/forgot-password-help`.

### Step 6 — Developer-surface widget (`<akashic-clients>`)

This replaces the original Chapter 6 (developer-surface portal pages)
entirely. Largest widget — list/detail/create/edit/rotate-secret/delete
flows. Calls api-server's `/clients/*` endpoints.

### Step 7 — Auth-server hosted pages: theme-CSS hook

1. New env: `AKASHIC_PORTAL_THEME_CSS_URL`. Optional.
2. Auth-server's `login.html.tmpl`, `error.html.tmpl`, future
   `signup.html.tmpl` and `consent.html.tmpl` — include
   `<link rel="stylesheet" href="{{.ExternalThemeCSS}}">`
   in `<head>` when the env var is set, after the default
   stylesheet.
3. Operators who want pixel-matched OAuth pages publish their
   stylesheet at any URL and point the env var at it.

### Step 8 — Sample portal: gut + rebuild as a widget consumer

The Next.js portal's job changes. It's no longer a BFF; it's a
demonstration of how a tenant's product would integrate widgets.

**Delete:**

- `web/portal/server/` entirely (api-client, session, oauth, audit, csrf, pre-session)
- `web/portal/app/api/*` proxy routes (auth/signup, users/me, users/me/password)
- `web/portal/middleware.ts`
- `web/portal/lib/redis.ts`, `web/portal/lib/csrf-client.ts`
- `iron-session`, `ioredis`, `oauth4webapi` from `package.json`
- Redis DB 2 / RedisInsight third card / `AKASHIC_PORTAL_REDIS_*` env

**Keep / simplify:**

- Pages — but they're now thin shells that import the widget bundle
  and drop in `<akashic-signup>` etc.
- `lib/env.ts` — only brand-name and tagline read from env (operator
  customization for the sample).
- Health endpoint, basic Next.js scaffold.

**Result:** the portal directory shrinks dramatically (estimated
~80% line reduction). Each page is essentially:

```tsx
// app/(public)/sign-up/page.tsx (after pivot)
export default function SignUpPage() {
  return (
    <main>
      <h1>Create your account</h1>
      <akashic-signup />
    </main>
  );
}
```

The portal's Dockerfile becomes simpler too — no need to ship
ioredis or iron-session in the runtime bundle.

### Step 9 — Documentation

1. `doc/widgets-integration.md` — tenant integration guide.
   Three-tier customization examples. Setup steps. CORS-origins
   config requirement.
2. `doc/widgets-styling.md` — the styling API. Every component's
   `::part()` regions and `--akashic-*` variables.
3. Update `doc/phase-8-plan.md` with a "superseded by phase-8b"
   marker on chapters 6/7/8.
4. Update `CLAUDE.md` if it currently describes the portal as
   the primary surface.

### Step 10 — Compose: `--profile sample` for everything portal-related

Already done in Step 1 for the portal service. Sweep for any
remaining portal-coupled bits (RedisInsight third card?
nginx-proxy root-domain block?) and tag them sample-profile too,
or document that they're sample-only.

## Decisions made

The original draft had six open questions. These have been resolved:

1. **Auth model: bearer everywhere on api-server; bearer source
   differs by integration type.** ✅ REVISED — was originally
   "cookie for first-party, bearer for third-party," but the
   subdomain-cookie security trade-off pushed us to a cleaner
   pattern:
   - **First-party widgets** (Tenant product on `acme.com`):
     widget calls `auth.<tenant>/session/token` to exchange the
     host-scoped session cookie for a short-lived (15 min) bearer.
     Bearer goes in `Authorization` header on api-server calls.
     Bearer is in-memory only (never localStorage).
   - **Third-party Clients** (SSO from `widget.com`): standard
     OAuth flow → `/oauth/token` → bearer in their backend.
   - **API-server is bearer-only.** Both bearer sources mint
     tokens via the same OAuth keystore; api-server validates them
     identically.
   - **Why this is better than the original cookie-everywhere
     plan**: session cookie stays host-scoped to `auth.<tenant>`,
     so other subdomains of the tenant's eTLD+1 (e.g.,
     `legacy.acme.com`) cannot see it. Strict isolation.

2. **CORS allowlist: deployment-wide for now; per-client when
   client registration is implemented.** ✅ DECIDED.
   - Phase 8b: operator sets `AKASHIC_TENANT_ORIGINS` env var
     (comma-separated list of allowed origins, e.g.
     `https://acme.com,https://www.acme.com`). Enforced on
     **both** api.<tenant> (resource API CORS) **and**
     auth.<tenant>/session/token (bearer-exchange CORS).
   - Future (post-8b, when tenants programmatically register
     additional Clients): each registered `client_services` row
     carries its own allowed CORS origins, dynamically extending the
     deployment-wide list. *Tracked as future work — explicitly
     deferred.*

3. **Widget framework: Lit.** ✅ DECIDED.
   - Small (~5 KB), mature, framework-neutral, Web Components-native.
   - Sticking with Lit unless a deal-breaker appears mid-implementation.

4. **TypeScript types / npm publishing: keep private for now.**
   ✅ DECIDED.
   - The widget bundle is built and served from `auth.<tenant>` only.
     Tenants integrate via `<script src="...">`, no npm install.
   - No `@akashic/widgets` or `@akashic/widgets-types` npm packages
     in this phase.
   - Once the API is solid and we have external usage, future
     consideration for public npm publishing.

5. **Sample: keep Next.js for Phase 8b; add a static-HTML sample
   later.** ✅ DECIDED.
   - The existing Next.js portal gets gutted (Step 8) and becomes
     a thin widget consumer. Stays as the "tenants with a backend"
     reference — demonstrates BOTH the OAuth+BFF pattern (for
     server-side bearer access) AND widget integration (for
     client-side cookie access).
   - **Second sample at `web/sample-static/` deferred** until
     public/PKCE OAuth client support lands. That sample will
     demonstrate "tenants without a backend" — pure HTML, widgets
     only, public OAuth client.
   - Renaming `web/portal/` → `web/sample-nextjs/` is OPTIONAL and
     can ship with the second sample (so both directories appear at
     once with consistent naming).

6. **OAuth public/PKCE clients: deferred follow-up.** ✅ DECIDED.
   - Not blocking Phase 8b. The Next.js sample uses confidential
     OAuth client (current state, `client_secret_post`).
   - Becomes blocking only when the static-HTML sample lands;
     scheduled as a precursor to that work.

## Adjusted scope notes

Given the decisions above, two clarifications to the implementation
steps:

- **Step 4 (cookie-auth on api-server)** is now the primary auth
  story for first-party widgets; bearer auth becomes the SSO/Client
  story. The api-server middleware needs to accept both, but the
  documentation should reflect "cookies for widgets, bearer for
  Clients" as the default mental model.
- **Step 8 (sample portal rebuild)** keeps the Next.js BFF's OAuth +
  iron-session paths — they demonstrate the "tenants with a backend"
  pattern and let the BFF make server-side bearer calls. What gets
  deleted is the BFF's API-proxy routes (`/api/users/me`,
  `/api/auth/signup`, etc.) — those are now widget territory. The
  BFF stays for OAuth code exchange + session storage; the widgets
  layer on top using the same cookie the BFF's session-establish
  path emits.

## Risks

1. **Cross-origin cookie story breaks for tenants on different
   eTLD+1.** The widget pattern requires same eTLD+1 between the
   tenant's product and the Akashic deployment. Tenants whose
   product is on a different domain fall back to OAuth-redirect
   integration only (no widgets). Need to document this constraint
   loudly in the integration guide.
2. **Default stylesheet "looks like Akashic" for tenants who don't
   override.** If a tenant ships our default stylesheet to
   production, every Akashic deployment would look the same. We
   should make this NOT-the-recommended-tier in the integration
   guide and gently push tenants toward Tier 1 (CSS variables) or
   Tier 2 (full custom).
3. **Widget bundle versioning.** Once tenants embed
   `<script src="https://auth.<tenant>/widgets/akashic.js">`, that
   bundle's behavior is part of the contract. Need to think about
   versioning — should the URL include a major version
   (`/widgets/v1/akashic.js`)? My instinct: yes, from the start,
   so we can ship breaking changes via `/widgets/v2/`.
4. **Sample portal becomes irrelevant and bitrots.** If nobody runs
   `--profile sample`, the sample stops being maintained. Mitigate
   by including the sample in CI (smoke test sign-up flow against
   the sample weekly?).

## Verification

End-to-end the pivot is complete when:

1. `docker compose up -d` (no `--profile sample`) brings up a
   functional Akashic that's 100% widget-ready: tenants can include
   the bundle, drop in `<akashic-signup>`, and create users.
2. `docker compose --profile sample up -d` additionally brings up
   the sample portal, which works as a tenant integration would —
   embedding widgets, no internal API proxying.
3. The api-server accepts both bearer (existing BFF callers) and
   cookie auth (widgets) on `/users/me`, `/users/me/password`,
   `/clients/*`.
4. CORS is correctly configured: a widget on `acme.com` can call
   `api.acme.com` with credentials and succeed; a widget on
   `evil.com` cannot.
5. The sample portal's `package.json` no longer depends on
   `iron-session`, `ioredis`, or `oauth4webapi`.
6. `doc/widgets-integration.md` exists with a working three-tier
   example.

## Sequencing recommendation

The work splits cleanly into a "core pivot" (steps 1–4) and an
"adoption" (steps 5–10). The core pivot establishes that widgets
work end-to-end with one example component; the adoption phase
fans out to the full widget set and rebuilds the sample.

A reasonable schedule:

- **Week 1**: Steps 1, 2, 3 (compose pivot, scaffold, first widget).
- **Week 2**: Step 4 (cookie auth on api-server). Unblocks all
  authenticated widgets.
- **Week 3**: Step 5 (rest of public + post-auth widgets except clients).
- **Week 4**: Step 6 (developer-surface widget — biggest).
- **Week 5**: Steps 7, 8, 9 (auth-server theme hook, sample portal
  rebuild, documentation).
- **Week 6**: Step 10 (compose sweep, polish, verification).

Aggressive but feasible if no big surprises in cookie-auth or CORS.

---

## Files referenced

- `doc/phase-8-plan.md` — original plan; this document supersedes
  chapters 6+, leaves 1–5 intact.
- `docker-compose.yml` — `portal:` service gets `profiles: [sample]`.
- `web/portal/` — heavy gut + rebuild as widget consumer.
- `services/akashic/Dockerfile` — bake widget bundle artefacts.
- `pkg/server/auth/` — add `/widgets/akashic.js`, `/widgets/akashic-default.css`
  static handlers; theme-CSS hook on hosted templates.
- `pkg/server/api/` — cookie-auth alternative path; CORS config.
- `web/widgets/` — new package, Lit-based components.
- `services/api-docs/` — extend OpenAPI specs to cover the cookie-auth alternative.
- `.env.example` — `AKASHIC_API_CORS_ORIGINS`, `AKASHIC_PORTAL_THEME_CSS_URL`.
