# Chapter 05 — The Admin BFF

> **Goal**: by the end of this chapter, you should understand the BFF
> pattern as we use it, why the React FE is embedded in the Go binary,
> and how lazy initialization decoupled the BFF from the akashic
> server's startup ordering.

## What is a BFF?

**BFF = Backend For Frontend**. It's a server that sits between a
frontend (typically a SPA) and one or more backend APIs. Its job is
to translate between the conventions the frontend expects (cookies,
session-based auth, friendly JSON envelopes) and the conventions the
backend uses (mTLS, raw protocol APIs, sometimes binary formats).

In Akashic's case:

- **Frontend** is a React SPA at `web/admin/`. It makes `fetch()`
  calls to `/api/*` and `/oauth/callback` and expects cookies for
  session state.
- **Backend** is the akashic control plane at `https://ctrl.akashic.local:8081`,
  which speaks mTLS. The browser can't speak mTLS to it directly —
  browsers don't ship with akashic-issued client certs.

The BFF solves this by being mTLS-authenticated itself (it has a
`bff.akashic.local` client cert) and translating browser HTTP
calls into mTLS calls to the akashic server.

## The "FE embedded in Go binary" pattern

The React FE is *not* served from a separate nginx or static-files
host. It's compiled by Vite (`npm run build` → static files in
`cmd/admin-bff/dist/`), then **embedded into the admin-bff Go
binary** via `//go:embed all:dist`:

```go
// cmd/admin-bff/main.go
//go:embed all:dist
var feAssetsRaw embed.FS
```

When the binary starts, it serves those embedded assets at `/`,
falling back to `index.html` for any unmatched path (so client-side
routing works). The BFF and the FE ship as **one artifact**.

### Why embed instead of serve separately?

Three reasons:

1. **No FE/BFF version skew.** The FE and the BFF are in lockstep —
   if you deploy a new BFF, you get exactly the FE bundle that was
   built against it. No "the new API expects field X but the old FE
   doesn't send it" surprises.
2. **No CORS.** The FE and the BFF are at the same origin (the BFF
   serves both). Avoids the CORS dance entirely.
3. **One image to deploy.** No nginx-for-static-files container, no
   FE deployment pipeline. `docker compose up -d admin-bff` deploys
   both layers.

The tradeoff: **slower iteration during pure FE development**. Every
.tsx change requires a Go rebuild. For active FE development you'd
typically run Vite's dev server (`npm run dev`) with a proxy to a
running BFF — but Akashic doesn't currently have that wired up. It's
a future polish, not a current limitation.

## The BFF's HTTP surface

| Path | Method | Purpose |
|---|---|---|
| `/` (and any non-API path) | GET | Serve the FE shell (index.html or static asset) |
| `/api/health` | GET | Liveness probe (used by docker) |
| `/api/bootstrap/status` | GET | Forward to control plane: are we bootstrapped? |
| `/api/bootstrap/create-root` | POST | Forward to control plane: create root user |
| `/api/session` | GET | Returns logged-in user info (200) or 401 |
| `/login` | GET | Initiate OAuth flow → redirect to auth-server |
| `/oauth/callback` | GET | Receive code from auth-server, complete the flow |
| `/logout` | POST | Clear BFF session, return RP-initiated logout URL |

The convention: `/api/*` is for the FE's `fetch()` calls;
non-`/api/*` paths (`/login`, `/oauth/callback`, `/logout` — and
the static FE assets at `/`) are for top-level navigation. The
distinction matters for cookies (`SameSite=Lax` for navigation,
strict for fetches) and for CSRF protection (header-validated for
fetches, cookie-only for navigation).

## Browser-side patterns the BFF supports

### CSRF: double-submit cookie

For state-changing fetch requests (`POST /api/bootstrap/create-root`,
`POST /logout`), the BFF requires a CSRF token in the
`X-Akashic-CSRF` header. The token's value must match the
`akashic_csrf` cookie (which is set automatically on first response
and re-fetchable from `document.cookie` because it's *not* HttpOnly).

This is the **double-submit cookie pattern**. The protection: a
cross-origin attacker can cause the browser to send the cookie
automatically (cookies travel) but *cannot* read the cookie value
(same-origin policy), so they can't put a matching value in the
header. Same-origin code can read the cookie (set the header) and
the request goes through.

`pkg/admin_bff/csrf.go` is the middleware. The cookie is
`SameSite=Strict; Secure` (defense-in-depth — modern browsers won't
send it cross-site at all, the explicit check is for older clients).

### Cookies the BFF sets

| Cookie | What it is | Attributes |
|---|---|---|
| `akashic_csrf` | Double-submit CSRF token | Path=/, Secure, SameSite=Strict, **HttpOnly=false** |
| `akashic_admin_oauth_pre` | Short-lived state+PKCE binding for OAuth flow | Path=/, Max-Age=300, HttpOnly, Secure, SameSite=Lax |
| `akashic_admin_session` | The actual logged-in session ID | Path=/, Secure, HttpOnly, SameSite=Lax |

`SameSite=Lax` (not Strict) on the session cookie matters. The
admin's `/oauth/callback` is reached via top-level navigation from
`auth.<domain>` — that's same-site (registrable-domain is the same)
but cross-origin (subdomains differ). Strict would block the cookie
from being sent on this nav. Lax allows it on safe top-level
navigations, which is exactly what we need.

## The OAuth client side

The BFF acts as an **OAuth client** to the akashic auth server (not
the same as the akashic control plane!). On `/login` it initiates an
OAuth flow with PKCE; on `/oauth/callback` it completes the flow,
verifies the ID token, runs a role check, and creates a session.

That's a non-trivial subsystem; chapter 06 covers OAuth concepts and
chapter 07 walks through the full flow including the BFF's role.
This chapter just notes the relevant files:

- **`pkg/admin_bff/oauth.go`** — OAuth-client identity (client_id,
  secret, scopes, public+internal URLs), state+PKCE generation, code
  exchange, ID-token verification.
- **`pkg/admin_bff/jwks.go`** — caches the auth server's JWKS for
  ID-token signature verification.
- **`pkg/admin_bff/oauth_handlers.go`** — the HTTP handlers for the
  three OAuth endpoints (`/login`, `/oauth/callback`, `/logout`).
- **`pkg/admin_bff/session.go`** — the BFF's Redis-backed session
  store.

## The lazy-init refactor (Phase 7)

Initially the BFF eagerly initialized everything at startup —
including reading the `akashic-admin` client secret from
`/keys/oauth/client-secrets/akashic-admin.txt`. If that file didn't
exist (which is normal during a first-startup ordering where
admin-bff comes up before akashic), init would log a warning and set
the OAuth client to nil. Then **every subsequent /login would fail**
until the BFF was restarted.

The Phase 7 fix: **lazy init with retry**. The OAuth client is
constructed inside `pkg/admin_bff/server.go`'s `ensureOAuth()`
method, which:

1. Returns the cached `*oauthClient` if one exists.
2. Otherwise tries to construct it.
3. On success, caches and returns.
4. On failure, returns nil (the handler returns
   `AUTH_SERVER_UNREACHABLE`).
5. The next `/login` request retries.

The state lives in an `atomic.Pointer[oauthClient]`. A mutex
(`oauthMu`) serializes concurrent init attempts so we don't do
file-read work N times in parallel.

Why this matters architecturally: it **decouples the BFF and akashic
startup orderings**. They can now boot in any order, restart
independently, recover automatically. No `depends_on: akashic` on
the BFF in compose. No "ordering tax" at all.

This is a worthwhile refactor pattern in any service that depends on
state owned by another service:

> **Don't validate transitive dependencies at startup. Try once,
> degrade if they're not ready, retry on demand.**

## The control client (mTLS to akashic)

`pkg/admin_bff/client.go` defines `ControlClient` — the BFF's typed
HTTP client for the akashic control plane. It uses
`tls.Config.GetClientCertificate` (the per-handshake callback) to
pick up rotated mTLS client certs without reconnecting:

```go
transport := &http.Transport{
    TLSClientConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,
        RootCAs:    caPool,
        GetClientCertificate: func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
            return reloadr.GetCertificate(nil)
        },
    },
}
```

`reloadr` is a `pkg/pki.Reloader` instance — same atomic-pointer
pattern as the akashic server uses for its server certs. Vault Agent
rotates the BFF's client cert on disk; fsnotify wakes the reloader;
the next mTLS handshake sees the new cert.

`ControlClient` exposes typed methods like `BootstrapStatusGet(ctx)`
and `BootstrapCreateRoot(ctx, req)` — each one corresponds to a
control-plane endpoint and parses the standard response envelope
(`{success, data, error}`).

## The audit log

Every state-changing or security-relevant action emits a structured
JSON line via `pkg/admin_bff/audit.go`. There's a critical detail
worth calling out:

> **The audit logger uses an explicit field allowlist, not a
> denylist.**

If a future handler tries to log a field that isn't in the allowlist
(say, `password` or `bootstrap_token` "for debugging"), the audit
writer **silently drops it**. This is by design — the cost of
accidentally adding a sensitive field to an audit log is high
(audits go to long-retention storage for compliance), so the
machinery is fail-safe-by-default. You *cannot* add a new audit
field without updating the allowlist; that's a feature.

## What you should walk away with

After this chapter:

1. You can explain the BFF pattern in general and how Akashic uses
   it specifically.
2. You understand why the React FE is embedded in the Go binary and
   what tradeoff that makes.
3. You can name the three cookies the BFF sets and explain their
   different SameSite settings.
4. You know the lazy-init pattern and can explain the
   "decoupled startup" property it enables.
5. You know that audit logs use a field allowlist and why.

## Continue to → [Chapter 06 — OAuth / OIDC](./06-oauth-oidc.md)
