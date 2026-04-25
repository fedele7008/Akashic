# Phase 6 Revision — As-Built Summary

This document records what actually shipped in Phase 6, complementing
[`phase-6-plan.md`](./phase-6-plan.md) (the forward-looking design).
Use this one as the operational reference for the new web-bootstrap
flow, the admin-bff service, and the two-level proxy topology.

> **Status**: All eight steps of Phase 6 landed. Browser-based
> bootstrap works end-to-end against a fresh Akashic deployment.

---

## What's New at a Glance

### New service

```
admin-bff    Go binary that serves the React admin FE + /api/* endpoints.
             Embeds the FE via embed.FS (single-binary deploy).
             Reaches the control plane over mTLS as bff.akashic.local.
```

Available under `--profile app` in docker-compose, alongside the
existing `akashic` service.

### New web surface

```
admin.akashic.<domain>     React + Vite admin FE (Phase 6: bootstrap form only)
                           Behind nginx-proxy, which routes by Host header.
```

In production, an additional **host-level nginx** sits in front of the
docker stack and terminates public-CA TLS. In direct-dev mode, the
operator hits the docker proxy directly over plain HTTP.

### New API endpoints (BFF, not control plane)

| Method | Path | Purpose |
|---|---|---|
| GET | `/` (and any non-`/api/` path) | React app shell (with SPA fallback) |
| GET | `/api/health` | Liveness probe (used by docker / nginx) |
| GET | `/api/bootstrap/status` | Pass-through to control plane's status |
| POST | `/api/bootstrap/create-root` | CSRF-protected, rate-limited bootstrap submission |

The BFF is the **only** browser-facing component that holds an mTLS
client cert. Browsers never see mTLS material directly.

### New on-disk state (none for operators)

Phase 6 deliberately added no operator-managed state. The BFF's mTLS
certs come from `services/vault-agent/templates/bff-client.tpl`
(unchanged from Phase 4); React FE source lives at `web/admin/` and
its build output is embedded into the Go binary at compile time.

---

## The Canonical Workflow (Web Bootstrap)

The browser-based version of the Phase 5 CLI flow. Three steps, no
mTLS cert handling required by the operator (the BFF holds the cert
on the operator's behalf).

### Step 0 — Bring up the stack

```bash
./scripts/reset-vault.sh           # clean slate (regenerates CA + certs)
docker compose --profile app up -d
sleep 30                           # vault-agent issues bff-client cert; admin-bff builds + starts
```

### Step 1 — Add the hosts entry (one-time per machine)

```bash
sudo sh -c 'echo "127.0.0.1 admin.akashic.local" >> /etc/hosts'
```

In production with a real public domain, replace this with proper DNS
+ a host-level nginx terminating public-CA TLS for `admin.akashic.<domain>`.

### Step 2 — Open the admin URL and submit the bootstrap form

```bash
open http://admin.akashic.local:8280   # direct-dev mode (no host nginx)
# or
open https://admin.akashic.<domain>     # production (with host nginx)
```

Steps in the browser:
1. Page loads with a "Akashic Bootstrap" form
2. Run `docker logs akashic-server | grep -A 1 "Bootstrap Token:"` to find the token
3. Paste token, fill in username + email + password (twice), submit
4. Form refreshes to "Bootstrap Complete" view

After this, the `/api/bootstrap/create-root` endpoint is permanently
closed on this deployment. The same `akashic-cli bootstrap status`
that you'd run after a CLI bootstrap shows `is_complete: true`.

### CLI vs Web — pick whichever fits

The CLI (Phase 5) and the web flow (Phase 6) are functionally
interchangeable for first-time bootstrap. Use whichever fits the
operator's environment:

| Use the CLI when... | Use the web flow when... |
|---|---|
| You already have shell access to the host | You don't have shell access (managed deployment) |
| You're scripting / running from CI | You want a guided form |
| You want one-command idempotent re-runs | First-time setup with a person at a keyboard |
| You're on a workstation with the project tree checked out | You're administering a remote deployment |

Both paths land in the same place: a root user in PG + LDAP, with
`bootstrap_status.completion_source` recording which path was used
(`cli.akashic.local` or `bff.akashic.local`).

---

## Architecture Reference

### Three-tier request flow

```
Browser
  │  HTTPS (public CA / Let's Encrypt) ─ production
  │  HTTP                              ─ direct-dev mode
  ▼
Host nginx (production only)             ← terminates public-CA TLS
  │  HTTP (loopback)
  ▼
Docker nginx-proxy :8280                 ← subdomain router, plain HTTP only
  │  HTTP (docker network)
  ▼
admin-bff :8082                          ← Go BFF + embedded React FE
  │  HTTPS + mTLS (CN = bff.akashic.local)
  ▼
control-server :8081 (loopback only)     ← /bootstrap/root, etc.
```

Each layer's role:

- **Host nginx** terminates the only public-facing TLS in the chain.
  Holds the public-CA cert (Let's Encrypt typical). Forwards to the
  docker proxy over loopback HTTP. Optional in dev; required in prod.
- **Docker nginx-proxy** routes by Host header to backend containers.
  Plain HTTP only at this layer (TLS already terminated upstream).
  Bound to `127.0.0.1:8280` on the host — never publicly reachable.
- **admin-bff** terminates browser HTTP, applies CSRF + rate limit +
  security headers + audit log, then forwards `/api/*` requests to
  the control plane over mTLS. Serves the React FE for any non-API path.
- **Control server** authenticates via `bff.akashic.local` mTLS cert
  CN (allowlisted in Phase 5). Returns standard JSON envelope.

### Trust chain (X-Forwarded-For)

Each hop trusts ONLY its immediate upstream. Misconfiguring any step
creates a source-IP-spoofing hole.

| Hop | Trust scope | What it does with X-Forwarded-For |
|---|---|---|
| Browser → Host nginx | (untrusted client) | Sets X-Forwarded-For = real client IP, OVERWRITE |
| Host nginx → Docker proxy | only loopback (host nginx) | Passes through unchanged |
| Docker proxy → admin-bff | only loopback (host nginx) | Adds the host-nginx hop to X-Forwarded-For chain |
| admin-bff (rate limiter) | docker network (172.0.0.0/8) | Reads leftmost X-Forwarded-For entry as client IP |

Verification: after a successful bootstrap, the BFF's audit log line
should show `remote_ip: <browser's actual IP>`, not a docker-internal
address. If you see `172.18.0.x`, the trust chain is broken.

### What the BFF does NOT do

Three deliberate non-features in Phase 6:

1. **No login flow.** No session store, no OAuth, no auth context. The
   bootstrap form trusts the bootstrap token alone (the same way the
   CLI does). Login + dashboards arrive in Phase 7.
2. **No token auto-fetch.** The CLI can `GET /bootstrap/token` because
   it has an mTLS client cert; the browser cannot, so the operator
   has to copy the token from server logs into the form. This is
   the right asymmetry — browsers are not credentialed for token
   retrieval, and pretending otherwise would break the threat model.
3. **No persistent state.** The BFF holds Redis sessions / OAuth
   state nowhere; in Phase 6 it's effectively a stateless proxy
   between browser and control plane. Phase 7 adds session storage.

---

## API Reference (BFF)

All `/api/*` responses use the standard envelope:

```json
{ "success": true, "data": { ... } }
{ "success": false, "error": { "code": "...", "message": "...", "details": {...} } }
```

### `GET /api/health`

```bash
curl http://admin.akashic.local:8280/api/health
# → {"service":"admin-bff","status":"healthy"}
```

Liveness probe. Doesn't reach the control plane. Used by docker for
`HEALTHCHECK` (when configured) and by the nginx-proxy resolver for
upstream availability.

Skips both CSRF and rate-limiting middlewares — should always work,
even when the control plane is down.

### `GET /api/bootstrap/status`

```bash
curl http://admin.akashic.local:8280/api/bootstrap/status
# → {"success":true,"data":{"is_complete":false,"token_exists":true,"token_ttl_seconds":3592}}
```

Pass-through to the control plane's `GET /bootstrap/status`.

Reachable in BOTH bootstrap and normal modes (it's the question being
answered, not gated by the answer). Sets the CSRF cookie if missing
on the way out — first request from a fresh browser is typically
this one, so the form has its CSRF token ready by the time it
submits.

### `POST /api/bootstrap/create-root`

```bash
curl -b cookies.txt -H "X-Akashic-CSRF: $CSRF" \
     -H "Content-Type: application/json" \
     -X POST http://admin.akashic.local:8280/api/bootstrap/create-root \
     -d '{"token":"<bootstrap-token>","username":"admin","email":"admin@example.com","password":"Strong@Pass123"}'
```

Submits a root-user creation request to the control plane.

Required:
- CSRF cookie + `X-Akashic-CSRF` header matching its value
- All four body fields non-empty
- Token must match what's in Redis on the control plane
- Source IP must not be over the rate limit (5/min default)

Error code mapping (subset):

| BFF response | When |
|---|---|
| 401 `INVALID_TOKEN` | Token wrong or expired |
| 410 `BOOTSTRAP_COMPLETE` | Already done; endpoint permanently closed |
| 400 `PASSWORD_POLICY_VIOLATION` | Specific rule failed (e.g., min length) |
| 400 `VALIDATION_FAILED` | Email format, username chars, etc. |
| 429 `RATE_LIMITED` | Too many submissions from this IP — `Retry-After` header set |
| 403 `CSRF_FAILED` | Cookie missing, header missing, or values don't match |
| 502 `UPSTREAM_UNREACHABLE` | BFF couldn't reach the control plane |
| 502 `BFF_AUTH_FAILED` | BFF's own mTLS cert rejected by the control plane (deployment misconfig) |
| 502 `SERVER_ERROR` | Generic upstream 5xx |

Successful response (201):

```json
{
  "success": true,
  "data": {
    "user": {
      "uid": "<uuid>",
      "ldap_dn": "uid=admin,ou=users,dc=akashic,dc=local",
      "username": "admin",
      "email": "admin@example.com",
      "user_type": "root",
      "created_at": "2026-04-25T..."
    }
  }
}
```

---

## Security Baseline

Behaviors that ship out of the box:

| Concern | Mechanism | Where |
|---|---|---|
| TLS termination (browser ↔ host) | Public-CA cert on host nginx | Host system, not docker |
| TLS to control plane (BFF ↔ control) | mTLS via `bff.akashic.local` cert | `pkg/admin_bff/client.go` (uses `pkg/pki`) |
| Cert rotation | `pkg/pki.Reloader` + `GetClientCertificate` callback (zero-downtime) | `pkg/admin_bff/client.go` |
| CSRF | Double-submit cookie (`akashic_csrf` + `X-Akashic-CSRF` header) | `pkg/admin_bff/csrf.go` |
| Rate limit (per-source-IP) | 5 attempts/min on `/api/bootstrap/create-root`; 30/min on idempotent reads | `pkg/admin_bff/ratelimit.go` |
| Rate limit (per-CN at control plane) | 5/min, mirrors the BFF's bucket size; from Phase 5 | unchanged |
| HSTS | `max-age=31536000; includeSubDomains; preload` | `pkg/admin_bff/headers.go` |
| CSP | `default-src 'self'; script-src 'self'; ...; frame-ancestors 'none'` | `pkg/admin_bff/headers.go` |
| Cookie hygiene | `HttpOnly=false` (FE needs read), `SameSite=Strict`, `Secure` set conditionally on X-Forwarded-Proto=https | `pkg/admin_bff/csrf.go` |
| X-Forwarded-For trust | Honored only from CIDR ranges in `AKASHIC_BFF_TRUSTED_PROXIES` (default `172.0.0.0/8`) | `pkg/admin_bff/ratelimit.go` |
| Audit log | Security-channel JSON lines with **explicit field allowlist** (no token/password leaks possible) | `pkg/admin_bff/audit.go` |
| Audit columns at completion | `bootstrap_status.completion_source = "bff.akashic.local"` for web flows | Phase 5 schema, populated by `requireClientIdentity` middleware |

### CSRF mechanics in detail

On the first GET to any BFF endpoint, the BFF sets a cookie:

```
Set-Cookie: akashic_csrf=<32-byte-hex-random>;
            Path=/;
            HttpOnly=false;        # FE must read this
            SameSite=Strict;
            Secure                 # only when X-Forwarded-Proto=https
```

The React FE reads the cookie on form submit and echoes the value in
the `X-Akashic-CSRF` header. The middleware compares cookie value to
header value via `subtle.ConstantTimeCompare`. Cross-origin attackers
can cause the cookie to be sent (cookies travel automatically with
cross-origin requests in some scenarios) but cannot READ the cookie
to set the matching header — so cookie-and-header agreement proves
same-origin.

### The `Secure` cookie conditional

The CSRF cookie is set `Secure: true` only when the original request
was HTTPS. The BFF detects this via:

1. `r.TLS != nil` — direct HTTPS to the BFF (rare; BFF normally
   speaks plain HTTP behind the proxy)
2. `r.Header.Get("X-Forwarded-Proto") == "https"` — when an upstream
   proxy terminated TLS

If neither holds, the cookie is set without `Secure` so dev can hit
plain HTTP without the cookie being silently dropped by the browser.
In production both hold (host nginx sets `X-Forwarded-Proto: https`)
and the cookie gets the full strictness.

---

## Migration Notes

### Phase 6 is purely additive

Existing deployments upgraded to Phase 6 see:

- A new `admin-bff` container (only when `--profile app` is used)
- A new `admin.akashic.local` server block on the docker-proxy
- New aliases (`ctrl.akashic.local`, `auth.akashic.local`) on the
  akashic service so the BFF can address it by cert-SAN-matching name
- No changes to existing endpoints, configs, or schemas

CLI bootstrap (Phase 5) continues to work unchanged. The web bootstrap
is an alternative path, not a replacement.

### What the operator has to do

1. **Pull and rebuild containers**: `docker compose --profile app build && docker compose --profile app up -d`
2. **Add `/etc/hosts` entry** for local dev: `127.0.0.1 admin.akashic.local`
3. **(Production) install host nginx** with the example config from
   `services/proxy/host-nginx-example.conf` (planned; falls back to
   direct dev access until installed)

That's it. No schema migrations, no config edits, no env-var changes
in `.env`.

### When is host nginx actually needed?

- **Required**: production deployment with a real public domain
- **Optional**: local dev (you can hit the docker proxy directly at
  `http://admin.akashic.local:8280`; the BFF detects no-TLS and
  adapts the cookie's Secure flag accordingly)

For mid-environments (staging, internal-only-but-on-corp-LAN), use
host nginx if you want HTTPS enforced; otherwise direct-dev mode is
fine.

### What happens after vault-reset

A `./scripts/reset-vault.sh` regenerates the entire CA chain. This
invalidates:

- The CLI profile's cert files in `~/.akashic/certs/<profile>/`
  (re-add the profile)
- The BFF's `bff-client.{crt,key}` (Vault Agent re-issues automatically;
  but the running BFF needs a restart or `POST /tls/reload` to pick
  them up — see Phase 4's reloader)

Since the BFF's container restarts after a reset (`docker compose up
-d` recreates it as part of the up flow), this is usually invisible —
the new container starts with fresh certs from the regenerated CA.

---

## Files Touched (for code review)

### New files

| Path | Purpose |
|---|---|
| `cmd/admin-bff/main.go` | Entry point; embeds `dist/` via `//go:embed` |
| `pkg/admin_bff/server.go` | HTTP listener, lifecycle, middleware composition, FE static handler with SPA fallback |
| `pkg/admin_bff/config.go` | Viper-based config loader, `AKASHIC_BFF_*` env vars |
| `pkg/admin_bff/client.go` | Typed control-plane client over mTLS (uses `pkg/pki.Reloader` for rotation) |
| `pkg/admin_bff/handlers.go` | `/api/health`, `/api/bootstrap/{status,create-root}` with error mapping |
| `pkg/admin_bff/ratelimit.go` | Per-source-IP token bucket honoring X-Forwarded-For only from trusted CIDRs |
| `pkg/admin_bff/csrf.go` | Double-submit cookie middleware with conditional Secure flag |
| `pkg/admin_bff/headers.go` | HSTS, CSP, X-Frame, cache-control as a global middleware |
| `pkg/admin_bff/audit.go` | Security-channel logger with explicit field allowlist |
| `services/admin-bff/Dockerfile` | Multi-stage: vite (Node) → go build → alpine runtime |
| `web/admin/package.json` | npm package manifest |
| `web/admin/tsconfig.json` | TypeScript strict config |
| `web/admin/vite.config.ts` | Vite config; `outDir: '../../cmd/admin-bff/dist'` for Go embed |
| `web/admin/index.html` | Vite entry HTML |
| `web/admin/src/main.tsx` | React entry point |
| `web/admin/src/App.tsx` | Two-state shell (form vs. already-complete) |
| `web/admin/src/api/client.ts` | Fetch wrappers + CSRF helper + typed API surface |
| `web/admin/src/components/BootstrapForm.tsx` | The form component |
| `web/admin/src/components/BootstrapAlreadyComplete.tsx` | Post-bootstrap view |
| `web/admin/src/styles.css` | Dark-themed minimal CSS (~150 lines) |
| `doc/phase-6-revision.md` | This document |

### Modified files

| Path | Change |
|---|---|
| `docker-compose.yml` | New `admin-bff` service under `profiles: ["app"]`; added `ctrl.akashic.local` and `auth.akashic.local` aliases on the akashic service |
| `services/proxy/nginx.conf` | New server block for `~^admin\.` (Phase 6); new `admin_limit` rate-limit zone |
| `.gitignore` | Note about Phase 6 build artifacts (covered by global `node_modules/` and `dist/` rules) |
| `.dockerignore` | Note about the same |

### NOT touched

- `pkg/server/control/` — server-side bootstrap was already complete (Phase 5)
- `pkg/cli/` — CLI is already complete (Phase 5)
- `pkg/auth/`, `pkg/ldap/`, `pkg/repository/`, `pkg/bootstrap/` — no changes needed
- `pkg/pki/` — reloader pattern reused unchanged from Phase 4
- `services/vault-agent/` — `bff-client.tpl` was already in place from Phase 4

---

## Quick Recipe Index

For copy-paste convenience.

### Fresh deployment, web-bootstrap end-to-end:

```bash
./scripts/reset-vault.sh
docker compose --profile app up -d
sleep 30

# Add hosts entry once per machine
sudo sh -c 'echo "127.0.0.1 admin.akashic.local" >> /etc/hosts'

# Open the form
open http://admin.akashic.local:8280

# Get the token to paste into the form
docker logs akashic-server | grep -A 1 "Bootstrap Token:"
```

### Scripted web-bootstrap (e.g. CI / staging deploy):

```bash
COOKIES=$(mktemp)
curl -s -c $COOKIES -H "Host: admin.akashic.local" \
    http://127.0.0.1:8280/api/bootstrap/status > /dev/null

CSRF=$(grep akashic_csrf $COOKIES | awk '{print $7}')
TOKEN=$(docker logs akashic-server | grep -A 1 "Bootstrap Token:" | tail -1 | tr -d ' ')

curl -s -b $COOKIES -H "Host: admin.akashic.local" \
    -H "X-Akashic-CSRF: $CSRF" \
    -H "Content-Type: application/json" \
    -X POST http://127.0.0.1:8280/api/bootstrap/create-root \
    -d "{\"token\":\"$TOKEN\",\"username\":\"admin\",\"email\":\"admin@example.com\",\"password\":\"Strong@Pass123\"}"

rm -f $COOKIES
```

### Sanity check after web-bootstrap:

```bash
# Status flipped
curl -s -H "Host: admin.akashic.local" http://127.0.0.1:8280/api/bootstrap/status | jq

# Audit columns recorded the source
docker exec akashic-postgres psql -U admin -d akashic -t \
    -c "SELECT is_complete, completion_source, completion_ip FROM bootstrap_status"
# → t | bff.akashic.local | <real-client-ip>

# BFF audit log
docker logs akashic-admin-bff 2>&1 | tail -10
```

### Local FE iteration (Vite dev server with HMR):

```bash
# Terminal 1: BFF (no FE assets needed in dev mode)
docker compose --profile app up -d admin-bff

# Terminal 2: vite dev server with HMR; proxies /api → BFF
cd web/admin
npm install
npm run dev
# → opens http://localhost:5173 with HMR;
# any code change reloads instantly without rebuilding the Go binary
```

### Direct-dev access from another machine on the LAN (NOT for prod):

```bash
# Bind docker-proxy to all interfaces instead of loopback
# (edit docker-compose.yml, change "127.0.0.1:8280:80" → "8280:80")
# Then access from another machine via the host's LAN IP:
open http://<host-lan-ip>:8280
# Browser will need /etc/hosts entry pointing admin.akashic.local
# at <host-lan-ip>, OR the operator can hit the URL with -H "Host:" via curl
```

This last recipe is for **dev convenience only**. In any environment
where multiple people / machines reach the URL, install host nginx
and serve over public-CA HTTPS instead.

---

## Phase 7 Preview (orientation only)

Phase 7 builds on this foundation:

1. **OAuth client registration** for `akashic-admin` (built-in, server-side)
2. **Login flow** at `/login` (admin-bff → auth-server → admin-bff with code exchange)
3. **Session store** in Redis (key prefix `akashic:bff:session:*`)
4. **Re-auth-for-dangerous-actions middleware** (sudo mode)
5. **Dashboard** with server status, recent audit events, RBAC group viewer
6. **User management** — create / disable / delete admins via the FE
7. **Tenant management** — register OAuth clients (lives at root domain, not admin)
8. The "Bootstrap Complete" page becomes a redirect to `/login` once
   bootstrap is done

None of that is in Phase 6. Phase 6 ends at "browser bootstrap works".
