# Phase 7 Progress — In Flight

> **Status: 3 of 10 steps complete.** The OAuth infrastructure is in place
> (signing keys, discovery doc, JWKS), but the actual flow endpoints
> (`/authorize`, `/token`, `/userinfo`, login UI) are not yet wired up.
> Akashic announces itself as an OIDC IdP at `/.well-known/openid-configuration`
> but cannot yet authenticate any user.
>
> When Phase 7 completes, this document gets replaced by `phase-7-revision.md`
> following the plan/revision discipline used in Phases 5 and 6.

This document records what's been built so far so that:

- An operator picking up the codebase mid-phase can see what's
  already deployable
- A reviewer can scope what landed without re-reading commit history
- The next contributor (possibly future-me) knows where the seams are

For the design intent, see [`phase-7-plan.md`](./phase-7-plan.md).

---

## What's Landed

### ✅ Step 1 — Data model + AutoMigrate

**New table**: `client_services` (corresponding Go struct: `models.ClientService`)

Schema lives in `pkg/models/client_service.go`. Registered in
`pkg/database/akashic_postgres/postgres.go`'s AutoMigrate list, so
GORM creates the table on first server start.

**Naming**: in Akashic terminology, an OAuth client is a "client
service" — a service registered with the IdP that wants to
authenticate users via Akashic. This matches the operator's mental
model better than the OAuth-spec term "client" (which is overloaded
in the codebase with HTTP-client and other meanings).

The schema accommodates two future kinds of client services:

| Kind | `BuiltIn` | Secret managed by | Phase |
|---|---|---|---|
| Built-in (`akashic-admin`, `akashic-tenant-portal`) | `true` | Server itself, on startup | 7 / 8 |
| Tenant-registered | `false` | Operator captures plaintext at creation | 8+ |

**Auth-type column**: a new `auth_types` column records which OAuth
grant types each client service is authorized to use. Values are the
canonical OAuth spec strings (`authorization_code`, `client_credentials`,
`password` (ROPC), `implicit`). Phase 7 enables only `authorization_code`;
the others exist in the schema and constants so future phases enable
them without migration. Validation enforces this at registration:
known but not-yet-enabled values are rejected.

Phase 7 only writes built-in rows. The schema (notably `RoleAllowlist`,
`RequirePKCE`, `BuiltIn`, `AuthTypes`) is forward-compatible with
tenant-registered clients without migration.

### ✅ Step 2 — JWT signing keystore

**New on-disk state**: `./keys/oauth/<kid>.json` (one file per signing key)

Implementation in `pkg/oauth/keystore.go` + `pkg/oauth/jwt.go`.
Properties:

- **Algorithm**: RS256 (RSA-2048). Universal client-library support.
- **First-run bootstrap**: server generates a fresh RSA keypair on
  startup if the directory is empty. Subsequent starts load the
  existing key.
- **Atomic-pointer pattern**: same as Phase 4's `pkg/pki.Reloader`.
  Key rotation can swap the active key without restarting; in-flight
  sign/verify operations either see the old or new state, never a
  half-built one.
- **Multi-key support**: rotated-out keys stay in the JWKS until
  manually deleted, so existing tokens with older `kid` headers
  still verify. Auto-aging is a Phase 8+ task.
- **Storage trade-off (acknowledged)**: filesystem-backed for now,
  not Vault KV. Reason: the akashic-server doesn't have a Vault
  client library wired in (only Vault-Agent renders to disk for it),
  and adding HTTP/AppRole auth to the server is its own architecture
  task. Migration to Vault KV is one substituted file (`keystore.go`)
  when we do it.

**KID format**: first 16 bytes of `SHA256(MarshalPKIXPublicKey(pub))`,
base64url-encoded → 22-char identifier. Compact in JWT headers, 128
bits of entropy, deterministic across re-loads.

**File permissions**: `0600` on key files (private material), `0700`
on the directory. Atomic-replace via `.tmp` + `rename` on every
write.

### ✅ Step 3 — Discovery + JWKS endpoints

**New auth-server endpoints**:

| Endpoint | Method | Purpose | Cache |
|---|---|---|---|
| `/.well-known/openid-configuration` | GET | OIDC discovery document | `max-age=3600` |
| `/jwks.json` | GET | Public signing keys (JWK Set) | `max-age=300` |

Both are public (no authentication required) and reachable on the
auth server's listener (port 8080 by default).

**Discovery doc** is built dynamically from config — the `issuer` URL
comes from `AKASHIC_OAUTH_ISSUER`, and the algorithm/scope/claim
lists reflect what's actually supported. It currently advertises:

- `response_types_supported`: `["code"]`
- `grant_types_supported`: `["authorization_code"]`
- `id_token_signing_alg_values_supported`: `["RS256"]`
- `code_challenge_methods_supported`: `["S256"]` (PKCE required)
- `scopes_supported`: `["openid", "profile", "email"]`
- `token_endpoint_auth_methods_supported`: `["client_secret_basic", "client_secret_post"]`

**JWKS** publishes every key in the keystore (active + verify-only).
RSA keys are encoded with `n` (modulus) and `e` (exponent) as
base64url-encoded big-endian integers per RFC 7517. The `kid` field
on each entry matches the keystore's KID, so JWT verifiers can
look up the right key directly from the token's header.

**503 graceful failure**: if the keystore isn't yet wired (rare; only
during a startup race), `/jwks.json` returns 503 instead of crashing.
Clients caching the JWKS retry on next request.

---

## What an Operator Can Do Today

### Verify Akashic announces itself as an OIDC IdP

```bash
curl -sk https://localhost:8080/.well-known/openid-configuration | jq
# Returns the full discovery doc

curl -sk https://localhost:8080/jwks.json | jq
# Returns {"keys": [{"kty":"RSA","kid":"...","alg":"RS256","n":"...","e":"AQAB","use":"sig"}]}
```

In production with a host-level nginx terminating TLS, these become:

```
https://auth.akashic.<domain>/.well-known/openid-configuration
https://auth.akashic.<domain>/jwks.json
```

### Verify the keystore on disk

```bash
# After akashic-server starts at least once
ls -la ./keys/oauth/
# drwx------ ... (0700 directory)
# -rw------- ... <kid>.json (0600 key file)

cat ./keys/oauth/*.json | jq 'del(.private_key_pem)'
# Inspect everything except the private key
```

### What Akashic CANNOT do yet

- **Cannot authenticate users**. There's no `/login`, no session,
  no /authorize, no /token, no /userinfo. The auth-server is an
  IdP that announces itself but can't actually issue tokens.
- **Admin login does not work**. The admin-bff still serves the
  Phase 6 bootstrap form (post-bootstrap, the "already complete"
  view). There's no `/login` route on admin-bff yet.
- **No third-party can integrate**. Discovery is published but no
  client can complete a flow against it.

These all land in Steps 4-10.

---

## New Configuration

Eight new keys under `oauth.*` in the config tree. Defaults aim at
the docker-compose dev deployment; production deployments override
`oauth.issuer` and `oauth.admin_redirect_uri`.

| Key | Default | Notes |
|---|---|---|
| `oauth.issuer` | `https://auth.akashic.local:8080` | Used as JWT `iss` claim and in discovery doc |
| `oauth.signing_key_dir` | `./keys/oauth` | Filesystem path for signing keys |
| `oauth.access_token_ttl` | `15m` | Access-token lifetime |
| `oauth.id_token_ttl` | `15m` | ID-token lifetime |
| `oauth.auth_code_ttl` | `60s` | Authorization-code lifetime (RFC 6749 recommends ≤10m) |
| `oauth.admin_redirect_uri` | `https://admin.akashic.local/oauth/callback` | Where /authorize sends the user after login (akashic-admin client) |
| `oauth.auth_session_idle_ttl` | `30m` | Auth-server session idle timeout |
| `oauth.auth_session_max_ttl` | `8h` | Auth-server session absolute timeout |

All overridable via `AKASHIC_OAUTH_*` env vars (Viper precedence:
flag > env > YAML > default).

The `signing_key_dir` is automatically rewritten to `/keys/oauth`
inside containers (same `NormalizeContainerPaths` mechanism Phase 4
introduced for TLS cert paths).

---

## What's Still TODO

Steps 4-10 of `phase-7-plan.md`. Each step's scope is unchanged from
the plan; this list is just a snapshot of what's pending.

| Step | Title | Estimated complexity |
|---|---|---|
| 4 | Login UI (server-rendered HTML, /login + /login/submit, CSRF, rate limit, sessions) | ~400 lines Go + ~150 HTML+CSS |
| 5 | `/authorize` endpoint (query validation, session check, code generation, redirect) | ~250 lines Go |
| 6 | `/token` endpoint (code exchange, PKCE verify, JWT mint) | ~300 lines Go |
| 7 | `/userinfo` endpoint (bearer-token verification + claim filtering by scope) | ~120 lines Go |
| 8 | Built-in `akashic-admin` client (startup-time upsert with secret in Vault KV, hash in PG) | ~150 lines Go |
| 9 | Admin BFF login wiring (state/PKCE generation, /oauth/callback, role check, session in Redis) | ~400 lines Go + small React FE update |
| 10 | End-to-end verification (curl-driven OAuth flow + browser-driven full flow + failure modes) | smoke tests |

Steps 4-7 are coupled — none of them is verifiable in isolation. The
interlocking nature is why they'll likely land as one chunk during
implementation.

Steps 8-9 then bring online the first OAuth client (Akashic itself,
via the admin-bff). Step 10 is the gate.

---

## Pragmatic Deviations from the Plan

Recording these so a future reviewer can trace why the implementation
diverged from the plan in specific places.

### Filesystem signing keys instead of Vault KV

The plan specified Vault KV at `kv/akashic/oauth/signing-keys/<kid>`.
Implementation uses filesystem at `./keys/oauth/<kid>.json`.

Reason: the akashic-server doesn't have a Vault HTTP client wired up
(only Vault-Agent renders to disk for it), and adding one is its
own architecture task with auth/policy/network surface. Filesystem
storage gets us all the *functional* properties of the keystore
(rotation, verify-only old keys, JWKS publishing) at a fraction of
the implementation cost. Migration to Vault KV later is one
substituted file.

Trade-off acknowledged: loses Vault's audit trail of key access. For
single-node deployments this is acceptable; multi-node setups will
want centralized key storage. Revisit when we have multi-node.

### Hand-rolled OAuth handlers + golang-jwt for JWT operations

The plan recommended `fosite` (production-grade Go OAuth/OIDC library).
Implementation uses `github.com/golang-jwt/jwt/v5` for JWT operations
plus hand-written handlers for the OAuth-flow logic.

Reason: fosite is opinionated about its Storage / Hasher / Strategy
interfaces, and bending Akashic's existing GORM/Redis/Viper patterns
to fit those interfaces was higher cost than writing the OAuth flow
logic carefully. The cryptographically-subtle parts (sign / verify /
key rotation / audience binding) are entirely inside `golang-jwt`,
which is well-vetted; the spec-edge parts (redirect URI exact-match,
PKCE SHA256, code single-use) are individual pieces that fit on a
half-page each.

Trade-off acknowledged: hand-written handlers are easier to get
subtly wrong than a full library. Mitigations: each handler will be
written against the spec section directly (RFC 6749 §4.1, RFC 7636,
OIDC core §3.1), with the spec text cited inline in the comments,
and the test plan specifically exercises the spec-edge cases.

---

## Files Touched (so far)

### New files

| Path | Purpose |
|---|---|
| `pkg/models/client_service.go` | ClientService model + AuthType constants + GORM hook |
| `pkg/oauth/keystore.go` | RSA signing-key store with atomic-pointer pattern + first-run generation |
| `pkg/oauth/jwt.go` | JWT mint/verify helpers + JWKS marshaling |
| `pkg/server/auth/oauth_handlers.go` | `/.well-known/openid-configuration` + `/jwks.json` handlers |
| `doc/phase-7-progress.md` | This document |

### Modified files

| Path | Change |
|---|---|
| `pkg/database/akashic_postgres/postgres.go` | Added `&models.ClientService{}` to `AutoMigrate` model list |
| `pkg/server/auth/server.go` | Added `oauthKeyStore` field + `SetOAuthKeyStore` setter + `OAuthKeyStore` getter |
| `pkg/server/auth/routes.go` | Registered `/.well-known/openid-configuration` and `/jwks.json` routes |
| `pkg/akashic/core/context.go` | Added `OAuthKeyStore` field on `AkashicApp`; init logic that loads (or generates) the keystore during `Init()`; wires it into the auth server |
| `pkg/config/types.go` | Added `OAuthConfig` struct + field on root `Config` |
| `pkg/config/defaults.go` | Defaults for all `oauth.*` keys; `oauth.signing_key_dir` added to `NormalizeContainerPaths` |
| `go.mod` / `go.sum` | Added `github.com/golang-jwt/jwt/v5 v5.3.1` |

### NOT touched (intentionally)

- `pkg/auth/service.go` — LDAP authentication logic; unchanged. Will
  be called from `/login/submit` in Step 4.
- `pkg/admin_bff/` — admin BFF still serves Phase 6 bootstrap form;
  login wiring lands in Step 9.
- `pkg/cli/` — CLI uses mTLS, not OAuth; unchanged.
- `pkg/pki/` — TLS PKI is independent of OAuth signing keys.

---

## Migration Notes (so far)

Phase 7 is **purely additive**. Existing deployments upgrading to
this checkpoint experience:

1. A new `client_services` table appears (empty until built-in
   client services are registered in Step 8)
2. A new directory `./keys/oauth/` (or `/keys/oauth/` in container
   mode) appears with a generated RSA key
3. Two new endpoints are reachable on the auth server: discovery and
   JWKS
4. Existing endpoints (`/health`, `/ready`) and behavior unchanged
5. Existing CLI bootstrap flow unchanged
6. Existing admin BFF web bootstrap flow unchanged

No migration steps required. No env-var changes required (all the
new `oauth.*` defaults are sensible). No schema migrations to apply
manually (GORM `AutoMigrate` handles it).

### What happens after `./scripts/reset-akashic.sh`

The reset script wipes Vault state + project `./certs/` (per Phase 5
script). The OAuth signing keys at `./keys/oauth/` are wiped along
with everything else. On next server start, a fresh key is generated.

This is a **deliberate property**: vault-reset implies "burn it all
and start over", and the OAuth signing key is part of that burn-it-all
scope. Any tokens issued by the previous key become un-verifiable
(missing kid in the new JWKS) — which is correct, because the entire
trust chain has been replaced.

---

## Phase 7 Completion Outlook

When Steps 4-10 complete, this document gets replaced by
`phase-7-revision.md` following the plan/revision pattern. The
revision doc will:

- Document the as-built command set, endpoint behaviors, and recipes
- Capture any further pragmatic deviations from the plan
- Include the canonical "fresh deployment to logged-in admin"
  workflow (the equivalent of Phase 5's three-command CLI bootstrap)

Until then, this `phase-7-progress.md` is the operational reference
for what works *today*, partial as it is.
