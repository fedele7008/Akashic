# Phase 7: OAuth/OIDC Core + Admin Login

## Context

After six phases of infrastructure, Phase 7 builds the actual product:
the OAuth 2.1 / OIDC authorization-code flow with PKCE that makes
Akashic a real Identity Provider. Then we use that flow ourselves —
the admin surface gets a login page by becoming Akashic's first
OAuth client.

**Why this ordering**: every other phase ahead of us (tenant onboarding
at the root domain, customer integrations, refresh-token support,
device flow, etc.) depends on a working authorization-code flow. Build
the spine first; everything else hangs off it.

**Phase 7 scope**: OAuth core endpoints + default login UI + admin
login wiring + role check on the admin surface.

**Phase 8 scope (deferred)**: tenant surface at `<root domain>`. Same
OAuth flow, different client, different stack (Next.js per the
existing tenant-BFF design in `phase-5-plan.md` §5.5). Phase 7 lays
all the infrastructure the tenant flow will reuse.

---

## Architectural Principles (decisions locked in)

These are non-negotiable for Phase 7. Future contributors who want to
deviate need a separate ADR explaining why.

### 1. Akashic is its own first OAuth client

The admin login on `admin.akashic.<domain>` works by Akashic calling
itself: admin-bff is the OAuth *client*, auth-server is the OAuth
*server*, and the user authenticates against LDAP via auth-server's
default login form.

This is the idiomatic IdP pattern (Keycloak, Authentik, etc.) but
worth stating explicitly because it has implications:

- **`akashic-admin` is a built-in client**, not operator-configured.
  It's registered automatically on server startup with redirect URIs
  derived from config.
- **`akashic-admin`'s client secret lives in Vault KV**, fetched at
  startup by both the admin-bff (for code exchange) and the auth
  server (for issuing/validating). Rotation is independent of the
  TLS PKI's rotation cycle.
- **The admin-bff cannot bootstrap itself.** Until the akashic-admin
  client row exists in `client_services`, the login flow doesn't work.
  We ensure the row exists during akashic-server startup, before
  admin-bff's first connection attempt.

### 2. Tokens stay server-side

The browser never holds an access token, ID token, refresh token, or
client secret. The full flow is:

- **Browser-visible**: session cookie (opaque random ID, Redis-backed)
  + CSRF cookie (Phase 6 unchanged)
- **Admin-bff-internal**: access token, ID token (in Redis session
  store, keyed by session ID)
- **Vault**: client secret, JWT signing key

This is the BFF-for-OAuth pattern; it's the OWASP recommendation for
browser-based OAuth in 2026 (the older "SPA with public client +
PKCE + tokens in localStorage" pattern has fallen out of favor).

### 3. Server-rendered login page

The auth server renders the login form via Go's `html/template`. Not
React. Reasons:

- Login pages are security-critical: minimizing JS narrows the attack
  surface dramatically (no XSS-injected stealing of credentials)
- The form posts to the same origin (auth.akashic.<domain>); no API
  contract or session-bridging needed
- Future tenants may want to **replace** the login page (their own
  branding), which is much easier when the page is HTML+CSS than
  when it's a React build
- Adds zero new build pipelines — just HTML templates embedded into
  the akashic binary via `embed.FS`

A separate `web/auth/` directory holds the templates + minimal CSS;
embedded same way `web/admin/` is in Phase 6.

### 4. RS256-signed JWTs

Access and ID tokens are JWTs signed with RSA 2048-bit keys. Reasons:

- RS256 is the most universally supported algorithm across OAuth
  client libraries (every language we'd integrate with handles it)
- 2048 is the NIST baseline through 2030; we don't need 4096 for
  short-lived tokens (15 min)
- ECDSA (ES256) is faster and produces smaller tokens but has
  marginally less universal support; revisit if token size becomes a
  bottleneck

Signing keys live in Vault KV at `kv/akashic/oauth/signing-keys`,
rotated on a separate schedule from TLS certs (default: 6 months,
overlapping window of 14 days where both old and new keys are
valid for verification).

### 5. PKCE required for confidential clients too

RFC 7636 says PKCE is "recommended" for public clients (SPAs, mobile)
and "optional" for confidential clients (server-side, has a secret).
We require it everywhere. Reasons:

- Defense-in-depth: even if a client secret leaks, the auth code
  can't be replayed without the matching code_verifier
- Simplifies the implementation: one code path, not two
- Adds zero meaningful friction (the BFF generates the verifier
  automatically; operators never see it)

---

## Audience Model

Two distinct audiences, two distinct OAuth clients in Phase 7:

| Surface | OAuth client_id | User roles allowed | Phase |
|---|---|---|---|
| `admin.akashic.<domain>` | `akashic-admin` | `root`, `admin` only | 7 |
| `<root domain>` | `akashic-tenant-portal` | any user | 8 (deferred) |

The role check happens **at the admin-bff** after token validation,
NOT at the auth server. The auth server issues tokens to any
authenticated user; the BFF then refuses to set a session if the ID
token's `user_type` claim isn't `root` or `admin`. This separation
keeps the auth server simple (it doesn't know about per-client role
policies) and lets each BFF enforce its own access policy.

---

## Threat Model: New Attack Surface

| Attack | Defense | Layer |
|---|---|---|
| Authorization code interception (network) | TLS 1.2+ end-to-end | Transport |
| Authorization code replay | Single-use; deleted from Redis on first `/token` exchange | Auth server |
| Authorization code → wrong client | client_id binding stored alongside code in Redis | Auth server |
| Authorization code intercepted, used by attacker without secret | PKCE: attacker doesn't have code_verifier | Auth server (verify SHA256) |
| Cross-site OAuth flow injection (CSRF on /authorize redirect) | `state` parameter — admin-bff verifies it's the value it sent | Admin BFF |
| Stolen ID token | Short TTL (15 min) + audience binding (`aud` claim must match client_id) | Admin BFF (verify) |
| Stolen access token | Same as above; tokens never leave server-side | Admin BFF |
| Stolen session cookie | `HttpOnly; Secure; SameSite=Strict` + idle/absolute timeouts; admin BFF binds session to client IP optionally | Admin BFF |
| LDAP credential brute force | Rate limit on `/login/submit` per IP; account lockout (existing, in `pkg/auth/service.go`) | Auth server |
| Credential phishing on a fake auth.akashic.<domain> | HSTS preload + clear branding + DNS hygiene | Operator |
| Auth server compromised → all tokens forged | JWT signing key in Vault KV with audit log on access; rotation possible | Auth server + Vault |
| Replay of valid token after user disabled | Existing deprovisioning service flips `is_disabled`; admin BFF checks on every API call (Phase 7.9) | Auth server + admin BFF |

The most novel risk is **the auth server itself becoming a target**.
Phase 1-6 hardened the control plane; Phase 7 introduces a new
public-facing surface (`auth.akashic.<domain>`) that anyone on the
Internet can reach. We mitigate by:

- Same security headers / rate limit baseline as the admin BFF
- Login endpoint specifically rate-limited per source IP
- LDAP-bind failures audit-logged with the username (security log
  channel, retention policy applies)
- All OAuth endpoints idempotent or single-use; no state mutations
  via GET
- JWT signing key access audit-logged via Vault

---

## Execution Order

```
Step 1: Data models + DB schema    ← client_services, JWT key infra
Step 2: JWT signing keys           ← Vault KV + reloader, JWKS endpoint
Step 3: Discovery doc              ← /.well-known/openid-configuration
Step 4: Login UI                   ← templates, /login, /login/submit, sessions
Step 5: /authorize                 ← redirect-flow start, code generation
Step 6: /token                     ← code exchange + PKCE verify + JWT mint
Step 7: /userinfo                  ← token introspection
Step 8: akashic-admin built-in     ← startup-time client registration
Step 9: Admin BFF login wiring     ← redirect, callback, session, role check
Step 10: End-to-end verification   ← curl-driven flow + browser flow
```

Steps 1-3 produce a server that ANNOUNCES itself as an OIDC IdP
(`/.well-known/openid-configuration` + `/jwks.json` work) but doesn't
yet handle authentication. Step 4-7 implement the actual flow.
Step 8-9 wire the admin surface to use it. Step 10 is the gate.

---

## Step 1: Data Models + DB Schema

### 1.1 `client_services` table

In Akashic terminology, an OAuth client is a "client service" — a
service registered with the IdP that wants to authenticate users via
Akashic. Naming the table `client_services` (and the Go struct
`ClientService`) matches the operator's mental model better than the
OAuth-spec term "client", which is overloaded with HTTP-client and
many other meanings in the codebase.

```go
// pkg/models/client_service.go
type ClientService struct {
    // ClientID is the public identifier (URL-safe, immutable, e.g. "akashic-admin")
    ClientID string `gorm:"primaryKey;size:255" json:"client_id"`

    // ClientSecretHash is bcrypt(client_secret). Plaintext is never stored;
    // operators retrieve the secret once at registration and store it
    // out-of-band (Vault for built-in clients, secret manager for tenants).
    ClientSecretHash string `gorm:"size:255" json:"-"`

    // Name is operator-readable; used in consent UI (Phase 8+).
    Name string `gorm:"size:255;not null"`

    // RedirectURIs is the allowlist of redirect URIs accepted by /authorize.
    // Stored as comma-separated string for simplicity; switch to a join
    // table if we ever need >5 URIs per client service.
    RedirectURIs string `gorm:"type:text;not null"`

    // AllowedScopes is the space-separated set of scopes this client service may request.
    // Default for built-in clients: "openid profile email".
    AllowedScopes string `gorm:"type:text;not null;default:'openid profile email'"`

    // AuthTypes is the space-separated list of OAuth grant_type values
    // this client service is authorized to use. Phase 7 enables only
    // "authorization_code"; the schema and constants accommodate
    // "client_credentials", "password" (ROPC), "implicit" so future
    // phases enable them without migration.
    AuthTypes string `gorm:"type:text;not null;default:'authorization_code'"`

    // BuiltIn=true marks the client as managed by the akashic-server itself
    // (akashic-admin, akashic-tenant-portal). Built-ins cannot be deleted via
    // admin UI; they're re-upserted on every server startup.
    BuiltIn bool `gorm:"not null;default:false"`

    // RoleAllowlist constrains which user_types may complete an auth flow
    // for this client service. Empty = any user. "root,admin" = only those types.
    // Enforced by the BFF, but stored here so it's auditable.
    RoleAllowlist string `gorm:"size:255"`

    // RequirePKCE forces PKCE on all auth flows for this client service.
    // Default true; we never set false for built-ins.
    RequirePKCE bool `gorm:"not null;default:true"`

    CreatedAt time.Time `gorm:"autoCreateTime"`
    UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

// AuthType constants are the canonical OAuth grant_type strings.
// Stored in the AuthTypes column; checked at /token request time.
const (
    AuthTypeAuthorizationCode AuthType = "authorization_code" // Phase 7: ENABLED
    AuthTypeClientCredentials AuthType = "client_credentials" // Phase 8+
    AuthTypePassword          AuthType = "password"           // ROPC; deferred (under review)
    AuthTypeImplicit          AuthType = "implicit"           // deprecated in OAuth 2.1; deferred
)
```

Migrated via GORM `AutoMigrate`. No manual SQL.

### 1.2 Authorization codes (Redis, not PG)

Codes have a 60-second TTL and are written/read once each. Redis is
the obvious storage:

```
KEY:  akashic:oauth:code:<code>
VALUE (JSON):
  {
    "client_id":      "akashic-admin",
    "user_id":        "<uuid>",
    "redirect_uri":   "https://admin.akashic.local/oauth/callback",
    "scope":          "openid profile email",
    "code_challenge": "<base64url-sha256>",
    "code_challenge_method": "S256",
    "issued_at":      1234567890,
    "session_id":     "<sid for the auth-server session that issued it>"
  }
TTL:  60s
```

Code itself: 32 bytes random, base64url-encoded → 43-char string. Single
use: `GET` + `DEL` in a Lua script for atomicity.

### 1.3 Auth-server sessions (Redis)

When a user logs in via `/login/submit`, we set a session cookie that
survives across `/authorize` calls so they don't re-enter credentials
when navigating between OAuth clients (this is the SSO experience).

```
KEY:  akashic:auth:session:<session_id>
VALUE (JSON):
  {
    "user_id":      "<uuid>",
    "user_type":    "root" | "admin" | "user",
    "ldap_dn":      "uid=alice,ou=users,dc=akashic,dc=local",
    "issued_at":    1234567890,
    "last_seen_at": 1234567890,
    "ip":           "<client-ip>"
  }
TTL: 8h absolute, refreshed on each /authorize visit (idle 30 min)
```

Cookie:
- Name: `akashic_auth_session`
- `HttpOnly; Secure; SameSite=Lax; Path=/`
  (Lax not Strict — Strict breaks the OAuth redirect flow because
  the post-login redirect is "cross-site" from the browser's POV)

---

## Step 2: JWT Signing Keys

### 2.1 Key infrastructure

Store the signing keypair in Vault KV at `kv/akashic/oauth/signing-keys/<kid>`:

```
{
  "private_key": "<PEM>",
  "public_key":  "<PEM>",
  "algorithm":   "RS256",
  "created_at":  "<ISO-8601>",
  "rotated_out_at": null  // set when this key is rotated out; verifies-only after this
}
```

Multiple keys can coexist for rotation. The auth server tracks two:

- **Active key**: used to *sign* new JWTs. There's exactly one.
- **Verify-only keys**: not used for signing, but `/jwks.json` still
  publishes them so existing tokens validate. Aged out after
  `(token_max_ttl + safety_margin)` from `rotated_out_at`.

### 2.2 Key reloader

Mirrors `pkg/pki.Reloader` (Phase 4) but for the signing key:

```go
// pkg/oauth/keystore.go
type KeyStore struct {
    activeKID string
    keys      atomic.Pointer[map[string]*SigningKey]  // kid → key
    vault     *vaultclient.KVClient
    debounce  time.Duration
}

func (ks *KeyStore) ActiveSigningKey() *SigningKey { ... }
func (ks *KeyStore) PublicKeysForJWKS() []*PublicKey { ... }
func (ks *KeyStore) Reload(ctx context.Context) error { ... }
```

Same atomic-pointer-swap pattern: `Reload()` reads from Vault,
constructs a new map, atomically swaps it in. Existing JWT
sign/verify operations either see the old map or the new one, never
a half-built state.

### 2.3 Bootstrap key generation

On first startup, if no signing keys exist in Vault KV, the auth
server generates one:

```go
// During akashic-server Init(), after DB connection but before serving
if !keystore.HasAnyKeys(ctx) {
    if err := keystore.GenerateInitial(ctx); err != nil {
        return fmt.Errorf("generate initial OAuth signing key: %w", err)
    }
}
```

This is a "first-run" action analogous to bootstrap. After it runs,
subsequent restarts just load the existing key.

---

## Step 3: Discovery Doc + JWKS

Cheapest endpoints to ship; useful even before the flow works.

### 3.1 `GET /.well-known/openid-configuration`

```json
{
  "issuer": "https://auth.akashic.local",
  "authorization_endpoint": "https://auth.akashic.local/authorize",
  "token_endpoint": "https://auth.akashic.local/token",
  "userinfo_endpoint": "https://auth.akashic.local/userinfo",
  "jwks_uri": "https://auth.akashic.local/jwks.json",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "code_challenge_methods_supported": ["S256"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "name", "email", "preferred_username", "user_type"]
}
```

Built dynamically from config (issuer URL) + the keystore's algorithm.
Cache headers: `Cache-Control: public, max-age=3600`.

### 3.2 `GET /jwks.json`

Standard JWKS format:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "<kid>",
      "use": "sig",
      "alg": "RS256",
      "n": "<base64url-modulus>",
      "e": "<base64url-exponent>"
    }
  ]
}
```

Includes both the active key and any verify-only keys. Cache headers
match the rotation cadence: `Cache-Control: public, max-age=300`.

---

## Step 4: Login UI

### 4.1 Templates and layout

```
pkg/server/auth/web/
├── login.html.tmpl           ← username + password form
├── error.html.tmpl           ← generic error page
└── styles.css                ← minimal styling, embedded
```

Templates use Go's `html/template` (auto-escapes user input by
default — important defense against XSS). Embedded into the binary
via `embed.FS`.

### 4.2 Routes

| Method | Path | Purpose |
|---|---|---|
| GET | `/login` | Render the login form. Accepts `?return_to=<path>` query param so we can resume the OAuth flow after auth. |
| POST | `/login/submit` | Validate credentials against LDAP, set session cookie, redirect to `return_to`. |
| GET | `/logout` | Clear the session cookie + redirect (RP-initiated logout deferred to Phase 8). |
| GET | `/error` | Generic error page shown when OAuth flows fail outside the redirect_uri (e.g. invalid client_id at /authorize). |

### 4.3 Login flow

```
GET /authorize?... (no session cookie)
  └─ 302 redirect to /login?return_to=/authorize?...

GET /login
  └─ render form with hidden CSRF token

POST /login/submit
  ├─ validate CSRF token
  ├─ rate-limit per IP (5/min)
  ├─ call pkg/auth/service.go's Authenticate(username, password) — existing LDAP-bind logic
  ├─ on success: create session in Redis, set cookie, 302 to return_to
  └─ on failure: re-render /login with "invalid credentials" error
```

The CSRF token here is the same double-submit pattern as Phase 6
(cookie + hidden form field). We DO NOT reuse the admin-bff's CSRF
cookie because they're on different origins (admin.* vs auth.*) and
the cookie wouldn't cross.

---

## Step 5: `/authorize` Endpoint

```
GET /authorize?
    response_type=code
   &client_id=akashic-admin
   &redirect_uri=https://admin.akashic.local/oauth/callback
   &scope=openid profile email
   &state=<random>
   &code_challenge=<base64url-sha256>
   &code_challenge_method=S256
   &nonce=<random>          (optional; OIDC)
```

Steps:
1. Parse & validate query params (RFC 6749 + RFC 7636 + OIDC core).
2. Look up `client_id` in `client_services`. Reject if not found, or
   `redirect_uri` not in the client's allowlist, or `scope` outside
   `AllowedScopes`, or the requested grant type isn't in the client's
   `AuthTypes` list. Errors here render `/error` (don't redirect to
   an attacker-controlled URL).
3. Check session cookie. If absent → 302 to `/login?return_to=<this URL>`.
4. (Future, deferred) Render consent UI. For Phase 7's only client
   (akashic-admin), consent is implicit — no consent page.
5. Generate authorization code (32 bytes random, base64url). Store
   in Redis with `client_id`, `user_id`, `redirect_uri`, `scope`,
   `code_challenge`, etc. TTL 60s.
6. 302 redirect to `redirect_uri?code=<code>&state=<state>`. The
   `state` is passed through unchanged.

### Error handling

OAuth distinguishes two error contexts:

- **Errors before a valid redirect_uri is determined** (e.g., bad
  client_id, redirect_uri not in allowlist) → render `/error`. NEVER
  redirect to the supplied redirect_uri because we can't trust it.
- **Errors after redirect_uri is validated** (e.g., user denied
  consent, server error during code generation) → 302 to
  `redirect_uri?error=<code>&state=<state>`.

This distinction matters: an attacker who supplies their own
redirect_uri shouldn't be redirected to it just because an error
occurred. Standard OAuth-implementation gotcha.

---

## Step 6: `/token` Endpoint

```
POST /token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>

grant_type=authorization_code
&code=<code>
&redirect_uri=<original-redirect-uri>
&code_verifier=<verifier>
```

Steps:
1. Authenticate the client. We accept BOTH `client_secret_basic`
   (HTTP Basic auth header — recommended) and `client_secret_post`
   (in form body) per RFC 6749 §2.3.1.
2. Look up `code` in Redis. Atomic GET+DEL via Lua. If not found or
   expired → 400 `invalid_grant`.
3. Verify `client_id` from auth matches the one stored alongside
   the code.
4. Verify `redirect_uri` matches the one stored alongside the code.
5. Verify `SHA256(code_verifier) == code_challenge` (PKCE). Mismatch
   → 400 `invalid_grant`.
6. Look up the user (stored alongside the code) — confirm `is_disabled
   = false`. If disabled → 401, audit-log.
7. Mint:
   - **Access token**: JWT signed with active key. `aud=client_id`,
     `exp=now+15m`, `scope=<requested>`, `sub=<user_id>`.
   - **ID token** (if `openid` scope requested): JWT with the same
     `aud/exp` plus `name`, `email`, `preferred_username`,
     `user_type`, `nonce`.
   - **Refresh token**: deferred to Phase 8.
8. Return:

```json
{
  "access_token":  "<jwt>",
  "token_type":    "Bearer",
  "expires_in":    900,
  "id_token":      "<jwt>",  // if openid scope requested
  "scope":         "openid profile email"
}
```

### What's in an ID token

Standard claims plus `user_type`:

```json
{
  "iss":   "https://auth.akashic.local",
  "sub":   "<uuid>",
  "aud":   "akashic-admin",
  "exp":   1234567890,
  "iat":   1234567890,
  "nonce": "<from /authorize>",
  "name":  "Alice Admin",
  "email": "alice@example.com",
  "preferred_username": "alice",
  "user_type": "admin"
}
```

The `user_type` claim is what the admin-bff's role check (Step 9)
reads to decide whether to allow the session.

---

## Step 7: `/userinfo` Endpoint

```
GET /userinfo
Authorization: Bearer <access_token>
```

Steps:
1. Verify the access token (signature + `exp` + `aud`).
2. Look up the user by the `sub` claim. Confirm `is_disabled = false`.
3. Return user attributes restricted by the token's `scope`:

```json
{
  "sub":   "<uuid>",
  "name":  "Alice Admin",
  "email": "alice@example.com",                     // only if "email" scope
  "preferred_username": "alice",                    // only if "profile" scope
  "user_type": "admin"                              // always, since we use it for authz
}
```

The admin-bff calls this on every API request to verify the session
is still valid (catches the "user disabled while logged in" case).

---

## Step 8: Built-In `akashic-admin` Client

On akashic-server startup, after DB connection + before serving,
upsert the `akashic-admin` row in `client_services`:

```go
// pkg/oauth/builtin.go
func EnsureBuiltInClients(ctx context.Context, db *gorm.DB, cfg *config.Config, vault *vaultclient.KVClient) error {
    // akashic-admin — for the admin UI on admin.akashic.<domain>
    secret, err := vault.GetOrCreate(ctx, "kv/akashic/oauth/clients/akashic-admin", func() string {
        // Generate fresh secret on first run; subsequent runs reuse it.
        b := make([]byte, 32)
        _, _ = rand.Read(b)
        return base64.RawURLEncoding.EncodeToString(b)
    })
    if err != nil { return err }

    return upsertClient(db, &models.ClientService{
        ClientID:         "akashic-admin",
        ClientSecretHash: bcryptHash(secret),
        Name:             "Akashic Admin Console",
        RedirectURIs:     cfg.OAuth.AdminRedirectURI,  // e.g. "https://admin.akashic.local/oauth/callback"
        AllowedScopes:    "openid profile email",
        AuthTypes:        string(models.AuthTypeAuthorizationCode),
        BuiltIn:          true,
        RoleAllowlist:    "root,admin",
        RequirePKCE:      true,
    })
}
```

The Vault KV path holds the raw secret; the DB holds only its bcrypt
hash. Admin-bff fetches the raw secret from Vault on its own startup
to use in `/token` exchanges.

This pattern (built-in client, secret in Vault, hash in DB) is the
template for `akashic-tenant-portal` in Phase 8.

---

## Step 9: Admin BFF Login Wiring

### 9.1 New routes in admin-bff

| Method | Path | Purpose |
|---|---|---|
| GET | `/login` | Initiate OAuth flow. Generates `state` + `code_verifier`, stores in pre-session cookie, redirects to auth-server's `/authorize`. |
| GET | `/oauth/callback` | Receives `code` + `state` from auth-server. Verifies state. POSTs to `/token`. Verifies ID token. Reads `user_type` claim. **Rejects if not root or admin.** Creates BFF session (Redis), sets session cookie, redirects to `/`. |
| POST | `/logout` | Clears BFF session, optionally calls auth-server's `/logout`. |

### 9.2 Session handling

```
KEY:   akashic:bff:admin:session:<sid>
VALUE: {
  "user_id":             "<uuid>",
  "user_type":           "admin",
  "username":            "alice",
  "email":               "...",
  "access_token":        "<jwt>",     // for calls back to control plane / userinfo
  "id_token":            "<jwt>",
  "expires_at":          "<ts>",
  "issued_at":           "<ts>",
  "last_activity_at":    "<ts>"
}
TTL: 8h absolute, 30m idle (refresh on each request)
```

Cookie:
- Name: `akashic_admin_session`
- `HttpOnly; Secure; SameSite=Lax` (Lax for OAuth redirect compatibility)
- `Max-Age` matches absolute TTL

### 9.3 Role check

Implemented in admin-bff's `/oauth/callback` handler:

```go
const allowedRoles = "root,admin"

// after successful /token exchange and ID token verification
userType, _ := idToken.Claims["user_type"].(string)
if !slices.Contains([]string{"root", "admin"}, userType) {
    s.auditLog(r, "admin_login_denied_role", map[string]any{
        "user_type": userType,
        "username":  username,
    })
    writeError(w, http.StatusForbidden, "ACCESS_DENIED",
        "Your account does not have permission to access the admin console.")
    return
}
```

This is enforced **at the BFF**, not the auth server. The auth server
issues the token to anyone authenticated; the BFF decides whether to
let them past the door.

### 9.4 Replacing the bootstrap-required page

The Phase 6 React FE shows two states:
- `is_complete = false` → BootstrapForm
- `is_complete = true` → BootstrapAlreadyComplete

Phase 7 adds a third state: `is_complete = true && !logged_in` →
redirect to `/login`. The "Already complete" view stays as the
fallback for users who somehow land at the URL without a session
(shouldn't normally happen).

Once logged in, the FE shows a placeholder dashboard ("Welcome, alice.
Phase 7.5 dashboard coming soon."). The full admin dashboard is
Phase 8+.

---

## Step 10: End-to-End Verification

### 10.1 Curl-driven OAuth flow

```bash
# 1. Get the discovery doc
curl https://auth.akashic.local:8080/.well-known/openid-configuration | jq

# 2. Get JWKS
curl https://auth.akashic.local:8080/jwks.json | jq

# 3. Begin auth flow (would normally happen in browser)
# Generate verifier + challenge
VERIFIER=$(openssl rand -base64 64 | tr -d "=+/" | cut -c -64)
CHALLENGE=$(echo -n "$VERIFIER" | openssl dgst -sha256 -binary | base64 | tr -d "=+/")

# 4. /authorize requires a session; this would be after /login
# Skip to: assume we have a session cookie + an authorization code
# (in real testing, drive this via headless Chrome or just use the browser)

# 5. Exchange code for tokens
curl -X POST https://auth.akashic.local:8080/token \
    -u "akashic-admin:$CLIENT_SECRET" \
    -d "grant_type=authorization_code" \
    -d "code=$CODE" \
    -d "redirect_uri=https://admin.akashic.local/oauth/callback" \
    -d "code_verifier=$VERIFIER" | jq

# 6. Use access token at /userinfo
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
    https://auth.akashic.local:8080/userinfo | jq
```

### 10.2 Browser-driven full flow

```
1. Visit https://admin.akashic.local
2. Auto-redirect to /login at admin.akashic.local
3. /login redirects to auth.akashic.local/authorize
4. /authorize redirects to auth.akashic.local/login (no session)
5. Log in as bootstrap-created root user
6. Redirect chain: /login/submit → /authorize → /oauth/callback → /
7. Land on the admin dashboard (placeholder)
```

Failure-mode checks:

- Log in as a `user`-type account → admin-bff returns 403 ACCESS_DENIED
  (verifies the role check)
- Visit `/oauth/callback` directly without a state cookie → BFF
  returns 400 (state mismatch)
- Tamper with the ID token → BFF rejects (signature verification)
- Disable the user via deprovisioning while logged in → next
  /userinfo call returns 401, BFF clears session
- Auth server's signing key rotated → existing sessions still work
  until token expires; new logins use new key (verified via JWKS
  containing both keys during overlap window)

---

## Files Summary (planned)

### New files

| Path | Purpose |
|---|---|
| `pkg/models/client_service.go` | ClientService model + AuthType constants + GORM hooks |
| `pkg/oauth/keystore.go` | JWT signing key store + reloader (mirrors `pkg/pki`) |
| `pkg/oauth/jwt.go` | JWT mint + verify helpers |
| `pkg/oauth/codes.go` | Authorization-code Redis storage |
| `pkg/oauth/sessions.go` | Auth-server session store (Redis) |
| `pkg/oauth/builtin.go` | EnsureBuiltInClients startup logic |
| `pkg/oauth/pkce.go` | code_challenge / code_verifier helpers |
| `pkg/server/auth/oauth_handlers.go` | `/authorize`, `/token`, `/userinfo`, discovery, JWKS |
| `pkg/server/auth/login_handlers.go` | `/login`, `/login/submit`, `/logout` |
| `pkg/server/auth/templates.go` | `embed.FS` for login UI templates |
| `pkg/server/auth/web/login.html.tmpl` | Login form template |
| `pkg/server/auth/web/error.html.tmpl` | Generic error page |
| `pkg/server/auth/web/styles.css` | Minimal CSS for login pages |
| `pkg/admin_bff/oauth.go` | Admin BFF's OAuth-client logic (state, code exchange) |
| `pkg/admin_bff/session.go` | BFF-side session store |
| `web/admin/src/components/Dashboard.tsx` | Placeholder logged-in view |
| `doc/phase-7-revision.md` | (later) — as-built operator-facing summary |

### Modified files

| Path | Change |
|---|---|
| `pkg/server/auth/routes.go` | Register OAuth + login routes |
| `pkg/server/auth/server.go` | Wire keystore + session store into the server |
| `pkg/akashic/core/context.go` | Initialize keystore + EnsureBuiltInClients during Init() |
| `pkg/config/types.go` | New `OAuthConfig` struct (issuer URL, redirect URIs, key rotation policy) |
| `pkg/config/defaults.go` | Defaults for the above |
| `pkg/database/akashic_postgres/postgres.go` | Add ClientService to AutoMigrate list |
| `pkg/admin_bff/server.go` | Register `/login`, `/oauth/callback`, `/logout` |
| `pkg/admin_bff/handlers.go` | Add session-required check on `/api/*` paths (after Phase 7 lands) |
| `web/admin/src/App.tsx` | Three-state shell (form / login-required / logged-in) |
| `docker-compose.yml` | Add auth-server alias `auth.akashic.local`; ports if needed for direct dev access |
| `services/proxy/nginx.conf` | New server block for `~^auth\.` (proxy → auth-server :8080) |

### NOT touched

- `pkg/pki/` — TLS PKI is unchanged; OAuth signing keys are independent
- `pkg/cli/` — CLI keeps its mTLS auth; doesn't use OAuth
- Bootstrap flow — unchanged; bootstrap completion is a precondition
  for OAuth (the LDAP root user must exist to log in as)

---

## Known Risks

| Risk | Mitigation |
|---|---|
| OAuth implementation bugs (it's a thoroughly-spec'd protocol but easy to get subtly wrong) | Follow OWASP OAuth 2.1 cheat sheet; test against `oauth-rs` or similar conformance tooling; consider integrating an established library (`go-oidc`, `fosite`) instead of writing from scratch — strongly recommended |
| JWT signing key compromise | Vault audit log + rotation + short token TTLs limit blast radius |
| Authorization code interception via TLS downgrade | TLS 1.2+ minimum + HSTS preload on auth subdomain |
| Cross-tenant scope confusion (Phase 8 risk, surface here) | `aud` claim binds tokens to specific client_id; admin-bff verifies aud=akashic-admin |
| Refresh tokens deferred → users re-login every 15min for active sessions | UX friction in dev; production sessions are 8h via the BFF session cookie. Refresh tokens land in Phase 8 |
| Login page phishing risk on auth.akashic.<domain> | HSTS preload + branding consistency. Future tenant-customizable themes need careful XSS review |
| LDAP brute force via /login/submit | Rate limit per IP (5/min) + per username (10/hour); audit-log every failed bind |
| Session fixation (attacker pre-creates a session, induces victim to log into it) | Rotate session ID on successful auth (Go's `securecookie` or equivalent) |

The library question is the biggest one. Writing OAuth from scratch
is *possible* but carries genuine "did you implement this exactly
right?" risk. The mitigation is to use a vetted Go library — `fosite`
is the most production-grade option; `go-oidc` is more passive (just
verification).

**Recommendation**: use `fosite` for the auth-server side
(it implements all the spec edges correctly and gives us future grant
types for free) and `go-oidc` for the admin-bff client side. Both
are battle-tested.

If preferred, hand-rolling Phase 7 is doable and educational, but
expect to spend ~30% of the time on conformance edge cases that
libraries handle by default.

---

## Non-Goals (Deferred)

- **Refresh tokens** — Phase 8. Adds DB state + rotation logic.
- **Logout (RP-initiated, front-channel)** — Phase 8.
- **Tenant root-domain BFF** — Phase 8 (Next.js + akashic-tenant-portal client).
- **Consent UI** — Phase 8+. Required for non-built-in clients (when
  customers register their own apps); for akashic-admin, consent is
  implicit.
- **Token revocation endpoint** — Phase 8.
- **Token introspection endpoint** — Phase 9. /userinfo covers the
  immediate need.
- **Other grant types** (client_credentials, device, password) —
  case-by-case as use cases arise. Probably client_credentials in
  Phase 9 for service-to-service.
- **Dynamic client registration** — Phase 8 (tenant UI registers
  clients). Phase 7 has only built-ins.
- **Multi-tenant scope handling** (per-tenant scopes) — Phase 9.
- **Production cert for auth subdomain** — same Let's Encrypt /
  pki-public choice as admin subdomain (Phase 6).
- **Customizable login themes** — Phase 9+.
- **MFA / WebAuthn / TOTP** — Phase 10+. Password-only initially.
- **OIDC session management spec / front-channel logout** — Phase 10+.

---

## Phase 8 Preview (orientation only)

After Phase 7 lands:

1. **Refresh tokens** + rotation + the database state to track them
2. **Tenant surface at `<root domain>`**: Next.js BFF, OAuth login as
   `akashic-tenant-portal`, no role restriction
3. **Tenant management UI**: register OAuth clients, set redirect
   URIs, manage scopes
4. **Consent UI** at the auth server (required for non-built-in
   clients)
5. **RP-initiated logout** + token revocation endpoint
6. **Admin dashboard** (real one, not the placeholder): user
   management, RBAC viewer, audit log browser, server controls

None of that is in Phase 7. Phase 7 ends when an admin can log into
`admin.akashic.<domain>` via OAuth, and the `user_type` claim is
correctly enforcing access.
