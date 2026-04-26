# Chapter 09 — Reference & Glossary

> **Goal**: this is a lookup reference, not a learning chapter.
> Bookmark it. When you're reading code and hit an unfamiliar term,
> file path, or hostname — start here.

## Glossary

### Actors and parties

| Term | Definition |
|---|---|
| **Akashic** | The IdP itself, written in Go, runs as either a docker container or a host process |
| **Admin BFF** | Browser-facing service (`admin-bff`) that fronts the React admin UI and acts as an OAuth client |
| **Tenant** | A future concept — a customer/org that registers OAuth clients via the admin UI |
| **Client / OAuth client / Client service** | A service registered in the `client_services` table that wants to authenticate users via Akashic. Currently only `akashic-admin` (the BFF). |
| **Resource Owner** | The user being authenticated (OAuth spec term) |
| **Authorization Server / IdP** | The thing minting tokens — Akashic's auth-server (port 8080) |
| **Resource Server** | A service that consumes access tokens. In our setup it's effectively the BFF (it issues the access token and consumes it via the BFF session). |

### Protocols and standards

| Term | Definition |
|---|---|
| **OAuth 2.1** | Updated IETF OAuth spec; mostly RFC 6749 with PKCE mandatory and a few legacy flows removed |
| **OIDC** | OpenID Connect — adds identity-tokens and a discovery doc on top of OAuth |
| **PKCE** | Proof Key for Code Exchange (RFC 7636); binds an auth code to the browser that requested it |
| **JWT** | JSON Web Token (RFC 7519); a signed JSON payload |
| **JWS / JWA / JWK / JWKS** | The JOSE family: Signature, Algorithms, Key, Key Set. JWKS = a JSON document containing public keys for verifying JWTs |
| **mTLS** | Mutual TLS — both client and server present X.509 certs |
| **PKI** | Public Key Infrastructure — the cert-issuance machinery (Vault + Vault Agent) |
| **CA** | Certificate Authority — the entity that issues certs |
| **SAN** | Subject Alternative Name — names a cert is valid for |
| **CSR** | Certificate Signing Request — a request to a CA to issue a cert |
| **JIT provisioning** | Just-In-Time — create the postgres row for a user on first authentication, rather than ahead of time |
| **RP-Initiated Logout** | OIDC pattern where the relying party (BFF) tells the IdP to invalidate its session |
| **CSRF** | Cross-Site Request Forgery |
| **SSO** | Single Sign-On |

### Akashic-specific terms

| Term | Definition |
|---|---|
| **`app` profile** | Docker Compose profile that gates only the akashic-server container |
| **Container mode** | Akashic runs in docker (`--profile app`) |
| **Host(-akashic) mode** | Akashic runs on the host (`go run ./cmd/akashic run`); deps + BFF still in docker |
| **Bootstrap mode** | Initial state of a fresh install — no root user yet |
| **Bootstrap token** | One-time random token printed at akashic startup, used to create the first root user |
| **Built-in client** | An OAuth client managed by akashic itself (currently only `akashic-admin`); secret auto-generated on first run |
| **Auth server / Auth listener** | The akashic process's port-8080 HTTP listener (public OAuth/OIDC) |
| **Control server / Control plane** | The akashic process's port-8081 HTTP listener (mTLS-only management) |
| **The two listeners** | Shorthand for the auth server + control server pair, both running in the same Go process |
| **`pki-internal`** | Vault PKI mount that issues server certs for everyone |
| **`pki-mtls-akashic-ctrl`** | Vault PKI mount for mTLS server + client certs on the control plane |
| **The cert reloader** | `pkg/pki.Reloader` — atomic-pointer-backed live cert swap |
| **The keystore** | `pkg/oauth.KeyStore` — atomic-pointer-backed JWT signing key store |
| **Lazy init** | Pattern where a dependency is initialized on first use, retrying on failure |

## File-path map

A quick alphabetical map of "where does X live?":

| Concern | Path |
|---|---|
| Admin BFF | `pkg/admin_bff/` |
| Auth-server HTTP routes | `pkg/server/auth/routes.go` |
| Auth-server OAuth handlers | `pkg/server/auth/oauth_flow_handlers.go` |
| Auth-server login UI | `pkg/server/auth/login_handlers.go` + `pkg/server/auth/web/` |
| Bootstrap manager | `pkg/bootstrap/manager.go` |
| BFF OAuth client | `pkg/admin_bff/oauth.go` |
| BFF OAuth handlers | `pkg/admin_bff/oauth_handlers.go` |
| BFF session store | `pkg/admin_bff/session.go` |
| BFF JWKS cache | `pkg/admin_bff/jwks.go` |
| Built-in OAuth clients (akashic-admin) | `pkg/oauth/builtin.go` |
| Cert reloader | `pkg/pki/reloader.go` |
| Config schema | `pkg/config/types.go` |
| Config defaults | `pkg/config/defaults.go` |
| Control-plane HTTP routes | `pkg/server/control/routes.go` |
| Control-plane handlers | `pkg/server/control/handlers.go` |
| Database connection (postgres) | `pkg/database/akashic_postgres/postgres.go` |
| Database connection (redis) | `pkg/database/akashic_redis/redis.go` |
| Deprovisioning service | `pkg/ldap/deprovisioning.go` |
| FE source | `web/admin/src/` |
| FE build output (embedded) | `cmd/admin-bff/dist/` |
| GORM models | `pkg/models/` |
| GORM↔zap adapter | `pkg/database/akashic_postgres/zap_logger.go` |
| LDAP client | `pkg/ldap/client.go` |
| LDAP RBAC service | `pkg/ldap/rbac.go` |
| Lifecycle | `pkg/akashic/core/context.go` |
| Logger | `pkg/logging/logger.go` |
| Loki sink | `pkg/logging/loki_writer.go` |
| Middleware | `pkg/middleware/` |
| OAuth authorization code | `pkg/oauth/codes.go` |
| OAuth JWT mint/verify | `pkg/oauth/jwt.go` |
| OAuth keystore | `pkg/oauth/keystore.go` |
| OAuth PKCE helpers | `pkg/oauth/pkce.go` |
| OAuth session (auth-server side) | `pkg/oauth/sessions.go` |
| Reset script | `scripts/reset-akashic.sh` |
| User repository | `pkg/repository/user_repository.go` |
| Vault Agent templates | `services/vault-agent/templates/` |
| Vault bootstrap | `services/vault/bootstrap/` |

## Hostnames

These hostnames recur throughout the codebase. Knowing what each one
means is essential for reading the code:

| Hostname | What it points at | Where it's used |
|---|---|---|
| `akashic.akashic.local` | The akashic container | Generic container alias |
| `auth.akashic.local` | The akashic auth listener (port 8080) | TLS cert SAN; nginx upstream |
| `ctrl.akashic.local` | The akashic control listener (port 8081) | TLS cert SAN; mTLS upstream |
| `admin-bff.akashic.local` | The admin-bff container | Network alias |
| `bff.akashic.local` | mTLS client cert CN of the admin-bff | The BFF's identity to the control plane |
| `cli.akashic.local` | mTLS client cert CN of the akashic-cli | The CLI's identity to the control plane |
| `postgres.akashic.local` | Postgres container | TLS cert SAN |
| `redis.akashic.local` | Redis container | TLS cert SAN |
| `ldap.akashic.local` | LDAP container | TLS cert SAN |
| `vault.akashic.local` | Vault container | Network alias |
| `loki.akashic.local` | loki-proxy fronting Loki | TLS cert SAN |
| `proxy.akashic.local` | nginx-proxy | Network alias |
| `host.docker.internal` | The docker host (Mac/Win Docker Desktop magic; Linux requires extra_hosts) | Used for host-akashic mode routing |

## Ports

| Port | What's there | Where exposed |
|---|---|---|
| 8080 | Akashic auth listener (HTTPS, OAuth/OIDC) | Container's port; published on host as `${AKASHIC_AUTH_HOST_PORT:-8080}` |
| 8081 | Akashic control listener (HTTPS+mTLS) | Container's port; published on host as `127.0.0.1:${AKASHIC_CTRL_HOST_PORT:-8081}` |
| 8082 | Admin BFF | Internal to docker; reachable via the proxy on 8280 |
| 8200 | Vault HTTPS | Internal; UI proxied via vault.akashic.<domain> |
| 8280 | nginx-proxy | Published on host as `${AKASHIC_NGINX_PORT:-8280}` |
| 5432 | Postgres | Internal |
| 6379 | Redis | Internal |
| 389 | LDAP plain (StartTLS-upgradeable) | Internal |
| 636 | LDAPS (TLS from connect) | Internal |
| 3100 | Loki HTTPS | Internal |
| 3000 | Grafana | Internal; UI proxied via grafana.akashic.<domain> |

## Cookies

| Cookie | Origin | What it does | Attributes |
|---|---|---|---|
| `akashic_csrf` | admin.* | Double-submit CSRF token for `/api/*` POSTs | Path=/, Secure, SameSite=Strict, HttpOnly=false |
| `akashic_admin_oauth_pre` | admin.* | Carries OAuth state+verifier across the auth flow | Path=/, Max-Age=300, HttpOnly, Secure, SameSite=Lax |
| `akashic_admin_session` | admin.* | The logged-in BFF session ID | Path=/, Secure, HttpOnly, SameSite=Lax |
| `akashic_login_csrf` | auth.* | CSRF token for the login form | Path=/, Secure, SameSite=Strict |
| `akashic_auth_session` | auth.* | The IdP-side session ID | Path=/, Secure, HttpOnly, SameSite=Lax |

## Redis keyspaces

| Prefix | What it stores | TTL |
|---|---|---|
| `akashic:auth:session:<sid>` | Auth-server (IdP) session | 8h absolute / 30m idle |
| `akashic:bff:admin:session:<sid>` | BFF session | 8h / 30m |
| `akashic:oauth:code:<code>` | Single-use authorization code | 60s |

## Environment variables (selected)

The full list is in `.env.example`. Most-used ones:

| Variable | What it controls | Default |
|---|---|---|
| `AKASHIC_OAUTH_ISSUER` | Public issuer URL (JWT iss claim, discovery doc) | `https://auth.akashic.local` |
| `AKASHIC_OAUTH_ADMIN_REDIRECT_URI` | akashic-admin client's redirect_uri | `https://admin.akashic.local/oauth/callback` |
| `AKASHIC_BFF_OAUTH_INTERNAL_URL` | Where the BFF dials akashic for /token + /jwks | `https://auth.akashic.local:8080` |
| `AKASHIC_SERVER_CONTROL_HOST` | Bind address for control plane (in container: 0.0.0.0; on host: 127.0.0.1 default, override to 0.0.0.0 for hybrid) | (varies) |
| `AKASHIC_*_TLS` | TLS toggles per service (postgres, redis, ldap, loki-proxy) | `on` |
| `AKASHIC_LDAP_ADMIN_PASSWORD` | LDAP admin bind password | (in .env) |
| `AKASHIC_DATABASE_REDIS_PASSWORD` | Redis AUTH password | (in .env) |
| `AKASHIC_DATABASE_POSTGRES_PASSWORD` | Postgres password | (in .env) |

## Scripts

| Script | Purpose |
|---|---|
| `scripts/reset-akashic.sh` | Full-stack reset (vault, certs, keys, every docker volume, host-side state) |
| `scripts/init/*` | Project-init helpers (cert generation for first-time setup) |

## Phase docs

| Doc | Status |
|---|---|
| `phase-3-plan.md` | Plan only |
| `phase-4-plan.md` | Plan only |
| `phase-5-plan.md` + `phase-5-revision.md` | Plan + as-built |
| `phase-6-plan.md` + `phase-6-revision.md` | Plan + as-built |
| `phase-7-plan.md` + `phase-7-progress.md` | Plan + in-flight progress (eventual revision pending) |

The "study" guide you're reading right now is the conceptual
counterpart to those phase-specific docs.

## Common-failure quick-reference

| Symptom | First check |
|---|---|
| `cannot load certificate` from a service | `find ./certs -type f` — vault-agent finished rendering? |
| `502 Bad Gateway` on auth.* | Is akashic running? `docker compose ps akashic` or check terminal for `go run` |
| `OAUTH_NOT_CONFIGURED` from BFF | Restart admin-bff (or wait for next /login lazy retry); akashic must be up first to write the secret file |
| `TOKEN_EXCHANGE_FAILED` from BFF | BFF can't reach akashic. Check `extra_hosts` resolution, akashic listening on 0.0.0.0:8080 |
| `ID_TOKEN_INVALID` from BFF | iss/aud mismatch — typically `AKASHIC_OAUTH_ISSUER` differs between akashic and BFF env |
| Login form rejects correct password | LDAP connection state corrupt? Check that admin-bind succeeded after a wrong-password attempt; `pkg/ldap/client.go`'s defer rebindAsAdmin should prevent this |
| `Invalid form submission` after login submit | CSP `form-action` blocked the redirect chain; fixed in Phase 7 to allow `https:` |
| Browser stuck on login form | DevTools console — likely a CSP violation; check `services/proxy/nginx.conf` and `pkg/server/auth/templates.go`'s CSP |

## End

You've reached the end of the study guide. Re-read individual chapters
as the codebase evolves — when something feels unclear, the
walkthrough in chapter 07 is usually the fastest re-orientation.

If you find any chapter has drifted from reality (a renamed file, a
removed concept, a changed pattern), update it. The guide is meant
to stay current with the code; the alternative is the same problem
you wrote it to avoid.

## ← Back to [Index](./README.md)
