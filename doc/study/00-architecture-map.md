# Chapter 00 — The Architecture Map

> **Goal**: by the end of this chapter, you should be able to look at a
> live `docker compose ps` output and explain what every running
> container is for and why it exists.

## What is Akashic?

Akashic is a **Go-based identity provider (IdP)**. It implements the
OAuth 2.1 + OIDC protocols, and it speaks LDAP on the back end as its
source of user identity. A "tenant" registers an OAuth client with
Akashic; users authenticate to Akashic; the tenant's app receives
identity tokens that prove who the user is.

Architecturally, Akashic is *not* a microservice swarm. It's a
deliberately monolithic Go binary (`cmd/akashic/main.go`) plus a
single browser-facing BFF (`cmd/admin-bff/main.go`) and a stack of
*infrastructural* dependencies (postgres, redis, ldap, vault, etc.)
that the binary uses. The "monolith with dependencies" shape is a
pragmatic choice — every concern that's *core to identity* lives in
the same Go binary, while every *off-the-shelf service* lives in
docker.

## The container inventory

When you run `docker compose --profile app up -d`, you get this:

```
┌────────────────────────────────────────────────────────────────────┐
│                     YOUR DEV MACHINE (host)                        │
│                                                                    │
│  Browser ──────────► host-side TLS terminator ─────────────┐       │
│                                                            │       │
│  ┌─────────────────── docker network: akashic-net ─────────┼────┐  │
│  │                                                         ▼    │  │
│  │  ┌──────────┐    ┌──────────────────────────────────────────┐│  │
│  │  │  proxy   │◄───┤ all browser traffic, by subdomain        ││  │
│  │  │ (nginx)  │    │ admin.* / auth.* / vault.* / grafana.* / ││  │
│  │  └──────────┘    │ adminer.* / redisinsight.* / phpldapadmin││  │
│  │       │          │ etc.                                     ││  │
│  │       ▼          └──────────────────────────────────────────┘│  │
│  │  ┌──────────┐         ┌─────────────────┐                    │  │
│  │  │admin-bff │────────►│   akashic       │ (the IdP itself)   │  │
│  │  │ (Go BFF) │  mTLS   │  (Go server)    │                    │  │
│  │  └──────────┘ ports   │  ports 8080+8081│                    │  │
│  │       │      8080,8081└─────────────────┘                    │  │
│  │       ▼                       │                              │  │
│  │  ┌──────────┐ ┌─────────┐ ┌────────┐ ┌──────────┐ ┌────────┐ │  │
│  │  │  redis   │ │postgres │ │  ldap  │ │  vault   │ │  loki  │ │  │
│  │  └──────────┘ └─────────┘ └────────┘ └──────────┘ └────────┘ │  │
│  │                                            │                 │  │
│  │                                            ▼                 │  │
│  │                                       ┌──────────────┐       │  │
│  │                                       │  vault-agent │       │  │
│  │                                       │  (cert       │       │  │
│  │                                       │   rendering) │       │  │
│  │                                       └──────────────┘       │  │
│  │                                                              │  │
│  │  Plus: grafana, loki-proxy, adminer, redisinsight,           │  │
│  │  phpldapadmin (UIs and observability)                        │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

## The components, in three tiers

### Tier 1 — The application services

| Service | Container | What it does |
|---|---|---|
| **akashic** | akashic-server | The IdP. Two listeners: auth (port 8080, public-facing OAuth/OIDC) and control (port 8081, mTLS-only management API). Gated by `--profile app`. |
| **admin-bff** | akashic-admin-bff | Browser-facing BFF for the admin UI. Hosts the embedded React FE on `/`, proxies `/api/*` calls to the akashic control plane over mTLS, and acts as an OAuth client for admin login. |
| **proxy** | akashic-proxy | nginx reverse-proxy that does TLS subdomain routing for everything browser-facing. |

These three are the application-layer services. The akashic server
holds the protocol logic; the BFF translates between browser
conventions and Akashic's internal mTLS API; the proxy fans out
traffic by subdomain.

### Tier 2 — The data stores

| Service | Container | What it stores |
|---|---|---|
| **postgres** | akashic-postgres | Akashic-specific metadata: user records (linked to LDAP DNs), client_services (OAuth client registry), bootstrap state |
| **redis** | akashic-redis | Short-lived state: auth-server sessions, BFF sessions, OAuth authorization codes |
| **ldap** | akashic-ldap | The **canonical user identity** store. Usernames, emails, passwords (hashed). Akashic *cannot start* without LDAP being reachable. |

The split is deliberate. **LDAP is the source of truth for identity**;
postgres only carries Akashic-specific metadata that LDAP doesn't
know about (e.g., "is this user disabled in our admin console?").
Redis is for state that should not survive a restart — sessions,
codes, transient cache.

### Tier 3 — The PKI and observability

| Service | Container | What it does |
|---|---|---|
| **vault** | akashic-vault | Issues all internal TLS certs. Holds the project's root CA chain. Also acts as a generic secrets store. |
| **vault-agent** | akashic-vault-agent | Continuously renders certs from Vault to disk for every other service. Renews them before expiry. |
| **vault-bootstrap** | akashic-vault-bootstrap | One-shot container: initializes Vault on first run (creates the root CA, configures PKI mounts, sets up policies). |
| **loki** + **loki-proxy** | akashic-loki, akashic-loki-proxy | Log aggregation. Akashic ships logs here; loki-proxy adds TLS termination. |
| **grafana** | akashic-grafana | Dashboards over Loki. |

### The auxiliary UIs

These exist purely for development convenience — none are required
for Akashic to function:

| Service | What you'd use it for |
|---|---|
| adminer | Browse the postgres database in a web UI |
| redisinsight | Browse Redis keys |
| phpldapadmin | Browse the LDAP DIT |

## The two listeners on the akashic server

This is the single most important architectural concept to internalize.

The akashic Go process binds **two HTTP listeners**:

```
                ┌──────────── akashic process ────────────┐
                │                                          │
   browser ────►│  :8080 auth listener                     │
                │     (TLS, no mTLS — public surface)      │
                │     OAuth/OIDC: /authorize, /token,      │
                │     /userinfo, /login, /jwks.json, etc.  │
                │                                          │
   bff/cli ────►│  :8081 control listener                  │
                │     (TLS + mTLS — admin surface)         │
                │     Bootstrap, server lifecycle, future  │
                │     admin endpoints                      │
                └──────────────────────────────────────────┘
```

**Why two ports?** Different security models for different audiences.

- **Auth listener (8080)**: serves the OIDC IdP surface. Browsers hit
  this directly during login. TLS yes; mTLS no — anyone can reach it,
  the protocol handles authentication via OAuth flows, not via
  client certs.
- **Control listener (8081)**: management API. Only authenticated
  clients (the admin-bff, the akashic-cli, future admin tools) talk
  to it. mTLS is required — if you can't present a client cert
  signed by the project's mTLS CA, you don't get past the handshake.

The two listeners share the same process (so they share state — same
config, same database connections, same logger), but they are
*separately middleware-stacked* and present *separately-issued TLS
certs* (`auth.crt` for 8080, `ctrl.crt` for 8081).

## How the network fans out

```
  Browser hits https://admin.akashic.<your-domain>/
       │
       ├─► host-side TLS terminator (Caddy, nginx, etc. on your machine)
       │
       └─► docker proxy:8280 (subdomain routing)
              │
              ├─ admin.*       → admin-bff:8082 (FE + /api/*)
              ├─ auth.*        → akashic:8080 (OAuth endpoints)
              ├─ vault.*       → vault:8200 (Vault UI)
              ├─ grafana.*     → grafana:3000
              ├─ adminer.*     → adminer:8080
              ├─ redisinsight.*→ redisinsight:5540
              └─ phpldapadmin.*→ phpldapadmin:80
```

The subdomain dispatch is purely the nginx-proxy's job. Each backend
sees a clean HTTP/HTTPS request and doesn't know about the others.
This separation lets you swap or remove individual backends without
disrupting the routing.

## Two ways the akashic server can run

When `--profile app` is set, akashic runs **inside the docker network**
as a container. When it's omitted, akashic runs **on the host machine**
as a `go run` process — and the rest of the docker stack (admin-bff
included) talks to it across the docker/host boundary via the host
gateway. Both modes work without any override files; the BFF and
proxy are configured to dial akashic via hostnames that resolve to
the docker host gateway, so docker port-forwarding (container mode)
or the host akashic process (host mode) handles the request
transparently.

This dual-mode arrangement was a Phase 7 polish — see chapter 08 for
how it was made to work without override files.

## Where to look for what

When you ask "where in the code does X live?", these are the
addresses:

- **HTTP routing on the auth server** → `pkg/server/auth/routes.go`
- **HTTP routing on the control server** → `pkg/server/control/routes.go`
- **App lifecycle (start/stop, signals, deps wiring)** → `pkg/akashic/core/context.go`
- **Config schema** → `pkg/config/types.go`
- **Logging setup** → `pkg/logging/`
- **OAuth protocol logic** → `pkg/oauth/` and `pkg/server/auth/oauth_*.go`
- **Bootstrap flow** → `pkg/bootstrap/`
- **LDAP integration** → `pkg/ldap/`
- **Database models and migrations** → `pkg/models/`, `pkg/database/akashic_postgres/`
- **The admin BFF** → `pkg/admin_bff/`
- **The CLI** → `pkg/cli/` and `cmd/akashic-cli/`
- **Front-end** → `web/admin/` (React + Vite)

These prefixes will recur throughout the next chapters.

## What you should walk away with

After reading this chapter:

1. You can name the three application services (akashic, admin-bff,
   proxy) and explain what each one is for.
2. You understand why the akashic server has two listeners and why
   they have different security models.
3. You can sketch the path a browser request takes through the system.
4. You know where in the codebase to look for each kind of concern.

If any of those don't feel solid yet, re-read the relevant section.
The next chapter (PKI and TLS) leans heavily on this skeleton, so a
shaky foundation here will hurt later.

## Continue to → [Chapter 01 — PKI and TLS](./01-pki-and-tls.md)
