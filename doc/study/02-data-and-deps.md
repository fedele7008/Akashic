# Chapter 02 — Data and Dependencies

> **Goal**: by the end of this chapter, you should know what each of
> Postgres, Redis, and LDAP is responsible for, why the split exists,
> and how the akashic server connects to each one.

## The three-store split

Akashic has three places where state lives:

| Store | What it holds | Lifecycle |
|---|---|---|
| **LDAP** | Users (canonical: username, email, password hash, group memberships) | Survives forever, source of truth |
| **Postgres** | Akashic-specific user metadata, OAuth client registry, bootstrap state | Survives forever, references LDAP via DN |
| **Redis** | Sessions (auth-server + BFF), OAuth authorization codes, rate-limit counters | Short-lived, OK to lose on restart |

There's a strong design principle here: **LDAP is the ONLY source of
truth for identity**. Postgres holds metadata that LDAP can't
naturally express — "is this user disabled in Akashic specifically?",
"what user_type role do we tag this user with?" — but it never
holds passwords, never holds the canonical username/email. Those
live in LDAP exclusively.

## Why this split?

Three reasons.

**1. Tenant flexibility.** Akashic is intended to plug into existing
LDAP directories (Active Directory, OpenLDAP, FreeIPA, etc.). Tenants
who already have an identity directory don't want Akashic to fork
their user list — they want Akashic to *use* it. The split means
adopting Akashic doesn't require migrating users.

**2. No password storage in postgres.** Passwords live exclusively in
LDAP, where they're hashed by the LDAP server itself (typically SSHA
or SHA-512). Akashic's postgres has no `password` column at all. This
removes an entire class of "we leaked a password DB" risk — Akashic
*literally cannot* leak passwords because it never stores them.

**3. JIT provisioning works cleanly.** A user can exist in LDAP and
not yet in postgres; the first time they authenticate, postgres gets
a corresponding row created with default metadata. This pattern is
called **Just-In-Time provisioning** (chapter 04 covers it in
detail).

## LDAP — the identity source of truth

The LDAP container is OpenLDAP (osixia/openldap image). The base DN
is `dc=akashic,dc=local`. On first startup, the akashic server
creates two organizational units:

- `ou=users,dc=akashic,dc=local` — where user entries live
- `ou=groups,dc=akashic,dc=local` — where role groups live (RBAC)

Plus three RBAC groups:

- `cn=akashic-root,ou=groups,...` — the root user
- `cn=akashic-admins,ou=groups,...` — admin users
- `cn=akashic-users,ou=groups,...` — regular users

This **automatic LDAP structure initialization** is patterned after
GORM's AutoMigrate — the akashic server doesn't expect operators to
hand-build the LDAP schema; it does it on startup if missing. See
`pkg/ldap/client.go`'s `InitializeStructure()`.

### A user entry in LDAP

```ldif
dn: uid=admin,ou=users,dc=akashic,dc=local
objectClass: inetOrgPerson
uid: admin
cn: admin
sn: admin
mail: admin@example.com
userPassword: {SSHA}<hash>
```

The `inetOrgPerson` schema is RFC 2798 — a standard LDAP class
designed for human users in an org directory. Akashic uses standard
attributes: `uid` for username, `mail` for email, `userPassword` for
the hash, `cn`+`sn` for display names.

### Authentication via LDAP bind

When a user logs in, the akashic server doesn't *fetch* the password
hash and compare. It does a standard LDAP bind:

```
1. Search for the user → find their DN
2. Attempt to bind to LDAP as that DN with the supplied password
3. If the bind succeeds, the password was correct
4. Rebind as admin so subsequent operations have the right privileges
```

This is the safe pattern — Akashic never sees plaintext passwords
beyond the brief moment of forwarding them to LDAP, and it never
sees password hashes at all (LDAP does the comparison internally).

There's a subtlety: the LDAP connection is *shared* across goroutines
in `pkg/ldap/client.go`'s `Client`. Bind state is connection-level,
not request-level — so any operation that changes the bound identity
must be serialized to prevent interleaving. This is what
`Client.authMu` (a `sync.Mutex`) guards. Plus a deferred
`rebindAsAdmin` ensures the connection is left in a known-good state
even if the user's bind fails (so the next request's search won't
fail spuriously). See `pkg/ldap/client.go`'s `Authenticate()`.

### LDAP login filter: uid OR mail

A nice UX touch: users can sign in with their **uid** OR their
**email**. The login filter (configurable, default
`(|(uid={login})(mail={login}))`) ORs both attributes, so whichever
identifier the user remembers, they get matched. This is implemented
by `searchLoginDN` (deliberately separate from `searchUserDN` which
stays uid-only — the latter is used for "is this username taken?"
checks where matching emails would cause false-positive collisions).

## Postgres — the metadata store

Postgres holds three categories of data:

### `users` table

```
id              uuid (primary key)
ldap_dn         text (unique — references LDAP)
user_type       enum ('root', 'admin', 'user')
is_disabled     bool
disabled_at     timestamp
disabled_by     uuid
missing_identity        bool (true if LDAP entry vanished)
missing_identity_since  timestamp
created_at      timestamp
updated_at      timestamp
```

Notably absent: `username`, `email`, `password_hash`. Those are
LDAP-only.

### `client_services` table (Phase 7)

The OAuth client registry:

```
client_id            text PK
client_secret_hash   text (bcrypt of the plaintext secret)
name                 text
redirect_uris        text (CSV; exact-match validated)
allowed_scopes       text (space-separated)
auth_types           text (e.g. "authorization_code")
built_in             bool
role_allowlist       text (CSV of allowed user_types)
require_pkce         bool
```

Each row represents a service that can authenticate users via
Akashic. The `akashic-admin` row is special — it's auto-upserted on
every server start so the admin BFF can always log in.

### `bootstrap_status` table

A single row that tracks whether the system has been bootstrapped
(see chapter 04). Not interesting until you read that chapter.

### Migrations

Akashic uses **GORM's AutoMigrate**, not a separate migration tool.
The list of registered models lives in
`pkg/database/akashic_postgres/postgres.go`'s `RunMigrations()`. On
each startup, GORM compares the table state to the model and adds
columns/indexes as needed. There's no migration *script* per se;
the Go struct *is* the schema.

This works for greenfield projects but has a known limitation: GORM
won't drop columns you removed from a struct. If you remove a field,
you have to write a manual SQL migration to drop the column. For
Phase 7's complexity this hasn't been an issue yet.

### TLS to postgres

```go
opts := &pgx.ConnConfig{
    ...
    TLSConfig: &tls.Config{
        ServerName: cfg.Host,
        RootCAs:    pool,    // built from /certs/postgres/ca.crt
    },
}
```

The TLS posture is `verify-full` by default — postgres' cert SAN
must match the dial hostname (`postgres.akashic.local` inside docker,
`localhost` host-run). This is the strictest TLS verification level.

## Redis — short-lived state

Redis holds three kinds of keys, partitioned by prefix:

| Prefix | What it holds | TTL |
|---|---|---|
| `akashic:auth:session:<sid>` | Auth-server (IdP) sessions | 8h absolute / 30m idle |
| `akashic:bff:admin:session:<sid>` | Admin BFF browser sessions | 8h / 30m |
| `akashic:oauth:code:<code>` | Single-use OAuth authorization codes | 60s |

Plus rate-limit counters that the akashic-server's middleware uses.

### Why two session namespaces?

Because the auth-server and the BFF are *different services* with
*different cookies* on *different origins*. The auth-server's session
(`akashic_auth_session` cookie on `auth.<domain>`) lives long enough
to support SSO across multiple OAuth clients. The BFF's session
(`akashic_admin_session` cookie on `admin.<domain>`) is the
browser→BFF binding for the admin SPA. Same Redis instance, two
separate keyspaces, two separate cookies.

Different DBs too: the akashic server uses Redis DB 0, the admin-bff
uses DB 1. This is purely organizational — both are full Redis logical
databases inside the same physical instance. Set via `redis.db` (=0)
and `AKASHIC_BFF_REDIS_DB` (=1).

### TLS to Redis

Same `verify-full` posture as postgres. Both server (Redis) and
clients (akashic, admin-bff) load `/certs/redis/ca.crt` to verify the
server cert. Certs auto-rotate via vault-agent.

### Atomic-consume for auth codes

OAuth authorization codes are **single-use**. The /token endpoint
must atomically read and delete the code so two concurrent /token
requests for the same code can't both succeed (a "token theft via
race condition" attack).

Redis Lua script for the GET+DEL:

```lua
local v = redis.call('GET', KEYS[1])
if v then
    redis.call('DEL', KEYS[1])
end
return v
```

`pkg/oauth/codes.go`'s `Consume()` runs this via `EVAL`. Because Lua
scripts run atomically in Redis, no race window exists. See chapter
06 for the full /token flow.

## How the akashic server wires up to all three

`pkg/akashic/core/context.go`'s `Init()` is the wiring code. In
order:

1. Load config + initialize logger
2. **Connect to Postgres**, run migrations
3. **Connect to Redis**, ping
4. **Connect to LDAP**, bind as admin, test connection
5. Initialize LDAP directory structure (idempotent OU + RBAC group
   creation)
6. Initialize the OAuth keystore (chapter 06)
7. Set up bootstrap state from postgres
8. Ensure built-in OAuth clients (akashic-admin) are upserted
9. Start the deprovisioning service (background goroutine)
10. Start the control listener (port 8081)
11. Auto-start the auth listener (port 8080)

If any of steps 2–4 fail, the server **refuses to start**. This is
deliberate — running Akashic with a broken backend would either
silently lose data (postgres down → users created during outage
vanish) or behave inconsistently (LDAP down → can't authenticate
anyone). Failing fast is the safer mode.

## Deprovisioning: the LDAP↔Postgres reconciliation loop

A background goroutine runs every hour (`sync_interval` config) and
asks: for each user in postgres, does their `ldap_dn` still exist in
LDAP? If not, postgres marks the row `missing_identity = true` with a
timestamp. After a configurable grace period (default 90 days for
regular users, 30 days for admins, immediately for root), the
postgres row is deleted entirely.

The corollary: if a user reappears in LDAP after being marked
missing, the next reconciliation clears the missing flag. Useful for
"oops, I deleted that user, but actually they should be back."

See `pkg/ldap/deprovisioning.go`.

## What you should walk away with

After this chapter:

1. You can explain why LDAP is the source of truth for identity and
   why postgres doesn't have a password column.
2. You know what the three Redis keyspaces are for and which TTLs
   apply.
3. You understand JIT provisioning at a conceptual level (deferred
   to chapter 04 for the full flow).
4. You know that GORM AutoMigrate handles schema changes — and its
   limitation around dropped columns.
5. You understand why concurrent access to the LDAP connection
   requires a mutex.

## Continue to → [Chapter 03 — The Akashic Server](./03-akashic-server.md)
