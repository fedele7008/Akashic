# Chapter 04 — Bootstrap Flow

> **Goal**: by the end of this chapter, you should be able to describe
> exactly what happens between "fresh `docker compose up -d`" and "I
> just signed in as the root user for the first time."

## What "bootstrap" means here

Akashic, fresh out of the box, has zero users in LDAP and zero
records in postgres. Someone has to be the *first* user — and that
first user has to have administrative privileges (to add other
users, configure tenants, etc.). This is the **bootstrap problem**:
how do you authenticate the very first admin, when the authentication
system is what they're trying to set up?

The answer Akashic uses: **a one-time bootstrap token** printed to
the server's stderr at startup. Anyone who can read the server logs
(i.e., the operator) can use that token to create the first user.

## States the system can be in

```
┌─────────────────────┐
│ "Bootstrap mode"    │  ← initial state on a fresh install
│ — no root user yet  │
│ — token is valid    │
└─────────┬───────────┘
          │
          │ operator submits token + new-user form
          │ via the admin BFF (web) or akashic-cli
          ▼
┌─────────────────────┐
│ "Normal mode"       │  ← persistent state forever after
│ — root user exists  │
│ — bootstrap token   │
│   is invalidated    │
└─────────────────────┘
```

The `bootstrap_status` table in postgres tracks which mode we're in.
A single row, never deleted (so the state is permanent once
bootstrap is done).

## The bootstrap token

When the server starts and notices no root user exists, it generates
a 32-byte random token (base64-encoded, ~43 chars) and stores it in
postgres with a 1-hour TTL. The token is also printed to the server's
stderr in a hard-to-miss banner:

```
=======================================================================
  !! BOOTSTRAP MODE ACTIVE !!
-----------------------------------------------------------------------
  Root user not configured. Please create one.

  Bootstrap Token:
    cc4b83141abee78a8500ecde7cc0ca9d39eb8a69da1914ccf0c28d80c8226cce

  Methods:
  1. Web: Use BFF to submit token + credentials
  2. CLI: akashic-cli bootstrap create-root --help

  Token expires in: 1h0m0s
=======================================================================
```

If the token expires unused, the next request to a bootstrap endpoint
generates a new one (and re-logs it). So there's no risk of "I forgot
to bootstrap within an hour and now I'm locked out" — restart and a
new token is issued.

The token has rate-limited bucketing on its submission endpoints —
the control plane caps create-root attempts at 5 per minute per
client cert, the BFF caps it at 5 per minute per source IP.
Together this makes brute-forcing a 32-byte token a multi-decade
proposition even before the 1h expiry.

## The two paths to bootstrap

### Path A — Web (admin BFF)

This is the user-facing path. It looks like this from the operator's
perspective:

```
1. Operator opens https://admin.<domain>/ in a browser
2. The React FE calls GET /api/bootstrap/status — sees is_complete=false
3. The FE renders the BootstrapForm component
4. Operator pastes the token + types username/email/password + submits
5. The FE calls POST /api/bootstrap/create-root
6. BFF validates input, forwards over mTLS to akashic control plane
7. Akashic validates the token, creates user in BOTH LDAP and postgres
8. Bootstrap row marked is_complete=true; token deleted
9. The FE refreshes; status now is_complete=true → renders the
   "sign in" landing page (or the dashboard if already logged in)
```

Every step here is wired up. The relevant files:

- **FE**: `web/admin/src/components/BootstrapForm.tsx`
- **BFF**: `pkg/admin_bff/handlers.go`'s `handleBootstrapCreateRoot`
- **BFF↔akashic mTLS**: `pkg/admin_bff/client.go`'s `BootstrapCreateRoot`
- **Akashic handler**: `pkg/server/control/handlers.go` (route
  `POST /bootstrap/root`)
- **Bootstrap manager**: `pkg/bootstrap/manager.go`'s `CreateRootUser`
- **User repository (creates LDAP + Postgres atomically)**:
  `pkg/repository/user_repository.go`'s `CreateUser`

### Path B — CLI

For headless deployments or if the BFF isn't running:

```
akashic-cli bootstrap create-root \
  --token cc4b83... \
  --username admin \
  --email admin@example.com \
  --password 'SecurePass!23'
```

Same control-plane endpoint, same logic, just a different client. The
CLI uses an mTLS client cert from `./certs/akashic-cli/` rather than
the BFF's cert.

## What happens during user creation

The user-create operation is a **two-step atomic process**:

```
Step 1: Create the user in LDAP
  POST: a new inetOrgPerson entry to ou=users,dc=akashic,dc=local
  Sets uid, cn, sn, mail, userPassword (LDAP hashes the password
  internally — Akashic never stores the hash)

Step 2: Create the user in Postgres
  INSERT into users (id, ldap_dn, user_type='root', ...)
  The ldap_dn is the foreign-key into LDAP; user_type marks them
  as root

Step 3: Add the user to the akashic-root RBAC group in LDAP
  ldap.AddUserToGroup(userDN, "cn=akashic-root,...")

Step 4: Mark bootstrap_status.is_complete = true
Step 5: Delete the bootstrap token
```

The "atomic" claim is partial: if step 2 fails after step 1
succeeded, the LDAP entry is left dangling. The deprovisioning
service (chapter 02) will eventually mark it as orphaned and clean
it up, but the user briefly exists in LDAP without postgres
metadata. For Phase 7 this is accepted — the failure mode is rare
(both backends working but one transiently flaky), and the cleanup
is automatic.

## The bootstrap manager

`pkg/bootstrap/manager.go` is the orchestrator. It exposes:

- `IsBootstrapped(ctx)` — quick query of `bootstrap_status` table
- `GetOrIssueToken(ctx, ttl)` — returns the current token or issues a
  new one if expired/missing
- `CreateRootUser(ctx, token, req)` — validates the token and runs
  the create-user steps above

The manager owns the *bootstrap state machine*. Other components ask
it questions ("are we bootstrapped?") rather than touching the
postgres rows directly.

## The mTLS layer

Both the BFF and the CLI talk to the **control plane** for bootstrap
operations — never to the auth plane (port 8080). That's because
bootstrap is fundamentally a *management* operation, not an *end-user*
operation, and the control plane is what management operations use.

The mTLS setup:

- Client (BFF / CLI) presents a cert signed by `pki-mtls-akashic-ctrl`
- Control plane (akashic:8081) verifies it against the same CA
- After the TLS handshake, the request runs through the control
  plane's middleware stack
- The mTLS middleware extracts the client cert's CN and attaches it
  to the request context — endpoint handlers can see "this request
  came from `bff.akashic.local`" or `cli.akashic.local`

The `pkg/middleware/mtls.go` middleware has a hardcoded list of
allowed CNs (the "client allowlist"). Even if someone got their hands
on a cert signed by the right CA but with an unrecognized CN, the
middleware would reject it. This is defense-in-depth — the mTLS CA
itself is the primary trust boundary, the CN allowlist is the
secondary.

## What you should walk away with

After this chapter:

1. You can explain what bootstrap mode is and why it exists.
2. You know how the bootstrap token is generated, stored, and
   delivered to the operator.
3. You can name the two paths (web/CLI) for completing bootstrap and
   describe what's different between them.
4. You understand that user creation is a two-step LDAP-then-postgres
   process and what happens if step 2 fails.
5. You know that the bootstrap manager is the single source of truth
   for "are we bootstrapped?"

## Continue to → [Chapter 05 — The Admin BFF](./05-admin-bff.md)
