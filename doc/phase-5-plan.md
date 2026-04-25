# Phase 5: Completing the Bootstrap Process

## Context

Phase 4 brought up a fully TLS-secured Akashic stack running either from the host
or inside Docker. When the server starts with no root user in PostgreSQL **and**
no corresponding LDAP entry, it enters **bootstrap mode**: a short-lived state
in which exactly one action is permitted — creating the very first root user.
Everything else on the control plane is gated behind `requireBootstrapMode`.

The server-side bootstrap machinery already exists (Phase 3 / early Phase 4):

- `pkg/bootstrap/manager.go` — the 10-step `CreateRootUser` flow
- `pkg/bootstrap/token.go` — secure token generation + Redis-backed TTL storage
- `pkg/server/control/bootstrap_handlers.go` — four HTTP endpoints, plus the
  `requireBootstrapMode` and `requireCLI` middlewares
- `pkg/models/user.go` — `UserType` enum (`root` / `admin` / `user`)
- Wired into `pkg/akashic/core/context.go`: startup generates a token and prints
  it to stdout when bootstrap is needed

What's missing is the **client side** — there is no way for an operator to
actually consume the bootstrap token and submit a root-user creation request
without hand-crafting `curl --cert --key ...` commands. The akashic-cli binary
exists but only has `pki` subcommands; no `bootstrap` family, no `configure`
subcommand, no notion of a persistent profile.

**Goal of Phase 5**: make the bootstrap flow end-to-end usable via akashic-cli,
introduce a persistent CLI profile so operators aren't typing `--cert`/`--key`
for every call, and harden the server-side bootstrap against the soft spots
documented below. Phase 5 ends at the CLI being able to complete a full
bootstrap in one command against a fresh Akashic deployment. A web-based BFF
flow is deliberately out of scope (abstract notes at the end for future work).

---

## Recap: How Bootstrap Works Today

For future reference — so no one has to re-derive the design by reading six
files. This is the definition-of-truth section.

### The invariant

> There must be exactly **one** pathway to create the first root user, and
> that pathway must only be available when no root user exists.

Why: the first root user is a trust-anchor installation. Whoever creates them
controls the system forever. That action cannot be discoverable to a random
attacker who happens to hit the control plane — but it also cannot require
out-of-band physical access to every Akashic deployment, or operations doesn't
scale. The bootstrap pattern threads that needle with three security layers:

1. **A one-time, short-lived, random token** (32 bytes, hex-encoded) generated
   in Redis with a TTL (default 1 h).
2. **A state flag** in PostgreSQL (`bootstrap_status.is_complete`) that, once
   flipped, permanently closes all bootstrap endpoints.
3. **mTLS on the control plane** (Phase 4) — the endpoints aren't reachable at
   all without a client cert signed by `pki-mtls-akashic-ctrl`.

All three must fail simultaneously for an attacker to hijack the bootstrap
window: they'd need to (a) guess or steal the token, (b) arrive before a
legitimate operator, AND (c) already hold a valid mTLS client cert. That's a
meaningful defense-in-depth composition.

### The state machine

```
                  ┌────────────────────────────┐
                  │   Akashic server starts    │
                  └────────────┬───────────────┘
                               │
                 NeedsBootstrap() reads
                 bootstrap_status row from PG
                               │
             ┌─────────────────┴─────────────────┐
             │                                   │
  is_complete=false                       is_complete=true
             │                                   │
  ┌──────────▼───────────┐          ┌────────────▼────────────┐
  │  BOOTSTRAP MODE      │          │  NORMAL MODE            │
  │  - Generate token    │          │  - Bootstrap endpoints  │
  │    (Redis, TTL=1h)   │          │    return 403           │
  │  - Print token to    │          │  - No token in Redis    │
  │    stdout + log      │          │  - All normal control   │
  │  - Accept requests   │          │    plane endpoints work │
  │    at /bootstrap/*   │          └─────────────────────────┘
  └──────────┬───────────┘
             │
   POST /bootstrap/root with
   valid token + credentials
             │
   CreateRootUser (10 steps below)
             │
   Mark is_complete=true
   Delete token from Redis
             │
             ▼
    [transition to NORMAL MODE]
```

State transitions only move one way: bootstrap → normal. The only way back is
`bootstrap_repository.Reset()`, which is gated to be called from exactly one
place: the deprovisioning service, when it detects that the *current* root user
has been deleted from LDAP. This is the "lost root" recovery path — when an
attacker or admin deletes root from LDAP, the system returns to bootstrap mode
so the operators can legitimately reinstall a new root. Any other caller of
`Reset()` must be considered a bug.

### The 10-step `CreateRootUser` flow

From `pkg/bootstrap/manager.go:83`:

```
Step 1  Validate bootstrap token (Redis GET + constant-time compare)
Step 2  Re-check NeedsBootstrap() to prevent race on double-submit
Step 3  Validate username format (auth.ValidateUsername)
Step 4  Validate email format (auth.ValidateEmail)
Step 5  Validate password against policy (min length, mixed case, ...)
Step 6  Force UserType = root (override whatever the caller sent)
Step 7  Create user atomically in LDAP + PostgreSQL (userRepo.CreateUser)
Step 8  Assign user to RBAC group (cn=akashic-root,ou=groups,...)
Step 9  Mark bootstrap_status.is_complete = true
Step 10 Delete bootstrap token from Redis
```

Steps 1–6 are validation; steps 7–10 are mutation, in an order designed so that
a mid-flow crash leaves the system recoverable (see the audit below).

### HTTP endpoints

All mounted on the control server (port 8081, mTLS required):

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/bootstrap/status` | anyone (mTLS) | Is bootstrap active? |
| GET | `/bootstrap/token` | `requireCLI` + `requireBootstrapMode` | Fetch the current token |
| POST | `/bootstrap/token/regenerate` | `requireCLI` + `requireBootstrapMode` | Rotate the token |
| POST | `/bootstrap/root` | `requireBootstrapMode` | Submit root-user request |

`requireCLI` currently checks the `User-Agent` header for `akashic-cli/`, which
is trivially spoofable — **see hardening in Step 1.1 below**.

### Why Redis for the token, not PG?

Three reasons. First, TTL is native to Redis (`SET ... EX`) and doesn't require
a background sweeper. Second, token lookups are high-frequency and short-lived
— exactly Redis's workload. Third, tokens are deliberately not audit-logged in
durable storage: a failed bootstrap attempt should leave as little forensic
residue as possible (an attacker who later gets PG read access shouldn't
discover historical token values, even expired ones). Redis's volatile nature
aligns with that principle.

---

## Execution Order

```
Step 1: Harden server-side bootstrap   ← close the mTLS-as-CLI gap, add audit
Step 2: Build `akashic-cli configure`  ← profile / cert / endpoint persistence
Step 3: Build `akashic-cli bootstrap`  ← status / token / create-root subcmds
Step 4: End-to-end verification        ← fresh stack → one CLI command → root user
Step 5: (abstract) BFF/web planning    ← scope notes for future phase
```

Steps 1 and 2 are independent and can land in either order. Step 3 depends on
both 2 (profile machinery) and 1 (hardened server). Step 4 is the gate.

---

## Step 1: Harden Server-Side Bootstrap

The existing manager is functional but has three soft spots that become visible
once a real CLI starts exercising it. Fixing them now is cheaper than after
step 3 is in production use.

### 1.1 Replace `requireCLI` User-Agent check with mTLS client-cert identity check

**File**: `pkg/server/control/bootstrap_handlers.go` (lines 43–57)

The current middleware trusts a header any HTTP client can set. Phase 4 already
gave us a stronger signal: every request to port 8081 carries a verified mTLS
client certificate. The Subject CN of that cert is exactly the identity we
want: `cli.akashic.local` (issued to akashic-cli) or `bff.akashic.local`
(issued to the future BFF). These CNs match `pki-mtls-akashic-ctrl/issue/client`
configs from Phase 4.

Implementation:

```go
func requireClientIdentity(allowedCNs ...string) func(http.HandlerFunc) http.HandlerFunc {
    allowed := make(map[string]bool, len(allowedCNs))
    for _, cn := range allowedCNs { allowed[cn] = true }
    return func(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
            if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
                response.WriteJSON(w, 403, response.Fail("MTLS_REQUIRED",
                    "client certificate required", nil))
                return
            }
            cn := r.TLS.PeerCertificates[0].Subject.CommonName
            if !allowed[cn] {
                response.WriteJSON(w, 403, response.Fail("CLIENT_NOT_ALLOWED",
                    "this endpoint not authorized for client CN", map[string]any{"cn": cn}))
                return
            }
            next(w, r)
        }
    }
}
```

Apply to token endpoints:

```go
mux.HandleFunc("/bootstrap/token",
    requireClientIdentity("cli.akashic.local")(s.requireBootstrapMode(s.handleGetBootstrapToken)))
mux.HandleFunc("/bootstrap/token/regenerate",
    requireClientIdentity("cli.akashic.local")(s.requireBootstrapMode(s.handleRegenerateToken)))
```

Leave `/bootstrap/root` accessible to both CLI and BFF client CNs (once the BFF
exists). For Phase 5 scope, only `cli.akashic.local` is allowed.

### 1.2 Rate-limit bootstrap token attempts

Currently `POST /bootstrap/root` accepts unlimited submissions. A token is
32 bytes (2^256 keyspace), so brute-force is infeasible in the TTL window, but:

- A distributed scanner could still pepper the endpoint with nonsense, filling
  logs and obscuring real attacks.
- If we ever shorten the token for UX, the brute-force floor drops.

Add a middleware that allows at most **5 POST attempts per minute per client
CN** on `/bootstrap/root`. On the 6th attempt: 429 + security-channel log.

**File**: `pkg/middleware/bootstrap_ratelimit.go` (new)

Reuse the existing rate-limit infrastructure in `pkg/middleware/rate_limit.go`
but with a narrower key function that uses `cn` instead of IP (more accurate
when clients share an IP, e.g. behind a corporate NAT).

### 1.3 Tighten `RegenerateToken` semantics

Currently `POST /bootstrap/token/regenerate` replaces the existing token
silently. That's fine for the "operator lost the original" case, but it also
means an attacker who *gets* the control-plane briefly and then loses it can
rotate the token out from under a legitimate operator.

Add an audit log line at **security** level on every regeneration, and consider
making the endpoint require an additional confirmation parameter:
`?force=true`. Without it, returns 409 if a valid token already exists.

**File**: `pkg/bootstrap/manager.go` — extend `RegenerateToken` to accept a
`force bool` flag; error if `!force && tokenMgr.Exists(ctx)`.

### 1.4 Add a `bootstrap_status` audit row

The current `bootstrap_status` table has `id, is_complete, created_at,
completed_at, root_user_id`. That's enough for the state machine but not enough
for an incident review.

Add:

- `completion_source TEXT` — "cli" / "bff" / "api" based on the client CN
- `completion_ip INET` — source IP at completion time
- `attempts_before_success INT` — how many POST attempts preceded success

These columns become forensic breadcrumbs if a bootstrap goes wrong.
**File**: `pkg/models/bootstrap_status.go` + GORM migration.

### 1.5 Verify

```bash
./scripts/reset-vault.sh
docker compose --profile app up -d akashic

# Status endpoint: reachable with any valid mTLS cert
curl --cacert ./certs/akashic/mtls-ca.crt \
     --cert   ./certs/akashic-cli/akashic-ctrl-client.crt \
     --key    ./certs/akashic-cli/akashic-ctrl-client.key \
     https://localhost:8081/bootstrap/status
# → {"success": true, "data": {"is_complete": false, ...}}

# Token endpoint: only reachable with cli.akashic.local CN
curl --cacert ./certs/akashic/mtls-ca.crt \
     --cert   ./certs/bff/akashic-ctrl-client.crt \
     --key    ./certs/bff/akashic-ctrl-client.key \
     https://localhost:8081/bootstrap/token
# → 403 CLIENT_NOT_ALLOWED (cn=bff.akashic.local)

# Rate limiting kicks in after 5 failures
for i in {1..6}; do
  curl ... -X POST https://localhost:8081/bootstrap/root \
       -d '{"token":"wrong","username":"x","email":"x@y","password":"x"}'
done
# Calls 1-5: 400 INVALID_TOKEN. Call 6: 429 RATE_LIMITED.
```

---

## Step 2: Build `akashic-cli configure`

This is the foundation for every future CLI interaction. Without persistent
config, every call needs `--control-url --cacert --cert --key` — eight tokens
of typing per command, with predictable copy-paste bugs.

### 2.1 Design: the `~/.akashic/` layout

```
~/.akashic/
├── config.yaml           # per-profile settings, pointer to active profile
└── certs/
    ├── default/
    │   ├── ca.crt        # pki-mtls-akashic-ctrl CA chain (trust root)
    │   ├── client.crt    # the mTLS client cert (CN=cli.akashic.local)
    │   └── client.key    # private key (chmod 0600)
    ├── staging/
    │   ├── ca.crt
    │   ├── ...
    └── prod/
        └── ...
```

**`~/.akashic/config.yaml`** format:

```yaml
# Name of the profile used when --profile is not specified on the command line
active_profile: default

profiles:
  default:
    control_url: https://127.0.0.1:8081
    ca_cert:     ~/.akashic/certs/default/ca.crt
    client_cert: ~/.akashic/certs/default/client.crt
    client_key:  ~/.akashic/certs/default/client.key

  staging:
    control_url: https://akashic-staging.internal:8081
    ca_cert:     ~/.akashic/certs/staging/ca.crt
    client_cert: ~/.akashic/certs/staging/client.crt
    client_key:  ~/.akashic/certs/staging/client.key

  prod:
    control_url: https://akashic.example.com:8081
    ca_cert:     ~/.akashic/certs/prod/ca.crt
    client_cert: ~/.akashic/certs/prod/client.crt
    client_key:  ~/.akashic/certs/prod/client.key
```

**Permissions**: `~/.akashic/` is `0700`, `~/.akashic/certs/*/client.key` is
`0600`. These are enforced on every CLI invocation — if the permissions have
drifted (e.g. a careless `chmod -R`), the CLI refuses to read the profile.
This is the same pattern OpenSSH uses for `~/.ssh/id_rsa`.

### 2.2 Subcommand surface

```
akashic-cli configure add        --name <name> --control-url <url> \
                                 --ca-cert <path> --client-cert <path> --client-key <path>
akashic-cli configure list
akashic-cli configure show       [--profile <name>]
akashic-cli configure use        <name>
akashic-cli configure remove     <name>
akashic-cli configure set-active <name>   # alias for `use`
```

`add` copies the cert files into `~/.akashic/certs/<name>/` and rewrites their
paths in `config.yaml`. The rationale for copying: operators provision the
certs somewhere (maybe Vault-Agent wrote them to `./certs/akashic-cli/` in the
project tree), then forget. Six months later the project directory is moved
and the CLI mysteriously stops working. Copying to `~/.akashic/certs/` pins a
stable location that survives project-tree changes.

Alternative: `add` accepts `--link` to symlink instead of copy, for operators
who *want* the CLI to track the source-of-truth path. Default is copy.

`show` prints the profile minus the private key (obviously). `--verbose` shows
cert Subject / Issuer / NotAfter, decoded from the on-disk files, so operators
can audit at a glance: "is this cert expired?" / "is this the right CA?".

### 2.3 Implementation

**New files**:

- `pkg/cli/cmd/root_configure.go` — parent `configure` command
- `pkg/cli/cmd/root_configure_add.go`
- `pkg/cli/cmd/root_configure_list.go`
- `pkg/cli/cmd/root_configure_show.go`
- `pkg/cli/cmd/root_configure_use.go`
- `pkg/cli/cmd/root_configure_remove.go`
- `pkg/cli/core/profile.go` — profile model + load/save helpers
- `pkg/cli/core/fs.go` — `ensureDir(path, mode)`, `verifyPerms(path, want)`,
  `expandHome(path)`, `copyFileSecure(src, dst, mode)`

### 2.4 Profile-aware HTTP client

**File**: `pkg/cli/core/client.go` (extend existing)

Adds `NewAkashicControlClient(profileName string) (*http.Client, string, error)`
which returns `(client, controlURL, err)`. The client is pre-configured with:

- `Transport.TLSClientConfig.RootCAs` ← parsed from profile's `ca_cert`
- `Transport.TLSClientConfig.Certificates` ← `tls.LoadX509KeyPair(cert, key)`
- `Timeout: 10 * time.Second`

If `profileName == ""`, reads `active_profile` from `config.yaml`.

Every existing CLI subcommand that currently hits Vault can later be migrated
to use this same pattern for control-plane calls. Phase 5 only uses it from
the new bootstrap commands; deeper migration is out of scope.

### 2.5 Configuration flag precedence

When a user types a command, the flag/env/config precedence should be:

1. **Explicit flag** (`--control-url https://...`) — always wins
2. **Env var** (`AKASHIC_CLI_CONTROL_URL=...`) — overrides profile
3. **--profile <name>** — selects a named profile from `config.yaml`
4. **Active profile** (default) — `config.yaml`'s `active_profile`
5. **Hardcoded defaults** — only for documented fallbacks

The cascade is implemented in `pkg/cli/core/profile.go:ResolveSettings()`.

### 2.6 Verify

```bash
# First-time setup
akashic-cli configure add \
    --name default \
    --control-url https://127.0.0.1:8081 \
    --ca-cert ./certs/akashic/mtls-ca.crt \
    --client-cert ./certs/akashic-cli/akashic-ctrl-client.crt \
    --client-key ./certs/akashic-cli/akashic-ctrl-client.key

ls -la ~/.akashic/
# drwx------   config.yaml
# drwx------   certs/
#   drwx------ default/
#     -rw-r--r-- ca.crt
#     -rw-r--r-- client.crt
#     -rw------- client.key

akashic-cli configure list
# PROFILES
#   default (active)  →  https://127.0.0.1:8081

akashic-cli configure show
# control_url: https://127.0.0.1:8081
# ca_cert:     ~/.akashic/certs/default/ca.crt
# client_cert: ~/.akashic/certs/default/client.crt (CN=cli.akashic.local, expires 2026-05-23)
# client_key:  ~/.akashic/certs/default/client.key (mode 0600 ✓)

# Permission drift is caught
chmod 0644 ~/.akashic/certs/default/client.key
akashic-cli configure show
# ERROR: client.key has permissions 0644 (expected 0600). Run `chmod 0600 <path>`.
```

---

## Step 3: Build `akashic-cli bootstrap`

Now that the CLI has identity (Step 2) and the server trusts that identity
(Step 1), the bootstrap commands are thin wrappers around existing HTTP
endpoints.

### 3.1 Subcommand surface

```
akashic-cli bootstrap status
    # GET /bootstrap/status

akashic-cli bootstrap token [--regenerate [--force]]
    # GET /bootstrap/token    (default)
    # POST /bootstrap/token/regenerate  (with --regenerate)
    # The --force flag is passed through to override the "token already exists"
    # guard we added in Step 1.3.

akashic-cli bootstrap create-root
    --username <username>
    --email <email>
    [--password <password>]     # if omitted, prompt interactively
    [--token <token>]           # if omitted, fetch via `bootstrap token`
    # POST /bootstrap/root
```

Prompting behavior:

- `--password` omitted → interactive prompt with `golang.org/x/term.ReadPassword`
  (no echo), followed by a confirmation prompt. Passwords never appear in
  shell history, `ps`, or logs.
- `--token` omitted → CLI first does `GET /bootstrap/token`, fetches the
  current token, uses it. This is the ergonomically important case: operator
  only needs to type username/email/password.

### 3.2 One-command bootstrap flow

With the above, the entire "first-time setup" fits in **two commands**:

```bash
akashic-cli configure add --name default \
    --control-url https://127.0.0.1:8081 \
    --ca-cert ./certs/akashic/mtls-ca.crt \
    --client-cert ./certs/akashic-cli/akashic-ctrl-client.crt \
    --client-key ./certs/akashic-cli/akashic-ctrl-client.key

akashic-cli bootstrap create-root --username admin --email admin@example.com
```

The second command auto-fetches the token, prompts for password twice, submits
the create-root request, and prints the created user summary. No `curl`,
no copy-pasting tokens, no visible credentials in shell history.

### 3.3 Implementation

**New files**:

- `pkg/cli/cmd/root_bootstrap.go` — parent command
- `pkg/cli/cmd/root_bootstrap_status.go`
- `pkg/cli/cmd/root_bootstrap_token.go`
- `pkg/cli/cmd/root_bootstrap_create_root.go`
- `pkg/cli/core/prompt.go` — interactive password prompt with confirmation,
  optional `--password-stdin` for scripted use

All use `core.NewAkashicControlClient()` from Step 2.4 — no ad-hoc HTTP code.

### 3.4 Error surface

The server returns structured errors (from Phase 3); map them to exit codes:

| Server error code | CLI behavior | Exit code |
|---|---|---|
| `BOOTSTRAP_COMPLETE` | "Bootstrap already done; nothing to do." | 0 |
| `INVALID_TOKEN` | "Token invalid or expired. Regenerate with `akashic-cli bootstrap token --regenerate`." | 2 |
| `TOKEN_NOT_FOUND` | "No active bootstrap token. Is server in bootstrap mode?" | 2 |
| `PASSWORD_POLICY_VIOLATION` | Print the specific policy rule that failed. | 3 |
| `VALIDATION_FAILED` | Print which field failed. | 3 |
| `RATE_LIMITED` | "Too many attempts; wait N seconds." | 4 |
| `CLIENT_NOT_ALLOWED` | "This profile's client cert isn't authorized. Check `akashic-cli configure show`." | 5 |
| `MTLS_REQUIRED` | "Server requires mTLS. Did you forget `akashic-cli configure`?" | 5 |
| network/timeout | "Couldn't reach <control-url>. Is the server up?" | 6 |

Distinct exit codes matter for operators wiring the CLI into init scripts or
Ansible playbooks: they can branch on failure type without parsing the text
message.

### 3.5 Verify

```bash
# Clean slate
./scripts/reset-vault.sh
docker compose --profile app up -d
# (server prints bootstrap token; we'll let the CLI fetch it)

akashic-cli bootstrap status
# is_complete: false
# token_exists: true
# token_ttl: 59m 42s

akashic-cli bootstrap create-root \
    --username admin \
    --email admin@example.com
Password: ****************
Confirm:  ****************
# ✓ Root user created successfully
#   uid:       7b3e...
#   username:  admin
#   email:     admin@example.com
#   ldap_dn:   uid=admin,ou=users,dc=akashic,dc=local
#   user_type: root

akashic-cli bootstrap status
# is_complete: true
# completed_at: 2026-04-24T15:30:21Z
# root_user_id: 7b3e...
```

---

## Step 4: End-to-End Verification

Drives the entire flow from zero state. This is the gate for Phase 5.

### 4.1 Fresh-deployment smoke test

```bash
./scripts/reset-vault.sh
docker compose --profile app up -d
sleep 30

# Configure the CLI once
akashic-cli configure add \
    --name default \
    --control-url https://127.0.0.1:8081 \
    --ca-cert ./certs/akashic/mtls-ca.crt \
    --client-cert ./certs/akashic-cli/akashic-ctrl-client.crt \
    --client-key ./certs/akashic-cli/akashic-ctrl-client.key

# Bootstrap with one command
echo 'MyStrongP@ss!' | akashic-cli bootstrap create-root \
    --username admin \
    --email admin@example.com \
    --password-stdin

# Confirm transition to normal mode
akashic-cli bootstrap status
# is_complete: true

# Confirm the bootstrap endpoints are now closed
curl --cacert ... --cert ... --key ... \
     -X POST https://127.0.0.1:8081/bootstrap/root \
     -d '{"token":"whatever","username":"x","email":"x@y.z","password":"x"}'
# 403 BOOTSTRAP_COMPLETE
```

### 4.2 Failure-mode sanity checks

Each of these should produce a clear error, not hang or crash:

- Bootstrap with wrong password complexity → `PASSWORD_POLICY_VIOLATION`, exit 3
- Bootstrap with already-complete status → `BOOTSTRAP_COMPLETE`, exit 0
- Bootstrap with expired token → `INVALID_TOKEN`, exit 2
- CLI with corrupted `~/.akashic/config.yaml` → actionable "malformed config" error
- CLI with `client.key` at mode 0644 → "insecure permissions" error, exit 5
- CLI with no `--profile` and no `active_profile` → "run `akashic-cli configure add`" error, exit 5
- Server in normal mode but operator tries `bootstrap token --regenerate` → `BOOTSTRAP_COMPLETE`, exit 0

### 4.3 Recovery path

Simulate the "lost root" case: delete the root user from LDAP, wait for
deprovisioning, verify the system re-enters bootstrap mode, then re-bootstrap.

```bash
# Delete root from LDAP
docker exec akashic-ldap ldapdelete -x -D "cn=admin,dc=akashic,dc=local" \
    -w "$AKASHIC_LDAP_ADMIN_PASSWORD" \
    "uid=admin,ou=users,dc=akashic,dc=local"

# Trigger reconciliation (or wait up to sync_interval)
docker compose restart akashic

# Verify we're back in bootstrap mode
akashic-cli bootstrap status
# is_complete: false (reset by deprovisioning)

# Re-bootstrap
akashic-cli bootstrap create-root --username admin2 --email admin2@example.com
```

---

## Step 5: Web Surfaces — Three-Surface Architecture, Implementation Deferred to Phase 6+

Phase 5 scopes out the admin-FE *implementation*, but the **architecture** is
nailed down in this section so Phase 6 has a clear blueprint.

### 5.1 The three-surface model

Akashic exposes three distinct HTTPS surfaces, each for a different audience
with a different threat profile:

```
╔════════════════════════════════════════════════════════════════════════════╗
║  SURFACE 1 — admin.akashic.<domain>                                        ║
║                                                                            ║
║  Audience: Akashic operator (the SERVICE PROVIDER who installed Akashic).  ║
║  Purpose:  Deep configuration of the Akashic deployment itself: TLS modes,║
║            LDAP wiring, deprovisioning thresholds, Vault control, log      ║
║            sinks, etc. Talks to the CONTROL PLANE.                         ║
║                                                                            ║
║  Admin Browser ──HTTPS(public CA)──▶ nginx-proxy                           ║
║                                         │ plain HTTP (docker net)          ║
║                                         ▼                                  ║
║                                    admin-bff (Go)                          ║
║                                         │ HTTPS + mTLS                     ║
║                                         │ (pki-mtls-akashic-ctrl)          ║
║                                         ▼                                  ║
║                                    control-server :8081                    ║
║                                     (loopback-bound, never publicly routed)║
║                                                                            ║
║  Direct alternative: Operator CLI ──HTTPS+mTLS──▶ 127.0.0.1:8081           ║
║  Protocol: internal JSON APIs                                              ║
║  Auth:     OAuth login (logged-in admin role) + BFF holds mTLS client cert ║
║  Who:      handful of operators per deployment                             ║
╚════════════════════════════════════════════════════════════════════════════╝

╔════════════════════════════════════════════════════════════════════════════╗
║  SURFACE 2 — auth.akashic.<domain>                                         ║
║                                                                            ║
║  Audience: OAuth callers — browsers, mobile apps, customer apps, akashic   ║
║            itself (for admin login).                                       ║
║  Purpose:  Standard OAuth 2.1 / OIDC endpoints: /authorize, /token,        ║
║            /userinfo, /jwks.json, /.well-known/openid-configuration.       ║
║            Talks to the AUTH PLANE.                                        ║
║                                                                            ║
║  Browser ──HTTPS(public CA)──▶ nginx-proxy ──plain HTTP──▶ auth-server     ║
║    or                                                        :8080         ║
║  Mobile app                                                                ║
║    or                                                                      ║
║  CLI (device flow)                                                         ║
║    or                                                                      ║
║  Tenant's own BFF (customer-side, not Akashic's concern)                   ║
║                                                                            ║
║  Protocol: OAuth 2.1 / OIDC (RFC-standard flows)                           ║
║  Auth:     None at transport layer (TLS only, no client certs)             ║
║  Who:      anyone with the URL — public by design                          ║
╚════════════════════════════════════════════════════════════════════════════╝

╔════════════════════════════════════════════════════════════════════════════╗
║  SURFACE 3 — akashic.<domain> (root)                                       ║
║                                                                            ║
║  Audience: Tenants / customers — companies using Akashic as their IdP.     ║
║  Purpose:  Day-to-day OAuth IdP management for one's own tenant: register  ║
║            OAuth clients, set redirect URIs, manage scopes, view consent   ║
║            records, see one's own users. Talks to the AUTH PLANE's data    ║
║            APIs.                                                           ║
║                                                                            ║
║  Tenant Browser ──HTTPS(public CA)──▶ nginx-proxy                          ║
║                                          │ plain HTTP (docker net)         ║
║                                          ▼                                 ║
║                                    tenant-bff (Next.js)                    ║
║                                          │ HTTPS (regular)                 ║
║                                          ▼                                 ║
║                                    auth-server data API :8080              ║
║                                                                            ║
║  Protocol: tenant-management JSON APIs (NOT OAuth itself)                  ║
║  Auth:     OAuth login (tenant-admin role) + BFF holds tenant session      ║
║  Who:      tenant admins, scoped to their own data                         ║
╚════════════════════════════════════════════════════════════════════════════╝
```

**Critical invariants** that hold across this architecture:

1. **The control plane never gets a public subdomain.** Only `admin-bff` and
   `akashic-cli` ever hold mTLS client certs to it. If `ctrl.akashic.<domain>`
   ever becomes a thing, something is wrong.
2. **The auth plane never gets wrapped in a BFF.** Wrapping it would break the
   OAuth contract with integrators (browsers, customer BFFs, mobile apps) who
   expect to hit standard endpoints.
3. **Browsers never hold tokens.** Both BFFs (admin and tenant) keep tokens
   server-side; browsers receive opaque session cookies and nothing else.

### 5.2 Audience separation matters

The three audiences have very different threat profiles, and treating them as
one would force the security model to the lowest common denominator:

| Audience | Count per deployment | Risk if compromised | Privilege scope |
|---|---|---|---|
| **Operator** (admin.) | 1–5 | Full system — TLS off, LDAP repointed, etc. | Everything |
| **OAuth caller** (auth.) | thousands+ | Limited to one tenant's session | Per-token |
| **Tenant admin** (root) | tens–hundreds | Limited to one tenant's clients/scopes | Per-tenant |

The operator surface (`admin.`) is the smallest by population and the largest
by privilege. Hardening it aggressively (mTLS, deep-config-only access, no
public discovery) is cheap because there's no "user growth" pressure on the
operator population.

The tenant surface (root) is the largest and grows with adoption. Its security
model has to accept that surface area scales: standard web-app hardening,
per-tenant data isolation enforced at the API layer, no privileged operations.

### 5.3 BFF stack choices (per surface)

| Surface | BFF technology | Rationale |
|---|---|---|
| `admin.akashic.<domain>` | **React (FE) + Go BFF** | Security-sensitive: holds mTLS client cert, drives control plane. Go BFF reuses `pkg/pki` cert reloader, `pkg/models`, `pkg/logging`, and the Phase 4 audit-log format unchanged. React FE is just static assets (`vite build → dist/` served by Go's `http.FileServer`). |
| `auth.akashic.<domain>` | **No BFF** — `auth-server` serves directly | Pure OAuth/OIDC endpoints. Browser-friendly by design (no client certs, no session intermediary). nginx-proxy terminates public TLS, forwards to auth-server. |
| `akashic.<domain>` (root) | **Next.js (TypeScript) fe+be** | Normal web-app stakes — no privileged plumbing. Next.js's full-stack model fits well: Server Components keep tokens server-side; file-based routing matches admin-UI patterns; large React talent pool for tenant-facing UI work. |

#### Why React + Go BFF for admin (and not Next.js):

- The admin BFF holds the only mTLS client cert authorized to talk to the
  control plane. A compromise of the admin BFF means a compromise of the
  whole Akashic deployment. Keeping its security-critical code (cert
  rotation, mTLS handshake, audit log emission) in the same language as the
  rest of Akashic means **one audit surface** instead of two.
- `pkg/pki/cert_reloader.go` and `pkg/pki/cert_watcher.go` from Phase 4 are
  directly reusable. Reimplementing them in TypeScript is ~80–120 lines of
  cert + fsnotify orchestration that we'd then own.
- `pkg/models` (User, BootstrapStatus, RBAC roles) is the source of truth
  for data shapes. Go BFF imports them; TS BFF would need codegen
  (`tygo`/similar) and constant drift maintenance.
- Audit logs from admin BFF land in the same Loki stream, same format, same
  fields as Akashic-server logs. No schema-translation layer.
- React FE is a separate concern: `vite` build, static `dist/` directory,
  served by the Go BFF's `http.FileServer`. FE devs work in React, infra
  devs work in Go BFF, no language tax for either side.

#### Why Next.js for tenant (root) BFF:

- Not security-sensitive in the same way: no privileged certs, no control
  plane access, normal web-app threat model.
- Full-stack TypeScript is a productivity win for tenant-UI iteration —
  forms, tables, modals, dashboards, scope editors, redirect-URI managers,
  consent-history viewers. These are React's strength.
- Server Components handle the "tokens stay server-side" requirement
  cleanly, without needing to bolt on a separate BFF process.
- Larger talent pool for the tenant-facing UI work, which scales with
  customer count.

#### Why no BFF for auth.:

- OAuth/OIDC are protocol-level contracts with downstream integrators.
  Wrapping them in a BFF would break browsers' redirect flows, mobile
  apps' PKCE flows, server-side `client_credentials` flows — i.e., would
  break the entire integration story Akashic exists to provide.
- nginx-proxy gives us public-CA TLS termination at the edge, which is all
  the auth surface needs from a proxy layer. Forwarding to auth-server in
  cleartext over the docker network is fine; that network is private.

### 5.4 Bootstrap path: CLI required, optional web fallback later

The original plan was "CLI-only bootstrap." After review, the security
argument for CLI-only is weaker than initially claimed (the bootstrap token
itself is the identity, not mTLS). The **engineering argument** still favors
CLI-only as the Phase 5/6 default:

- Bootstrap is one-time per deployment; FE state-machine code for it runs
  exactly once and then stays as dead weight forever
- The "bootstrap required" page in the admin FE is trivial (no form, just
  copy-pasteable CLI commands)
- Operators who provision a fresh Akashic already have shell access

But web-based bootstrap **is defensible** if the project later prioritizes
turnkey/self-service UX. We'd add it as a **Phase 6.5 deliverable** — a
single bootstrap page in admin FE that shows when `is_complete=false`,
behind the same token check the CLI uses. Cost: ~200–400 LOC + tests + 1–2
days. Pay it if/when the use case materializes.

**Phase 6 default**: admin-FE shows a "bootstrap required — please use
akashic-cli" page when `is_complete=false`. Zero login state, zero form
handling, just instructions.

### 5.5 The admin FE authenticates via OAuth against Akashic itself

This is the idiomatic pattern for IdPs that ship their own admin UI (Keycloak,
Authentik, etc.), but it's worth naming it explicitly because Akashic is
simultaneously the IdP **and** one of its own registered clients.

**Login flow when an admin opens `https://admin.akashic.<domain>`:**

```
Admin browser
    │ 1. GET /  (no session cookie)
    ▼
admin-bff
    │ 2. no session → redirect to OAuth authorize endpoint
    ▼
https://auth.akashic.<domain>/authorize?client_id=akashic-admin&...
    │ 3. login page prompts admin for credentials
    │ 4. auth-server authenticates against LDAP
    │ 5. auth-server checks user's RBAC group (must be akashic-admins or akashic-root)
    │ 6. auth-server issues code, redirects back
    ▼
https://admin.akashic.<domain>/oauth/callback?code=...
    │ 7. admin-bff exchanges code for access_token + id_token
    │ 8. admin-bff verifies id_token, extracts admin identity
    │ 9. admin-bff sets session cookie, redirects to dashboard
    ▼
Admin dashboard UI (now with a valid session)
```

**Built-in OAuth client registration**: `akashic-admin` is a built-in OAuth
client registered automatically during server startup, not something operators
configure by hand. Its `redirect_uri` comes from config (`admin.akashic.
<domain>/oauth/callback`); its client secret is stored in Vault KV and fetched
by the admin-bff at startup. This client can't exist before bootstrap — so
the very first root user is created via CLI.

The same pattern applies to the **tenant** surface: `akashic-tenant-portal`
is a built-in OAuth client whose admin UI lives at `<domain>` and serves
tenant admins.

### 5.6 Customer-side BFF is NOT Akashic's concern

When a customer (tenant) integrates Akashic into their own service, they may
or may not build their own BFF to mediate OAuth flows. That's entirely their
architectural choice. From Akashic's side:

- The **public auth plane** is callable from anything — browsers (redirect
  flow), mobile apps (PKCE), SPAs (PKCE + their-own-BFF), server-side apps
  (client credentials), CLIs (device flow). All standard OAuth 2.1 / OIDC.
- Akashic publishes a **JWKS endpoint**, a **discovery document**
  (`/.well-known/openid-configuration`), and standard OAuth endpoints. That
  is the integration contract.
- Akashic does NOT ship a customer-BFF SDK or prescribe a customer BFF
  architecture. Tenants decide.

What Akashic DOES ship (Phase 6+):

- **`admin-bff` + admin FE** (React + Go BFF) for service operators
- **`tenant-bff` + tenant FE** (Next.js fe+be) for tenant admins
- **No BFF on auth.** — auth-server serves OAuth endpoints directly behind
  nginx-proxy

These are distinct from each other and from any customer-side BFF.

### 5.7 Required security measures (apply to BOTH BFFs unless noted)

Bake these in from day one — audit findings for any of them are avoidable:

| Measure | Spec |
|---|---|
| Session timeout | admin: 15 min idle / 8 h absolute. tenant: 30 min idle / 24 h absolute |
| Session cookie | `HttpOnly; Secure; SameSite=Strict; Path=/` |
| Session ID entropy | 32 bytes random, stored in Redis with TTL |
| CSRF protection | Double-submit cookie pattern on every POST/PUT/DELETE |
| Re-auth for dangerous actions | Password re-prompt for: user creation, RBAC changes, OAuth client deletion, deployment-config changes (admin only) |
| CSP | `default-src 'self'` baseline; admin BFF tightens further; tenant BFF allows tenant-controlled redirect URIs in `form-action` |
| HSTS | `max-age=31536000; includeSubDomains; preload` on admin and root subdomains |
| Failed-login lockout | 5 failures in 15 min → IP-level lockout for 15 min (BFF layer) |
| Audit log | Every state-changing action writes to security channel: `{ actor_id, actor_dn, surface, action, target, result, ip, user_agent, timestamp }` |
| mTLS cert rotation (admin BFF only) | Reuses `pkg/pki` reloader from Phase 4 |
| Token storage | Server-side only; never in browser localStorage / cookies |
| OAuth state/nonce | Per-login-attempt random values, stored in Redis with 5 min TTL |
| Per-tenant data isolation (tenant BFF only) | Every API call scoped by `tenant_id` from session; never trust client-supplied tenant ID |

### 5.8 Open questions remaining (to resolve before Phase 6 implementation)

1. **`auth.akashic.<domain>` TLS termination location**: at nginx-proxy
   (consistent with admin/root planes) or at auth-server directly. **Leaning
   proxy** — single place to manage public certs.
2. **OAuth client secret storage**: where do `akashic-admin` and
   `akashic-tenant-portal` client secrets live? **Leaning Vault KV**
   (consistent with how we treat other secrets, gets rotation for free).
3. **First-admin-after-root creation**: the very first non-root admin is
   created by the root user post-bootstrap. Web flow (admin FE) or CLI?
   **Leaning admin FE** — uniform path for all admin creations except the
   very first root. CLI stays a fallback.
4. **Public cert source**: `pki-public` (our internal CA), Let's Encrypt, or
   operator-supplied? Likely all three supported via a config switch. Same
   question for both admin and root subdomains.
5. **Tenant onboarding flow**: how does a new tenant get an admin account
   on `<domain>`? Self-signup, operator-invitation, or both? **Leaning
   operator-invitation initially**, self-signup later.
6. **Where does the React admin FE build land?** Embedded in the Go binary
   via `embed.FS` (single static deployable) vs. shipped as a separate
   `dist/` volume mounted at runtime (faster iteration). **Leaning embed**
   for prod, with a dev-mode flag for hot-reload during local work.

These are design items for Phase 6 kickoff, not blockers for Phase 5.

---

## Phase 6+ Preview (for orientation only; implemented separately)

When Phase 5 lands, the follow-on phases are:

### Phase 6 — Admin surface (`admin.akashic.<domain>`)

1. `services/admin-bff/` — Go binary (BFF + static-asset server)
2. `web/admin/` — React app (`vite`-built, embedded via `embed.FS`)
3. OAuth client registration for `akashic-admin` (built-in, not operator-configured)
4. nginx-proxy server block for `admin.akashic.<domain>`
5. End-to-end admin login flow + dashboard
6. "Bootstrap required" page when `is_complete=false`
7. mTLS cert rotation in admin BFF using `pkg/pki`

### Phase 7 — Tenant surface (`akashic.<domain>`)

1. `services/tenant-bff/` — Next.js application (TypeScript fe+be)
2. OAuth client registration for `akashic-tenant-portal`
3. nginx-proxy server block for `akashic.<domain>` (root)
4. Tenant login + dashboard + OAuth client CRUD UI
5. Tenant data isolation enforcement at the API layer

### Phase 8 — Auth surface enhancements (`auth.akashic.<domain>`)

1. Default login pages (HTML rendered by auth-server) for tenants who
   don't want to build their own login UI
2. Discovery document + JWKS endpoint hardening
3. Public cert source switch (pki-public / Let's Encrypt / BYO)

None of this is in Phase 5. Phase 5 ends at CLI bootstrap working.

---

## Files Summary

### New files (Phase 5 proper)

| File | Purpose |
|---|---|
| `pkg/middleware/bootstrap_ratelimit.go` | Per-CN rate limit for /bootstrap/root |
| `pkg/cli/cmd/root_configure.go` | Parent `configure` command |
| `pkg/cli/cmd/root_configure_add.go` | `configure add --name ... --cert ...` |
| `pkg/cli/cmd/root_configure_list.go` | `configure list` |
| `pkg/cli/cmd/root_configure_show.go` | `configure show [--profile]` |
| `pkg/cli/cmd/root_configure_use.go` | `configure use <name>` |
| `pkg/cli/cmd/root_configure_remove.go` | `configure remove <name>` |
| `pkg/cli/cmd/root_bootstrap.go` | Parent `bootstrap` command |
| `pkg/cli/cmd/root_bootstrap_status.go` | `bootstrap status` |
| `pkg/cli/cmd/root_bootstrap_token.go` | `bootstrap token [--regenerate]` |
| `pkg/cli/cmd/root_bootstrap_create_root.go` | `bootstrap create-root` |
| `pkg/cli/core/profile.go` | Profile load/save/resolve |
| `pkg/cli/core/fs.go` | Home-expansion, perm-verify, secure-copy helpers |
| `pkg/cli/core/prompt.go` | Interactive password prompt, `--password-stdin` |

### Modified files

| File | Change |
|---|---|
| `pkg/server/control/bootstrap_handlers.go` | Replace `requireCLI` with `requireClientIdentity("cli.akashic.local")` |
| `pkg/server/control/routes.go` | Apply new middleware to `/bootstrap/token*` |
| `pkg/bootstrap/manager.go` | `RegenerateToken(ctx, force bool)` semantics |
| `pkg/models/bootstrap_status.go` | Add audit columns (source, IP, attempts) |
| `pkg/cli/cmd/root.go` | Register `configure` + `bootstrap` subcommands |
| `pkg/cli/core/client.go` | Add `NewAkashicControlClient(profileName)` |
| `doc/phase-5-plan.md` | This document |

### Not touched

- Phase 1/2/3/4 infrastructure (Vault, Vault Agent, dependency TLS)
- pkg/auth (OAuth/OIDC core — not part of bootstrap)
- Middleware chains (reuse existing)

---

## Known Risks

| Risk | Mitigation |
|---|---|
| mTLS CN spoofing | `tls.Config.ClientAuth = RequireAndVerifyClientCert` (already set in Phase 4) guarantees CN is from a cert signed by our private CA |
| `~/.akashic/client.key` left world-readable | CLI verifies permissions on every load; refuses to proceed if drift detected |
| Operator runs `configure add` with wrong cert → bootstrap silently 403s | `configure add` does a cert-introspection sanity check: CN must start with `cli.akashic.local` or it warns |
| Bootstrap token leaks via shell history (`--token XYZ`) | CLI defaults to fetching token internally; `--token` is only for scripted override; `--password` similarly is discouraged (docs) |
| Race: two operators run `bootstrap create-root` simultaneously | Server's Step 2 re-check + PG unique constraint on `bootstrap_status.root_user_id` wins whoever commits first; the other gets `BOOTSTRAP_COMPLETE` |
| Server restart mid-bootstrap (after user created in LDAP+PG, before `is_complete=true`) | On next startup, `NeedsBootstrap()` returns true, deprovisioning notices the orphan root user in PG without LDAP entry being the *truth* of bootstrap state, reconciles. Worst case: operator has to re-run `bootstrap create-root`. |
| Config file corruption | On load error, CLI prints path + parse error + offers `--recover` mode that regenerates an empty config |

---

## Non-Goals (Deferred)

- **Web/BFF bootstrap** — Phase 6 (see Step 5 above for design notes)
- **Additional admin users** — `bootstrap` is *only* for the first root; later admin creation goes through a different endpoint (`/users/create` with admin auth)
- **Cert rotation for the CLI client cert** — the profile points at files; if the files get rotated, the CLI picks up the new cert automatically. No in-CLI rotation subcommand planned
- **Multi-user CLI** — one operator per workstation. Shared-CLI scenarios (e.g., CI runners) use `--profile <name>` or `AKASHIC_CLI_PROFILE` env
- **Password reset** — separate flow, needs email / recovery codes / etc. Scope for Phase 7 or later
- **TOTP / WebAuthn on root** — MFA is future scope; the root user starts with password-only
