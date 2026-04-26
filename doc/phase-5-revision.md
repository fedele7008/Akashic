# Phase 5 Revision — As-Built Summary

This document records what actually shipped in Phase 5, complementing
[`phase-5-plan.md`](./phase-5-plan.md) (the forward-looking design). Use
this one as the operational reference: it covers the new CLI subcommands,
the canonical workflow for bringing up a fresh Akashic deployment, the
server-side hardening, and a few migration notes.

> **Status**: All four steps of Phase 5 landed. CLI bootstrap works end-to-end.

---

## What's New at a Glance

### New CLI subcommands

```
akashic-cli configure  add | list | show | use | remove   ← profile management
akashic-cli bootstrap  status | token | create-root        ← bootstrap actions
```

### New on-disk state

```
~/.akashic/                           (mode 0700)
├── config.yaml                       (mode 0600 — profile registry)
└── certs/
    └── <profile-name>/                (mode 0700)
        ├── ca.crt                    (mode 0644 — mTLS CA)
        ├── client.crt                (mode 0644 — mTLS client cert)
        └── client.key                (mode 0600 — mTLS client key)
```

The CLI enforces these permissions on every invocation and refuses to
load a profile whose private key is world-readable. Same pattern as
OpenSSH's `~/.ssh/id_rsa`.

### New server-side behaviors

- mTLS client-cert **CN-based** authorization on bootstrap endpoints
  (replaces the spoofable User-Agent header check)
- Per-CN **rate limit** on `/bootstrap/root` and
  `/bootstrap/token/regenerate` (5/min)
- `RegenerateToken` requires explicit `?force=true` to overwrite a
  still-valid token
- `bootstrap_status` table now records `completion_source`,
  `completion_ip`, `attempts_before_success` for forensic review

---

## The Canonical Workflow

The "fresh deployment to working server" recipe, in three commands.
Pick the deployment mode (host or container) and run the rest unchanged.

### Step 0 — Bring up the stack

**Container mode** (recommended):

```bash
./scripts/reset-akashic.sh           # clean slate
docker compose --profile app up -d
sleep 30                           # let vault-agent issue all certs
```

**Host mode** (Akashic on host, dependencies in containers):

```bash
./scripts/reset-akashic.sh
docker compose up -d               # everything except akashic itself
sleep 25
go run ./cmd/akashic run --verbose &
sleep 5
```

After this, the server is up but in **bootstrap mode** — it has no root
user yet and is waiting for one to be created.

### Step 1 — Configure the CLI (one-time per machine)

```bash
akashic-cli configure add \
    --name default \
    --control-url https://127.0.0.1:8081 \
    --ca-cert ./certs/akashic/mtls-ca.crt \
    --client-cert ./certs/akashic-cli/akashic-ctrl-client.crt \
    --client-key ./certs/akashic-cli/akashic-ctrl-client.key
```

This:
- Copies the three cert files into `~/.akashic/certs/default/` with
  correct permissions
- Records the URL + cert paths in `~/.akashic/config.yaml`
- Sets `default` as the active profile (because it's the first one)

### Step 2 — Create the root user

```bash
akashic-cli bootstrap create-root \
    --username admin \
    --email admin@example.com
```

The CLI:
1. Auto-fetches the bootstrap token from the server (no copy-paste needed)
2. Prompts for the password twice (no echo, requires confirmation)
3. Submits the request over mTLS
4. Prints the created user summary

After this, the server is in **normal mode**. Bootstrap endpoints
permanently close.

### That's the entire workflow

Three commands total. No curl. No env vars. No copy-pasting tokens. The
CLI handles the cert setup, the token retrieval, the password prompt,
and the API call.

---

## Subcommand Reference

### `akashic-cli configure`

#### `configure add` — register a new profile

```
akashic-cli configure add \
    --name <profile-name> \
    --control-url <https-url> \
    --ca-cert <path> \
    --client-cert <path> \
    --client-key <path> \
    [--link]              # symlink instead of copy (track source rotation)
    [--set-active]        # make this the active profile (default: only on first add)
```

Copies the three cert files into `~/.akashic/certs/<profile-name>/`
with correct permissions. The first-ever profile auto-activates.

**Why copy by default?** Operators often store certs in their project
directory (e.g., `./certs/...`). Six months later the project moves and
the CLI mysteriously breaks. Copying to `~/.akashic/certs/` pins a
stable location that survives project-tree changes.

**When to use `--link`?** When the source files are managed by Vault
Agent and you want the CLI to pick up rotations automatically without
re-running `configure add`.

#### `configure list` — show all profiles

```
$ akashic-cli configure list
PROFILES
* default              → https://127.0.0.1:8081
  staging              → https://akashic-staging.internal:8081
  prod                 → https://akashic.example.com:8081

* = active profile
```

#### `configure show` — full details + cert audit

```
$ akashic-cli configure show
Profile: default (active)
  control_url: https://127.0.0.1:8081
  ca_cert:     ~/.akashic/certs/default/ca.crt
    Subject:  CN=Akashic Control Plane mTLS CA,...
    Issuer:   CN=Akashic Internal CA,...
    Validity: 2026-04-25 → 2031-04-24
  client_cert: ~/.akashic/certs/default/client.crt
    Subject:  CN=cli.akashic.local
    Issuer:   CN=Akashic Control Plane mTLS CA,...
    Validity: 2026-04-25 → 2026-05-25
  client_key:  ~/.akashic/certs/default/client.key
    Permissions: 0600 (ok)
```

`--profile <name>` shows a different profile than the active one.
Cert subjects/issuers/expiries are decoded from the on-disk PEM files
each time, so this command also catches "is my cert expired?" and "is
my key still 0600?" at a glance.

#### `configure use <name>` — switch active profile

```
$ akashic-cli configure use prod
✓ Active profile is now "prod"
```

Equivalent to opening `~/.akashic/config.yaml` and editing
`active_profile:` by hand.

#### `configure remove <name>` — delete a profile

```
$ akashic-cli configure remove staging
✓ Profile "staging" removed
```

Also wipes `~/.akashic/certs/staging/`. Pass `--keep-certs` to
preserve the cert files (useful if you're temporarily detaching from
a deployment but might re-attach later).

### `akashic-cli bootstrap`

All bootstrap commands accept `--profile <name>` to override the
active profile, or you can set `AKASHIC_CLI_PROFILE` in the env.

#### `bootstrap status`

Reachable in **both** bootstrap and normal modes — the answer to "are
you in bootstrap mode?" is itself the response.

```
$ akashic-cli bootstrap status
Bootstrap status (profile "default"):
  is_complete: false
  token_exists: true
  token_ttl: 3560s (59m 20s)
```

After bootstrap completes:

```
$ akashic-cli bootstrap status
Bootstrap status (profile "default"):
  is_complete: true
  completed_at: 2026-04-24T23:04:09.276496-06:00
  root_user_id: fe3bc752-d252-454b-aa49-58084b64d883
```

#### `bootstrap token [--regenerate [--force]]`

Default: GET the current token.

```
$ akashic-cli bootstrap token
Bootstrap token:
  token: 8aa8ff7c11606ab1f626e09a5c0249d44f7c78163768fb02f3414453a1607fb7
  ttl:   3560s (59m 20s)
```

`--regenerate`: rotate the token. Server returns 409 if a valid token
already exists; pass `--force` to override.

```
$ akashic-cli bootstrap token --regenerate
Error: a valid token already exists; pass --force to overwrite

$ akashic-cli bootstrap token --regenerate --force
Token regenerated:
  token: <new-token>
  ttl:   3600s (1h 0m 0s)
  (forced overwrite)
```

#### `bootstrap create-root`

The one-command bootstrap entry point.

```
akashic-cli bootstrap create-root \
    --username <username> \
    --email <email> \
    [--password <pw>]       # NOT recommended (shell history)
    [--password-stdin]      # for scripted use: echo "$PW" | ...
    [--token <token>]       # default: auto-fetched
```

**Interactive flow** (recommended for humans):

```
$ akashic-cli bootstrap create-root --username admin --email admin@example.com
Password: ************
Confirm:  ************
✓ Root user created successfully
  uid:        fe3bc752-d252-454b-aa49-58084b64d883
  username:   admin
  email:      admin@example.com
  ldap_dn:    uid=admin,ou=users,dc=akashic,dc=local
  user_type:  root
  created_at: 2026-04-24T23:04:09.27499734-06:00
```

**Scripted flow**:

```bash
echo 'StrongP@ss123!' | akashic-cli bootstrap create-root \
    --username admin --email admin@example.com --password-stdin
```

**Idempotent re-run** (safe to retry):

```
$ akashic-cli bootstrap create-root --username admin --email admin@example.com
Bootstrap is already complete; nothing to do.
$ echo $?
0
```

---

## Exit Codes

Distinct exit codes let scripts branch on failure type without parsing
the error text. Reserve **exit 1** for "generic / cobra-level failure";
specific failures get their own slot.

| Code | Name | When |
|------|------|------|
| 0 | OK | Success, or already-in-desired-state (idempotent re-runs) |
| 1 | (cobra default) | Argument parsing, generic |
| 2 | `ExitInvalidToken` | No active token, expired token, wrong token |
| 3 | `ExitValidation` | Password policy violation, validation failure on input |
| 4 | `ExitRateLimit` | 429 from server's rate limiter |
| 5 | `ExitConfigError` | Profile missing, profile permissions wrong, profile YAML malformed, bogus `--profile <name>`, mTLS client cert rejected |
| 6 | `ExitNetworkError` | Connection refused, DNS failure, timeout |
| 7 | `ExitServerError` | Unexpected 5xx, malformed response envelope |

Example branching:

```bash
akashic-cli bootstrap create-root --username admin --email admin@example.com
case $? in
  0) echo "all good" ;;
  2) echo "token issue — server probably not in bootstrap mode" ;;
  3) echo "validation failed — check password policy" ;;
  5) echo "config issue — run akashic-cli configure" ;;
  6) echo "can't reach server — is it up?" ;;
  *) echo "unexpected: $?" ;;
esac
```

---

## Server-Side Changes (Hardening)

These ship transparently for the operator but matter for security review.

### 1. mTLS client-cert CN-based authorization

The pre-Phase-5 `requireCLI` middleware checked the User-Agent header
for `akashic-cli/`. Trivially spoofable. Replaced with
`requireClientIdentity(allowedCNs...)`, which inspects the verified
peer cert's Subject CN.

| Endpoint | Allowed CNs |
|---|---|
| `GET /bootstrap/status` | (no CN check — answers "are you in bootstrap?") |
| `GET /bootstrap/token` | `cli.akashic.local` |
| `POST /bootstrap/token/regenerate` | `cli.akashic.local` |
| `POST /bootstrap/root` | `cli.akashic.local`, `bff.akashic.local` |

Phase 6's BFF will hold the `bff.akashic.local` cert, completing the
allowlist. Until then, only akashic-cli is authorized to call these.

### 2. Bootstrap rate limit

Per-CN, in-memory, resets on server restart. 5 attempts per minute on
`/bootstrap/root` and `/bootstrap/token/regenerate`. The 6th gets
HTTP 429 + a security-channel log line:

```
SECURITY  bootstrap endpoint rate-limited  key=cn:cli.akashic.local
                                           retry_after_seconds=42
                                           path=/bootstrap/root
```

The 32-byte token already makes brute-force infeasible by construction;
the rate limit isn't there to defeat brute-force, it's there to make
attacker probing visible in security logs and to keep the DB from
absorbing junk attempts under load.

### 3. `RegenerateToken` force-flag guard

```
POST /bootstrap/token/regenerate
→ 200 OK if no valid token currently exists (initial generate)
→ 409 TOKEN_ALREADY_EXISTS if one does exist and ?force=true is missing
→ 200 OK if ?force=true (silent overwrite, security-channel log)
```

Without this guard, an attacker who briefly compromised the control
plane could rotate the token out from under a legitimate operator.
The force flag turns rotation from a silent overwrite into an
audit-loggable operator action.

### 4. Audit columns on `bootstrap_status`

```sql
ALTER TABLE bootstrap_status ADD COLUMN completion_source       VARCHAR(255);
ALTER TABLE bootstrap_status ADD COLUMN completion_ip           VARCHAR(64);
ALTER TABLE bootstrap_status ADD COLUMN attempts_before_success INT NOT NULL DEFAULT 0;
```

Populated when `is_complete` flips to true. `completion_source` records
the client cert CN that drove the successful bootstrap; for system-
initiated reconciliation (deprovisioning service auto-restoring root
from LDAP), the value is `deprovisioning-service`. These columns are
unused by the application logic — they exist purely for forensic review
if a bootstrap goes wrong.

GORM's `AutoMigrate` adds the columns automatically on first startup
after upgrade; no manual SQL required.

---

## Migration Notes

### Upgrading an existing deployment

Phase 5 is **backward-compatible** for normal operation. Pre-existing
`bootstrap_status` rows have empty audit columns (the new fields
default to `""` / `0` for missing data, which is what GORM does for
nullable additions).

The two operator-visible changes:

1. **`POST /bootstrap/token/regenerate` now requires `?force=true`** when
   a valid token already exists. Old scripts that called this in a
   loop and relied on silent overwrite will start hitting 409 —
   update them to add the query param.
2. **`POST /bootstrap/root` is now per-CN rate-limited.** Scripts that
   retry rapidly on failure may hit 429 after 5 tries. Add backoff or
   reduce retry frequency.

The CLI doesn't exist before Phase 5, so there's nothing to migrate
from on the client side.

### What a vault-reset breaks

`./scripts/reset-akashic.sh` regenerates the entire CA chain. This
invalidates every cert, including the ones in your `~/.akashic/certs/
<profile>/` directory. After a reset:

```
$ akashic-cli bootstrap status
Error: tls: failed to verify certificate: x509: certificate signed by unknown authority
```

The fix is one command — re-add the profile to pick up the new certs:

```
akashic-cli configure add \
    --name default \
    --control-url https://127.0.0.1:8081 \
    --ca-cert ./certs/akashic/mtls-ca.crt \
    --client-cert ./certs/akashic-cli/akashic-ctrl-client.crt \
    --client-key ./certs/akashic-cli/akashic-ctrl-client.key
```

This overwrites the existing profile's cert files in place. No
permission drift, no other state changes.

(If you used `--link` originally, no re-add is needed — the symlinks
still point at the right source paths and Vault Agent has updated the
files in place.)

---

## Files Touched (for code review)

### New files

| Path | Purpose |
|---|---|
| `pkg/cli/cmd/root_configure.go` | Parent `configure` command |
| `pkg/cli/cmd/root_configure_add.go` | Add a profile |
| `pkg/cli/cmd/root_configure_list.go` | List profiles |
| `pkg/cli/cmd/root_configure_show.go` | Show profile details |
| `pkg/cli/cmd/root_configure_use.go` | Set active profile |
| `pkg/cli/cmd/root_configure_remove.go` | Remove profile |
| `pkg/cli/cmd/root_bootstrap.go` | Parent `bootstrap` command |
| `pkg/cli/cmd/root_bootstrap_status.go` | bootstrap status + exit-code helpers |
| `pkg/cli/cmd/root_bootstrap_token.go` | bootstrap token + token --regenerate |
| `pkg/cli/cmd/root_bootstrap_create_root.go` | bootstrap create-root |
| `pkg/cli/core/profile.go` | Profile model, load/save, perm verification |
| `pkg/cli/core/fs.go` | `CopyFileSecure`, `ExpandHome` |
| `pkg/cli/core/prompt.go` | Interactive password prompt |
| `pkg/server/control/bootstrap_ratelimit.go` | Per-CN rate limiter for /bootstrap/* |

### Modified files

| Path | Change |
|---|---|
| `cmd/akashic-cli/main.go` | Use `HandleExitError` for structured exit codes |
| `pkg/cli/cmd/root.go` | Register `configure` and `bootstrap` parent commands; SilenceErrors |
| `pkg/cli/core/client.go` | Add `NewAkashicControlClient(profileName)` |
| `pkg/server/control/bootstrap_handlers.go` | Replace `requireCLI` with `requireClientIdentity`; thread audit context into `CreateRootUser`; map server errors to friendlier client codes |
| `pkg/server/control/routes.go` | Wire new middleware + rate limit on bootstrap routes |
| `pkg/server/control/server.go` | Hold a per-server `bootstrapLimiter` instance |
| `pkg/bootstrap/manager.go` | `RegenerateToken(ctx, force)`; `CreateRootUser(ctx, token, req, attempt)` with audit context |
| `pkg/repository/bootstrap_repository.go` | `MarkComplete(ctx, id, audit)` populates audit columns |
| `pkg/models/bootstrap.go` | New audit columns on `BootstrapStatus`; new `BootstrapCompletionAudit` shared type |
| `pkg/ldap/deprovisioning.go` | Updated interface to match new `MarkComplete` signature; tags JIT-provisioned roots with `Source: "deprovisioning-service"` |

---

## Quick Recipe Index

For copy-paste convenience.

**Fresh deployment, container mode:**
```bash
./scripts/reset-akashic.sh
docker compose --profile app up -d && sleep 30
akashic-cli configure add --name default \
    --control-url https://127.0.0.1:8081 \
    --ca-cert ./certs/akashic/mtls-ca.crt \
    --client-cert ./certs/akashic-cli/akashic-ctrl-client.crt \
    --client-key ./certs/akashic-cli/akashic-ctrl-client.key
akashic-cli bootstrap create-root --username admin --email admin@example.com
```

**After a vault reset (existing profile):**
```bash
./scripts/reset-akashic.sh
docker compose --profile app up -d && sleep 30
# Re-add to refresh cert files (overwrites existing profile)
akashic-cli configure add --name default \
    --control-url https://127.0.0.1:8081 \
    --ca-cert ./certs/akashic/mtls-ca.crt \
    --client-cert ./certs/akashic-cli/akashic-ctrl-client.crt \
    --client-key ./certs/akashic-cli/akashic-ctrl-client.key
akashic-cli bootstrap create-root --username admin --email admin@example.com
```

**Multi-deployment (dev / staging / prod):**
```bash
akashic-cli configure add --name dev     --control-url https://127.0.0.1:8081 ...
akashic-cli configure add --name staging --control-url https://akashic-staging.internal:8081 ...
akashic-cli configure add --name prod    --control-url https://akashic.example.com:8081 ...

akashic-cli configure use prod
akashic-cli bootstrap status              # uses prod

# Or one-off:
akashic-cli --profile staging bootstrap status
AKASHIC_CLI_PROFILE=dev akashic-cli bootstrap status
```

**Scripted bootstrap (CI/CD):**
```bash
PASSWORD="$(openssl rand -base64 24)"   # or pull from secret manager
echo "$PASSWORD" | akashic-cli bootstrap create-root \
    --username admin \
    --email admin@example.com \
    --password-stdin

case $? in
  0) echo "ok" ;;
  2) echo "no token — was server in bootstrap mode?" ;;
  3) echo "password policy issue" ;;
  6) echo "server unreachable" ;;
  *) exit 1 ;;
esac
```

**Sanity check after bootstrap:**
```bash
akashic-cli bootstrap status                          # is_complete: true
akashic-cli configure show                            # cert expiry visible
docker logs akashic-server 2>&1 | grep -i security    # check audit log
```
