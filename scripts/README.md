# Development Scripts

Utility scripts for Akashic development.

> ⚠️ **The reset script DELETES ALL DEV DATA. Never run it against a
> deployment whose state you care about.**

## Reset

There is one reset script. It does a complete project-wide wipe:
Vault PKI, TLS certs, OAuth signing keys, every named docker volume,
host-side secret material — everything. After it runs, the next
`docker compose up -d` starts from a truly empty slate (re-init Vault,
re-issue every cert, regenerate OAuth keys, empty postgres + redis +
ldap, etc.).

```bash
./scripts/reset-akashic.sh
```

The script's leading comment explains exactly what it touches and why
each piece is wiped. Read it before running if you've never used it.

### Why one script instead of per-subsystem ones

Akashic's TLS chain, application data, and OAuth signing material are
all tied together by Vault's PKI. Resetting only the database (or only
LDAP) leaves the certs and signing keys behind, which means the *next*
server start mixes new app state with old trust anchors and surfaces
confusing failures (sessions decrypted by an old key, mTLS handshakes
against a stale CA, etc.). Treating the whole project state as one
slate that resets together avoids that class of bug entirely.

If you find yourself wanting a partial reset for a specific dev case
(e.g., "wipe just postgres but keep certs"), you can usually do it
ad-hoc with `docker compose exec` — and if it becomes a recurring
need, that's a signal to add a narrower script alongside this one.

## Quick Start After Fresh Clone

```bash
# 1. Start the dependency stack + admin-bff + proxy (no akashic yet)
docker compose up -d

# 2a. Run akashic on the host (fast Go iteration)
go run ./cmd/akashic run --verbose

#   ── OR ──

# 2b. Run akashic in a container (full-container deployment)
docker compose --profile app up -d akashic

# 3. Bootstrap token is printed to akashic's stderr; visit
#    https://admin.<your-domain>/ and submit the form.
```

The admin-bff lazy-initializes its OAuth client, so you can switch
between options 2a and 2b without restarting it — login picks up
whichever akashic is currently authoritative.

## Migration Behavior

The migration system:

- ✅ Only runs migrations when needed
- ✅ Skips if database is already up-to-date
- ✅ Detects dirty states with helpful error messages
- ✅ Provides automatic fix via environment variable

### Migration States

- **Clean, up-to-date**: No migrations run, server starts normally
- **Pending migrations**: Migrations run automatically on startup
- **Dirty state**: Server won't start, provides instructions for fix

### Fix Dirty Migration State

If a migration was interrupted partway through, the migration tracker
table is left in a "dirty" state. Two ways to recover:

**Quick** — force the migration version (only safe if you know which
version was last applied):

```bash
AKASHIC_FORCE_MIGRATION_VERSION=1 go run ./cmd/akashic run --verbose
```

**Clean slate** — full project reset (this is what most operators
reach for):

```bash
./scripts/reset-akashic.sh
docker compose up -d
go run ./cmd/akashic run --verbose
```

## Troubleshooting

### "Dirty database" error

**Cause:** A previous migration was interrupted.

See *Fix Dirty Migration State* above.

### Database connection refused

**Cause:** PostgreSQL container not running.

```bash
docker compose up -d postgres
```
