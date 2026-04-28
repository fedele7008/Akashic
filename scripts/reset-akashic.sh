#!/usr/bin/env bash
#
# Full-stack reset for an Akashic dev/test deployment.
#
# Wipes every piece of project state — Vault PKI, TLS certs, OAuth
# signing keys, every named docker volume, host-side secret material —
# so `docker compose up -d` afterwards starts from a truly empty slate.
# Use this when you want to:
#   - re-bootstrap from scratch (forget the root user, regenerate JWT
#     signing keys, re-issue all TLS certs)
#   - test a brand-new install path on the same machine
#   - recover from a corrupted state where something got out of sync
#
# Usage:
#   ./scripts/reset-akashic.sh           # project-scoped reset
#   ./scripts/reset-akashic.sh --deep    # also prune docker build cache
#                                        # + dangling images (host-wide)
#
# Why --deep exists:
#   Default mode reclaims roughly 1–2 MB of named-volume storage. The
#   real disk hog after a long iterative build session is Docker's own
#   build cache — it can climb to 20–40 GB on macOS Docker Desktop and
#   eventually cause "no space left on device" errors inside any
#   container, including a half-initialised Vault. --deep adds the
#   build-cache + dangling-image prunes that the default doesn't touch.
#
#   --deep deliberately does NOT use `docker system prune --volumes`:
#   that would also nuke other projects' named volumes on the same
#   host. We only prune cache + images — both of which are caches that
#   regenerate on the next build.
#
# What gets wiped:
#
#   Host-side state
#   ───────────────
#     ./certs/           Vault-Agent-rendered TLS material (whole tree
#                        bar .gitignore + README.md)
#     ./keys/            server-managed key material — OAuth signing
#                        keys + built-in client secrets (Phase 7)
#     ./.secrets/vault   Vault root token + recovery shares (issued by
#                        the bootstrap container on first init)
#     ./.secrets/vault-agent  AppRole role-id / secret-id files
#     ./logs/            host-run app/security/audit logs (if any)
#
#   Docker volumes (every named volume prefixed `akashic_`)
#   ──────────────
#     akashic_certs                bind-mount of ./certs (the named
#                                  volume gets removed, the bind path
#                                  is wiped above)
#     akashic_keys                 bind-mount of ./keys (same idea)
#     akashic_secrets              bind-mount of ./.secrets (same idea)
#     akashic_vault_file           Vault's raft storage (KV, PKI mounts,
#                                  policies, auth methods)
#     akashic_vault_logs           Vault audit log
#     akashic_vault_agent_file     Vault Agent's leases / sink material
#     akashic_vault_agent_logs     Vault Agent diagnostic logs
#     akashic_pg_data              Postgres database (users,
#                                  client_services, bootstrap rows)
#     akashic_redis_data           Redis (sessions, auth codes, cache)
#     akashic_loki_data            Loki log storage
#     akashic_grafana_data         Grafana DB (dashboards, datasource
#                                  configs with inlined CA certs)
#     akashic_ldap_data            LDAP DIT
#     akashic_ldap_config          LDAP cn=config (TLS trust anchors)
#     akashic_redisinsight_data    RedisInsight admin DB
#     akashic_phpldapadmin_www     phpLDAPadmin session/cache
#
# After this runs, `docker compose [--profile app] up -d` will:
#   1. Vault container re-inits empty raft
#   2. Vault bootstrap runs from scratch (writes new root token,
#      seals/unseals, configures PKI mounts)
#   3. Vault Agent re-authenticates via fresh AppRole material and
#      renders new TLS certs into ./certs/
#   4. Akashic server generates a new OAuth signing key into ./keys/
#      and a fresh akashic-admin client secret
#   5. Postgres comes up empty → bootstrap mode → operator must
#      re-create the root user via the admin UI

set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────
# 0. Parse args
# ──────────────────────────────────────────────────────────────────────────
deep=false
for arg in "$@"; do
    case "$arg" in
        --deep)
            deep=true
            ;;
        -h|--help)
            # Surface the file header (the lines starting with `# `) as
            # the usage text. Cheaper to maintain than duplicating the
            # docs in a help string.
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Unknown option: $arg" >&2
            echo "Usage: $0 [--deep]" >&2
            exit 2
            ;;
    esac
done

current_dir_name="${PWD##*/}"
if [[ "$current_dir_name" != "Akashic" ]]; then
    echo "Current directory is '${current_dir_name}'. Please run this script from the Akashic project root."
    exit 1
fi

# ──────────────────────────────────────────────────────────────────────────
# 1. Bring the entire stack down (covers vault, akashic-server, and deps)
# ──────────────────────────────────────────────────────────────────────────
# `docker compose down` is idempotent -- no-op when nothing is running.
# Both `--profile app` (akashic-server) and `--profile sample` (the
# Next.js sample portal, post-Phase-8b pivot) are needed so every
# project-owned container is included in the teardown. Without them,
# profile-gated containers stay running and hold open file handles
# into the bind-mounted host paths, blocking the rm steps below.
# `--remove-orphans` also cleans up any containers that used to belong
# to this project but were removed from docker-compose.yml since their
# last start.
echo "Bringing the Akashic stack down (if running)..."
docker compose --profile app --profile sample down --remove-orphans

# ──────────────────────────────────────────────────────────────────────────
# 2. Wipe host-side cert + secret + key + log state
# ──────────────────────────────────────────────────────────────────────────
# Each top-level dir keeps its .gitignore / README.md so the directory
# structure remains committable; every actual data file gets deleted.
echo "Wiping ./certs/ (preserving .gitignore and README.md)..."
find ./certs -mindepth 1 ! -name '.gitignore' ! -name 'README.md' -exec rm -rf {} + 2>/dev/null || true

# Phase 7: server-managed key material (OAuth signing keys, client
# secrets). Wiping these on a vault-reset is correct: a reset
# regenerates the entire trust chain, and tokens signed by the old
# OAuth key shouldn't be valid against the new identity infrastructure.
echo "Wiping ./keys/ (preserving .gitignore and README.md)..."
find ./keys -mindepth 1 ! -name '.gitignore' ! -name 'README.md' -exec rm -rf {} + 2>/dev/null || true

echo "Wiping ./.secrets/vault and ./.secrets/vault-agent..."
rm -rf ./.secrets/vault ./.secrets/vault-agent

# ./logs may not exist if host-run mode hasn't been used; the dir is
# created lazily by pkg/logging when configured. Test for existence
# so the find doesn't error.
if [[ -d ./logs ]]; then
    echo "Wiping ./logs/ (preserving .gitignore and README.md if present)..."
    find ./logs -mindepth 1 ! -name '.gitignore' ! -name 'README.md' -exec rm -rf {} + 2>/dev/null || true
fi

# ──────────────────────────────────────────────────────────────────────────
# 3. Remove every akashic-prefixed docker volume
# ──────────────────────────────────────────────────────────────────────────
# The anchored regex `^akashic_` ensures we only touch volumes that
# belong to this docker-compose project (the project name `akashic`
# becomes the volume-name prefix). We never touch volumes from other
# projects on the same host.
#
# Bind-mounted volumes (akashic_certs, akashic_keys, akashic_secrets)
# get removed here too; the bind targets on the host were already
# wiped in step 2, and removing the named volume tells Docker to
# recreate the bind on next `up -d`.
echo "Removing every akashic_* docker volume..."
project_vols=$(docker volume ls --format '{{.Name}}' | grep -E '^akashic_' || true)
if [[ -n "$project_vols" ]]; then
    # shellcheck disable=SC2086  # intentional word-splitting for multi-arg
    docker volume rm $project_vols 2>&1 | sed 's/^/  /' || true
else
    echo "  (no akashic_* volumes found — nothing to remove)"
fi

# ──────────────────────────────────────────────────────────────────────────
# 4. (--deep only) Reclaim Docker build cache + dangling images
# ──────────────────────────────────────────────────────────────────────────
# These prunes are HOST-WIDE — they affect every project sharing this
# Docker daemon, not just Akashic. Both targets are pure caches that
# regenerate on the next build, so the cost is build-time slowdown,
# not data loss.
#
# Why this lives behind a flag instead of running by default:
#   - The default reset is meant to be fast and project-scoped; deep
#     prunes can take 30s+ on a busy machine.
#   - Other projects on the same host might be in mid-iteration; we
#     don't want to throw away their build cache silently every time
#     someone resets Akashic.
#
# What we deliberately do NOT do here:
#   - `docker system prune --volumes` would nuke OTHER projects' named
#     volumes too (their database state, etc.). That's an operator-
#     decision, not a reset-akashic decision.
#   - `docker container prune` — stopped containers from other projects
#     might still be useful to their owners.
if [[ "$deep" == "true" ]]; then
    echo ""
    echo "Deep clean: pruning Docker build cache + dangling images (host-wide)..."
    docker builder prune --all --force 2>&1 | sed 's/^/  /'
    docker image prune --all --force 2>&1 | sed 's/^/  /'
fi

echo ""
echo "Reset complete."
if [[ "$deep" != "true" ]]; then
    echo "Tip: pass --deep to also prune Docker build cache + dangling images."
    echo "     Useful if you hit \"no space left on device\" inside containers."
fi
echo "Next: docker compose [--profile app] up -d"
