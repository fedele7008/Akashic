#!/usr/bin/env bash
#
# Full-stack reset for an Akashic dev/test deployment.
#
# Originally just a Vault PKI reset; now wipes every piece of project
# state so `docker compose up -d` afterwards starts from a truly empty
# slate. Use this when you want to:
#   - re-bootstrap from scratch (forget the root user, regenerate JWT
#     signing keys, re-issue all TLS certs)
#   - test a brand-new install path on the same machine
#   - recover from a corrupted state where something got out of sync
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

current_dir_name="${PWD##*/}"
if [[ "$current_dir_name" != "Akashic" ]]; then
    echo "Current directory is '${current_dir_name}'. Please run this script from the Akashic project root."
    exit 1
fi

# ──────────────────────────────────────────────────────────────────────────
# 1. Bring the entire stack down (covers vault, akashic-server, and deps)
# ──────────────────────────────────────────────────────────────────────────
# `docker compose down` is idempotent -- no-op when nothing is running.
# `--profile app` ensures the profile-gated akashic-server + admin-bff are
# included in the teardown; without it, those containers would be left
# behind with file handles into the bind-mounted host paths, blocking
# the rm steps below.
# `--remove-orphans` cleans up any containers that used to belong to this
# project but were removed from docker-compose.yml since their last start.
echo "Bringing the Akashic stack down (if running)..."
docker compose --profile app down --remove-orphans

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

echo ""
echo "Reset complete."
echo "Next: docker compose [--profile app] up -d"
