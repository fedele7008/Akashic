#!/usr/bin/env bash
#
# Reset Akashic's Vault-backed PKI state.
#
# A Vault reset regenerates the root CA chain, which invalidates every leaf
# cert and every secret-id/role-id previously issued. This script wipes:
#   - Host-side cert + secret state (./certs/*, ./.secrets/vault*)
#   - The whole Akashic docker-compose stack (so old certs aren't still in
#     use by running containers, which would block volume removal)
#   - Docker volumes that persist CA-chain-bound state:
#       * vault family (vault_file, vault_logs, vault_agent_*)
#       * ldap cn=config (TLS trust settings baked in)
#       * grafana provisioning (inlined CA cert in datasource)
#       * redisinsight (admin DB references CA bundle)
#
# After this script runs, `docker compose [--profile app] up -d` rebuilds
# everything from scratch: new root CA, new leaf certs, fresh Vault state.

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
# The `--profile app` flag ensures the profile-gated akashic-server is
# included in the teardown; without it, a running akashic container would
# be left behind with its cert-watcher holding file handles into ./certs/.
# `--remove-orphans` cleans up any containers that used to belong to this
# project but were removed from docker-compose.yml since their last start.
echo "Bringing the Akashic stack down (if running)..."
docker compose --profile app down --remove-orphans

# ──────────────────────────────────────────────────────────────────────────
# 2. Wipe host-side cert + secret state
# ──────────────────────────────────────────────────────────────────────────
# Keep .gitignore / README.md in ./certs so the directory structure is
# committable; every actual cert file gets deleted.
echo "Wiping ./certs/ (preserving .gitignore and README.md)..."
find ./certs -mindepth 1 ! -name '.gitignore' ! -name 'README.md' -exec rm -rf {} + 2>/dev/null || true

echo "Wiping ./.secrets/vault and ./.secrets/vault-agent..."
rm -rf ./.secrets/vault ./.secrets/vault-agent

# ──────────────────────────────────────────────────────────────────────────
# 3. Remove vault-family docker volumes
# ──────────────────────────────────────────────────────────────────────────
# Anchored regex ensures we only touch this project's volumes (prefix
# akashic_), never a vault volume belonging to some other compose project.
vault_vols=$(docker volume ls --format '{{.Name}}' | grep -E '^akashic_vault(_|$)' || true)
if [[ -n "$vault_vols" ]]; then
    echo "Removing vault-family volumes:"
    printf '  %s\n' $vault_vols
    # shellcheck disable=SC2086  # intentional word-splitting for multi-arg
    docker volume rm $vault_vols
fi

# ──────────────────────────────────────────────────────────────────────────
# 4. Remove downstream volumes that cache CA-chain-bound state
# ──────────────────────────────────────────────────────────────────────────
# LDAP cn=config stores TLS cert trust state tied to the old CA chain.
# Grafana provisioning YAML has the old CA cert PEM inlined in the
# datasource. RedisInsight's admin DB references the old CA bundle path.
# All of these must be reset together, or the new stack will mix new certs
# with old trust anchors and silently break TLS handshakes.
for vol in akashic_ldap_data akashic_ldap_config akashic_grafana_data akashic_redisinsight_data; do
    docker volume rm "$vol" 2>/dev/null && echo "Removed volume: $vol" || true
done

echo ""
echo "Reset complete."
echo "Next: docker compose [--profile app] up -d"
