#!/usr/bin/env bash
#
# Convenience launcher for hybrid host-run mode:
#   - Dependencies + admin-bff + proxy run in docker
#   - Akashic server runs on the host via `go run`
#
# Use this when you want fast iteration on the akashic server (rebuild
# loop, debugger, profiler) without giving up the docker-managed
# stack for everything else.
#
# This script:
#   1. Brings up the dependency containers (default profile)
#   2. Starts admin-bff + proxy with the host-akashic overrides
#   3. Execs `go run ./cmd/akashic run` with the right env vars
#
# The script execs the akashic server in the foreground, so Ctrl+C
# stops the akashic process. The docker stack keeps running; tear it
# down explicitly with `docker compose down` (and `--profile app` to
# also stop admin-bff).

set -euo pipefail

current_dir_name="${PWD##*/}"
if [[ "$current_dir_name" != "Akashic" ]]; then
    echo "Run this script from the Akashic project root."
    exit 1
fi

OVERRIDE="-f docker-compose.yml -f docker-compose.host-akashic.yml"

echo "── 1/3 Starting dependency containers..."
docker compose up -d

echo "── 2/3 Starting admin-bff + proxy in hybrid host-akashic mode..."
# shellcheck disable=SC2086  # intentional word-splitting of $OVERRIDE
docker compose $OVERRIDE --profile app up -d --no-deps admin-bff
# shellcheck disable=SC2086
docker compose $OVERRIDE up -d --force-recreate proxy

echo "── 3/3 Starting akashic server on host..."
echo "      (control plane bound to 0.0.0.0 so docker can reach it via host-gateway)"
echo "      Press Ctrl+C to stop the akashic server. Docker stack stays up."
echo ""

# AKASHIC_SERVER_CONTROL_HOST=0.0.0.0 makes the control listener
# reachable from inside docker via host-gateway. mTLS still gates
# access — the listener won't accept anything without a valid client
# cert. Firewall the port off from non-trusted networks if your dev
# machine is multi-homed.
exec env AKASHIC_SERVER_CONTROL_HOST=0.0.0.0 go run ./cmd/akashic run --verbose "$@"
