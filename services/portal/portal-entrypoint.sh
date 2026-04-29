#!/bin/sh
# Portal container entrypoint.
#
# Two pieces of runtime wiring (in order):
#
#   1. Install the akashic internal CA into the OS trust store via
#      update-ca-certificates. Once installed, Node's TLS defaults
#      automatically trust certs issued from this CA — no
#      NODE_EXTRA_CA_CERTS gymnastics, no undici dispatcher patching.
#      Both `fetch` (to api.<tenant>) and ioredis (to redis.akashic.local)
#      use this trust path.
#
#   2. Drop privileges from root → uid 10100 (akashic) and exec node.
#      Step 1 must run as root (writing into /usr/local/share/...);
#      everything else can run unprivileged.
#
# OAuth credentials (client_id + client_secret) come from the
# operator-managed JSON file mounted at /secrets/sample/nextjs.json,
# read at OAuth-call time by web/portal/server/oauth.ts. No
# entrypoint-time secret loading needed.
#
# All steps are best-effort: if a precondition is missing (CA file
# not yet rendered by vault-agent, etc.), the portal still starts.
# The first OAuth or API call will fail with a clear error, which is
# better than refusing to boot.

set -e

# ─── Step 1: install akashic CA into the OS trust store ───────────────
# Two halves to this:
#  (a) Copy the CA into /usr/local/share/ca-certificates/ and run
#      update-ca-certificates so it's part of the OS bundle at
#      /etc/ssl/certs/ca-certificates.crt.
#  (b) Tell Node to USE that bundle. By default Node ships its own
#      Mozilla-derived CA list and ignores the OS one. The
#      --use-openssl-ca flag (passed via NODE_OPTIONS) flips this so
#      Node reads /etc/ssl/certs/ca-certificates.crt instead. This is
#      the missing piece that makes update-ca-certificates actually
#      take effect for Node TLS.
CA_FILE="/certs/akashic/api-ca.crt"
if [ -f "$CA_FILE" ] && [ -r "$CA_FILE" ]; then
    cp "$CA_FILE" /usr/local/share/ca-certificates/akashic-internal.crt
    update-ca-certificates >/dev/null 2>&1 || true
    # Tell Node to use the OS trust store.
    if [ -z "$NODE_OPTIONS" ]; then
        export NODE_OPTIONS="--use-openssl-ca"
    else
        export NODE_OPTIONS="$NODE_OPTIONS --use-openssl-ca"
    fi
fi

# ─── Step 2: drop privileges and exec ─────────────────────────────────
# We're currently running as root (no USER directive in the Dockerfile
# after the update-ca-certificates step needs root). Drop to akashic
# (uid 10100) before launching the long-lived Node process.
exec su-exec akashic node /app/server.js
