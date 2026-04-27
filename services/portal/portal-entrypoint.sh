#!/bin/sh
# Tenant-portal container entrypoint.
#
# Two pieces of runtime wiring this script handles:
#
#   1. Read the OAuth client secret from disk and export it. The
#      built-in akashic-portal client's secret is provisioned by the
#      akashic-server's EnsureBuiltInClients on first run and lands
#      at /keys/oauth/client-secrets/akashic-portal.txt. We export
#      the contents as AKASHIC_PORTAL_CLIENT_SECRET so the Next.js
#      process picks it up via process.env. (Doing this in the
#      entrypoint rather than in the env: stanza of compose keeps
#      the secret off the docker-inspect surface and keeps compose
#      itself stateless about it.)
#
#   2. Point Node's TLS at the internal akashic CA so that fetch()
#      to api.akashic.local validates without `rejectUnauthorized:
#      false` hacks. NODE_EXTRA_CA_CERTS is the standard knob —
#      Node reads the file at startup and adds its certs to the
#      system trust store.
#
# Both wirings are best-effort: if the files are absent at startup
# (e.g. first run before vault-agent has rendered, or before
# akashic-server has provisioned the secret), the portal still
# starts. The first OAuth or API call will then fail with a clear
# error message, which is better than refusing to boot.

set -e

SECRET_FILE="/keys/oauth/client-secrets/akashic-portal.txt"
if [ -f "$SECRET_FILE" ] && [ -r "$SECRET_FILE" ]; then
    AKASHIC_PORTAL_CLIENT_SECRET="$(cat "$SECRET_FILE")"
    export AKASHIC_PORTAL_CLIENT_SECRET
fi

CA_FILE="/certs/akashic/api-ca.crt"
if [ -f "$CA_FILE" ] && [ -r "$CA_FILE" ]; then
    export NODE_EXTRA_CA_CERTS="$CA_FILE"
fi

# Hand off to the standalone Next.js bundle.
exec node /app/server.js
