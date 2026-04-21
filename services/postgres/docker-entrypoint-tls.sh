#!/bin/bash
set -e

CERT_SRC="/certs-source/postgres"
CERT_DST="/certs"

# ── Wait for Vault Agent to issue certificates ──────────────
echo "Waiting for certificates from Vault Agent..."
while [ ! -f "$CERT_SRC/postgres.crt" ] || \
      [ ! -f "$CERT_SRC/postgres.key" ] || \
      [ ! -f "$CERT_SRC/ca.pem" ]; do
    sleep 1
done
echo "Certificates found."

# ── Copy certs to writable directory with correct ownership ──
# PostgreSQL requires key files owned by uid 70 (postgres) with 0600
mkdir -p "$CERT_DST"
cp "$CERT_SRC/postgres.crt" "$CERT_DST/server.crt"
cp "$CERT_SRC/postgres.key" "$CERT_DST/server.key"
cp "$CERT_SRC/ca.pem"       "$CERT_DST/ca.crt"

chown 70:70 "$CERT_DST/server.crt" "$CERT_DST/server.key" "$CERT_DST/ca.crt"
chmod 0600  "$CERT_DST/server.key"
chmod 0644  "$CERT_DST/server.crt" "$CERT_DST/ca.crt"

echo "Certificates loaded: server.crt, server.key, ca.crt"

# ── Delegate to the official postgres entrypoint ─────────────
exec docker-entrypoint.sh "$@"
