#!/bin/sh
set -e

CERT_SRC="/certs-source/loki"
CERT_DST="/certs"
LOKI_TLS_MODE="${LOKI_TLS_MODE:-off}"
CONFIG_SRC_BASE="/etc/loki/config.yml"
CONFIG_SRC_TLS="/etc/loki/config.tls.yml"
CONFIG_RUNTIME="/tmp/loki-runtime.yml"

if [ "$LOKI_TLS_MODE" = "on" ]; then
    echo "TLS enabled -- waiting for certificates from Vault Agent..."
    while [ ! -f "$CERT_SRC/loki.crt" ] || \
          [ ! -f "$CERT_SRC/loki.key" ] || \
          [ ! -f "$CERT_SRC/ca.crt" ]; do
        sleep 1
    done
    echo "Certificates found."

    # Copy certs with correct ownership (Loki runs as uid 10001)
    mkdir -p "$CERT_DST"
    cp "$CERT_SRC/loki.crt" "$CERT_DST/loki.crt"
    cp "$CERT_SRC/loki.key" "$CERT_DST/loki.key"
    cp "$CERT_SRC/ca.crt"   "$CERT_DST/ca.crt"
    chown 10001:10001 "$CERT_DST/loki.crt" "$CERT_DST/loki.key" "$CERT_DST/ca.crt"
    chmod 0600 "$CERT_DST/loki.key"
    chmod 0644 "$CERT_DST/loki.crt" "$CERT_DST/ca.crt"

    cp "$CONFIG_SRC_TLS" "$CONFIG_RUNTIME"
    echo "TLS enforced -- using config.tls.yml"
    WATCHER_ENABLED=1
else
    cp "$CONFIG_SRC_BASE" "$CONFIG_RUNTIME"
    echo "TLS disabled -- using config.yml"
    WATCHER_ENABLED=0
fi

# Ensure loki can read the runtime config
chown loki:loki "$CONFIG_RUNTIME" || true

# Run loki and cert-watcher as children of this shell (PID 1). We don't exec
# into loki because the cert-watcher needs a parent that stays alive and
# needs to be able to signal loki via its PID.
gosu loki:loki /usr/bin/loki -config.file="$CONFIG_RUNTIME" &
LOKI_PID=$!
export LOKI_PID

if [ "$WATCHER_ENABLED" = "1" ]; then
    /usr/local/bin/cert-watcher.sh &
fi

# Forward SIGTERM/SIGINT to loki for graceful shutdown
trap 'kill -TERM "$LOKI_PID" 2>/dev/null; wait "$LOKI_PID"' TERM INT

wait "$LOKI_PID"
