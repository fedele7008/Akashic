#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Certificate Watcher for Redis
# ═══════════════════════════════════════════════════════════════
# Watches for Vault Agent cert renewals in /certs-source/redis/.
# Only reloads after ALL 3 files have changed, to prevent
# cert/key mismatch from partial updates.
#
# Uses atomic file replacement (cp -> chown/chmod -> mv) and
# Redis CONFIG SET for zero-downtime TLS cert rotation.
# ═══════════════════════════════════════════════════════════════

set -e

CERT_SRC="/certs-source/redis"
CERT_DST="/certs"
TRACK_DIR="/tmp/cert-watcher"
REDIS_PASSWORD="${REDIS_PASSWORD:-}"

mkdir -p "$TRACK_DIR"

# Build redis-cli auth args
CLI_AUTH=""
if [ -n "$REDIS_PASSWORD" ]; then
    CLI_AUTH="-a $REDIS_PASSWORD"
fi

# Build redis-cli TLS args (watcher connects over TLS since plain port is disabled)
CLI_TLS="--tls --cacert $CERT_DST/ca.crt"

# Wait for Redis to be ready before watching
echo "[cert-watcher] Waiting for Redis to start..."
until redis-cli $CLI_TLS $CLI_AUTH ping 2>/dev/null | grep -q PONG; do sleep 1; done
echo "[cert-watcher] Redis is ready. Watching for certificate changes..."

inotifywait -m -e close_write --format '%f' "$CERT_SRC" | while read file; do
    case "$file" in
        redis.crt|redis.key|ca.crt)
            touch "$TRACK_DIR/$file"
            ;;
        *) continue ;;
    esac

    # Only proceed when ALL 3 cert files have been updated
    if [ -f "$TRACK_DIR/redis.crt" ] && \
       [ -f "$TRACK_DIR/redis.key" ] && \
       [ -f "$TRACK_DIR/ca.crt" ]; then

        echo "[cert-watcher] All certificates updated. Performing atomic copy..."

        # -- Atomic copy: cp -> chown/chmod -> mv ------------------
        cp "$CERT_SRC/redis.crt" "$CERT_DST/redis.crt.tmp"
        cp "$CERT_SRC/redis.key" "$CERT_DST/redis.key.tmp"
        cp "$CERT_SRC/ca.crt"    "$CERT_DST/ca.crt.tmp"

        chown redis:redis "$CERT_DST/redis.crt.tmp" "$CERT_DST/redis.key.tmp" "$CERT_DST/ca.crt.tmp"
        chmod 0600 "$CERT_DST/redis.key.tmp"
        chmod 0644 "$CERT_DST/redis.crt.tmp" "$CERT_DST/ca.crt.tmp"

        mv "$CERT_DST/redis.crt.tmp" "$CERT_DST/redis.crt"
        mv "$CERT_DST/redis.key.tmp" "$CERT_DST/redis.key"
        mv "$CERT_DST/ca.crt.tmp"    "$CERT_DST/ca.crt"

        # -- Hot-reload TLS certs via CONFIG SET -------------------
        # Extract new cert serial for logging
        NEW_SERIAL=$(openssl x509 -noout -serial -in "$CERT_DST/redis.crt" 2>/dev/null | cut -d= -f2)
        NEW_EXPIRY=$(openssl x509 -noout -enddate -in "$CERT_DST/redis.crt" 2>/dev/null | cut -d= -f2)

        echo "[cert-watcher] Applying new certificate:"
        echo "[cert-watcher]   Serial:  ${NEW_SERIAL:-unknown}"
        echo "[cert-watcher]   Expires: ${NEW_EXPIRY:-unknown}"

        RESULT_CERT=$(redis-cli $CLI_TLS $CLI_AUTH CONFIG SET tls-cert-file "$CERT_DST/redis.crt" 2>/dev/null)
        RESULT_KEY=$(redis-cli $CLI_TLS $CLI_AUTH CONFIG SET tls-key-file "$CERT_DST/redis.key" 2>/dev/null)
        RESULT_CA=$(redis-cli $CLI_TLS $CLI_AUTH CONFIG SET tls-ca-cert-file "$CERT_DST/ca.crt" 2>/dev/null)

        echo "[cert-watcher]   tls-cert-file:    $RESULT_CERT"
        echo "[cert-watcher]   tls-key-file:     $RESULT_KEY"
        echo "[cert-watcher]   tls-ca-cert-file: $RESULT_CA"

        if echo "$RESULT_CERT $RESULT_KEY $RESULT_CA" | grep -qi "err"; then
            echo "[cert-watcher] WARNING: One or more CONFIG SET commands failed!"
        else
            echo "[cert-watcher] Redis TLS certificates reloaded successfully."
        fi

        # Reset tracking for next renewal cycle
        rm -f "$TRACK_DIR/redis.crt" "$TRACK_DIR/redis.key" "$TRACK_DIR/ca.crt"
    fi
done
