#!/bin/bash
set -e

CERT_SRC="/certs-source/redis"
CERT_DST="/certs"
REDIS_TLS="${REDIS_TLS:-off}"

if [ "$REDIS_TLS" = "on" ]; then
    # -- Wait for Vault Agent to issue certificates ----------------
    echo "TLS enabled -- waiting for certificates from Vault Agent..."
    while [ ! -f "$CERT_SRC/redis.crt" ] || \
          [ ! -f "$CERT_SRC/redis.key" ] || \
          [ ! -f "$CERT_SRC/ca.crt" ]; do
        sleep 1
    done
    echo "Certificates found."

    # -- Copy certs with correct ownership -------------------------
    # Redis runs as uid 999 (redis user in Alpine)
    mkdir -p "$CERT_DST"
    cp "$CERT_SRC/redis.crt" "$CERT_DST/redis.crt"
    cp "$CERT_SRC/redis.key" "$CERT_DST/redis.key"
    cp "$CERT_SRC/ca.crt"    "$CERT_DST/ca.crt"

    chown redis:redis "$CERT_DST/redis.crt" "$CERT_DST/redis.key" "$CERT_DST/ca.crt"
    chmod 0600 "$CERT_DST/redis.key"
    chmod 0644 "$CERT_DST/redis.crt" "$CERT_DST/ca.crt"

    echo "Certificates loaded: redis.crt, redis.key, ca.crt"
    echo "TLS enforced -- plain TCP port disabled."

    # Start certificate watcher in background for auto-reload on renewal
    /usr/local/bin/cert-watcher.sh &

    # -- Start Redis with TLS flags --------------------------------
    # --tls-port 6379: TLS on the main port
    # --port 0: disable non-TLS port entirely
    # --tls-auth-clients no: server-TLS only (no mTLS required)
    exec redis-server \
        --tls-port 6379 \
        --port 0 \
        --tls-cert-file "$CERT_DST/redis.crt" \
        --tls-key-file "$CERT_DST/redis.key" \
        --tls-ca-cert-file "$CERT_DST/ca.crt" \
        --tls-auth-clients no \
        "$@"
else
    echo "TLS disabled -- starting Redis without TLS."
    exec redis-server "$@"
fi
