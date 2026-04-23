#!/bin/sh
# ═══════════════════════════════════════════════════════════════
# Certificate Watcher for Loki
# ═══════════════════════════════════════════════════════════════
# Watches for Vault Agent cert renewals in /certs-source/loki/.
# Only reloads after ALL 3 files have changed, to prevent
# cert/key mismatch from partial updates.
#
# Loki re-reads cert files on each new TLS handshake, so atomic
# file replacement is sufficient. Existing connections keep the
# old cert until they reconnect; new connections use the new cert.
# ═══════════════════════════════════════════════════════════════

set -e

CERT_SRC="/certs-source/loki"
CERT_DST="/certs"
TRACK_DIR="/tmp/cert-watcher"

mkdir -p "$TRACK_DIR"

# Wait for Loki to start accepting on its listen port
echo "[cert-watcher] Waiting for Loki to start..."
until wget -qO- "http://127.0.0.1:3100/ready" 2>/dev/null | grep -q "ready" ||
      wget -qO- --no-check-certificate "https://127.0.0.1:3100/ready" 2>/dev/null | grep -q "ready"; do
    sleep 2
done
echo "[cert-watcher] Loki is ready. Watching for certificate changes..."

inotifywait -m -e close_write --format '%f' "$CERT_SRC" | while read file; do
    case "$file" in
        loki.crt|loki.key|ca.crt)
            touch "$TRACK_DIR/$file"
            ;;
        *) continue ;;
    esac

    if [ -f "$TRACK_DIR/loki.crt" ] && \
       [ -f "$TRACK_DIR/loki.key" ] && \
       [ -f "$TRACK_DIR/ca.crt" ]; then

        echo "[cert-watcher] All certificates updated. Performing atomic copy..."

        cp "$CERT_SRC/loki.crt" "$CERT_DST/loki.crt.tmp"
        cp "$CERT_SRC/loki.key" "$CERT_DST/loki.key.tmp"
        cp "$CERT_SRC/ca.crt"   "$CERT_DST/ca.crt.tmp"

        chown 10001:10001 "$CERT_DST/loki.crt.tmp" "$CERT_DST/loki.key.tmp" "$CERT_DST/ca.crt.tmp"
        chmod 0600 "$CERT_DST/loki.key.tmp"
        chmod 0644 "$CERT_DST/loki.crt.tmp" "$CERT_DST/ca.crt.tmp"

        mv "$CERT_DST/loki.crt.tmp" "$CERT_DST/loki.crt"
        mv "$CERT_DST/loki.key.tmp" "$CERT_DST/loki.key"
        mv "$CERT_DST/ca.crt.tmp"   "$CERT_DST/ca.crt"

        NEW_SERIAL=$(openssl x509 -noout -serial -in "$CERT_DST/loki.crt" 2>/dev/null | cut -d= -f2)
        NEW_EXPIRY=$(openssl x509 -noout -enddate -in "$CERT_DST/loki.crt" 2>/dev/null | cut -d= -f2)
        echo "[cert-watcher] Applying new certificate:"
        echo "[cert-watcher]   Serial:  ${NEW_SERIAL:-unknown}"
        echo "[cert-watcher]   Expires: ${NEW_EXPIRY:-unknown}"

        # Loki caches the TLS context in memory. SIGHUP triggers a reload
        # of the cert files without dropping connections. LOKI_PID is set
        # by the entrypoint (which stays alive as PID 1 with loki as a child).
        if [ -n "$LOKI_PID" ] && kill -HUP "$LOKI_PID" 2>/dev/null; then
            echo "[cert-watcher] Sent SIGHUP to loki (PID $LOKI_PID) to reload TLS certs."
        else
            echo "[cert-watcher] WARNING: could not signal loki (LOKI_PID=$LOKI_PID)"
        fi

        rm -f "$TRACK_DIR/loki.crt" "$TRACK_DIR/loki.key" "$TRACK_DIR/ca.crt"
    fi
done
