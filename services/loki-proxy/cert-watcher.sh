#!/bin/sh
# ═══════════════════════════════════════════════════════════════
# Certificate Watcher for Loki Proxy (nginx)
# ═══════════════════════════════════════════════════════════════
# Watches Vault Agent renewals in /certs-source/loki-proxy/.
# Only reloads after ALL 3 files have changed, to prevent
# cert/key mismatch from partial updates.
#
# nginx reloads TLS certs gracefully via `nginx -s reload` --
# existing connections drain naturally, new connections get
# the new cert. No downtime.
# ═══════════════════════════════════════════════════════════════

set -e

CERT_SRC="/certs-source/loki-proxy"
CERT_DST="/certs"
TRACK_DIR="/tmp/cert-watcher"

mkdir -p "$TRACK_DIR"

# Wait for nginx to be running before watching
echo "[cert-watcher] Waiting for nginx to start..."
while [ ! -f /var/run/nginx.pid ] && ! pgrep -x nginx >/dev/null 2>&1; do
    sleep 1
done
echo "[cert-watcher] nginx is ready. Watching for certificate changes..."

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

        if nginx -s reload 2>&1; then
            echo "[cert-watcher] nginx reloaded with new certificates."
        else
            echo "[cert-watcher] WARNING: nginx reload failed."
        fi

        rm -f "$TRACK_DIR/loki.crt" "$TRACK_DIR/loki.key" "$TRACK_DIR/ca.crt"
    fi
done
