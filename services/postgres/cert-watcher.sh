#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Certificate Watcher for PostgreSQL
# ═══════════════════════════════════════════════════════════════
# Watches for Vault Agent cert renewals in /certs-source/postgres/.
# Only reloads PostgreSQL after ALL 3 files have changed, to
# prevent cert/key mismatch from partial updates.
#
# Uses atomic file replacement (cp → chown/chmod → mv) so
# PostgreSQL never reads a partially-written cert.
# ═══════════════════════════════════════════════════════════════

set -e

CERT_SRC="/certs-source/postgres"
CERT_DST="/certs"
TRACK_DIR="/tmp/cert-watcher"

mkdir -p "$TRACK_DIR"

# Wait for PostgreSQL to be ready before watching
echo "[cert-watcher] Waiting for PostgreSQL to start..."
until pg_isready -q -h /var/run/postgresql 2>/dev/null; do sleep 1; done
echo "[cert-watcher] PostgreSQL is ready. Watching for certificate changes..."

inotifywait -m -e close_write --format '%f' "$CERT_SRC" | while read file; do
    case "$file" in
        postgres.crt|postgres.key|ca.crt)
            touch "$TRACK_DIR/$file"
            ;;
        *) continue ;;
    esac

    # Only proceed when ALL 3 cert files have been updated
    if [ -f "$TRACK_DIR/postgres.crt" ] && \
       [ -f "$TRACK_DIR/postgres.key" ] && \
       [ -f "$TRACK_DIR/ca.crt" ]; then

        echo "[cert-watcher] All certificates updated. Performing atomic copy..."

        # ── Atomic copy: cp → chown/chmod → mv ──────────────────
        cp "$CERT_SRC/postgres.crt" "$CERT_DST/server.crt.tmp"
        cp "$CERT_SRC/postgres.key" "$CERT_DST/server.key.tmp"
        cp "$CERT_SRC/ca.crt"       "$CERT_DST/ca.crt.tmp"

        chown 70:70 "$CERT_DST/server.crt.tmp" "$CERT_DST/server.key.tmp" "$CERT_DST/ca.crt.tmp"
        chmod 0600  "$CERT_DST/server.key.tmp"
        chmod 0644  "$CERT_DST/server.crt.tmp" "$CERT_DST/ca.crt.tmp"

        mv "$CERT_DST/server.crt.tmp" "$CERT_DST/server.crt"
        mv "$CERT_DST/server.key.tmp" "$CERT_DST/server.key"
        mv "$CERT_DST/ca.crt.tmp"     "$CERT_DST/ca.crt"

        # Update root.crt for psql client verification
        cp "$CERT_SRC/ca.crt" "/root/.postgresql/root.crt"

        # ── Reload PostgreSQL ────────────────────────────────────
        NEW_SERIAL=$(openssl x509 -noout -serial -in "$CERT_DST/server.crt" 2>/dev/null | cut -d= -f2)
        NEW_EXPIRY=$(openssl x509 -noout -enddate -in "$CERT_DST/server.crt" 2>/dev/null | cut -d= -f2)

        echo "[cert-watcher] Applying new certificate:"
        echo "[cert-watcher]   Serial:  ${NEW_SERIAL:-unknown}"
        echo "[cert-watcher]   Expires: ${NEW_EXPIRY:-unknown}"

        RELOAD_RESULT=$(su postgres -c "pg_ctl reload" 2>&1)
        echo "[cert-watcher]   pg_ctl: $RELOAD_RESULT"

        echo "[cert-watcher] PostgreSQL reloaded with new certificates."

        # Reset tracking for next renewal cycle
        rm -f "$TRACK_DIR/postgres.crt" "$TRACK_DIR/postgres.key" "$TRACK_DIR/ca.crt"
    fi
done
