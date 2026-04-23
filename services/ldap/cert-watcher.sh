#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Certificate Watcher for OpenLDAP
# ═══════════════════════════════════════════════════════════════
# Watches for Vault Agent cert renewals in /certs-source/ldap/.
# Only reloads after ALL 3 files have changed, to prevent
# cert/key mismatch from partial updates.
#
# OpenLDAP doesn't auto-reload TLS certs. We trigger reload by
# updating olcTLSCertificateFile on cn=config via ldapmodify --
# slapd re-reads the cert file when this attribute is set (even
# to the same value it already has).
# ═══════════════════════════════════════════════════════════════

set -e

CERT_SRC="/certs-source/ldap"
CERT_DST="/container/service/slapd/assets/certs"
TRACK_DIR="/tmp/cert-watcher"
LDAP_CONFIG_PASSWORD="${LDAP_CONFIG_PASSWORD:-}"

mkdir -p "$TRACK_DIR"

# Wait for LDAP to be ready (accepts connections) before watching
echo "[cert-watcher] Waiting for LDAP to start..."
until ldapsearch -x -H ldap://localhost -b "" -s base 2>/dev/null | grep -q "result:"; do
    sleep 2
done
echo "[cert-watcher] LDAP is ready. Watching for certificate changes..."

inotifywait -m -e close_write --format '%f' "$CERT_SRC" | while read file; do
    case "$file" in
        ldap.crt|ldap.key|ca.crt)
            touch "$TRACK_DIR/$file"
            ;;
        *) continue ;;
    esac

    # Only proceed when ALL 3 cert files have been updated
    if [ -f "$TRACK_DIR/ldap.crt" ] && \
       [ -f "$TRACK_DIR/ldap.key" ] && \
       [ -f "$TRACK_DIR/ca.crt" ]; then

        echo "[cert-watcher] All certificates updated. Performing atomic copy..."

        # -- Atomic copy: cp -> chmod -> mv ------------------------
        cp "$CERT_SRC/ldap.crt" "$CERT_DST/ldap.crt.tmp"
        cp "$CERT_SRC/ldap.key" "$CERT_DST/ldap.key.tmp"
        cp "$CERT_SRC/ca.crt"   "$CERT_DST/ca.crt.tmp"

        chown openldap:openldap "$CERT_DST/ldap.crt.tmp" "$CERT_DST/ldap.key.tmp" "$CERT_DST/ca.crt.tmp"
        chmod 0600 "$CERT_DST/ldap.key.tmp"
        chmod 0644 "$CERT_DST/ldap.crt.tmp" "$CERT_DST/ca.crt.tmp"

        mv "$CERT_DST/ldap.crt.tmp" "$CERT_DST/ldap.crt"
        mv "$CERT_DST/ldap.key.tmp" "$CERT_DST/ldap.key"
        mv "$CERT_DST/ca.crt.tmp"   "$CERT_DST/ca.crt"

        # -- Log cert details ---------------------------------------
        NEW_SERIAL=$(openssl x509 -noout -serial -in "$CERT_DST/ldap.crt" 2>/dev/null | cut -d= -f2)
        NEW_EXPIRY=$(openssl x509 -noout -enddate -in "$CERT_DST/ldap.crt" 2>/dev/null | cut -d= -f2)
        echo "[cert-watcher] Applying new certificate:"
        echo "[cert-watcher]   Serial:  ${NEW_SERIAL:-unknown}"
        echo "[cert-watcher]   Expires: ${NEW_EXPIRY:-unknown}"

        # -- Trigger slapd to re-read cert via ldapmodify ----------
        # Setting olcTLSCertificateFile (even to same path) triggers
        # slapd to re-load the cert from disk. No restart needed.
        RELOAD_RESULT=$(ldapmodify -Y EXTERNAL -H ldapi:/// 2>&1 <<EOF || true
dn: cn=config
changetype: modify
replace: olcTLSCertificateFile
olcTLSCertificateFile: $CERT_DST/ldap.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: $CERT_DST/ldap.key
-
replace: olcTLSCACertificateFile
olcTLSCACertificateFile: $CERT_DST/ca.crt
EOF
)
        echo "[cert-watcher]   ldapmodify: $(echo "$RELOAD_RESULT" | head -1)"

        if echo "$RELOAD_RESULT" | grep -qi "success\|modifying entry"; then
            echo "[cert-watcher] LDAP TLS certificates reloaded successfully."
        else
            echo "[cert-watcher] WARNING: reload may have failed -- output: $RELOAD_RESULT"
        fi

        # Reset tracking for next renewal cycle
        rm -f "$TRACK_DIR/ldap.crt" "$TRACK_DIR/ldap.key" "$TRACK_DIR/ca.crt"
    fi
done
