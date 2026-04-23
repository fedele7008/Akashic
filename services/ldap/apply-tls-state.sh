#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Apply TLS Enforcement State to slapd's cn=config
# ═══════════════════════════════════════════════════════════════
# osixia persists cn=config in the ldap_config volume. Once TLS
# enforcement (olcSecurity: ssf=128) is set, it stays set across
# container restarts even if LDAP_TLS_MODE changes.
#
# This script reconciles the desired state (from LDAP_TLS_MODE)
# against the current cn=config state, using ldapmodify via
# ldapi:/// (Unix socket, no TLS needed for the modify itself).
# ═══════════════════════════════════════════════════════════════

set -e

LDAP_TLS_MODE="${LDAP_TLS_MODE:-off}"

# Wait for slapd to be ready on ldapi:/// (Unix socket)
echo "[tls-state] Waiting for slapd to start..."
until ldapsearch -Y EXTERNAL -H ldapi:/// -b "" -s base 2>/dev/null | grep -q "result:"; do
    sleep 2
done

# Check current olcSecurity value
CURRENT=$(ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config -s base "(objectClass=*)" olcSecurity 2>/dev/null \
    | grep "^olcSecurity:" | head -1 | cut -d: -f2- | xargs)

echo "[tls-state] Current olcSecurity: '${CURRENT:-<none>}'"
echo "[tls-state] Desired LDAP_TLS_MODE: $LDAP_TLS_MODE"

CHANGED=false
if [ "$LDAP_TLS_MODE" = "on" ]; then
    # Want: olcSecurity: ssf=128 (enforces TLS)
    if [ "$CURRENT" = "ssf=128" ]; then
        echo "[tls-state] TLS enforcement already on -- no change."
    else
        echo "[tls-state] Enabling TLS enforcement..."
        if [ -z "$CURRENT" ]; then
            OP="add"
        else
            OP="replace"
        fi
        ldapmodify -Y EXTERNAL -H ldapi:/// <<EOF 2>&1 | grep -v "SASL" || true
dn: cn=config
changetype: modify
$OP: olcSecurity
olcSecurity: ssf=128
EOF
        echo "[tls-state] TLS enforcement enabled (olcSecurity: ssf=128)."
        CHANGED=true
    fi
else
    # Want: no olcSecurity (allows plain connections)
    if [ -z "$CURRENT" ]; then
        echo "[tls-state] TLS enforcement already off -- no change."
    else
        echo "[tls-state] Disabling TLS enforcement..."
        ldapmodify -Y EXTERNAL -H ldapi:/// <<EOF 2>&1 | grep -v "SASL" || true
dn: cn=config
changetype: modify
delete: olcSecurity
EOF
        echo "[tls-state] TLS enforcement disabled."
        CHANGED=true
    fi
fi

# slapd caches olcSecurity in memory and doesn't reload on ldapmodify.
# If we changed it, signal slapd to restart so the new state takes effect.
# s6-overlay will automatically restart slapd after we kill it.
if [ "$CHANGED" = "true" ]; then
    SLAPD_PID=$(pgrep -f "^/usr/sbin/slapd" | head -1)
    if [ -n "$SLAPD_PID" ]; then
        echo "[tls-state] Restarting slapd (pid $SLAPD_PID) to apply olcSecurity change..."
        kill "$SLAPD_PID"
    fi
fi

echo "[tls-state] Done."
