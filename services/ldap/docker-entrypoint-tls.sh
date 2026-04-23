#!/bin/bash
set -e

CERT_SRC="/certs-source/ldap"
CERT_DST="/container/service/slapd/assets/certs"
LDAP_TLS_MODE="${LDAP_TLS_MODE:-off}"

# Always run the TLS state reconciler in the background -- it waits for slapd
# and then applies the correct olcSecurity state based on LDAP_TLS_MODE.
# Without this, toggling LDAP_TLS_MODE has no effect because osixia's initial
# TLS config is persisted in the ldap_config volume.
/usr/local/bin/apply-tls-state.sh &

if [ "$LDAP_TLS_MODE" = "on" ]; then
    # -- Wait for Vault Agent to issue certificates ----------------
    echo "TLS enabled -- waiting for certificates from Vault Agent..."
    while [ ! -f "$CERT_SRC/ldap.crt" ] || \
          [ ! -f "$CERT_SRC/ldap.key" ] || \
          [ ! -f "$CERT_SRC/ca.crt" ]; do
        sleep 1
    done
    echo "Certificates found."

    # -- Copy certs to osixia's expected writable path -------------
    # osixia/openldap chowns cert files to openldap user at startup.
    # If the cert source is read-only, it crashes. We copy first to
    # a writable path that osixia manages.
    mkdir -p "$CERT_DST"
    cp "$CERT_SRC/ldap.crt" "$CERT_DST/ldap.crt"
    cp "$CERT_SRC/ldap.key" "$CERT_DST/ldap.key"
    cp "$CERT_SRC/ca.crt"   "$CERT_DST/ca.crt"

    # osixia's startup scripts expect a trust-bundle.pem file at this path
    # (for DH params / trust concatenation). We alias it to our CA chain.
    cp "$CERT_SRC/ca.crt"   "$CERT_DST/trust-bundle.pem"

    # slapd runs as openldap (uid 911). Cert files copied by root default to
    # root:root ownership, which makes the key unreadable (0600) to slapd.
    # osixia's chown during startup doesn't reliably cover these files after
    # our entrypoint copies them, so we chown explicitly.
    chown openldap:openldap "$CERT_DST/ldap.crt" "$CERT_DST/ldap.key" "$CERT_DST/ca.crt" "$CERT_DST/trust-bundle.pem"
    chmod 0644 "$CERT_DST/ldap.crt" "$CERT_DST/ca.crt" "$CERT_DST/trust-bundle.pem"
    chmod 0600 "$CERT_DST/ldap.key"

    echo "Certificates copied: ldap.crt, ldap.key, ca.crt, trust-bundle.pem"

    # -- Configure osixia env vars for TLS -------------------------
    export LDAP_TLS="true"
    export LDAP_TLS_CRT_FILENAME="ldap.crt"
    export LDAP_TLS_KEY_FILENAME="ldap.key"
    export LDAP_TLS_CA_CRT_FILENAME="ca.crt"
    export LDAP_TLS_ENFORCE="true"
    export LDAP_TLS_VERIFY_CLIENT="never"

    echo "TLS enforced -- LDAPS required for all connections."

    # Start cert-watcher in background after LDAP is ready
    /usr/local/bin/cert-watcher.sh &
else
    echo "TLS disabled -- starting LDAP without TLS."
    export LDAP_TLS="false"
fi

# Delegate to osixia's original entrypoint
exec /container/tool/run "$@"
