#!/bin/bash
set -e

CERT_SRC="/certs-source/ldap"
LDAP_TLS_MODE="${LDAP_TLS_MODE:-off}"
ENV_FILE="/container/environment/99-default/default.startup.yaml"

mkdir -p "$(dirname "$ENV_FILE")"

# Force osixia to regenerate config.php on every startup so TLS toggles
# take effect when AKASHIC_LDAP_TLS changes in .env. Without this, osixia's
# first-start logic skips regeneration, and an old config.php (from the
# previous TLS mode) persists on the container's writable layer.
rm -f /var/www/phpldapadmin/config/config.php
rm -f /container/run/state/docker-phpldapadmin-first-start-done

if [ "$LDAP_TLS_MODE" = "on" ]; then
    # -- Wait for CA cert (needed to verify LDAP server cert) ------
    echo "[phpldapadmin] TLS enabled -- waiting for CA cert..."
    while [ ! -f "$CERT_SRC/ca.crt" ]; do sleep 1; done

    # osixia's ssl-helper creates its own self-signed CA and points ldap.conf at it
    # via a symlink: /container/run/service/ldap-client/assets/certs/ldap-ca.crt
    #   -> /container/run/service/:ssl-tools/assets/default-ca/default-ca.pem
    #
    # We overwrite the target file with our actual CA cert in the background --
    # osixia creates it during its startup AFTER our entrypoint exec's /container/tool/run.
    OSIXIA_CA_TARGET="/container/run/service/:ssl-tools/assets/default-ca/default-ca.pem"
    (
        while [ ! -f "$OSIXIA_CA_TARGET" ]; do sleep 1; done
        # Overwrite osixia's self-signed CA with our Internal CA chain so libldap
        # (used by phpldapadmin) trusts the LDAP server's cert.
        cp "$CERT_SRC/ca.crt" "$OSIXIA_CA_TARGET"
        echo "[phpldapadmin] Overwrote osixia default-ca.pem with Akashic CA chain."
    ) &

    echo "[phpldapadmin] StartTLS to ldap.akashic.local:389 configured via docker-compose env."
else
    # When TLS is off, unset the docker-compose-provided TLS config and let the
    # startup yaml (processed before env vars are defined) set a non-TLS host
    # with the same login.bind_id so the admin DN stays pre-filled.
    unset PHPLDAPADMIN_LDAP_HOSTS
    cat > "$ENV_FILE" <<'EOF'
PHPLDAPADMIN_LDAP_HOSTS: "#PYTHON2BASH:[{'ldap.akashic.local': [{'server': [{'tls': False}, {'port': 389}]}, {'login': [{'bind_id': 'cn=admin,dc=akashic,dc=local'}]}]}]"
EOF
    echo "[phpldapadmin] TLS disabled -- connecting to ldap.akashic.local:389 (no TLS)"
fi

# Delegate to osixia's original entrypoint
exec /container/tool/run "$@"
