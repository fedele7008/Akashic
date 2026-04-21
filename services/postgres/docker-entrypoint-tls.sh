#!/bin/bash
set -e

CERT_SRC="/certs-source/postgres"
CERT_DST="/certs"
POSTGRES_TLS="${POSTGRES_TLS:-off}"

if [ "$POSTGRES_TLS" = "on" ]; then
    # -- Wait for Vault Agent to issue certificates ----------------
    echo "TLS enabled -- waiting for certificates from Vault Agent..."
    while [ ! -f "$CERT_SRC/postgres.crt" ] || \
          [ ! -f "$CERT_SRC/postgres.key" ] || \
          [ ! -f "$CERT_SRC/ca.crt" ]; do
        sleep 1
    done
    echo "Certificates found."

    # -- Copy certs with correct ownership -------------------------
    # PostgreSQL requires key files owned by uid 70 (postgres) with 0600
    mkdir -p "$CERT_DST"
    cp "$CERT_SRC/postgres.crt" "$CERT_DST/server.crt"
    cp "$CERT_SRC/postgres.key" "$CERT_DST/server.key"
    cp "$CERT_SRC/ca.crt"       "$CERT_DST/ca.crt"

    # Copy CA to the location psql client expects
    mkdir -p /root/.postgresql
    cp "$CERT_SRC/ca.crt"       "/root/.postgresql/root.crt"

    chown 70:70 "$CERT_DST/server.crt" "$CERT_DST/server.key" "$CERT_DST/ca.crt"
    chmod 0600  "$CERT_DST/server.key"
    chmod 0644  "$CERT_DST/server.crt" "$CERT_DST/ca.crt"

    echo "Certificates loaded: server.crt, server.key, ca.crt"

    # -- Generate pg_hba.conf that forces TLS on TCP ---------------
    # hostssl = only allow TLS connections over TCP
    # local   = Unix socket (no TLS needed, same-container only)
    PG_HBA="$CERT_DST/pg_hba.conf"
    cat > "$PG_HBA" <<'EOF'
# TYPE    DATABASE  USER  ADDRESS    METHOD
local     all       all              trust
hostssl   all       all   0.0.0.0/0  scram-sha-256
hostssl   all       all   ::0/0      scram-sha-256
EOF
    chown 70:70 "$PG_HBA"

    echo "TLS enforced -- plain TCP connections will be rejected."

    # Start certificate watcher in background for auto-reload on renewal
    /usr/local/bin/cert-watcher.sh &

    # -- Start PostgreSQL with TLS flags ---------------------------
    exec docker-entrypoint.sh "$@" \
        -c ssl=on \
        -c ssl_cert_file=/certs/server.crt \
        -c ssl_key_file=/certs/server.key \
        -c ssl_ca_file=/certs/ca.crt \
        -c hba_file=/certs/pg_hba.conf
else
    echo "TLS disabled -- starting PostgreSQL without SSL."
    exec docker-entrypoint.sh "$@"
fi
