#!/bin/sh
set -e

CERT_SRC="/certs-source/loki"
LOKI_TLS_MODE="${LOKI_TLS_MODE:-off}"
DATASOURCE_DIR="/etc/grafana/provisioning/datasources"

mkdir -p "$DATASOURCE_DIR"

if [ "$LOKI_TLS_MODE" = "on" ]; then
    echo "[grafana] TLS enabled -- waiting for Loki CA cert..."
    while [ ! -f "$CERT_SRC/ca.crt" ]; do sleep 1; done

    # Generate datasource pointing to https://loki with CA cert verification.
    # Grafana's datasource YAML supports inlining CA cert as PEM string.
    # Content of a YAML block scalar must be indented MORE than the parent key,
    # so tlsCACert at 6 spaces -> content at 8 spaces.
    CA_CERT=$(awk 'NF { sub("\r$", ""); printf "        %s\n", $0 }' "$CERT_SRC/ca.crt")
    cat > "$DATASOURCE_DIR/loki.yml" <<EOF
apiVersion: 1
datasources:
  - name: Loki
    type: loki
    access: proxy
    url: https://loki.akashic.local:3100
    isDefault: true
    jsonData:
      tlsAuthWithCACert: true
    secureJsonData:
      tlsCACert: |
$CA_CERT
EOF
    echo "[grafana] Datasource configured for HTTPS with Akashic CA verification."
else
    cat > "$DATASOURCE_DIR/loki.yml" <<EOF
apiVersion: 1
datasources:
  - name: Loki
    type: loki
    access: proxy
    url: http://loki.akashic.local:3100
    isDefault: true
EOF
    echo "[grafana] Datasource configured for plain HTTP (no TLS)."
fi

# Fix ownership (Grafana runs as uid 472)
chown -R 472:0 "$DATASOURCE_DIR" 2>/dev/null || true

# Delegate to Grafana's original entrypoint
exec /run.sh "$@"
