#!/bin/sh
set -e

CERT_SRC="/certs-source/loki-proxy"
LOKI_TLS_MODE="${LOKI_TLS_MODE:-on}"
DATASOURCE_DIR="/etc/grafana/provisioning/datasources"

mkdir -p "$DATASOURCE_DIR"

if [ "$LOKI_TLS_MODE" = "on" ]; then
    echo "[grafana] TLS mode -- waiting for Loki proxy CA cert..."
    while [ ! -f "$CERT_SRC/ca.crt" ]; do sleep 1; done

    # YAML block scalar requires content indented MORE than the parent key.
    # tlsCACert lives at 6 spaces, so the PEM body goes at 8.
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
    echo "[grafana] Datasource: https://loki.akashic.local:3100 (TLS via loki-proxy, CA-verified)"
else
    cat > "$DATASOURCE_DIR/loki.yml" <<'EOF'
apiVersion: 1
datasources:
  - name: Loki
    type: loki
    access: proxy
    url: http://loki.akashic.local:3100
    isDefault: true
EOF
    echo "[grafana] Datasource: http://loki.akashic.local:3100 (plain via loki-proxy, no TLS)"
fi

# Fix ownership (Grafana runs as uid 472)
chown -R 472:0 "$DATASOURCE_DIR" 2>/dev/null || true

exec /run.sh "$@"
