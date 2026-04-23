#!/bin/sh
set -e

CERT_SRC="/certs-source/loki-proxy"
CERT_DST="/certs"
LOKI_TLS_MODE="${LOKI_TLS_MODE:-on}"
NGINX_CONF_DIR="/etc/nginx/conf.d"

# Clear any previously-linked config
rm -f "$NGINX_CONF_DIR/default.conf"

if [ "$LOKI_TLS_MODE" = "on" ]; then
    echo "[loki-proxy] TLS enabled -- waiting for certificates from Vault Agent..."
    while [ ! -f "$CERT_SRC/loki.crt" ] || \
          [ ! -f "$CERT_SRC/loki.key" ] || \
          [ ! -f "$CERT_SRC/ca.crt" ]; do
        sleep 1
    done
    echo "[loki-proxy] Certificates found."

    mkdir -p "$CERT_DST"
    cp "$CERT_SRC/loki.crt" "$CERT_DST/loki.crt"
    cp "$CERT_SRC/loki.key" "$CERT_DST/loki.key"
    cp "$CERT_SRC/ca.crt"   "$CERT_DST/ca.crt"
    chmod 0600 "$CERT_DST/loki.key"
    chmod 0644 "$CERT_DST/loki.crt" "$CERT_DST/ca.crt"

    cp /etc/nginx/conf-variants/nginx.tls.conf "$NGINX_CONF_DIR/default.conf"
    echo "[loki-proxy] Certificates installed. TLS mode active on port 3100."

    # Start cert-watcher in background; it will signal nginx -s reload on renewal
    /usr/local/bin/cert-watcher.sh &
else
    cp /etc/nginx/conf-variants/nginx.plain.conf "$NGINX_CONF_DIR/default.conf"
    echo "[loki-proxy] TLS disabled -- plain HTTP pass-through on port 3100."
fi

exec nginx -g "daemon off;"
