#!/bin/sh

# -e : in case of err, exit immediately
# -u : treat use of unset variables as errors
set -eu

OUT_DIR="/certs/vault"

mkdir -p "$OUT_DIR"

CRT="$OUT_DIR/vault.crt"
KEY="$OUT_DIR/vault.key"
ROOT="$OUT_DIR/root-ca.crt"
ROOT_KEY="$OUT_DIR/root-ca.key"
SAN_CONF="$OUT_DIR/san.conf"
CSR="$OUT_DIR/vault.csr"

if [ -f "$CRT" ] && [ -f "$KEY" ] && [ -f "$ROOT" ]; then
    echo "==> Vault TLS certs already exist. Skipping bootstrap."
    exit 0
fi

echo "==> openssl --version"
openssl version

echo "==> Generating Vault Root CA ($ROOT_KEY)"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$ROOT_KEY" > /dev/null 2>&1
openssl req -new -x509 -nodes -key "$ROOT_KEY" -sha256 -days 3650 -out "$ROOT" \
    -subj "/C=US/O=Akashic/CN=Akashic Vault Root CA"

echo "==> Creating SAN config file ($SAN_CONF)"
cat > "$SAN_CONF" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
O = Akashic
CN = Akashic Vault Root CA

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = vault
DNS.2 = localhost
DNS.3 = vault.akashic.local
IP.1 = 127.0.0.1
EOF

echo "==> Generating Vault Server key/csr with SAN"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEY" > /dev/null 2>&1
openssl req -new -key "$KEY" -out "$CSR" -config "$SAN_CONF"

echo "==> Signing Vault Server CSR with Root CA"
openssl x509 -req -in "$CSR" -CA "$ROOT" -CAkey "$ROOT_KEY" \
    -sha256 -days 3650 -extfile "$SAN_CONF" -extensions v3_req -out "$CRT"

rm -f "$SAN_CONF" "$CSR" "$ROOT_KEY"

chown -R 100:100 /file /certs

chmod 644 "$ROOT"
chmod 600 "$KEY"
chmod 644 "$CRT"

echo "==> Done:"
ls -l "$OUT_DIR"

exit 0
