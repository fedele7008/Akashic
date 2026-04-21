# Phase 3: TLS on Docker Services + Cert Rotation

## Context

All Vault PKI infrastructure is operational (13-step vault-init pipeline). Leaf certificates for every service exist in `./certs/`. The four dependency services (PostgreSQL, Redis, LDAP, Loki) are commented out in `docker-compose.yml`. No Vault Agent, no cert-watcher, and no `pkg/pki/` package exist yet.

**Goal**: Enable TLS on all Docker services, add automatic cert rotation via Vault Agent, and add cert watchers for graceful reload/restart when certs rotate.

**Phase 4** (next): Modify the Akashic Go server to use TLS (control server, auth server, and client connections to postgres/redis/ldap/loki).

---

## Lessons from Previous Attempt

These were discovered before the rollback and **must** be followed:

| Issue | Root Cause | Fix |
|-------|-----------|-----|
| Vault Agent cert/key mismatch | Separate `pkiCert` template blocks generate independent key pairs | Single bundle template per cert + `split-bundle.sh` post-processor |
| Docker PID namespace fails on macOS | `pid: "service:X"` causes OCI runtime error on Docker Desktop | Mount Docker socket + `docker kill --signal` |
| osixia/openldap chowns cert files | Container chowns to openldap user; fails on read-only mounts | Custom entrypoint: copy certs → writable dir → chown → exec slapd |
| PostgreSQL key permissions | Requires key owned by postgres (uid 70) with 0600 | Custom entrypoint: copy certs → chown 70:70 → chmod 0600 |
| vault-init Step 12 vs Vault Agent | Both issue certs with different keys → mismatch during transition | Option A: skip Step 12 when Vault Agent is present |
| Redis TLS | No native hot-reload of TLS certs | Restart container on rotation |

---

## Execution Order

```
Step 1: PostgreSQL TLS          ← simplest, tests the entrypoint pattern
Step 2: Redis TLS               ← same pattern, different flags
Step 3: LDAP TLS                ← complex (osixia quirks)
Step 4: Loki TLS                ← obs profile, mTLS
Step 5: Vault Agent sidecar     ← takes over cert issuance from Step 12
Step 6: Cert Watcher            ← watches files, signals containers
Step 7: Wire up dependencies    ← final topology + full stack test
```

Steps 1–4 use existing vault-init Step 12 certs. Step 5 introduces Vault Agent. Step 6 adds the watcher. Step 7 ties it all together.

---

## Step 1: PostgreSQL TLS

### 1.1 Create custom entrypoint

**New file**: `services/postgres/docker-entrypoint-tls.sh`

```bash
#!/bin/bash
set -e

CERT_SRC="/certs-source/postgres"
CERT_DST="/certs"
CA_SRC="/certs-source/ca/trust/trust-bundle.pem"

mkdir -p "$CERT_DST"
cp "$CERT_SRC/postgres.crt" "$CERT_DST/server.crt"
cp "$CERT_SRC/postgres.key" "$CERT_DST/server.key"
cp "$CA_SRC"                "$CERT_DST/ca.crt"

chown 70:70 "$CERT_DST"/*          # postgres uid in alpine
chmod 0600  "$CERT_DST/server.key"
chmod 0644  "$CERT_DST/server.crt" "$CERT_DST/ca.crt"

exec docker-entrypoint.sh "$@"
```

### 1.2 Create Dockerfile

**New file**: `services/postgres/Dockerfile`

```dockerfile
FROM postgres:16-alpine
COPY docker-entrypoint-tls.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint-tls.sh
ENTRYPOINT ["docker-entrypoint-tls.sh"]
CMD ["postgres", \
     "-c", "ssl=on", \
     "-c", "ssl_cert_file=/certs/server.crt", \
     "-c", "ssl_key_file=/certs/server.key", \
     "-c", "ssl_ca_file=/certs/ca.crt"]
```

### 1.3 Uncomment and modify in docker-compose.yml

- Change `image:` → `build: ./services/postgres`
- Add volume: `certs:/certs-source:ro`
- Add `depends_on: vault-init: condition: service_completed_successfully`
- Healthcheck: keep `pg_isready` (works with SSL enabled)

### 1.4 Verify

```bash
docker compose up vault-bootstrap vault vault-init postgres -d
# Wait for postgres to start
psql "sslmode=verify-ca sslrootcert=./certs/ca/trust/trust-bundle.pem \
      host=localhost port=5432 dbname=akashic user=<user>"
# Check \conninfo → should show "SSL connection"
```

---

## Step 2: Redis TLS

### 2.1 Create custom entrypoint

**New file**: `services/redis/docker-entrypoint-tls.sh`

```bash
#!/bin/bash
set -e

CERT_SRC="/certs-source/redis"
CERT_DST="/certs"
CA_SRC="/certs-source/ca/trust/trust-bundle.pem"

mkdir -p "$CERT_DST"
cp "$CERT_SRC/redis.crt" "$CERT_DST/redis.crt"
cp "$CERT_SRC/redis.key" "$CERT_DST/redis.key"
cp "$CA_SRC"             "$CERT_DST/ca.crt"

chown redis:redis "$CERT_DST"/*
chmod 0600 "$CERT_DST/redis.key"
chmod 0644 "$CERT_DST/redis.crt" "$CERT_DST/ca.crt"

exec redis-server "$@"
```

### 2.2 Create Dockerfile

**New file**: `services/redis/Dockerfile`

```dockerfile
FROM redis:7-alpine
COPY docker-entrypoint-tls.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint-tls.sh
ENTRYPOINT ["docker-entrypoint-tls.sh"]
```

### 2.3 Modify in docker-compose.yml

- Change `image:` → `build: ./services/redis`
- Add volume: `certs:/certs-source:ro`
- TLS command flags: `--tls-port 6379 --port 0 --tls-cert-file /certs/redis.crt --tls-key-file /certs/redis.key --tls-ca-cert-file /certs/ca.crt --tls-auth-clients no`
- Keep existing `--appendonly`, `--save`, `--requirepass` flags
- Update healthcheck: add `--tls --cacert /certs/ca.crt`
- Add `depends_on: vault-init`

### 2.4 Verify

```bash
docker compose up vault-bootstrap vault vault-init redis -d
redis-cli --tls --cacert ./certs/ca/trust/trust-bundle.pem \
          -a <password> -h localhost ping
# → PONG
```

---

## Step 3: LDAP TLS

### 3.1 Create custom entrypoint

**New file**: `services/ldap/docker-entrypoint-tls.sh`

The osixia/openldap image expects certs at `/container/service/slapd/assets/certs/`.

```bash
#!/bin/bash
set -e

CERT_SRC="/certs-source/ldap"
CA_SRC="/certs-source/ca/trust/trust-bundle.pem"
CERT_DST="/container/service/slapd/assets/certs"

mkdir -p "$CERT_DST"
cp "$CERT_SRC/ldap.crt" "$CERT_DST/ldap.crt"
cp "$CERT_SRC/ldap.key" "$CERT_DST/ldap.key"
cp "$CA_SRC"            "$CERT_DST/ca.crt"

chown -R openldap:openldap "$CERT_DST"
chmod 0600 "$CERT_DST/ldap.key"
chmod 0644 "$CERT_DST/ldap.crt" "$CERT_DST/ca.crt"

exec /container/tool/run "$@"
```

### 3.2 Create Dockerfile

**New file**: `services/ldap/Dockerfile`

```dockerfile
FROM osixia/openldap:1.5.0
COPY docker-entrypoint-tls.sh /custom-entrypoint.sh
RUN chmod +x /custom-entrypoint.sh
ENTRYPOINT ["/custom-entrypoint.sh"]
```

### 3.3 Modify in docker-compose.yml

- Change `image:` → `build: ./services/ldap`
- Add volume: `certs:/certs-source:ro`
- Set `LDAP_TLS: "true"`
- Add TLS env vars:
  - `LDAP_TLS_CRT_FILENAME: ldap.crt`
  - `LDAP_TLS_KEY_FILENAME: ldap.key`
  - `LDAP_TLS_CA_CRT_FILENAME: ca.crt`
  - `LDAP_TLS_VERIFY_CLIENT: try`
- Add `depends_on: vault-init`
- Keep `profiles: ["ldap"]`

### 3.4 Verify

```bash
docker compose --profile ldap up vault-bootstrap vault vault-init ldap -d
LDAPTLS_CACERT=./certs/ca/trust/trust-bundle.pem \
  ldapsearch -H ldaps://localhost:636 \
  -D "cn=admin,dc=akashic,dc=local" -w <password> \
  -b "dc=akashic,dc=local" -x
```

---

## Step 4: Loki TLS

### 4.1 Create custom entrypoint (if needed for permissions)

Loki runs as uid 10001. If the bind-mounted key is not readable, use the copy pattern.

**New file**: `services/loki/docker-entrypoint-tls.sh`

```bash
#!/bin/bash
set -e

CERT_SRC="/certs-source/loki"
CA_SRC="/certs-source/ca/trust/trust-bundle.pem"
MTLS_CA="/certs-source/ca/mtls/loki/loki-ca.crt"
CERT_DST="/certs"

mkdir -p "$CERT_DST"
cp "$CERT_SRC/loki.crt"  "$CERT_DST/loki.crt"
cp "$CERT_SRC/loki.key"  "$CERT_DST/loki.key"
cp "$CA_SRC"              "$CERT_DST/ca.crt"
cp "$MTLS_CA"             "$CERT_DST/mtls-ca.crt"

chown -R 10001:10001 "$CERT_DST"
chmod 0600 "$CERT_DST/loki.key"
chmod 0644 "$CERT_DST/loki.crt" "$CERT_DST/ca.crt" "$CERT_DST/mtls-ca.crt"

exec /usr/bin/loki "$@"
```

### 4.2 Create Dockerfile

**New file**: `services/loki/Dockerfile`

```dockerfile
FROM grafana/loki:3.5.5
USER root
COPY docker-entrypoint-tls.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint-tls.sh
ENTRYPOINT ["docker-entrypoint-tls.sh"]
CMD ["-config.file=/etc/loki/config.yml"]
```

### 4.3 Update loki/config.yml

Add to the `server:` block:

```yaml
server:
  http_listen_port: 3100
  http_tls_config:
    cert_file: /certs/loki.crt
    key_file: /certs/loki.key
    client_ca_file: /certs/mtls-ca.crt
    client_auth_type: RequestClientCert
```

### 4.4 Modify in docker-compose.yml

- Add `build: ./services/loki`
- Add volume: `certs:/certs-source:ro`
- Add `depends_on: vault-init`
- Keep `profiles: ["obs"]`

### 4.5 Verify

```bash
docker compose --profile obs up vault-bootstrap vault vault-init loki -d
curl --cacert ./certs/ca/trust/trust-bundle.pem \
     --cert ./certs/akashic/loki-client.crt \
     --key ./certs/akashic/loki-client.key \
     https://localhost:3100/ready
```

---

## Step 5: Vault Agent Sidecar

### 5.1 Add AppRole auth to vault-init — DONE

Already implemented in `services/vault/init/scripts/vault-init.sh` (Step 14) and
`services/vault/init/configs/policy/cert-issuer.hcl`.

Creates:
- `cert-issuer` policy (scoped to `pki-*/issue/*` + CA chain reads)
- AppRole auth method
- `cert-agent` role (token_period=768h, secret_id_ttl=0)
- Outputs `role-id` and `secret-id` to `/vault/token/vault-agent/`

### 5.2 Handle vault-init Step 12 handoff

**Strategy**: Add env var `SKIP_LEAF_CERTS`. When set, vault-init skips Steps 12–13 (leaf cert issuance + trust bundle). Vault Agent takes over.

When Vault Agent is NOT in the stack (e.g., minimal dev mode), `SKIP_LEAF_CERTS` is unset and vault-init issues certs as before.

### 5.3 Create Vault Agent config

**New file**: `services/vault-agent/config.hcl`

Key design: **one `template` block per service**, each outputting a cert+key bundle, with `command` calling `split-bundle.sh`.

```hcl
vault {
  address = "https://vault:8200"
  tls_config {
    ca_cert = "/certs/vault/root-ca.crt"
  }
}

auto_auth {
  method "approle" {
    config = {
      role_id_file_path   = "/vault-agent/auth/role-id"
      secret_id_file_path = "/vault-agent/auth/secret-id"
    }
  }
  sink "file" {
    config = { path = "/vault-agent/token" }
  }
}

# One template per service cert — outputs combined bundle
# split-bundle.sh splits into .crt and .key
template {
  contents    = "{{- with pkiCert \"pki-internal/issue/server\" \"common_name=postgres.akashic.local\" ... }}{{ .Cert }}{{ .CA }}{{ .Key }}{{- end -}}"
  destination = "/certs/postgres/postgres.bundle"
  command     = "/scripts/split-bundle.sh /certs/postgres/postgres"
}
# ... repeat for redis, ldap, loki, akashic/ctrl, akashic/auth
# ... repeat for mTLS certs from pki-mtls-* engines
```

### 5.4 Create split-bundle.sh

**New file**: `services/vault-agent/scripts/split-bundle.sh`

```bash
#!/bin/sh
# Usage: split-bundle.sh /certs/postgres/postgres
# Reads:  $1.bundle
# Writes: $1.crt (cert chain) and $1.key (private key)
BUNDLE="$1.bundle"
sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' "$BUNDLE" > "$1.crt"
sed -n '/BEGIN.*PRIVATE KEY/,/END.*PRIVATE KEY/p' "$BUNDLE" > "$1.key"
chmod 0644 "$1.crt"
chmod 0600 "$1.key"
```

### 5.5 Create Dockerfile and add to docker-compose

**New file**: `services/vault-agent/Dockerfile`

```dockerfile
FROM hashicorp/vault:1.20
COPY config.hcl /vault-agent/config.hcl
COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh
ENTRYPOINT ["vault", "agent", "-config=/vault-agent/config.hcl"]
```

**docker-compose.yml** addition:

```yaml
vault-agent:
  build: ./services/vault-agent
  container_name: akashic-vault-agent
  restart: unless-stopped
  depends_on:
    vault-init:
      condition: service_completed_successfully
  volumes:
    - certs:/certs
    - secrets:/vault-agent/auth:ro
  networks:
    default:
      aliases:
        - vault-agent.akashic.local
```

### 5.6 Verify

```bash
docker compose up vault-bootstrap vault vault-init vault-agent -d
# Check certs were issued:
openssl x509 -noout -subject -in ./certs/postgres/postgres.crt
# Verify cert/key match:
openssl x509 -noout -modulus -in ./certs/postgres/postgres.crt | md5
openssl rsa  -noout -modulus -in ./certs/postgres/postgres.key | md5
# Both hashes must match
```

---

## Step 6: Cert Watcher

### 6.1 Create watch script

**New file**: `services/cert-watcher/watch-certs.sh`

Uses `inotifywait` to watch cert directories. On change, signals containers via Docker socket.

**Signal strategy per service**:

| Service | Signal | Reason |
|---------|--------|--------|
| PostgreSQL | `SIGHUP` | Native SSL config reload |
| Redis | restart | No TLS hot-reload support |
| LDAP | restart | slapd doesn't reload certs on signal |
| Loki | restart | No TLS hot-reload support |

```bash
#!/bin/sh
# Debounce: wait 5s after last change before signaling
inotifywait -m -r -e close_write /certs/ |
while read dir action file; do
  case "$dir" in
    */postgres/*) docker kill --signal SIGHUP akashic-postgres ;;
    */redis/*)    docker restart akashic-redis ;;
    */ldap/*)     docker restart akashic-ldap ;;
    */loki/*)     docker restart akashic-loki ;;
  esac
done
```

(Production version should add debouncing and error handling.)

### 6.2 Create Dockerfile

**New file**: `services/cert-watcher/Dockerfile`

```dockerfile
FROM docker:cli
RUN apk add --no-cache inotify-tools bash
COPY watch-certs.sh /scripts/
RUN chmod +x /scripts/watch-certs.sh
ENTRYPOINT ["/scripts/watch-certs.sh"]
```

### 6.3 Add to docker-compose.yml

```yaml
cert-watcher:
  build: ./services/cert-watcher
  container_name: akashic-cert-watcher
  restart: unless-stopped
  depends_on:
    vault-agent:
      condition: service_started
  volumes:
    - certs:/certs:ro
    - /var/run/docker.sock:/var/run/docker.sock
```

### 6.4 Verify end-to-end rotation

1. Start full stack
2. Reduce a cert TTL to 5m for testing
3. Wait for Vault Agent to renew
4. Observe cert-watcher logs → signals container
5. Verify service is using new cert (check serial number)

---

## Step 7: Final Topology

### Dependency chain

```
vault-bootstrap
    └─→ vault (healthy)
          └─→ vault-init (completed)
                ├─→ vault-agent (started, issues certs)
                │     └─→ cert-watcher
                └─→ proxy

vault-agent certs ready
    ├─→ postgres
    ├─→ redis
    ├─→ ldap (profile: ldap)
    └─→ loki (profile: obs)
```

### New volumes

```yaml
volumes:
  pg_certs:     # (removed — entrypoint uses tmpfs or inline copy)
  # All services use certs:/certs-source:ro + internal copy
```

### Service entrypoint wait-for-certs pattern

Each service entrypoint should poll for its cert file before starting:

```bash
echo "Waiting for certificates..."
while [ ! -f "/certs-source/postgres/postgres.crt" ]; do sleep 1; done
```

This handles the race between vault-agent issuing certs and the service starting.

---

## Files Summary

### New files (14)

| File | Purpose |
|------|---------|
| `services/postgres/Dockerfile` | Custom image with TLS entrypoint |
| `services/postgres/docker-entrypoint-tls.sh` | Copy certs, fix perms, start postgres |
| `services/redis/Dockerfile` | Custom image with TLS entrypoint |
| `services/redis/docker-entrypoint-tls.sh` | Copy certs, fix perms, start redis |
| `services/ldap/Dockerfile` | Custom image with TLS entrypoint |
| `services/ldap/docker-entrypoint-tls.sh` | Copy certs, chown to openldap, start slapd |
| `services/loki/Dockerfile` | Custom image with TLS entrypoint |
| `services/loki/docker-entrypoint-tls.sh` | Copy certs, fix perms, start loki |
| `services/vault-agent/Dockerfile` | Vault Agent sidecar image |
| `services/vault-agent/config.hcl` | Agent config with pkiCert templates |
| `services/vault-agent/scripts/split-bundle.sh` | Split cert+key bundles |
| `services/cert-watcher/Dockerfile` | inotifywait + Docker CLI |
| `services/cert-watcher/watch-certs.sh` | Watch certs, signal containers |
| `services/vault/init/configs/policy/cert-issuer.hcl` | Vault policy for agent |

### Modified files (5)

| File | Change |
|------|--------|
| `docker-compose.yml` | Uncomment services, add vault-agent + cert-watcher, update deps |
| `services/vault/init/scripts/vault-init.sh` | Add Step 14 (AppRole), conditional Step 12 skip |
| `loki/config.yml` | Add TLS server config |
| `pkg/config/types.go` | Add TLS fields to Redis/Postgres/LDAP config structs |
| `configs/config.yaml` | Add TLS config values (prep for Phase 4) |

---

## Known Risks

| Risk | Mitigation |
|------|-----------|
| Service starts before cert exists | Wait-for-certs loop in entrypoint |
| Docker socket in cert-watcher = root equivalent | Acceptable for dev; replace in production |
| Redis has no TLS hot-reload | Graceful restart (30-day TTL = rare) |
| osixia/openldap 1.5.0 TLS quirks | Test thoroughly, set `LDAP_TLS_PROTOCOL_MIN: "3.3"` |
| Vault Agent AppRole secret-id expires | Set `secret_id_ttl=0` (non-expiring) |
| Grafana datasource needs mTLS to Loki | Update provisioning config to use HTTPS + client certs |
