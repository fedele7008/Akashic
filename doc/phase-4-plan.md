# Phase 4: Akashic Go Server — TLS Integration, Cert Reload, and Containerization

## Context

Phase 3 delivered a fully TLS-enabled dependency stack on Docker:

- **Vault PKI** with `pki-root`, `pki-internal`, `pki-public`, `pki-mtls-akashic-ctrl`
- **Vault Agent** issuing + auto-renewing server certs for `postgres`, `redis`, `ldap`, `loki-proxy`
  via `writeToFile` templates (atomic cert/key output, no bundle-split hack)
- **Cert watchers** per service with soft-reload strategies:
  - postgres → `pg_ctl reload` (SIGHUP)
  - redis → `CONFIG SET` (hot-reload of TLS paths)
  - ldap → `ldapmodify` to `cn=config` + `kill $SLAPD_PID` (s6 respawn)
  - loki → internal SIGHUP to Loki process (no container restart)
  - loki-proxy → `nginx -s reload`
- **TLS toggles** per service driven by `AKASHIC_*_TLS=on|off` env vars
- **Loki-proxy** redesign: Loki runs plain HTTP internally; a dedicated nginx sidecar
  terminates TLS and is the only thing `127.0.0.1:3100` points at. The Akashic server
  never talks directly to the Loki container.
- **AKASHIC_LOKI_API_URL** auto-derived by the Go config loader from
  `AKASHIC_LOKI_PROXY_TLS` + `HOST` + `HOST_PORT`, so one toggle flips the scheme.

What Phase 3 did **not** touch:

- The Akashic Go server itself. Its Postgres / Redis / LDAP / Loki clients do not yet
  know how to dial TLS endpoints based on env vars.
- The Akashic server's own TLS listeners (control + auth). Vault-init Step 12 drops
  static certs at `certs/akashic/{auth,ctrl,mtls-ctrl}.{crt,key}`, but those never
  renew, and the server doesn't pick up rotated certs if they ever did.
- Running Akashic inside docker-compose alongside the dependencies.

**Goal of Phase 4**: make the Akashic Go server a first-class citizen of the TLS
stack — consuming the Phase 3 toggles, serving on Vault-Agent-issued certs that
rotate in place, optionally watching certs for reload, and (optionally) running
inside the compose stack.

---

## Lessons from Phase 3 That Apply Here

These are non-obvious constraints we learned the hard way. They shape Phase 4:

| Lesson | Consequence for Phase 4 |
|---|---|
| `pkiCert` called twice generates independent key pairs → cert/key mismatch | One `pkiCert` block per akashic service; split via `writeToFile`, not separate templates |
| `crypto/tls.Config.Certificates` is evaluated once at listener creation | Use `tls.Config.GetCertificate` callback backed by an atomic pointer; no listener restart needed on rotation |
| Atomic replace (`cp X.tmp && mv X.tmp X`) avoids torn reads during rotation | Cert-reloader must use the same pattern on the watcher side (read cert+key together, swap atomically) |
| Host binding on `127.0.0.1:3100` means host-run Akashic works today | Containerized Akashic must preserve the ability to reach services by their docker-network aliases (`postgres.akashic.local`, etc.), not the host-bound ports |
| Separating Loki (plain HTTP) from loki-proxy (TLS) | Akashic's Loki writer keeps pointing at the proxy URL, not Loki directly. No special-casing needed. |
| `AKASHIC_LOKI_PROXY_TLS` toggles scheme automatically via Go config | All other services should follow the **same convention**: `AKASHIC_<SVC>_TLS=on\|off` drives the Go client's TLS decision |

---

## Execution Order

```
Step 1: Go config surface         ← add TLS fields + env → struct wiring for every client
Step 2: Go client TLS integration ← postgres, redis, ldap, loki writer consume the new fields
Step 3: Akashic server certs      ← Vault Agent takes over akashic-ctrl / akashic-auth / mtls
Step 4: Cert reloader (pkg/pki)   ← GetCertificate callback, atomic pointer swap
Step 5: Optional cert watcher     ← opt-in inotify/fsnotify trigger, toggleable via env
Step 6: Containerize Akashic      ← Dockerfile + compose service, host-run still supported
Step 7: End-to-end verification   ← TLS on → TLS off → rotation → Grafana shows logs
```

Steps 1–2 are pure Go changes and can be merged independently. Step 3 changes
Vault Agent output paths and must land together with Step 4 (reloader expects the
new paths). Steps 5–6 are additive. Step 7 is the gate.

---

## Step 1: Go Config Surface — Read TLS on/off from .env

### 1.1 Extend `DatabaseConfig`

**File**: `pkg/config/types.go`

Add sibling `TLS` blocks to Postgres and Redis config structs so each has its own
toggle and CA-bundle path:

```go
type PostgresConfig struct {
    Host     string `mapstructure:"host"      yaml:"host"`
    Port     int    `mapstructure:"port"      yaml:"port"`
    Database string `mapstructure:"database"  yaml:"database"`
    Username string `mapstructure:"username"  yaml:"username"`
    Password string `mapstructure:"password"  yaml:"password"`

    // TLS toggle (driven by AKASHIC_POSTGRES_TLS=on|off, same convention as Phase 3)
    TLS PostgresTLSConfig `mapstructure:"tls" yaml:"tls"`
}

type PostgresTLSConfig struct {
    Enabled    bool   `mapstructure:"enabled"     yaml:"enabled"`      // AKASHIC_DATABASE_POSTGRES_TLS_ENABLED
    CACertPath string `mapstructure:"ca_cert"     yaml:"ca_cert"`      // path to Vault root CA bundle
    ServerName string `mapstructure:"server_name" yaml:"server_name"`  // defaults to Host
    // VerifyFull vs VerifyCA vs Require — mirror pg sslmode. Start with VerifyFull.
    Mode       string `mapstructure:"mode"        yaml:"mode"`         // verify-full | verify-ca | require
}
```

Same shape for Redis (`RedisTLSConfig`) and a new `LokiTLSConfig` if we want an
explicit CA path (the scheme is already auto-derived, but TLS verification needs
the CA bundle in-process).

### 1.2 Convert existing `LdapConfig.UseTLS` to the same pattern

**File**: `pkg/config/types.go`

The LDAP config already has `UseTLS` and `TLSSkipVerify`. Promote them to a
nested struct for consistency:

```go
type LdapConfig struct {
    Host     string          `mapstructure:"host"`
    Port     int             `mapstructure:"port"`
    // ...
    TLS      LdapTLSConfig   `mapstructure:"tls" yaml:"tls"`
}

type LdapTLSConfig struct {
    Enabled    bool   `mapstructure:"enabled"`     // was UseTLS
    SkipVerify bool   `mapstructure:"skip_verify"` // was TLSSkipVerify
    CACertPath string `mapstructure:"ca_cert"`
    Mode       string `mapstructure:"mode"`        // ldaps | starttls | plain
}
```

Keep a deprecation shim that maps the old `use_tls` / `tls_skip_verify` keys to the
new struct for one release, so existing `configs/config.yaml` doesn't break.

### 1.3 Env-var bindings + defaults

**Files**: `pkg/config/defaults.go`, `pkg/config/flags.go`, `.env.example`

For each new field, register a default in `setDefaults(v)` and a Viper binding so
`AKASHIC_DATABASE_POSTGRES_TLS_ENABLED`, `AKASHIC_DATABASE_REDIS_TLS_ENABLED`,
`AKASHIC_LDAP_TLS_ENABLED`, and `AKASHIC_LOKI_PROXY_TLS` all unmarshal cleanly.

Add a helper that accepts the Phase 3-style `on|off` values so the Go side uses
the exact same strings as the docker scripts:

```go
func parseOnOff(s string) bool {
    return strings.EqualFold(strings.TrimSpace(s), "on")
}
```

Use it via a custom mapstructure decode hook so any `bool`-typed TLS field can
be set from the string "on"/"off" in YAML or env, not just `true`/`false`.

### 1.4 Mirror the Loki scheme-derivation pattern

**File**: `pkg/config/config_manager.go`

The `AKASHIC_LOKI_API_URL` derivation in `NewConfigManager` (lines 72–89) is the
template. Do the same for `postgres`, `redis`, `ldap`, **but only for the CA cert
path**, not a full URL — because only Loki needs a URL derived; the others just
need to know whether to dial TLS. Example:

```go
// AKASHIC_DATABASE_POSTGRES_TLS_CA_CERT auto-defaults to /etc/akashic/certs/ca.crt
// when running in the container, or ./certs/ca/... when running from host.
```

Pick the default based on detecting container mode (e.g. `os.Stat("/.dockerenv")`).

### 1.5 Validation

**File**: `pkg/config/config_manager.go`, `validateConfig`

If `TLS.Enabled` is true but `CACertPath` doesn't exist, fail at startup with a
clear error. Do **not** silently fall back to plaintext — Phase 3's design
principle is "TLS on means TLS on, everywhere".

### 1.6 Verify

```bash
# Unit test: AKASHIC_DATABASE_POSTGRES_TLS_ENABLED=on → config.Database.Postgres.TLS.Enabled==true
go test ./pkg/config -run TestTLSToggleFromEnv -v
```

---

## Step 2: Go Client TLS Integration

Now that the config knows the intent, wire it into the actual client dialers.

### 2.1 Postgres (`pkg/database/akashic_postgres/`)

The connection is likely via `pgx` or `lib/pq`. Extend the DSN builder:

```go
func buildDSN(cfg *PostgresConfig) string {
    sslmode := "disable"
    if cfg.TLS.Enabled {
        switch cfg.TLS.Mode {
        case "verify-full": sslmode = "verify-full"
        case "verify-ca":   sslmode = "verify-ca"
        default:            sslmode = "require"
        }
    }
    return fmt.Sprintf(
        "host=%s port=%d user=%s password=%s dbname=%s sslmode=%s sslrootcert=%s",
        cfg.Host, cfg.Port, cfg.Username, cfg.Password, cfg.Database,
        sslmode, cfg.TLS.CACertPath,
    )
}
```

Important: **do not** pass `sslrootcert` when TLS is off — some driver versions
choke on the file check.

### 2.2 Redis (`pkg/database/akashic_redis/`)

`go-redis/v9` accepts a `TLSConfig *tls.Config` on the options struct:

```go
opts := &redis.Options{
    Addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
    Password: cfg.Password,
}
if cfg.TLS.Enabled {
    caPool, err := loadCAPool(cfg.TLS.CACertPath)
    if err != nil { return nil, err }
    opts.TLSConfig = &tls.Config{
        RootCAs:    caPool,
        ServerName: firstNonEmpty(cfg.TLS.ServerName, cfg.Host),
        MinVersion: tls.VersionTLS12,
    }
}
```

Phase 3 sets `redis --tls-port 6379 --port 0` when TLS is on (plain port
disabled). With `AKASHIC_REDIS_TLS=off`, redis listens on port 6379 unencrypted.
The Go client reads the same env var, so both ends toggle in sync.

### 2.3 LDAP (`pkg/ldap/client.go`)

The current `Connect()` uses `ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(...))`.
Switch on the new `TLS.Mode`:

```go
switch cfg.TLS.Mode {
case "ldaps":     // dial ldaps:// directly
case "starttls":  // dial ldap://, then Conn.StartTLS(tlsCfg)
case "plain":     // no TLS (dev/embedded profile only)
}
```

The existing `InitializeStructure()` and `CreateUser()` code stays unchanged —
only the dial phase cares about TLS mode.

### 2.4 Loki writer (`pkg/logging/loki_writer.go`)

The writer already uses `AKASHIC_LOKI_API_URL` (auto-derived). Phase 4 adds: if
the URL scheme is `https`, build an `http.Transport` with a `TLSClientConfig`
loaded from the CA bundle. This is the one spot where we **must** verify, because
the loki-proxy presents a cert issued by `pki-internal`.

```go
transport := &http.Transport{}
if strings.HasPrefix(apiURL, "https://") {
    caPool, _ := loadCAPool(cfg.TLSCACertPath)
    transport.TLSClientConfig = &tls.Config{
        RootCAs:    caPool,
        ServerName: "loki.akashic.local", // alias served by loki-proxy
    }
}
```

### 2.5 Verify

```bash
# With AKASHIC_*_TLS=on on all four services
go run ./cmd/akashic run --verbose 2>&1 | grep -iE 'tls|ssl|https' | head -20
# Should see: Postgres connecting via SSL, Redis TLS handshake OK, LDAP LDAPS bind OK, Loki POST over HTTPS

# Flip one to off and restart dependencies accordingly
export AKASHIC_REDIS_TLS=off
docker compose up -d redis
go run ./cmd/akashic run --verbose  # should now dial plain Redis
```

---

## Step 3: Vault Agent Issues Akashic Server Certs

Today `certs/akashic/` is populated by vault-init Step 12 (static, non-rotating).
Move issuance into Vault Agent so the Akashic server gets the same rotation
treatment as the dependency services.

### 3.1 Add templates for Akashic server certs

**New files**: `services/vault-agent/templates/akashic-ctrl.tpl`,
`services/vault-agent/templates/akashic-auth.tpl`

Following the existing `postgres.tpl` pattern exactly (single `pkiCert`, three
`writeToFile` calls):

```gotemplate
{{- with pkiCert "pki-internal/issue/server"
  "common_name=ctrl.akashic.local"
  "alt_names=ctrl.akashic.local,localhost,akashic-server"
  "ip_sans=127.0.0.1"
  "ttl=720h" -}}
{{ .Key  | writeToFile "/certs/akashic/ctrl.key" "root" "root" "0600" }}
{{ .Cert | writeToFile "/certs/akashic/ctrl.crt" "root" "root" "0644" }}
{{ join "" .CAChain | printf "%s\n" | writeToFile "/certs/akashic/ca.crt" "root" "root" "0644" }}
{{- end -}}
```

Repeat for `auth.akashic.local` with whatever extra SANs are appropriate (public
DNS name in production).

### 3.2 Add templates for mTLS control-server cert

**New file**: `services/vault-agent/templates/akashic-mtls-ctrl.tpl`

The control server uses the `pki-mtls-akashic-ctrl` engine — a private CA just
for the management-plane mTLS relationship. Issue from there, not pki-internal:

```gotemplate
{{- with pkiCert "pki-mtls-akashic-ctrl/issue/server"
  "common_name=akashic-ctrl-mtls"
  "alt_names=ctrl.akashic.local,localhost"
  "ip_sans=127.0.0.1"
  "ttl=720h" -}}
{{ .Key  | writeToFile "/certs/akashic/mtls-ctrl.key" "root" "root" "0600" }}
{{ .Cert | writeToFile "/certs/akashic/mtls-ctrl.crt" "root" "root" "0644" }}
{{ join "" .CAChain | printf "%s\n" | writeToFile "/certs/akashic/mtls-ca.crt" "root" "root" "0644" }}
{{- end -}}
```

### 3.3 Add templates for mTLS client certs (akashic-cli, bff)

**New files**: `services/vault-agent/templates/akashic-cli-client.tpl`,
`services/vault-agent/templates/bff-client.tpl`

Issue from `pki-mtls-akashic-ctrl/issue/client`. Output to `certs/akashic-cli/`
and `certs/bff/` respectively. Same writeToFile pattern.

### 3.4 Register templates in `config.hcl`

**File**: `services/vault-agent/config.hcl`

Add five new `template` blocks (ctrl, auth, mtls-ctrl, cli-client, bff-client)
with destinations at `/certs/<dir>/.rendered` (matching the existing convention).

### 3.5 Update vault-init Step 12 to skip akashic certs when Vault Agent is active

**File**: `services/vault/init/scripts/vault-init.sh`

Step 12 already issues the dependency certs statically for non-Vault-Agent dev
setups. Extend its `SKIP_LEAF_CERTS` or add a narrower `SKIP_AKASHIC_CERTS` flag
so Vault Agent's issuance doesn't race with Step 12's. Simpler: once we've made
this commitment, remove akashic cert issuance from vault-init entirely — the
Agent is now the only producer.

### 3.6 Verify

```bash
./scripts/reset-vault.sh   # nuke everything
docker compose up -d vault-bootstrap vault vault-init vault-agent

# Wait for agent to render
sleep 10
openssl x509 -noout -subject -issuer -dates -in ./certs/akashic/ctrl.crt
openssl x509 -noout -subject -issuer -dates -in ./certs/akashic/mtls-ctrl.crt
# Verify cert/key modulus match
openssl x509 -noout -modulus -in ./certs/akashic/ctrl.crt | md5
openssl rsa  -noout -modulus -in ./certs/akashic/ctrl.key | md5
```

---

## Step 4: Cert Reloader (`pkg/pki/`)

This is where we finally create the `pkg/pki/` package that `CLAUDE.md` has been
documenting aspirationally. Start narrow — one thing, done well: a hot-swappable
certificate provider for `tls.Config.GetCertificate`.

### 4.1 Create `pkg/pki/cert_reloader.go`

```go
package pki

import (
    "crypto/tls"
    "fmt"
    "sync/atomic"
)

// Reloader holds an atomic pointer to the current tls.Certificate.
// Use (*Reloader).GetCertificate as tls.Config.GetCertificate — each TLS
// handshake reads the pointer, so rotation is zero-downtime.
type Reloader struct {
    certPath string
    keyPath  string
    current  atomic.Pointer[tls.Certificate]
}

func NewReloader(certPath, keyPath string) (*Reloader, error) {
    r := &Reloader{certPath: certPath, keyPath: keyPath}
    if err := r.Reload(); err != nil {
        return nil, fmt.Errorf("initial cert load: %w", err)
    }
    return r, nil
}

func (r *Reloader) Reload() error {
    cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
    if err != nil {
        return fmt.Errorf("load keypair %s/%s: %w", r.certPath, r.keyPath, err)
    }
    r.current.Store(&cert)
    return nil
}

func (r *Reloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
    c := r.current.Load()
    if c == nil {
        return nil, fmt.Errorf("cert not loaded yet")
    }
    return c, nil
}
```

Why `atomic.Pointer[tls.Certificate]`? — A handshake can happen in any goroutine
and we need lock-free reads. The `Store`/`Load` pair provides the happens-before
relationship so the new cert is fully constructed before readers see it.

### 4.2 Wire into control server

**File**: `pkg/server/control/server.go`

```go
reloader, err := pki.NewReloader(cfg.TLS.CertFile, cfg.TLS.KeyFile)
if err != nil { return err }
s.certReloader = reloader

tlsConfig := &tls.Config{
    MinVersion:     tls.VersionTLS13,
    GetCertificate: reloader.GetCertificate, // replaces Certificates field
    ClientAuth:     tls.RequireAndVerifyClientCert,
    ClientCAs:      mtlsCAPool,
}
```

The same reloader gets exposed via `s.ReloadCert()` so the optional watcher
(Step 5) or a manual `POST /config/reload` endpoint can poke it.

### 4.3 Wire into auth server

**File**: `pkg/server/auth/server.go`

Same pattern with `cfg.Server.Auth.TLS.CertFile/KeyFile`. Auth server is
public-facing and does **not** require client certs, so `ClientAuth` is
`tls.NoClientCert`.

### 4.4 Expose reload on the control plane

**File**: `pkg/server/control/handlers.go`

Add `POST /tls/reload` that calls `authServer.ReloadCert()` and
`ctrlServer.ReloadCert()`. This is the manual fallback if the watcher is
disabled — you can still rotate without a restart by curling the endpoint.

### 4.5 Verify

```bash
# Start server
go run ./cmd/akashic run --verbose &

# Check old cert serial
echo | openssl s_client -connect localhost:8080 2>/dev/null | openssl x509 -noout -serial

# Force Vault Agent to re-issue (delete .rendered marker or lower TTL)
rm ./certs/akashic/.rendered
docker compose restart vault-agent
sleep 10

# Trigger reload
curl -X POST http://localhost:8081/tls/reload

# Verify new serial
echo | openssl s_client -connect localhost:8080 2>/dev/null | openssl x509 -noout -serial
```

---

## Step 5: Optional In-Process Cert Watcher

The Phase 3 pattern is shell-level inotifywait scripts per container. For the
Akashic Go server running in-process, the equivalent is `fsnotify`. Keep it
opt-in so users who don't want a background goroutine reading the FS can turn it
off.

### 5.1 Config flag

**File**: `pkg/config/types.go`

```go
type PKIConfig struct {
    // ... existing fields from CLAUDE.md ...

    // CertWatcherEnabled enables an in-process fsnotify watcher that calls
    // Reloader.Reload() when cert/key files change on disk. Safe to disable
    // — rotation still works via POST /tls/reload or process restart.
    CertWatcherEnabled bool `mapstructure:"cert_watcher_enabled" yaml:"cert_watcher_enabled"`
}
```

Env var: `AKASHIC_PKI_CERT_WATCHER_ENABLED=true|false`. Default **true** (safer
— you get hands-off rotation out of the box).

### 5.2 Create `pkg/pki/cert_watcher.go`

```go
package pki

import (
    "context"
    "path/filepath"

    "github.com/fsnotify/fsnotify"
)

type Watcher struct {
    reloader *Reloader
    watcher  *fsnotify.Watcher
    paths    []string // dirs to watch
}

func NewWatcher(r *Reloader) (*Watcher, error) {
    w, err := fsnotify.NewWatcher()
    if err != nil { return nil, err }
    dirs := uniqueDirs(r.certPath, r.keyPath)
    for _, d := range dirs {
        if err := w.Add(d); err != nil {
            w.Close()
            return nil, err
        }
    }
    return &Watcher{reloader: r, watcher: w, paths: dirs}, nil
}

func (w *Watcher) Run(ctx context.Context) {
    for {
        select {
        case <-ctx.Done():
            w.watcher.Close()
            return
        case ev := <-w.watcher.Events:
            // Vault Agent writes via rename (tmp → target) → watch Create/Rename events
            if ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename) == 0 { continue }
            if filepath.Base(ev.Name) != filepath.Base(w.reloader.certPath) &&
               filepath.Base(ev.Name) != filepath.Base(w.reloader.keyPath) { continue }
            // Debounce: wait for key+cert to both settle
            debouncedReload(w.reloader)
        }
    }
}
```

Important: Vault Agent writes `.crt` and `.key` in sequence, **not atomically
together**. Debounce for ~500ms after the last relevant event before calling
`Reload()` — otherwise you risk reloading a new cert paired with the old key
(mismatched modulus = handshake failure).

### 5.3 Lifecycle wiring

**File**: `pkg/akashic/context.go`

```go
if cfg.PKI.CertWatcherEnabled {
    watcher, err := pki.NewWatcher(reloader)
    if err != nil { return fmt.Errorf("cert watcher: %w", err) }
    go watcher.Run(ctx)
    app.AddCloser(func() error { return watcher.Close() })
}
```

### 5.4 Verify

```bash
# Watcher on (default)
AKASHIC_PKI_CERT_WATCHER_ENABLED=true go run ./cmd/akashic run --verbose &

# Force a reissue; observe log line "cert reloaded, new serial=..."
# Without manual POST /tls/reload

# Watcher off — confirm it's a clean no-op
AKASHIC_PKI_CERT_WATCHER_ENABLED=false go run ./cmd/akashic run --verbose &
# Rotation now requires POST /tls/reload or restart
```

---

## Step 6: Containerize Akashic

Host-run must keep working. The container is an **additional** deployment
option, not a replacement.

### 6.1 Dockerfile

**New file**: `services/akashic/Dockerfile`

Multi-stage build — tiny final image, full toolchain only at build time:

```dockerfile
FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/akashic ./cmd/akashic

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /out/akashic /usr/local/bin/akashic
# Certs mounted at /certs, config at /etc/akashic
ENTRYPOINT ["/usr/local/bin/akashic"]
CMD ["run"]
```

### 6.2 Compose service

**File**: `docker-compose.yml`

```yaml
akashic:
  build: ./services/akashic
  container_name: akashic-server
  depends_on:
    postgres:    { condition: service_healthy }
    redis:       { condition: service_healthy }
    ldap:        { condition: service_healthy, required: false }  # ldap profile
    loki-proxy:  { condition: service_healthy, required: false }  # obs profile
    vault-agent: { condition: service_started }
  environment:
    # Re-use the same env vars from .env; no duplication
    AKASHIC_DATABASE_POSTGRES_HOST: postgres.akashic.local
    AKASHIC_DATABASE_REDIS_HOST:    redis.akashic.local
    AKASHIC_LDAP_HOST:              ldap.akashic.local
    AKASHIC_LOKI_PROXY_HOST:        loki.akashic.local
    # TLS toggles already in .env
  volumes:
    - certs:/certs:ro                        # cert-watcher can see rotations
    - ./configs/config.yaml:/etc/akashic/config.yaml:ro
  ports:
    - "${AKASHIC_AUTH_HOST_PORT:-8080}:8080"
    - "127.0.0.1:${AKASHIC_CTRL_HOST_PORT:-8081}:8081"
  profiles: ["app"]   # opt-in profile, host-run is still the default
```

### 6.3 Host-run vs container-run parity

Two concerns:

1. **Cert paths**. Host-run reads `./certs/akashic/ctrl.crt`. Container reads
   `/certs/akashic/ctrl.crt`. Make the default come from a helper:

   ```go
   func defaultCertDir() string {
       if _, err := os.Stat("/.dockerenv"); err == nil { return "/certs" }
       return "./certs"
   }
   ```

2. **Service hosts**. Host-run uses `localhost:<host-port>`. Container uses
   docker-network aliases. The `AKASHIC_*_HOST` env vars in `.env.example`
   already point at localhost for host-run; the compose `environment:` block
   above overrides them to docker aliases for container-run. No code changes.

### 6.4 Verify

```bash
# Container-run
docker compose --profile app up -d akashic
docker logs -f akashic-server
curl -k https://localhost:8080/health   # through container TLS listener

# Host-run (unchanged from today)
docker compose --profile app down akashic
go run ./cmd/akashic run --verbose
```

---

## Step 7: End-to-End Verification

The gate for Phase 4 is a full lifecycle test with zero manual intervention.

### 7.1 Full-stack TLS on

```bash
./scripts/reset-vault.sh
# .env has all *_TLS=on
docker compose --profile ldap --profile obs --profile app up -d
sleep 30  # let vault-agent issue + akashic boot

# Check every hop is TLS
docker logs akashic-server 2>&1 | grep -iE 'connected|tls' | head
curl -k https://localhost:8080/health                              # Auth server TLS
curl -k --cert ./certs/akashic-cli/akashic-ctrl-client.crt \
       --key  ./certs/akashic-cli/akashic-ctrl-client.key \
       https://localhost:8081/status                               # Control server mTLS
```

### 7.2 Observability: Grafana sees akashic logs

Grafana datasource is already provisioned in Phase 3. Just verify the pipeline:

```bash
open http://localhost:3000  # Grafana
# Explore → Loki → {service="akashic"} → see app + security + audit channels
```

### 7.3 Rotation with watcher enabled

```bash
# Lower TTLs in vault-agent templates to 5m for test, restart vault-agent
# Observe akashic logs: "cert reloaded, old serial=X, new serial=Y"
# Verify new serial visible on the listener
echo | openssl s_client -connect localhost:8080 2>/dev/null | openssl x509 -noout -serial
```

### 7.4 Rotation with watcher disabled

```bash
# AKASHIC_PKI_CERT_WATCHER_ENABLED=false, restart akashic
# Force reissue
curl -X POST --cert ... --key ... https://localhost:8081/tls/reload
# Serial should update
```

### 7.5 Toggle one dependency to TLS off

```bash
# Set AKASHIC_REDIS_TLS=off in .env
docker compose up -d redis   # redis restarts in plain mode
docker compose restart akashic  # picks up new env
docker logs akashic-server | grep -i redis   # no TLS handshake, plain ping OK
```

---

## Files Summary

### New files (14)

| File | Purpose |
|---|---|
| `services/vault-agent/templates/akashic-ctrl.tpl` | Issue control-server cert |
| `services/vault-agent/templates/akashic-auth.tpl` | Issue auth-server cert |
| `services/vault-agent/templates/akashic-mtls-ctrl.tpl` | Issue mTLS control-server cert |
| `services/vault-agent/templates/akashic-cli-client.tpl` | Issue CLI client cert |
| `services/vault-agent/templates/bff-client.tpl` | Issue BFF client cert |
| `services/akashic/Dockerfile` | Multi-stage build for containerized Akashic |
| `pkg/pki/cert_reloader.go` | Atomic cert pointer + `GetCertificate` callback |
| `pkg/pki/cert_watcher.go` | Optional fsnotify-based watcher with debounce |
| `pkg/pki/ca.go` | `loadCAPool(path) (*x509.CertPool, error)` helper |
| `pkg/pki/pki_test.go` | Unit tests (cert swap, watcher triggers, mismatched-key debouncing) |

### Modified files (12)

| File | Change |
|---|---|
| `pkg/config/types.go` | Add `PostgresTLSConfig`, `RedisTLSConfig`, `LdapTLSConfig`, `LokiTLSConfig`, `PKIConfig.CertWatcherEnabled` |
| `pkg/config/defaults.go` | Defaults for all new TLS fields |
| `pkg/config/config_manager.go` | on/off decode hook, CA-path auto-derivation, validation |
| `pkg/database/akashic_postgres/*.go` | Build DSN with `sslmode` from `TLS.Mode` |
| `pkg/database/akashic_redis/*.go` | Set `redis.Options.TLSConfig` when enabled |
| `pkg/ldap/client.go` | Switch on `TLS.Mode` (ldaps/starttls/plain) |
| `pkg/logging/loki_writer.go` | `http.Transport` with TLS config when URL is https |
| `pkg/server/control/server.go` | Use `GetCertificate` callback, expose `ReloadCert()` |
| `pkg/server/auth/server.go` | Use `GetCertificate` callback |
| `pkg/server/control/handlers.go` | `POST /tls/reload` endpoint |
| `pkg/akashic/context.go` | Start cert watcher goroutine when enabled |
| `services/vault-agent/config.hcl` | Register 5 new akashic templates |
| `services/vault/init/scripts/vault-init.sh` | Stop issuing akashic certs in Step 12 |
| `docker-compose.yml` | Add `akashic` service under `profiles: ["app"]` |
| `.env.example` | Add `AKASHIC_PKI_CERT_WATCHER_ENABLED`, TLS toggles already exist |

---

## Known Risks

| Risk | Mitigation |
|---|---|
| Watcher reloads mid-rotation → cert/key modulus mismatch | Debounce 500ms; on mismatch, retry once |
| fsnotify on macOS via volume mount can miss events | Test specifically in container-run mode; fall back to POST /tls/reload |
| TLS on/off toggle inconsistency between Akashic and its dependency | Health check at startup verifies dial works both ways; fail fast |
| Container + host-run cert path drift | `defaultCertDir()` helper + `/.dockerenv` detection |
| mTLS CA changes without Akashic noticing | Reloader reloads `ClientCAs` too, not just server cert — Step 4.2 must swap both |
| Auth server cert rotation drops in-flight OAuth flows | `GetCertificate` callback only affects **new** handshakes; existing connections keep the old cert |
| Vault Agent race: writes .crt before .key | Watcher debounce handles this; also `Reload()` returns error on mismatched modulus so the old cert stays active |

---

## Non-Goals (Deferred to Phase 5+)

- **Graceful restart on fatal TLS error**. If `Reload()` consistently fails
  (e.g. corrupt files), we log loudly but keep serving the old cert. A separate
  orchestration story decides whether to restart the process.
- **OCSP stapling / CRL**. The `AKASHIC_PKI_CRL_BASE_URL` env is plumbed but not
  yet wired to a CRL endpoint. Phase 5.
- **HSM-backed CA private key**. Dev uses file storage; production hardening is
  a later concern.
- **Kubernetes deployment**. Phase 4 ends at docker-compose. Helm chart is a
  separate deliverable.
