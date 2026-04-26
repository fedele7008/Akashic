# Phase 6: Bootstrap Web UI — admin.akashic.&lt;domain&gt;

## Context

Phase 5 made bootstrap fully usable via `akashic-cli`. That covers the
"operator with shell access" persona. Phase 6 adds a parallel browser-
based path so an operator who only has a browser tab (e.g., on a hosted
deployment, or working from a corporate-managed laptop where running
binaries is hard) can complete bootstrap too.

This phase is deliberately scoped to **bootstrap only** — no login
flow, no admin dashboard, no user management. Those land in Phase 7.
Doing bootstrap first gives us a contained ~1-week deliverable that
proves out:

- React + Vite FE build → embedded via `embed.FS` into a Go binary
- Go BFF as the only browser-facing thing that holds an mTLS client cert
- nginx-proxy server block for `admin.akashic.<domain>`
- Cert rotation in the BFF using Phase 4's `pkg/pki` reloader
- Public-CA TLS termination at the proxy + private mTLS to control plane
- The "browser knows nothing about mTLS" property of the BFF pattern

Once these foundations exist on a small surface, Phase 7's much larger
admin dashboard becomes incremental rather than greenfield.

---

## Architectural Frame: Two Identity Primitives, Same Endpoint

The CLI and the web UI both ultimately call `POST /bootstrap/root` on
the control plane, but they get there through **different network
paths** authenticated by **different evidence**:

```
CLI path:
  akashic-cli ──HTTPS+mTLS(cli.akashic.local)──▶ control-server :8081
                                                  ↑ (loopback only)

Web UI path (two-level proxy chain — see Step 7 for detail):
  Browser
    │ HTTPS (public CA / Let's Encrypt)
    ▼
  Host nginx                  ← TLS terminator, runs on host (not docker)
    │ HTTP (loopback)
    ▼
  Docker nginx-proxy          ← subdomain router, existing Phase 3 service
    │ HTTP (docker network)
    ▼
  admin-bff                   ← Go BFF
    │ HTTPS+mTLS (bff.akashic.local)
    ▼
  control-server :8081
```

The control plane already accepts both CNs (`cli.akashic.local` and
`bff.akashic.local`) on `/bootstrap/root` — Phase 5 wired that up. So
the server side requires zero changes for Phase 6.

**Key invariants** (carried over from `phase-5-plan.md` §5.1):

1. The control plane never gets a public subdomain.
2. The browser never holds tokens, certs, or any privileged credential.
3. The BFF is the only browser-facing component that holds an mTLS
   client cert.

These invariants stay intact in Phase 6.

### What "trusting bootstrap token" means in practice

The browser-side identity primitive is the **bootstrap token** itself:
a 32-byte random value that the operator copies from server stdout/logs
and pastes into the form. The token already serves as identity — anyone
who possesses it gets to bootstrap exactly once. The mTLS layer (which
the browser doesn't speak) is what protects everything *else* on the
control plane; for the bootstrap endpoint specifically, the token alone
is sufficient evidence.

The BFF has its own mTLS cert because **the control plane** demands one
on every request, regardless of what the browser is doing. The BFF acts
as a trusted gateway that translates "browser sent a token over public
TLS" into "trusted infra component sent a token over mTLS", without the
token ever changing meaning.

---

## Threat Model: What's New vs. CLI

| Attack | CLI exposure | Web UI exposure | Mitigation |
|---|---|---|---|
| Network attacker on Internet hits the URL | n/a (loopback-bound) | endpoint reachable, but useless without token | 32-byte random token (2^256 keyspace) |
| Phishing — fake "akashic admin" page tricks operator | n/a (operator runs CLI locally) | possible via DNS spoofing or typo-domain | HSTS preload + clear branding + token-pasting confined to operator's session |
| Token leaked in operator's chat / email / browser history | possible (CLI users may copy token to chat) | similar — token still reaches operator's clipboard | TTL on token (default 1h); audit log of completion source |
| Replay of intercepted form POST | n/a | possible if attacker has packet capture (defeated by TLS); CSRF defeats cross-origin replay | TLS 1.2+ minimum; SameSite=Strict CSRF cookie |
| Browser extension scraping form fields | n/a | possible | CSP `default-src 'self'`; no third-party origins allowed |
| BFF-side privilege escalation (compromise of BFF binary) | n/a | attacker gets `bff.akashic.local` mTLS cert → full access to bootstrap endpoint family | BFF runs as non-root, cert rotation via Vault Agent, audit log every action |
| DoS on bootstrap form (fill the token bucket so legit ops can't get through) | per-CN bucket (just CLI) — small impact | per-CN bucket (`bff.akashic.local`) — shared by all browser users → big impact | **Source-IP rate limit at BFF layer**, in addition to control-plane per-CN rate limit |

That last row is the most important new constraint. Phase 5's rate
limiter buckets per cert CN. With one CN representing all browser
traffic, a single attacker sharing the BFF's bucket could DoS legit
operators. Phase 6 adds a **source-IP rate limit at the BFF layer** —
5 attempts per minute per browser IP, before the request is forwarded
to the control plane at all.

---

## Execution Order

```
Step 1: Project layout + admin-bff skeleton  ← Go service, zero handlers
Step 2: BFF mTLS plumbing                     ← cert load, reloader, control-plane client
Step 3: BFF API handlers (bootstrap proxy)    ← /api/bootstrap/{status,create-root}
Step 4: BFF security baseline                 ← CSRF, rate limit, headers, audit log
Step 5: React FE skeleton + Vite              ← bootstrap form, two-state UI
Step 6: Embed FE into Go binary               ← embed.FS, http.FileServer routing
Step 7: nginx-proxy + docker-compose          ← admin.akashic.<domain> routing
Step 8: End-to-end verification               ← from browser → root user created
```

Steps 1–4 are pure backend. Steps 5–6 are pure frontend. Step 7 is the
deployment glue. They can be developed in roughly any order but the
listed order is what makes integration smoothest.

---

## Step 1: Project Layout + admin-bff Skeleton

### 1.1 New top-level directories

```
services/admin-bff/
├── Dockerfile                 ← multi-stage: node build + go build + alpine runtime
└── README.md

cmd/admin-bff/
└── main.go                    ← entry point; small wrapper around pkg/admin_bff

pkg/admin_bff/
├── server.go                  ← HTTP listener + middleware chain
├── handlers.go                ← /api/* handlers
├── client.go                  ← typed control-plane client (uses pkg/pki for mTLS)
├── ratelimit.go               ← per-source-IP rate limit
├── csrf.go                    ← double-submit cookie CSRF
└── audit.go                   ← security-channel audit logger

web/admin/                     ← React FE source (Vite)
├── package.json
├── vite.config.ts
├── tsconfig.json
├── index.html
├── src/
│   ├── App.tsx
│   ├── components/
│   │   └── BootstrapForm.tsx
│   └── api/
│       └── client.ts
└── dist/                      ← gitignored; vite build output
```

### 1.2 Skeleton main.go

```go
package main

import (
    "akashic/akashic/pkg/admin_bff"
    "log"
)

func main() {
    s, err := admin_bff.NewServer()
    if err != nil { log.Fatalf("init: %v", err) }
    if err := s.Run(); err != nil { log.Fatalf("run: %v", err) }
}
```

### 1.3 Skeleton server.go

Just enough to listen on `:8082` (or whatever the BFF port is), serve
`/api/health`, and shut down cleanly on SIGTERM. Real handlers come in
Step 3.

---

## Step 2: BFF mTLS Plumbing

The BFF reads its mTLS client identity from the `certs` volume that
Vault Agent writes to. The cert exists today (see
`services/vault-agent/templates/bff-client.tpl`).

### 2.1 Config

`pkg/admin_bff/config.go`:

```go
type Config struct {
    ListenAddr        string  // ":8082"
    ControlURL        string  // "https://akashic.akashic.local:8081"
    BFFCertFile       string  // /certs/bff/akashic-ctrl-client.crt
    BFFKeyFile        string  // /certs/bff/akashic-ctrl-client.key
    BFFCAFile         string  // /certs/bff/mtls-ca.crt
    CertWatcherEnable bool    // mirror Akashic-server's PKI.CertWatcherEnabled

    BootstrapRateLimit int    // 5 per IP per minute
    AuditLogPath       string // optional file sink; otherwise stdout
}
```

Loaded via Viper with `AKASHIC_BFF_*` env-var prefix, mirroring the
Akashic server's config style. Defaults assume container-mode paths
(`/certs/bff/...`); operators running the BFF on the host can override
via env vars.

### 2.2 Control-plane client

`pkg/admin_bff/client.go`:

```go
type ControlClient struct {
    base    string
    httpC   *http.Client
    reload  *pki.Reloader   // from pkg/pki — same as Akashic server
}

func NewControlClient(cfg *Config) (*ControlClient, error) {
    reload, err := pki.NewReloader("admin-bff-client", cfg.BFFCertFile, cfg.BFFKeyFile)
    if err != nil { return nil, err }

    pool, err := pki.LoadCAPool(cfg.BFFCAFile)
    if err != nil { return nil, err }

    transport := &http.Transport{
        TLSClientConfig: &tls.Config{
            MinVersion: tls.VersionTLS12,
            RootCAs:    pool,
            // GetClientCertificate is the client-side analogue of
            // GetCertificate -- called per-handshake so rotation works.
            GetClientCertificate: func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
                cert, err := reload.GetCertificate(nil)
                return cert, err
            },
        },
    }
    return &ControlClient{
        base:   cfg.ControlURL,
        httpC:  &http.Client{Transport: transport, Timeout: 10 * time.Second},
        reload: reload,
    }, nil
}

func (c *ControlClient) BootstrapStatus(ctx context.Context) (*BootstrapStatus, error) {...}
func (c *ControlClient) BootstrapCreateRoot(ctx context.Context, req *CreateRootRequest) (*User, error) {...}
```

The `GetClientCertificate` callback is the **client-side** mirror of
the `GetCertificate` callback we used in Phase 4 for the server. Same
zero-downtime rotation property: every handshake reads the current
cert from the atomic pointer.

### 2.3 Cert watcher (optional, mirrors Phase 4)

When `CertWatcherEnable` is true, an fsnotify watcher fires `reload.Reload()`
on cert file changes. Reuses `pkg/pki/cert_watcher.go` directly.

---

## Step 3: BFF API Handlers

Three endpoints in this phase:

### `GET /api/health` — proxy / k8s liveness

Returns `200 OK` with `{"status":"healthy"}`. Doesn't touch the control
plane. nginx-proxy uses this for upstream health checks.

### `GET /api/bootstrap/status` — proxy passthrough

Calls `controlClient.BootstrapStatus()`, returns the response unchanged
to the browser. The React FE polls this on load to decide which UI to
show.

### `POST /api/bootstrap/create-root` — the real action

Request body: `{token, username, email, password}`. CSRF token in
header (validated by middleware).

Flow:
1. CSRF middleware validates the cookie/header pair (Step 4)
2. Source-IP rate limit (Step 4)
3. Validate input shape (non-empty fields, email format)
4. Forward to `controlClient.BootstrapCreateRoot(ctx, req)`
5. On success: clear sensitive fields from logs, write audit row with
   IP + outcome, return success JSON to browser
6. On error: map control-plane error code to user-facing message

### Error mapping (control plane → user)

| Control plane code | User-facing message | HTTP status to browser |
|---|---|---|
| `INVALID_TOKEN` | "The bootstrap token is invalid or expired. Get a fresh one from the server logs." | 401 |
| `BOOTSTRAP_COMPLETE` | "Bootstrap is already complete. The form is no longer accepting submissions." | 410 (Gone) |
| `PASSWORD_POLICY_VIOLATION` | (pass through the specific rule) | 400 |
| `VALIDATION_FAILED` | (pass through specific field) | 400 |
| `RATE_LIMITED` | "Too many attempts. Please wait %d seconds." | 429 |
| any 5xx | "Server error. Please retry in a moment." | 502 |
| network/timeout | "Couldn't reach the server. Please retry." | 502 |

The BFF deliberately re-maps to a small, browser-friendly set of codes
+ messages. We do NOT pass through internal control-plane error
codes verbatim — that leaks implementation details.

---

## Step 4: BFF Security Baseline

These ship from day one. Baking them in early is much cheaper than
retrofit during an audit.

### 4.1 Source-IP rate limit

`pkg/admin_bff/ratelimit.go`. Same in-memory token-bucket pattern as
`pkg/middleware/rate_limit.go`, but keyed on `r.RemoteAddr` (or
`X-Forwarded-For` when behind nginx-proxy).

- 5 attempts per minute per IP for `/api/bootstrap/create-root`
- 30 per minute for `/api/bootstrap/status` (it's idempotent and cheap)
- 429 + `Retry-After` header on excess
- Audit log on every 429

### 4.2 CSRF (double-submit cookie pattern)

On first GET to any `/api/*` endpoint, set a cookie:

```
Set-Cookie: akashic_csrf=<32-byte-random>;
            HttpOnly=false; Secure; SameSite=Strict; Path=/api
```

Every state-changing request must include the same value in an
`X-Akashic-CSRF` header. Browser JS reads the cookie (HttpOnly=false
deliberately — we *want* JS to read it), sets the header on submit.
Server middleware compares cookie value with header value.

This is the OWASP "double-submit cookie" pattern. Defeats CSRF without
needing a per-request stateful token store.

### 4.3 Security headers (set globally)

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

CSP is locked tight: no third-party scripts/styles/images. The
`'unsafe-inline'` for styles is required for Vite's CSS-in-JS output;
we'll work around it later if it's worth the effort. `frame-ancestors
'none'` prevents clickjacking.

### 4.4 Audit log

Every state-changing endpoint emits a security-channel log line:

```json
{
  "channel": "security",
  "action": "bootstrap_create_root",
  "outcome": "success",
  "remote_ip": "203.0.113.5",
  "user_agent": "Mozilla/5.0 ...",
  "control_response_code": 201,
  "duration_ms": 142,
  "request_id": "..."
}
```

Critically, **the password and token fields never appear in these logs**.
The audit logger has an explicit allowlist of fields, not a denylist.

### 4.5 HTTPS-only

The BFF refuses to start if `ListenAddr` points to a public interface
without TLS configured. Inside the docker network, plain HTTP is fine
(the proxy terminates TLS); on the host, the BFF demands TLS.

---

## Step 5: React FE Skeleton

### 5.1 Vite + TypeScript setup

```bash
cd web/admin
npm create vite@latest . -- --template react-ts
npm install
```

Add `tsconfig.json` with `strict: true`. We're not going to fight
TypeScript on a fresh project.

### 5.2 Two-state app

`web/admin/src/App.tsx`:

```tsx
function App() {
  const [status, setStatus] = useState<BootstrapStatus | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/bootstrap/status")
      .then(r => r.json())
      .then(d => setStatus(d.data))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <Spinner />;
  if (status?.is_complete) return <BootstrapAlreadyComplete status={status} />;
  return <BootstrapForm />;
}
```

That's the entire app shell for Phase 6. No router, no auth context, no
state management library — there's exactly one screen with two states.

### 5.3 The form component

```tsx
function BootstrapForm() {
  const [form, setForm] = useState({ token: "", username: "", email: "",
                                       password: "", confirm: "" });
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (form.password !== form.confirm) { setError("Passwords don't match"); return; }
    setSubmitting(true);
    try {
      const csrf = readCookie("akashic_csrf");
      const r = await fetch("/api/bootstrap/create-root", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Akashic-CSRF": csrf },
        body: JSON.stringify({
          token: form.token, username: form.username,
          email: form.email, password: form.password,
        }),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error?.message || "Submission failed");
      // success: replace the page with a "done!" view
      window.location.reload();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (/* form JSX with five fields + submit button */);
}
```

### 5.4 Visual design

Minimal. Phase 6 is functional; Phase 7 brings the design system. A
single centered form on a plain background, with Akashic branding in
the header. ~150 lines of CSS total.

### 5.5 Where the bootstrap token comes from

The form has a "Bootstrap token" field. The user pastes the token from
the server's stdout/logs (same source the CLI fetches from). We do NOT
fetch the token automatically — that would require the BFF to be able
to fetch it, which would mean exposing `/api/bootstrap/token` to the
browser, which would mean any browser that hits the URL gets the token
for free. That breaks the whole "token is the identity" model.

Instead: operator copies token from logs, pastes into form. Same
operational gesture as the CLI's `--token <value>` flag. Slightly less
ergonomic than the CLI's auto-fetch (since the CLI is mTLS-trusted),
but this is the right asymmetry — browsers can't be trusted to fetch
secrets they shouldn't be able to fetch.

---

## Step 6: Embed FE into Go Binary

### 6.1 embed.FS in the BFF

```go
//go:embed all:web/admin/dist
var feAssets embed.FS

func feHandler() http.Handler {
    sub, _ := fs.Sub(feAssets, "web/admin/dist")
    return http.FileServer(http.FS(sub))
}
```

### 6.2 Routing

```go
mux := http.NewServeMux()
mux.Handle("/api/", apiMiddleware(apiRouter))
mux.Handle("/", feHandler())  // catches everything else: SPA fallback
```

For an SPA, every non-API path should serve `index.html` (so
client-side routing works). Easy to bolt on, not needed for Phase 6
since there's only one route.

### 6.3 Build pipeline

The Dockerfile builds the FE first, then the Go binary embeds it:

```dockerfile
# stage 1: vite build
FROM node:20-alpine AS fe-builder
WORKDIR /src/web/admin
COPY web/admin/package*.json ./
RUN npm ci
COPY web/admin/ ./
RUN npm run build   # outputs to ./dist

# stage 2: go build (with FE embedded)
FROM golang:1.24-alpine AS go-builder
WORKDIR /src
COPY --from=fe-builder /src/web/admin/dist ./web/admin/dist
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/admin-bff ./cmd/admin-bff

# stage 3: runtime
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=go-builder /out/admin-bff /usr/local/bin/admin-bff
ENTRYPOINT ["/usr/local/bin/admin-bff"]
```

One artifact (the Go binary) contains the entire BFF + FE. Single deploy
unit, no separate static-assets bucket, no SPA-routing-on-CDN concern.

### 6.4 Dev-mode hot-reload

For local development, manually rebuilding on every FE change is
painful. Two options:

1. **Vite dev server proxy**: run `npm run dev` separately on `:5173`,
   point it at the BFF's API via Vite's proxy config:
   ```js
   server: { proxy: { '/api': 'http://localhost:8082' } }
   ```
   Operators iterating on FE see live HMR; final build still embeds.
2. **`-fe-dir` flag**: BFF in dev mode reads from disk (`web/admin/dist/`)
   instead of `embed.FS`. Less ergonomic than option 1 but doesn't
   require a separate process.

We'll use option 1 by default, document option 2 as the fallback.

---

## Step 7: Two-Level nginx + docker-compose

### 7.1 The two-level proxy topology

Akashic deployments use **two layers of nginx**, not one:

```
                  Internet (public DNS: admin.akashic.<domain>)
                          │
                          │ HTTPS (public CA / Let's Encrypt)
                          ▼
          ┌─────────────────────────────────────────────┐
          │  HOST nginx  (runs on the host, not docker) │
          │  - Public TLS termination                   │
          │  - Holds the public CA cert                 │
          │  - Forwards to docker via 127.0.0.1 / HTTP  │
          └─────────────────┬───────────────────────────┘
                            │ HTTP (loopback)
                            │ Host: admin.akashic.<domain>
                            ▼
          ┌─────────────────────────────────────────────┐
          │  DOCKER nginx-proxy  (existing service)     │
          │  - Listens on 127.0.0.1:8280 (loopback)    │
          │  - Routes by Host header to backend service │
          │  - Speaks plain HTTP on the docker network  │
          └─────────────────┬───────────────────────────┘
                            │ HTTP (docker network)
                            ▼
                      admin-bff:8082
                            │ HTTPS+mTLS (pki-mtls-akashic-ctrl)
                            ▼
                      control-server :8081
```

**Why two levels?**

- The **host nginx** lives outside docker because public-CA TLS material
  (Let's Encrypt cert + key, ACME challenge state, possibly OCSP
  stapling) is operationally simpler to manage on the host than inside
  containers. Operators may already have a host nginx for unrelated
  services; this slots in alongside.
- The **docker nginx-proxy** is the existing Phase 3 service that
  already does subdomain routing for `adminer.akashic.local`,
  `phpldapadmin.akashic.local`, etc. Adding `admin.akashic.local`
  follows that established pattern.

This two-level split has another benefit: the host nginx is the only
component with public IP exposure. The docker proxy stays bound to
`127.0.0.1:8280` (loopback only). External traffic literally cannot
reach the docker proxy except through the host nginx.

### 7.2 Host-level nginx (production deployment notes)

The host nginx is **not** managed by this repository's docker-compose;
it's part of the host's system configuration. Operators set this up
once when the deployment goes into production. Reference config:

```nginx
# /etc/nginx/sites-available/akashic-admin.conf  (on the host)
server {
    listen 443 ssl http2;
    server_name admin.akashic.<your-domain>;

    # Production: Let's Encrypt via certbot
    ssl_certificate     /etc/letsencrypt/live/admin.akashic.<your-domain>/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/admin.akashic.<your-domain>/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    # HSTS: tell browsers to never accept plain HTTP for this name
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    location / {
        # Forward to the docker-level proxy on host loopback
        proxy_pass http://127.0.0.1:8280;
        proxy_http_version 1.1;

        # Preserve the original Host so docker-level subdomain routing works
        proxy_set_header Host $host;

        # Tell the BFF where the request came from. The docker-level
        # proxy will pass these through unchanged.
        proxy_set_header X-Forwarded-For  $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Real-IP        $remote_addr;
    }
}

# Redirect plain HTTP to HTTPS (HSTS preload requires this)
server {
    listen 80;
    server_name admin.akashic.<your-domain>;
    return 301 https://$host$request_uri;
}
```

**Local development** can skip the host nginx entirely: hit the docker
nginx-proxy directly at `https://admin.akashic.local:8280` (using the
internal `pki-public` cert, accept-once in the browser). The Phase 6
verification steps below cover both modes.

### 7.3 Docker-level nginx-proxy server block

`services/proxy/nginx.conf` — add a new server block. Note this listens
on **plain HTTP** (no `ssl` directive); TLS termination already happened
at the host nginx upstream. Keep the existing real-ip configuration
that lets the proxy honor `X-Forwarded-For` from the host nginx:

```nginx
# Trust X-Forwarded-* headers ONLY from the host nginx (loopback).
# Without this scoping, a malicious client could spoof X-Forwarded-For
# to bypass the BFF's source-IP rate limit.
set_real_ip_from 127.0.0.1;
real_ip_header   X-Forwarded-For;
real_ip_recursive on;

server {
    listen 80;
    server_name admin.akashic.local admin.akashic.*;

    location / {
        proxy_pass http://admin-bff:8082;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;
        proxy_set_header X-Real-IP         $remote_addr;
    }
}
```

The `proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto`
preserves whatever the host nginx put there (typically `https`), so the
BFF correctly reports HTTPS in audit logs and CSP reports even though
the docker-level hop is plain HTTP.

### 7.4 Local-dev cert for direct access (optional)

For developers who want to hit the docker proxy directly without
setting up a host nginx, add a Vault Agent template that issues a
`pki-public` cert for the docker proxy:

`services/vault-agent/templates/proxy-public.tpl`:

```gotemplate
{{- with pkiCert "pki-public/issue/server"
  "common_name=admin.akashic.local"
  "alt_names=admin.akashic.local,akashic.local,*.akashic.local"
  "ttl=720h" -}}
{{ .Key  | writeToFile "/certs/proxy/public.key" "root" "root" "0600" }}
{{ .Cert | writeToFile "/certs/proxy/public.crt" "root" "root" "0644" }}
{{- end -}}
```

And in `services/proxy/nginx.conf`, an *additional* server block on
port 443 for direct dev access:

```nginx
server {
    listen 443 ssl;   # dev only -- production uses host nginx instead
    server_name admin.akashic.local;
    ssl_certificate     /certs/proxy/public.crt;
    ssl_certificate_key /certs/proxy/public.key;
    # Same location block as above
    location / { ... }
}
```

Bind `127.0.0.1:8443:443` in compose for this; production deployments
just don't expose this port.

### 7.5 New `admin-bff` compose service

```yaml
admin-bff:
  build:
    context: .
    dockerfile: ./services/admin-bff/Dockerfile
  container_name: akashic-admin-bff
  restart: unless-stopped
  depends_on:
    vault-agent:
      condition: service_started
    akashic:
      condition: service_started   # only when --profile app is up
  environment:
    AKASHIC_BFF_LISTEN_ADDR: ":8082"
    AKASHIC_BFF_CONTROL_URL: https://akashic.akashic.local:8081
    AKASHIC_BFF_BFF_CERT_FILE: /certs/bff/akashic-ctrl-client.crt
    AKASHIC_BFF_BFF_KEY_FILE: /certs/bff/akashic-ctrl-client.key
    AKASHIC_BFF_BFF_CA_FILE: /certs/bff/mtls-ca.crt
    # Trusted-proxy chain for X-Forwarded-For: the BFF will accept the
    # header only when it comes from the docker-level proxy. Same
    # principle as the docker proxy's set_real_ip_from above.
    AKASHIC_BFF_TRUSTED_PROXIES: 172.0.0.0/8
    TZ: ${AKASHIC_TZ:-UTC}
  volumes:
    - certs:/certs:ro
  networks:
    default:
      aliases:
        - admin-bff.akashic.local
  profiles: ["app"]   # comes up with the rest of the app stack
```

The BFF is **not** publicly bound. It only listens on the docker network;
even from the host, it's not reachable on a published port. The only way
in is through the docker proxy → host proxy chain.

### 7.6 X-Forwarded-For trust chain

A mistake here would let any browser spoof its source IP and bypass
the BFF's rate limit. The chain that must hold:

```
Browser            (untrusted; X-Forwarded-For is whatever it claims)
  │
  ▼
Host nginx        (set X-Forwarded-For = real client IP, OVERWRITE)
  │ trust: only this nginx
  ▼
Docker nginx-proxy (set_real_ip_from 127.0.0.1; trust upstream's X-Forwarded-For)
  │ trust: only loopback (i.e., the host nginx)
  ▼
admin-bff         (TrustedProxies: 172.0.0.0/8 covers the docker network)
                   trust: only docker-network upstream proxies
```

Each hop must trust *only its immediate upstream* and overwrite or
preserve the X-Forwarded-For header accordingly. Misconfiguring any
step (e.g., docker-level proxy trusting Internet IPs) creates a spoof
hole. This is documented prominently in the BFF's config to keep
operators from breaking it.

### 7.7 Compose profile relationship

The BFF lives under the same `app` profile as the Akashic server itself.
Operators who run `docker compose --profile app up -d` get the entire
stack including the admin UI. Host-run mode of Akashic doesn't have
the BFF (yet) — we can add a host-run BFF flow in a follow-up if
desired, but Phase 6 doesn't require it.

---

## Step 8: End-to-End Verification

### 8.1 Fresh-deploy smoke test (two paths)

The verification covers both access modes: **direct dev** (skipping the
host nginx, hitting docker proxy directly) and **production-shape**
(through host nginx → docker proxy → BFF).

#### 8.1a Direct-dev path

```bash
./scripts/reset-akashic.sh
docker compose --profile app up -d
sleep 30   # vault-agent issues all certs; admin-bff builds + starts

# Add hosts entry so admin.akashic.local resolves
sudo sh -c 'echo "127.0.0.1 admin.akashic.local" >> /etc/hosts'

# Visit the bootstrap form, hitting docker proxy directly on its
# loopback-bound public port (Step 7.4 dev cert)
open https://admin.akashic.local:8443
# Chrome will warn on the pki-public cert; accept once for dev.

# Get the token from server logs and paste into the form
docker logs akashic-server | grep -A 1 "Bootstrap Token"
```

#### 8.1b Production-shape path (with host nginx)

```bash
# 1. Install nginx on the host (e.g. brew install nginx, apt install nginx)
# 2. Drop services/proxy/host-nginx-example.conf into /etc/nginx/sites-enabled/
#    (we'll ship this example file as part of Phase 6)
# 3. For local testing, use a mkcert-issued cert instead of Let's Encrypt:
brew install mkcert
mkcert -install
mkcert admin.akashic.local
sudo mv admin.akashic.local*.pem /etc/nginx/ssl/

# 4. Reload nginx
sudo nginx -t && sudo nginx -s reload

# 5. Visit
open https://admin.akashic.local
# No cert warning (mkcert is locally trusted), full request goes
# host-nginx → 127.0.0.1:8280 → docker-proxy → admin-bff
```

#### Expected outcome (both paths)
- Form loads
- Status check (GET /api/bootstrap/status) returns `is_complete: false`
- Submit form with valid token + credentials
- Success page shown
- `akashic-cli bootstrap status` afterward shows `is_complete: true`

#### Verifying the X-Forwarded-For chain

The BFF should see the **browser's** IP, not the docker network IP:

```bash
# from the BFF logs, look for the audit row from your form submission
docker logs akashic-admin-bff 2>&1 | grep bootstrap_create_root | tail -1
# Should include "remote_ip": "<your real client IP>"
# NOT "remote_ip": "172.18.0.x" (docker network)
```

If you see a docker-network IP, the trust chain is broken — most likely
the host nginx isn't sending X-Forwarded-For, or the docker proxy isn't
configured to honor it from loopback.

### 8.2 Failure-mode checks

| Scenario | Expected UI behavior |
|---|---|
| Submit with invalid token | Error: "The bootstrap token is invalid or expired" |
| Submit with too-short password | Error: specific policy rule that failed |
| Submit > 5 times rapidly from same IP | Error: "Too many attempts. Please wait N seconds." |
| Submit after bootstrap already complete | UI auto-detects on load → "Already complete" view |
| Submit without CSRF header (curl) | 403 from BFF |
| Visit URL while server is down | UI shows "Couldn't reach the server" |

### 8.3 Security checks (tooling)

```bash
# Headers should be present on every response
curl -I -k https://admin.akashic.local/
# Expect: HSTS, CSP, X-Frame-Options DENY, Referrer-Policy

# Mozilla Observatory or similar scoring
curl https://http-observatory.security.mozilla.org/api/v1/analyze?host=admin.akashic.local
# Expect: A or higher

# CSP report-only mode for validation during dev (optional)
```

---

## Files Summary (planned)

### New files

| Path | Purpose |
|---|---|
| `services/admin-bff/Dockerfile` | Multi-stage Vite + Go build |
| `services/admin-bff/README.md` | Operator docs |
| `services/vault-agent/templates/proxy-admin.tpl` | Vault Agent template for admin subdomain cert |
| `services/proxy/nginx.conf` | (modified) — new server block for admin.akashic.local |
| `cmd/admin-bff/main.go` | BFF entry point |
| `pkg/admin_bff/server.go` | HTTP listener + middleware chain |
| `pkg/admin_bff/handlers.go` | /api/health, /api/bootstrap/{status,create-root} |
| `pkg/admin_bff/client.go` | Typed control-plane client over mTLS |
| `pkg/admin_bff/config.go` | Viper-based config loader |
| `pkg/admin_bff/ratelimit.go` | Per-source-IP rate limiter |
| `pkg/admin_bff/csrf.go` | Double-submit cookie middleware |
| `pkg/admin_bff/audit.go` | Security-channel audit logger with field allowlist |
| `web/admin/package.json` | npm config |
| `web/admin/vite.config.ts` | Vite config (proxy /api → BFF in dev) |
| `web/admin/tsconfig.json` | TS strict |
| `web/admin/index.html` | Vite entry |
| `web/admin/src/App.tsx` | Two-state app shell |
| `web/admin/src/components/BootstrapForm.tsx` | The form |
| `web/admin/src/components/BootstrapAlreadyComplete.tsx` | Post-bootstrap view |
| `web/admin/src/api/client.ts` | Fetch wrappers + CSRF helper |
| `web/admin/src/styles.css` | ~150 lines of CSS |
| `services/vault-agent/templates/proxy-public.tpl` | Vault Agent template for the docker-proxy's optional dev-only public cert |
| `services/proxy/host-nginx-example.conf` | Reference host-level nginx config that operators install on their host (`/etc/nginx/sites-enabled/`); not consumed by docker-compose |
| `doc/phase-6-revision.md` | (later) — as-built operator-facing summary |

### Modified files

| Path | Change |
|---|---|
| `docker-compose.yml` | Add `admin-bff` service under `profiles: ["app"]` |
| `services/proxy/nginx.conf` | New plain-HTTP server block for `admin.akashic.local`; `set_real_ip_from 127.0.0.1` so X-Forwarded-For from host nginx is honored |
| `services/vault-agent/config.hcl` | Register `proxy-public.tpl` (dev cert) |
| `.gitignore` | Add `web/admin/node_modules/`, `web/admin/dist/` |
| `.dockerignore` | Allow `web/admin/` (currently might be excluded) |

### NOT touched

- `pkg/server/control/` — server-side bootstrap is already complete (Phase 5)
- `pkg/cli/` — CLI is already complete (Phase 5)
- `pkg/auth/`, `pkg/ldap/`, `pkg/repository/` — no changes needed
- `configs/config.yaml` — Akashic server unchanged

---

## Known Risks

| Risk | Mitigation |
|---|---|
| CSP `'unsafe-inline'` for styles enables some XSS classes | Vite-generated CSS is fully under our control; review at PR time. Phase 7 can tighten further with nonces. |
| FE rebuild on every Go change is slow | `--fe-dir` flag for dev mode reads `web/admin/dist/` from disk, skips embed |
| Vite build adds ~30-50MB of node_modules to the build context | `.dockerignore` excludes node_modules from the Go build stage; only `dist/` crosses stage boundaries |
| Browser caches old `dist/` aggressively after redeploy | Vite injects content-hashed filenames by default (`app.abc123.js`); `index.html` is short-cached |
| Operator pastes token into form on a malicious clone of admin.akashic.local | HSTS preload + clear branding + token TTL limit blast radius (token expires in 1h) |
| Rate-limit bypass via X-Forwarded-For header spoofing | Two-level trust chain (Step 7.6): host nginx overwrites X-Forwarded-For with real client IP; docker proxy only trusts loopback as upstream; BFF only trusts docker network (172.0.0.0/8) as upstream. Each hop must trust ONLY its immediate upstream. |
| Misconfigured trust chain (e.g. docker proxy trusts Internet IPs) | Step 7.6 documents the trust contract; verification in Step 8.1 explicitly checks that BFF logs show the browser's real IP, not a docker-internal one |
| Replay of an intercepted form POST | TLS 1.2+ on the wire; CSRF defeats cross-origin; same-origin replay would still need to know the token |

---

## Non-Goals (Deferred to Phase 7)

- **Admin login flow** — OAuth-against-self requires `akashic-admin` OAuth client registration; that's its own subsystem
- **Admin dashboard** — user listing, RBAC management, server controls all need login first
- **Session management** — we're stateless in Phase 6; sessions arrive in Phase 7
- **OAuth client registration UI** — tenant-facing; lives at `<root domain>` (Phase 7+)
- **Production cert rotation for the public TLS** — Let's Encrypt integration is its own story; for now `pki-public` is fine
- **i18n / theming / dark mode** — visual polish lives in Phase 7+
- **Audit log viewer in the FE** — view via Grafana for now

---

## Phase 7 Preview

Once Phase 6 lands, Phase 7 is "the admin dashboard":

1. OAuth client registration for `akashic-admin` (built-in, server-side)
2. Login flow at `/login` (admin-bff → auth-server → admin-bff)
3. Session store in Redis (key prefix `akashic:bff:session:*`)
4. Re-auth-for-dangerous-actions middleware (sudo mode)
5. Dashboard with server status, recent audit events
6. User management (create / disable / delete admins)
7. RBAC group viewer (LDAP cn=akashic-admins membership)
8. The "bootstrap required" page on `/` becomes a redirect to `/login`
   when bootstrap is complete

None of that is in Phase 6.
