# Chapter 03 — The Akashic Server

> **Goal**: by the end of this chapter, you should be able to trace
> the akashic Go process from `main()` through to "ready to serve
> requests" and understand the conventions the codebase uses for
> config, logging, and middleware.

## The entry point

`cmd/akashic/main.go` is intentionally tiny. It calls into Cobra (a
CLI framework) which dispatches to `pkg/command/run.go`'s `run`
subcommand. The `run` command constructs an `AkashicApp` (the
top-level lifecycle object) and calls `Init()` then `Run()` on it.

Why all this indirection? Because the same binary will eventually
support multiple subcommands (`akashic migrate`, `akashic verify`,
etc. — Phase 8+). Cobra is the standard Go CLI framework; pulling it
in early avoids re-architecting later.

## The lifecycle object

`pkg/akashic/core/context.go` defines `AkashicApp`. It's the *single
owning object* of every long-lived resource:

```go
type AkashicApp struct {
    Config         *config.ConfigManager
    Logger         *logging.Logger
    Postgres       *akashic_postgres.DB
    Redis          *akashic_redis.Client
    LDAPClient     *ldap.Client
    AuthService    *auth.Service
    BootstrapMgr   *bootstrap.Manager
    Deprovisioning *ldap.DeprovisioningService
    OAuthKeyStore  *oauth.KeyStore
    AuthServer     *auth.Server   // the OAuth/OIDC listener (port 8080)
    ControlServer  *control.Server // the management API (port 8081)
    closers        []io.Closer    // LIFO cleanup
}
```

The pattern: **every dependency is a field; nothing is package-level
state**. This makes the app easy to construct (e.g., for tests with
fakes) and easy to clean up — when shutting down, every Closer is
called in reverse order (LIFO), guaranteeing things shut down in the
opposite order they came up.

### `Init()` — the wiring code

Conceptually, `Init()` does this:

```
1. Load config (Viper reads YAML + env vars + CLI flags)
2. Build the logger (zap with multi-channel sinks)
3. Create the Postgres client + run migrations
4. Create the Redis client + ping
5. Create the LDAP client + bind + initialize structure
6. Build the auth service (LDAP + repository wrapper)
7. Initialize the OAuth keystore (./keys/oauth/)
8. Run initial deprovisioning reconciliation
9. Detect bootstrap state (root user exists?)
   - If yes: clear bootstrap mode
   - If no: generate bootstrap token, log it, set bootstrap mode
10. EnsureBuiltInClients (akashic-admin row in client_services)
11. Initialize the deprovisioning service (don't start it yet)
12. Build the AuthServer + ControlServer (don't start listeners yet)
13. AddCloser for everything in reverse order
```

Then `Run()` actually *starts* the listeners and blocks on a signal:

```
1. Start the deprovisioning goroutine
2. Start the control listener
3. Auto-start the auth listener (unless --no-auto-start)
4. Block on SIGINT/SIGTERM
5. On signal: Close() each registered Closer in LIFO order
```

The split between Init and Run is intentional. Init *can fail* — if
postgres is down, that's not a runtime error, that's "the server
shouldn't have started." Run is mostly waiting; failures inside Run
are rare and usually unrecoverable.

## The dual-server pattern

Recall from chapter 00: the akashic process binds two listeners.
That's literally implemented as two separate `*http.Server` instances
inside the same process:

```
pkg/server/auth/server.go      ← public OAuth/OIDC surface (port 8080)
pkg/server/control/server.go   ← mTLS management API (port 8081)
```

Each has its own:

- TLS cert (different `pkg/pki.Reloader` instance)
- Middleware chain
- Route table
- Listener configuration

But they *share* the underlying `AkashicApp` — same DB connection,
same logger, same LDAP client. The "server" is mostly an HTTP
binding; the *behavior* lives in the app's services.

Each server uses the **pre-bind listener pattern** (`net.Listen`
synchronously, then `srv.Serve(ln)` in a goroutine). This catches
"port already in use" errors at the right level — synchronously, so
`Init()` can return an error — instead of asynchronously inside the
goroutine where the error would be hard to surface.

## Configuration: Viper + YAML + env

The config system lives in `pkg/config/`. The model:

1. **A Go struct hierarchy** in `pkg/config/types.go` defines the
   shape of every config option.
2. **Defaults** in `pkg/config/defaults.go` set sensible values.
3. **`configs/config.yaml`** can override defaults.
4. **Env vars** with prefix `AKASHIC_` override YAML.
5. **CLI flags** override env vars.

The order is "later sources win." So for any config key, the
resolution chain is:

```
CLI flag > AKASHIC_* env var > config.yaml value > Go default
```

Viper handles all of this — the akashic code just calls
`v.GetString("ldap.host")` and gets the resolved value.

### Hot-reload

The `ConfigManager` supports **hot-reload**: an operator can `POST
/config/reload` to the control plane, and the manager re-reads the
config file, re-validates, and updates the live config. Subscribers
to config changes (notably the logger, which has its own
`Reconfigure()` method) get the new values without a restart.

Most components don't need this — they read config once at startup.
The logger does because operators sometimes want to crank up
verbosity in prod without a deploy.

### Decode hooks

Some config values aren't simple strings. `30m` should parse to a
`time.Duration`; `info` should parse to a `zap.AtomicLevel`. Viper
supports custom decode hooks for this; they live in
`pkg/config/decode_hooks.go`. Adding a new hook is rare — only when
you introduce a config field of an unusual type.

## Logging: zap + multi-channel sinks

`pkg/logging/` is a substantial subsystem. The headline features:

- **Three channels**: `App`, `Security`, `Audit`. Each is a separate
  `*zap.Logger` — `App.Info(...)`, `Security.Warn(...)`,
  `Audit.Info(...)`. They can have different log levels and different
  destinations.
- **Multi-sink**: each channel can write to multiple sinks
  simultaneously — stdout, stderr, file (with rolling rotation),
  Loki.
- **Hot-reconfigurable**: change config → call `Reconfigure()` →
  every running goroutine that holds a reference to the logger sees
  the new sinks on its next log call (atomic-pointer pattern, same
  as the cert reloader).

### Why three channels?

Audit and security have *different operational requirements* than app
logs. Audit logs are typically **kept forever** (compliance), shipped
to a separate sink, and have a strict format. Security logs are the
"someone tried to log in 100 times in a minute" stream — useful for
incident response. App logs are "I made an HTTP request, here's how
long it took" — useful for debugging, less useful for compliance.

Splitting them at the *channel* level (rather than via tags on a
single stream) makes it easy to e.g. ship only audit logs to a
high-retention bucket while keeping app logs in cheap short-retention
storage.

### The Loki sink

`pkg/logging/loki_writer.go` implements a writer that batches log
lines and POSTs them to Loki in chunks. It has a **circuit breaker**:
if Loki is unreachable, the writer trips, drops further writes for a
back-off period, and retries. This is critical — without the
circuit, a Loki outage would stall every log call (which is on the
hot path of every request) until the connection times out.

### GORM's logger

GORM (the ORM library) has its own logger interface. Phase 7 added
`pkg/database/akashic_postgres/zap_logger.go` — a small adapter that
makes GORM's log calls go through zap so query logs land in the
project's structured stream rather than via Go's stdlib `log`.

## Middleware: composable per-server chains

`pkg/middleware/` defines the middleware. Each middleware is a
`func(http.Handler) http.Handler` — the standard Go pattern. There's
a `Chain` type and a `ChainBuilder` that lets you compose them
fluently:

```go
chain := middleware.NewChain().
    Use(middleware.RequestID()).
    Use(middleware.Logging(logger)).
    Use(middleware.Recovery()).
    Use(middleware.SecurityHeaders()).
    Use(middleware.CORS(corsConfig)).
    Use(middleware.SizeLimit(1<<20)).
    Use(middleware.RateLimit(rateLimitConfig)).
    Use(middleware.Timeout(30 * time.Second))
```

There are pre-built chains for each server: `AuthServerChain()` and
`ControlServerChain()` (in `pkg/middleware/builder.go`). They differ
in security posture:

| Middleware | Auth server (8080) | Control server (8081) |
|---|---|---|
| Request ID | ✓ | ✓ |
| Logging | ✓ | ✓ |
| Recovery | ✓ | ✓ |
| Security headers | ✓ | ✓ |
| CORS | ✓ | ✓ |
| Size limit | ✓ | ✓ |
| Rate limit | ✓ | ✓ |
| Timeout | ✓ | ✓ |
| **IP allowlist** | — | ✓ |
| **mTLS validation** | — | ✓ |

The control server has two additional layers because it's
management-only — even if mTLS is broken or bypassed, the IP
allowlist is a second line of defense.

### Order matters

Middleware order in the chain determines the request-handling order.
The convention is: outermost middleware = first to see the request
and last to see the response. So:

```
Request flow:
  RequestID → Logging → Recovery → SecurityHeaders → ... → Handler

Response flow (reverse):
  Handler → ... → SecurityHeaders → Recovery → Logging → RequestID
```

Logging wraps Recovery so that a panic gets logged with the request
ID. Recovery is *inside* Logging because if Recovery panicked
(unlikely but possible) we want Logging to still emit something.

## Common patterns the codebase uses

A few patterns recur enough across the project that they're worth
naming up front:

### Atomic-pointer for hot-swappable state

Used by:
- `pkg/pki/Reloader` (TLS certs)
- `pkg/oauth/KeyStore` (OAuth signing keys)
- `pkg/logging/Logger` (zap cores)
- `pkg/admin_bff.Server.oauth` (lazy-init OAuth client)

The shape: a `sync/atomic.Pointer[T]` stores the current state. Reads
are lock-free. Writes acquire a mutex (to prevent two writers from
clobbering each other), atomically swap the pointer, and let GC reap
the old state when the last reference drops.

### Closer LIFO for resource cleanup

`AkashicApp.AddCloser` registers a function to call during shutdown.
On `Close()`, registered closers fire in *reverse* registration
order — so things tear down in the opposite order they came up.
This avoids a class of "the postgres client was closed before the
auth service stopped using it" bugs.

### Pre-bind listener for port-conflict detection

`net.Listen()` synchronously, `srv.Serve(ln)` asynchronously. Catches
"port in use" errors at startup-time instead of asynchronously inside
a goroutine.

### Lazy initialization with retry

Phase 7 added this for the BFF's OAuth client (chapter 05). The
pattern: try to init at startup, accept failure, retry on first
real-use. This decouples startup ordering from dependency readiness.

## What you should walk away with

After this chapter:

1. You can describe what `AkashicApp.Init()` does step by step.
2. You know the difference between the auth server and the control
   server and can predict which middleware runs on each.
3. You understand the multi-channel logger and can explain why audit
   and security are separate.
4. You recognize the atomic-pointer pattern when you see it.

## Continue to → [Chapter 04 — Bootstrap Flow](./04-bootstrap.md)
