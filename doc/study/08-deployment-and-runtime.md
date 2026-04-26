# Chapter 08 — Deployment & Runtime

> **Goal**: by the end of this chapter, you should know how to run
> Akashic in either of its two supported modes, when to pick which,
> and what tricks make the unified docker-compose work transparently
> across both.

## The two run modes

There are exactly two modes. Either akashic runs **in a container**
or it runs **on the host**. Everything else (deps, admin-bff, proxy)
runs in containers regardless.

### Mode A — full container

```bash
docker compose --profile app up -d --build
```

This brings up everything, including the akashic server itself, in
docker. The `app` profile is what gates the akashic container — by
default it's not started. Add the profile and it's included.

| When to pick this | Example tasks |
|---|---|
| Deploying to anything resembling production | Acceptance testing, demos, staging |
| Working on something that doesn't need a debugger | Small bug fixes, dependency upgrades, copy edits |
| Don't want to think about ports or DNS | Default for "just run it" |

Cost: ~30–60 second rebuild loop on Go changes. Not workflow-breaking
but real.

### Mode B — host akashic

```bash
docker compose up -d        # everything except akashic in containers
go run ./cmd/akashic run    # akashic on the host
```

The akashic server runs as a host process. Other services still in
docker. When the BFF dials `https://auth.akashic.local:8080/token`
or `https://ctrl.akashic.local:8081/...`, the request flows from
docker → host gateway → the host akashic process.

| When to pick this | Example tasks |
|---|---|
| Iterating fast on Go code | Adding a feature, debugging an OAuth flow |
| Attaching a debugger | dlv, delve breakpoints, race detector |
| Profiling | pprof endpoints, allocation tracing |

Cost: needs `AKASHIC_SERVER_CONTROL_HOST=0.0.0.0` so the docker
containers can reach the host's control plane. The default `127.0.0.1`
binding is unreachable from inside docker on Linux. (See the Linux
note in compose.)

## How the unified compose works

The non-obvious magic is that **the same compose file works in both
modes**. The trick is unconditional `extra_hosts: host-gateway`
mappings on the proxy and admin-bff containers.

```yaml
# In docker-compose.yml — applies in BOTH modes
admin-bff:
  extra_hosts:
    - "host.docker.internal:host-gateway"
    - "akashic:host-gateway"
    - "auth.akashic.local:host-gateway"
    - "ctrl.akashic.local:host-gateway"

proxy:
  extra_hosts:
    - "akashic:host-gateway"
    - "auth.akashic.local:host-gateway"
    - "ctrl.akashic.local:host-gateway"
```

These map the akashic-named hostnames to **the docker host gateway IP**
in each container's `/etc/hosts`. What that IP resolves to depends
on which mode is active:

- **Container mode**: docker port-forwarding bridges
  `host-gateway:8080 → akashic-container:8080`. The BFF dials the
  host, docker translates, the akashic container responds.
- **Host mode**: host-gateway is the docker host. The host akashic
  process listens on `0.0.0.0:8080`. The BFF dials the host, the
  host akashic process responds directly.

In both cases, the **TLS cert is the same** (auth.akashic.local SAN),
because both flavors of akashic-server load `/certs/akashic/auth.crt`
from the same volume — which Vault Agent rendered.

The browser never sees this layer. It dials
`https://auth.akashic.<your-public-domain>/...`, your host TLS
terminator forwards to the docker proxy on 8280, and the proxy
applies the same routing in both modes.

## The three changes that made this work

Phase 7 originally had a much messier hybrid mode with override files
and special scripts. Three structural fixes consolidated everything:

### 1. Drop `depends_on: akashic` from admin-bff

Before, admin-bff had `depends_on: akashic`, which meant
`docker compose --profile app up -d admin-bff` would also start
akashic — fine in container mode, but conflicting with host-akashic
mode. The dependency was removed.

Combined with...

### 2. Lazy OAuth init in admin-bff

The BFF tries to load the akashic-admin client secret at startup,
but **degrades gracefully** if the file isn't there yet. On the next
`/login` request it retries; once the akashic server has run and
created the file, the BFF picks it up automatically.

`pkg/admin_bff/server.go`'s `ensureOAuth()` — see chapter 05 for
detail.

This decouples the BFF and akashic startup orderings entirely. Any
order works; restarts of either don't require the other to restart.

### 3. Static `proxy_pass` + libc resolution in nginx

The proxy's auth.* server block originally used variable-based
`proxy_pass` with a runtime DNS resolver pointing at docker's
embedded DNS (127.0.0.11). That works for pure container mode but
**doesn't see /etc/hosts entries** — so `extra_hosts` had no effect.

Switching to static `proxy_pass https://akashic:8080;` makes nginx
resolve "akashic" at config-load via libc, which DOES honor
/etc/hosts. The `extra_hosts` entry steers the request to the host
gateway in both modes.

The tradeoff: static proxy_pass means nginx fails to start if
"akashic" doesn't resolve. With unconditional `extra_hosts` that's
a non-issue — the host-gateway IP always resolves.

## Profile mechanics

Docker Compose profiles **gate** services. A service tagged with
`profiles: ["app"]` is excluded from the default `up` unless you
pass `--profile app`. Akashic's compose uses exactly one profile —
`app` — applied to one service: akashic.

| Service | Profile gating |
|---|---|
| akashic | `app` |
| admin-bff | (none — always up) |
| proxy | (none — always up) |
| postgres, redis, ldap, vault, vault-agent, etc. | (none — always up) |

So `docker compose up -d` brings up *almost* everything (deps + BFF +
proxy + observability) — only akashic is missing. Add `--profile app`
to include akashic too.

This was deliberate: in host-akashic mode, akashic-on-host substitutes
for akashic-in-container, so the BFF + proxy still need to be running.
Profiles let you opt into just the akashic container without affecting
the rest of the stack.

## Logs & debugging

For container-mode akashic, logs flow through `docker compose logs`:

```
docker compose logs akashic -f      # follow
docker compose logs admin-bff -f    # BFF
docker compose logs proxy -f        # nginx
```

For host-mode, akashic's stderr goes directly to your terminal where
`go run` is running. Other services are still in docker so use
`docker compose logs` for them.

There's also Loki — every service ships logs there too (when
configured). Browse via `https://grafana.akashic.<domain>/`. Useful
when correlating events across services.

## The `./scripts/reset-akashic.sh` reset

Single script for full-stack reset (chapter 02 mentioned it). Wipes:

- `./certs/`, `./keys/`, `./.secrets/vault*`, `./logs/` (preserving
  .gitignore + README.md)
- Every named docker volume prefixed `akashic_` (postgres, redis,
  ldap, grafana, redisinsight, vault, vault-agent, vault-logs, etc.)

After a reset, **wait for vault-agent to render certs** (5–10 sec
after `docker compose up -d`) before starting akashic. Otherwise
akashic will fail to start with "cannot load certificate."

## Common runtime questions

### "I changed Go code; how fast can I see it?"

| Mode | Reload mechanism |
|---|---|
| Host (`go run`) | Ctrl+C, re-run `go run ./cmd/akashic run` (~3-5 sec) |
| Container (`--profile app`) | `docker compose --profile app up -d --build akashic` (~10-30 sec with warm cache) |

### "I changed FE code; how fast can I see it?"

You need a Go rebuild because the FE is embedded:
`docker compose build admin-bff && docker compose up -d --no-deps
admin-bff` (or, in host-bff mode that we don't currently support,
just Vite hot-reload).

### "I changed nginx.conf; how fast can I see it?"

The proxy bakes nginx.conf into its image:
`docker compose build proxy && docker compose up -d --force-recreate
proxy`.

### "Why isn't /api/X working?"

Three layers can break it. Walk them in order:

1. Is the BFF running? `docker compose logs admin-bff`
2. Did the BFF reach the akashic control plane? Look for
   `BFF_AUTH_FAILED` in the BFF audit log → mTLS broke
3. Did the control plane handler error? `docker compose logs akashic`
   (or the host-mode terminal) should show the request

### "My OAuth flow stopped working after a reset"

The akashic-admin client secret regenerates on every fresh akashic
startup. The admin-bff reads it lazily; if the BFF was running when
you reset, restart it (or wait for the next `/login` to trigger
`ensureOAuth()` retry).

## Switching between modes mid-session

You don't have to tear down to switch:

```bash
# host-akashic → container-only
docker compose --profile app up -d akashic
# (the BFF will see the same secret file, served by either akashic flavor)

# container-only → host-akashic
docker compose --profile app stop akashic
go run ./cmd/akashic run --verbose
```

The BFF and proxy don't notice the swap — their `extra_hosts` aliases
point at host-gateway either way, and lazy init handles whichever
akashic is currently authoritative.

## What you should walk away with

After this chapter:

1. You know the two run modes and when to pick each.
2. You can explain the `extra_hosts: host-gateway` trick and why it
   makes one compose file work in both modes.
3. You know which three structural changes (lazy init, drop
   depends_on, static proxy_pass) eliminated the need for override
   files.
4. You know the rebuild commands for changes in Go, FE, and nginx
   config.
5. You can switch modes mid-session without restarting the BFF.

## Continue to → [Chapter 09 — Reference & Glossary](./09-reference-glossary.md)
