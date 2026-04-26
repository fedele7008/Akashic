# Chapter 01 — PKI and TLS

> **Goal**: by the end of this chapter, you should understand where
> every cert in the project comes from, who issues them, and how
> rotation works without anything restarting.

## Why PKI deserves a whole chapter

In most projects you'd dismiss "PKI" as an ops detail. In Akashic,
PKI **is** the spine — it's how every component identifies itself,
how trust is established between services, and how the OAuth signing
keys are rotated. If you don't understand the PKI, you can't reason
about why services can't talk to each other when something breaks.

The single guiding principle: **TLS everywhere, no exceptions, no
self-signed-per-service.** Every cert traces back to one root, issued
by Vault.

## The trust hierarchy

```
                     pki-root (Vault root CA)
                            │
            ┌───────────────┼─────────────────┐
            ▼               ▼                 ▼
       pki-internal   pki-mtls-akashic-ctrl   (future: tenant-specific
       (server certs) (mTLS for control       intermediates)
                       plane only)
            │               │
   ┌────────┼────────┐      ├──── client certs (akashic-cli, admin-bff)
   ▼        ▼        ▼      └──── server cert (akashic control plane)
  postgres redis    ldap
  loki     auth     ctrl
  ...      (akashic)
```

**Two intermediates** sit under the root:

- **`pki-internal`** issues *server certs* for everyone — postgres,
  redis, ldap, loki, the akashic auth listener (port 8080), the
  loki-proxy. The leaf certs include the relevant docker network
  alias as a SAN (e.g. `auth.akashic.local`, `redis.akashic.local`).
- **`pki-mtls-akashic-ctrl`** is the dedicated mTLS authority for the
  akashic *control plane* (port 8081). It issues *both* the server
  cert that the control plane presents *and* the client certs that
  authorized callers (akashic-cli, admin-bff) present back. Anyone
  not signed by this intermediate fails the mTLS handshake.

The two-intermediate split is not just bureaucracy — it lets you
have a totally separate trust scope for the management API. The
public-facing servers' CA bundle includes only `pki-internal`, so
even if a public-server private key were somehow compromised, the
attacker would not become a valid client of the control plane
(they'd need a cert from `pki-mtls-akashic-ctrl` too).

## Vault's role: the certificate authority

The `vault` container holds the root CA chain and the two
intermediates. It exposes a PKI HTTP API; clients authenticate to
Vault, request a cert, and Vault signs and returns it.

The actual *issuance* of certs to disk doesn't happen by anyone's
direct API call. It happens through **Vault Agent**.

## Vault Agent: the cert-rendering daemon

`vault-agent` is a long-running container whose only job is to
**continuously render certificates from Vault to filesystem paths**
that other containers can read.

It works from a set of *templates* in
`services/vault-agent/templates/`. Each template names:

1. A PKI mount + role (e.g. `pki-internal/issue/server`)
2. A common-name and SAN list
3. The output paths on disk

For example, `services/vault-agent/templates/akashic-auth.tpl`:

```hcl
{{- with pkiCert "pki-internal/issue/server"
  "common_name=auth.akashic.local"
  "alt_names=auth.akashic.local,localhost"
  "ttl=720h" -}}
{{ .Key  | writeToFile "/certs/akashic/auth.key" "root" "root" "0600" }}
{{ .Cert | writeToFile "/certs/akashic/auth.crt" "root" "root" "0644" }}
{{ scratch.Set "chain" "" }}
{{ range .CAChain }}{{ scratch.Set "chain" (printf "%s%s\n" (scratch.Get "chain") .) }}{{ end }}
{{ scratch.Get "chain" | writeToFile "/certs/akashic/auth-ca.crt" "root" "root" "0644" }}
{{- end -}}
```

What this template does, in plain English:

1. Asks Vault to issue a cert with CN `auth.akashic.local` (and
   `localhost` as an additional SAN) from the `pki-internal/issue/server`
   role, valid for 720 hours (30 days).
2. Writes the private key to `/certs/akashic/auth.key` (mode 0600).
3. Writes the cert to `/certs/akashic/auth.crt`.
4. Concatenates the issuing CA chain into `/certs/akashic/auth-ca.crt`
   so callers that need to verify *the chain* can read it from one
   file.

`/certs` inside the vault-agent container is a bind-mount of the
host's `./certs/` directory. Other containers mount the same dir and
*read* from it. So when vault-agent writes a new cert, every reader
container sees it instantly.

The vault-agent process **continuously monitors lease expiration**.
When a cert is approaching its TTL/3, vault-agent re-issues, atomically
replaces the file (write-to-tmp, rename), and the cycle repeats. No
human action required.

## How services pick up rotated certs

Vault Agent rotating a cert on disk is necessary but not sufficient.
The reading service has to **notice** that the file changed and
*rebind* its TLS state to the new material. There are two patterns
in the codebase:

### Pattern A: SIGHUP to the running process

Used by Loki:

```
services/loki/cert-watcher.sh
  ├─ inotifywait detects /certs/loki/loki.crt changed
  ├─ kill -HUP $LOKI_PID
  └─ Loki re-reads its TLS config from the running config
```

Loki has built-in SIGHUP handling that re-reads its TLS material on
the fly. Connections in flight finish on the old cert; new
connections use the new cert. No Loki restart.

### Pattern B: In-process atomic-pointer reload

Used by the akashic Go server (and the admin-bff for its mTLS client):

```
pkg/pki/Reloader
  ├─ atomic.Pointer[tls.Certificate]
  ├─ fsnotify watches the cert file
  ├─ on event: re-load file, atomically swap pointer
  └─ tls.Config.GetCertificate callback returns whatever the pointer
     currently points at
```

Go's `tls.Config` has a `GetCertificate` (server side) and
`GetClientCertificate` (client side) callback that's invoked **per
TLS handshake**. By having those callbacks return whatever the atomic
pointer currently points at, certs swap mid-flight without a restart.
In-flight connections continue on the old material; new handshakes
pick up the new cert.

This pattern is reused for the OAuth signing-key store too (chapter
06's keystore section).

## The `./certs/` directory layout

```
./certs/
├── akashic/
│   ├── auth.crt         ← akashic auth listener (port 8080)
│   ├── auth.key
│   ├── auth-ca.crt      ← chain to verify auth.crt
│   ├── mtls-ctrl.crt    ← mTLS server cert for control plane (port 8081)
│   ├── mtls-ctrl.key
│   └── mtls-ca.crt      ← CA bundle accepted for mTLS client certs
│   (the control plane is mTLS-only — there is no separate
│    `pki-internal` server cert here, by design)
├── bff/
│   ├── akashic-ctrl-client.crt  ← admin-bff's CLIENT cert for mTLS
│   ├── akashic-ctrl-client.key
│   └── mtls-ca.crt              ← CA bundle to verify control plane's server cert
├── akashic-cli/
│   └── (similar — the CLI's mTLS client cert)
├── postgres/
│   ├── postgres.crt + .key + ca.crt
├── redis/
│   ├── redis.crt + .key + ca.crt
├── ldap/
│   ├── ldap.crt + .key + ca.crt
├── vault/
│   └── (vault's own server cert — the only one issued differently)
└── ca/
    └── (root + intermediate CA certs in PEM)
```

The pattern: each consumer gets a directory named after itself, with
the leaf cert + key + a CA-bundle for verification.

## Volumes and trust boundaries

The `./certs/` directory is a **shared bind-mount**. Every service
container mounts `/certs` (read-only or read-write depending on
role):

- vault-agent mounts it **read-write** (it's the writer)
- everyone else mounts it **read-only**

Within a container, `/certs/` is essentially a slow database of
TLS material that the application reads at startup and re-reads
when the file changes (via the patterns above).

**The trust boundary is the volume mount, not the filesystem
permissions.** Anything that mounts `/certs` can read every cert
in there. Filesystem perms (0600 on private keys) are defense in
depth, but the real isolation comes from "does this container have
the volume?" — most don't.

## Why `./keys/` is separate

Phase 7 added a *second* writable trust domain: `./keys/`.

Why a new dir instead of putting OAuth signing keys under `./certs/`?

- `./certs/` is **Vault-Agent-managed** (read-only to the akashic
  server — Vault is the writer).
- `./keys/` is **server-managed** (the akashic server itself writes
  here — it generates its own RSA signing keys, its own client
  secrets).

Mixing them would have meant either making `./certs/` writable for
akashic (breaking the Vault-Agent-is-canonical model) or making
akashic ask Vault to issue OAuth signing material (Vault PKI doesn't
issue arbitrary RSA keys, only X.509 certs).

So:

| Directory | Owner / writer | Readers |
|---|---|---|
| `./certs/` | Vault Agent | every service, read-only |
| `./keys/` | Akashic server | admin-bff (read-only, for the akashic-admin client secret) |

This separation is enforced by the docker-compose volume modes:
`certs:/certs:ro` for everyone except vault-agent, `keys:/keys:rw`
for akashic, `keys:/keys:ro` for admin-bff.

## TLS modes per dependency

Not every service uses the same TLS posture. The defaults in
`.env.example`:

```
AKASHIC_POSTGRES_TLS=on        # forces TLS on TCP connections
AKASHIC_REDIS_TLS=on           # forces TLS, plain port disabled
AKASHIC_LDAP_TLS=on            # LDAPS (port 636) only
AKASHIC_LOKI_PROXY_TLS=on      # loki-proxy terminates TLS
```

Each toggle propagates into both the server's listener (e.g., postgres
starts with TLS-required) and the client's dialer in the akashic
server (e.g., the postgres GORM driver builds a `tls.Config` with the
right CA bundle).

There's a subtle wrinkle for LDAP: it supports LDAPS (TLS on its own
port 636) and StartTLS (upgrade plain ldap:389 to TLS in-band).
Akashic uses **StartTLS by default** — the connection starts as plain
ldap:389 and immediately negotiates TLS via the `STARTTLS` extension.
This is configurable via `ldap.tls_mode` (`ldaps`, `starttls`, or
`plain`). See `pkg/ldap/client.go`'s `resolveTLSMode()`.

## Cert rotation: the full picture

Putting it all together, here's what happens when a cert is about
to expire:

```
1. Vault Agent's lease tracker notices auth.crt is at TTL/3 remaining
2. Vault Agent calls Vault: "issue a new cert with these SANs"
3. Vault returns: new cert + new key + CA chain
4. Vault Agent renders to /certs/akashic/auth.crt.tmp + .key.tmp + .ca.tmp
5. Atomic rename: .tmp → real path
6. fsnotify (in akashic server) fires
7. pkg/pki/Reloader reads the new files, builds a new tls.Certificate
8. Atomic.Pointer.Store(newCert)
9. Next TLS handshake: GetCertificate callback returns the new cert
10. In-flight handshakes: old cert is still referenced by their tls.Config snapshot, completes normally
11. Eventually all old connections close; the old cert object is GC'd
```

**No restart anywhere in this chain.** Vault Agent doesn't restart.
Akashic doesn't restart. The browser just sees one cert one minute
and a different cert the next, both signed by a CA it trusts.

## When PKI breaks

The most common failure is `./certs/` being empty or stale:

- After `./scripts/reset-akashic.sh` wipes `./certs/`, you have to
  bring up the dependency stack and *wait* for vault-agent to render
  certs (typically 5-10 seconds) before akashic can start with TLS.
- If a cert exists but its CA chain has rotated (e.g., you reset
  Vault but a downstream service has the old CA cached), TLS
  handshakes fail with "unknown authority". The reset script wipes
  every CA-bound cache for this reason.

A useful debug habit: when something TLS-y breaks, your first three
checks are:

1. Does the cert file even exist? `find ./certs -name '*.crt'`
2. Is it the same one the dialer is verifying against? `openssl
   s_client -connect <host>:<port>` and compare cert fingerprints
3. Has Vault Agent's lease expired? `docker compose logs vault-agent
   --tail 50`

## What you should walk away with

After this chapter:

1. You can name the two PKI intermediates and explain what kind of
   cert each one issues.
2. You understand vault-agent as a cert-rendering daemon, not just a
   "vault thing."
3. You know the two cert-reload patterns (SIGHUP and atomic-pointer)
   and which services use which.
4. You can explain why `./certs/` and `./keys/` are separate.
5. You know the debug ladder for "TLS isn't working."

## Continue to → [Chapter 02 — Data and Dependencies](./02-data-and-deps.md)
