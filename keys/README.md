# `./keys/` — Server-Managed Key Material

This directory holds key material that the **akashic-server itself**
manages — distinct from `./certs/`, which is rendered by Vault Agent.

## Current contents (Phase 7+)

```
./keys/
└── oauth/
    └── <kid>.json       OAuth/OIDC JWT signing keys (RSA-2048, RS256)
                         Generated on first server start; rotated manually
                         until auto-rotation lands in a later phase.
```

## Why a separate directory from `./certs/`

Two distinct trust domains that benefit from physical separation:

| Domain | Source of truth | Mount inside container | Lifecycle |
|---|---|---|---|
| `./certs/` | Vault Agent (issues from Vault PKI) | `/certs:ro` (read-only) | Auto-rotated by Vault Agent at ~2/3 TTL |
| `./keys/` | akashic-server (generates on first start) | `/keys:rw` (writable) | Manual rotation until auto-rotation phase lands |

If we tried to put OAuth signing keys under `./certs/`, the akashic
server couldn't write them in containerized mode — `/certs` is mounted
read-only as defense-in-depth (so a compromised akashic process can't
silently corrupt Vault-issued certs).

Separating the two domains lets each have appropriate permissions,
ownership, and rotation cadence without compromising the other.

## File permissions

```
./keys/                    drwx------  (0700)
./keys/oauth/              drwx------  (0700)
./keys/oauth/<kid>.json    -rw-------  (0600)
```

The akashic-server enforces these permissions on every write. If a key
file's permissions drift (e.g., from `chmod -R`), the server logs a
warning but continues to operate; the next rotation will tighten them.

## Reset and recovery

`./scripts/reset-akashic.sh` wipes this directory along with `./certs/`.
On the next server start, a fresh OAuth signing key is generated
automatically. Any previously-issued JWTs become un-verifiable
(missing kid in the new JWKS) — which is the correct behavior, since
a vault reset implies "burn it all."

If you want to preserve OAuth signing keys across resets (e.g., to
keep existing tokens valid), back up `./keys/` before running the
reset script and restore afterward. This is rare; the usual operator
intent on a vault reset is "fresh deployment, all old material void."
