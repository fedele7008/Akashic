# `.secrets/sample/`

Operator-managed credential drops for in-stack samples (the Next.js
sample at `services/portal/`, the static-HTML sample at
`services/sample-static/`).

## What goes here

Files written by `akashic-cli clients create --save-credentials-to`,
typically a JSON envelope:

```json
{
  "client_id": "tc-abc1234567",
  "client_secret": "<base64-string>"
}
```

The samples mount this directory at `/secrets/sample/` (read-only)
and read credentials at OAuth-call time so a freshly-registered
client takes effect without restarting the sample container.

## Why this directory exists

Samples run in the same docker-compose stack as akashic-server. The
sample's container starts BEFORE the operator can run
`akashic-cli clients create`. Reading credentials from a runtime
file (rather than at container startup) lets the post-bootstrap
"register your portal" step land in a still-running sample.

Real-tenant deployments don't use this — they paste the printed
secret into their portal's `.env` and start the portal once.

## Conventions

- File names mirror the sample identity:
  - `nextjs.json` — Next.js sample (`services/portal/`)
  - `static.json` — static-HTML sample (`services/sample-static/`)
    (only client_id, no secret — SPA / public client)
- Mode `0600` (set by the CLI's atomic write).
- Wiped by `scripts/reset-akashic.sh` on full reset.
