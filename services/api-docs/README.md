# services/api-docs

API documentation surface for Akashic. Currently a static collection
of hand-authored OpenAPI 3.1 specs — one per server. The directory
lives under `services/` rather than `doc/` because, conceptually,
this is the seed of a future docs-rendering service (Swagger UI /
Redoc behind an `apidocs.<domain>` subdomain). Today there is no
container; only the spec files. Tomorrow we add a static-site
container that serves them.

## The three specs

| File | Server | Port | Trust model | Audience |
|------|--------|------|-------------|----------|
| [`auth-server.yaml`](./auth-server.yaml) | OIDC IdP | 8080 | public + browser session + OAuth bearer | end users (browser), OAuth clients |
| [`api-server.yaml`](./api-server.yaml) | Resource API | 8082 | public (registration only) + OAuth bearer | end users (via portal), tenant operators |
| [`control-server.yaml`](./control-server.yaml) | Admin / control plane | 8081 | mTLS (CLI / BFF) | operators, automation |

This split mirrors the runtime architecture: each spec covers one
listener, one trust mechanism, one audience. Don't merge them — the
reader for a control-plane spec is an SRE, the reader for the
auth-server spec is an OAuth-client author. Different vocabulary,
different needs, different security definitions.

## Why hand-authored (vs. swag/swaggo)

We deliberately **don't** use `swag init` to generate these from Go
struct tags / handler comments, even though that's the popular pattern.
Reasons:

1. **Three trust models, three audiences.** A single repo-wide swag
   sweep produces one giant spec; we want three intentionally separate
   ones. Splitting after generation is more annotation overhead than
   maintaining the YAML directly.
2. **OAuth/OIDC endpoints don't fit the "envelope" pattern.** The auth
   server emits raw RFC-shaped responses (RFC 6749 token, RFC 6750
   userinfo, OpenID discovery), but the rest of the codebase uses
   `pkg/server/response`'s `{success, data|error}` envelope. Swag
   assumes one response shape per handler; documenting the exception
   inline is awkward.
3. **Auto-generators encode whatever they see.** When a handler does
   something subtle (envelope-bypass, RFC error format, multi-method
   dispatch on the same path), the generator either gets it wrong or
   forces you to scatter `@Router` / `@Failure` lines across the code.
   The signal-to-noise ratio of a hand-written YAML is much higher.
4. **Specs are documentation, not contract.** These describe what the
   server does today, not what callers must trust. If a Go struct field
   is renamed and the spec drifts, that's a doc bug, not a contract
   break — same as any markdown drift.

## Promoting this to a real service

When the time comes to render these in-browser, the cheapest path is:

1. Drop a Swagger UI or Redoc Docker image into this directory
   (`Dockerfile`, plus a thin `nginx.conf` if needed).
2. Mount or copy the three `.yaml` files into the container's web
   root.
3. Configure the bundle's multi-spec dropdown
   (`urls: [{name, url}, ...]`) so users can switch between auth,
   resource, and control specs.
4. Add the service to `docker-compose.yml` and create an
   `apidocs.<domain>` route in `services/proxy/nginx.conf`.
5. Restrict the control-plane spec to internal/operator surfaces —
   its endpoints are mTLS-gated, so a public swagger page would
   advertise a surface that 99% of the world can't even reach.

No code changes required to enable this — the specs are already
the static input; the renderer is the only missing piece.

## Maintenance rules

When you add or modify a route in `pkg/server/{auth,api,control}/`:

1. Find the handler (typically in `handlers*.go`).
2. Update the matching spec in this directory.
3. If the change affects an existing schema (e.g. adding a field to
   `User` or `ClientView`), update the **schema** in the spec — don't
   inline-duplicate it on each operation.
4. Bump the spec's `info.version` field if the change is breaking
   (removed field, semantic change, etc.). Non-breaking additions
   don't need a bump.

Keep error code strings (`USERNAME_TAKEN`, `BEARER_INVALID_TOKEN`,
`AUTH_SERVER_RUNNING`, …) in lockstep with what the handlers actually
emit. These strings are the API's stable contract, not the HTTP status
codes.

## Validating a spec

```bash
# Quick syntax check via npx (one-off; no install needed)
npx @redocly/cli lint services/api-docs/auth-server.yaml
npx @redocly/cli lint services/api-docs/api-server.yaml
npx @redocly/cli lint services/api-docs/control-server.yaml

# Or with go-swagger if it's already on the system
swagger validate services/api-docs/auth-server.yaml
```

Linter warnings about missing `examples`, `description`, or
`operationId` are non-blocking — the goal here is structural
correctness, not full prose coverage. Once this becomes a real
rendered surface, fill those in for callers' sake.
