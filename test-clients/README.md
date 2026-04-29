# test-clients

Standalone third-party clients used to manually exercise Akashic
end-to-end. Each subdirectory is a self-contained app that an
operator runs OUTSIDE the docker-compose stack to play the role of
"some random tenant integrating Login with Akashic."

The in-stack samples (`services/portal/`, `services/sample-static/`)
demonstrate the same flows but live in the same compose project as
akashic-server itself. The clients here are meant to feel like a
real third-party — operator clones, registers a client, runs the
app on their host, and watches the round-trip happen against the
public Akashic URLs.

## Available test clients

| Path | Type | Purpose |
|---|---|---|
| `login-with-akashic-py/` | WEB (Flask) | Python+HTML "Login with Akashic" demonstration. Server-side BFF holds the client_secret and exchanges authorization codes via `/token`. |

## General workflow

1. Pick a test client and `cd` into its directory.
2. Read its `README.md` for setup steps (Python version, deps, env).
3. Register the test app as an OAuth client in your Akashic deployment:
   ```bash
   akashic-cli clients create --type WEB \
       --name "Login Test" \
       --redirect-uri http://localhost:5050/callback
   ```
4. Copy the printed `client_id` + `client_secret` into the test app's
   environment variables (each app's README documents the exact names).
5. Run the test app and exercise the flow in your browser.

## Why these aren't part of `make test`

These clients require a running Akashic deployment + interactive
browser steps (the operator clicks "Sign in," types credentials,
clicks "Authorize"). Automating them would require headless-browser
fixtures + a fully-bootstrapped Akashic instance — out of scope for
unit-test-style CI. They're intentionally manual.
