# login-with-akashic-py

A minimal Flask app that demonstrates the **full OAuth 2.1 + OpenID
Connect flow** against an Akashic deployment, end-to-end.

> **Default port: `5050`** (not 5000). macOS Monterey+ ships AirPlay
> Receiver squatting on port 5000 by default; Flask appears to bind
> but the OS routes traffic to AirPlay, which produces a confusing
> `chrome-error://chromewebdata/` symptom downstream. Picking a
> non-system-default port avoids this entirely.

```
┌────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  browser   │     │  this Flask app  │     │  Akashic         │
│  (you)     │     │  localhost:5050  │     │  auth.<tenant>   │
└─────┬──────┘     └────────┬─────────┘     └────────┬─────────┘
      │                     │                        │
      │ click "Sign in"     │                        │
      ├────────────────────►│                        │
      │                     │ 302 → /authorize       │
      │◄────────────────────┤                        │
      │ follow redirect     │                        │
      ├──────────────────────────────────────────────►│
      │                     │  user signs in         │
      │◄──────────────────────────────────────────────┤
      │ 302 /callback?code= │                        │
      ├────────────────────►│                        │
      │                     │ POST /token (code +    │
      │                     │   secret + verifier)   │
      │                     ├───────────────────────►│
      │                     │◄───────────────────────┤
      │                     │ access_token, id_token │
      │                     │                        │
      │                     │ verify id_token sig    │
      │                     │ against /jwks.json     │
      │                     ├───────────────────────►│
      │                     │◄───────────────────────┤
      │ 302 → home (signed-in) │                     │
      │◄────────────────────┤                        │
```

The whole flow is in **one file** (`app.py`, ~250 LOC). Read it
top-to-bottom; the OAuth steps are commented inline with
their RFC / OIDC spec references. This is a learning artefact, not
a production template — split into proper modules + add token
refresh + cache discovery with TTLs before deploying anything real.

## Prerequisites

- A running Akashic deployment (host-mode `go run` or
  `docker compose --profile app up -d`).
- Python 3.11+ on your host (3.10 may work; not tested).
- The `akashic-cli` binary configured against your deployment
  (so you can register this app as a client).

## Setup

### 1. Create a Python venv and install dependencies

```bash
cd test-clients/login-with-akashic-py
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Register this app as an OAuth client in Akashic

```bash
akashic-cli clients create --type WEB \
    --name "Login Test (Python)" \
    --redirect-uri http://localhost:5050/callback
```

Copy the printed `client_id` and `client_secret` — the secret is
shown ONCE, so capture it now.

> **Why `--type WEB`**: this is a server-side BFF — the Flask
> backend holds the secret and exchanges codes via `/token`. Use
> `--type SPA` if you were building a browser-only PKCE-flow
> integration; that variant is already demonstrated by
> `services/sample-static/`.

### 3. Configure via `.env` (recommended) — or inline env vars

> ⚠ **`AKASHIC_ISSUER` is the AKASHIC AUTH SERVER's URL — NOT this
> demo's URL.**
>
> This demo runs at `http://localhost:5050` and acts as a
> THIRD-PARTY CLIENT calling Akashic. The "issuer" is the OAuth
> identity provider — your Akashic deployment's auth server.
>
> Examples:
> - `https://auth.akashic.example.com` ← your real Akashic auth URL
> - `https://auth.akashic.yohan-yoon.com`
>
> If you set `AKASHIC_ISSUER=http://localhost:5050` (this app's URL),
> the demo will refuse to start with a clear error.

**Recommended: copy the example file and edit it in-place.**

```bash
cp .env.example .env
# Open .env in your editor and fill in:
#   AKASHIC_ISSUER=https://auth.akashic.<your-domain>
#   AKASHIC_TEST_CLIENT_ID=<from step 2>
#   AKASHIC_TEST_CLIENT_SECRET=<from step 2>
python app.py
```

`.env` is gitignored locally — the secret never touches version
control. `.env.example` (committable, no real values) is what you
copied from.

**Alternative: inline export.** Anything in your shell env wins
over `.env` (python-dotenv's default), so this still works for
quick experiments or scripted runs:

```bash
AKASHIC_ISSUER=https://auth.akashic.<your-domain> \
AKASHIC_TEST_CLIENT_ID=tc-abcd1234ef \
AKASHIC_TEST_CLIENT_SECRET=<the-secret-from-step-2> \
    python app.py
```

You should see:

```
INFO:app:login-with-akashic-py starting on http://localhost:5050
INFO:app:issuer:       https://auth.akashic.<your-domain>
INFO:app:client_id:    tc-abcd1234ef
INFO:app:redirect_uri: http://localhost:5050/callback
 * Running on http://localhost:5050
```

### 4. Open the browser and sign in

Navigate to http://localhost:5050, click **"Sign in with Akashic"**,
authenticate against your Akashic deployment, and you should land
back on the home page with your identity displayed.

## Environment variables

| Variable | Required? | Default | Purpose |
|---|---|---|---|
| `AKASHIC_ISSUER` | yes | — | Public URL of the Akashic auth server (e.g. `https://auth.akashic.example.com`). |
| `AKASHIC_TEST_CLIENT_ID` | yes | — | `client_id` from `akashic-cli clients create`. |
| `AKASHIC_TEST_CLIENT_SECRET` | yes | — | `client_secret` from same. WEB clients only. |
| `AKASHIC_TEST_REDIRECT_URI` | no | `http://localhost:5050/callback` | Must match what was registered. |
| `AKASHIC_TEST_SCOPE` | no | `openid profile email` | Space-separated. |
| `AKASHIC_TEST_PORT` | no | `5050` | Local bind port. Default avoids macOS AirPlay's port-5000 squatter. |
| `AKASHIC_TLS_VERIFY` | no | `true` | Set to `false` to skip TLS verification on calls to Akashic (dev with self-signed CA). |
| `REQUESTS_CA_BUNDLE` | no | — | Standard Python pattern. Path to a CA bundle (e.g. your akashic-internal CA). Preferred over disabling verification. |

## What this app does NOT demonstrate

- **Token refresh** — Akashic doesn't issue refresh tokens (Phase 7+
  decision); when the access token expires the user re-signs in.
- **Resource API calls** — the app shows identity from the id_token
  but doesn't call Akashic's `/users/me` or `/clients/mine`. Wire up
  via `Authorization: Bearer <access_token>` if you want to.
- **Production session storage** — uses Flask's signed-cookie sessions.
  Real apps use a server-side store (Redis, Postgres) so logout
  actually invalidates sessions, not just the cookie.
- **Concurrent flows / state cleanup** — the session-stored state and
  PKCE verifier overwrite on each /login click. A user with two
  /login tabs open will see one of them fail with "state mismatch."
  Real apps key by a per-flow ID.

## Common errors and what they mean

| Error | Likely cause | Fix |
|---|---|---|
| `ERROR: AKASHIC_ISSUER points at this Flask app` (refuses to start) | You set `AKASHIC_ISSUER=http://localhost:5050` (or `127.0.0.1:5050`) — that's THIS app, not Akashic. | Set it to your Akashic auth server's URL, e.g. `https://auth.akashic.example.com`. |
| `ERROR: OIDC discovery at … is missing required fields` (refuses to start) | `AKASHIC_ISSUER` points at SOME server, but not Akashic's auth server (e.g. the api server, control plane, or an unrelated host). | Use the auth server's URL specifically — it's the one whose `/.well-known/openid-configuration` returns `authorization_endpoint`, `token_endpoint`, `jwks_uri`. |
| `redirect_uri_mismatch` from Akashic | The redirect_uri you registered in `clients create` doesn't match `AKASHIC_TEST_REDIRECT_URI`. | Re-register with the exact URL `http://localhost:5050/callback`, OR override the env var. |
| `invalid_client` from /token | Wrong `client_secret`, OR you registered as SPA (no secret) but this app sends one. | Run `clients rotate-secret <id>` to get a fresh secret, OR re-register as WEB. |
| `ssl.SSLCertVerificationError` | Akashic uses a self-signed CA your Python doesn't trust. | Set `REQUESTS_CA_BUNDLE=/path/to/akashic-ca.pem` or (dev only) `AKASHIC_TLS_VERIFY=false`. |
| `bootstrap is not yet complete` from `clients create` | You haven't run `akashic-cli bootstrap create-root` yet on this Akashic instance. | Run that first; then retry `clients create`. |
| `Unsafe attempt to load URL ... from frame with URL chrome-error://` (in browser) | Downstream of one of the above — the OAuth chain redirected to an unreachable URL, browser landed on a chrome-error page, clicking back to localhost is blocked by Chrome's mixed-protocol rule. | Fix the underlying configuration error; **close any stale tabs** and open a fresh tab to `http://localhost:5050/`. |
| `ERROR: cannot bind localhost:<port>` (refuses to start) | Something else is listening on the port. On macOS specifically: AirPlay Receiver squats on port 5000 by default, which is why this demo's default port is **5050** (not 5000). | Pick a different port via `AKASHIC_TEST_PORT=<num>` and re-register the OAuth client with `--redirect-uri http://localhost:<num>/callback`. If your override is 5000 specifically, also disable AirPlay Receiver: System Settings → General → AirDrop & Handoff → AirPlay Receiver: OFF. |

## Tearing down

To clean up after testing:

```bash
# Inside the app: click "Sign out" — kills both the local session
# AND the Akashic auth-server session (RP-Initiated Logout).

# When done with the app entirely, optionally delete the OAuth
# client registration:
akashic-cli clients delete tc-abcd1234ef
```
