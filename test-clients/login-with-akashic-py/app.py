"""
Login-with-Akashic — Flask demo.

A minimal third-party "tenant" that demonstrates OAuth 2.1 +
OpenID Connect against an Akashic deployment, end-to-end:

  1. User clicks "Sign in with Akashic" → redirect to Akashic's
     /authorize endpoint with state+nonce+PKCE.
  2. Akashic authenticates the user and redirects back to /callback
     with an authorization code.
  3. We POST to Akashic's /token endpoint to exchange the code for
     access_token + id_token (passing client_secret + code_verifier).
  4. We verify the id_token's signature against Akashic's JWKS and
     check the standard claims (iss, aud, exp, nonce).
  5. User identity is captured in the Flask session; the home page
     greets them and offers a logout button.
  6. Logout clears the local session AND triggers Akashic's
     RP-Initiated Logout (so the auth-server session cookie dies
     too — without this step, the next "Sign in" silently re-auths).

Deliberately single-file. Reading top-to-bottom should give a clear
picture of the OAuth flow without library abstractions hiding the
spec mappings. This is a learning artefact, not a production
template.

Run:
  pip install -r requirements.txt
  AKASHIC_ISSUER=https://auth.akashic.<your-tenant> \\
  AKASHIC_TEST_CLIENT_ID=<from `akashic-cli clients create`> \\
  AKASHIC_TEST_CLIENT_SECRET=<from `akashic-cli clients create`> \\
      python app.py
"""

import base64
import hashlib
import logging
import os
import secrets
import socket
import time
from urllib.parse import urlencode, urlparse

import jwt
import requests
from dotenv import load_dotenv
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

# Load `.env` from the current working directory before any env-var
# resolution. Variables already set in the process environment win
# over the file (python-dotenv's default), so operators who prefer
# `AKASHIC_ISSUER=... python app.py` still get the inline override.
load_dotenv()


# ─── Configuration (env-driven, fail-fast on missing) ────────────────


def _require(name: str) -> str:
    """Read a required env var; abort startup with a clear message
    if missing. Better than letting the first OAuth click 500."""
    val = os.environ.get(name)
    if not val:
        raise SystemExit(
            f"\nERROR: env var {name} is required.\n"
            f"See README.md for the full setup walkthrough.\n"
        )
    return val


ISSUER = _require("AKASHIC_ISSUER").rstrip("/")
CLIENT_ID = _require("AKASHIC_TEST_CLIENT_ID")
CLIENT_SECRET = _require("AKASHIC_TEST_CLIENT_SECRET")
REDIRECT_URI = os.environ.get(
    "AKASHIC_TEST_REDIRECT_URI", "http://localhost:5050/callback"
)
# `offline_access` is included by default so the demo can showcase
# the refresh-token rotation + replay-detection flow on the home
# page (the "Token liveness lab"). Operators who want to test the
# AT-only flow can override the env var to drop it.
SCOPE = os.environ.get("AKASHIC_TEST_SCOPE", "openid profile email offline_access")
# 5050 (not 5000) by default. macOS Monterey+ ships AirPlay Receiver
# squatting on 5000 — Flask binds successfully but the OS routes
# requests to AirPlay, so the browser gets garbage and lands on
# chrome-error://. 5050 has no famous default so it's collision-light.
PORT = int(os.environ.get("AKASHIC_TEST_PORT", "5050"))

# TLS verify toggle — operators on self-signed CA can either point
# REQUESTS_CA_BUNDLE at the trust bundle (recommended) or set this
# to `false` to skip verification entirely (dev-only, INSECURE).
TLS_VERIFY: bool | str = os.environ.get(
    "AKASHIC_TLS_VERIFY", "true"
).lower() not in ("0", "false", "no")
if TLS_VERIFY and (bundle := os.environ.get("REQUESTS_CA_BUNDLE")):
    # When REQUESTS_CA_BUNDLE is set, requests already picks it up
    # automatically — we just surface it in the startup log so the
    # operator knows which trust bundle is in play.
    logging.info("using CA bundle from REQUESTS_CA_BUNDLE: %s", bundle)


# ─── Issuer sanity check ─────────────────────────────────────────────


def _validate_issuer() -> None:
    """Refuse to start when AKASHIC_ISSUER is obviously misconfigured.

    The most common copy-paste mistake is setting AKASHIC_ISSUER to
    THIS Flask app's URL (http://localhost:5000) instead of the
    Akashic auth server's URL. That makes OIDC discovery fetch from
    this app's own /.well-known/openid-configuration, which 404s,
    and the OAuth flow never starts.

    Failing here means the operator sees the problem the moment they
    run `python app.py`, not after clicking "Sign in" and getting an
    opaque 500.
    """
    parsed = urlparse(ISSUER)
    if not parsed.scheme or not parsed.netloc:
        raise SystemExit(
            f"\nERROR: AKASHIC_ISSUER must be a full URL with scheme + host.\n"
            f"  got:      {ISSUER!r}\n"
            f"  expected: https://auth.akashic.<your-domain>\n"
        )
    # The demo's own bind. Compare host:port loosely against both
    # localhost and 127.0.0.1 since either could be configured.
    own_netlocs = {f"localhost:{PORT}", f"127.0.0.1:{PORT}"}
    if parsed.netloc in own_netlocs:
        raise SystemExit(
            f"\nERROR: AKASHIC_ISSUER points at this Flask app ({ISSUER}).\n"
            f"\n"
            f"  AKASHIC_ISSUER must be the AKASHIC AUTH SERVER's URL,\n"
            f"  NOT this demo's URL. For example:\n"
            f"    https://auth.akashic.example.com\n"
            f"    https://auth.akashic.yohan-yoon.com\n"
            f"\n"
            f"  This demo runs at {REDIRECT_URI.rsplit('/', 1)[0]} and\n"
            f"  REGISTERS as an OAuth client AGAINST that auth server.\n"
        )


_validate_issuer()


# ─── Pre-flight discovery fetch ──────────────────────────────────────


def _preflight_discovery() -> None:
    """Try OIDC discovery once at startup. Three outcomes:

      - succeeds, doc looks valid     → great, log and continue
      - succeeds, doc looks malformed → fail with sharp message (the
                                        most common cause is issuer
                                        pointing at the WRONG remote
                                        — e.g. the api server, the
                                        control plane, or some other
                                        web server entirely)
      - fails (network / TLS / 4xx)   → log warning, allow startup;
                                        operator might be running
                                        the demo before akashic is
                                        up, which is OK
    """
    discovery_url = f"{ISSUER}/.well-known/openid-configuration"
    try:
        r = requests.get(discovery_url, verify=TLS_VERIFY, timeout=5)
    except requests.exceptions.RequestException as e:
        logging.warning(
            "Could not pre-fetch OIDC discovery from %s: %s\n"
            "  Sign-in will retry. If Akashic isn't running yet this\n"
            "  is expected; otherwise check AKASHIC_ISSUER, network,\n"
            "  and TLS verify settings.",
            discovery_url,
            e,
        )
        return

    if not r.ok:
        raise SystemExit(
            f"\nERROR: OIDC discovery at {discovery_url}\n"
            f"  returned HTTP {r.status_code}.\n"
            f"\n"
            f"  Body (truncated): {r.text[:200]!r}\n"
            f"\n"
            f"  Likely causes:\n"
            f"    1. AKASHIC_ISSUER points at the wrong server\n"
            f"       (e.g. api server, control plane, or a non-Akashic URL).\n"
            f"       It should be the AUTH server, e.g.\n"
            f"       https://auth.akashic.<your-domain>\n"
            f"    2. Akashic auth server not yet started.\n"
            f"    3. A reverse proxy / firewall is intercepting the request.\n"
        )

    try:
        doc = r.json()
    except ValueError:
        raise SystemExit(
            f"\nERROR: {discovery_url} returned non-JSON.\n"
            f"  This usually means AKASHIC_ISSUER points at a server\n"
            f"  that ISN'T running OIDC discovery — e.g. a generic web\n"
            f"  app, a 404 page, or this demo itself.\n"
        )

    required = ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer")
    missing = [k for k in required if not doc.get(k)]
    if missing:
        raise SystemExit(
            f"\nERROR: OIDC discovery at {discovery_url}\n"
            f"  is missing required fields: {missing}\n"
            f"  Is AKASHIC_ISSUER pointing at the Akashic auth server?\n"
        )

    logging.info(
        "OIDC discovery OK · authorization_endpoint=%s",
        doc["authorization_endpoint"],
    )


def _check_port_available() -> None:
    """Probe-bind the demo's port BEFORE Flask's `app.run()` so we
    can emit a sharp error if it's already in use.

    The most common offender on macOS Monterey+: AirPlay Receiver,
    which silently squats on port 5000 by default. Flask's
    "Running on http://localhost:5000" log line appears anyway, but
    the OS routes incoming traffic to AirPlay's listener, the
    browser gets garbage, and Chrome lands on chrome-error.
    Detecting the conflict here turns a confusing browser symptom
    into an immediate "your port is taken" message.

    The probe binds-and-closes; tiny race window before app.run()
    grabs it again, but in practice this is dev-localhost and
    nothing else is racing for that port between the close and the
    next bind.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("localhost", PORT))
    except OSError as e:
        # macOS-specific hint when port == 5000: AirPlay Receiver is
        # the overwhelmingly most-likely cause. Other ports get a
        # generic "something else is on this port" message with a
        # different port suggestion.
        if PORT == 5000:
            extra = (
                "\n\n  Most likely cause on macOS: AirPlay Receiver squats\n"
                "  on port 5000 by default. The current demo default is\n"
                "  5050 to avoid this; if you've explicitly set\n"
                "  AKASHIC_TEST_PORT=5000, either disable AirPlay\n"
                "  (System Settings → General → AirDrop & Handoff →\n"
                "  AirPlay Receiver: OFF) or pick a different port.\n"
            )
        else:
            extra = (
                f"\n\n  Pick a different port and re-register the OAuth\n"
                f"  client to match. For example:\n"
                f"    AKASHIC_TEST_PORT={PORT + 1} python app.py\n"
                f"  Then re-register with:\n"
                f"    akashic-cli clients create --type WEB \\\n"
                f"        --name \"Login Test\" \\\n"
                f"        --redirect-uri http://localhost:{PORT + 1}/callback\n"
            )
        raise SystemExit(
            f"\nERROR: cannot bind localhost:{PORT} ({e}).\n"
            f"  Something else is already listening on this port.{extra}\n"
        )
    finally:
        s.close()
    logging.info("port %d available", PORT)


# ─── Flask app ───────────────────────────────────────────────────────

app = Flask(__name__)
# Per-process session secret. Fresh on every restart, so any in-flight
# session on a previous run is invalidated — fine for a dev demo.
app.secret_key = secrets.token_bytes(32)


# ─── OIDC discovery (cached on first call) ───────────────────────────


_DISCOVERY: dict | None = None


def discovery() -> dict:
    """Return the OIDC discovery document, fetched lazily on first
    use and cached for the lifetime of the process. Real apps add
    a TTL; here we just trust process restarts to refresh."""
    global _DISCOVERY
    if _DISCOVERY is None:
        url = f"{ISSUER}/.well-known/openid-configuration"
        app.logger.info("fetching OIDC discovery from %s", url)
        r = requests.get(url, verify=TLS_VERIFY, timeout=10)
        r.raise_for_status()
        _DISCOVERY = r.json()
    return _DISCOVERY


def get_signing_key(id_token: str):
    """Pull the JWKS, find the key matching the id_token's `kid`,
    return it as a usable PyJWK key.

    Implemented manually (not via pyjwt's PyJWKClient) so the JWKS
    fetch goes through `requests` and inherits REQUESTS_CA_BUNDLE +
    AKASHIC_TLS_VERIFY. PyJWKClient uses urllib internally, which
    doesn't honour either."""
    headers = jwt.get_unverified_header(id_token)
    kid = headers.get("kid")
    if not kid:
        raise ValueError("id_token header missing `kid`")

    jwks_url = discovery()["jwks_uri"]
    r = requests.get(jwks_url, verify=TLS_VERIFY, timeout=10)
    r.raise_for_status()
    for key in r.json().get("keys", []):
        if key.get("kid") == kid:
            return jwt.PyJWK(key).key
    raise ValueError(f"no signing key in JWKS for kid={kid}")


# ─── PKCE helpers ────────────────────────────────────────────────────


def _b64url(b: bytes) -> str:
    """Base64url WITHOUT padding (RFC 7636 §4.2)."""
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def make_pkce() -> tuple[str, str]:
    """Generate a PKCE code_verifier (high-entropy random) and the
    matching S256 challenge. Returns (verifier, challenge)."""
    verifier = _b64url(secrets.token_bytes(48))  # 64 chars
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


# ─── Routes ──────────────────────────────────────────────────────────


@app.route("/")
def home():
    user = session.get("user")
    return render_template(
        "home.html",
        user=user,
        issuer=ISSUER,
        client_id=CLIENT_ID,
        redirect_uri=REDIRECT_URI,
    )


@app.route("/login")
def login():
    """Step 1: build the /authorize URL with state, nonce, and a
    fresh PKCE pair. Stash the proofs in the Flask session so /callback
    can validate them."""
    state = _b64url(secrets.token_bytes(16))
    nonce = _b64url(secrets.token_bytes(16))
    verifier, challenge = make_pkce()

    session["oauth_state"] = state
    session["oauth_nonce"] = nonce
    session["oauth_verifier"] = verifier

    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": SCOPE,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return redirect(f"{discovery()['authorization_endpoint']}?{urlencode(params)}")


@app.route("/callback")
def callback():
    """Step 2: receive the authorization code, exchange for tokens,
    verify id_token. On success, populate the session."""
    # Surface OAuth-spec error redirects with a clear message.
    if err := request.args.get("error"):
        return render_template(
            "error.html",
            title="OAuth error",
            message=f"{err}: {request.args.get('error_description', '')}",
        ), 400

    code = request.args.get("code")
    state = request.args.get("state")
    if not code or not state:
        return render_template(
            "error.html",
            title="Missing parameters",
            message="The callback is missing `code` or `state` query parameters.",
        ), 400
    if state != session.pop("oauth_state", None):
        # Pop on read — defends against replay even if validation fails
        # (the original state is single-use either way).
        return render_template(
            "error.html",
            title="State mismatch",
            message="The state parameter doesn't match. Either the session "
            "expired or this is a CSRF attempt.",
        ), 400

    verifier = session.pop("oauth_verifier", None)
    nonce = session.pop("oauth_nonce", None)
    if not verifier or not nonce:
        return render_template(
            "error.html",
            title="Session lost",
            message="The PKCE verifier or nonce isn't in the session. "
            "Did you restart the dev server mid-flow?",
        ), 400

    # Step 3: exchange code for tokens (POST /token with client_secret
    # and code_verifier). client_secret_post auth — credentials in the
    # form body, not the Authorization header.
    r = requests.post(
        discovery()["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code_verifier": verifier,
        },
        headers={"Accept": "application/json"},
        verify=TLS_VERIFY,
        timeout=10,
    )
    if not r.ok:
        return render_template(
            "error.html",
            title=f"Token exchange failed (HTTP {r.status_code})",
            message=r.text,
        ), 502

    tokens = r.json()
    id_token = tokens.get("id_token")
    if not id_token:
        return render_template(
            "error.html",
            title="No id_token in response",
            message="Akashic returned a token response without an id_token. "
            "The client_service may not be registered with the `openid` scope.",
        ), 502

    # Step 4: verify id_token signature against JWKS + standard claims.
    try:
        signing_key = get_signing_key(id_token)
        claims = jwt.decode(
            id_token,
            signing_key,
            algorithms=["RS256", "ES256"],
            audience=CLIENT_ID,
            issuer=ISSUER,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.InvalidTokenError as e:
        return render_template(
            "error.html",
            title="id_token verification failed",
            message=str(e),
        ), 502

    # Nonce binding — pyjwt doesn't enforce this; we do.
    if claims.get("nonce") != nonce:
        return render_template(
            "error.html",
            title="Nonce mismatch",
            message="The id_token's `nonce` doesn't match the value sent on "
            "/authorize. This would let an attacker replay an id_token.",
        ), 502

    # Step 5: capture identity + the full token set in the session.
    # We store absolute epoch-ms timestamps for the access + refresh
    # token expiries so the home page's live countdown can render
    # without re-deriving from the original issuance time. The raw
    # access_token / refresh_token strings stay in the session so the
    # "Token liveness lab" UI can exercise /userinfo and /token from
    # button presses.
    now_ms = int(time.time() * 1000)
    access_expires_in = int(tokens.get("expires_in", 0))
    # Akashic adds `refresh_token_expires_in` alongside `refresh_token`
    # whenever the auth code carried `offline_access`; older OAuth
    # servers omit it. We default to 0 so missing-RT renders cleanly
    # in the UI.
    refresh_expires_in = int(tokens.get("refresh_token_expires_in", 0))

    session["user"] = {
        "sub": claims.get("sub"),
        "username": claims.get("preferred_username") or claims.get("sub"),
        "email": claims.get("email"),
        "name": claims.get("name"),
    }
    session["id_token"] = id_token
    session["access_token"] = tokens.get("access_token")
    session["access_token_expires_at_ms"] = (
        now_ms + access_expires_in * 1000 if access_expires_in else 0
    )
    session["refresh_token"] = tokens.get("refresh_token")
    session["refresh_token_expires_at_ms"] = (
        now_ms + refresh_expires_in * 1000 if refresh_expires_in else 0
    )
    # `previous_refresh_token` is set by the /api/refresh endpoint
    # when an RT is rotated — it lets the "Replay previous RT" button
    # demonstrate chain revocation. Initialised empty here.
    session["previous_refresh_token"] = ""
    # Append-only log of token-lifecycle events shown in the home
    # page's "Activity" pane. Bounded; oldest entries drop off.
    session["activity"] = []
    _log_activity(
        f"signed in · access_token TTL {access_expires_in}s"
        + (f" · refresh_token TTL {refresh_expires_in}s" if refresh_expires_in else " · no refresh_token (offline_access not granted)")
    )
    return redirect(url_for("home"))


@app.route("/logout")
def logout():
    """Step 6: RP-Initiated Logout. Clears our session AND redirects
    the browser to Akashic's /logout so the auth-server session
    cookie dies. Without the round-trip, the next /authorize would
    silently SSO-reauth without prompting for credentials."""
    id_token = session.get("id_token")
    session.clear()

    # Akashic's discovery doc may or may not advertise an
    # end_session_endpoint; we fall back to <issuer>/logout, which is
    # the path Akashic exposes per its README.
    end_session = discovery().get(
        "end_session_endpoint", f"{ISSUER}/logout"
    )
    params = {"post_logout_redirect_uri": url_for("home", _external=True)}
    if id_token:
        params["id_token_hint"] = id_token
    return redirect(f"{end_session}?{urlencode(params)}")


# ─── Token liveness lab (test endpoints) ─────────────────────────────
#
# Four endpoints power the "Token liveness lab" panel on the home
# page. They're deliberately small + JSON-shaped so a future curl-
# based test could call them too:
#
#   GET  /api/status          → current AT/RT state + expiry timestamps
#   POST /api/test-call       → call /userinfo with the current AT;
#                                shows whether AT is still valid
#   POST /api/refresh         → call /token with grant_type=refresh_token;
#                                rotates the chain (new AT + new RT)
#   POST /api/replay-last-rt  → submit the PREVIOUS (consumed) RT;
#                                triggers chain revocation per OAuth 2.1


_ACTIVITY_MAX = 30  # cap on activity log; older entries drop off.


def _log_activity(msg: str) -> None:
    """Append a timestamped entry to the session's activity log.
    Bounded so the session cookie doesn't grow without limit during
    long demo runs."""
    log = session.get("activity", [])
    log.append({"ts": int(time.time() * 1000), "msg": msg})
    if len(log) > _ACTIVITY_MAX:
        log = log[-_ACTIVITY_MAX:]
    session["activity"] = log
    session.modified = True


def _short(token: str | None) -> str:
    """Render the last 6 chars of a token as a visual identifier.
    Lets the UI show 'access_token …a8f3c2' so the user can SEE that
    the token actually changed after a refresh, without exposing the
    full secret."""
    if not token:
        return "—"
    return "…" + token[-6:]


@app.route("/api/status")
def api_status():
    """Snapshot of the current token state. Polled by the home page
    every ~500ms to keep countdowns live without page reloads."""
    if not session.get("user"):
        return jsonify({"signed_in": False}), 200
    return jsonify(
        {
            "signed_in": True,
            "now_ms": int(time.time() * 1000),
            "access_token": {
                "present": bool(session.get("access_token")),
                "marker": _short(session.get("access_token")),
                "expires_at_ms": session.get("access_token_expires_at_ms", 0),
            },
            "refresh_token": {
                "present": bool(session.get("refresh_token")),
                "marker": _short(session.get("refresh_token")),
                "expires_at_ms": session.get("refresh_token_expires_at_ms", 0),
            },
            "has_previous_rt": bool(session.get("previous_refresh_token")),
            "activity": session.get("activity", []),
        }
    )


@app.route("/api/test-call", methods=["POST"])
def api_test_call():
    """Call Akashic's /userinfo with the current access_token.
    Standard OIDC endpoint that requires a valid bearer — perfect
    "is my token still alive?" probe. 200 = AT good. 401 = AT
    expired or revoked; the user should hit Refresh."""
    if not session.get("user"):
        return jsonify({"ok": False, "message": "not signed in"}), 401
    at = session.get("access_token")
    if not at:
        _log_activity("test call: no access_token in session")
        return jsonify({"ok": False, "message": "no access_token"}), 400

    userinfo_url = discovery().get("userinfo_endpoint")
    if not userinfo_url:
        return (
            jsonify({"ok": False, "message": "discovery doc missing userinfo_endpoint"}),
            502,
        )
    r = requests.get(
        userinfo_url,
        headers={"Authorization": f"Bearer {at}"},
        verify=TLS_VERIFY,
        timeout=10,
    )
    if r.ok:
        _log_activity(f"test call → /userinfo · 200 OK · AT {_short(at)} valid")
        return jsonify({"ok": True, "status": r.status_code, "claims": r.json()}), 200

    # Akashic's /userinfo returns the RFC 6750 WWW-Authenticate header
    # on bearer failures; surface the error_description for clarity.
    auth_header = r.headers.get("WWW-Authenticate", "")
    body_msg = r.text[:200]
    _log_activity(
        f"test call → /userinfo · {r.status_code} · AT {_short(at)} rejected"
    )
    return (
        jsonify(
            {
                "ok": False,
                "status": r.status_code,
                "message": body_msg,
                "www_authenticate": auth_header,
            }
        ),
        200,  # 200 to the BROWSER even on AT failure — we want the
        # JSON to flow into the UI's result panel; the inner `ok`
        # field signals the actual outcome.
    )


@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    """Exchange the current refresh_token for a new (AT, RT) pair.
    On success: rotate the session — new AT + new RT take over,
    OLD RT moves to `previous_refresh_token` so the next button
    can demonstrate replay detection."""
    if not session.get("user"):
        return jsonify({"ok": False, "message": "not signed in"}), 401
    rt = session.get("refresh_token")
    if not rt:
        _log_activity("refresh: no refresh_token in session")
        return jsonify({"ok": False, "message": "no refresh_token"}), 400

    r = requests.post(
        discovery()["token_endpoint"],
        data={
            "grant_type": "refresh_token",
            "refresh_token": rt,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        headers={"Accept": "application/json"},
        verify=TLS_VERIFY,
        timeout=10,
    )
    if not r.ok:
        body = r.text[:300]
        _log_activity(
            f"refresh → /token · {r.status_code} · RT {_short(rt)} rejected"
        )
        return (
            jsonify({"ok": False, "status": r.status_code, "message": body}),
            200,
        )

    tokens = r.json()
    now_ms = int(time.time() * 1000)
    new_at = tokens.get("access_token")
    new_rt = tokens.get("refresh_token")
    access_expires_in = int(tokens.get("expires_in", 0))
    refresh_expires_in = int(tokens.get("refresh_token_expires_in", 0))

    # Stash the OLD RT for the replay-detection demo BEFORE we
    # overwrite. The replay button submits this exact value to
    # trigger chain revocation.
    session["previous_refresh_token"] = rt
    session["access_token"] = new_at
    session["access_token_expires_at_ms"] = (
        now_ms + access_expires_in * 1000 if access_expires_in else 0
    )
    session["refresh_token"] = new_rt
    session["refresh_token_expires_at_ms"] = (
        now_ms + refresh_expires_in * 1000 if refresh_expires_in else 0
    )
    _log_activity(
        f"refresh → /token · 200 OK · "
        f"AT {_short(new_at)} (TTL {access_expires_in}s) · "
        f"RT {_short(new_rt)} (TTL {refresh_expires_in}s)"
    )
    return jsonify({"ok": True, "status": r.status_code}), 200


@app.route("/api/replay-last-rt", methods=["POST"])
def api_replay_last_rt():
    """Submit the PREVIOUS (already-consumed) refresh_token to
    Akashic's /token. OAuth 2.1 §6.1 requires this to fail AND
    revoke the entire chain — meaning the CURRENT (still-valid)
    refresh_token also dies. Subsequent /api/refresh calls then
    fail too; the user must re-authenticate via /authorize.

    This is THE demonstrative test for refresh-token rotation
    safety: it shows that a stolen RT used by an attacker burns
    the legitimate client's session along with the attacker's."""
    if not session.get("user"):
        return jsonify({"ok": False, "message": "not signed in"}), 401
    prev_rt = session.get("previous_refresh_token")
    if not prev_rt:
        return (
            jsonify(
                {
                    "ok": False,
                    "message": (
                        "no previous refresh_token to replay. Click 'Refresh tokens' "
                        "first — that rotates the RT and stores the old one for replay."
                    ),
                }
            ),
            400,
        )

    r = requests.post(
        discovery()["token_endpoint"],
        data={
            "grant_type": "refresh_token",
            "refresh_token": prev_rt,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        headers={"Accept": "application/json"},
        verify=TLS_VERIFY,
        timeout=10,
    )
    body = r.text[:300]
    expected = "invalid_grant" in body.lower()
    if expected:
        _log_activity(
            f"replay → /token · {r.status_code} invalid_grant · chain revoked "
            f"(current RT {_short(session.get('refresh_token'))} now ALSO dead)"
        )
    else:
        _log_activity(
            f"replay → /token · {r.status_code} (UNEXPECTED — replay should fail)"
        )
    return (
        jsonify(
            {
                "ok": expected,
                "status": r.status_code,
                "message": body,
                "expected_failure": expected,
            }
        ),
        200,
    )


# ─── Entry point ─────────────────────────────────────────────────────


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.logger.info("login-with-akashic-py starting on http://localhost:%d", PORT)
    app.logger.info("issuer:       %s", ISSUER)
    app.logger.info("client_id:    %s", CLIENT_ID)
    app.logger.info("redirect_uri: %s", REDIRECT_URI)
    if not TLS_VERIFY:
        app.logger.warning(
            "TLS verification DISABLED — never run this configuration "
            "outside dev/testing"
        )

    # Pre-flight: validate that the OAuth chain CAN actually run
    # before we start serving. Catches misconfigured AKASHIC_ISSUER
    # at startup rather than when the user clicks Sign in. Skipped
    # under the Werkzeug reloader's child process (it fires an extra
    # check on every code change, which makes dev loops noisy).
    if os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        _preflight_discovery()
        _check_port_available()

    app.run(host="localhost", port=PORT, debug=True)
