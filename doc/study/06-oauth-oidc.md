# Chapter 06 — OAuth / OIDC

> **Goal**: by the end of this chapter, you should know the OAuth
> 2.1 + OIDC protocol shape well enough to read RFC 6749 and OIDC
> Core without getting lost, and you should be able to point at
> exactly which file in `pkg/oauth/` and `pkg/server/auth/`
> implements each part of it.

## The protocol, in one paragraph

OAuth 2.1 is a protocol where a **client** (a service that wants to
authenticate users) redirects the user's browser to an **authorization
server** (a.k.a. IdP — that's Akashic). The user logs in there, and
the auth server redirects the browser *back* to the client, with a
short-lived **authorization code** in the URL. The client then makes
a **server-to-server** call to the auth server's `/token` endpoint,
exchanges the code for tokens, and uses those tokens to identify the
user. **OIDC** sits on top of OAuth — it specifies a particular kind
of token (the **ID token**) that contains user identity claims
signed by the auth server, so the client can verify who logged in
without needing to trust the browser.

That's the whole shape. Everything else is details.

## The four parties

```
┌───────────┐    1. user clicks Login
│  browser  │ ─────────────────────────────────►
└───────────┘                                    ┌────────────┐
       ▲                                         │   client   │
       │                                         │  (akashic- │
       │ 2. redirect to IdP /authorize           │   admin    │
       │     ◄──────────────────────────────────│   = the    │
       │                                         │   admin-bff)│
       │                                         └────────────┘
       │                                                ▲
       ▼                                                │
┌──────────────┐                                        │
│ auth server  │ ─── 3. authorization code ────────────►│
│   (Akashic   │                                        │
│   IdP — the  │ ◄── 4. server-to-server: code+secret ──┤
│   akashic    │                                        │
│   server's   │ ─── 5. response: access + ID token ───►│
│   :8080)     │                                        │
└──────────────┘                                        │
       ▲                                                │
       │                                                │
       └─── 6. (optional) verify ID token signature ────┘
            against the IdP's published JWKS
```

The four parties:

1. **Resource Owner** — the user.
2. **Client** — the service that wants to authenticate the user.
   In Akashic's case (today) the only client is the admin-bff,
   registered as `akashic-admin` in `client_services`.
3. **Authorization Server** (a.k.a. IdP) — Akashic's auth-server
   (port 8080).
4. **Resource Server** — strictly, the API the client wants to access
   on behalf of the user. In our setup the client and resource server
   are the same component (the admin-bff has its own session-backed
   API), so this party is fused with the client.

## What each token is for

OAuth/OIDC has **three kinds of tokens** the client may receive:

| Token | Format | Audience | Purpose |
|---|---|---|---|
| **Access token** | JWT (RS256) | Resource server | "I have permission to call /userinfo" — bearer-presented to the resource server |
| **ID token** | JWT (RS256) | Client | "Here's who logged in" — proves the user's identity to the client |
| **Refresh token** | (not implemented yet) | Auth server | "Mint me a new access token" — long-lived |

Akashic mints the first two on `/token`. Refresh tokens are a Phase
8+ concern — for now, when the access token expires, the user has
to re-authenticate (typically silent, because the auth-server
session cookie is still valid for SSO).

**Why two tokens for one login?** The access token is a *bearer*
token — anyone holding it can use it. It's short-lived (15 min
default) and scope-limited. The ID token is signed and verifiable
*offline* — the client can verify the IdP's signature without ever
calling the IdP. They serve different purposes:

- Access token → the **passport** to the resource server.
- ID token → the **proof of identity** to the client.

In Akashic's admin-bff scenario, the client *is* the resource server
(the BFF), so technically you could elide the access token. We mint
both because the spec requires it and because it future-proofs for
other clients.

## The flow Akashic implements: Authorization Code with PKCE

There are several OAuth flows. Akashic implements **exactly one**:
**authorization_code with PKCE (RFC 7636)**.

### What's PKCE

PKCE = "Proof Key for Code Exchange" (pronounced "pixie"). It binds
the authorization code to the specific browser that requested it,
preventing **code interception attacks**.

The mechanic:

```
1. Client generates a random verifier (high-entropy string, 43-128
   chars)
2. Client computes challenge = SHA256(verifier), base64url-encoded
3. Client includes the CHALLENGE in the /authorize redirect
4. Auth server stores the challenge alongside the auth code
5. When the client calls /token, it includes the VERIFIER
6. Auth server checks: SHA256(verifier) == stored challenge
7. If yes, mint tokens; if no, reject
```

Even if an attacker intercepts the auth code (e.g., from a redirect
log, a malicious system extension, or a misconfigured redirect_uri),
they can't exchange it without the verifier — which the client
generated and never sent over the wire (only the hash was).

PKCE was originally designed for public clients (mobile apps) that
can't keep client secrets. OAuth 2.1 makes it **mandatory for all
flows**, public or confidential. Akashic enforces it accordingly:
`/authorize` rejects requests without `code_challenge`, and only
accepts `code_challenge_method=S256` (plain is forbidden).

## The endpoints

The auth-server's OAuth/OIDC endpoints, as registered in
`pkg/server/auth/routes.go`:

| Path | Method | Purpose |
|---|---|---|
| `/.well-known/openid-configuration` | GET | OIDC discovery doc |
| `/jwks.json` | GET | Published signing keys (JWK Set) |
| `/login` | GET | Render login form |
| `/login/submit` | POST | Process credentials, set session, redirect to return_to |
| `/logout` | GET | Clear auth-server session, optionally redirect back to client |
| `/authorize` | GET | Begin OAuth flow — validate request, set/check session, mint code, redirect |
| `/token` | POST | Exchange code for tokens (server-to-server) |
| `/userinfo` | GET | Bearer-token verify, return user claims |
| `/static/` | * | CSS for login form |
| `/health`, `/ready` | GET | Standard probes |

You'll meet each one again in chapter 07's walkthrough. For now just
internalize that **these endpoints together implement the full
OIDC core**.

## The discovery doc

`/.well-known/openid-configuration` returns JSON like:

```json
{
  "issuer": "https://auth.akashic.yohan-yoon.com",
  "authorization_endpoint": ".../authorize",
  "token_endpoint": ".../token",
  "userinfo_endpoint": ".../userinfo",
  "jwks_uri": ".../jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported":
    ["client_secret_basic", "client_secret_post"]
}
```

This is what the spec calls a **client-discovery mechanism**. A
sophisticated client doesn't hardcode endpoint URLs — it fetches the
discovery doc once, learns where everything lives, and uses that.
Akashic's own admin-bff is *not* sophisticated in this way (it
hardcodes the relevant URLs in config), but external OAuth clients
that integrate with Akashic in the future will use the discovery
doc.

## The keystore

`pkg/oauth/keystore.go` manages the **RSA signing keys** the
auth-server uses to sign access tokens and ID tokens. The store:

- Keeps keys on disk at `./keys/oauth/<kid>.json`
- Uses an `atomic.Pointer[keysMap]` so reads are lock-free
- Generates an initial key on first run (when the directory is empty)
- Supports holding multiple keys (active = signing, others =
  verify-only) for rotation overlap

A **kid** (key identifier) is the first 16 bytes of
`SHA256(MarshalPKIXPublicKey(pub))`, base64url-encoded — a 22-char
fingerprint. JWT verifiers read the `kid` field from the token's
header and look up the right key.

The on-disk format is JSON containing both the PEM-encoded private
key (for signing) and the public key (for JWKS publishing). File
mode is 0600.

### Filesystem instead of Vault KV — a deliberate tradeoff

The Phase 7 plan originally specified Vault KV at
`kv/akashic/oauth/signing-keys/<kid>`. Implementation uses
filesystem instead. Reason: the akashic-server doesn't have a Vault
HTTP client wired up (only Vault Agent renders to disk for it), and
adding one is its own architecture task. Filesystem storage gets us
the same *functional* properties (rotation, verify-only old keys,
JWKS publishing) at a fraction of the implementation cost. Migration
to Vault KV later is one substituted file (`keystore.go`) — the
interface is identical.

Tradeoff acknowledged: loses Vault's audit trail of key access.
For single-node dev deployments this is fine; multi-node setups
will want centralized key storage. Revisit when there's a multi-node
deployment to design for.

## The authorization code's payload

`pkg/oauth/codes.go` defines `AuthorizationCode` — what's stored in
Redis under each code. Fields include:

- **ClientID** — which OAuth client this code is for
- **UserID, LDAPDN** — the authenticated user
- **RedirectURI** — must match what the client passes to /token
- **Scope** — what the user consented to (or default if no consent
  step)
- **CodeChallenge, CodeChallengeMethod** — for PKCE verification
- **Nonce** — echoed into the ID token's nonce claim (OIDC anti-
  replay)
- **SessionID** — the auth-server session that issued this code
- **UserType, Username, Email** — captured-at-login snapshot for the
  ID token, so /token doesn't have to re-fetch from LDAP

That last bullet is interesting. The Phase 7 implementation
originally **didn't** carry Username/Email through — `/token` was
supposed to fetch them from LDAP at mint time ("Phase 8 deferred").
But that placed an LDAP round-trip on the token-mint hot path, and
the auth-server already had the values (from the login session). So
the snapshot fields were added later — `/authorize` writes them into
the code, `/token` reads them out. This is also the *correct* OIDC
behavior — the ID token represents identity-at-login-time, not
identity-at-token-mint-time.

## Sessions: two layers

### Auth-server session (`akashic_auth_session`)

Created when the user POSTs `/login/submit` successfully. Stored in
Redis at `akashic:auth:session:<sid>`. Its purpose: remember
"this user is logged in at the IdP" so subsequent `/authorize`
visits skip the login form. This is what makes **single sign-on**
work — log in once, authenticate to many clients.

TTLs: 8h absolute, 30m idle. Cookie is `HttpOnly; Secure;
SameSite=Lax` on the auth-server origin.

### BFF session (`akashic_admin_session`)

Created when the BFF's `/oauth/callback` succeeds. Stored at
`akashic:bff:admin:session:<sid>`. Its purpose: maintain the
browser↔BFF binding for the admin SPA. Holds the access token, ID
token, and user info.

Same TTL pattern as the auth-server session, but on a different
origin (`admin.<domain>`) and a different cookie.

### Why two layers?

Because they're for different parties. The auth-server session is
about "is the user logged in at the IdP?" — answers `/authorize`'s
"can I issue a code without prompting?" question. The BFF session is
about "is the browser tied to a logged-in identity at the BFF?" —
answers `/api/session`'s "who is this user?" question. They can have
different TTLs, different invalidation rules, different storage. The
two-layer model is what makes RP-Initiated Logout meaningful — see
chapter 07.

## Built-in vs tenant-registered clients

The `client_services` table has a `built_in` boolean. Phase 7's only
built-in client is `akashic-admin` (the admin-bff). The
`EnsureBuiltInClients` function in `pkg/oauth/builtin.go` upserts
this row on every server startup, so:

- Configuration changes (new redirect URI, etc.) take effect on
  restart
- Operators don't have to register the admin client by hand
- The client secret is generated on first run, persisted at
  `./keys/oauth/client-secrets/akashic-admin.txt`, and **read by the
  admin-bff** at startup

Phase 8+ will add tenant-registered clients — operators will register
their services via the admin UI, and rows will be inserted with
`built_in=false`. The current schema is ready for it; the UI isn't
yet.

## Token verification

The admin-bff's `pkg/admin_bff/oauth.go` does ID-token verification
using `golang-jwt/v5`. The crypto is well-vetted; the verification
checks are:

1. **Signature** — RS256 signature against a public key from the JWKS.
   The `kid` header tells us which key.
2. **iss** — must match the configured public issuer
3. **aud** — must match the BFF's client_id (`akashic-admin`)
4. **exp** — must be in the future
5. **nonce** (when present) — must match what the BFF sent in
   `/authorize`

Item 1 has a subtle correctness pitfall: the `aud` claim can be
either a string or a string array per RFC 7519 §4.1.3. Akashic's
auth-server (using `golang-jwt/v5`'s `RegisteredClaims`) marshals it
as an array. The BFF's `IDClaims` uses `jwt.ClaimStrings` (which
unmarshals both forms) for cross-version compatibility. Failing to
do this would cause `cannot unmarshal array into Go struct field
Audience of type string`.

## What you should walk away with

After this chapter:

1. You can name the four parties in OAuth and explain what each
   one does.
2. You understand PKCE — what it is, why it's needed, and the exact
   mechanic.
3. You know that Akashic implements *one* flow (authorization code
   with PKCE) and which endpoints support it.
4. You can explain the difference between the access token and the
   ID token and what each is for.
5. You know what's in an `AuthorizationCode` and why the username/
   email snapshot was added.
6. You understand the two-layer session model and why both exist.

## Continue to → [Chapter 07 — Login Flow Walkthrough](./07-login-flow-walkthrough.md)
