# Chapter 07 — Login Flow Walkthrough

> **Goal**: this is the chapter you'll come back to when something
> breaks. It traces every single hop a browser makes during a login,
> showing what state changes at each step, what cookies get set, and
> what file in the codebase handles each event. Read with chapters
> 05 and 06 fresh in your mind.

## The scenario

You open a fresh incognito window. Bootstrap is complete. You navigate
to `https://admin.akashic.<domain>/`. You click "Sign in". You enter
credentials. You land on the dashboard. We're going to trace **every
HTTP request** that takes place between those events.

## Stage 0 — Loading the admin SPA

```
Browser → https://admin.akashic.<domain>/
  ↓
[host TLS terminator] → docker proxy:8280 → admin-bff:8082
  ↓
admin-bff serves embedded index.html + /assets/*
```

The browser executes the React FE. `App.tsx` runs `useEffect` →
calls two API endpoints in parallel:

```javascript
Promise.all([BootstrapApi.status(), SessionApi.info()])
```

- `GET /api/bootstrap/status` → bff forwards over mTLS to akashic
  control plane → returns `is_complete: true`
- `GET /api/session` → bff checks cookie `akashic_admin_session`
  → no cookie → 401

Result: bootstrap done + not logged in. The FE renders the **"Sign
in to Akashic"** landing card.

State at this point:
- Cookie: `akashic_csrf=<random>` (set by BFF on first response)
- Nothing else.

## Stage 1 — Click "Sign in"

The FE's "Sign in" button is just an `<a href="/login">`. The
browser navigates to `https://admin.akashic.<domain>/login`. That's
a top-level navigation hitting the BFF's `handleLogin`.

```
Browser → GET https://admin.akashic.<domain>/login
  ↓
[proxy] → admin-bff:8082
  ↓
pkg/admin_bff/oauth_handlers.go → handleLogin
```

### What handleLogin does

1. Calls `s.ensureOAuth()` — returns the (lazily-initialized) OAuth
   client. If init fails (akashic isn't up yet), returns
   `AUTH_SERVER_UNREACHABLE` 503; otherwise proceeds.
2. Checks if there's already a valid `akashic_admin_session` cookie.
   If yes → 302 to `/` (we're already logged in). For our scenario
   there isn't, so we keep going.
3. Generates `state` (32 random bytes, base64url) for CSRF protection
   on the OAuth flow.
4. Generates a PKCE pair: `verifier` (64 random bytes) and
   `challenge = SHA256(verifier)` base64url-encoded.
5. Stores `{state, verifier, iat}` in a short-lived cookie:

   ```
   Set-Cookie: akashic_admin_oauth_pre=<base64url(json)>;
       Path=/; Max-Age=300; HttpOnly; Secure; SameSite=Lax
   ```
6. Builds the `/authorize` URL:

   ```
   https://auth.akashic.<domain>/authorize?
     response_type=code&
     client_id=akashic-admin&
     redirect_uri=https://admin.akashic.<domain>/oauth/callback&
     scope=openid+profile+email&
     state=<random>&
     code_challenge=<sha256-hash>&
     code_challenge_method=S256
   ```
7. Returns 302 with `Location:` pointing at that URL.

State change:
- Set-Cookie: `akashic_admin_oauth_pre` (HttpOnly, 5 min lifetime)
- Browser instructed to navigate to auth.* /authorize

## Stage 2 — Hit the auth server's /authorize

The browser follows the 302 to `https://auth.akashic.<domain>/authorize?…`.
It carries no cookies on the auth.* origin yet (different subdomain).

```
Browser → GET https://auth.akashic.<domain>/authorize?...
  ↓
[host TLS terminator] → docker proxy:8280
  ↓
[nginx auth.* server block] → akashic:8080 (TLS-to-TLS)
  ↓
pkg/server/auth/oauth_flow_handlers.go → handleAuthorize
```

### What handleAuthorize does

```
1. Parse query params: client_id, redirect_uri, response_type, scope,
   state, code_challenge, code_challenge_method, nonce
2. Look up the client in postgres `client_services` table
3. Validate redirect_uri — exact-string match against the registered
   redirect_uris CSV (RFC 6749 §3.1.2.4)
4. Validate response_type=code (only code supported)
5. Validate scope — every requested scope must be in the client's
   allowed_scopes
6. Validate that the client is authorized for grant_type=
   authorization_code (auth_types column)
7. Validate PKCE:
   - code_challenge MUST be present
   - code_challenge_method MUST be "S256" (plain forbidden)
   - code_challenge MUST be base64url-encoded SHA256 (43 chars)
8. Check the auth-server session cookie (akashic_auth_session)
   - For our scenario: NO cookie yet → 302 to /login?return_to=<URI-encoded /authorize?...>
```

Result: 302 redirect to the auth server's *own* /login page. State
unchanged (no auth-server cookies yet).

## Stage 3 — Render the login form

```
Browser → GET https://auth.akashic.<domain>/login?return_to=...
  ↓
pkg/server/auth/login_handlers.go → handleLoginPage
```

### What handleLoginPage does

1. `ensureLoginCSRF(w, r)` — issues a fresh `akashic_login_csrf`
   cookie if none exists. The token is also injected into the form
   as a hidden field (double-submit cookie pattern).
2. Validates `return_to` is same-origin (relative path only).
   External redirects are rejected — open-redirect prevention.
3. Renders `login.html.tmpl` with the CSRF token and return_to in
   hidden inputs.

Result: 200 with the login HTML.

State change:
- Set-Cookie: `akashic_login_csrf=<random>` (NOT HttpOnly — the
  form's JS-less render means the cookie is purely cosmetic for
  the form itself, but if the page had any JS it could read it.
  HttpOnly=false aligns with the BFF's CSRF cookie pattern)
- SameSite=Strict (cross-site requests would never send it)

The login form's HTML includes:
- A hidden `csrf_token` input (matches the cookie)
- A hidden `return_to` input (the original /authorize URL)
- Visible username + password inputs
- The form's `action="/login/submit"` and `method="POST"`

## Stage 4 — Submit credentials

User types `admin` / `mypassword`, clicks "Sign in".

```
Browser → POST https://auth.akashic.<domain>/login/submit
   Cookies: akashic_login_csrf=<X>
   Body:   csrf_token=<X>&return_to=/authorize?...&
           username=admin&password=mypassword
  ↓
pkg/server/auth/login_handlers.go → handleLoginSubmit
```

### What handleLoginSubmit does (success path)

```
1. ParseForm — parse the form body
2. CSRF check — cookie value MUST equal form's csrf_token field
   (constant-time compare)
3. Rate limit — per-IP, 5/min on /login/submit
4. Authenticate via LDAP:
   pkg/ldap/client.go → Authenticate(username, password)
     a. searchLoginDN — search by uid OR mail
        (filter: (|(uid={login})(mail={login})))
     b. Bind to LDAP as the user's DN with the password
        (success = correct password)
     c. defer rebindAsAdmin (so the connection stays
        admin-bound for next caller, even on bind failure)
5. Look up the user in postgres by ldap_dn
   - Found: use existing user record
   - Not found: JIT-provision (create postgres row)
6. Build AuthSession:
   {UserID, LDAPDN, Username, Email, UserType, IP, ...}
7. Create session in Redis (akashic:auth:session:<sid>)
8. Clear the login CSRF cookie (won't be needed again)
9. Set the auth-server session cookie:
     Set-Cookie: akashic_auth_session=<sid>;
         Path=/; HttpOnly; Secure; SameSite=Lax
10. 303 redirect to return_to (which is /authorize?...)
```

Note: SameSite=**Lax** on the session cookie (not Strict) — this
matters for the cross-subdomain redirects that follow.

State change:
- New Redis key: `akashic:auth:session:<sid>` with the auth session
- Set-Cookie: `akashic_auth_session=<sid>`
- Set-Cookie: `akashic_login_csrf=` Max-Age=0 (cleared)
- Browser instructed to GET /authorize?...

## Stage 5 — /authorize, take 2 (with session)

```
Browser → GET https://auth.akashic.<domain>/authorize?...
   Cookies: akashic_auth_session=<sid>
  ↓
pkg/server/auth/oauth_flow_handlers.go → handleAuthorize (again)
```

### What handleAuthorize does this time

Steps 1–7 same as before — re-validates client, redirect_uri, PKCE.

Step 8 now finds the session cookie. It calls
`sessionStore.Touch(ctx, sid)` which:

- Reads the AuthSession from Redis
- Checks idle timeout (last activity < 30m ago) — passes
- Updates `LastActivityAt = now`
- Re-saves with the remaining absolute TTL

The session is valid → no /login redirect needed. Continue:

9. Generate the authorization code:
   - 32 random bytes, base64url-encoded
   - Store an `AuthorizationCode` struct in Redis at
     `akashic:oauth:code:<code>` with TTL = 60 seconds
   - The struct includes: client_id, user_id, ldap_dn,
     redirect_uri, scope, code_challenge, code_challenge_method,
     nonce, session_id, user_type, username, email, issued
10. Build the redirect URL:
    `<redirect_uri>?code=<code>&state=<state>`
11. 302 redirect

State change:
- New Redis key: `akashic:oauth:code:<code>` with the AuthorizationCode
- Browser instructed to GET admin.* /oauth/callback?code=...&state=...

## Stage 6 — The callback hits the BFF

```
Browser → GET https://admin.akashic.<domain>/oauth/callback?code=...&state=...
   Cookies: akashic_admin_oauth_pre=<base64(state+verifier)>,
            akashic_csrf=<X>
  ↓
[proxy] → admin-bff:8082
  ↓
pkg/admin_bff/oauth_handlers.go → handleOAuthCallback
```

### What handleOAuthCallback does

```
1. ensureOAuth() — get the OAuth client (lazy-init may run here)
2. Check the query for ?error= (auth-server-side OAuth errors).
   None in our happy path.
3. Read the akashic_admin_oauth_pre cookie. Decode base64url, parse
   JSON. Get back {state, verifier, iat}.
4. Constant-time compare: query state == cookie state. Match → OK,
   continue. Mismatch → 400 INVALID_REQUEST.
5. Clear the pre-session cookie (no longer needed; replay protection)
6. Code exchange: HTTP POST to
     <internal-url>/token   (back-channel; uses docker network)
   Body:
     grant_type=authorization_code
     code=<code>
     redirect_uri=<our redirect_uri>
     code_verifier=<the verifier from cookie>
   Authorization: Basic <base64(client_id:client_secret)>
```

The /token call goes from admin-bff (in docker) to the akashic
auth-server. In container mode, that's container→container; in
host-akashic mode, the BFF dials `auth.akashic.local:8080` which
resolves via /etc/hosts to host-gateway → host akashic process.
Either way, TLS-verified against the cert SAN.

## Stage 7 — Server-to-server: the /token exchange

```
admin-bff → POST https://auth.akashic.local:8080/token
  ↓
pkg/server/auth/oauth_flow_handlers.go → handleToken
```

### What handleToken does

```
1. Parse form body
2. Authenticate the client:
   - Try HTTP Basic header first
   - Fall back to client_id/client_secret form params
3. Look up the client in postgres
4. bcrypt.CompareHashAndPassword(client.ClientSecretHash, secret)
5. Validate grant_type=authorization_code
6. Atomically consume the auth code from Redis (Lua GET+DEL)
7. Check: authCode.ClientID == authenticated client_id
   (in constant time — defense against client confusion)
8. Check: requested redirect_uri == authCode.RedirectURI
9. PKCE: SHA256(verifier) == authCode.CodeChallenge
   (constant-time compare)
10. Look up the user in postgres; check IsDisabled
11. Mint access token (RS256, claims: iss, sub, aud, exp, iat, scope, user_type)
12. If openid scope: mint ID token (claims: iss, sub, aud, exp, iat,
    user_type, preferred_username, email, nonce)
13. Return JSON:
    {
      "access_token": "<jwt>",
      "token_type": "Bearer",
      "expires_in": 900,
      "scope": "openid profile email",
      "id_token": "<jwt>"
    }
```

Things validated, in order: client identity → grant type → code
validity → client/code binding → redirect binding → PKCE → user
status. **Each one of these is a security requirement**; skipping
any opens a real attack.

State change:
- Redis: code key deleted (single-use)
- Akashic logs: "token issued" security audit line

## Stage 8 — BFF verifies the ID token

Back in `handleOAuthCallback`:

```
7. Verify the ID token:
   - Parse JWT (golang-jwt/v5)
   - Read the kid from the header
   - Look up the public key from the JWKS cache (fetches if stale)
   - Verify RS256 signature
   - Verify iss == configured issuer
   - Verify aud == "akashic-admin"
   - Verify exp > now
   - Verify nonce (if expected)
8. Role check:
   - claims.UserType must be in OAuthAllowedRoles ("root,admin")
   - If not: audit log "admin_login_denied_role", return 403
   - If yes: continue
9. Create the BFF session:
   sess := &Session{
     UserID, UserType, Username, Email,
     AccessToken, IDToken,
     AccessExpires, IssuedAt, LastActivityAt, IP,
   }
   sid := sessionStore.Create(ctx, sess)
   // Stored at akashic:bff:admin:session:<sid>
10. Set cookie:
    Set-Cookie: akashic_admin_session=<sid>;
        Path=/; HttpOnly; Secure; SameSite=Lax;
        Max-Age=<absolute TTL seconds>
11. 302 redirect to /
```

State change:
- New Redis key: `akashic:bff:admin:session:<sid>`
- Set-Cookie: `akashic_admin_session=<sid>`
- Browser instructed to GET /

## Stage 9 — Land on the dashboard

```
Browser → GET https://admin.akashic.<domain>/
   Cookies: akashic_admin_session=<sid>, akashic_csrf=<X>
  ↓
admin-bff serves index.html
  ↓
React FE re-runs:
  → GET /api/bootstrap/status (cached, but FE doesn't know)
  → GET /api/session
```

This time, `/api/session`:

```
pkg/admin_bff/oauth_handlers.go → handleSessionInfo
  ↓
Read cookie akashic_admin_session
sessionStore.Touch(sid) — updates LastActivityAt
Return JSON {user_id, user_type, username, email, issued_at, expires_at}
```

The FE renders `<Dashboard session={...} />`. Done. Login complete.

## Logging out: RP-Initiated Logout

You click "Log out". The Dashboard component calls
`SessionApi.logout()`:

```
1. POST /logout (BFF) with X-Akashic-CSRF header
   ↓
   pkg/admin_bff/oauth_handlers.go → handleLogout
   ↓
   - Delete the BFF session from Redis
   - Clear the akashic_admin_session cookie
   - Build the auth-server logout URL:
     https://auth.akashic.<domain>/logout?
       post_logout_redirect_uri=https://admin.akashic.<domain>/
   - Return JSON {logged_out: true, auth_logout_url: "..."}
2. The FE navigates window.location.href to the auth_logout_url
   ↓
   GET auth.* /logout?post_logout_redirect_uri=admin.* /
   ↓
   pkg/server/auth/login_handlers.go → handleLogout
   ↓
   - Delete the auth-server session from Redis
   - Clear akashic_auth_session cookie
   - Validate post_logout_redirect_uri origin against registered clients
   - 303 redirect to it
3. Browser lands on admin.* / again
   ↓
   FE → GET /api/session → 401 (cookie cleared)
   ↓
   FE renders the "Sign in to Akashic" landing
```

**Why both hops are necessary**: without step 2, the auth-server
session cookie survives. Next time the user clicks "Sign in", the
chain at /authorize finds a valid auth-server session and **silently
re-authenticates** without a credential prompt. The user expects
"log out" to mean "log out everywhere", so the BFF orchestrates
both layers.

This is the **OIDC RP-Initiated Logout** flow (RFC: OpenID Connect
RP-Initiated Logout 1.0).

## Common failure modes & where they surface

| Symptom | Likely stage | Where to look |
|---|---|---|
| 502 Bad Gateway on auth.* | Stage 2 (proxy → akashic) | proxy logs; is akashic running? |
| Browser stuck on login form after submit | Stage 4 → CSP form-action | auth-server CSP header (`form-action 'self' https:`) |
| TOKEN_EXCHANGE_FAILED in BFF | Stage 7 (network or cred) | admin-bff logs for connection error vs 401 |
| ID_TOKEN_INVALID | Stage 8 (verification) | admin-bff stderr — usually iss or aud mismatch |
| ACCESS_DENIED in BFF | Stage 8 step 8 (role check) | the user_type isn't in OAuthAllowedRoles |
| Login form rejected even with correct password | Stage 4 step 4 (LDAP) | ldap connection state — has rebind-on-failure run? |
| OAUTH_NOT_CONFIGURED 503 | Stage 1 (BFF init) | did akashic write `keys/oauth/client-secrets/`? |

## What you should walk away with

After this chapter:

1. You can trace a successful login from the first request to the
   dashboard render, naming each handler involved.
2. You understand why there are *two* /authorize hits in the chain
   (once before login, once after).
3. You can name the three cookies in play (`akashic_admin_oauth_pre`,
   `akashic_login_csrf`, `akashic_auth_session`) and their roles.
4. You understand RP-Initiated Logout and why both sessions need to
   be killed.
5. You know which stage to investigate when a particular failure
   message shows up.

## Continue to → [Chapter 08 — Deployment & Runtime](./08-deployment-and-runtime.md)
