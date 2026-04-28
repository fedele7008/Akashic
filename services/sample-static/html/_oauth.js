/**
 * Tiny SPA-OAuth helper for the static sample.
 *
 * Implements RFC 6749 Authorization Code Flow + RFC 7636 PKCE (S256)
 * for browsers, against the akashic-sample-static public client
 * registered server-side. Tenants writing their own static-HTML
 * integrations can copy this file as-is or substitute any standard
 * SPA OAuth library (e.g., oauth4webapi).
 *
 * Token storage: sessionStorage. Lives until tab close. Simpler than
 * IndexedDB, more bounded than localStorage's "forever". Standard
 * SPA-OAuth practice.
 *
 * Public API:
 *   AkashicOAuth.signin()                — start PKCE flow
 *   AkashicOAuth.handleCallback()        — finish PKCE flow on /callback
 *   AkashicOAuth.signout()               — clear local tokens AND
 *                                          terminate the IdP session via
 *                                          OIDC RP-Initiated Logout
 *                                          (§6.4.4); navigates the browser
 *   AkashicOAuth.getAccessToken()        — { token, expiresAt } | null
 *   AkashicOAuth.applyToWidgets()        — pass token into Akashic.configure
 */
(function () {
  // ---- config ---------------------------------------------------------

  // Baked in by docker-entrypoint.d/30-envsubst-html.sh at container
  // start (same envsubst pass that templates the .html files). We
  // can't infer this from a <script> tag at runtime: the callback
  // page is deliberately minimal and doesn't load the widget bundle,
  // so any querySelector('script[src*="akashic.js"]') would be null.
  // Window-global override stays available for tenants forking this
  // file into their own integration.
  const apiBase = window.AKASHIC_API_BASE_URL || "${AKASHIC_PORTAL_API_BASE_URL}";
  // Convention: api.<tenant> → auth.<tenant>. Tenants who need a
  // different topology can edit this file.
  const authBase = apiBase.replace(/\/\/api\./, "//auth.");

  const CLIENT_ID = "akashic-sample-static";
  const SCOPE = "openid profile email";
  const STORAGE_TOKEN = "akashic.access_token";
  const STORAGE_EXPIRES_AT = "akashic.access_expires_at";
  // Stored only to use as `id_token_hint` on RP-initiated logout —
  // helps the IdP correlate the right session in multi-session
  // scenarios. Required scope is `openid` (which we already request).
  const STORAGE_ID_TOKEN = "akashic.id_token";
  const STORAGE_PKCE_VERIFIER = "akashic.pkce.verifier";
  const STORAGE_PKCE_STATE = "akashic.pkce.state";

  // ---- crypto helpers -------------------------------------------------

  function base64url(bytes) {
    let s = btoa(String.fromCharCode.apply(null, bytes));
    return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function sha256(input) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
    return new Uint8Array(buf);
  }

  function randomBase64(byteLength) {
    const bytes = new Uint8Array(byteLength);
    crypto.getRandomValues(bytes);
    return base64url(bytes);
  }

  // ---- callback URL ---------------------------------------------------

  function callbackUrl() {
    return location.origin + "/callback";
  }

  // ---- public API -----------------------------------------------------

  async function signin() {
    const verifier = randomBase64(32);   // 256 bits of entropy
    const state = randomBase64(16);
    const challenge = base64url(await sha256(verifier));

    sessionStorage.setItem(STORAGE_PKCE_VERIFIER, verifier);
    sessionStorage.setItem(STORAGE_PKCE_STATE, state);

    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: callbackUrl(),
      response_type: "code",
      scope: SCOPE,
      state: state,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    location.href = authBase + "/authorize?" + params;
  }

  async function handleCallback() {
    const params = new URLSearchParams(location.search);
    const code = params.get("code");
    const state = params.get("state");
    if (!code || !state) throw new Error("missing code or state on callback");

    const expectedState = sessionStorage.getItem(STORAGE_PKCE_STATE);
    if (state !== expectedState) throw new Error("OAuth state mismatch");

    const verifier = sessionStorage.getItem(STORAGE_PKCE_VERIFIER);
    if (!verifier) throw new Error("missing PKCE verifier (session lost?)");

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: code,
      redirect_uri: callbackUrl(),
      client_id: CLIENT_ID,
      code_verifier: verifier,
    });

    const res = await fetch(authBase + "/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body,
    });
    if (!res.ok) {
      const errBody = await res.text();
      throw new Error("token exchange failed: " + res.status + " " + errBody);
    }
    const tokens = await res.json();

    sessionStorage.setItem(STORAGE_TOKEN, tokens.access_token);
    sessionStorage.setItem(
      STORAGE_EXPIRES_AT,
      String(Date.now() + tokens.expires_in * 1000),
    );
    if (tokens.id_token) sessionStorage.setItem(STORAGE_ID_TOKEN, tokens.id_token);
    sessionStorage.removeItem(STORAGE_PKCE_VERIFIER);
    sessionStorage.removeItem(STORAGE_PKCE_STATE);
  }

  // Two-stage cleanup, mirroring the Next.js sample's
  // /api/auth/logout flow:
  //   1. Drop local tokens from sessionStorage so this tab is
  //      immediately signed-out from the SPA's perspective.
  //   2. Navigate the browser to the IdP's /logout (OIDC RP-Initiated
  //      Logout, §6.4.4). The IdP clears its own auth_session cookie
  //      + Redis row, then 303-redirects back to
  //      `post_logout_redirect_uri` (origin must match a registered
  //      client's redirect_uri origin — see the auth server's
  //      postLogoutOriginAllowed allowlist check).
  //
  // Without step 2, the IdP cookie survives and clicking "Sign in"
  // again silently re-authenticates without prompting for a password
  // — protocol-correct SSO behaviour, but rarely what users expect
  // when they just clicked "Sign out."
  function signout() {
    const idToken = sessionStorage.getItem(STORAGE_ID_TOKEN);
    sessionStorage.removeItem(STORAGE_TOKEN);
    sessionStorage.removeItem(STORAGE_EXPIRES_AT);
    sessionStorage.removeItem(STORAGE_ID_TOKEN);

    const params = new URLSearchParams({
      post_logout_redirect_uri: location.origin + "/",
    });
    if (idToken) params.set("id_token_hint", idToken);
    location.href = authBase + "/logout?" + params;
  }

  function getAccessToken() {
    const token = sessionStorage.getItem(STORAGE_TOKEN);
    const expiresAt = parseInt(sessionStorage.getItem(STORAGE_EXPIRES_AT) || "0", 10);
    if (!token || !expiresAt || expiresAt <= Date.now()) return null;
    return { token: token, expiresAt: expiresAt };
  }

  // Hand the stored token to the widget bundle so authenticated
  // widgets can fetch their data. Idempotent — call on every page
  // that mounts auth-required widgets, before the bundle's
  // scheduling kicks in. Safe even before the bundle has loaded
  // (we attach a load handler).
  function applyToWidgets() {
    const t = getAccessToken();
    if (!t) return;
    function apply() {
      if (window.Akashic && window.Akashic.configure) {
        window.Akashic.configure({
          accessToken: t.token,
          accessTokenExpiresAt: t.expiresAt,
        });
      }
    }
    if (window.Akashic) {
      apply();
    } else {
      // The widget bundle script attaches `window.Akashic` synchronously
      // when it executes. Module scripts are deferred, so on early
      // page render the global may not exist yet; poll briefly.
      let tries = 0;
      const iv = setInterval(function () {
        if (window.Akashic) {
          clearInterval(iv);
          apply();
        } else if (++tries > 50) {
          clearInterval(iv);
        }
      }, 50);
    }
  }

  window.AkashicOAuth = {
    signin: signin,
    handleCallback: handleCallback,
    signout: signout,
    getAccessToken: getAccessToken,
    applyToWidgets: applyToWidgets,
  };

  // Auto-apply on DOM ready so authenticated pages don't have to
  // remember to call applyToWidgets() themselves.
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", applyToWidgets);
  } else {
    applyToWidgets();
  }
})();
