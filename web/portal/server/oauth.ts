/**
 * Portal OAuth 2.1 / OIDC client.
 *
 * Wraps `oauth4webapi` (the IETF-spec-aligned, Web-platform-native
 * OAuth library) so that handler code can call simple primitives:
 *   buildAuthorizeUrl(state, codeVerifier)
 *   exchangeCode(code, codeVerifier)
 *   verifyIdToken(idToken, nonce)
 *
 * Lazy initialization (Step 3.5):
 *   The OIDC discovery document is fetched on first need, NOT at
 *   module import. This is critical because:
 *     - The portal container can boot before akashic-server finishes
 *       its own startup (LDAP wait, migrations, etc.)
 *     - We don't want "/sign-in is broken until you restart the
 *       portal" if the auth server briefly hiccups
 *   The cached client is held until either invalidated by an explicit
 *   reset call or by a stale-discovery 401 on token exchange.
 */

import * as oauth from "oauth4webapi";

import { env } from "../lib/env";

interface OAuthClientCache {
  issuer: oauth.AuthorizationServer;
  client: oauth.Client;
  clientAuth: oauth.ClientAuth;
  redirectUri: string;
  scopes: string;
}

let cache: OAuthClientCache | undefined;

/**
 * Resolve (and memoise) the OAuth client. Throws on discovery failure
 * — the caller should map that to a 503 "Sign-in temporarily
 * unavailable" page rather than a 500.
 */
export async function getOAuth(): Promise<OAuthClientCache> {
  if (cache) return cache;

  const issuerUrl = new URL(env.oauth.issuer);
  const discoveryRes = await oauth.discoveryRequest(issuerUrl, {
    algorithm: "oidc",
  });
  const issuer = await oauth.processDiscoveryResponse(issuerUrl, discoveryRes);

  const client: oauth.Client = {
    client_id: env.oauth.clientId,
    token_endpoint_auth_method: "client_secret_basic",
  };

  const clientAuth = oauth.ClientSecretBasic(env.oauth.clientSecret);

  cache = {
    issuer,
    client,
    clientAuth,
    redirectUri: env.oauth.redirectUri,
    scopes: env.oauth.scopes,
  };
  return cache;
}

/**
 * Force a re-fetch of discovery on next access. Used by the callback
 * handler when a 401 from the token endpoint suggests our cached
 * client config is stale (e.g. the auth server's signing key rotated
 * after we cached the JWKS endpoint URL).
 */
export function resetOAuthCache(): void {
  cache = undefined;
}

/** Generate a cryptographically random `state` parameter. */
export function generateState(): string {
  return oauth.generateRandomState();
}

/** Generate a cryptographically random `nonce` parameter. */
export function generateNonce(): string {
  return oauth.generateRandomNonce();
}

/** Generate a PKCE code verifier (the secret), to be paired with a challenge. */
export function generateCodeVerifier(): string {
  return oauth.generateRandomCodeVerifier();
}

/** Compute the S256 challenge corresponding to a verifier. */
export async function computeCodeChallenge(verifier: string): Promise<string> {
  return oauth.calculatePKCECodeChallenge(verifier);
}

/**
 * Build the URL we redirect the browser to in order to start an
 * authorization-code flow.
 */
export async function buildAuthorizeUrl(opts: {
  state: string;
  nonce: string;
  codeChallenge: string;
}): Promise<string> {
  const c = await getOAuth();
  const u = new URL(c.issuer.authorization_endpoint!);
  u.searchParams.set("client_id", c.client.client_id);
  u.searchParams.set("redirect_uri", c.redirectUri);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("scope", c.scopes);
  u.searchParams.set("state", opts.state);
  u.searchParams.set("nonce", opts.nonce);
  u.searchParams.set("code_challenge", opts.codeChallenge);
  u.searchParams.set("code_challenge_method", "S256");
  return u.toString();
}

/**
 * Exchange a callback `code` for tokens. Returns the parsed token
 * response (access_token, id_token, etc.) on success, or an error
 * shape on failure — callers map errors to 401 redirect-to-login.
 *
 * Nonce verification happens inside `processAuthorizationCodeResponse`
 * via the `expectedNonce` option — there's no separate verifyIdToken
 * step. To pull the parsed ID token claims out of the token response,
 * call `getIdTokenClaims(tokens)` below.
 */
export type ExchangeResult =
  | { ok: true; tokens: oauth.TokenEndpointResponse }
  | { ok: false; code: string; message: string };

export async function exchangeCode(opts: {
  code: string;
  codeVerifier: string;
  expectedState: string;
  receivedState: string;
  expectedNonce: string;
}): Promise<ExchangeResult> {
  if (opts.expectedState !== opts.receivedState) {
    return { ok: false, code: "STATE_MISMATCH", message: "OAuth state parameter mismatch" };
  }

  const c = await getOAuth();
  const params = new URL(c.redirectUri);
  params.searchParams.set("code", opts.code);
  params.searchParams.set("state", opts.receivedState);

  const callbackParams = oauth.validateAuthResponse(
    c.issuer,
    c.client,
    params.searchParams,
    opts.expectedState,
  );

  const tokRes = await oauth.authorizationCodeGrantRequest(
    c.issuer,
    c.client,
    c.clientAuth,
    callbackParams,
    c.redirectUri,
    opts.codeVerifier,
  );
  const tokens = await oauth.processAuthorizationCodeResponse(c.issuer, c.client, tokRes, {
    expectedNonce: opts.expectedNonce,
  });

  return { ok: true, tokens };
}

/**
 * Pull the validated ID-token claims out of a token response. Wraps
 * oauth4webapi's `getValidatedIdTokenClaims` so callers don't have to
 * know that validation already happened upstream.
 */
export function getIdTokenClaims(
  tokens: oauth.TokenEndpointResponse,
): Record<string, unknown> {
  const claims = oauth.getValidatedIdTokenClaims(tokens);
  return (claims ?? {}) as Record<string, unknown>;
}

/**
 * Lookup the userinfo claims for a freshly-issued access token. We
 * use this on the OAuth callback to populate the session payload
 * (email, username, user_type) — the id_token alone may not carry
 * all of these depending on scope grants.
 */
export async function fetchUserInfo(accessToken: string): Promise<Record<string, unknown>> {
  const c = await getOAuth();
  const res = await oauth.userInfoRequest(c.issuer, c.client, accessToken);
  return (await oauth.processUserInfoResponse(c.issuer, c.client, "", res)) as Record<
    string,
    unknown
  >;
}
