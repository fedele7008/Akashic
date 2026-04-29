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
import { readFileSync } from "node:fs";

import { env } from "../lib/env";

/**
 * Two-tier caching strategy:
 *
 *   - Discovery + JWKS endpoint URLs are cached (`discoveryCache`)
 *     because re-fetching them on every OAuth call is wasteful and
 *     they change rarely (only on signing-key rotation, which we
 *     handle via `resetOAuthCache` from the 401 path).
 *
 *   - Credentials (client_id + client_secret) are NOT cached. They're
 *     re-resolved on every OAuth call so that `akashic-cli clients
 *     create --save-credentials-to <path>` writing the credentials
 *     file mid-flight is picked up by the next /authorize without a
 *     portal restart. This is the in-stack-sample dev-flow case;
 *     real-tenant deployments hardcode their secret into env and
 *     incur the same per-call read of an env var (negligible).
 *
 * The split is what makes the user experience "operator runs `clients
 * create`, then user clicks sign-in, it just works" possible without
 * any container restart in the sample stack.
 */

interface Credentials {
  clientId: string;
  clientSecret: string;
}

/**
 * Tagged error so route handlers can distinguish "operator hasn't
 * dropped a credentials file yet" (CREDENTIALS_MISSING — actionable)
 * from real network/discovery failures (OAUTH_DISCOVERY_FAILED —
 * retry, escalate to ops). Plain Error wouldn't let `route.ts`
 * branch on the cause without string-matching the message.
 */
export class CredentialsMissingError extends Error {
  readonly code = "CREDENTIALS_MISSING";
  constructor(message: string) {
    super(message);
    this.name = "CredentialsMissingError";
  }
}

/**
 * Hardcoded path the sample reads its credentials from. Kept here
 * (Node-only file) rather than in lib/env.ts because lib/env.ts is
 * pulled into the Edge bundle via middleware.ts → server/csrf.ts.
 *
 * The docker-compose `sample-nextjs` service mounts the host's
 * `.secrets/sample/` directory at /secrets/, so the operator-issued
 * credentials JSON written by:
 *
 *   akashic-cli clients create --save-credentials-to .secrets/sample/nextjs.json
 *
 * shows up here without any env wiring. Real tenants taking the
 * sample to production fork the repo and replace the path (or read
 * from their secret manager directly).
 */
const CREDENTIALS_FILE = "/secrets/sample/nextjs.json";

/**
 * Resolve the OAuth credentials (client_id + client_secret) by
 * reading the operator-managed JSON file at CREDENTIALS_FILE. Read
 * on every OAuth call so a freshly-registered client (from
 * `akashic-cli clients create --save-credentials-to`) takes effect
 * without a portal restart.
 *
 * Throws if the file is missing, unreadable, or doesn't contain
 * both fields — caller maps to a 503 "sign-in temporarily
 * unavailable" page. The error message points the operator at the
 * exact CLI command needed to fix it.
 *
 * Only call this from inside Node-runtime code (route handlers).
 * Edge-runtime callers cannot use node:fs.
 */
function resolveCredentials(): Credentials {
  try {
    const raw = readFileSync(CREDENTIALS_FILE, "utf8");
    const parsed = JSON.parse(raw) as Partial<Credentials> & {
      client_id?: string;
      client_secret?: string;
    };
    const clientId = parsed.client_id ?? parsed.clientId ?? "";
    const clientSecret = parsed.client_secret ?? parsed.clientSecret ?? "";
    if (clientId && clientSecret) {
      return { clientId, clientSecret };
    }
  } catch {
    // File missing / unreadable / non-JSON. Expected in the gap
    // between sample container start and `clients create`. Throw a
    // tagged error so the route handler can surface a sharper code
    // than the generic "discovery failed" wrapper.
  }
  throw new CredentialsMissingError(
    `OAuth credentials not available at ${CREDENTIALS_FILE}. Run: akashic-cli clients create --type WEB --save-credentials-to .secrets/sample/nextjs.json --redirect-uri <your-callback> --name "Next.js sample"`,
  );
}

interface OAuthClientCtx {
  issuer: oauth.AuthorizationServer;
  client: oauth.Client;
  clientAuth: oauth.ClientAuth;
  redirectUri: string;
  scopes: string;
}

/** Discovery cache — issuer metadata only, no credentials. */
let discoveryCache: oauth.AuthorizationServer | undefined;

async function getDiscovery(): Promise<oauth.AuthorizationServer> {
  if (discoveryCache) return discoveryCache;
  const issuerUrl = new URL(env.oauth.issuer);
  const discoveryRes = await oauth.discoveryRequest(issuerUrl, {
    algorithm: "oidc",
  });
  discoveryCache = await oauth.processDiscoveryResponse(issuerUrl, discoveryRes);
  return discoveryCache;
}

/**
 * Resolve the OAuth client context. Throws on discovery failure or
 * missing credentials — the caller should map that to a 503 "Sign-in
 * temporarily unavailable" page rather than a 500.
 *
 * Discovery is cached; credentials are read fresh on every call (see
 * the comment block at the top of this file).
 */
export async function getOAuth(): Promise<OAuthClientCtx> {
  const issuer = await getDiscovery();
  const creds = resolveCredentials();

  const client: oauth.Client = {
    client_id: creds.clientId,
    // Use client_secret_post (credentials in form body) rather than
    // client_secret_basic (Authorization header). Two reasons:
    //   1. RFC 6749 §2.3.1 requires URL-encoding the client_id and
    //      secret before base64 in the Basic header. oauth4webapi
    //      complies; many auth-server implementations (ours included)
    //      compare raw bytes and never URL-decode. So a hyphenated
    //      client_id sent as %2D-escaped looks like a different
    //      client_id and we get 401 invalid_client. Form bodies don't
    //      have this asymmetry — both sides handle URL-encoding
    //      uniformly.
    //   2. Our auth server advertises both methods in discovery, so
    //      this is a pure client-side switch.
    token_endpoint_auth_method: "client_secret_post",
  };

  return {
    issuer,
    client,
    clientAuth: oauth.ClientSecretPost(creds.clientSecret),
    redirectUri: env.oauth.redirectUri,
    scopes: env.oauth.scopes,
  };
}

/**
 * Force a re-fetch of discovery on next access. Used by the callback
 * handler when a 401 from the token endpoint suggests our cached
 * discovery (e.g. the auth server's signing key rotated, JWKS URL
 * stale) is the cause.
 *
 * Does NOT clear credentials — they're re-read on every call, so a
 * stale cached secret cannot exist.
 */
export function resetOAuthCache(): void {
  discoveryCache = undefined;
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
