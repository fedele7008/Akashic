/**
 * Centralised, typed access to portal env vars.
 *
 * The portal reads its configuration entirely from env — no config
 * file. All required values use `requireEnv()`, which throws on
 * access if the var is missing/empty. Required vars are exposed via
 * getters so that `next build` (which runs without runtime env)
 * doesn't trip over them; the throw only happens when handler code
 * actually reads the value.
 *
 * Server-only. Never import this from a client component.
 */

function requireEnv(name: string): string {
  const v = process.env[name];
  if (v === undefined || v === "") {
    throw new Error(`missing required env var: ${name}`);
  }
  return v;
}

function optionalEnv(name: string, fallback: string): string {
  const v = process.env[name];
  return v === undefined || v === "" ? fallback : v;
}

function envInt(name: string, fallback: number): number {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  const n = Number.parseInt(v, 10);
  if (Number.isNaN(n)) {
    throw new Error(`env var ${name} must be an integer, got: ${v}`);
  }
  return n;
}

/**
 * Resolved at first access. Required-env getters throw at the call
 * site rather than at module load — this keeps `next build` happy
 * even when production env isn't injected into the build container.
 */
export const env = {
  redis: {
    host: optionalEnv("AKASHIC_PORTAL_REDIS_HOST", "redis"),
    port: envInt("AKASHIC_PORTAL_REDIS_PORT", 6379),
    password: optionalEnv("AKASHIC_PORTAL_REDIS_PASSWORD", ""),
    tls: optionalEnv("AKASHIC_PORTAL_REDIS_TLS", "on") === "on",
    db: envInt("AKASHIC_PORTAL_REDIS_DB", 2),
  },

  session: {
    cookieName: optionalEnv("AKASHIC_PORTAL_SESSION_COOKIE", "akashic_portal_session"),
    get password(): string {
      // 32+ bytes. Used by iron-session for AEAD encryption.
      return requireEnv("AKASHIC_PORTAL_SESSION_SECRET");
    },
    // Idle: refreshed on activity. Default 30 minutes.
    idleSeconds: envInt("AKASHIC_PORTAL_SESSION_IDLE_SECONDS", 30 * 60),
    // Absolute: never extended. Default 12 hours.
    absoluteSeconds: envInt("AKASHIC_PORTAL_SESSION_ABSOLUTE_SECONDS", 12 * 3600),
  },

  oauth: {
    get issuer(): string {
      return requireEnv("AKASHIC_OAUTH_ISSUER");
    },
    clientId: optionalEnv("AKASHIC_PORTAL_CLIENT_ID", "akashic-portal"),
    /**
     * Raw env-var read; can be empty when the portal starts before
     * akashic-server finishes provisioning the secret. Callers that
     * need the actual secret (only the OAuth code path) use
     * `resolveClientSecret()` from server/oauth.ts, which falls
     * back to reading the secret file on disk.
     *
     * Why not putting the disk fallback here: lib/env.ts is imported
     * (transitively) by middleware.ts, which Next.js bundles for the
     * Edge runtime. A `require("node:fs")` here would poison the
     * Edge bundle. So the fallback lives in oauth.ts (Node-only).
     */
    clientSecretFromEnv: optionalEnv("AKASHIC_PORTAL_CLIENT_SECRET", ""),
    get redirectUri(): string {
      // Same env var the akashic-server reads (config path
       // oauth.portal_redirect_uri → AKASHIC_OAUTH_PORTAL_REDIRECT_URI).
      // Single source of truth across the two services prevents
      // redirect_uri_mismatch on the OAuth callback.
      return requireEnv("AKASHIC_OAUTH_PORTAL_REDIRECT_URI");
    },
    scopes: optionalEnv("AKASHIC_PORTAL_OAUTH_SCOPES", "openid profile email"),
  },

  api: {
    baseUrl: optionalEnv("AKASHIC_PORTAL_API_BASE_URL", "https://api.akashic.local:8082"),
  },

  brand: {
    name: optionalEnv("AKASHIC_PORTAL_BRAND_NAME", "Akashic"),
    tagline: optionalEnv(
      "AKASHIC_PORTAL_TAGLINE",
      "Identity provider built on Akashic.",
    ),
    description: optionalEnv(
      "AKASHIC_PORTAL_DESCRIPTION",
      "Sign in or create an account to manage your identity and OAuth integrations.",
    ),
    // Operator-configured contact for the Phase 8 forgot-password
    // informational page. Empty string means "not configured" — the
    // /forgot page renders a generic fallback.
    supportEmail: optionalEnv("AKASHIC_PORTAL_SUPPORT_EMAIL", ""),
  },

  nodeEnv: optionalEnv("NODE_ENV", "development"),
};

export type PortalEnv = typeof env;

/**
 * The public origin the user's browser actually reaches the portal
 * at. Derived from the (operator-configured) OAuth redirect URI —
 * that value is, by definition, a URL the browser successfully
 * resolves to this portal.
 *
 * Use this for any user-facing redirect (login error pages, post-
 * logout landing, etc.). Don't use `request.url` as the base — Next
 * standalone in a container reports its internal listening address
 * (`https://0.0.0.0:3000`), which leaks into the user's browser if
 * passed through `new URL("/path", request.url)`.
 *
 * Returns `https://akashic.example.com` (no path, no trailing slash).
 */
export function portalOrigin(): string {
  try {
    const u = new URL(env.oauth.redirectUri);
    return `${u.protocol}//${u.host}`;
  } catch {
    // env.oauth.redirectUri throws if AKASHIC_OAUTH_PORTAL_REDIRECT_URI
    // is unset. In that case we have no source of truth, so return a
    // best-effort placeholder; the redirect still works as a relative
    // URL in browsers, just without an absolute base.
    return "";
  }
}

/** Build an absolute URL on the portal origin for a given path. */
export function portalUrl(path: string): string {
  const origin = portalOrigin();
  if (!origin) return path; // relative — browser resolves against current page
  const normalized = path.startsWith("/") ? path : "/" + path;
  return origin + normalized;
}
