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
    get clientSecret(): string {
      return requireEnv("AKASHIC_PORTAL_CLIENT_SECRET");
    },
    get redirectUri(): string {
      return requireEnv("AKASHIC_PORTAL_REDIRECT_URI");
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
  },

  nodeEnv: optionalEnv("NODE_ENV", "development"),
};

export type PortalEnv = typeof env;
