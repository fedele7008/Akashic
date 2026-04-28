/**
 * Runtime config for the widget bundle.
 *
 * Defaults are derived from the `<script>` tag's URL — if the tenant
 * loads `https://api.acme.com/widgets/akashic.js`, the bundle infers
 * `apiBaseUrl = https://api.acme.com` and `authBaseUrl = https://auth.acme.com`
 * (swap `api.` → `auth.`). Tenants can override via `Akashic.configure(...)`
 * before any widget mounts.
 *
 * No env vars (browser context) — config travels via the script URL or
 * an explicit configure() call.
 */

export interface AkashicConfig {
  /** Base URL of the api server. e.g., "https://api.acme.com". No trailing slash. */
  apiBaseUrl: string;
  /** Base URL of the auth server. e.g., "https://auth.acme.com". No trailing slash. */
  authBaseUrl: string;
}

let cfg: AkashicConfig | null = null;

function inferFromScriptUrl(): AkashicConfig | null {
  if (typeof document === "undefined") return null;
  // Find OUR script tag — the one that loaded this bundle.
  const scripts = Array.from(document.querySelectorAll("script[src]"));
  const ours = scripts.find((s) => {
    const src = (s as HTMLScriptElement).src;
    return /\/widgets\/akashic\.js(\?|$)/.test(src);
  }) as HTMLScriptElement | undefined;
  if (!ours) return null;

  try {
    const url = new URL(ours.src);
    const apiOrigin = `${url.protocol}//${url.host}`;
    // Convention: swap leading "api." for "auth." to derive the auth origin.
    // Tenants who deploy with a different topology call configure() explicitly.
    const authHost = url.host.replace(/^api\./, "auth.");
    const authOrigin = `${url.protocol}//${authHost}`;
    return { apiBaseUrl: apiOrigin, authBaseUrl: authOrigin };
  } catch {
    return null;
  }
}

export function getConfig(): AkashicConfig {
  if (cfg) return cfg;
  const inferred = inferFromScriptUrl();
  if (inferred) {
    cfg = inferred;
    return cfg;
  }
  throw new Error(
    "Akashic widgets: could not infer config from script URL. Call Akashic.configure({apiBaseUrl, authBaseUrl}) before mounting widgets.",
  );
}

export function configure(overrides: Partial<AkashicConfig>): void {
  const base = cfg ?? inferFromScriptUrl() ?? { apiBaseUrl: "", authBaseUrl: "" };
  cfg = {
    apiBaseUrl: stripTrail(overrides.apiBaseUrl ?? base.apiBaseUrl),
    authBaseUrl: stripTrail(overrides.authBaseUrl ?? base.authBaseUrl),
  };
}

function stripTrail(s: string): string {
  return s.endsWith("/") ? s.slice(0, -1) : s;
}
