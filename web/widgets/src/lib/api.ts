/**
 * API helpers — public (no auth) and authenticated (bearer-from-cookie).
 *
 * The authenticated path uses Option C from the Phase 8b design: the
 * widget calls `auth.<tenant>/session/token` with `credentials:
 * 'include'` (host-scoped cookie travels via SameSite=Lax cross-origin
 * same-site send), gets a short-lived bearer JWT, caches it
 * in-memory, uses it for api-server calls.
 *
 * The bearer-exchange endpoint itself is implemented in Step 4 of
 * the pivot plan; for now this module compiles against the contract
 * and the API helper is ready to use as soon as the endpoint exists.
 */

import { getConfig } from "./config";

/** Result of an API call — typed for ergonomic narrowing. */
export type ApiResult<T> =
  | { ok: true; status: number; data: T }
  | { ok: false; status: number; code: string; message: string; details?: Record<string, unknown> };

interface TokenResponse {
  access_token: string;
  expires_in: number;
  token_type: "Bearer";
}

interface CachedToken {
  token: string;
  expiresAt: number; // ms epoch
}

let cached: CachedToken | null = null;
const REFRESH_MARGIN_MS = 30_000; // refresh 30s before expiry

/**
 * Get a bearer for api-server calls. Two paths:
 *
 *   1. **SPA tenant**: tenant called `Akashic.configure({ accessToken,
 *      accessTokenExpiresAt })` after a PKCE flow. We use that token
 *      directly. Tenant owns refresh.
 *   2. **First-party widget**: tenant has a backend-set auth-server
 *      session cookie. We exchange it for a short-lived bearer via
 *      `auth.<tenant>/session/token`, cache in-memory.
 *
 * Returns null if neither path produces a bearer (widget should
 * render a sign-in CTA).
 */
export async function getAccessToken(): Promise<string | null> {
  // Path 1 — explicit token supplied by an SPA via Akashic.configure.
  const cfg = getConfig();
  if (cfg.accessToken) {
    if (
      !cfg.accessTokenExpiresAt ||
      cfg.accessTokenExpiresAt > Date.now() + REFRESH_MARGIN_MS
    ) {
      return cfg.accessToken;
    }
    // Configured token is expired. SPA needs to refresh; we don't
    // attempt to fall back to /session/token since SPA tenants don't
    // typically have an auth-server cookie.
    return null;
  }

  // Path 2 — cookie-bridge for first-party widgets with a session.
  if (cached && cached.expiresAt > Date.now() + REFRESH_MARGIN_MS) {
    return cached.token;
  }
  const { authBaseUrl } = cfg;
  let res: Response;
  try {
    res = await fetch(`${authBaseUrl}/session/token`, {
      method: "POST",
      credentials: "include",
    });
  } catch {
    // Network error / CORS rejection. Treat as logged-out so the widget
    // can render a sign-in CTA rather than crashing.
    cached = null;
    return null;
  }
  if (res.status === 401 || res.status === 403) {
    cached = null;
    return null;
  }
  if (!res.ok) {
    cached = null;
    return null;
  }
  const body = (await res.json()) as TokenResponse;
  cached = { token: body.access_token, expiresAt: Date.now() + body.expires_in * 1000 };
  return cached.token;
}

/** Force-clear the cached bearer. Used after sign-out, password change, etc. */
export function clearCachedToken(): void {
  cached = null;
}

/**
 * Public API call — no auth header. For endpoints like
 * `POST /users/register` that the api-server explicitly marks as
 * public.
 */
export async function apiCallPublic<T>(
  path: string,
  init?: { method?: string; json?: unknown },
): Promise<ApiResult<T>> {
  const { apiBaseUrl } = getConfig();
  const headers: Record<string, string> = { Accept: "application/json" };
  let body: string | undefined;
  if (init?.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(init.json);
  }
  const res = await fetch(joinUrl(apiBaseUrl, path), {
    method: init?.method ?? "GET",
    headers,
    body,
    credentials: "omit",
  });
  return parseEnvelope<T>(res);
}

/**
 * Authenticated API call — fetches a bearer via getAccessToken() and
 * adds Authorization: Bearer header. Returns NO_SESSION if the
 * user isn't logged in.
 */
export async function apiCall<T>(
  path: string,
  init?: { method?: string; json?: unknown },
): Promise<ApiResult<T>> {
  const token = await getAccessToken();
  if (!token) {
    return {
      ok: false,
      status: 401,
      code: "NO_SESSION",
      message: "Not signed in",
    };
  }
  const { apiBaseUrl } = getConfig();
  const headers: Record<string, string> = {
    Accept: "application/json",
    Authorization: `Bearer ${token}`,
  };
  let body: string | undefined;
  if (init?.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(init.json);
  }
  const res = await fetch(joinUrl(apiBaseUrl, path), {
    method: init?.method ?? "GET",
    headers,
    body,
    credentials: "omit", // bearer is the auth; cookies aren't needed on api calls
  });
  // 401 might mean the bearer expired between cache check and request.
  // Clear and let the caller retry once.
  if (res.status === 401) clearCachedToken();
  return parseEnvelope<T>(res);
}

async function parseEnvelope<T>(res: Response): Promise<ApiResult<T>> {
  const status = res.status;
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    return {
      ok: false,
      status,
      code: status >= 500 ? "API_UNAVAILABLE" : "API_BAD_RESPONSE",
      message: `Non-JSON response (${status})`,
    };
  }
  if (body && typeof body === "object" && "success" in body) {
    const env = body as {
      success: boolean;
      data?: unknown;
      error?: { code: string; message: string; details?: Record<string, unknown> };
    };
    if (env.success === true) {
      return { ok: true, status, data: env.data as T };
    }
    if (env.success === false && env.error) {
      return {
        ok: false,
        status,
        code: env.error.code,
        message: env.error.message,
        details: env.error.details,
      };
    }
  }
  return {
    ok: false,
    status,
    code: "API_BAD_RESPONSE",
    message: `Unexpected envelope shape (status=${status})`,
  };
}

function joinUrl(base: string, path: string): string {
  if (/^https?:\/\//.test(path)) return path;
  return base + (path.startsWith("/") ? path : "/" + path);
}
