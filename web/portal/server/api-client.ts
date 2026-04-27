/**
 * Bearer-token client to the Akashic resource API server (port 8082).
 *
 * Pattern: every call carries the user's own access token. The portal
 * holds no privileged trust material — no mTLS, no service account.
 * If the access token is invalid or missing we return a typed error
 * the caller can map to a 401, which the FE turns into a
 * redirect-to-sign-in.
 *
 * TLS:
 *   The api server's cert is issued from `pki-internal/server` and
 *   the akashic CA is rooted in the portal container's system trust
 *   store (Dockerfile copies `/certs/akashic/api-ca.crt` into
 *   /usr/local/share/ca-certificates and runs update-ca-certificates).
 *   So a plain `fetch(...)` against `https://api.akashic.local:8082`
 *   validates without any per-call agent setup.
 *
 * Why fetch vs. an HTTPS agent: this server-side code runs under
 * Next 15 / Node 20+, where `fetch` honours NODE_EXTRA_CA_CERTS and
 * the OS trust store. No need for the cookie-jar / agent gymnastics
 * the admin-bff's Go ControlClient does — that one needs a client
 * cert; we don't.
 */

import { getSession, touchSession, type SessionPayload } from "./session";
import { env } from "../lib/env";

/** What the api server returns inside the standard envelope. */
interface ErrorBody {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

interface SuccessEnvelope<T> {
  success: true;
  data: T;
}

interface ErrorEnvelope {
  success: false;
  error: ErrorBody;
}

type Envelope<T> = SuccessEnvelope<T> | ErrorEnvelope;

/**
 * Result of an API call, designed for ergonomic narrowing in the
 * caller. Either you got data and the call was 2xx, or you have an
 * error code + message and the appropriate HTTP status.
 */
export type ApiResult<T> =
  | { ok: true; data: T; status: number }
  | { ok: false; status: number; code: string; message: string; details?: Record<string, unknown> };

export interface ApiCallOptions {
  /** HTTP method. Defaults to GET. */
  method?: "GET" | "POST" | "PATCH" | "DELETE" | "PUT";
  /** JSON body. Auto-stringified; sets Content-Type: application/json. */
  json?: unknown;
  /**
   * Whether to bump the session's idle TTL. Default true. Set false
   * for read-only "is the session alive?" probes that shouldn't keep
   * the session warm.
   */
  touch?: boolean;
}

const ENV_NO_SESSION: ApiResult<never> = {
  ok: false,
  status: 401,
  code: "NO_SESSION",
  message: "no portal session — sign in first",
};

/**
 * Call the api server on behalf of the currently logged-in user.
 *
 * Reads the access token from the Redis-backed session (touching it
 * by default, so active users stay logged in). Returns a typed
 * `ApiResult` rather than throwing on 4xx/5xx — handlers shouldn't
 * have to sprinkle try/catch around routine "wrong password" or
 * "client not found" responses.
 *
 * Throws ONLY on transport failures (DNS, TLS, network) — those are
 * truly exceptional and should bubble up to a Next 500 page.
 */
export async function apiCall<T>(
  path: string,
  opts: ApiCallOptions = {},
): Promise<ApiResult<T>> {
  const session: SessionPayload | null =
    opts.touch === false ? await getSession() : await touchSession();

  if (!session) return ENV_NO_SESSION as ApiResult<T>;

  const url = joinPath(env.api.baseUrl, path);
  const headers: Record<string, string> = {
    Authorization: `Bearer ${session.access_token}`,
    Accept: "application/json",
  };
  let body: string | undefined;
  if (opts.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.json);
  }

  const res = await fetch(url, {
    method: opts.method ?? "GET",
    headers,
    body,
    // Server-to-server: don't follow redirects implicitly. The api
    // server should never 30x its bearer-protected routes; if it does
    // we want the caller to see the surprise.
    redirect: "manual",
  });

  return parseEnvelope<T>(res);
}

/**
 * Public-endpoint variant — no bearer token. Used for /users/register
 * and /users/forgot-password-help, which are intentionally
 * unauthenticated. Same envelope-parsing pipeline.
 */
export async function apiCallPublic<T>(
  path: string,
  opts: Omit<ApiCallOptions, "touch"> = {},
): Promise<ApiResult<T>> {
  const url = joinPath(env.api.baseUrl, path);
  const headers: Record<string, string> = { Accept: "application/json" };
  let body: string | undefined;
  if (opts.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.json);
  }

  const res = await fetch(url, {
    method: opts.method ?? "GET",
    headers,
    body,
    redirect: "manual",
  });

  return parseEnvelope<T>(res);
}

async function parseEnvelope<T>(res: Response): Promise<ApiResult<T>> {
  const status = res.status;
  let parsed: Envelope<T> | undefined;

  // The api server always returns the standard envelope, but we still
  // guard against transport-level oddities (proxy serving HTML error
  // pages, etc.) so a corrupt body doesn't crash a render.
  try {
    parsed = (await res.json()) as Envelope<T>;
  } catch {
    return {
      ok: false,
      status,
      code: status >= 500 ? "API_UNAVAILABLE" : "API_BAD_RESPONSE",
      message: `api server returned non-JSON ${status}`,
    };
  }

  if (parsed && parsed.success === true) {
    return { ok: true, status, data: parsed.data };
  }
  if (parsed && parsed.success === false) {
    return {
      ok: false,
      status,
      code: parsed.error.code,
      message: parsed.error.message,
      details: parsed.error.details,
    };
  }
  return {
    ok: false,
    status,
    code: "API_BAD_RESPONSE",
    message: `api server returned unexpected envelope shape (status=${status})`,
  };
}

function joinPath(base: string, path: string): string {
  if (path.startsWith("http://") || path.startsWith("https://")) return path;
  const trimmedBase = base.endsWith("/") ? base.slice(0, -1) : base;
  const trimmedPath = path.startsWith("/") ? path : "/" + path;
  return trimmedBase + trimmedPath;
}
