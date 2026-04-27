/**
 * Client-side CSRF helper. Reads the `akashic_portal_csrf` cookie
 * (set by middleware on any prior /api/* GET) and returns its value
 * so a fetch() can echo it in the X-Akashic-CSRF header.
 *
 * The cookie is HttpOnly=false BY DESIGN — see server/csrf.ts for
 * the full reasoning. Same-origin JS reads it; cross-origin code
 * cannot.
 */

export const CSRF_COOKIE_NAME = "akashic_portal_csrf";
export const CSRF_HEADER_NAME = "X-Akashic-CSRF";

export function readCsrfCookie(): string | null {
  if (typeof document === "undefined") return null;
  const all = document.cookie.split("; ");
  const prefix = CSRF_COOKIE_NAME + "=";
  for (const c of all) {
    if (c.startsWith(prefix)) {
      return decodeURIComponent(c.slice(prefix.length));
    }
  }
  return null;
}

/**
 * Lazily bootstrap the CSRF cookie. The portal's CSRF middleware
 * only runs on /api/* requests, so a user whose first interaction
 * is a form POST has no cookie yet. We fix that by hitting
 * /api/health (a GET, ergo cookie-setting under our middleware)
 * once before any state-changing call.
 *
 * Idempotent: if a cookie already exists we skip the bootstrap.
 */
async function ensureCsrfCookie(): Promise<string | null> {
  let token = readCsrfCookie();
  if (token) return token;
  // Bootstrap. /api/health is exempt from CSRF enforcement but our
  // middleware still attaches the cookie on the way back.
  await fetch("/api/health", { method: "GET", credentials: "same-origin" });
  token = readCsrfCookie();
  return token;
}

/**
 * fetch wrapper that adds Content-Type + CSRF header, lazy-
 * bootstrapping the CSRF cookie when the page hasn't yet touched
 * any /api/* route. Returns parsed JSON envelope.
 */
export async function postJson<T = unknown>(
  url: string,
  body: unknown,
): Promise<{ ok: boolean; status: number; body: T | null }> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const token = await ensureCsrfCookie();
  if (token) headers[CSRF_HEADER_NAME] = token;

  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
    credentials: "same-origin",
  });
  let parsed: T | null = null;
  try {
    parsed = (await res.json()) as T;
  } catch {
    /* non-JSON response (e.g. 502 HTML) — body stays null */
  }
  return { ok: res.ok, status: res.status, body: parsed };
}
