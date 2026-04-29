// Thin fetch wrappers + CSRF helper for the admin FE.
//
// The BFF sets a CSRF cookie on first response (see
// pkg/admin_bff/csrf.go); for any state-changing request we have to
// echo that cookie's value back in the X-Akashic-CSRF header.

const CSRF_COOKIE = 'akashic_csrf';
const CSRF_HEADER = 'X-Akashic-CSRF';

/** Read a cookie value by name. Returns '' if not set. */
function readCookie(name: string): string {
  const target = name + '=';
  for (const part of document.cookie.split(';')) {
    const trimmed = part.trim();
    if (trimmed.startsWith(target)) {
      return decodeURIComponent(trimmed.substring(target.length));
    }
  }
  return '';
}

export interface BootstrapStatus {
  is_complete: boolean;
  completed_at?: string;
  root_user_id?: string;
  token_exists?: boolean;
  token_ttl_seconds?: number;
}

export interface CreateRootRequest {
  token: string;
  username: string;
  email: string;
  password: string;
}

export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

/** Standard envelope returned by the BFF (matches pkg/server/response). */
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: ApiError;
}

/**
 * Session info returned by GET /api/session when the browser has a
 * valid BFF session cookie. Mirrors pkg/admin_bff/oauth_handlers.go's
 * handleSessionInfo response shape.
 */
export interface SessionInfo {
  user_id: string;
  user_type: string;
  username: string;
  email: string;
  issued_at: string;
  expires_at: string;
}

export class SessionApi {
  /**
   * GET /api/session — returns the logged-in user's info.
   *
   * On 401 (no session OR expired) returns null rather than throwing,
   * because "not logged in" is a normal expected state at this
   * endpoint. The App shell switches its rendered view based on the
   * null/non-null outcome.
   *
   * Other failure modes (network down, BFF crashed) DO throw, since
   * those represent infrastructure problems the user should see.
   */
  static async info(): Promise<SessionInfo | null> {
    const r = await fetch('/api/session', {
      method: 'GET',
      credentials: 'same-origin',
    });
    if (r.status === 401) {
      return null; // not logged in -- normal
    }
    const body: ApiResponse<SessionInfo> = await r.json();
    if (!r.ok || !body.success) {
      throw new Error(body.error?.message ?? `Session check failed (HTTP ${r.status})`);
    }
    return body.data!;
  }

  /**
   * POST /logout — invalidates the BFF session and returns the auth
   * server's RP-Initiated Logout URL.
   *
   * The full logout chain is:
   *
   *   1. POST /logout (BFF)        → kills the BFF session + cookie
   *   2. GET <auth_logout_url>     → kills the auth-server session,
   *                                  redirects browser back to admin
   *
   * Without the second hop, the auth-server's session cookie survives,
   * and the next "Sign in" click silently re-uses it (single-sign-on
   * is great until you explicitly want OUT). The caller navigates the
   * browser to the returned URL to complete the chain.
   *
   * Returns the URL the FE should navigate to next; empty string means
   * the BFF couldn't compute one (rare; happens only if OAuth init
   * failed at BFF startup).
   */
  static async logout(): Promise<string> {
    const csrf = readCookie(CSRF_COOKIE);
    const r = await fetch('/logout', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        [CSRF_HEADER]: csrf,
      },
    });
    try {
      const body: ApiResponse<{ logged_out: boolean; auth_logout_url?: string }> =
        await r.json();
      return body.data?.auth_logout_url ?? '';
    } catch {
      return '';
    }
  }
}

/**
 * Request body for POST /api/clients. Matches the server-side shape
 * (pkg/admin_bff/client.go:CreateClientRequest).
 */
export interface CreateClientRequest {
  name: string;
  client_type: 'WEB' | 'SPA';
  redirect_uris: string;
  description?: string;
  homepage_url?: string;
  /**
   * WEB clients only — operator-configurable. Default true. Ignored
   * for SPA (always-true is enforced server-side regardless).
   */
  require_pkce?: boolean;
}

export interface ClientView {
  client_id: string;
  name: string;
  description?: string;
  homepage_url?: string;
  client_type: 'WEB' | 'SPA';
  public: boolean;
  redirect_uris: string;
  allowed_scopes: string;
  auth_types: string;
  built_in: boolean;
  require_pkce: boolean;
  created_at: string;
  updated_at: string;
}

/**
 * Response from POST /api/clients on success. `client_secret` is
 * present (and non-empty) only for WEB clients; absent for SPA. The
 * UI MUST render the secret in a one-time-display panel — only its
 * bcrypt hash is persisted server-side.
 */
export interface CreateClientResponse {
  client: ClientView;
  client_secret: string;
}

export class ClientsApi {
  /**
   * POST /api/clients — register a new OAuth client (WEB or SPA).
   *
   * On success: returns the new client's view + (for WEB) the
   * plaintext client_secret. On any 4xx/5xx the call throws with
   * the structured error attached so the caller can render
   * server-supplied messages directly.
   *
   * Session is enforced server-side (admin/root only). A 401/403
   * response indicates the FE shell should reload to surface the
   * sign-in landing page.
   */
  static async create(req: CreateClientRequest): Promise<CreateClientResponse> {
    const r = await fetch('/api/clients', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        [CSRF_HEADER]: readCookie(CSRF_COOKIE),
      },
      body: JSON.stringify(req),
    });
    const body: ApiResponse<CreateClientResponse> = await r.json();
    if (!r.ok || !body.success) {
      const err = new Error(body.error?.message ?? `Client registration failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
    return body.data!;
  }
}

export class BootstrapApi {
  /**
   * GET /api/bootstrap/status — fetch the current bootstrap state.
   * Always reachable, both in bootstrap-required and normal modes.
   */
  static async status(): Promise<BootstrapStatus> {
    const r = await fetch('/api/bootstrap/status', {
      method: 'GET',
      credentials: 'same-origin',
    });
    const body: ApiResponse<BootstrapStatus> = await r.json();
    if (!r.ok || !body.success) {
      throw new Error(body.error?.message ?? `Status check failed (HTTP ${r.status})`);
    }
    return body.data!;
  }

  /**
   * POST /api/bootstrap/create-root — submit the bootstrap form.
   * On any structured error we throw with the server-supplied message
   * so the caller can render it directly to the user.
   */
  static async createRoot(req: CreateRootRequest): Promise<{ user: Record<string, unknown> }> {
    const csrf = readCookie(CSRF_COOKIE);
    if (!csrf) {
      // The BFF sets the CSRF cookie on the very first response. If
      // we don't have it yet, do a no-op GET to acquire one. In
      // practice the App component's status call already did this,
      // but defensive double-check.
      await fetch('/api/health', { credentials: 'same-origin' });
    }
    const r = await fetch('/api/bootstrap/create-root', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        [CSRF_HEADER]: readCookie(CSRF_COOKIE),
      },
      body: JSON.stringify(req),
    });
    const body: ApiResponse<{ user: Record<string, unknown> }> = await r.json();
    if (!r.ok || !body.success) {
      const err = new Error(body.error?.message ?? `Submission failed (HTTP ${r.status})`);
      // Attach the structured error so the caller can branch on .code
      // for special handling (e.g., RATE_LIMITED).
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
    return body.data!;
  }
}
