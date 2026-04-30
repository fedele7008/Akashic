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

/**
 * Setup-status snapshot — Phase 8c.1.
 *
 * Each field is a single boolean for "this setup gate has been
 * cleared." The banner renders one row per `false` field, in the
 * order an operator would naturally fix them (bootstrap before
 * portal-registration before LDAP-anything else). A field set to
 * `false` may also mean "subsystem unreachable; check logs" — the
 * server logs a warning in those cases.
 */
export interface SetupStatus {
  bootstrap_complete: boolean;
  tenant_portal_registered: boolean;
  ldap_ok: boolean;
}

export class SetupStatusApi {
  /**
   * GET /api/admin/setup-status — snapshot of outstanding setup
   * gates. Session-gated server-side (admin/root only).
   *
   * Returns null on any failure (network, 5xx, malformed body) so
   * the calling banner can degrade gracefully — a status check
   * that errors out should never block the page itself from
   * rendering. The error is logged to the console for operator
   * diagnostics but not surfaced as a UI blocker.
   */
  static async get(): Promise<SetupStatus | null> {
    try {
      const r = await fetch('/api/admin/setup-status', {
        method: 'GET',
        credentials: 'same-origin',
        headers: { [CSRF_HEADER]: readCookie(CSRF_COOKIE) },
      });
      if (!r.ok) return null;
      const body: ApiResponse<SetupStatus> = await r.json();
      if (!body.success || !body.data) return null;
      return body.data;
    } catch (e) {
      console.warn('SetupStatusApi.get failed:', e);
      return null;
    }
  }
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
  /**
   * Mark this client as first-party (operator-owned). Any number
   * of clients may carry the flag — flag each operator-owned app
   * you register so the admin UI can distinguish them from
   * third-party developer integrations.
   */
  is_tenant_portal?: boolean;
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
  is_tenant_portal: boolean;
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

/**
 * Response shape for POST /api/clients/<id>/rotate-secret.
 */
export interface RotateSecretResponse {
  client_id: string;
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

  /**
   * GET /api/clients — list every registered client (built-in +
   * tenant). Read-only; refreshes whenever the dashboard remounts
   * the list view or after a delete/rotate succeeds.
   */
  static async list(): Promise<ClientView[]> {
    const r = await fetch('/api/clients', {
      method: 'GET',
      credentials: 'same-origin',
      headers: { [CSRF_HEADER]: readCookie(CSRF_COOKIE) },
    });
    const body: ApiResponse<{ clients: ClientView[] }> = await r.json();
    if (!r.ok || !body.success) {
      const err = new Error(body.error?.message ?? `List failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
    return body.data?.clients ?? [];
  }

  /**
   * DELETE /api/clients/<id> — remove a registered client. Built-ins
   * are server-side-rejected with BUILTIN_IMMUTABLE.
   */
  static async remove(clientID: string): Promise<void> {
    const r = await fetch(`/api/clients/${encodeURIComponent(clientID)}`, {
      method: 'DELETE',
      credentials: 'same-origin',
      headers: { [CSRF_HEADER]: readCookie(CSRF_COOKIE) },
    });
    const body: ApiResponse<{ deleted: boolean }> = await r.json();
    if (!r.ok || !body.success) {
      const err = new Error(body.error?.message ?? `Delete failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
  }

  /**
   * POST /api/clients/<id>/rotate-secret — issue a fresh client_secret.
   * Returns the plaintext exactly once; UI MUST render it in a
   * shown-once panel. Old secret is immediately invalid.
   *
   * Server rejects rotate for built-ins (BUILTIN_IMMUTABLE) and
   * SPA/public clients (PUBLIC_CLIENT_NO_SECRET).
   */
  static async rotateSecret(clientID: string): Promise<RotateSecretResponse> {
    const r = await fetch(`/api/clients/${encodeURIComponent(clientID)}/rotate-secret`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { [CSRF_HEADER]: readCookie(CSRF_COOKIE) },
    });
    const body: ApiResponse<RotateSecretResponse> = await r.json();
    if (!r.ok || !body.success) {
      const err = new Error(body.error?.message ?? `Rotate failed (HTTP ${r.status})`);
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
