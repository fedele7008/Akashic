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
