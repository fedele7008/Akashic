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

// ─── Phase 8c.6: tenant policy ────────────────────────────────────

export interface TenantPolicy {
  password_min_length: number;
  password_require_uppercase: boolean;
  password_require_number: boolean;
  password_require_special: boolean;
  signup_enabled: boolean;
  uid_change_cooldown_days: number;
  // Phase 9 prep: token-lifetime ceilings. Per-client overrides on
  // ClientView may clamp DOWN within these but never exceed them.
  access_token_ttl_seconds: number;
  refresh_token_sliding_ttl_seconds: number;
  refresh_token_absolute_ttl_seconds: number;
  // Phase A: tenant-wide ceiling on scopes any client may request.
  // Per-client `required_scopes` ∪ `optional_scopes` must be a
  // subset. Special scopes (e.g. `offline_access`) bypass this and
  // require admin approval via the scope-request workflow.
  allowed_client_scopes: string;
  // Phase 9e v2: client-registration qualification.
  //   - require_verified_email default true; UI greys-out the
  //     checkbox when no mailer is configured but keeps the stored
  //     value visible. Eligibility silently bypasses the gate when
  //     no mailer is configured.
  //   - require_approval routes every POST /clients through the
  //     per-attempt approval workflow when on.
  //   - default_max_clients is the tenant-wide cap; per-user offset
  //     on User.client_count_offset adjusts it.
  require_verified_email_for_client_registration: boolean;
  require_approval_for_client_registration: boolean;
  default_max_clients: number;
  updated_at: string;
  updated_by?: string;
}

export interface UpdatePolicyRequest {
  password_min_length?: number;
  password_require_uppercase?: boolean;
  password_require_number?: boolean;
  password_require_special?: boolean;
  signup_enabled?: boolean;
  uid_change_cooldown_days?: number;
  access_token_ttl_seconds?: number;
  refresh_token_sliding_ttl_seconds?: number;
  refresh_token_absolute_ttl_seconds?: number;
  allowed_client_scopes?: string;
  require_verified_email_for_client_registration?: boolean;
  require_approval_for_client_registration?: boolean;
  default_max_clients?: number;
}

export class PolicyApi {
  static async get(): Promise<TenantPolicy> {
    const r = await fetch('/api/policy', {
      method: 'GET',
      credentials: 'same-origin',
      headers: { [CSRF_HEADER]: readCookie(CSRF_COOKIE) },
    });
    const body: ApiResponse<{ policy: TenantPolicy }> = await r.json();
    if (!r.ok || !body.success || !body.data) {
      const err = new Error(body.error?.message ?? `Get failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
    return body.data.policy;
  }

  static async update(req: UpdatePolicyRequest): Promise<TenantPolicy> {
    const r = await fetch('/api/policy', {
      method: 'PATCH',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        [CSRF_HEADER]: readCookie(CSRF_COOKIE),
      },
      body: JSON.stringify(req),
    });
    const body: ApiResponse<{ policy: TenantPolicy }> = await r.json();
    if (!r.ok || !body.success || !body.data) {
      const err = new Error(body.error?.message ?? `Update failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
    return body.data.policy;
  }
}

// ─── Phase 8c.2: user management ──────────────────────────────────

export interface UserView {
  id: string;
  ldap_dn: string;
  /** Joined from LDAP at admin-list/get time. May be empty if the
   *  LDAP entry is missing (deprovisioned mid-flight) — UI falls
   *  back to extracting uid from ldap_dn in that case. */
  email?: string;
  user_type: 'root' | 'admin' | 'user';
  is_disabled: boolean;
  disabled_at?: string;
  disabled_by?: string;
  missing_identity: boolean;
  missing_identity_since?: string;
  email_verified: boolean;
  /** Phase 9e v2: signed offset on tenant default_max_clients.
   *  Effective cap = max(0, policy.default_max_clients + offset). */
  client_count_offset: number;
  last_login_at?: string;
  created_at: string;
  updated_at: string;
}

export interface ListUsersResponse {
  users: UserView[];
  total: number;
}

export interface UpdateUserRequest {
  user_type?: 'root' | 'admin' | 'user';
  is_disabled?: boolean;
  /** Phase 9e v2: signed offset on tenant default_max_clients. */
  client_count_offset?: number;
}

export interface UserListParams {
  limit?: number;
  offset?: number;
  user_type?: 'root' | 'admin' | 'user' | '';
  is_disabled?: boolean;
  missing_identity?: boolean;
}

export class UsersApi {
  /** GET /api/users — list with filters + pagination. */
  static async list(params: UserListParams = {}): Promise<ListUsersResponse> {
    const q = new URLSearchParams();
    if (params.limit !== undefined) q.set('limit', String(params.limit));
    if (params.offset !== undefined) q.set('offset', String(params.offset));
    if (params.user_type) q.set('user_type', params.user_type);
    if (params.is_disabled !== undefined) q.set('is_disabled', String(params.is_disabled));
    if (params.missing_identity !== undefined) q.set('missing_identity', String(params.missing_identity));
    const url = '/api/users' + (q.toString() ? '?' + q.toString() : '');
    const r = await fetch(url, {
      method: 'GET',
      credentials: 'same-origin',
      headers: { [CSRF_HEADER]: readCookie(CSRF_COOKIE) },
    });
    const body: ApiResponse<ListUsersResponse> = await r.json();
    if (!r.ok || !body.success || !body.data) {
      const err = new Error(body.error?.message ?? `List failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
    return body.data;
  }

  /** GET /api/users/<id>. */
  static async get(id: string): Promise<UserView> {
    const r = await fetch(`/api/users/${encodeURIComponent(id)}`, {
      method: 'GET',
      credentials: 'same-origin',
      headers: { [CSRF_HEADER]: readCookie(CSRF_COOKIE) },
    });
    const body: ApiResponse<{ user: UserView }> = await r.json();
    if (!r.ok || !body.success || !body.data) {
      const err = new Error(body.error?.message ?? `Get failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
    return body.data.user;
  }

  /** PATCH /api/users/<id> — update user_type and/or is_disabled. */
  static async patch(id: string, req: UpdateUserRequest): Promise<UserView> {
    const r = await fetch(`/api/users/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        [CSRF_HEADER]: readCookie(CSRF_COOKIE),
      },
      body: JSON.stringify(req),
    });
    const body: ApiResponse<{ user: UserView }> = await r.json();
    if (!r.ok || !body.success || !body.data) {
      const err = new Error(body.error?.message ?? `Update failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
    return body.data.user;
  }

  /** DELETE /api/users/<id> — hard-delete (LDAP + PG). */
  static async remove(id: string): Promise<void> {
    const r = await fetch(`/api/users/${encodeURIComponent(id)}`, {
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
   * POST /api/users/<id>/reset-password — Phase 9d. Issues a
   * temporary password. The control plane decides whether to mail
   * it to the user (when SendGrid is configured) or hand the
   * plaintext back to this caller (for the operator to deliver
   * out-of-band). The plaintext lives only in this response —
   * never persist it client-side.
   */
  static async resetPassword(id: string): Promise<ResetPasswordResult> {
    const r = await fetch(`/api/users/${encodeURIComponent(id)}/reset-password`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        [CSRF_HEADER]: readCookie(CSRF_COOKIE),
      },
      body: JSON.stringify({}),
    });
    const body: ApiResponse<ResetPasswordResult> = await r.json();
    if (!r.ok || !body.success || !body.data) {
      const err = new Error(body.error?.message ?? `Reset password failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
    return body.data;
  }
}

/** Result of POST /api/users/<id>/reset-password. */
export interface ResetPasswordResult {
  /** True when the temp password was emailed; false otherwise. */
  sent: boolean;
  /** Recipient email when known; may be empty. */
  email?: string;
  /**
   * The plaintext temporary password. Present ONLY when sent=false
   * (mailer not configured / no email on LDAP entry / send failed).
   * Render once in a confirmation modal; never store.
   */
  temp_password?: string;
  /**
   * Why the operator is seeing a plaintext fallback. One of:
   *   - "mailer_not_configured"
   *   - "no_email_on_ldap_entry"
   *   - "email_send_failed"
   */
  reason?: string;
}

/**
 * Snapshot of the akashic server's runtime state — Phase 8c.3.
 * Inner subsystem dicts are loose because the control plane composes
 * them from state machines whose schema we don't pin here. The
 * Server page renders them as key/value rows.
 */
export interface SystemStatus {
  control_server: Record<string, unknown>;
  auth_server: Record<string, unknown>;
  uptime: string;
  pid: number;
}

export class ServerApi {
  /**
   * GET /api/admin/server/status — snapshot used by the Server
   * page header. Throws on any failure (the Server page surfaces
   * the error inline so the operator knows the BFF is reachable
   * even when the control plane isn't).
   */
  static async status(): Promise<SystemStatus> {
    const r = await fetch('/api/admin/server/status', {
      method: 'GET',
      credentials: 'same-origin',
      headers: { [CSRF_HEADER]: readCookie(CSRF_COOKIE) },
    });
    const body: ApiResponse<SystemStatus> = await r.json();
    if (!r.ok || !body.success || !body.data) {
      const err = new Error(body.error?.message ?? `Status fetch failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
    return body.data;
  }

  /**
   * Internal helper — POSTs to one of the lifecycle/reload routes.
   * Each public method below names its target explicitly so the
   * caller doesn't pass arbitrary paths through this surface.
   * Rejects with the structured error so the FE can render the
   * upstream message verbatim ("Auth server is already running").
   */
  private static async post(path: string): Promise<void> {
    const r = await fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { [CSRF_HEADER]: readCookie(CSRF_COOKIE) },
    });
    const body: ApiResponse<{ ok: boolean }> = await r.json();
    if (!r.ok || !body.success) {
      const err = new Error(body.error?.message ?? `Request failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
  }

  static authStart()    { return ServerApi.post('/api/admin/server/auth/start'); }
  static authStop()     { return ServerApi.post('/api/admin/server/auth/stop'); }
  static authRestart()  { return ServerApi.post('/api/admin/server/auth/restart'); }
  static apiStart()     { return ServerApi.post('/api/admin/server/api/start'); }
  static apiStop()      { return ServerApi.post('/api/admin/server/api/stop'); }
  static apiRestart()   { return ServerApi.post('/api/admin/server/api/restart'); }
  static quit()         { return ServerApi.post('/api/admin/server/quit'); }
  static configReload() { return ServerApi.post('/api/admin/server/config/reload'); }
  static tlsReload()    { return ServerApi.post('/api/admin/server/tls/reload'); }
}

/**
 * One row in the tools card grid (Phase 8c.5). The `key` field
 * drives the icon lookup on the FE; `label` is the human-readable
 * card title; `url` is the operator-configured target.
 *
 * The BFF only returns rows whose URL is configured, so the FE
 * never has to render an empty/disabled card.
 */
export interface AdminTool {
  key: 'grafana' | 'adminer' | 'redisinsight' | 'vault' | 'phpldapadmin';
  label: string;
  url: string;
}

export class AdminToolsApi {
  /**
   * GET /api/admin/tools — returns the configured external tool
   * URLs (Grafana, Adminer, RedisInsight, Vault, phpLDAPadmin).
   *
   * Returns an empty array on any failure (network, 5xx, malformed
   * body) so the calling page degrades gracefully — operators with
   * a misconfigured BFF still see the rest of the page.
   */
  static async list(): Promise<AdminTool[]> {
    try {
      const r = await fetch('/api/admin/tools', {
        method: 'GET',
        credentials: 'same-origin',
        headers: { [CSRF_HEADER]: readCookie(CSRF_COOKIE) },
      });
      if (!r.ok) return [];
      const body: ApiResponse<{ tools: AdminTool[] }> = await r.json();
      return body.data?.tools ?? [];
    } catch (e) {
      console.warn('AdminToolsApi.list failed:', e);
      return [];
    }
  }
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
 * Request body for PATCH /api/clients/<id> — Phase 8c.4. Pointer
 * fields preserve "leave unchanged" (omitted) vs "set to empty/false".
 * Operator-only fields (role_allowlist, require_pkce,
 * is_tenant_portal) are accepted only via this admin-bff path.
 */
export interface UpdateClientRequest {
  name?: string;
  description?: string;
  homepage_url?: string;
  redirect_uris?: string;
  allowed_scopes?: string;
  // Phase A: split scope fields. Send these instead of (not
  // alongside) allowed_scopes — mixing the legacy and new shapes
  // in one PATCH is rejected with VALIDATION_FAILED.
  required_scopes?: string;
  optional_scopes?: string;
  role_allowlist?: string;
  require_pkce?: boolean;
  is_tenant_portal?: boolean;

  // Per-client TTL overrides + companion clear flags.
  // Send the seconds value to set; send the matching `clear_*: true`
  // boolean to revert to inheriting the tenant ceiling. Set+clear in
  // the same request is rejected at the server.
  access_token_ttl_seconds_override?: number;
  refresh_token_sliding_ttl_seconds_override?: number;
  refresh_token_absolute_ttl_seconds_override?: number;
  clear_access_token_ttl_override?: boolean;
  clear_refresh_token_sliding_ttl_override?: boolean;
  clear_refresh_token_absolute_ttl_override?: boolean;
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
  // Phase A: required vs optional scope split. Either may be
  // empty — when both are empty the control plane defaults to
  // `required_scopes = "openid profile email"`. Special scopes
  // (e.g. `offline_access`) get rejected here with the dedicated
  // SPECIAL_SCOPE_REQUIRES_REQUEST error code.
  required_scopes?: string;
  optional_scopes?: string;
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
  required_scopes: string;
  optional_scopes: string;
  auth_types: string;
  built_in: boolean;
  require_pkce: boolean;
  is_tenant_portal: boolean;

  // Per-client TTL overrides; absent/null means "inherits the
  // tenant ceiling." UI renders nullish as the literal label
  // "<inherited>" so operators see the inheritance explicitly.
  access_token_ttl_seconds_override?: number;
  refresh_token_sliding_ttl_seconds_override?: number;
  refresh_token_absolute_ttl_seconds_override?: number;

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
   * GET /api/clients/<id> — Phase 8c.4. Single-client fetch used
   * by the edit form to hydrate from current server state (rather
   * than relying on possibly-stale data from the list page).
   */
  static async get(clientID: string): Promise<ClientView> {
    const r = await fetch(`/api/clients/${encodeURIComponent(clientID)}`, {
      method: 'GET',
      credentials: 'same-origin',
      headers: { [CSRF_HEADER]: readCookie(CSRF_COOKIE) },
    });
    const body: ApiResponse<{ client: ClientView }> = await r.json();
    if (!r.ok || !body.success || !body.data) {
      const err = new Error(body.error?.message ?? `Get failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
    return body.data.client;
  }

  /**
   * PATCH /api/clients/<id> — Phase 8c.4. Returns the freshly-
   * loaded view so the FE can re-render with server-side
   * normalisations (trimmed strings, bumped updated_at).
   */
  static async update(clientID: string, req: UpdateClientRequest): Promise<ClientView> {
    const r = await fetch(`/api/clients/${encodeURIComponent(clientID)}`, {
      method: 'PATCH',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        [CSRF_HEADER]: readCookie(CSRF_COOKIE),
      },
      body: JSON.stringify(req),
    });
    const body: ApiResponse<{ client: ClientView }> = await r.json();
    if (!r.ok || !body.success || !body.data) {
      const err = new Error(body.error?.message ?? `Update failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
    return body.data.client;
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

// ─── Phase 9: email config (DB-backed) ──────────────────────────

export interface EmailConfig {
  provider: string;
  from_address: string;
  from_name: string;
  // Returned as the masked placeholder (••••••••) when set,
  // empty string when not. Send back unedited to preserve the
  // stored key when patching unrelated fields.
  sendgrid_api_key: string;
  sendgrid_api_key_set: boolean;
  verify_url_base: string;
  updated_at: string;
  updated_by?: string;
  is_configured: boolean;
}

export interface UpdateEmailConfigRequest {
  provider?: string;
  from_address?: string;
  from_name?: string;
  sendgrid_api_key?: string;
  verify_url_base?: string;
}

export interface TestEmailResult {
  sent: boolean;
  to?: string;
  error?: string;
}

export class EmailConfigApi {
  static async get(): Promise<EmailConfig> {
    const r = await fetch('/api/email-config', {
      method: 'GET',
      credentials: 'same-origin',
      headers: { [CSRF_HEADER]: readCookie(CSRF_COOKIE) },
    });
    const body: ApiResponse<{ email_config: EmailConfig }> = await r.json();
    if (!r.ok || !body.success || !body.data) {
      const err = new Error(body.error?.message ?? `Get failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
    return body.data.email_config;
  }

  static async update(req: UpdateEmailConfigRequest): Promise<EmailConfig> {
    const r = await fetch('/api/email-config', {
      method: 'PATCH',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        [CSRF_HEADER]: readCookie(CSRF_COOKIE),
      },
      body: JSON.stringify(req),
    });
    const body: ApiResponse<{ email_config: EmailConfig }> = await r.json();
    if (!r.ok || !body.success || !body.data) {
      const err = new Error(body.error?.message ?? `Update failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
    return body.data.email_config;
  }

  static async test(to: string): Promise<TestEmailResult> {
    const r = await fetch('/api/email-config/test', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        [CSRF_HEADER]: readCookie(CSRF_COOKIE),
      },
      body: JSON.stringify({ to }),
    });
    const body: ApiResponse<TestEmailResult> = await r.json();
    if (!r.ok || !body.success || !body.data) {
      const err = new Error(body.error?.message ?? `Test failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
    return body.data;
  }
}

// ─── Phase B: scope-request workflow ─────────────────────────────

export interface ScopeRequestView {
  id: string;
  client_id: string;
  scope: string;
  reason: string;
  proposed_access_token_ttl_seconds?: number;
  proposed_refresh_token_sliding_ttl_seconds?: number;
  proposed_refresh_token_absolute_ttl_seconds?: number;
  status: 'pending' | 'approved' | 'rejected';
  submitted_by?: string;
  submitted_at: string;
  reviewed_by?: string;
  reviewed_at?: string;
  decision_note?: string;
}

export interface SubmitScopeRequestBody {
  client_id: string;
  scope: string;
  reason: string;
  proposed_access_token_ttl_seconds?: number;
  proposed_refresh_token_sliding_ttl_seconds?: number;
  proposed_refresh_token_absolute_ttl_seconds?: number;
}

export class ScopeRequestsApi {
  static async list(status?: 'pending' | 'approved' | 'rejected'): Promise<ScopeRequestView[]> {
    const q = status ? '?status=' + encodeURIComponent(status) : '';
    const r = await fetch('/api/scope-requests' + q, {
      method: 'GET',
      credentials: 'same-origin',
      headers: { [CSRF_HEADER]: readCookie(CSRF_COOKIE) },
    });
    const body: ApiResponse<{ scope_requests: ScopeRequestView[] }> = await r.json();
    if (!r.ok || !body.success || !body.data) {
      const err = new Error(body.error?.message ?? `List failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
    return body.data.scope_requests;
  }

  static async submit(req: SubmitScopeRequestBody): Promise<ScopeRequestView> {
    const r = await fetch('/api/scope-requests', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        [CSRF_HEADER]: readCookie(CSRF_COOKIE),
      },
      body: JSON.stringify(req),
    });
    const body: ApiResponse<{ scope_request: ScopeRequestView }> = await r.json();
    if (!r.ok || !body.success || !body.data) {
      const err = new Error(body.error?.message ?? `Submit failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
    return body.data.scope_request;
  }

  static async approve(id: string, decisionNote?: string): Promise<ScopeRequestView> {
    return this.review(id, 'approve', decisionNote);
  }
  static async reject(id: string, decisionNote?: string): Promise<ScopeRequestView> {
    return this.review(id, 'reject', decisionNote);
  }

  private static async review(
    id: string,
    action: 'approve' | 'reject',
    decisionNote?: string,
  ): Promise<ScopeRequestView> {
    const r = await fetch(`/api/scope-requests/${encodeURIComponent(id)}/${action}`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        [CSRF_HEADER]: readCookie(CSRF_COOKIE),
      },
      body: JSON.stringify({ decision_note: decisionNote ?? '' }),
    });
    const body: ApiResponse<{ scope_request: ScopeRequestView }> = await r.json();
    if (!r.ok || !body.success || !body.data) {
      const err = new Error(body.error?.message ?? `${action} failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
    return body.data.scope_request;
  }
}

// ─── Phase 9e v2: client-registration request workflow ─────────

export interface ClientRegistrationRequestView {
  id: string;
  user_id: string;
  /** LDAP-joined fields, may be empty when LDAP is unreachable. */
  requester_email?: string;
  requester_display_name?: string;
  reason: string;
  /** Proposed client params; mirrors the create-client form. */
  name: string;
  description?: string;
  homepage_url?: string;
  client_type: 'WEB' | 'SPA';
  redirect_uris: string;
  required_scopes?: string;
  optional_scopes?: string;
  require_pkce: boolean;
  status: 'pending' | 'approved' | 'rejected';
  submitted_at: string;
  reviewed_by?: string;
  reviewed_at?: string;
  decision_note?: string;
  /** Set on approve only — the materialized client_services row. */
  created_client_id?: string;
}

export class ClientRegistrationRequestsApi {
  static async list(status?: 'pending' | 'approved' | 'rejected'): Promise<ClientRegistrationRequestView[]> {
    const q = status ? '?status=' + encodeURIComponent(status) : '';
    const r = await fetch('/api/client-registration-requests' + q, {
      method: 'GET',
      credentials: 'same-origin',
      headers: { [CSRF_HEADER]: readCookie(CSRF_COOKIE) },
    });
    const body: ApiResponse<{ client_registration_requests: ClientRegistrationRequestView[] }> = await r.json();
    if (!r.ok || !body.success || !body.data) {
      const err = new Error(body.error?.message ?? `List failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
    return body.data.client_registration_requests;
  }

  /** Approve a pending request "as proposed" — the request's stored
   *  client params become a new `client_services` row owned by the
   *  requester. v2: no field editing on review; reject + ask user
   *  to resubmit if changes are needed. */
  static async approve(
    id: string,
    decisionNote?: string,
  ): Promise<ClientRegistrationRequestView> {
    const r = await fetch(`/api/client-registration-requests/${encodeURIComponent(id)}/approve`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        [CSRF_HEADER]: readCookie(CSRF_COOKIE),
      },
      body: JSON.stringify({ decision_note: decisionNote ?? '' }),
    });
    const body: ApiResponse<{ client_registration_request: ClientRegistrationRequestView }> = await r.json();
    if (!r.ok || !body.success || !body.data) {
      const err = new Error(body.error?.message ?? `Approve failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
    return body.data.client_registration_request;
  }

  static async reject(id: string, decisionNote?: string): Promise<ClientRegistrationRequestView> {
    const r = await fetch(`/api/client-registration-requests/${encodeURIComponent(id)}/reject`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        [CSRF_HEADER]: readCookie(CSRF_COOKIE),
      },
      body: JSON.stringify({ decision_note: decisionNote ?? '' }),
    });
    const body: ApiResponse<{ client_registration_request: ClientRegistrationRequestView }> = await r.json();
    if (!r.ok || !body.success || !body.data) {
      const err = new Error(body.error?.message ?? `Reject failed (HTTP ${r.status})`);
      (err as Error & { apiError?: ApiError }).apiError = body.error;
      throw err;
    }
    return body.data.client_registration_request;
  }
}
