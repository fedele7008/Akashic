/**
 * <akashic-clients> — tenant developer surface for OAuth client
 * management. Mounted in tenant portal pages by users who want to
 * register and manage their own OAuth integrations.
 *
 * Distinct from the admin-web's client-management UI:
 *   - admin-web: operator-side (mTLS), sees ALL clients, can edit
 *     built-ins via env. Lives in the akashic-bff React app.
 *   - this widget: tenant-developer-side (bearer), sees only their
 *     own (`/clients/mine`), bound by owner_user_id + admin/root
 *     override. Renders inside any tenant portal that mounts it.
 *
 * Shared `client_services` table; different scopes at the API level.
 *
 * Public API (DOM events bubble to embedding page):
 *   akashic-needs-signin       — no live session; embedder should
 *                                redirect to /sign-in flow
 *   akashic-client-created     — fired after a successful registration
 *   akashic-client-deleted     — fired after a successful delete
 *
 * Styling: open shadow DOM with `::part(...)` hooks. Tenants supply
 * their own CSS targeting parts; the optional default stylesheet
 * (akashic-default.css) provides a baseline look.
 */

import { LitElement, css, html } from "lit";
import { customElement, state } from "lit/decorators.js";

import { apiCall, apiCallPublic, type ApiResult } from "../lib/api";
import { dispatchNeedsSignin, renderNeedsSignin } from "../lib/needs-signin";

interface ClientView {
  client_id: string;
  name: string;
  description?: string;
  homepage_url?: string;
  client_type: "WEB" | "SPA";
  public: boolean;
  redirect_uris: string;
  allowed_scopes: string;
  required_scopes: string;
  optional_scopes: string;
  auth_types: string;
  built_in: boolean;
  require_pkce: boolean;
  is_tenant_portal: boolean;
  created_at: string;
  updated_at: string;
}

interface AllowedClientScopes {
  allowed_client_scopes: string;
  special_scopes: string[];
}

interface ScopeRequestView {
  id: string;
  client_id: string;
  scope: string;
  reason: string;
  proposed_access_token_ttl_seconds?: number;
  proposed_refresh_token_sliding_ttl_seconds?: number;
  proposed_refresh_token_absolute_ttl_seconds?: number;
  status: "pending" | "approved" | "rejected";
  submitted_at: string;
  reviewed_at?: string;
  decision_note?: string;
}

type ScopeMode = "disabled" | "required" | "optional";

interface CreatedClient {
  client: ClientView;
  client_secret: string;
}

interface RotateSecretResult {
  client_id: string;
  client_secret: string;
}

/** Internal view-state machine. Same pattern admin-web's Dashboard
 *  uses; discriminated union beats parallel booleans. */
type View =
  | { kind: "loading" }
  | { kind: "needs-signin" }
  | { kind: "error"; message: string }
  | { kind: "list" }
  | { kind: "create" }
  | { kind: "created"; result: CreatedClient }
  | { kind: "rotate-confirm"; target: ClientView }
  | { kind: "rotated"; client: ClientView; result: RotateSecretResult }
  // Phase B portal-side: per-client scope management — required/optional
  // matrix + special-scope request submission + history.
  | { kind: "scopes"; client: ClientView };

@customElement("akashic-clients")
export class AkashicClients extends LitElement {
  @state() private view: View = { kind: "loading" };
  @state() private clients: ClientView[] = [];

  // Per-row delete confirmation: maps client_id → operator-typed
  // confirmation. Storing here (rather than per-row state) lets the
  // list re-render without losing in-progress confirmations.
  @state() private deleteTyped: Record<string, string> = {};
  @state() private busyDelete: string | null = null;

  // Form state for the create view. Held on the host rather than as
  // form-element values so we can prefill on retry / show server
  // errors next to fields without losing the typed values.
  @state() private form = {
    name: "",
    clientType: "WEB" as "WEB" | "SPA",
    redirectURI: "",
    description: "",
    requirePKCE: true,
    // Phase B: scope tristate map. openid is always required at
    // start (OIDC mandatory); other scopes default to optional so
    // the developer opts them in explicitly.
    scopeModes: {} as Record<string, ScopeMode>,
  };
  @state() private formError: string | null = null;
  @state() private fieldErrors: Record<string, string> = {};
  @state() private submitting = false;

  // Phase B: tenant scope policy. Fetched once on mount via the
  // public /allowed-client-scopes endpoint; used by the create form
  // and the per-client scopes view to render the matrix.
  @state() private allowedScopes: AllowedClientScopes | null = null;

  // Per-client scope-management state (the `scopes` view).
  @state() private scopesForm = {
    modes: {} as Record<string, ScopeMode>,
  };
  @state() private scopesSaving = false;
  @state() private scopesError: string | null = null;
  @state() private scopeRequests: ScopeRequestView[] = [];
  @state() private requestForm = {
    showing: false,
    reason: "",
    accessTTL: "",
    refreshSlidingTTL: "",
    refreshAbsoluteTTL: "",
    submitting: false,
    error: null as string | null,
  };

  // Rotate-flow state.
  @state() private rotating = false;
  @state() private rotateError: string | null = null;
  @state() private secretCopied = false;

  static override styles = css`
    :host {
      display: block;
      color: var(--akashic-text, inherit);
      font-family: var(--akashic-font-family, inherit);
    }

    /* ─── Shared bits ─── */
    [part="header"] {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 1rem;
      flex-wrap: wrap;
      margin-bottom: 1rem;
    }
    [part="header-text"] h2 {
      margin: 0;
      font-size: 1.125rem;
      font-weight: 600;
    }
    [part="header-sub"] {
      margin: 0.25rem 0 0 0;
      font-size: 0.875rem;
      color: var(--akashic-text-muted, currentColor);
      opacity: 0.7;
    }

    button,
    [part^="button"] {
      font: inherit;
      cursor: pointer;
      padding: 0.5rem 0.875rem;
      border-radius: var(--akashic-input-radius, 0.375rem);
      border: 1px solid currentColor;
      background: transparent;
      color: inherit;
    }
    [part="button-primary"] {
      background: var(--akashic-button-bg, #4f8cff);
      color: var(--akashic-button-fg, white);
      border-color: transparent;
    }
    [part="button-primary"][disabled],
    button[disabled] {
      opacity: 0.6;
      cursor: not-allowed;
    }
    [part="button-danger"] {
      color: var(--akashic-error, #dc2626);
      border-color: var(--akashic-error, #dc2626);
    }
    [part="button-danger-confirm"] {
      background: var(--akashic-error, #dc2626);
      color: white;
      border-color: transparent;
    }

    [part="error"] {
      color: var(--akashic-error, #dc2626);
      font-size: 0.875rem;
      padding: 0.5rem 0.75rem;
      border-radius: var(--akashic-input-radius, 0.375rem);
      border: 1px solid var(--akashic-error, #dc2626);
      background: var(--akashic-error-bg, transparent);
      margin: 0;
    }

    /* ─── List view ─── */
    [part="table"] {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.875rem;
    }
    [part="table"] th,
    [part="table"] td {
      text-align: left;
      padding: 0.625rem 0.5rem;
      vertical-align: top;
    }
    [part="table"] th {
      font-weight: 500;
      font-size: 0.8125rem;
      color: var(--akashic-text-muted, currentColor);
      opacity: 0.7;
      border-bottom: 1px solid var(--akashic-border, currentColor);
    }
    [part="table"] tbody tr {
      border-bottom: 1px solid var(--akashic-border-subtle, transparent);
    }
    [part="badge-builtin"] {
      display: inline-block;
      margin-left: 0.5rem;
      padding: 0.125rem 0.375rem;
      font-size: 0.6875rem;
      border-radius: 0.25rem;
      background: var(--akashic-accent-soft, rgba(79, 140, 255, 0.15));
      color: var(--akashic-accent, #4f8cff);
    }
    [part="badge-primary"] {
      display: inline-block;
      margin-left: 0.5rem;
      padding: 0.125rem 0.375rem;
      font-size: 0.6875rem;
      font-weight: 500;
      border-radius: 0.25rem;
      background: var(--akashic-success-soft, rgba(22, 163, 74, 0.18));
      color: var(--akashic-success, #16a34a);
    }
    [part="row-actions"] {
      text-align: right;
      white-space: nowrap;
    }
    [part="row-actions"] button {
      margin-left: 0.5rem;
      font-size: 0.8125rem;
      padding: 0.25rem 0.625rem;
    }
    [part="empty"] {
      padding: 2rem 1rem;
      text-align: center;
      color: var(--akashic-text-muted, currentColor);
      opacity: 0.7;
      font-size: 0.875rem;
    }

    /* ─── Inline delete confirm ─── */
    [part="delete-confirm"] {
      display: inline-flex;
      align-items: center;
      gap: 0.375rem;
    }
    [part="delete-confirm"] input {
      font: inherit;
      font-family: ui-monospace, monospace;
      font-size: 0.75rem;
      padding: 0.25rem 0.5rem;
      width: 14rem;
      border-radius: 0.25rem;
      border: 1px solid currentColor;
      background: transparent;
      color: inherit;
    }

    /* ─── Form (create / rotate) ─── */
    [part="form"] {
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }
    [part="field"] {
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
    }
    [part="field-label"] {
      font-size: 0.875rem;
      font-weight: 500;
    }
    [part="field-input"] {
      font: inherit;
      color: inherit;
      padding: 0.5rem 0.75rem;
      border-radius: var(--akashic-input-radius, 0.375rem);
      border: var(--akashic-input-border, 1px solid currentColor);
      background: var(--akashic-input-bg, transparent);
    }
    [part="field-input"][aria-invalid="true"] {
      border-color: var(--akashic-error, #dc2626);
    }
    [part="field-error"] {
      color: var(--akashic-error, #dc2626);
      font-size: 0.75rem;
    }
    [part="field-hint"] {
      color: var(--akashic-text-muted, currentColor);
      opacity: 0.7;
      font-size: 0.75rem;
    }
    [part="radio-group"] {
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      padding: 0.75rem;
      border: 1px solid var(--akashic-border, currentColor);
      border-radius: var(--akashic-input-radius, 0.375rem);
    }
    [part="radio-row"] {
      display: flex;
      flex-direction: row;
      align-items: flex-start;
      gap: 0.5rem;
    }
    [part="radio-row"] input {
      margin-top: 0.25rem;
    }

    /* ─── Secret-shown-once panel ─── */
    [part="secret-panel"] {
      margin-top: 1rem;
      padding: 1rem;
      border: 2px solid var(--akashic-warning, #f59e0b);
      border-radius: var(--akashic-input-radius, 0.375rem);
      background: var(--akashic-warning-bg, rgba(245, 158, 11, 0.08));
    }
    [part="secret-panel"] strong {
      display: block;
      font-weight: 600;
      margin-bottom: 0.25rem;
    }
    [part="secret-panel"] p {
      margin: 0 0 0.5rem 0;
      font-size: 0.875rem;
    }
    [part="secret-value"] {
      display: block;
      padding: 0.5rem;
      background: rgba(0, 0, 0, 0.3);
      border-radius: 0.25rem;
      word-break: break-all;
      font-family: ui-monospace, monospace;
      font-size: 0.875rem;
    }

    [part="actions"] {
      display: flex;
      gap: 0.5rem;
      margin-top: 1rem;
    }

    [part="kv"] {
      display: grid;
      grid-template-columns: max-content 1fr;
      column-gap: 1rem;
      row-gap: 0.375rem;
      margin: 1rem 0;
      font-size: 0.875rem;
    }
    [part="kv"] dt {
      color: var(--akashic-text-muted, currentColor);
      opacity: 0.7;
    }
    [part="kv"] dd {
      margin: 0;
      word-break: break-all;
    }
  `;

  override connectedCallback(): void {
    super.connectedCallback();
    void this.loadClients();
    void this.loadAllowedScopes();
  }

  // Fetch the tenant-allowed scope policy. Public endpoint — no
  // bearer needed. Failure is non-fatal: the create form falls
  // back to "openid profile email" so a brief network blip
  // doesn't block registration.
  private async loadAllowedScopes() {
    const res = await apiCallPublic<AllowedClientScopes>("/allowed-client-scopes");
    if (res.ok) {
      this.allowedScopes = res.data;
    }
  }

  // ─── data ────────────────────────────────────────────────────────

  private async loadClients() {
    this.view = { kind: "loading" };
    const res = await apiCall<{ clients: ClientView[] }>("/clients/mine");
    if (!res.ok) {
      if (res.code === "NO_SESSION") {
        this.view = { kind: "needs-signin" };
        dispatchNeedsSignin(this);
        return;
      }
      this.view = { kind: "error", message: res.message };
      return;
    }
    this.clients = res.data.clients;
    this.view = { kind: "list" };
  }

  // ─── render dispatch ─────────────────────────────────────────────

  override render() {
    switch (this.view.kind) {
      case "loading":
        return html`<p part="loading">Loading clients…</p>`;
      case "needs-signin":
        return renderNeedsSignin();
      case "error":
        return html`
          <p part="error" role="alert">${this.view.message}</p>
          <button part="button-primary" @click=${() => void this.loadClients()}>
            Retry
          </button>
        `;
      case "list":
        return this.renderList();
      case "create":
        return this.renderCreate();
      case "created":
        return this.renderCreated(this.view.result);
      case "rotate-confirm":
        return this.renderRotateConfirm(this.view.target);
      case "rotated":
        return this.renderRotated(this.view.client, this.view.result);
      case "scopes":
        return this.renderScopes(this.view.client);
    }
  }

  // ─── list view ───────────────────────────────────────────────────

  private renderList() {
    return html`
      <div part="header">
        <div part="header-text">
          <h2 part="header-title">Your OAuth clients</h2>
          <p part="header-sub">
            Register integrations and manage their credentials.
          </p>
        </div>
        <button
          part="button-primary"
          @click=${() => this.startCreate()}
        >
          Register a new client
        </button>
      </div>

      ${this.clients.length === 0
        ? html`
            <div part="empty">
              No clients yet. Click "Register a new client" to add your first
              OAuth integration.
            </div>
          `
        : html`
            <table part="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Client ID</th>
                  <th>Type</th>
                  <th>Redirect URIs</th>
                  <th part="row-actions">Actions</th>
                </tr>
              </thead>
              <tbody>
                ${this.clients.map((c) => this.renderRow(c))}
              </tbody>
            </table>
          `}
    `;
  }

  private renderRow(c: ClientView) {
    const deleting = this.deleteTyped[c.client_id] !== undefined;
    return html`
      <tr part="row" data-client-id=${c.client_id}>
        <td part="cell">
          ${c.name}${c.built_in
            ? html`<span part="badge-builtin">built-in</span>`
            : ""}${c.is_tenant_portal
            ? html`<span part="badge-primary">first-party</span>`
            : ""}
        </td>
        <td part="cell"><code>${c.client_id}</code></td>
        <td part="cell">${c.client_type}</td>
        <td part="cell">
          <code part="redirect-uris">${c.redirect_uris}</code>
        </td>
        <td part="row-actions">
          ${c.built_in
            ? html`<span part="row-managed">managed by server</span>`
            : deleting
              ? this.renderDeleteConfirm(c)
              : html`
                  <button
                    @click=${() => this.startScopes(c)}
                  >Scopes</button>
                  ${!c.public
                    ? html`<button
                        @click=${() => this.startRotate(c)}
                      >Rotate</button>`
                    : ""}
                  <button
                    part="button-danger"
                    @click=${() => this.beginDelete(c.client_id)}
                  >Delete</button>
                `}
        </td>
      </tr>
    `;
  }

  private renderDeleteConfirm(c: ClientView) {
    const typed = this.deleteTyped[c.client_id] ?? "";
    const matches = typed === c.client_id;
    const busy = this.busyDelete === c.client_id;
    return html`
      <div part="delete-confirm">
        <input
          type="text"
          autofocus
          placeholder="type ${c.client_id}"
          .value=${typed}
          @input=${(e: Event) =>
            this.setDeleteTyped(c.client_id, (e.target as HTMLInputElement).value)}
          ?disabled=${busy}
        />
        <button
          part=${matches ? "button-danger-confirm" : "button-danger"}
          ?disabled=${!matches || busy}
          @click=${() => void this.confirmDelete(c.client_id)}
        >${busy ? "…" : "Confirm"}</button>
        <button
          @click=${() => this.cancelDelete(c.client_id)}
          ?disabled=${busy}
        >Cancel</button>
      </div>
    `;
  }

  private beginDelete(id: string) {
    this.deleteTyped = { ...this.deleteTyped, [id]: "" };
  }
  private cancelDelete(id: string) {
    const next = { ...this.deleteTyped };
    delete next[id];
    this.deleteTyped = next;
  }
  private setDeleteTyped(id: string, value: string) {
    this.deleteTyped = { ...this.deleteTyped, [id]: value };
  }

  private async confirmDelete(id: string) {
    if (this.deleteTyped[id] !== id) return;
    this.busyDelete = id;
    const res = await apiCall<unknown>(`/clients/${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
    this.busyDelete = null;
    if (!res.ok) {
      if (res.code === "NO_SESSION") {
        this.view = { kind: "needs-signin" };
        dispatchNeedsSignin(this);
        return;
      }
      this.view = { kind: "error", message: res.message };
      return;
    }
    this.cancelDelete(id);
    this.dispatchEvent(
      new CustomEvent("akashic-client-deleted", {
        detail: { client_id: id },
        bubbles: true,
        composed: true,
      }),
    );
    await this.loadClients();
  }

  // ─── create view ─────────────────────────────────────────────────

  private startCreate() {
    // Seed scope modes: openid required (OIDC mandatory), email +
    // profile optional. Other tenant-allowed scopes default to
    // "disabled" so the developer opts them in explicitly. Special
    // scopes (e.g. offline_access) are NOT in the matrix — they
    // require the post-creation scope-request workflow.
    const seed: Record<string, ScopeMode> = {};
    const allowed = this.allowedScopes?.allowed_client_scopes ?? "openid profile email";
    const specials = new Set(this.allowedScopes?.special_scopes ?? ["offline_access"]);
    for (const tok of allowed.split(/\s+/).filter(Boolean)) {
      if (specials.has(tok)) continue;
      if (tok === "openid") seed[tok] = "required";
      else if (tok === "email" || tok === "profile") seed[tok] = "optional";
      else seed[tok] = "disabled";
    }
    this.form = {
      name: "",
      clientType: "WEB",
      redirectURI: "",
      description: "",
      requirePKCE: true,
      scopeModes: seed,
    };
    this.formError = null;
    this.fieldErrors = {};
    this.submitting = false;
    this.view = { kind: "create" };
  }

  private renderCreate() {
    const f = this.form;
    return html`
      <div part="header">
        <div part="header-text">
          <h2 part="header-title">Register a new client</h2>
          <p part="header-sub">
            Choose <strong>WEB</strong> if your app has a backend that
            holds a client_secret. Choose <strong>SPA</strong> if it's
            browser-only.
          </p>
        </div>
      </div>

      <form part="form" @submit=${this.onCreateSubmit} novalidate>
        ${this.formError
          ? html`<p part="error" role="alert">${this.formError}</p>`
          : ""}

        <label part="field">
          <span part="field-label">Name</span>
          <input
            part="field-input"
            type="text"
            name="name"
            required
            .value=${f.name}
            @input=${(e: Event) =>
              (this.form = { ...f, name: (e.target as HTMLInputElement).value })}
            aria-invalid=${this.fieldErrors.name ? "true" : "false"}
          />
          ${this.fieldErrors.name
            ? html`<span part="field-error">${this.fieldErrors.name}</span>`
            : ""}
        </label>

        <fieldset part="radio-group">
          <legend part="field-label">Client type</legend>
          <label part="radio-row">
            <input
              type="radio"
              name="client_type"
              value="WEB"
              .checked=${f.clientType === "WEB"}
              @change=${() => (this.form = { ...f, clientType: "WEB" })}
            />
            <span>
              <strong>WEB</strong> — server-side / BFF. App has a backend
              that stores the client_secret. PKCE optional.
            </span>
          </label>
          <label part="radio-row">
            <input
              type="radio"
              name="client_type"
              value="SPA"
              .checked=${f.clientType === "SPA"}
              @change=${() => (this.form = { ...f, clientType: "SPA" })}
            />
            <span>
              <strong>SPA</strong> — browser-only or native. No secret
              storage; PKCE required.
            </span>
          </label>
        </fieldset>

        <label part="field">
          <span part="field-label">Redirect URI</span>
          <input
            part="field-input"
            type="url"
            name="redirect_uri"
            placeholder="https://acme.com/api/auth/callback"
            required
            .value=${f.redirectURI}
            @input=${(e: Event) =>
              (this.form = { ...f, redirectURI: (e.target as HTMLInputElement).value })}
            aria-invalid=${this.fieldErrors.redirect_uris ? "true" : "false"}
          />
          ${this.fieldErrors.redirect_uris
            ? html`<span part="field-error">${this.fieldErrors.redirect_uris}</span>`
            : html`<span part="field-hint">
                Comma-separate multiple URIs. Must match exactly what your
                app sends to /authorize.
              </span>`}
        </label>

        <label part="field">
          <span part="field-label">Description (optional)</span>
          <input
            part="field-input"
            type="text"
            name="description"
            .value=${f.description}
            @input=${(e: Event) =>
              (this.form = { ...f, description: (e.target as HTMLInputElement).value })}
          />
        </label>

        ${f.clientType === "WEB"
          ? html`
              <label part="radio-row">
                <input
                  type="checkbox"
                  .checked=${f.requirePKCE}
                  @change=${(e: Event) =>
                    (this.form = {
                      ...f,
                      requirePKCE: (e.target as HTMLInputElement).checked,
                    })}
                />
                <span>
                  Require PKCE (recommended).
                  <span part="field-hint">
                    Layered defense even with a client_secret.
                  </span>
                </span>
              </label>
            `
          : ""}

        <fieldset part="radio-group">
          <legend part="field-label">Scopes</legend>
          <p part="field-hint" style="margin-top: 0;">
            Per scope, pick how this client uses it. <strong>Required</strong>
            (always requested; consent locks it on) ·
            <strong>Optional</strong> (consent shows a user-toggleable
            checkbox) · <strong>Disabled</strong> (this client doesn't
            request it). Special scopes like
            <code>offline_access</code> need admin approval — request
            them after registering.
          </p>
          ${this.renderScopeMatrix(f.scopeModes, (next) =>
            (this.form = { ...f, scopeModes: next }))}
        </fieldset>

        <div part="actions">
          <button
            type="submit"
            part="button-primary"
            ?disabled=${this.submitting}
          >${this.submitting ? "Registering…" : "Register client"}</button>
          <button
            type="button"
            @click=${() => (this.view = { kind: "list" })}
            ?disabled=${this.submitting}
          >Cancel</button>
        </div>
      </form>
    `;
  }

  private async onCreateSubmit(e: SubmitEvent) {
    e.preventDefault();
    if (this.submitting) return;
    this.submitting = true;
    this.formError = null;
    this.fieldErrors = {};

    const payload: Record<string, unknown> = {
      name: this.form.name.trim(),
      client_type: this.form.clientType,
      redirect_uris: this.form.redirectURI.trim(),
    };
    if (this.form.description.trim()) {
      payload.description = this.form.description.trim();
    }
    // SPA always-true PKCE is enforced server-side; we only send the
    // override when WEB + operator opted out.
    if (this.form.clientType === "WEB" && !this.form.requirePKCE) {
      payload.require_pkce = false;
    }
    // Phase B: pack the scope tristate map into the split fields.
    // Empty "" is a valid value; the server's create defaults only
    // kick in when BOTH split fields are empty AND legacy
    // `allowed_scopes` is absent — which we never send here.
    const required = Object.entries(this.form.scopeModes)
      .filter(([, m]) => m === "required")
      .map(([s]) => s)
      .sort()
      .join(" ");
    const optional = Object.entries(this.form.scopeModes)
      .filter(([, m]) => m === "optional")
      .map(([s]) => s)
      .sort()
      .join(" ");
    payload.required_scopes = required;
    payload.optional_scopes = optional;

    const res = await apiCall<CreatedClient>("/clients", {
      method: "POST",
      json: payload,
    });
    this.submitting = false;

    if (!res.ok) {
      this.handleCreateError(res);
      return;
    }
    this.dispatchEvent(
      new CustomEvent("akashic-client-created", {
        detail: { client_id: res.data.client.client_id },
        bubbles: true,
        composed: true,
      }),
    );
    this.view = { kind: "created", result: res.data };
    // Refresh the list in the background so it's ready when the
    // operator clicks Done after copying the secret.
    void this.refreshListSilent();
  }

  private handleCreateError(res: Extract<ApiResult<unknown>, { ok: false }>) {
    if (res.code === "NO_SESSION") {
      this.view = { kind: "needs-signin" };
      dispatchNeedsSignin(this);
      return;
    }
    if (res.code === "VALIDATION_FAILED") {
      // The api server returns one VALIDATION_FAILED per missing
      // field but doesn't structure them — surface the server's
      // message inline and try to attribute it to a field.
      const msg = res.message;
      if (/redirect_uris?/i.test(msg)) this.fieldErrors = { redirect_uris: msg };
      else if (/name/i.test(msg)) this.fieldErrors = { name: msg };
      else this.formError = msg;
      return;
    }
    this.formError = res.message;
  }

  private async refreshListSilent() {
    const res = await apiCall<{ clients: ClientView[] }>("/clients/mine");
    if (res.ok) this.clients = res.data.clients;
  }

  // ─── scope matrix (shared by create + scopes view) ──────────────

  /**
   * Render the per-scope tristate selector. Used by both the create
   * form and the post-creation `scopes` view. The list of scopes
   * comes from the tenant policy's `allowed_client_scopes`, minus
   * any special scopes (those go through the request workflow).
   */
  private renderScopeMatrix(
    modes: Record<string, ScopeMode>,
    onChange: (next: Record<string, ScopeMode>) => void,
  ) {
    const allowed = this.allowedScopes?.allowed_client_scopes ?? "";
    const specials = new Set(this.allowedScopes?.special_scopes ?? []);
    const tokens = allowed
      .split(/\s+/)
      .filter(Boolean)
      .filter((t) => !specials.has(t))
      .sort();

    if (tokens.length === 0) {
      return html`<p part="field-hint">
        Tenant policy doesn't allow any non-special scopes yet —
        contact the operator.
      </p>`;
    }

    const setMode = (scope: string, mode: ScopeMode) => {
      onChange({ ...modes, [scope]: mode });
    };

    return html`
      <div part="scope-matrix">
        ${tokens.map((scope) => {
          const mode = modes[scope] ?? "disabled";
          const isOpenID = scope === "openid";
          // openid is OIDC-mandatory: the consent screen + auth-server
          // both require it. Lock it on Required so a developer can't
          // accidentally disable it. Server would reject the disabled
          // form anyway with `invalid_scope` at /authorize, but
          // disabling the radio is sharper UX.
          return html`
            <div part="scope-row" data-scope=${scope}>
              <code part="scope-name">${scope}</code>
              ${(["disabled", "required", "optional"] as ScopeMode[]).map(
                (opt) => html`
                  <label part="scope-mode">
                    <input
                      type="radio"
                      name="scope-${scope}"
                      value=${opt}
                      .checked=${mode === opt}
                      ?disabled=${isOpenID && opt !== "required"}
                      @change=${() => setMode(scope, opt)}
                    />
                    <span>${opt}</span>
                  </label>
                `,
              )}
            </div>
          `;
        })}
      </div>
    `;
  }

  // ─── scopes view (per-client) ────────────────────────────────────

  private async startScopes(client: ClientView) {
    // Seed modes from the row's stored required+optional. Legacy
    // rows fall back to allowed_scopes as required.
    const seed: Record<string, ScopeMode> = {};
    const required = client.required_scopes || client.allowed_scopes;
    for (const tok of required.split(/\s+/).filter(Boolean)) {
      seed[tok] = "required";
    }
    for (const tok of (client.optional_scopes ?? "").split(/\s+/).filter(Boolean)) {
      seed[tok] = "optional";
    }
    this.scopesForm = { modes: seed };
    this.scopesError = null;
    this.scopesSaving = false;
    this.scopeRequests = [];
    this.requestForm = {
      showing: false,
      reason: "",
      accessTTL: "",
      refreshSlidingTTL: "",
      refreshAbsoluteTTL: "",
      submitting: false,
      error: null,
    };
    this.view = { kind: "scopes", client };
    void this.loadScopeRequests(client.client_id);
  }

  private async loadScopeRequests(clientID: string) {
    const res = await apiCall<{ scope_requests: ScopeRequestView[] }>(
      `/clients/${encodeURIComponent(clientID)}/scope-requests`,
    );
    if (res.ok) {
      this.scopeRequests = res.data.scope_requests;
    }
  }

  private renderScopes(client: ClientView) {
    const f = this.scopesForm;
    const reqForm = this.requestForm;
    const specials = this.allowedScopes?.special_scopes ?? ["offline_access"];
    const hasPendingSpecial = this.scopeRequests.some(
      (r) => r.status === "pending" && specials.includes(r.scope),
    );

    return html`
      <div part="header">
        <div part="header-text">
          <h2 part="header-title">Scopes for ${client.name}</h2>
          <p part="header-sub">
            <code>${client.client_id}</code> · choose required vs.
            optional, or request a special scope.
          </p>
        </div>
      </div>

      ${this.scopesError
        ? html`<p part="error" role="alert">${this.scopesError}</p>`
        : ""}

      <fieldset part="radio-group">
        <legend part="field-label">Standard scopes</legend>
        ${this.renderScopeMatrix(f.modes, (next) =>
          (this.scopesForm = { modes: next }))}
        <div part="actions">
          <button
            part="button-primary"
            ?disabled=${this.scopesSaving}
            @click=${() => void this.saveScopes(client)}
          >
            ${this.scopesSaving ? "Saving…" : "Save scopes"}
          </button>
          <button
            type="button"
            ?disabled=${this.scopesSaving}
            @click=${() => (this.view = { kind: "list" })}
          >Back</button>
        </div>
      </fieldset>

      <fieldset part="radio-group" style="margin-top: 1.5rem;">
        <legend part="field-label">Special-scope requests</legend>
        <p part="field-hint">
          Special scopes need admin approval. Submit a request with
          your reason and (optionally) proposed token-lifetime
          policy. Once approved, the scope unlocks above.
        </p>

        ${this.scopeRequests.length === 0
          ? html`<p part="field-hint">
              No requests submitted for this client yet.
            </p>`
          : html`
              <ul part="scope-request-list">
                ${this.scopeRequests.map(
                  (r) => html`
                    <li part="scope-request-row" data-status=${r.status}>
                      <code>${r.scope}</code> · <strong>${r.status}</strong>
                      <span part="field-hint">
                        submitted ${new Date(r.submitted_at).toLocaleString()}
                      </span>
                      ${r.decision_note
                        ? html`<div part="field-hint">
                            Note: ${r.decision_note}
                          </div>`
                        : ""}
                    </li>
                  `,
                )}
              </ul>
            `}

        ${reqForm.showing
          ? this.renderScopeRequestForm(client)
          : hasPendingSpecial
            ? html`<p part="field-hint">
                A pending special-scope request exists. Wait for
                operator review before submitting another.
              </p>`
            : html`<button
                @click=${() =>
                  (this.requestForm = { ...reqForm, showing: true })}
              >Request offline_access</button>`}
      </fieldset>
    `;
  }

  private renderScopeRequestForm(client: ClientView) {
    const f = this.requestForm;
    const update = (patch: Partial<typeof this.requestForm>) =>
      (this.requestForm = { ...f, ...patch });
    return html`
      <div part="scope-request-form">
        <label part="field">
          <span part="field-label">Reason (required)</span>
          <textarea
            part="field-input"
            rows="3"
            .value=${f.reason}
            @input=${(e: Event) =>
              update({ reason: (e.target as HTMLTextAreaElement).value })}
            placeholder="e.g. background sync of documents while user is offline"
          ></textarea>
        </label>
        <label part="field">
          <span part="field-label">Proposed access-token TTL (optional)</span>
          <input
            part="field-input"
            type="text"
            .value=${f.accessTTL}
            @input=${(e: Event) =>
              update({ accessTTL: (e.target as HTMLInputElement).value })}
            placeholder="e.g. 30s, 5m, 1h"
          />
        </label>
        <label part="field">
          <span part="field-label">Proposed refresh sliding TTL (optional)</span>
          <input
            part="field-input"
            type="text"
            .value=${f.refreshSlidingTTL}
            @input=${(e: Event) =>
              update({ refreshSlidingTTL: (e.target as HTMLInputElement).value })}
            placeholder="e.g. 7d"
          />
        </label>
        <label part="field">
          <span part="field-label">Proposed refresh absolute TTL (optional)</span>
          <input
            part="field-input"
            type="text"
            .value=${f.refreshAbsoluteTTL}
            @input=${(e: Event) =>
              update({ refreshAbsoluteTTL: (e.target as HTMLInputElement).value })}
            placeholder="e.g. 30d"
          />
        </label>
        ${f.error ? html`<p part="error">${f.error}</p>` : ""}
        <div part="actions">
          <button
            part="button-primary"
            ?disabled=${f.submitting}
            @click=${() => void this.submitScopeRequest(client.client_id)}
          >${f.submitting ? "Submitting…" : "Submit request"}</button>
          <button
            ?disabled=${f.submitting}
            @click=${() =>
              (this.requestForm = { ...f, showing: false, error: null })}
          >Cancel</button>
        </div>
      </div>
    `;
  }

  private async saveScopes(client: ClientView) {
    this.scopesSaving = true;
    this.scopesError = null;
    const required = Object.entries(this.scopesForm.modes)
      .filter(([, m]) => m === "required")
      .map(([s]) => s)
      .sort()
      .join(" ");
    const optional = Object.entries(this.scopesForm.modes)
      .filter(([, m]) => m === "optional")
      .map(([s]) => s)
      .sort()
      .join(" ");
    const res = await apiCall<{ updated: boolean }>(
      `/clients/${encodeURIComponent(client.client_id)}`,
      {
        method: "PATCH",
        json: { required_scopes: required, optional_scopes: optional },
      },
    );
    this.scopesSaving = false;
    if (!res.ok) {
      this.scopesError = res.message;
      return;
    }
    // Refresh the list so the next time we hit the row's button
    // we see the saved state. Then go back to list.
    await this.refreshListSilent();
    this.view = { kind: "list" };
  }

  private async submitScopeRequest(clientID: string) {
    const f = this.requestForm;
    if (!f.reason.trim()) {
      this.requestForm = { ...f, error: "Reason is required." };
      return;
    }
    this.requestForm = { ...f, submitting: true, error: null };
    const body: Record<string, unknown> = {
      scope: "offline_access",
      reason: f.reason.trim(),
    };
    const parsedAccess = parseDurationStr(f.accessTTL);
    const parsedSliding = parseDurationStr(f.refreshSlidingTTL);
    const parsedAbsolute = parseDurationStr(f.refreshAbsoluteTTL);
    if (parsedAccess === null || parsedSliding === null || parsedAbsolute === null) {
      this.requestForm = {
        ...f,
        submitting: false,
        error: "Bad duration. Use forms like 30s, 5m, 7d.",
      };
      return;
    }
    if (parsedAccess > 0) body.proposed_access_token_ttl_seconds = parsedAccess;
    if (parsedSliding > 0) body.proposed_refresh_token_sliding_ttl_seconds = parsedSliding;
    if (parsedAbsolute > 0) body.proposed_refresh_token_absolute_ttl_seconds = parsedAbsolute;

    const res = await apiCall<{ scope_request: ScopeRequestView }>(
      `/clients/${encodeURIComponent(clientID)}/scope-requests`,
      { method: "POST", json: body },
    );
    if (!res.ok) {
      this.requestForm = { ...f, submitting: false, error: res.message };
      return;
    }
    // Reload history + collapse the form.
    await this.loadScopeRequests(clientID);
    this.requestForm = {
      showing: false,
      reason: "",
      accessTTL: "",
      refreshSlidingTTL: "",
      refreshAbsoluteTTL: "",
      submitting: false,
      error: null,
    };
  }

  // ─── created (post-create result) ────────────────────────────────

  private renderCreated(result: CreatedClient) {
    return html`
      <div part="header">
        <div part="header-text">
          <h2 part="header-title">Client registered</h2>
          <p part="header-sub">Save the credentials below — the secret won't be shown again.</p>
        </div>
      </div>

      <dl part="kv">
        <dt>Client ID</dt><dd><code>${result.client.client_id}</code></dd>
        <dt>Name</dt><dd>${result.client.name}</dd>
        <dt>Type</dt><dd>${result.client.client_type}</dd>
        <dt>Redirect URI</dt><dd><code>${result.client.redirect_uris}</code></dd>
        <dt>PKCE</dt><dd>${result.client.require_pkce ? "required" : "optional"}</dd>
      </dl>

      ${result.client_secret
        ? this.renderSecretPanel(result.client_secret, "Client secret")
        : html`<p part="field-hint">
            No client_secret — this is a public (SPA) client. PKCE replaces
            the shared secret on every authorization.
          </p>`}

      <div part="actions">
        <button
          part="button-primary"
          @click=${() => (this.view = { kind: "list" })}
        >Done</button>
      </div>
    `;
  }

  // ─── rotate ──────────────────────────────────────────────────────

  private startRotate(target: ClientView) {
    this.rotateError = null;
    this.rotating = false;
    this.view = { kind: "rotate-confirm", target };
  }

  private renderRotateConfirm(target: ClientView) {
    return html`
      <div part="header">
        <div part="header-text">
          <h2 part="header-title">Rotate client secret?</h2>
          <p part="header-sub">
            A fresh secret will be generated. The old secret becomes
            invalid <strong>immediately</strong>.
          </p>
        </div>
      </div>

      <dl part="kv">
        <dt>Client ID</dt><dd><code>${target.client_id}</code></dd>
        <dt>Name</dt><dd>${target.name}</dd>
        <dt>Type</dt><dd>${target.client_type}</dd>
      </dl>

      ${this.rotateError
        ? html`<p part="error" role="alert">${this.rotateError}</p>`
        : ""}

      <div part="actions">
        <button
          part="button-primary"
          ?disabled=${this.rotating}
          @click=${() => void this.doRotate(target)}
        >${this.rotating ? "Rotating…" : "Rotate now"}</button>
        <button
          @click=${() => (this.view = { kind: "list" })}
          ?disabled=${this.rotating}
        >Cancel</button>
      </div>
    `;
  }

  private async doRotate(target: ClientView) {
    this.rotating = true;
    this.rotateError = null;
    const res = await apiCall<RotateSecretResult>(
      `/clients/${encodeURIComponent(target.client_id)}/rotate-secret`,
      { method: "POST" },
    );
    this.rotating = false;
    if (!res.ok) {
      if (res.code === "NO_SESSION") {
        this.view = { kind: "needs-signin" };
        dispatchNeedsSignin(this);
        return;
      }
      this.rotateError = res.message;
      return;
    }
    this.view = { kind: "rotated", client: target, result: res.data };
  }

  private renderRotated(client: ClientView, result: RotateSecretResult) {
    return html`
      <div part="header">
        <div part="header-text">
          <h2 part="header-title">Client secret rotated</h2>
          <p part="header-sub">
            Update your portal's secret store before its next OAuth flow.
          </p>
        </div>
      </div>

      <dl part="kv">
        <dt>Client ID</dt><dd><code>${result.client_id}</code></dd>
        <dt>Name</dt><dd>${client.name}</dd>
      </dl>

      ${this.renderSecretPanel(result.client_secret, "New client secret")}

      <div part="actions">
        <button
          part="button-primary"
          @click=${() => {
            this.view = { kind: "list" };
            void this.refreshListSilent();
          }}
        >Done</button>
      </div>
    `;
  }

  // ─── shared: secret-shown-once panel ─────────────────────────────

  private renderSecretPanel(secret: string, label: string) {
    return html`
      <div part="secret-panel">
        <strong>⚠ ${label} — shown ONCE</strong>
        <p>
          Copy this value now and store it in your portal's secret manager.
          Only its bcrypt hash is persisted server-side; if lost, rotate
          via the actions above.
        </p>
        <code part="secret-value">${secret}</code>
        <div part="actions" style="margin-top: 0.75rem;">
          <button
            part="button-primary"
            @click=${() => void this.copySecret(secret)}
          >${this.secretCopied ? "✓ Copied" : "Copy secret"}</button>
        </div>
      </div>
    `;
  }

  private async copySecret(secret: string) {
    try {
      await navigator.clipboard.writeText(secret);
      this.secretCopied = true;
      setTimeout(() => {
        this.secretCopied = false;
      }, 2000);
    } catch {
      // Clipboard API unavailable on insecure origins / denied perms;
      // operator can still triple-click the monospace value to select.
    }
  }
}

/**
 * parseDurationStr parses single-unit Go-style durations: 30s, 5m,
 * 2h, 30d. Returns seconds. Empty string returns 0 (caller treats
 * 0 as "field not supplied"). Returns null on parse failure so the
 * caller can surface a typed error.
 */
function parseDurationStr(raw: string): number | null {
  const trimmed = raw.trim();
  if (trimmed === "") return 0;
  const m = /^(\d+)\s*([smhd])$/i.exec(trimmed);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  if (!Number.isFinite(n) || n <= 0) return null;
  switch (m[2].toLowerCase()) {
    case "s":
      return n;
    case "m":
      return n * 60;
    case "h":
      return n * 60 * 60;
    case "d":
      return n * 24 * 60 * 60;
  }
  return null;
}

declare global {
  interface HTMLElementTagNameMap {
    "akashic-clients": AkashicClients;
  }
  interface HTMLElementEventMap {
    "akashic-client-created": CustomEvent<{ client_id: string }>;
    "akashic-client-deleted": CustomEvent<{ client_id: string }>;
  }
}
