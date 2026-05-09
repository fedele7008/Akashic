/**
 * <akashic-connected-apps> — end-user surface for managing OAuth
 * grants. Phase 7.5.
 *
 * Lists every third-party client the signed-in user has approved
 * (built-ins + first-party clients don't go through the consent
 * screen so they never appear here). Each row has a Revoke button;
 * inline confirm gates the actual delete to avoid one-click
 * accidents. Revoking a grant means the next /authorize for that
 * client+user pair re-prompts the consent screen.
 *
 * Public API (DOM events bubble to embedding page):
 *   akashic-needs-signin   — no live session; embedder should
 *                            redirect to /sign-in flow
 *   akashic-consent-revoked — fired after a successful revoke
 *
 * Styling: open shadow DOM with `::part(...)` hooks, mirroring
 * akashic-clients. The optional default stylesheet provides a
 * baseline; tenants supply their own CSS for branded looks.
 */

import { LitElement, css, html } from "lit";
import { customElement, state } from "lit/decorators.js";

import { apiCall, type ApiResult } from "../lib/api";
import { dispatchNeedsSignin, renderNeedsSignin } from "../lib/needs-signin";

interface ConsentView {
  client_id: string;
  client_name: string;
  homepage_url?: string;
  scopes: string;
  granted_at: string;
  updated_at: string;
}

type View =
  | { kind: "loading" }
  | { kind: "needs-signin" }
  | { kind: "error"; message: string }
  | { kind: "list" };

@customElement("akashic-connected-apps")
export class AkashicConnectedApps extends LitElement {
  @state() private view: View = { kind: "loading" };
  @state() private consents: ConsentView[] = [];
  // Per-row revoke flow: client_id of the row currently asking the
  // user to confirm. Null = no in-progress revoke. Storing on the
  // host (rather than per-row state) lets list re-renders preserve
  // an in-progress confirmation.
  @state() private confirmingRevoke: string | null = null;
  @state() private busyRevoke: string | null = null;

  static override styles = css`
    :host {
      display: block;
      color: var(--akashic-text, inherit);
      font-family: var(--akashic-font-family, inherit);
    }

    [part="header"] {
      margin-bottom: 1rem;
    }
    [part="header"] h2 {
      margin: 0;
      font-size: 1.125rem;
      font-weight: 600;
    }
    [part="header-sub"] {
      margin: 0.25rem 0 0 0;
      font-size: 0.875rem;
      opacity: 0.7;
    }

    [part="empty"] {
      padding: 1.25rem 1rem;
      text-align: center;
      opacity: 0.7;
      font-size: 0.9rem;
      border: 1px dashed currentColor;
      border-radius: 0.5rem;
    }

    [part="row"] {
      display: flex;
      align-items: center;
      gap: 1rem;
      padding: 0.75rem 1rem;
      border: 1px solid currentColor;
      border-radius: 0.5rem;
      margin-bottom: 0.5rem;
    }
    [part="row-body"] {
      flex: 1;
      min-width: 0;
    }
    [part="row-name"] {
      font-weight: 600;
      font-size: 0.95rem;
    }
    [part="row-meta"] {
      font-size: 0.8125rem;
      opacity: 0.75;
      margin-top: 0.25rem;
    }
    [part="scope-list"] {
      display: flex;
      flex-wrap: wrap;
      gap: 0.25rem;
      margin-top: 0.4rem;
    }
    [part="scope-chip"] {
      font-family: ui-monospace, monospace;
      font-size: 0.75rem;
      padding: 0.05rem 0.4rem;
      border-radius: 0.25rem;
      border: 1px solid currentColor;
      opacity: 0.7;
    }

    button {
      font: inherit;
      color: inherit;
      background: transparent;
      border: 1px solid currentColor;
      border-radius: 0.375rem;
      padding: 0.4rem 0.75rem;
      cursor: pointer;
    }
    button:hover:not(:disabled) {
      background: rgba(127, 127, 127, 0.1);
    }
    button:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }
    [part="revoke-btn"] {
      color: #c44;
      border-color: #c44;
    }

    [part="confirm-row"] {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.75rem 1rem;
      border: 1px solid #c44;
      border-radius: 0.5rem;
      margin-bottom: 0.5rem;
      background: rgba(196, 68, 68, 0.05);
    }
    [part="confirm-text"] {
      flex: 1;
      font-size: 0.875rem;
    }

    [part="error"] {
      color: #c44;
      padding: 0.75rem 1rem;
      border: 1px solid #c44;
      border-radius: 0.5rem;
      margin-bottom: 1rem;
      font-size: 0.9rem;
    }
  `;

  override connectedCallback() {
    super.connectedCallback();
    void this.refresh();
  }

  private async refresh() {
    this.view = { kind: "loading" };
    const res: ApiResult<{ consents: ConsentView[] }> = await apiCall(
      "/users/me/consents",
    );
    if (!res.ok) {
      if (res.code === "NO_SESSION") {
        this.view = { kind: "needs-signin" };
        dispatchNeedsSignin(this);
        return;
      }
      this.view = {
        kind: "error",
        message: res.message ?? "Could not load connected apps.",
      };
      return;
    }
    this.consents = res.data?.consents ?? [];
    this.view = { kind: "list" };
  }

  private async revoke(clientID: string) {
    this.busyRevoke = clientID;
    const res = await apiCall(`/users/me/consents/${encodeURIComponent(clientID)}`, {
      method: "DELETE",
    });
    this.busyRevoke = null;
    if (!res.ok) {
      this.view = {
        kind: "error",
        message: res.message ?? "Could not revoke access.",
      };
      return;
    }
    this.dispatchEvent(
      new CustomEvent("akashic-consent-revoked", {
        detail: { client_id: clientID },
        bubbles: true,
        composed: true,
      }),
    );
    this.confirmingRevoke = null;
    await this.refresh();
  }

  override render() {
    if (this.view.kind === "loading") {
      return html`<p>Loading…</p>`;
    }
    if (this.view.kind === "needs-signin") {
      return renderNeedsSignin();
    }

    return html`
      <div part="header">
        <h2>Connected apps</h2>
        <p part="header-sub">
          Apps you've signed into with this account. Revoking removes
          access — the app will need to ask permission again the next
          time you sign in.
        </p>
      </div>

      ${this.view.kind === "error"
        ? html`<div part="error" role="alert">${this.view.message}</div>`
        : ""}

      ${this.consents.length === 0
        ? html`
            <p part="empty">
              You haven't approved any third-party apps yet.
            </p>
          `
        : this.consents.map((c) => this.renderRow(c))}
    `;
  }

  private renderRow(c: ConsentView) {
    const confirming = this.confirmingRevoke === c.client_id;
    const busy = this.busyRevoke === c.client_id;
    const scopes = c.scopes.split(/\s+/).filter(Boolean);

    if (confirming) {
      return html`
        <div part="confirm-row" data-client-id=${c.client_id}>
          <div part="confirm-text">
            Revoke access for <strong>${c.client_name}</strong>?
          </div>
          <button
            part="revoke-btn"
            ?disabled=${busy}
            @click=${() => void this.revoke(c.client_id)}
          >
            ${busy ? "Revoking…" : "Confirm revoke"}
          </button>
          <button
            ?disabled=${busy}
            @click=${() => (this.confirmingRevoke = null)}
          >
            Cancel
          </button>
        </div>
      `;
    }

    return html`
      <div part="row" data-client-id=${c.client_id}>
        <div part="row-body">
          <div part="row-name">
            ${c.homepage_url
              ? html`<a
                  href=${c.homepage_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  >${c.client_name}</a
                >`
              : c.client_name}
          </div>
          <div part="row-meta">
            Granted ${formatDate(c.granted_at)}
            ${c.updated_at !== c.granted_at
              ? html` · Updated ${formatDate(c.updated_at)}`
              : ""}
          </div>
          <div part="scope-list">
            ${scopes.map(
              (s) => html`<span part="scope-chip">${s}</span>`,
            )}
          </div>
        </div>
        <button
          part="revoke-btn"
          @click=${() => (this.confirmingRevoke = c.client_id)}
        >
          Revoke
        </button>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "akashic-connected-apps": AkashicConnectedApps;
  }
}

/**
 * Format an ISO 8601 timestamp as the user's local date. Falls back
 * to the raw string if Date parsing fails — a malformed server
 * response shouldn't make the row unrenderable.
 */
function formatDate(iso: string): string {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleDateString();
}
