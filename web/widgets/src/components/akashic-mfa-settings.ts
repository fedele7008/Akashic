/**
 * `<akashic-mfa-settings>` — Phase 9f.
 *
 * User-facing surface for managing email-based MFA. Renders:
 *
 *   - On/off toggle for `users.mfa_enabled` (greyed-off when no
 *     mailer is configured; the API rejects enabling in that case).
 *   - Trusted-device list with a "Revoke" button per row, plus a
 *     "Revoke all" action.
 *   - A short explanation of how the flow works.
 *
 * The widget reads its initial state from `GET /users/me/mfa` and
 * mutates via `POST /users/me/mfa` and
 * `POST /users/me/mfa/trusted-devices/<id>/revoke`. No styling
 * surface beyond `::part()` regions; tenants compose the visual.
 */

import { LitElement, css, html } from "lit";
import { customElement, state } from "lit/decorators.js";

import { apiCall } from "../lib/api";
import { dispatchNeedsSignin, renderNeedsSignin } from "../lib/needs-signin";

interface TrustedDevice {
  id: string;
  label: string;
  issued_at: string;
  expires_at: string;
  last_used_at: string;
  revoked_at?: string;
  active: boolean;
}

interface MFASettings {
  enabled: boolean;
  mailer_configured: boolean;
  max_trusted_days: number;
  devices: TrustedDevice[];
}

type View =
  | { kind: "loading" }
  | { kind: "needs-signin" }
  | { kind: "error"; message: string }
  | { kind: "ready"; data: MFASettings };

@customElement("akashic-mfa-settings")
export class AkashicMFASettings extends LitElement {
  @state() private view: View = { kind: "loading" };
  // Per-row "busy" so revoking one device doesn't lock the whole
  // list. Keyed by device id.
  @state() private busyDevice: string | null = null;
  @state() private busyToggle = false;
  @state() private flashErr: string | null = null;

  static override styles = css`
    :host {
      display: block;
      width: 100%;
      max-width: 100%;
      min-width: 0;
      box-sizing: border-box;
      color: var(--akashic-text, inherit);
      font-family: var(--akashic-font-family, inherit);
    }
    [part="header"] h2 {
      margin: 0;
      font-size: 1.125rem;
      font-weight: 600;
    }
    [part="header-sub"] {
      margin: 0.25rem 0 1rem 0;
      font-size: 0.875rem;
      color: var(--akashic-text-muted, currentColor);
      opacity: 0.7;
    }
    [part="error"] {
      color: var(--akashic-error, #dc2626);
      font-size: 0.875rem;
      padding: 0.5rem 0.75rem;
      border-radius: var(--akashic-input-radius, 0.375rem);
      border: 1px solid var(--akashic-error, #dc2626);
      margin-bottom: 0.75rem;
    }
    [part="toggle-row"] {
      display: flex;
      flex-direction: row;
      gap: 0.75rem;
      align-items: flex-start;
      padding: 0.75rem 0;
      border-bottom: 1px solid var(--akashic-border-subtle, transparent);
    }
    [part="toggle-row"] input[type="checkbox"] {
      margin-top: 0.25rem;
      flex-shrink: 0;
    }
    [part="toggle-label"] {
      font-weight: 500;
    }
    [part="toggle-hint"] {
      display: block;
      margin-top: 0.25rem;
      font-size: 0.8125rem;
      color: var(--akashic-text-muted, currentColor);
      opacity: 0.8;
    }
    [part="devices"] {
      margin-top: 1rem;
    }
    [part="device-row"] {
      display: flex;
      flex-direction: row;
      gap: 0.75rem;
      align-items: center;
      padding: 0.625rem 0;
      border-bottom: 1px solid var(--akashic-border-subtle, transparent);
      font-size: 0.875rem;
    }
    [part="device-meta"] {
      flex: 1;
      min-width: 0;
    }
    [part="device-label"] {
      font-weight: 500;
    }
    [part="device-times"] {
      display: block;
      margin-top: 0.125rem;
      font-size: 0.75rem;
      color: var(--akashic-text-muted, currentColor);
      opacity: 0.8;
    }
    [part="device-status-active"] {
      display: inline-block;
      padding: 0.125rem 0.5rem;
      font-size: 0.6875rem;
      font-weight: 500;
      border-radius: 999px;
      background: var(--akashic-success-soft, rgba(22, 163, 74, 0.18));
      color: var(--akashic-success, #16a34a);
      white-space: nowrap;
    }
    [part="device-status-inactive"] {
      display: inline-block;
      padding: 0.125rem 0.5rem;
      font-size: 0.6875rem;
      font-weight: 500;
      border-radius: 999px;
      background: var(--akashic-muted-soft, rgba(120, 120, 120, 0.18));
      color: var(--akashic-text-muted, #888);
      white-space: nowrap;
    }
    button {
      font: inherit;
      cursor: pointer;
      padding: 0.375rem 0.75rem;
      border-radius: var(--akashic-input-radius, 0.375rem);
      border: 1px solid currentColor;
      background: transparent;
      color: inherit;
      font-size: 0.8125rem;
    }
    button[disabled] {
      opacity: 0.6;
      cursor: not-allowed;
    }
    [part="empty"] {
      padding: 0.75rem 0;
      font-size: 0.875rem;
      color: var(--akashic-text-muted, currentColor);
      opacity: 0.8;
    }
  `;

  override connectedCallback(): void {
    super.connectedCallback();
    void this.load();
  }

  private async load() {
    this.view = { kind: "loading" };
    const res = await apiCall<MFASettings>("/users/me/mfa");
    if (!res.ok) {
      if (res.code === "NO_SESSION") {
        this.view = { kind: "needs-signin" };
        dispatchNeedsSignin(this);
        return;
      }
      this.view = { kind: "error", message: res.message };
      return;
    }
    this.view = { kind: "ready", data: res.data };
  }

  override render() {
    switch (this.view.kind) {
      case "loading":
        return html`<p>Loading MFA settings…</p>`;
      case "needs-signin":
        return renderNeedsSignin();
      case "error":
        return html`
          <p part="error" role="alert">${this.view.message}</p>
          <button @click=${() => void this.load()}>Retry</button>
        `;
      case "ready":
        return this.renderReady(this.view.data);
    }
  }

  private renderReady(d: MFASettings) {
    const toggleHint = d.mailer_configured
      ? "Require a 6-digit code from email at every sign-in. You can mark trusted browsers below to skip the prompt for a bounded window."
      : "Email isn't configured for this deployment, so MFA can't be enabled. Ask your administrator to set up email; this toggle will activate automatically.";
    return html`
      <div part="header">
        <h2 part="header-title">Multi-factor authentication</h2>
        <p part="header-sub">
          Adds a second step at sign-in: a one-time code emailed to
          your address.
        </p>
      </div>

      ${this.flashErr ? html`<p part="error" role="alert">${this.flashErr}</p>` : ""}

      <div part="toggle-row">
        <input
          type="checkbox"
          ?checked=${d.enabled}
          ?disabled=${this.busyToggle || !d.mailer_configured}
          @change=${(e: Event) => void this.onToggle((e.target as HTMLInputElement).checked)}
        />
        <span>
          <span part="toggle-label">
            ${d.enabled ? "MFA is enabled." : "MFA is disabled."}
          </span>
          <span part="toggle-hint">${toggleHint}</span>
        </span>
      </div>

      <div part="devices">
        <h3 style="font-size: 0.9375rem; margin: 1rem 0 0.5rem;">Trusted devices</h3>
        ${d.devices.length === 0
          ? html`<div part="empty">No trusted devices yet. Mark "Remember this device" on the next MFA prompt to add one.</div>`
          : d.devices.map((dev) => this.renderDevice(dev))}
      </div>
    `;
  }

  private renderDevice(dev: TrustedDevice) {
    return html`
      <div part="device-row" data-device-id=${dev.id}>
        <div part="device-meta">
          <span part="device-label">${dev.label}</span>
          <span part="device-times">
            Issued ${new Date(dev.issued_at).toLocaleString()}
            · last used ${new Date(dev.last_used_at).toLocaleString()}
            ${dev.active
              ? html` · expires ${new Date(dev.expires_at).toLocaleDateString()}`
              : dev.revoked_at
                ? html` · revoked ${new Date(dev.revoked_at).toLocaleString()}`
                : html` · expired`}
          </span>
        </div>
        ${dev.active
          ? html`<span part="device-status-active">Active</span>`
          : html`<span part="device-status-inactive">${dev.revoked_at ? "Revoked" : "Expired"}</span>`}
        ${dev.active
          ? html`
              <button
                @click=${() => void this.onRevoke(dev.id)}
                ?disabled=${this.busyDevice === dev.id}
              >
                ${this.busyDevice === dev.id ? "Revoking…" : "Revoke"}
              </button>
            `
          : ""}
      </div>
    `;
  }

  private async onToggle(enabled: boolean) {
    this.busyToggle = true;
    this.flashErr = null;
    const res = await apiCall<{ enabled: boolean }>("/users/me/mfa", {
      method: "POST",
      json: { enabled },
    });
    this.busyToggle = false;
    if (!res.ok) {
      // The most common rejection: trying to enable without a mailer.
      // Surface the server-side message verbatim — it's already
      // user-friendly.
      this.flashErr = res.message;
      // Reload to re-sync the checkbox to actual server state.
      void this.load();
      return;
    }
    void this.load();
  }

  private async onRevoke(deviceID: string) {
    this.busyDevice = deviceID;
    this.flashErr = null;
    const res = await apiCall<{ revoked: boolean }>(
      `/users/me/mfa/trusted-devices/${encodeURIComponent(deviceID)}/revoke`,
      { method: "POST" },
    );
    this.busyDevice = null;
    if (!res.ok) {
      this.flashErr = res.message;
      return;
    }
    void this.load();
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "akashic-mfa-settings": AkashicMFASettings;
  }
}
