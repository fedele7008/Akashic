/**
 * `<akashic-notification-preferences>` — Phase 9g.
 *
 * User-facing surface for the two notification toggles:
 *
 *   - Login notifications: "you signed in" email after every
 *     successful login. Anti-takeover hint.
 *   - Approval notifications: emails when an admin decides on the
 *     user's client-registration / scope-request submissions.
 *
 * Both default-on at signup. The widget reads state from
 * `GET /users/me/notification-preferences` and mutates via
 * `POST /users/me/notification-preferences`. When the deployment's
 * mailer isn't configured, the toggles still flip (intent
 * survives), but the widget shows an "inactive — configure email"
 * hint because the actual send paths silently skip.
 */

import { LitElement, css, html } from "lit";
import { customElement, state } from "lit/decorators.js";

import { apiCall } from "../lib/api";
import { dispatchNeedsSignin, renderNeedsSignin } from "../lib/needs-signin";

interface Preferences {
  login_enabled: boolean;
  approval_enabled: boolean;
  mailer_configured: boolean;
}

type View =
  | { kind: "loading" }
  | { kind: "needs-signin" }
  | { kind: "error"; message: string }
  | { kind: "ready"; data: Preferences };

@customElement("akashic-notification-preferences")
export class AkashicNotificationPreferences extends LitElement {
  @state() private view: View = { kind: "loading" };
  @state() private busyField: "login" | "approval" | null = null;
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
    [part="hint-banner"] {
      font-size: 0.8125rem;
      padding: 0.5rem 0.75rem;
      border-radius: var(--akashic-input-radius, 0.375rem);
      background: var(--akashic-warning-soft, rgba(245, 158, 11, 0.12));
      color: var(--akashic-warning, #f59e0b);
      margin-bottom: 0.75rem;
    }
    [part="toggle-row"] {
      display: flex;
      flex-direction: row;
      gap: 0.75rem;
      align-items: flex-start;
      padding: 0.875rem 0;
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
  `;

  override connectedCallback(): void {
    super.connectedCallback();
    void this.load();
  }

  private async load() {
    this.view = { kind: "loading" };
    const res = await apiCall<Preferences>("/users/me/notification-preferences");
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
        return html`<p>Loading notification preferences…</p>`;
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

  private renderReady(d: Preferences) {
    return html`
      <div part="header">
        <h2 part="header-title">Notification preferences</h2>
        <p part="header-sub">
          Choose which transactional and workflow emails you want
          to receive. Security emails (password resets, MFA codes,
          email verification) are always sent.
        </p>
      </div>

      ${!d.mailer_configured
        ? html`
            <p part="hint-banner" role="status">
              Email isn't configured for this deployment, so these
              notifications are currently paused. Your preferences
              are still saved and will activate automatically once
              an admin sets up email.
            </p>
          `
        : ""}

      ${this.flashErr ? html`<p part="error" role="alert">${this.flashErr}</p>` : ""}

      <div part="toggle-row">
        <input
          type="checkbox"
          ?checked=${d.login_enabled}
          ?disabled=${this.busyField === "login"}
          @change=${(e: Event) => void this.onToggle("login", (e.target as HTMLInputElement).checked)}
        />
        <span>
          <span part="toggle-label">Sign-in activity</span>
          <span part="toggle-hint">
            Email me when my account is signed in to. Includes the
            time, source IP, device, and (when known) the
            application being authorized. Useful as an
            anti-account-takeover hint.
          </span>
        </span>
      </div>

      <div part="toggle-row">
        <input
          type="checkbox"
          ?checked=${d.approval_enabled}
          ?disabled=${this.busyField === "approval"}
          @change=${(e: Event) => void this.onToggle("approval", (e.target as HTMLInputElement).checked)}
        />
        <span>
          <span part="toggle-label">Approvals and decisions</span>
          <span part="toggle-hint">
            Email me when an admin approves or rejects a
            client-registration request or a special-scope request
            I submitted.
          </span>
        </span>
      </div>
    `;
  }

  private async onToggle(field: "login" | "approval", enabled: boolean) {
    this.busyField = field;
    this.flashErr = null;
    const body: Record<string, boolean> = {};
    if (field === "login") body.login_enabled = enabled;
    else body.approval_enabled = enabled;
    const res = await apiCall<Preferences>("/users/me/notification-preferences", {
      method: "POST",
      json: body,
    });
    this.busyField = null;
    if (!res.ok) {
      this.flashErr = res.message;
      // Reload to re-sync the checkbox to actual server state.
      void this.load();
      return;
    }
    this.view = { kind: "ready", data: res.data };
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "akashic-notification-preferences": AkashicNotificationPreferences;
  }
}
