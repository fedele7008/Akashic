/**
 * <akashic-verify-email-banner> — surfaces a "verify your email"
 * notice when the signed-in user's `email_verified` flag is false.
 * Phase 9b.
 *
 * Behavior:
 *   - Mounts on profile pages or anywhere a logged-in user lands
 *   - Fetches /users/me on connect
 *   - Renders nothing when:
 *       * not signed in (silent — embedding page handles auth)
 *       * email_verified=true (banner not needed)
 *       * /users/me reports email_configured=false (deployment
 *         doesn't have email; banner can't help, hide entirely)
 *   - When unverified + email available: renders banner with a
 *     "Resend verification email" button
 *   - On resend success: shows "Sent — check your inbox"; the
 *     banner remains until the user actually verifies (we don't
 *     poll /users/me after the click; reload triggers a refresh)
 *
 * Events:
 *   `akashic-verification-resent`  — fires after a successful
 *                                     resend. embedder can show
 *                                     a toast if they want.
 *
 * Headless. Style via:
 *   akashic-verify-email-banner::part(banner)
 *   akashic-verify-email-banner::part(message)
 *   akashic-verify-email-banner::part(button)
 *   akashic-verify-email-banner::part(success)
 *   akashic-verify-email-banner::part(error)
 */

import { LitElement, css, html } from "lit";
import { customElement, state } from "lit/decorators.js";

import { apiCall } from "../lib/api";

// Local mirror of the api-server's /users/me shape, minus fields
// we don't need here. Inline to avoid a cross-component import.
interface MeResponse {
  email: string;
  email_verified: boolean;
}

type View =
  | { kind: "hidden" }
  | { kind: "loading" }
  | { kind: "unverified"; email: string }
  | { kind: "resent"; email: string }
  | { kind: "error"; message: string };

@customElement("akashic-verify-email-banner")
export class AkashicVerifyEmailBanner extends LitElement {
  @state() private view: View = { kind: "loading" };
  @state() private busy = false;

  static override styles = css`
    :host {
      display: block;
      color: var(--akashic-text, inherit);
      font-family: var(--akashic-font-family, inherit);
    }
    [part="banner"] {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.75rem;
      padding: 0.75rem 1rem;
      border-radius: var(--akashic-input-radius, 0.5rem);
      background: var(--akashic-warning-bg, rgba(245, 158, 11, 0.08));
      border: 1px solid var(--akashic-warning, #f59e0b);
      color: var(--akashic-warning-fg, #92400e);
      font-size: 0.875rem;
    }
    [part="message"] {
      flex: 1 1 auto;
      min-width: 0;
    }
    [part="button"] {
      font: inherit;
      color: var(--akashic-button-fg, white);
      background: var(--akashic-button-bg, #4f8cff);
      border: none;
      padding: 0.375rem 0.75rem;
      border-radius: var(--akashic-input-radius, 0.375rem);
      cursor: pointer;
      font-size: 0.8125rem;
    }
    [part="button"][disabled] {
      opacity: 0.6;
      cursor: not-allowed;
    }
    [part="success"] {
      color: var(--akashic-success, #16a34a);
      font-size: 0.875rem;
      padding: 0.5rem 0.75rem;
      border: 1px solid var(--akashic-success, #16a34a);
      border-radius: var(--akashic-input-radius, 0.375rem);
    }
    [part="error"] {
      color: var(--akashic-error, #dc2626);
      font-size: 0.875rem;
      padding: 0.5rem 0.75rem;
      border: 1px solid var(--akashic-error, #dc2626);
      border-radius: var(--akashic-input-radius, 0.375rem);
    }
  `;

  override async connectedCallback(): Promise<void> {
    super.connectedCallback();
    await this.checkStatus();
  }

  private async checkStatus(): Promise<void> {
    const res = await apiCall<MeResponse>("/users/me");
    if (!res.ok) {
      // NO_SESSION → silent (page is responsible for sign-in CTA).
      // Other errors → silent too; banner is a "best effort" UI.
      this.view = { kind: "hidden" };
      return;
    }
    if (res.data.email_verified) {
      this.view = { kind: "hidden" };
      return;
    }
    this.view = { kind: "unverified", email: res.data.email };
  }

  private async onResend(): Promise<void> {
    if (this.busy) return;
    this.busy = true;
    const res = await apiCall<{ sent: boolean; email: string }>(
      "/users/me/send-verification-email",
      { method: "POST" },
    );
    this.busy = false;
    if (res.ok) {
      this.view = { kind: "resent", email: res.data.email };
      this.dispatchEvent(
        new CustomEvent("akashic-verification-resent", {
          bubbles: true,
          composed: true,
        }),
      );
      return;
    }
    // EMAIL_NOT_AVAILABLE → hide entirely (no path forward; same
    // posture as initial check). Other errors → render an error
    // banner with the server's message so the user knows something
    // went wrong but still sees a clear action (try again later).
    if (res.code === "EMAIL_NOT_AVAILABLE") {
      this.view = { kind: "hidden" };
      return;
    }
    this.view = { kind: "error", message: res.message };
  }

  override render() {
    switch (this.view.kind) {
      case "hidden":
      case "loading":
        return html``;
      case "unverified":
        return html`
          <div part="banner" role="status">
            <span part="message">
              Please verify your email — we sent a link to
              <strong>${this.view.email}</strong>. Didn't get it?
            </span>
            <button
              part="button"
              type="button"
              ?disabled=${this.busy}
              @click=${() => void this.onResend()}
            >
              ${this.busy ? "Sending…" : "Resend verification"}
            </button>
          </div>
        `;
      case "resent":
        return html`
          <div part="success" role="status">
            Sent — check the inbox at <strong>${this.view.email}</strong>.
            The link expires in 24 hours.
          </div>
        `;
      case "error":
        return html`
          <div part="error" role="alert">${this.view.message}</div>
        `;
    }
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "akashic-verify-email-banner": AkashicVerifyEmailBanner;
  }
  interface HTMLElementEventMap {
    "akashic-verification-resent": CustomEvent<void>;
  }
}
