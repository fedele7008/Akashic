/**
 * <akashic-forgot-help> — informational widget for password recovery.
 *
 * Public (no auth). Calls api.<tenant>/users/forgot-password-help and
 * renders the operator-supplied recovery copy. In Phase 8 the api
 * server returns a static "contact your operator at <email>" payload
 * since email-driven self-service reset is deferred to Phase 9; this
 * widget stays correct across that future change because it just
 * displays whatever the server says.
 *
 * Headless. Style via:
 *   akashic-forgot-help::part(card)        — outer card
 *   akashic-forgot-help::part(message)     — main message line
 *   akashic-forgot-help::part(contact)     — operator contact line
 */

import { LitElement, html, css } from "lit";
import { customElement, state } from "lit/decorators.js";

import { apiCallPublic } from "../lib/api";

interface ForgotHelp {
  phase: number;
  self_service: boolean;
  support_contact: string;
  message: string;
}

@customElement("akashic-forgot-help")
export class AkashicForgotHelp extends LitElement {
  @state() private help: ForgotHelp | null = null;
  @state() private error: string | null = null;

  static override styles = css`
    :host {
      display: block;
      color: var(--akashic-text, inherit);
      font-family: var(--akashic-font-family, inherit);
    }
    [part="card"] {
      padding: var(--akashic-card-padding, 1rem);
      border: var(--akashic-input-border, 1px solid currentColor);
      border-radius: var(--akashic-input-radius, 0.375rem);
      background: var(--akashic-card-bg, transparent);
    }
    [part="message"] {
      font-size: 0.875rem;
    }
    [part="contact"] {
      margin-top: 0.75rem;
      font-size: 0.875rem;
      color: var(--akashic-text-muted, currentColor);
      opacity: 0.8;
    }
    [part="contact"] code {
      font-family: var(--akashic-font-monospace, ui-monospace, "SF Mono", monospace);
      color: var(--akashic-text, inherit);
    }
    [part="error"] {
      color: var(--akashic-error, #dc2626);
      font-size: 0.875rem;
    }
  `;

  override async connectedCallback(): Promise<void> {
    super.connectedCallback();
    const res = await apiCallPublic<ForgotHelp>("/users/forgot-password-help");
    if (res.ok) {
      this.help = res.data;
    } else {
      this.error = res.message;
    }
  }

  override render() {
    if (this.error) {
      return html`<p part="error" role="alert">${this.error}</p>`;
    }
    if (!this.help) {
      return html`<p part="message">Loading…</p>`;
    }
    return html`
      <div part="card">
        <p part="message">${this.help.message}</p>
        ${this.help.support_contact
          ? html`
              <p part="contact">
                Contact your operator at
                <code>${this.help.support_contact}</code> to request a password
                reset.
              </p>
            `
          : ""}
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "akashic-forgot-help": AkashicForgotHelp;
  }
}
