/**
 * <akashic-change-password> — let the signed-in user change their password.
 *
 * Authenticated. Calls api.<tenant>/users/me/password (POST). The api
 * server does the actual work: validates the old password by binding
 * to LDAP, applies the password policy to the new value, then issues
 * the LDAP modify.
 *
 * Events:
 *   `akashic-needs-signin`        — no live session.
 *   `akashic-password-changed`    — emitted after a successful change.
 *
 * Headless. Style via:
 *   akashic-change-password::part(form)
 *   akashic-change-password::part(field), ::part(field-label), ::part(field-input)
 *   akashic-change-password::part(field-error), ::part(field-hint)
 *   akashic-change-password::part(submit-button)
 *   akashic-change-password::part(top-error), ::part(success)
 *   akashic-change-password::part(needs-signin)
 *
 * Note on UX: a successful password change does NOT log the user out
 * or invalidate active bearers. The user's existing access tokens
 * remain valid until natural expiry — that's correct because bearers
 * are issued by the OAuth keystore, independent of LDAP password
 * state. (If we wanted "force-logout-on-password-change", we'd need
 * server-side bearer revocation, which Phase 8 doesn't ship.)
 */

import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";

import { apiCall } from "../lib/api";
import { dispatchNeedsSignin, renderNeedsSignin } from "../lib/needs-signin";

interface FieldErrors {
  old_password?: string;
  new_password?: string;
  confirm?: string;
}

@customElement("akashic-change-password")
export class AkashicChangePassword extends LitElement {
  /** UX hint only; api server enforces the actual policy. */
  @property({ type: Number, attribute: "min-password-length" })
  minPasswordLength = 8;

  @state() private busy = false;
  @state() private noSession = false;
  @state() private done = false;
  @state() private topError: string | null = null;
  @state() private fieldErrors: FieldErrors = {};

  static override styles = css`
    :host {
      display: block;
      color: var(--akashic-text, inherit);
      font-family: var(--akashic-font-family, inherit);
    }
    [part="form"] {
      display: flex;
      flex-direction: column;
      gap: var(--akashic-field-gap, 1rem);
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
    [part="submit-button"] {
      font: inherit;
      color: var(--akashic-button-fg, white);
      background: var(--akashic-button-bg, #4f8cff);
      border: none;
      padding: 0.5rem 1rem;
      border-radius: var(--akashic-input-radius, 0.375rem);
      cursor: pointer;
      align-self: flex-start;
    }
    [part="submit-button"][disabled] {
      opacity: 0.6;
      cursor: not-allowed;
    }
    [part="top-error"] {
      color: var(--akashic-error, #dc2626);
      font-size: 0.875rem;
      padding: 0.5rem 0.75rem;
      border-radius: var(--akashic-input-radius, 0.375rem);
      border: 1px solid var(--akashic-error, #dc2626);
    }
    [part="success"] {
      color: var(--akashic-success, #16a34a);
      font-size: 0.875rem;
    }
  `;

  override render() {
    if (this.noSession) return renderNeedsSignin();
    if (this.done) {
      return html`
        <div part="success" role="status">
          Password updated. Your existing session is still valid.
        </div>
      `;
    }

    return html`
      <form part="form" @submit=${this.onSubmit} novalidate>
        ${this.topError
          ? html`<div part="top-error" role="alert">${this.topError}</div>`
          : ""}

        ${this.field({
          name: "old_password",
          label: "Current password",
          autocomplete: "current-password",
          error: this.fieldErrors.old_password,
        })}

        ${this.field({
          name: "new_password",
          label: "New password",
          autocomplete: "new-password",
          minLength: this.minPasswordLength,
          hint: `At least ${this.minPasswordLength} characters.`,
          error: this.fieldErrors.new_password,
        })}

        ${this.field({
          name: "confirm",
          label: "Confirm new password",
          autocomplete: "new-password",
          error: this.fieldErrors.confirm,
        })}

        <button part="submit-button" type="submit" ?disabled=${this.busy}>
          ${this.busy ? "Changing…" : "Change password"}
        </button>
      </form>
    `;
  }

  private field(opts: {
    name: keyof FieldErrors;
    label: string;
    autocomplete: string;
    minLength?: number;
    hint?: string;
    error?: string;
  }) {
    const id = `akashic-cp-${opts.name}`;
    return html`
      <label part="field" for=${id}>
        <span part="field-label">${opts.label}</span>
        <input
          part="field-input"
          id=${id}
          name=${opts.name}
          type="password"
          autocomplete=${opts.autocomplete}
          required
          minlength=${opts.minLength ?? null}
          aria-invalid=${opts.error ? "true" : "false"}
        />
        ${opts.error
          ? html`<span part="field-error" role="alert">${opts.error}</span>`
          : opts.hint
            ? html`<span part="field-hint">${opts.hint}</span>`
            : ""}
      </label>
    `;
  }

  private async onSubmit(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    if (this.busy) return;
    this.busy = true;
    this.topError = null;
    this.fieldErrors = {};

    const form = e.currentTarget as HTMLFormElement;
    const data = new FormData(form);
    const oldPw = String(data.get("old_password") ?? "");
    const newPw = String(data.get("new_password") ?? "");
    const confirm = String(data.get("confirm") ?? "");

    if (!oldPw || !newPw) {
      this.topError = "All fields are required.";
      this.busy = false;
      return;
    }
    if (newPw.length < this.minPasswordLength) {
      this.fieldErrors = {
        new_password: `Must be at least ${this.minPasswordLength} characters.`,
      };
      this.busy = false;
      return;
    }
    if (newPw !== confirm) {
      this.fieldErrors = { confirm: "Passwords do not match." };
      this.busy = false;
      return;
    }

    const res = await apiCall<{ updated: boolean }>("/users/me/password", {
      method: "POST",
      json: { old_password: oldPw, new_password: newPw },
    });

    if (res.ok) {
      this.done = true;
      this.busy = false;
      this.dispatchEvent(
        new CustomEvent("akashic-password-changed", {
          bubbles: true,
          composed: true,
        }),
      );
      return;
    }

    switch (res.code) {
      case "NO_SESSION":
        this.noSession = true;
        dispatchNeedsSignin(this);
        break;
      case "INVALID_CREDENTIALS":
        this.fieldErrors = { old_password: "That current password is incorrect." };
        break;
      case "PASSWORD_POLICY_VIOLATION":
        this.fieldErrors = { new_password: res.message };
        break;
      default:
        this.topError = res.message || "Could not change password.";
    }
    this.busy = false;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "akashic-change-password": AkashicChangePassword;
  }
  interface HTMLElementEventMap {
    "akashic-password-changed": CustomEvent<void>;
  }
}
