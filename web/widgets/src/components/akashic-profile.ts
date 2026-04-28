/**
 * <akashic-profile> — read + (optionally) edit the signed-in user's profile.
 *
 * Authenticated. Calls api.<tenant>/users/me on mount; renders fields.
 *
 * Attribute `editable` switches on inline display-name + email editing
 * (PATCH /users/me).
 *
 * Events:
 *   `akashic-needs-signin`  — no live session; tenant page should
 *                              redirect to its OAuth-start URL.
 *   `akashic-profile-updated` — emitted after a successful PATCH.
 *
 * Headless. Style via:
 *   akashic-profile::part(card)
 *   akashic-profile::part(field)
 *   akashic-profile::part(field-label)
 *   akashic-profile::part(field-value)         (read-only fields)
 *   akashic-profile::part(field-input)         (editable fields)
 *   akashic-profile::part(submit-button)
 *   akashic-profile::part(top-error)
 *   akashic-profile::part(top-success)
 *   akashic-profile::part(needs-signin)
 */

import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";

import { apiCall } from "../lib/api";
import { dispatchNeedsSignin, renderNeedsSignin } from "../lib/needs-signin";

interface UserProfile {
  id: string;
  username: string;
  email: string;
  display_name: string;
  user_type: "user" | "admin" | "root";
  email_verified: boolean;
  last_login_at: string | null;
  created_at: string;
}

@customElement("akashic-profile")
export class AkashicProfile extends LitElement {
  /** When set, an inline edit form for display_name + email is shown. */
  @property({ type: Boolean }) editable = false;

  @state() private profile: UserProfile | null = null;
  @state() private noSession = false;
  @state() private loadError: string | null = null;
  @state() private busy = false;
  @state() private topMsg: { kind: "ok" | "err"; text: string } | null = null;

  static override styles = css`
    :host {
      display: block;
      color: var(--akashic-text, inherit);
      font-family: var(--akashic-font-family, inherit);
    }
    [part="card"] {
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
      font-size: 0.75rem;
      font-weight: 500;
      color: var(--akashic-text-muted, currentColor);
      opacity: 0.8;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    [part="field-value"] {
      font-size: 0.95rem;
      word-break: break-word;
    }
    [part="field-input"] {
      font: inherit;
      color: inherit;
      padding: 0.5rem 0.75rem;
      border-radius: var(--akashic-input-radius, 0.375rem);
      border: var(--akashic-input-border, 1px solid currentColor);
      background: var(--akashic-input-bg, transparent);
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
    [part="top-error"],
    [part="top-success"] {
      font-size: 0.875rem;
      padding: 0.5rem 0.75rem;
      border-radius: var(--akashic-input-radius, 0.375rem);
      border: 1px solid currentColor;
    }
    [part="top-error"] {
      color: var(--akashic-error, #dc2626);
    }
    [part="top-success"] {
      color: var(--akashic-success, #16a34a);
    }
  `;

  override async connectedCallback(): Promise<void> {
    super.connectedCallback();
    await this.loadProfile();
  }

  private async loadProfile(): Promise<void> {
    const res = await apiCall<UserProfile>("/users/me");
    if (res.ok) {
      this.profile = res.data;
      this.noSession = false;
      this.loadError = null;
      return;
    }
    if (res.code === "NO_SESSION") {
      this.noSession = true;
      this.loadError = null;
      dispatchNeedsSignin(this);
      return;
    }
    this.loadError = res.message;
  }

  override render() {
    if (this.noSession) {
      return renderNeedsSignin();
    }
    if (this.loadError) {
      return html`<p part="top-error" role="alert">${this.loadError}</p>`;
    }
    if (!this.profile) {
      return html`<p>Loading…</p>`;
    }

    return html`
      <div part="card">
        ${this.topMsg
          ? html`<div
              part=${this.topMsg.kind === "ok" ? "top-success" : "top-error"}
              role=${this.topMsg.kind === "ok" ? "status" : "alert"}
            >
              ${this.topMsg.text}
            </div>`
          : ""}

        ${this.readOnlyField("Username", this.profile.username)}
        ${this.readOnlyField("User type", prettyUserType(this.profile.user_type))}
        ${this.readOnlyField("Created", formatDate(this.profile.created_at))}
        ${this.readOnlyField(
          "Last login",
          this.profile.last_login_at ? formatDate(this.profile.last_login_at) : "—",
        )}

        ${this.editable
          ? this.editorForm()
          : html`
              ${this.readOnlyField("Display name", this.profile.display_name)}
              ${this.readOnlyField("Email", this.profile.email)}
            `}
      </div>
    `;
  }

  private readOnlyField(label: string, value: string) {
    return html`
      <div part="field">
        <span part="field-label">${label}</span>
        <span part="field-value">${value}</span>
      </div>
    `;
  }

  private editorForm() {
    const p = this.profile!;
    return html`
      <form @submit=${this.onSave} novalidate>
        <div part="field">
          <label part="field-label" for="akashic-profile-display-name">
            Display name
          </label>
          <input
            part="field-input"
            id="akashic-profile-display-name"
            name="display_name"
            type="text"
            autocomplete="name"
            .value=${p.display_name}
            required
          />
        </div>
        <div part="field" style="margin-top: var(--akashic-field-gap, 1rem)">
          <label part="field-label" for="akashic-profile-email">Email</label>
          <input
            part="field-input"
            id="akashic-profile-email"
            name="email"
            type="email"
            autocomplete="email"
            .value=${p.email}
            required
          />
        </div>
        <button
          part="submit-button"
          type="submit"
          ?disabled=${this.busy}
          style="margin-top: var(--akashic-field-gap, 1rem)"
        >
          ${this.busy ? "Saving…" : "Save changes"}
        </button>
      </form>
    `;
  }

  private async onSave(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    if (this.busy || !this.profile) return;
    this.busy = true;
    this.topMsg = null;

    const form = e.currentTarget as HTMLFormElement;
    const data = new FormData(form);
    const next = {
      display_name: String(data.get("display_name") ?? "").trim(),
      email: String(data.get("email") ?? "").trim(),
    };

    // Diff so we only send changed fields — minimises LDAP-modify churn.
    const diff: Record<string, string> = {};
    if (next.display_name !== this.profile.display_name) diff.display_name = next.display_name;
    if (next.email !== this.profile.email) diff.email = next.email;
    if (Object.keys(diff).length === 0) {
      this.topMsg = { kind: "ok", text: "Nothing changed." };
      this.busy = false;
      return;
    }

    const res = await apiCall<{ updated: boolean }>("/users/me", {
      method: "PATCH",
      json: diff,
    });

    if (res.ok) {
      this.topMsg = { kind: "ok", text: "Profile updated." };
      // Re-fetch to reflect server-canonicalised values.
      await this.loadProfile();
      this.dispatchEvent(
        new CustomEvent("akashic-profile-updated", { bubbles: true, composed: true }),
      );
    } else if (res.code === "NO_SESSION") {
      this.noSession = true;
      dispatchNeedsSignin(this);
    } else {
      this.topMsg = { kind: "err", text: res.message || "Update failed." };
    }
    this.busy = false;
  }
}

function prettyUserType(t: string): string {
  if (t === "user") return "Standard";
  return t.charAt(0).toUpperCase() + t.slice(1);
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "akashic-profile": AkashicProfile;
  }
  interface HTMLElementEventMap {
    "akashic-profile-updated": CustomEvent<void>;
  }
}
