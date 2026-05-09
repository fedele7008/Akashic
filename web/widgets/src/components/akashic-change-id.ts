/**
 * <akashic-change-id> — let the signed-in user change their account ID
 * and/or tag (the two halves of the Discord-style `id#TAG` uid).
 *
 * Authenticated. Calls api.<tenant>/users/me/uid (PATCH). The api
 * server validates, enforces the operator-configured rotation
 * cooldown, performs the LDAP `modrdn` rename, then updates the PG
 * row + writes `last_uid_changed_at`.
 *
 * Body semantics (mirrored from /users/register):
 *   - Empty `username` field → server keeps the user's CURRENT id-base
 *     (extracted from their LDAP DN). So a user named `alice` who
 *     just rotates their tag stays as `alice#<new-tag>`.
 *   - Empty `tag` field → server auto-generates a fresh 4-char base36
 *     tag. Same flow as registration.
 *   - Submitting both blank is rejected at the server with
 *     `VALIDATION_FAILED`; we mirror that as a top-of-form error.
 *
 * Events:
 *   `akashic-needs-signin` — no live session.
 *   `akashic-uid-changed`  — emitted after a successful rotation.
 *                            CustomEvent.detail = { uid, ldap_dn }
 *
 * Headless. Style via:
 *   akashic-change-id::part(form)
 *   akashic-change-id::part(current-card), ::part(current-label),
 *     ::part(current-value)
 *   akashic-change-id::part(field), ::part(field-label),
 *     ::part(field-input), ::part(field-error), ::part(field-hint)
 *   akashic-change-id::part(field-row), ::part(field-row-cell),
 *     ::part(field-row-hint)
 *   akashic-change-id::part(submit-button)
 *   akashic-change-id::part(top-error), ::part(top-info), ::part(success)
 *   akashic-change-id::part(needs-signin)
 */

import { LitElement, html, css } from "lit";
import { customElement, state } from "lit/decorators.js";

import { apiCall, clearCachedToken } from "../lib/api";
import { dispatchNeedsSignin, renderNeedsSignin } from "../lib/needs-signin";

interface FieldErrors {
  username?: string;
  tag?: string;
}

interface UserProfile {
  id: string;
  username: string; // current full uid, e.g. "alice#A8F3"
  email: string;
  display_name: string;
}

interface ChangeUIDOk {
  changed: boolean;
  uid: string;
  ldap_dn: string;
  last_uid_changed_at?: string;
}

interface CooldownDetails {
  next_allowed_at?: string;
  cooldown_days?: number;
  last_changed_at?: string;
}

@customElement("akashic-change-id")
export class AkashicChangeID extends LitElement {
  @state() private busy = false;
  @state() private noSession = false;
  @state() private profile: UserProfile | null = null;
  @state() private loadError: string | null = null;
  @state() private done: ChangeUIDOk | null = null;
  @state() private topError: string | null = null;
  @state() private topInfo: string | null = null;
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
    [part="current-card"] {
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
      padding: 0.5rem 0.75rem;
      border-radius: var(--akashic-input-radius, 0.375rem);
      border: var(--akashic-input-border, 1px solid currentColor);
      background: var(--akashic-input-bg, transparent);
    }
    [part="current-label"] {
      font-size: 0.75rem;
      font-weight: 500;
      color: var(--akashic-text-muted, currentColor);
      opacity: 0.8;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    [part="current-value"] {
      font-size: 1rem;
      font-family: var(--akashic-mono, ui-monospace, monospace);
      word-break: break-word;
    }
    [part="field"] {
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
    }
    /* Side-by-side id + tag, same shape as <akashic-signup>.
       align-items: flex-end keeps the inputs on the same baseline
       even when the labels' rendered heights differ. min-width: 0
       lets the cells shrink below their intrinsic content width
       (the 4-char tag input would otherwise pin its cell wide). */
    [part="field-row"] {
      display: flex;
      flex-direction: row;
      gap: 0.75rem;
      align-items: flex-end;
    }
    [part="field-row-cell"] {
      min-width: 0;
    }
    [part="field-row-cell"][data-cell="tag"] {
      flex: 0 0 6rem;
    }
    [part="field-row-hint"] {
      color: var(--akashic-text-muted, currentColor);
      opacity: 0.7;
      font-size: 0.75rem;
      margin-top: -0.5rem;
    }
    [part="field-label"] {
      font-size: 0.875rem;
      font-weight: 500;
      white-space: nowrap;
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
    [part="top-error"],
    [part="top-info"] {
      font-size: 0.875rem;
      padding: 0.5rem 0.75rem;
      border-radius: var(--akashic-input-radius, 0.375rem);
      border: 1px solid currentColor;
    }
    [part="top-error"] {
      color: var(--akashic-error, #dc2626);
    }
    [part="top-info"] {
      color: var(--akashic-text-muted, currentColor);
    }
    [part="success"] {
      color: var(--akashic-success, #16a34a);
      font-size: 0.875rem;
      padding: 0.5rem 0.75rem;
      border-radius: var(--akashic-input-radius, 0.375rem);
      border: 1px solid var(--akashic-success, #16a34a);
    }
    [part="success-uid"] {
      font-family: var(--akashic-mono, ui-monospace, monospace);
      font-weight: 600;
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
      dispatchNeedsSignin(this);
      return;
    }
    this.loadError = res.message;
  }

  override render() {
    if (this.noSession) return renderNeedsSignin();
    if (this.loadError) {
      return html`<p part="top-error" role="alert">${this.loadError}</p>`;
    }
    if (!this.profile) {
      return html`<p>Loading…</p>`;
    }
    if (this.done) {
      return html`
        <div part="success" role="status">
          Account ID updated. You are now
          <span part="success-uid">${this.done.uid}</span>.
          Existing sessions and tokens stay valid.
        </div>
      `;
    }

    return html`
      <form part="form" @submit=${this.onSubmit} novalidate>
        <div part="current-card">
          <span part="current-label">Current ID</span>
          <span part="current-value">${this.profile.username}</span>
        </div>

        ${this.topError
          ? html`<div part="top-error" role="alert">${this.topError}</div>`
          : ""}
        ${this.topInfo
          ? html`<div part="top-info" role="status">${this.topInfo}</div>`
          : ""}

        <div part="field-row">
          <div part="field-row-cell" style="flex: 1 1 auto;">
            ${this.field({
              name: "username",
              label: "New ID",
              error: this.fieldErrors.username,
            })}
          </div>
          <div part="field-row-cell" data-cell="tag">
            ${this.field({
              name: "tag",
              label: "New Tag",
              error: this.fieldErrors.tag,
            })}
          </div>
        </div>
        <span part="field-row-hint">
          Leave a field blank to keep your current ID or auto-generate
          a fresh tag. Submitting both blank does nothing.
        </span>

        <button part="submit-button" type="submit" ?disabled=${this.busy}>
          ${this.busy ? "Updating…" : "Update ID"}
        </button>
      </form>
    `;
  }

  private field(opts: {
    name: keyof FieldErrors;
    label: string;
    error?: string;
  }) {
    const id = `akashic-cid-${opts.name}`;
    return html`
      <label part="field" for=${id}>
        <span part="field-label">${opts.label}</span>
        <input
          part="field-input"
          id=${id}
          name=${opts.name}
          type="text"
          autocomplete="off"
          aria-invalid=${opts.error ? "true" : "false"}
        />
        ${opts.error
          ? html`<span part="field-error" role="alert">${opts.error}</span>`
          : ""}
      </label>
    `;
  }

  private async onSubmit(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    if (this.busy) return;
    this.busy = true;
    this.topError = null;
    this.topInfo = null;
    this.fieldErrors = {};

    const form = e.currentTarget as HTMLFormElement;
    const data = new FormData(form);
    const wantedID = String(data.get("username") ?? "").trim();
    const wantedTag = String(data.get("tag") ?? "").trim();

    if (!wantedID && !wantedTag) {
      this.topError = "Enter a new ID, a new tag, or both.";
      this.busy = false;
      return;
    }

    // Only include keys the user actually supplied — empty strings
    // would be rejected by the server's "VALIDATION_FAILED" check
    // before it even sees that the OTHER field has content.
    const payload: Record<string, string> = {};
    if (wantedID) payload.username = wantedID;
    if (wantedTag) payload.tag = wantedTag;

    const res = await apiCall<ChangeUIDOk>("/users/me/uid", {
      method: "PATCH",
      json: payload,
    });

    if (res.ok) {
      if (res.data.changed === false) {
        // No-op short-circuit: the resolved uid matched the current
        // one. Server didn't burn the cooldown, so this is more
        // informational than a success.
        this.topInfo = `That's already your ID (${res.data.uid}). Nothing to update.`;
        this.busy = false;
        return;
      }
      this.done = res.data;
      this.busy = false;
      // The bearer's `sub` claim is the user's UUID, not their uid,
      // so the token stays valid through a rotation. We still clear
      // any cached one to make sure the next call re-mints with
      // up-to-date claims. (Belt-and-braces; not strictly required.)
      clearCachedToken();
      this.dispatchEvent(
        new CustomEvent("akashic-uid-changed", {
          bubbles: true,
          composed: true,
          detail: { uid: res.data.uid, ldap_dn: res.data.ldap_dn },
        }),
      );
      return;
    }

    switch (res.code) {
      case "NO_SESSION":
        this.noSession = true;
        dispatchNeedsSignin(this);
        break;
      case "UID_CHANGE_COOLDOWN_ACTIVE":
        this.topError = formatCooldownMessage(res.details);
        break;
      case "ID_INVALID":
        this.fieldErrors = {
          username:
            "ID must be 2–32 characters of letters, digits, dots, hyphens, or underscores.",
        };
        break;
      case "TAG_INVALID":
        this.fieldErrors = {
          tag: "Tag must be exactly 4 characters using 0–9 and A–Z.",
        };
        break;
      case "UID_TAKEN":
        this.fieldErrors = {
          tag: "That ID + tag combination is already taken. Try a different tag, or leave it blank to auto-pick.",
        };
        break;
      case "USERNAME_UNAVAILABLE":
        this.topError =
          "Could not generate a unique ID. Retry or supply an explicit tag.";
        break;
      case "VALIDATION_FAILED":
        this.topError = res.message || "Invalid request.";
        break;
      default:
        this.topError = res.message || "Could not change ID.";
    }
    this.busy = false;
  }
}

/**
 * Render the cooldown 409's `details` payload into a human sentence.
 * Server returns ISO-8601 timestamps + integer day count; we format
 * the absolute "next allowed" date in the user's locale and add a
 * relative-day hint when it's reasonably close.
 */
function formatCooldownMessage(details?: Record<string, unknown>): string {
  const d = (details ?? {}) as CooldownDetails;
  const fallback =
    "ID rotation is rate-limited by the operator's policy. Try again later.";
  if (!d.next_allowed_at) return fallback;
  let when: Date;
  try {
    when = new Date(d.next_allowed_at);
    if (Number.isNaN(when.getTime())) return fallback;
  } catch {
    return fallback;
  }
  const absolute = when.toLocaleString();
  const msLeft = when.getTime() - Date.now();
  if (msLeft <= 0) {
    // Edge case: server clock vs. browser clock drift. Tell the user
    // to retry rather than blocking the UI.
    return "ID rotation cooldown just elapsed. Retry the form.";
  }
  const daysLeft = Math.ceil(msLeft / (24 * 60 * 60 * 1000));
  const cd = typeof d.cooldown_days === "number" ? d.cooldown_days : null;
  const policyHint = cd ? ` (operator policy: ${cd} day${cd === 1 ? "" : "s"})` : "";
  return `You changed your ID recently. You can change it again on ${absolute} (in about ${daysLeft} day${daysLeft === 1 ? "" : "s"})${policyHint}.`;
}

declare global {
  interface HTMLElementTagNameMap {
    "akashic-change-id": AkashicChangeID;
  }
  interface HTMLElementEventMap {
    "akashic-uid-changed": CustomEvent<{ uid: string; ldap_dn: string }>;
  }
}
