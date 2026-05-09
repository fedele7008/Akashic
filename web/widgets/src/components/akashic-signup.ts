/**
 * <akashic-signup> — public registration form widget.
 *
 * Calls api.<tenant>/users/register (no auth, public endpoint).
 * On success, fires an `akashic-signup-success` CustomEvent so the
 * embedding page can redirect to its post-signup flow (typically
 * the OAuth /authorize URL to log the new user in immediately).
 *
 * Headless by default: every styleable region is exposed via
 * `part="..."` attributes; tenants style with their own CSS rules
 * targeting `akashic-signup::part(...)`. The optional default
 * stylesheet (akashic-default.css) provides a baseline look.
 */

import { LitElement, html, css } from "lit";
import { customElement, state } from "lit/decorators.js";

import { apiCallPublic } from "../lib/api";

interface FieldErrors {
  username?: string;
  tag?: string;
  email?: string;
  password?: string;
  password_confirm?: string;
  display_name?: string;
}

interface SignupOk {
  user: {
    id: string;
    username: string;
    email: string;
    ldap_dn: string;
  };
}

/**
 * Mirrors `auth.PasswordPolicy` (pkg/auth/password.go) returned by
 * `GET /users/password-policy`. Used for client-side pre-validation;
 * the server is still authoritative.
 */
interface PasswordPolicy {
  min_length: number;
  require_uppercase: boolean;
  require_lowercase: boolean;
  require_number: boolean;
  require_special: boolean;
}

/**
 * Sensible default that's shown immediately at widget mount, before
 * the policy fetch lands. Matches the most-common production policy
 * so the hint text doesn't flicker if the fetch is slow. Replaced
 * with the server's actual policy as soon as the response arrives.
 */
const FALLBACK_POLICY: PasswordPolicy = {
  min_length: 12,
  require_uppercase: true,
  require_lowercase: true,
  require_number: true,
  require_special: true,
};

/**
 * Run the same character-class checks the server applies in
 * `auth.PasswordPolicy.Validate`. Returns the FIRST policy violation
 * (server returns one error at a time too); empty string means the
 * password passes. Pre-flight only — the server re-validates and is
 * authoritative on every /users/register POST.
 */
function checkPassword(pw: string, policy: PasswordPolicy): string {
  if (pw.length < policy.min_length) {
    return `Password must be at least ${policy.min_length} characters long.`;
  }
  if (policy.require_uppercase && !/[A-Z]/.test(pw)) {
    return "Password must contain at least one uppercase letter.";
  }
  if (policy.require_lowercase && !/[a-z]/.test(pw)) {
    return "Password must contain at least one lowercase letter.";
  }
  if (policy.require_number && !/\d/.test(pw)) {
    return "Password must contain at least one number.";
  }
  if (policy.require_special && !/[^A-Za-z0-9]/.test(pw)) {
    return "Password must contain at least one special character.";
  }
  return "";
}

/**
 * Render the policy as a single-line hint shown under the password
 * field. Reads naturally even when only some rules are enabled
 * (e.g. min-length only would render "At least 8 characters.").
 */
function policyHint(policy: PasswordPolicy): string {
  const parts: string[] = [`At least ${policy.min_length} characters`];
  const required: string[] = [];
  if (policy.require_uppercase) required.push("uppercase");
  if (policy.require_lowercase) required.push("lowercase");
  if (policy.require_number) required.push("number");
  if (policy.require_special) required.push("special character");
  if (required.length > 0) parts.push("with " + required.join(", "));
  return parts.join(" ") + ".";
}

@customElement("akashic-signup")
export class AkashicSignup extends LitElement {
  @state() private busy = false;
  @state() private topError: string | null = null;
  @state() private fieldErrors: FieldErrors = {};
  @state() private done = false;
  /**
   * Live policy from the server. Starts at FALLBACK_POLICY so the
   * hint renders immediately; gets replaced once `connectedCallback`
   * finishes the fetch. The displayed hint and `checkPassword`
   * predicate both read from this state field, so the UI updates
   * automatically when the fetch lands.
   */
  @state() private policy: PasswordPolicy = FALLBACK_POLICY;

  override connectedCallback() {
    super.connectedCallback();
    // Fetch the server's password policy once when the widget mounts
    // so the hint text + client-side validation match the server's
    // accept criteria. Failure is non-fatal — we keep FALLBACK_POLICY
    // and the server's /users/register response will surface any
    // mismatch as a PASSWORD_POLICY_VIOLATION error.
    void this.loadPasswordPolicy();
  }

  private async loadPasswordPolicy() {
    const res = await apiCallPublic<PasswordPolicy>("/users/password-policy");
    if (res.ok) {
      this.policy = res.data;
    }
  }

  // Open shadow DOM by default — tenants style via `::part()` and
  // the `--akashic-*` CSS custom properties documented in
  // doc/widgets-styling.md (Phase 8b Step 9).
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
    /* Side-by-side layout for the id + tag pair. Tenants who want
       a stacked layout can override by setting flex-direction:
       column on this part.

       align-items: flex-end is load-bearing — when the cell labels
       have different heights (e.g. "Tag (optional)" wraps to two
       lines in a tight cell while "ID (optional)" stays one),
       anchoring to the bottom keeps both inputs on the same baseline.

       min-width: 0 on the cells lets them shrink below their
       default content width — without it, the 4-char tag input's
       intrinsic content size keeps its cell wide enough to push
       the row past the form. */
    [part="field-row"] {
      display: flex;
      flex-direction: row;
      gap: 0.75rem;
      align-items: flex-end;
    }
    [part="field-row-cell"] {
      min-width: 0;
    }
    /* The tag cell needs enough room for its label to render on
       one line + a 4-char input. Without this, narrow forms
       wrap "Tag (optional)" to two lines, making the column
       taller than the id column even with align-items: flex-end
       (the label content still occupies more vertical space than
       its sibling). 6rem fits the label in typical UI fonts. */
    [part="field-row-cell"][data-cell="tag"] {
      flex: 0 0 6rem;
    }
    [part="field-label"] {
      font-size: 0.875rem;
      font-weight: 500;
      /* Prevent labels from wrapping in narrow cells (the side-by-side
         id+tag layout puts tag in a ~6rem cell where any non-trivial
         label string would otherwise fold to two lines, breaking the
         row's visual alignment). Overflow stays visible — a too-long
         label spills into adjacent space rather than silently
         re-flowing. */
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
      background: var(--akashic-error-bg, transparent);
    }
    [part="success"] {
      color: var(--akashic-success, #16a34a);
      font-size: 0.875rem;
    }
  `;

  override render() {
    if (this.done) {
      return html`
        <div part="success" role="status">
          Account created. You can sign in now.
        </div>
      `;
    }

    return html`
      <form part="form" @submit=${this.onSubmit} novalidate>
        ${this.topError
          ? html`<div part="top-error" role="alert">${this.topError}</div>`
          : ""}

        ${this.field({
          name: "email",
          label: "Email",
          type: "email",
          autocomplete: "email",
          required: true,
          error: this.fieldErrors.email,
        })}

        <div part="field-row">
          <div part="field-row-cell" style="flex: 1 1 auto;">
            ${this.field({
              name: "username",
              label: "ID",
              type: "text",
              autocomplete: "username",
              required: false,
              error: this.fieldErrors.username,
            })}
          </div>
          <div part="field-row-cell" data-cell="tag">
            ${this.field({
              name: "tag",
              label: "Tag",
              type: "text",
              autocomplete: "off",
              required: false,
              error: this.fieldErrors.tag,
            })}
          </div>
        </div>
        <span part="field-hint" style="margin-top: -0.5rem;">
          ID: 2–32 chars (letters/digits/dots/hyphens/underscores).
          Tag: 4 chars (0–9, A–Z). Both auto-generated if blank;
          final form is <code>id#TAG</code>.
        </span>

        ${this.field({
          name: "password",
          label: "Password",
          type: "password",
          autocomplete: "new-password",
          required: true,
          minLength: this.policy.min_length,
          hint: policyHint(this.policy),
          error: this.fieldErrors.password,
        })}

        ${this.field({
          name: "password_confirm",
          label: "Confirm password",
          type: "password",
          autocomplete: "new-password",
          required: true,
          minLength: this.policy.min_length,
          error: this.fieldErrors.password_confirm,
        })}

        ${this.field({
          name: "display_name",
          label: "Display name (optional)",
          type: "text",
          autocomplete: "name",
          required: false,
          hint: "Defaults to your username.",
          error: this.fieldErrors.display_name,
        })}

        <button part="submit-button" type="submit" ?disabled=${this.busy}>
          ${this.busy ? "Creating…" : "Create account"}
        </button>
      </form>
    `;
  }

  private field(opts: {
    name: keyof FieldErrors | "display_name";
    label: string;
    type: string;
    autocomplete: string;
    required: boolean;
    minLength?: number;
    hint?: string;
    error?: string;
  }) {
    const id = `akashic-signup-${opts.name}`;
    return html`
      <label part="field" for="${id}">
        <span part="field-label">${opts.label}</span>
        <input
          part="field-input"
          id="${id}"
          name="${opts.name}"
          type="${opts.type}"
          autocomplete="${opts.autocomplete}"
          ?required=${opts.required}
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

  private async onSubmit(e: SubmitEvent) {
    e.preventDefault();
    if (this.busy) return;
    this.busy = true;
    this.topError = null;
    this.fieldErrors = {};

    const form = e.currentTarget as HTMLFormElement;
    const data = new FormData(form);
    const payload: Record<string, string> = {
      email: String(data.get("email") ?? "").trim(),
      password: String(data.get("password") ?? ""),
    };
    // Optional id + tag — only include in payload when present so
    // the server treats their absence as "auto-generate" rather
    // than "validate this empty string".
    const wantedID = String(data.get("username") ?? "").trim();
    if (wantedID) payload.username = wantedID;
    const wantedTag = String(data.get("tag") ?? "").trim();
    if (wantedTag) payload.tag = wantedTag;
    const passwordConfirm = String(data.get("password_confirm") ?? "");
    const dn = String(data.get("display_name") ?? "").trim();
    if (dn) payload.display_name = dn;

    // Pre-flight: required-fields, password-policy, password-match.
    // Server re-runs these and is authoritative; the early checks
    // give the user fast feedback without a round-trip. Username
    // is no longer in the required set — see above.
    if (!payload.email || !payload.password) {
      this.topError = "Email and password are required.";
      this.busy = false;
      return;
    }
    const policyError = checkPassword(payload.password, this.policy);
    if (policyError) {
      this.fieldErrors = { ...this.fieldErrors, password: policyError };
      this.busy = false;
      return;
    }
    if (payload.password !== passwordConfirm) {
      // Match check runs AFTER the policy check so a user with a
      // policy-failing password sees the policy error first (more
      // actionable than "passwords don't match" when both fields
      // hold the same too-short value).
      this.fieldErrors = {
        ...this.fieldErrors,
        password_confirm: "Passwords do not match.",
      };
      this.busy = false;
      return;
    }

    const res = await apiCallPublic<SignupOk>("/users/register", {
      method: "POST",
      json: payload,
    });

    if (res.ok) {
      this.done = true;
      this.busy = false;
      // Surface success to the embedding page so it can navigate to
      // its post-signup target (typically /authorize for immediate
      // sign-in).
      this.dispatchEvent(
        new CustomEvent("akashic-signup-success", {
          bubbles: true,
          composed: true,
        }),
      );
      return;
    }

    // Server-side error mapping.
    switch (res.code) {
      case "EMAIL_TAKEN":
        this.fieldErrors = {
          email:
            "An account with that email already exists. Sign in instead, or use a different email.",
        };
        break;
      case "ID_INVALID":
        this.fieldErrors = {
          username:
            "ID must be 2–32 characters of letters, digits, dots, hyphens, or underscores.",
        };
        break;
      case "TAG_INVALID":
        this.fieldErrors = {
          tag: "Tag must be exactly 4 characters using 0–9 and a–z.",
        };
        break;
      case "UID_TAKEN":
        this.fieldErrors = {
          tag:
            "That ID + tag combination is already taken. Try a different tag, or leave it blank to auto-pick.",
        };
        break;
      case "USERNAME_UNAVAILABLE":
        this.topError =
          "Could not generate a unique account ID. Please retry or pick an explicit tag.";
        break;
      case "PASSWORD_POLICY_VIOLATION":
        this.fieldErrors = { password: res.message };
        break;
      case "SIGNUP_DISABLED":
        this.topError =
          "Self-service signup is disabled on this deployment. Contact the operator.";
        break;
      case "BOOTSTRAP_INCOMPLETE":
        this.topError =
          "This deployment is still being set up by its operator. Sign-up will be available once initial setup is complete.";
        break;
      default:
        this.topError = res.message || "Sign-up failed. Please try again.";
    }
    this.busy = false;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "akashic-signup": AkashicSignup;
  }
  interface HTMLElementEventMap {
    "akashic-signup-success": CustomEvent<void>;
  }
}
