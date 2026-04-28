/**
 * <akashic-signin> — OAuth-launcher button.
 *
 * NOT a credential-entry widget. The user does NOT type their
 * password on the embedding page; this widget just navigates the
 * browser to the operator-configured OAuth-start URL, which lands
 * the user on `auth.<tenant>/login`. Once authenticated, they
 * round-trip back to the tenant page via the standard OAuth
 * redirect chain (BFF callback → tenant session → page reload).
 *
 * Why this exists alongside a plain `<a href>`:
 *   - Consistent styling tokens with other Akashic widgets
 *     (--akashic-button-bg, etc. — one design vocabulary).
 *   - `::part(button)` for full theming.
 *   - Optional `return-to` attribute that's URL-encoded properly,
 *     saving tenants from re-implementing param construction.
 *
 * Headless. Style via:
 *   akashic-signin::part(button)
 *
 * Usage (most tenants):
 *   <akashic-signin>Sign in</akashic-signin>
 *
 * Usage (with optional return target after sign-in):
 *   <akashic-signin return-to="/dashboard">Sign in</akashic-signin>
 *
 * Usage (tenant without a BFF — point at auth-server directly):
 *   <akashic-signin
 *     authorize-url="https://auth.acme.com/authorize?client_id=...&...">
 *     Sign in
 *   </akashic-signin>
 *
 * Attributes (all optional):
 *   authorize-url  Where to navigate on click. Default:
 *                   "/api/auth/authorize" — the BFF route the
 *                   sample portal exposes (and the conventional
 *                   path tenants with a BFF will also have). Set
 *                   only when you don't have a BFF and need to hit
 *                   the auth server directly with full OAuth params.
 *   return-to       Appended as `?return_to=<value>` query param.
 *                   Most BFFs honour this to bring the user back to
 *                   a specific page after sign-in.
 *
 * Slot (default): button label content. If empty, defaults to
 *   "Sign in".
 *
 * Event:
 *   `akashic-signin-clicked` — fired immediately before navigation.
 *   Cancellable via `event.preventDefault()` if the embedding page
 *   wants to intercept (e.g., show a confirmation dialog).
 */

import { LitElement, html, css } from "lit";
import { customElement, property } from "lit/decorators.js";

@customElement("akashic-signin")
export class AkashicSignin extends LitElement {
  /** Where to navigate on click. */
  @property({ type: String, attribute: "authorize-url" })
  authorizeUrl = "/api/auth/authorize";

  /** Optional ?return_to= query value. */
  @property({ type: String, attribute: "return-to" })
  returnTo: string | null = null;

  static override styles = css`
    :host {
      display: inline-block;
      color: var(--akashic-text, inherit);
      font-family: var(--akashic-font-family, inherit);
    }
    [part="button"] {
      font: inherit;
      color: var(--akashic-button-fg, white);
      background: var(--akashic-button-bg, #4f8cff);
      border: none;
      padding: 0.5rem 1rem;
      border-radius: var(--akashic-input-radius, 0.375rem);
      cursor: pointer;
    }
    [part="button"]:hover {
      opacity: 0.9;
    }
    [part="button"]:focus {
      outline: 2px solid var(--akashic-button-bg, #4f8cff);
      outline-offset: 2px;
    }
  `;

  override render() {
    return html`
      <button part="button" type="button" @click=${this.onClick}>
        <slot>Sign in</slot>
      </button>
    `;
  }

  private onClick(): void {
    // Surface a cancellable event so embedders can intercept (e.g.
    // for telemetry, "are you sure?" dialogs, or override navigation).
    const evt = new CustomEvent("akashic-signin-clicked", {
      bubbles: true,
      composed: true,
      cancelable: true,
    });
    const proceed = this.dispatchEvent(evt);
    if (!proceed) return;

    let url = this.authorizeUrl || "/api/auth/authorize";
    if (this.returnTo) {
      // URL-encode the return target so embedders don't need to do
      // it themselves. Append as query — this assumes the authorize
      // URL doesn't already carry one.
      const sep = url.includes("?") ? "&" : "?";
      url = `${url}${sep}return_to=${encodeURIComponent(this.returnTo)}`;
    }
    window.location.href = url;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "akashic-signin": AkashicSignin;
  }
  interface HTMLElementEventMap {
    "akashic-signin-clicked": CustomEvent<void>;
  }
}
