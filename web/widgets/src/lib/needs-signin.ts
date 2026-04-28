/**
 * Shared "you're not signed in" surface for authenticated widgets.
 *
 * Rather than every auth-required widget reinventing the sign-in
 * prompt, they all import `dispatchNeedsSignin()` and render
 * `renderNeedsSignin()` when the api returns NO_SESSION.
 *
 * The widget itself is intentionally dumb about HOW to sign in —
 * that's the embedding page's call (it might redirect to an OAuth
 * client, open a modal, swap to a sign-up flow, etc.). The widget
 * just emits a `akashic-needs-signin` event and shows a minimal
 * fallback message; tenants supply their own CTA via the
 * `signin-cta` slot.
 */

import { html, type TemplateResult } from "lit";
import type { LitElement } from "lit";

/** Dispatch the cross-cutting "user is not signed in" event. */
export function dispatchNeedsSignin(el: LitElement): void {
  el.dispatchEvent(
    new CustomEvent("akashic-needs-signin", {
      bubbles: true,
      composed: true,
    }),
  );
}

/**
 * Default render for the no-session state. Widgets pass a Lit
 * template that gets shown inside the standard layout. The
 * `<slot name="signin-cta">` lets the tenant page provide its own
 * sign-in button (an OAuth-start link, typically); the fallback
 * is a quiet text instruction.
 */
export function renderNeedsSignin(): TemplateResult {
  return html`
    <div part="needs-signin" role="status">
      <p part="needs-signin-message">
        You need to sign in to view this.
      </p>
      <slot name="signin-cta">
        <span part="needs-signin-fallback">
          Ask the page you're on for a sign-in link.
        </span>
      </slot>
    </div>
  `;
}
