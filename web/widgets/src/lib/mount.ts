/**
 * Programmatic mount helper. Tenants who can drop a custom element
 * directly into HTML should use that — `<akashic-signup></akashic-signup>`.
 * This helper is for cases where the tenant's framework controls
 * rendering (e.g., conditional UI based on app state) and they'd
 * rather mount widgets via JS.
 */

export type WidgetName =
  | "signup"
  | "profile"
  | "change-password"
  | "forgot-help"
  | "clients";

export interface MountOptions {
  widget: WidgetName;
  /** Forwarded as element attributes (string-only). */
  attrs?: Record<string, string>;
}

export function mount(target: string | Element, opts: MountOptions): Element {
  const el = typeof target === "string" ? document.querySelector(target) : target;
  if (!el) throw new Error(`Akashic.mount: target not found: ${String(target)}`);

  const tag = `akashic-${opts.widget}`;
  const widget = document.createElement(tag);
  if (opts.attrs) {
    for (const [k, v] of Object.entries(opts.attrs)) widget.setAttribute(k, v);
  }
  el.replaceChildren(widget);
  return widget;
}
