/**
 * Minimal button primitive.
 *
 * Three variants:
 *   - primary  — accent-coloured CTA (one per surface, ideally)
 *   - ghost    — flat, no-fill secondary action
 *   - link     — looks like a link but accepts button semantics
 *
 * Loading state: when `loading` is true, the button disables itself
 * and swaps text for a spinner. Used by the sign-up form so the
 * user can't double-submit while we wait on the api server.
 */

import type { ButtonHTMLAttributes } from "react";

type Variant = "primary" | "ghost" | "link";

const variantClasses: Record<Variant, string> = {
  primary:
    "bg-[var(--accent)] text-white hover:opacity-90 active:opacity-100 shadow-sm focus:ring-2 focus:ring-[var(--accent)]/40",
  ghost:
    "bg-transparent text-[var(--text)] border border-[var(--text-muted)]/30 hover:bg-[var(--card)] focus:ring-2 focus:ring-[var(--text-muted)]/30",
  link: "bg-transparent text-[var(--accent)] hover:underline px-0 py-0 focus:ring-0",
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  loading?: boolean;
}

export function Button({
  variant = "primary",
  loading = false,
  disabled,
  children,
  className = "",
  ...rest
}: ButtonProps) {
  const base =
    "inline-flex items-center justify-center rounded-md text-sm font-medium px-4 py-2 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none";
  return (
    <button
      {...rest}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={`${base} ${variantClasses[variant]} ${className}`}
    >
      {loading ? <Spinner /> : children}
    </button>
  );
}

function Spinner() {
  return (
    <span
      className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"
      aria-hidden
    />
  );
}
