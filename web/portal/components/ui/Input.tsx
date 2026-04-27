/**
 * Labelled input. Encapsulates the label-text-error layout so every
 * form field stays visually consistent. Use `error` to surface the
 * red message under the input; `hint` for neutral helper text.
 */

import type { InputHTMLAttributes, ReactNode } from "react";

export interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  error?: string | null;
  hint?: ReactNode;
}

export function Input({
  label,
  error,
  hint,
  id,
  className = "",
  ...rest
}: InputProps) {
  const fieldId = id ?? rest.name;
  return (
    <label htmlFor={fieldId} className="block">
      <span className="text-sm font-medium text-[var(--text)] block mb-1">{label}</span>
      <input
        id={fieldId}
        {...rest}
        aria-invalid={error ? "true" : undefined}
        aria-describedby={error ? `${fieldId}-error` : hint ? `${fieldId}-hint` : undefined}
        className={`block w-full rounded-md border bg-[var(--card)] px-3 py-2 text-sm text-[var(--text)] placeholder:text-[var(--text-muted)] focus:outline-none focus:ring-2 focus:ring-[var(--accent)]/40 ${
          error
            ? "border-red-500"
            : "border-[var(--text-muted)]/30 focus:border-[var(--accent)]"
        } ${className}`}
      />
      {error ? (
        <p id={`${fieldId}-error`} className="mt-1 text-xs text-red-400">
          {error}
        </p>
      ) : hint ? (
        <p id={`${fieldId}-hint`} className="mt-1 text-xs text-[var(--text-muted)]">
          {hint}
        </p>
      ) : null}
    </label>
  );
}
