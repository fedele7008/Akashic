import { useEffect, useRef, useState } from 'react';

/**
 * ConfirmModal — Phase 8c.3.
 *
 * A blocking dialog used to gate destructive operator actions
 * (server quit, auth/api stop). When `confirmPhrase` is supplied,
 * the operator must type it verbatim before the Confirm button
 * enables — the AWS pattern for production deletions. When
 * omitted, the modal is a simple yes/no.
 *
 * Closes on Escape, click outside the dialog, or the Cancel
 * button. The Confirm button does NOT close the modal — the
 * caller decides (via `onConfirm`'s resolution) whether to close
 * after the action completes.
 *
 * Why a custom modal rather than `<dialog>` or a library:
 * `<dialog>` is fine but has quirks around backdrop styling and
 * focus return; for a single-use confirm-pattern we get cleaner
 * control with a plain absolutely-positioned div. No library
 * because adding one for a single component is heavy.
 */
export function ConfirmModal({
  open,
  title,
  body,
  confirmPhrase,
  confirmLabel = 'Confirm',
  destructive = false,
  busy = false,
  onConfirm,
  onCancel,
  errorMessage,
}: {
  open: boolean;
  title: string;
  body: React.ReactNode;
  /** When supplied, operator must type this string verbatim to
   *  enable the Confirm button. */
  confirmPhrase?: string;
  confirmLabel?: string;
  /** Render the Confirm button in red (destructive style). */
  destructive?: boolean;
  /** Disable both buttons + show "Working…" while the action runs. */
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  /** Inline error from a previous failed attempt; cleared by the
   *  caller before each new submission. */
  errorMessage?: string | null;
}) {
  const [typed, setTyped] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  // Reset the typed phrase whenever the modal closes/reopens, so a
  // partial entry from a previous open doesn't carry over.
  useEffect(() => {
    if (open) {
      setTyped('');
      // Focus the input on open. Defer one tick so the element is
      // mounted before we focus.
      const t = setTimeout(() => inputRef.current?.focus(), 0);
      return () => clearTimeout(t);
    }
  }, [open]);

  // Escape closes the modal (operator-friendly default).
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !busy) onCancel();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, busy, onCancel]);

  if (!open) return null;

  const phraseSatisfied =
    confirmPhrase === undefined || typed.trim() === confirmPhrase;
  const confirmEnabled = phraseSatisfied && !busy;

  return (
    <div
      className="modal-backdrop"
      role="presentation"
      onClick={(e) => {
        // Close on backdrop click, but not on clicks inside the
        // dialog itself (those bubble through here unless we stop).
        if (e.target === e.currentTarget && !busy) onCancel();
      }}
    >
      <div
        className="modal-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="confirm-modal-title"
      >
        <h3 id="confirm-modal-title" className="modal-title">{title}</h3>
        <div className="modal-body">{body}</div>

        {confirmPhrase !== undefined && (
          <label className="modal-confirm-phrase">
            <span>
              Type <code>{confirmPhrase}</code> to confirm:
            </span>
            <input
              ref={inputRef}
              type="text"
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              disabled={busy}
              autoComplete="off"
              spellCheck={false}
              autoCapitalize="off"
            />
          </label>
        )}

        {errorMessage && (
          <p className="error" role="alert" style={{ marginTop: '0.75rem' }}>
            {errorMessage}
          </p>
        )}

        <div className="modal-actions">
          <button
            type="button"
            className="secondary"
            onClick={onCancel}
            disabled={busy}
          >
            Cancel
          </button>
          <button
            type="button"
            className={destructive ? 'destructive' : 'primary'}
            onClick={onConfirm}
            disabled={!confirmEnabled}
          >
            {busy ? 'Working…' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
