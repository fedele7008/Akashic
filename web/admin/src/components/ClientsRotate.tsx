import { useState } from 'react';
import {
  ClientsApi,
  type ApiError,
  type ClientView,
  type RotateSecretResponse,
} from '../api/client';

/**
 * ClientsRotate — full-card takeover that issues a new client_secret
 * and renders the result with the same shown-once panel as the
 * registration flow.
 *
 * Two-stage UX:
 *   1. confirm  → "rotate now?" with a clear warning that old secret
 *                 dies immediately
 *   2. result   → new plaintext secret + copy button + Done
 *
 * Auto-fires the rotate the moment the operator clicks Confirm. No
 * type-the-id step here (unlike Delete) — rotation is reversible by
 * doing it again, while delete is permanent. Same friction-budget
 * reasoning that AWS / Auth0 / Okta apply.
 */
export function ClientsRotate({
  client,
  onClose,
}: {
  client: ClientView;
  onClose: () => void;
}) {
  const [stage, setStage] = useState<'confirm' | 'busy' | 'done'>('confirm');
  const [result, setResult] = useState<RotateSecretResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [secretCopied, setSecretCopied] = useState(false);

  const handleRotate = async () => {
    setStage('busy');
    setErr(null);
    try {
      const resp = await ClientsApi.rotateSecret(client.client_id);
      setResult(resp);
      setStage('done');
    } catch (e) {
      const apiErr = (e as Error & { apiError?: ApiError }).apiError;
      setErr(apiErr?.message ?? (e as Error).message);
      setStage('confirm');
    }
  };

  const handleCopy = async () => {
    if (!result?.client_secret) return;
    try {
      await navigator.clipboard.writeText(result.client_secret);
      setSecretCopied(true);
      setTimeout(() => setSecretCopied(false), 2000);
    } catch {
      // Clipboard API can fail on insecure origins or denied perms;
      // operator can still triple-click the monospace value.
    }
  };

  // ─── done state ────────────────────────────────────────────────
  if (stage === 'done' && result) {
    return (
      <div className="card">
        <h2>Client secret rotated</h2>

        <dl className="kv">
          <dt>Client ID</dt>
          <dd><code>{result.client_id}</code></dd>
          <dt>Name</dt>
          <dd>{client.name}</dd>
        </dl>

        <div
          style={{
            marginTop: '1rem',
            padding: '1rem',
            border: '2px solid #f59e0b',
            borderRadius: '0.375rem',
            background: 'rgba(245, 158, 11, 0.08)',
          }}
        >
          <p style={{ fontWeight: 600, marginTop: 0 }}>
            ⚠ New client secret — shown ONCE
          </p>
          <p style={{ fontSize: '0.875rem', marginBottom: '0.5rem' }}>
            Copy this value now and update your portal's secret store
            before its next OAuth flow. The old secret is invalid as of
            this moment.
          </p>
          <code
            style={{
              display: 'block',
              padding: '0.5rem',
              background: 'rgba(0,0,0,0.3)',
              borderRadius: '0.25rem',
              wordBreak: 'break-all',
              fontFamily: 'ui-monospace, monospace',
              fontSize: '0.875rem',
            }}
          >
            {result.client_secret}
          </code>
          <button
            type="button"
            onClick={handleCopy}
            className="primary"
            style={{ marginTop: '0.75rem' }}
          >
            {secretCopied ? '✓ Copied' : 'Copy secret'}
          </button>
        </div>

        <div className="actions" style={{ marginTop: '1.5rem' }}>
          <button type="button" onClick={onClose} className="secondary">
            Done
          </button>
        </div>
      </div>
    );
  }

  // ─── confirm state ─────────────────────────────────────────────
  return (
    <div className="card">
      <h2>Rotate client secret?</h2>

      <dl className="kv">
        <dt>Client ID</dt>
        <dd><code>{client.client_id}</code></dd>
        <dt>Name</dt>
        <dd>{client.name}</dd>
        <dt>Type</dt>
        <dd>{client.client_type}</dd>
      </dl>

      <p className="hint" style={{ marginTop: '1rem' }}>
        A fresh client_secret will be generated. The old secret becomes
        invalid <strong>immediately</strong> — any portal still using it
        will fail its next /token call until you update its config.
      </p>

      {err && (
        <p className="error" style={{ marginTop: '1rem' }}>
          {err}
        </p>
      )}

      <div className="actions" style={{ marginTop: '1.5rem' }}>
        <button
          type="button"
          onClick={() => void handleRotate()}
          className="primary"
          disabled={stage === 'busy'}
        >
          {stage === 'busy' ? 'Rotating…' : 'Rotate now'}
        </button>
        <button
          type="button"
          onClick={onClose}
          className="secondary"
          disabled={stage === 'busy'}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
