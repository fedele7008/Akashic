import { useState } from 'react';
import {
  ClientsApi,
  type ApiError,
  type CreateClientRequest,
  type CreateClientResponse,
} from '../api/client';

/**
 * ClientsCreate — registration form for a new OAuth client.
 *
 * Two states:
 *   - form    → operator fills out name, type, redirect_uri, etc.
 *   - result  → server-issued credentials shown ("secret shown once"
 *               for WEB; just the client_id for SPA).
 *
 * The result state holds the plaintext client_secret in React state
 * for the duration of the component lifetime — once the user closes
 * the panel (clicks "Done") OR navigates away, the secret is
 * unrecoverable. Same UX the CLI's `--save-credentials-to` flag
 * mirrors via a file write; here the operator copy-pastes manually.
 *
 * Footgun copy ("WEB ≠ anything browser-facing") is surfaced inline
 * in the type radio so operators don't have to read external docs to
 * choose correctly. Same disambiguation the CLI shows.
 */
export function ClientsCreate({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState('');
  const [clientType, setClientType] = useState<'WEB' | 'SPA'>('WEB');
  const [redirectURI, setRedirectURI] = useState('');
  const [description, setDescription] = useState('');
  const [requirePKCE, setRequirePKCE] = useState(true);
  const [isTenantPortal, setIsTenantPortal] = useState(false);

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CreateClientResponse | null>(null);
  const [secretCopied, setSecretCopied] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const req: CreateClientRequest = {
        name: name.trim(),
        client_type: clientType,
        redirect_uris: redirectURI.trim(),
      };
      if (description.trim()) req.description = description.trim();
      // Only send require_pkce when WEB + operator explicitly opted
      // out. SPA always-true is enforced server-side regardless;
      // omitting keeps the request honest about operator intent.
      if (clientType === 'WEB' && !requirePKCE) {
        req.require_pkce = false;
      }
      if (isTenantPortal) {
        req.is_tenant_portal = true;
      }
      const resp = await ClientsApi.create(req);
      setResult(resp);
      // Notify any listeners that setup-relevant state may have
      // changed — most notably the SetupStatusBanner, which
      // surfaces "no tenant portal registered" until a flagged
      // client exists. Loose-coupled via a custom DOM event so
      // we don't have to thread a callback through ClientsPage
      // and Dashboard purely for this side-effect.
      if (isTenantPortal) {
        window.dispatchEvent(new CustomEvent('akashic:setup-changed'));
      }
    } catch (e) {
      const err = e as Error & { apiError?: ApiError };
      setError(err.apiError?.message ?? err.message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleCopy = async () => {
    if (!result?.client_secret) return;
    try {
      await navigator.clipboard.writeText(result.client_secret);
      setSecretCopied(true);
      // Reset copy-feedback after 2s so the operator can retry if
      // needed without the button looking permanently locked.
      setTimeout(() => setSecretCopied(false), 2000);
    } catch {
      // Clipboard API can fail on insecure origins or denied perms.
      // Silent fail — the operator can still triple-click the
      // monospace text to select+copy manually.
    }
  };

  // ─── result state ──────────────────────────────────────────────
  if (result) {
    return (
      <div className="card">
        <h2>OAuth client registered</h2>

        <dl className="kv">
          <dt>Client ID</dt>
          <dd><code>{result.client.client_id}</code></dd>
          <dt>Name</dt>
          <dd>{result.client.name}</dd>
          <dt>Type</dt>
          <dd>{result.client.client_type}</dd>
          <dt>Redirect URI</dt>
          <dd><code>{result.client.redirect_uris}</code></dd>
          <dt>PKCE required</dt>
          <dd>{result.client.require_pkce ? 'yes' : 'no (BFF, optional)'}</dd>
        </dl>

        {result.client_secret ? (
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
              ⚠ Client secret — shown ONCE
            </p>
            <p style={{ fontSize: '0.875rem', marginBottom: '0.5rem' }}>
              Copy this value now and store it in your portal's secret manager
              (e.g. <code>.env</code>, Vault, AWS Secrets Manager). Only its
              bcrypt hash persists on the server — you cannot recover this
              secret later. If lost, rotate via the API.
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
        ) : (
          <p className="hint" style={{ marginTop: '1rem' }}>
            No client_secret — this is a public (SPA) client. PKCE replaces the
            shared secret on every authorization.
          </p>
        )}

        <div className="actions" style={{ marginTop: '1.5rem' }}>
          <button type="button" onClick={onClose} className="secondary">
            Done
          </button>
        </div>
      </div>
    );
  }

  // ─── form state ────────────────────────────────────────────────
  return (
    <div className="card">
      <h2>Register a new OAuth client</h2>
      <p className="hint">
        Choose <strong>WEB</strong> if your app has a backend that can store a
        client_secret in a secure place (server-side / BFF). Choose{' '}
        <strong>SPA</strong> if it runs entirely in the browser or as a native
        app with no secret storage. <em>"WEB" doesn't mean
        "anything browser-facing"</em> — a SPA also runs in a browser.
      </p>

      <form onSubmit={handleSubmit}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <label>
            <div>Name <span style={{ color: '#f87171' }}>*</span></div>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="My Portal"
              required
              disabled={submitting}
              style={{ width: '100%' }}
            />
          </label>

          <fieldset style={{ border: '1px solid rgba(255,255,255,0.15)', padding: '0.75rem', borderRadius: '0.375rem' }}>
            <legend style={{ padding: '0 0.5rem', fontSize: '0.875rem' }}>Client type *</legend>
            {/* flexDirection: 'row' explicitly overrides the global
                `label { flex-direction: column }` rule from styles.css
                that's right for "label-on-top, input-below" stacks but
                wrong for radio/checkbox rows. flex:1 on the text span
                makes it take the remaining width so wrapping happens
                AT the right edge, not at the radio button. */}
            <label style={{ display: 'flex', flexDirection: 'row', alignItems: 'flex-start', gap: '0.5rem', marginBottom: '0.5rem' }}>
              <input
                type="radio"
                name="client_type"
                value="WEB"
                checked={clientType === 'WEB'}
                onChange={() => setClientType('WEB')}
                disabled={submitting}
                style={{ marginTop: '0.25rem' }}
              />
              <span style={{ flex: 1 }}>
                <strong>WEB</strong> — server-side / BFF. App has a backend
                that stores the client_secret securely. PKCE optional.
              </span>
            </label>
            <label style={{ display: 'flex', flexDirection: 'row', alignItems: 'flex-start', gap: '0.5rem' }}>
              <input
                type="radio"
                name="client_type"
                value="SPA"
                checked={clientType === 'SPA'}
                onChange={() => setClientType('SPA')}
                disabled={submitting}
                style={{ marginTop: '0.25rem' }}
              />
              <span style={{ flex: 1 }}>
                <strong>SPA</strong> — browser-only or native. No secret
                storage; PKCE required.
              </span>
            </label>
          </fieldset>

          <label>
            <div>Redirect URI <span style={{ color: '#f87171' }}>*</span></div>
            <input
              type="url"
              value={redirectURI}
              onChange={(e) => setRedirectURI(e.target.value)}
              placeholder="https://acme.com/api/auth/callback"
              required
              disabled={submitting}
              style={{ width: '100%' }}
            />
            <div className="hint" style={{ fontSize: '0.75rem' }}>
              Must match exactly what the app sends to /authorize.
              Comma-separate multiple values.
            </div>
          </label>

          <label>
            <div>Description (optional)</div>
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Shown on consent screens"
              disabled={submitting}
              style={{ width: '100%' }}
            />
          </label>

          {clientType === 'WEB' && (
            // Same row-flex + flex:1 fix as the radio rows above. The
            // helper text uses inline color/font-size rather than the
            // global `.hint` class, which has block-level padding +
            // background + 24px margin-bottom that turn an inline
            // <span> into a pill-shaped box that breaks the row.
            <label style={{ display: 'flex', flexDirection: 'row', alignItems: 'flex-start', gap: '0.5rem' }}>
              <input
                type="checkbox"
                checked={requirePKCE}
                onChange={(e) => setRequirePKCE(e.target.checked)}
                disabled={submitting}
                style={{ marginTop: '0.25rem' }}
              />
              <span style={{ flex: 1 }}>
                Require PKCE (recommended).{' '}
                <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
                  Layered defense even with a client_secret.
                </span>
              </span>
            </label>
          )}

          <label style={{ display: 'flex', flexDirection: 'row', alignItems: 'flex-start', gap: '0.5rem' }}>
            <input
              type="checkbox"
              checked={isTenantPortal}
              onChange={(e) => setIsTenantPortal(e.target.checked)}
              disabled={submitting}
              style={{ marginTop: '0.25rem' }}
            />
            <span style={{ flex: 1 }}>
              Mark as first-party (operator-owned).{' '}
              <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
                Flag this when you (the operator) own the app you're
                registering — your tenant portal, mail/calendar/drive
                apps, account-management page. Multiple clients can
                carry the flag. The "first-party" badge in the list
                view distinguishes these rows from third-party
                developer integrations.
              </span>
            </span>
          </label>
        </div>

        {error && (
          <p className="error" style={{ marginTop: '1rem' }}>
            {error}
          </p>
        )}

        <div className="actions" style={{ marginTop: '1.5rem' }}>
          <button type="submit" disabled={submitting} className="primary">
            {submitting ? 'Registering…' : 'Register client'}
          </button>
          <button type="button" onClick={onClose} disabled={submitting} className="secondary">
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}
