import { useEffect, useState } from 'react';
import {
  EmailConfigApi,
  type ApiError,
  type EmailConfig,
  type UpdateEmailConfigRequest,
} from '../api/client';

/**
 * EmailConfigPage — Phase 9 (revised).
 *
 * Operator surface for outbound-email settings. Replaces the
 * env-var-only configuration path. Admin types in provider +
 * from + key, saves; the server's `email.Service.Reload` swaps
 * the cached mailer driver in place — no server restart needed.
 *
 * Secret handling: the SendGrid API key is masked on read.
 * Re-typing the key is optional (the masked placeholder is sent
 * back unedited and the server preserves the stored value);
 * typing a fresh value replaces it.
 *
 * Test-send: a small "Send test email" form at the bottom lets
 * the operator verify the config without going through a full
 * signup-and-verify dance. Test sends use whatever the CURRENT
 * saved config is (not the unsaved form values) — save first.
 */
export function EmailConfigPage() {
  const [config, setConfig] = useState<EmailConfig | null>(null);
  const [err, setErr] = useState<string | null>(null);

  // Editable form state.
  const [provider, setProvider] = useState('');
  const [fromAddress, setFromAddress] = useState('');
  const [fromName, setFromName] = useState('');
  const [sendGridKey, setSendGridKey] = useState('');
  const [verifyURLBase, setVerifyURLBase] = useState('');

  const [submitting, setSubmitting] = useState(false);
  const [savedAt, setSavedAt] = useState<string | null>(null);
  const [submitErr, setSubmitErr] = useState<string | null>(null);

  // Test-send form state.
  const [testTo, setTestTo] = useState('');
  const [testSending, setTestSending] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [testErr, setTestErr] = useState<string | null>(null);

  const load = async () => {
    setErr(null);
    try {
      const c = await EmailConfigApi.get();
      setConfig(c);
      setProvider(c.provider);
      setFromAddress(c.from_address);
      setFromName(c.from_name);
      // Server returns the masked placeholder (••••••••) when set.
      // Echoing it back unedited preserves the stored key on save —
      // the PATCH handler treats the placeholder as "leave key
      // unchanged."
      setSendGridKey(c.sendgrid_api_key);
      setVerifyURLBase(c.verify_url_base);
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!config) return;
    setSubmitErr(null);
    setSavedAt(null);
    setSubmitting(true);

    const req: UpdateEmailConfigRequest = {};
    if (provider !== config.provider) req.provider = provider;
    if (fromAddress !== config.from_address) req.from_address = fromAddress;
    if (fromName !== config.from_name) req.from_name = fromName;
    // Always send the API key field (server differentiates the
    // masked placeholder = "preserve" vs a real value = "replace").
    // Sending it unconditionally means the user can clear the key
    // by submitting an empty string.
    if (sendGridKey !== config.sendgrid_api_key) req.sendgrid_api_key = sendGridKey;
    if (verifyURLBase !== config.verify_url_base) req.verify_url_base = verifyURLBase;

    if (Object.keys(req).length === 0) {
      setSubmitErr('No changes to save.');
      setSubmitting(false);
      return;
    }

    try {
      const updated = await EmailConfigApi.update(req);
      setConfig(updated);
      // Re-seed form state from the post-update row (server
      // canonicalises whitespace, restores the masked placeholder).
      setProvider(updated.provider);
      setFromAddress(updated.from_address);
      setFromName(updated.from_name);
      setSendGridKey(updated.sendgrid_api_key);
      setVerifyURLBase(updated.verify_url_base);
      setSavedAt(new Date(updated.updated_at).toLocaleString());
    } catch (e) {
      const apiErr = e as Error & { apiError?: ApiError };
      setSubmitErr(apiErr.apiError?.message ?? apiErr.message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleTest = async () => {
    setTestResult(null);
    setTestErr(null);
    if (!testTo.trim()) {
      setTestErr('Recipient email is required.');
      return;
    }
    setTestSending(true);
    try {
      const result = await EmailConfigApi.test(testTo.trim());
      if (result.sent) {
        setTestResult(`Sent to ${result.to}. Check the inbox.`);
      } else {
        setTestErr(result.error || 'Send failed (server returned no error detail).');
      }
    } catch (e) {
      const apiErr = e as Error & { apiError?: ApiError };
      setTestErr(apiErr.apiError?.message ?? apiErr.message);
    } finally {
      setTestSending(false);
    }
  };

  if (err) {
    return (
      <div className="panel">
        <p className="error">Could not load email config: {err}</p>
        <button type="button" onClick={() => void load()} className="secondary">
          Retry
        </button>
      </div>
    );
  }

  if (!config) {
    return <p className="hint">Loading email config…</p>;
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h2 className="page-header-title">Email</h2>
          <p className="page-header-sub">
            Outbound-email configuration. When unset, every email-
            dependent feature (verification, forgot-password, MFA,
            login notifications) greys out gracefully. Edits take
            effect immediately — no server restart needed.
          </p>
        </div>
        <span className={`badge ${config.is_configured ? 'approved' : 'pending'}`}>
          {config.is_configured ? 'configured' : 'not configured'}
        </span>
      </div>

      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div className="panel">
          <h3 style={{ marginTop: 0 }}>Provider</h3>
          <p className="hint" style={{ fontSize: '0.8125rem', marginTop: 0 }}>
            Leave blank to disable email entirely. Adding more
            providers (SMTP / Postmark / Resend / SES) is a
            future driver addition; for now SendGrid is the
            only HTTP-API option.
          </p>
          <label>
            <div>Provider</div>
            <select
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
              disabled={submitting}
              style={{ width: '200px' }}
            >
              <option value="">(disabled)</option>
              <option value="sendgrid">SendGrid</option>
            </select>
          </label>
        </div>

        <div className="panel">
          <h3 style={{ marginTop: 0 }}>Sender identity</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <label>
              <div>From address <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>(required when provider is set)</span></div>
              <input
                type="email"
                value={fromAddress}
                onChange={(e) => setFromAddress(e.target.value)}
                disabled={submitting}
                style={{ width: '100%' }}
                placeholder="noreply@yourdomain.com"
              />
              <div className="hint" style={{ fontSize: '0.75rem', padding: 0, background: 'transparent', border: 'none' }}>
                SendGrid requires this to be a verified sender or
                a domain you control with verified Domain
                Authentication.
              </div>
            </label>
            <label>
              <div>From name <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>(optional)</span></div>
              <input
                type="text"
                value={fromName}
                onChange={(e) => setFromName(e.target.value)}
                disabled={submitting}
                style={{ width: '100%' }}
                placeholder="Acme Identity"
              />
              <div className="hint" style={{ fontSize: '0.75rem', padding: 0, background: 'transparent', border: 'none' }}>
                Display name in the From header. Defaults to "Akashic" when blank.
              </div>
            </label>
          </div>
        </div>

        <div className="panel">
          <h3 style={{ marginTop: 0 }}>SendGrid credentials</h3>
          <label>
            <div>API key <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>(required when provider is sendgrid)</span></div>
            <input
              type="password"
              value={sendGridKey}
              onChange={(e) => setSendGridKey(e.target.value)}
              disabled={submitting}
              style={{ width: '100%', fontFamily: 'monospace' }}
              placeholder="SG.xxxxxxxxx"
              autoComplete="off"
              spellCheck={false}
            />
            <div className="hint" style={{ fontSize: '0.75rem', padding: 0, background: 'transparent', border: 'none' }}>
              From the SendGrid dashboard → Settings → API Keys →
              Create API Key (with at least the "Mail Send"
              permission). The current value is shown as
              ••••••••; leave it as-is to keep the stored key,
              type a new value to replace it, or clear the field
              to remove it.
            </div>
          </label>
        </div>

        <div className="panel">
          <h3 style={{ marginTop: 0 }}>Verification URL base</h3>
          <p className="hint" style={{ fontSize: '0.8125rem', marginTop: 0 }}>
            The externally-reachable URL prefix used in
            verification emails. Verification links get appended
            as <code>/verify-email?token=…</code>. Typically
            matches your auth-server's public hostname.
          </p>
          <label>
            <div>Verify URL base</div>
            <input
              type="url"
              value={verifyURLBase}
              onChange={(e) => setVerifyURLBase(e.target.value)}
              disabled={submitting}
              style={{ width: '100%' }}
              placeholder="https://auth.akashic.example.com"
            />
          </label>
        </div>

        {savedAt && (
          <p className="success" role="status">
            Saved at {savedAt}. New config is live on the next email send.
          </p>
        )}
        {submitErr && (
          <p className="error" role="alert">{submitErr}</p>
        )}

        <div className="actions">
          <button type="submit" disabled={submitting} className="primary">
            {submitting ? 'Saving…' : 'Save changes'}
          </button>
          <button
            type="button"
            disabled={submitting}
            className="secondary"
            onClick={() => void load()}
          >
            Reset
          </button>
        </div>
      </form>

      <div className="panel" style={{ marginTop: '1.5rem' }}>
        <h3 style={{ marginTop: 0 }}>Send test email</h3>
        <p className="hint" style={{ fontSize: '0.8125rem', marginTop: 0 }}>
          Sends a one-off test message to verify the saved config.
          Uses whatever's currently saved — save your changes
          first if you've edited fields above.
        </p>
        <label>
          <div>Recipient</div>
          <input
            type="email"
            value={testTo}
            onChange={(e) => setTestTo(e.target.value)}
            disabled={testSending || !config.is_configured}
            style={{ width: '100%' }}
            placeholder="your-email@example.com"
          />
        </label>
        {!config.is_configured && (
          <p className="hint" style={{ fontSize: '0.8125rem', marginTop: '0.5rem' }}>
            Save a valid config first to enable test sends.
          </p>
        )}
        {testResult && (
          <p className="success" role="status" style={{ marginTop: '0.75rem' }}>
            {testResult}
          </p>
        )}
        {testErr && (
          <p className="error" role="alert" style={{ marginTop: '0.75rem' }}>
            {testErr}
          </p>
        )}
        <div className="actions" style={{ marginTop: '1rem' }}>
          <button
            type="button"
            onClick={() => void handleTest()}
            disabled={testSending || !config.is_configured}
            className="primary"
          >
            {testSending ? 'Sending…' : 'Send test email'}
          </button>
        </div>
      </div>
    </>
  );
}
