import { useEffect, useState } from 'react';
import {
  PolicyApi,
  type ApiError,
  type TenantPolicy,
  type UpdatePolicyRequest,
} from '../api/client';

/**
 * PolicyPage — Phase 8c.6.
 *
 * Operator surface for the deployment's runtime policy:
 *   - Password rules (min length + four toggle flags)
 *   - Self-service signup enabled / disabled
 *
 * One form, one save button. Only-changed-fields PATCH semantics
 * (mirrors ClientsEdit / EditUserDialog) so the security-channel
 * audit trail is precise about what actually moved.
 *
 * Live read on the server side — operator edits take effect on the
 * next signup / password-change request, no restart needed. Existing
 * stored passwords are NOT re-validated against tighter rules; the
 * page makes that explicit in the help text so operators don't
 * expect existing accounts to be force-rotated.
 */
export function PolicyPage() {
  const [policy, setPolicy] = useState<TenantPolicy | null>(null);
  const [err, setErr] = useState<string | null>(null);

  // Editable form state — initialised from `policy` once loaded.
  const [minLength, setMinLength] = useState(8);
  const [requireUppercase, setRequireUppercase] = useState(false);
  const [requireNumber, setRequireNumber] = useState(false);
  const [requireSpecial, setRequireSpecial] = useState(false);
  const [signupEnabled, setSignupEnabled] = useState(true);
  const [uidCooldown, setUidCooldown] = useState(30);

  const [submitting, setSubmitting] = useState(false);
  const [savedAt, setSavedAt] = useState<string | null>(null);
  const [submitErr, setSubmitErr] = useState<string | null>(null);

  const load = async () => {
    setErr(null);
    try {
      const p = await PolicyApi.get();
      setPolicy(p);
      setMinLength(p.password_min_length);
      setRequireUppercase(p.password_require_uppercase);
      setRequireNumber(p.password_require_number);
      setRequireSpecial(p.password_require_special);
      setSignupEnabled(p.signup_enabled);
      setUidCooldown(p.uid_change_cooldown_days);
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!policy) return;
    setSubmitErr(null);
    setSavedAt(null);
    setSubmitting(true);

    const req: UpdatePolicyRequest = {};
    if (minLength !== policy.password_min_length) req.password_min_length = minLength;
    if (requireUppercase !== policy.password_require_uppercase) req.password_require_uppercase = requireUppercase;
    if (requireNumber !== policy.password_require_number) req.password_require_number = requireNumber;
    if (requireSpecial !== policy.password_require_special) req.password_require_special = requireSpecial;
    if (signupEnabled !== policy.signup_enabled) req.signup_enabled = signupEnabled;
    if (uidCooldown !== policy.uid_change_cooldown_days) req.uid_change_cooldown_days = uidCooldown;

    if (Object.keys(req).length === 0) {
      setSubmitErr('No changes to save.');
      setSubmitting(false);
      return;
    }

    try {
      const updated = await PolicyApi.update(req);
      setPolicy(updated);
      setSavedAt(new Date(updated.updated_at).toLocaleString());
    } catch (e) {
      const apiErr = e as Error & { apiError?: ApiError };
      setSubmitErr(apiErr.apiError?.message ?? apiErr.message);
    } finally {
      setSubmitting(false);
    }
  };

  if (err) {
    return (
      <div className="panel">
        <p className="error">Could not load policy: {err}</p>
        <button type="button" onClick={() => void load()} className="secondary">
          Retry
        </button>
      </div>
    );
  }

  if (!policy) {
    return <p className="hint">Loading policy…</p>;
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h2 className="page-header-title">Policy</h2>
          <p className="page-header-sub">
            Runtime password rules and the self-service signup gate.
            Changes take effect on the next signup / password-change
            request — no restart needed. Existing stored passwords
            are NOT re-validated against tighter rules; only new
            passwords going forward.
          </p>
        </div>
      </div>

      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div className="panel">
          <h3 style={{ marginTop: 0 }}>Password</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <label>
              <div>Minimum length</div>
              <input
                type="number"
                min={4}
                max={256}
                value={minLength}
                onChange={(e) => setMinLength(parseInt(e.target.value, 10) || 0)}
                disabled={submitting}
                style={{ width: '120px' }}
              />
              <div className="hint" style={{ fontSize: '0.75rem', padding: 0, background: 'transparent', border: 'none' }}>
                Between 4 and 256. Server rejects values outside this
                range.
              </div>
            </label>

            <Checkbox
              label="Require an uppercase letter"
              checked={requireUppercase}
              onChange={setRequireUppercase}
              disabled={submitting}
            />
            <Checkbox
              label="Require a number"
              checked={requireNumber}
              onChange={setRequireNumber}
              disabled={submitting}
            />
            <Checkbox
              label="Require a special character"
              checked={requireSpecial}
              onChange={setRequireSpecial}
              disabled={submitting}
            />

            <p className="hint" style={{ fontSize: '0.8125rem' }}>
              <strong>Note</strong>: lowercase letters are always
              required (not operator-configurable). The default
              defends against accidental all-uppercase passwords
              that look strong but reduce real entropy.
            </p>
          </div>
        </div>

        <div className="panel">
          <h3 style={{ marginTop: 0 }}>Signup</h3>
          <Checkbox
            label="Allow self-service signup"
            checked={signupEnabled}
            onChange={setSignupEnabled}
            disabled={submitting}
            help={
              "When off, both the auth-server's /signup page and the " +
              "api-server's /users/register endpoint refuse new accounts. " +
              "Operator-initiated user creation through admin tools stays " +
              "available regardless."
            }
          />
        </div>

        <div className="panel">
          <h3 style={{ marginTop: 0 }}>Account ID rotation</h3>
          <label>
            <div>Cooldown between ID changes (days)</div>
            <input
              type="number"
              min={0}
              max={365}
              value={uidCooldown}
              onChange={(e) => setUidCooldown(parseInt(e.target.value, 10) || 0)}
              disabled={submitting}
              style={{ width: '120px' }}
            />
            <div className="hint" style={{ fontSize: '0.75rem', padding: 0, background: 'transparent', border: 'none' }}>
              Minimum elapsed time before a user can change their ID
              (id + tag) again. <strong>0</strong> disables the cooldown.
              <strong>30</strong> is the default — discourages
              rotation-as-impersonation. Server caps the value at 365.
            </div>
          </label>
        </div>

        {savedAt && (
          <p className="success" role="status">
            Saved at {savedAt}.
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
    </>
  );
}

function Checkbox({
  label,
  checked,
  onChange,
  disabled,
  help,
}: {
  label: string;
  checked: boolean;
  onChange: (next: boolean) => void;
  disabled?: boolean;
  help?: string;
}) {
  return (
    <label style={{ display: 'flex', flexDirection: 'row', alignItems: 'flex-start', gap: '0.5rem' }}>
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        disabled={disabled}
        style={{ marginTop: '0.25rem' }}
      />
      <span style={{ flex: 1 }}>
        {label}
        {help && (
          <span style={{ display: 'block', color: 'var(--text-muted)', fontSize: '0.8125rem', marginTop: '4px' }}>
            {help}
          </span>
        )}
      </span>
    </label>
  );
}
