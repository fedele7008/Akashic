import { useEffect, useState } from 'react';
import {
  EmailConfigApi,
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
  // Token-lifetime ceilings — stored as seconds in the DB but
  // edited as duration strings (30s, 5m, 1h, 30d) for ergonomics.
  // The form holds the *string* representation so partial typing
  // doesn't reset to seconds; we parse on submit. Ceilings vs. per-
  // client overrides: this page edits the CEILING (the operator-
  // wide cap). Per-client overrides clamp DOWN within the ceiling
  // and live on the Client edit page.
  const [accessTTL, setAccessTTL] = useState('15m');
  const [refreshSlidingTTL, setRefreshSlidingTTL] = useState('30d');
  const [refreshAbsoluteTTL, setRefreshAbsoluteTTL] = useState('90d');
  // Tenant-allowed scope ceiling. Edited as a space-separated
  // string in a textarea; the parser canonicalises (sorts +
  // dedupes) on submit so save round-trips don't churn the column.
  const [allowedClientScopes, setAllowedClientScopes] = useState('openid profile email');
  // Phase 9e v2: client-registration qualification.
  // Verified-email default-on: the *intent* survives mailer state.
  // The eligibility service silently bypasses the gate when no
  // mailer is configured, so it's safe to keep the stored value
  // true even in that case; the admin UI shows it checked-but-
  // disabled to make the latent intent visible.
  const [requireVerifiedEmail, setRequireVerifiedEmail] = useState(true);
  const [requireApproval, setRequireApproval] = useState(false);
  const [defaultMaxClients, setDefaultMaxClients] = useState(25);
  const [mailerConfigured, setMailerConfigured] = useState(false);
  // Phase 9f: MFA trusted-device ceiling (1..365 days).
  const [mfaTrustedDays, setMfaTrustedDays] = useState(30);

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
      setAccessTTL(formatSecondsAsDuration(p.access_token_ttl_seconds));
      setRefreshSlidingTTL(formatSecondsAsDuration(p.refresh_token_sliding_ttl_seconds));
      setRefreshAbsoluteTTL(formatSecondsAsDuration(p.refresh_token_absolute_ttl_seconds));
      setAllowedClientScopes(p.allowed_client_scopes);
      setRequireVerifiedEmail(p.require_verified_email_for_client_registration);
      setRequireApproval(p.require_approval_for_client_registration);
      setDefaultMaxClients(p.default_max_clients);
      setMfaTrustedDays(p.mfa_trusted_device_max_days);
    } catch (e) {
      setErr((e as Error).message);
    }
    // Best-effort mailer-configured probe. Failures degrade to
    // "assume not configured" — safer than enabling a toggle that
    // could lock users out.
    try {
      const cfg = await EmailConfigApi.get();
      setMailerConfigured(cfg.provider !== '');
    } catch {
      setMailerConfigured(false);
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

    // Parse the duration-string fields. Errors here become a UI
    // banner rather than a network round-trip — same shape the
    // server would have produced anyway, but faster and clearer.
    let accessSec: number;
    let slidingSec: number;
    let absoluteSec: number;
    try {
      accessSec = parseDurationToSeconds(accessTTL, 'Access token TTL');
      slidingSec = parseDurationToSeconds(refreshSlidingTTL, 'Refresh token sliding TTL');
      absoluteSec = parseDurationToSeconds(refreshAbsoluteTTL, 'Refresh token absolute TTL');
    } catch (parseErr) {
      setSubmitErr((parseErr as Error).message);
      setSubmitting(false);
      return;
    }
    if (accessSec !== policy.access_token_ttl_seconds) req.access_token_ttl_seconds = accessSec;
    if (slidingSec !== policy.refresh_token_sliding_ttl_seconds) req.refresh_token_sliding_ttl_seconds = slidingSec;
    if (absoluteSec !== policy.refresh_token_absolute_ttl_seconds) req.refresh_token_absolute_ttl_seconds = absoluteSec;

    // Canonicalise the allowed-scopes string (sort + dedupe + trim)
    // before comparing to the loaded value. Avoids false-positive
    // "changed" diffs from whitespace edits.
    const canonScopes = canonicaliseScopes(allowedClientScopes);
    if (canonScopes !== canonicaliseScopes(policy.allowed_client_scopes)) {
      req.allowed_client_scopes = canonScopes;
    }

    // Phase 9e v2: client-registration toggles. Verified-email is
    // saved AS-IS (intent survives mailer state); eligibility
    // silently skips the gate when no mailer is configured.
    if (requireVerifiedEmail !== policy.require_verified_email_for_client_registration) {
      req.require_verified_email_for_client_registration = requireVerifiedEmail;
    }
    if (requireApproval !== policy.require_approval_for_client_registration) {
      req.require_approval_for_client_registration = requireApproval;
    }
    if (defaultMaxClients !== policy.default_max_clients) {
      req.default_max_clients = defaultMaxClients;
    }
    if (mfaTrustedDays !== policy.mfa_trusted_device_max_days) {
      req.mfa_trusted_device_max_days = mfaTrustedDays;
    }

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

        <div className="panel">
          <h3 style={{ marginTop: 0 }}>Allowed client scopes</h3>
          <p className="hint" style={{ fontSize: '0.8125rem', marginTop: 0 }}>
            Tenant-wide ceiling on what scopes any registered client may
            request. Per-client required + optional scopes must each be a
            subset of this set. <code>openid</code> is mandatory — Akashic
            is an OIDC IDP and clients need it to obtain id_tokens.
          </p>
          <p className="hint" style={{ fontSize: '0.8125rem' }}>
            <strong>Special scopes</strong> — currently <code>offline_access</code> —
            require per-client approval through the scope-request workflow.
            Even if listed here, special scopes need an approved request
            before a client may include them in a request.
          </p>
          <label>
            <div>Allowed scopes <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>(space-separated)</span></div>
            <input
              type="text"
              value={allowedClientScopes}
              onChange={(e) => setAllowedClientScopes(e.target.value)}
              disabled={submitting}
              style={{ width: '100%', fontFamily: 'monospace' }}
              placeholder="openid profile email"
            />
            <div className="hint" style={{ fontSize: '0.75rem', padding: 0, background: 'transparent', border: 'none' }}>
              Saved value is canonicalised — sorted + deduplicated.
            </div>
          </label>
        </div>

        <div className="panel">
          <h3 style={{ marginTop: 0 }}>Client registration</h3>
          <p className="hint" style={{ fontSize: '0.8125rem', marginTop: 0 }}>
            Tenant-wide rules for OAuth client registration via the
            <code>&lt;akashic-clients&gt;</code> widget. Per-user
            overrides (cap offset) live on the Users page.
          </p>
          <label style={{ display: 'block', marginBottom: '1rem' }}>
            <div>Default max clients per user</div>
            <input
              type="number"
              min={0}
              max={1000}
              value={defaultMaxClients}
              onChange={(e) => setDefaultMaxClients(parseInt(e.target.value, 10) || 0)}
              disabled={submitting}
              style={{ width: '120px' }}
            />
            <div className="hint" style={{ fontSize: '0.75rem', padding: 0, background: 'transparent', border: 'none' }}>
              Effective cap per user is{' '}
              <code>max(0, default + user.client_count_offset)</code> and
              counts (existing clients) + (pending registration requests).
              Default <strong>25</strong>; range 0–1000.
            </div>
          </label>
          <Checkbox
            label="Require a verified email"
            checked={requireVerifiedEmail}
            onChange={setRequireVerifiedEmail}
            disabled={submitting || !mailerConfigured}
            help={
              mailerConfigured
                ? "Users must verify their email before they can " +
                  "register OAuth clients. Default on."
                : "Inactive — no mailer is configured, so the gate is " +
                  "silently bypassed at runtime regardless of this " +
                  "setting. The stored value is preserved so it takes " +
                  "effect automatically once you configure email."
            }
          />
          <Checkbox
            label="Require approval"
            checked={requireApproval}
            onChange={setRequireApproval}
            disabled={submitting}
            help={
              "When on, every client registration goes through admin " +
              "review: the user submits client params + a reason via " +
              "the widget, you approve or reject on the Client " +
              "requests page, and the client_services row is created " +
              "on approve."
            }
          />
        </div>

        <div className="panel">
          <h3 style={{ marginTop: 0 }}>Token lifetimes</h3>
          <p className="hint" style={{ fontSize: '0.8125rem', marginTop: 0 }}>
            Tenant-wide ceilings for OAuth access + refresh tokens.
            Per-client overrides on the Clients page can clamp these
            DOWN for testing or specific integrations, but they cannot
            exceed these ceilings — a tighter ceiling here clamps every
            client immediately on the next mint. Durations: <code>30s</code>,{' '}
            <code>5m</code>, <code>2h</code>, <code>30d</code>.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <label>
              <div>Access token TTL</div>
              <input
                type="text"
                value={accessTTL}
                onChange={(e) => setAccessTTL(e.target.value)}
                disabled={submitting}
                style={{ width: '160px' }}
                placeholder="15m"
              />
              <div className="hint" style={{ fontSize: '0.75rem', padding: 0, background: 'transparent', border: 'none' }}>
                Lifetime of an issued access token. Floor 30 seconds,
                ceiling 24 hours. Default <strong>15m</strong>.
              </div>
            </label>

            <label>
              <div>Refresh token — sliding TTL</div>
              <input
                type="text"
                value={refreshSlidingTTL}
                onChange={(e) => setRefreshSlidingTTL(e.target.value)}
                disabled={submitting}
                style={{ width: '160px' }}
                placeholder="30d"
              />
              <div className="hint" style={{ fontSize: '0.75rem', padding: 0, background: 'transparent', border: 'none' }}>
                Per-row sliding window before a refresh token must be
                exchanged. Each rotation resets the window. Floor 60
                seconds, ceiling 1 year. Default <strong>30d</strong>.
              </div>
            </label>

            <label>
              <div>Refresh token — absolute TTL (chain)</div>
              <input
                type="text"
                value={refreshAbsoluteTTL}
                onChange={(e) => setRefreshAbsoluteTTL(e.target.value)}
                disabled={submitting}
                style={{ width: '160px' }}
                placeholder="90d"
              />
              <div className="hint" style={{ fontSize: '0.75rem', padding: 0, background: 'transparent', border: 'none' }}>
                Hard cap on the entire rotation chain from initial
                issuance. Even continuous use cannot extend past this —
                user re-authenticates via /authorize. Must be ≥ sliding
                TTL. Ceiling 10 years. Default <strong>90d</strong>.
              </div>
            </label>
          </div>
        </div>

        <div className="panel">
          <h3 style={{ marginTop: 0 }}>Multi-factor authentication</h3>
          <p className="hint" style={{ fontSize: '0.8125rem', marginTop: 0 }}>
            Email-based MFA: per-user opt-in (via the user's profile) or
            per-client requirement (via the client edit page) — either
            triggers a 6-digit code by email at login. Users can mark a
            browser as "trusted" to skip the prompt for a bounded window;
            this setting caps that window.
          </p>
          {!mailerConfigured && (
            <p className="hint" role="status" style={{ fontSize: '0.8125rem' }}>
              Email is not configured for this deployment. MFA gates
              are silently bypassed at login until you set up the
              Email page; the value below is preserved so it takes
              effect automatically once email is configured.
            </p>
          )}
          <label>
            <div>Trusted-device cookie max duration (days)</div>
            <input
              type="number"
              min={1}
              max={365}
              value={mfaTrustedDays}
              onChange={(e) => setMfaTrustedDays(parseInt(e.target.value, 10) || 1)}
              disabled={submitting}
              style={{ width: '120px' }}
            />
            <div className="hint" style={{ fontSize: '0.75rem', padding: 0, background: 'transparent', border: 'none' }}>
              User-pickable durations on the MFA challenge page clamp
              down to this. Range 1..365. Default <strong>30</strong>.
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

// parseDurationToSeconds accepts forms like "30s", "5m", "2h", "30d"
// (single-unit, integer coefficient). Returns the duration in
// seconds. Throws on parse failure with a contextual error message
// — caller catches and renders as a UI banner.
//
// We don't use a more permissive parser (e.g. "1h 30m") because the
// server's `time.ParseDuration` doesn't accept "d" at all (Go's
// stdlib has no day unit), and our duration strings are operator-
// facing; an operator typing "1h 30m" expecting it to work would be
// surprised when the next field they save accepts "1.5h" but their
// previous "30m 30s" didn't. Single-unit keeps the round-trip
// honest.
export function parseDurationToSeconds(raw: string, fieldLabel: string): number {
  const trimmed = raw.trim();
  if (trimmed === '') {
    throw new Error(`${fieldLabel}: a value is required (e.g. 30s, 5m, 1h, 30d)`);
  }
  const match = /^(\d+)\s*([smhd])$/i.exec(trimmed);
  if (!match) {
    throw new Error(
      `${fieldLabel}: invalid duration "${raw}". Use a single unit: ` +
        `30s (seconds), 5m (minutes), 2h (hours), 30d (days).`
    );
  }
  const n = parseInt(match[1], 10);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`${fieldLabel}: must be a positive integer.`);
  }
  switch (match[2].toLowerCase()) {
    case 's':
      return n;
    case 'm':
      return n * 60;
    case 'h':
      return n * 60 * 60;
    case 'd':
      return n * 24 * 60 * 60;
    default:
      // Unreachable given the regex above; keeps the type-checker
      // happy and surfaces a clear error if the regex ever evolves.
      throw new Error(`${fieldLabel}: unknown unit ${match[2]}.`);
  }
}

// canonicaliseScopes mirrors the server's `oauth.ParseScopeSet`
// helper: tokens split on whitespace, deduped, sorted, joined by
// single spaces. Exported so the Client edit page can use the same
// canonical form when diffing against stored values (avoids false-
// positive "changed" detections from whitespace edits).
export function canonicaliseScopes(s: string): string {
  const seen = new Set<string>();
  for (const tok of s.split(/\s+/)) {
    if (tok) seen.add(tok);
  }
  return Array.from(seen).sort().join(' ');
}

// formatSecondsAsDuration is the round-trip companion to
// parseDurationToSeconds. Picks the largest unit that divides the
// seconds value cleanly so 86400s renders as "1d" rather than
// "86400s". For values that don't fit a clean unit (e.g. 90 seconds,
// 25 hours), falls back to the next-smaller unit. Worst case is
// always seconds, which is always exact.
export function formatSecondsAsDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return '0s';
  if (seconds % (24 * 60 * 60) === 0) return `${seconds / (24 * 60 * 60)}d`;
  if (seconds % (60 * 60) === 0) return `${seconds / (60 * 60)}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}
