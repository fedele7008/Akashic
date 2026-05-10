import { useEffect, useState } from 'react';
import {
  ClientsApi,
  PolicyApi,
  ScopeRequestsApi,
  type ApiError,
  type ClientView,
  type ScopeRequestView,
  type TenantPolicy,
  type UpdateClientRequest,
} from '../api/client';
import {
  canonicaliseScopes,
  formatSecondsAsDuration,
  parseDurationToSeconds,
} from './PolicyPage';

/**
 * ClientsEdit — Phase 8c.4.
 *
 * Edit form for an existing OAuth client. Mirrors the shape of
 * ClientsCreate but with a key behavioural difference: only the
 * fields the operator actually changes get sent in the PATCH
 * (matches the server's pointer-field "leave unchanged" semantics).
 *
 * Immutable fields are rendered as read-only display values rather
 * than editable inputs:
 *   - client_id, client_type, public, built_in, owner_user_id are
 *     visible-but-locked.
 * Editable fields: name, description, homepage_url, redirect_uris,
 * allowed_scopes, role_allowlist (operator-only), require_pkce
 * (WEB only), is_tenant_portal (operator-only — multiple allowed).
 *
 * Built-in clients short-circuit to a "managed by env" notice
 * rather than the form.
 */
export function ClientsEdit({
  client,
  onClose,
}: {
  client: ClientView;
  onClose: () => void;
}) {
  const [name, setName] = useState(client.name);
  const [description, setDescription] = useState(client.description ?? '');
  const [homepageURL, setHomepageURL] = useState(client.homepage_url ?? '');
  const [redirectURIs, setRedirectURIs] = useState(client.redirect_uris);
  const [requirePKCE, setRequirePKCE] = useState(client.require_pkce);
  const [isTenantPortal, setIsTenantPortal] = useState(client.is_tenant_portal);

  // Phase A scope split. The map is keyed by scope name → "required"
  // | "optional" | "disabled". We fetch the tenant policy once on
  // mount to know which scopes are even ALLOWED to appear in the
  // selector; the row's existing required/optional values seed the
  // initial state. Legacy rows (empty required + populated allowed)
  // are migrated forward by treating allowed_scopes as required —
  // mirrors the server-side `oauth.EffectiveRequiredScopes` fallback.
  type ScopeMode = 'disabled' | 'required' | 'optional';
  const [scopeModes, setScopeModes] = useState<Record<string, ScopeMode>>(() => {
    const seed: Record<string, ScopeMode> = {};
    const required = client.required_scopes || client.allowed_scopes;
    for (const tok of required.split(/\s+/)) if (tok) seed[tok] = 'required';
    for (const tok of (client.optional_scopes ?? '').split(/\s+/)) {
      if (tok) seed[tok] = 'optional';
    }
    return seed;
  });
  const [tenantPolicy, setTenantPolicy] = useState<TenantPolicy | null>(null);
  const [policyErr, setPolicyErr] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        setTenantPolicy(await PolicyApi.get());
      } catch (e) {
        setPolicyErr((e as Error).message);
      }
    })();
  }, []);

  // Per-client TTL overrides — three-state UI per row:
  //   "<inherited>" (empty input)  → row uses tenant ceiling
  //   <duration>                   → row's override is set
  // The user types a duration string (30s, 5m, 1h, 30d) or clears
  // the input to revert to inheriting. We track the typed string;
  // an empty value sends the corresponding `clear_*: true` on
  // submit, a non-empty value parses to seconds and sets the
  // override.
  const [accessTTLOverride, setAccessTTLOverride] = useState(
    client.access_token_ttl_seconds_override != null
      ? formatSecondsAsDuration(client.access_token_ttl_seconds_override)
      : ''
  );
  const [refreshSlidingTTLOverride, setRefreshSlidingTTLOverride] = useState(
    client.refresh_token_sliding_ttl_seconds_override != null
      ? formatSecondsAsDuration(client.refresh_token_sliding_ttl_seconds_override)
      : ''
  );
  const [refreshAbsoluteTTLOverride, setRefreshAbsoluteTTLOverride] = useState(
    client.refresh_token_absolute_ttl_seconds_override != null
      ? formatSecondsAsDuration(client.refresh_token_absolute_ttl_seconds_override)
      : ''
  );

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<string | null>(null);

  if (client.built_in) {
    return (
      <div className="card">
        <h2>Built-in client</h2>
        <p className="hint">
          {client.name} (<code>{client.client_id}</code>) is server-managed.
          To toggle whether it exists, set the matching environment
          variable on the akashic server (e.g.{' '}
          <code>AKASHIC_OAUTH_ADMIN_BFF_ENABLED</code> for the admin
          built-in) and restart.
        </p>
        <div className="actions" style={{ marginTop: '1rem' }}>
          <button type="button" onClick={onClose} className="secondary">
            Back to list
          </button>
        </div>
      </div>
    );
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);

    // Only include fields whose value actually changed. This
    // matches the server's pointer-field semantics — sending
    // every field every time would re-bump updated_at and re-
    // log a "changed" entry for every save.
    const req: UpdateClientRequest = {};
    if (name.trim() !== client.name) req.name = name.trim();
    if (description !== (client.description ?? '')) req.description = description;
    if (homepageURL.trim() !== (client.homepage_url ?? '')) {
      req.homepage_url = homepageURL.trim();
    }
    if (redirectURIs.trim() !== client.redirect_uris) {
      req.redirect_uris = redirectURIs.trim();
    }
    // Build the canonical required/optional strings from the
    // tristate map and diff against the row's stored values.
    // Send only when something changed, in the new (Phase A) shape.
    const newRequired = canonicaliseScopes(
      Object.entries(scopeModes)
        .filter(([, mode]) => mode === 'required')
        .map(([s]) => s)
        .join(' ')
    );
    const newOptional = canonicaliseScopes(
      Object.entries(scopeModes)
        .filter(([, mode]) => mode === 'optional')
        .map(([s]) => s)
        .join(' ')
    );
    const storedRequired = canonicaliseScopes(
      client.required_scopes || client.allowed_scopes
    );
    const storedOptional = canonicaliseScopes(client.optional_scopes ?? '');
    if (newRequired !== storedRequired) req.required_scopes = newRequired;
    if (newOptional !== storedOptional) req.optional_scopes = newOptional;
    if (!client.public && requirePKCE !== client.require_pkce) {
      // SPA stays forced-true server-side regardless; only WEB
      // clients can toggle, so we only send for WEB.
      req.require_pkce = requirePKCE;
    }
    if (isTenantPortal !== client.is_tenant_portal) {
      req.is_tenant_portal = isTenantPortal;
    }

    // Per-client TTL overrides. For each field: compare the typed
    // string against the row's stored override.
    //   - typed empty + stored set      → clear flag
    //   - typed non-empty + stored unset → set
    //   - typed differs from stored      → set (new value)
    //   - typed equals stored            → no-op
    // Parse errors here become a UI banner without a network round-
    // trip (server would reject anyway, but faster to catch locally).
    try {
      diffTTLOverride(
        accessTTLOverride,
        client.access_token_ttl_seconds_override,
        'Access token TTL override',
        (n) => (req.access_token_ttl_seconds_override = n),
        () => (req.clear_access_token_ttl_override = true)
      );
      diffTTLOverride(
        refreshSlidingTTLOverride,
        client.refresh_token_sliding_ttl_seconds_override,
        'Refresh token sliding TTL override',
        (n) => (req.refresh_token_sliding_ttl_seconds_override = n),
        () => (req.clear_refresh_token_sliding_ttl_override = true)
      );
      diffTTLOverride(
        refreshAbsoluteTTLOverride,
        client.refresh_token_absolute_ttl_seconds_override,
        'Refresh token absolute TTL override',
        (n) => (req.refresh_token_absolute_ttl_seconds_override = n),
        () => (req.clear_refresh_token_absolute_ttl_override = true)
      );
    } catch (parseErr) {
      setError((parseErr as Error).message);
      setSubmitting(false);
      return;
    }

    if (Object.keys(req).length === 0) {
      setError('No changes to save.');
      setSubmitting(false);
      return;
    }

    try {
      const updated = await ClientsApi.update(client.client_id, req);
      setSavedAt(new Date(updated.updated_at).toLocaleString());
    } catch (e) {
      const err = e as Error & { apiError?: ApiError };
      setError(err.apiError?.message ?? err.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="card">
      <h2>Edit OAuth client</h2>
      <p className="hint">
        <code>{client.client_id}</code> · {client.client_type}{' '}
        {client.public ? '(public, PKCE-only)' : '(confidential, has client_secret)'}
      </p>

      {savedAt && (
        <p className="success" role="status">
          Saved at {savedAt}.
        </p>
      )}

      <form onSubmit={handleSubmit}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Read-only "you can't change this" panel. Surfaces
              the immutable fields so the operator doesn't think
              they're missing. */}
          <div className="panel" style={{ padding: '12px 16px', background: 'var(--surface)' }}>
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginBottom: '6px' }}>
              Immutable
            </div>
            <dl className="kv" style={{ margin: 0, fontSize: '0.875rem' }}>
              <dt>Client ID</dt>
              <dd><code>{client.client_id}</code></dd>
              <dt>Type</dt>
              <dd>{client.client_type}</dd>
              <dt>Auth flow</dt>
              <dd>{client.auth_types}</dd>
              <dt>Created</dt>
              <dd>{new Date(client.created_at).toLocaleString()}</dd>
            </dl>
          </div>

          <label>
            <div>Name</div>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={submitting}
              required
              style={{ width: '100%' }}
            />
          </label>

          <label>
            <div>Description</div>
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              disabled={submitting}
              style={{ width: '100%' }}
            />
          </label>

          <label>
            <div>Homepage URL</div>
            <input
              type="url"
              value={homepageURL}
              onChange={(e) => setHomepageURL(e.target.value)}
              disabled={submitting}
              placeholder="https://example.com"
              style={{ width: '100%' }}
            />
          </label>

          <label>
            <div>Redirect URIs <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>(comma-separated)</span></div>
            <input
              type="text"
              value={redirectURIs}
              onChange={(e) => setRedirectURIs(e.target.value)}
              disabled={submitting}
              required
              style={{ width: '100%' }}
            />
          </label>

          <div className="panel" style={{ padding: '12px 16px' }}>
            <div style={{ fontSize: '0.875rem', fontWeight: 500, marginBottom: '6px' }}>
              Scopes (per-client policy)
            </div>
            <p className="hint" style={{ fontSize: '0.8125rem', marginTop: 0, marginBottom: '12px' }}>
              For each scope the tenant allows, pick how this client uses it:
              <strong> Required</strong> (always requested; consent locks it
              on) · <strong>Optional</strong> (consent renders a togglable
              checkbox) · <strong>Disabled</strong> (this client doesn't
              request it). Special scopes like <code>offline_access</code>
              are gated by the scope-request workflow and don't appear
              here even if listed in the tenant ceiling.
            </p>
            {policyErr && (
              <p className="error" style={{ fontSize: '0.8125rem' }}>
                Could not load tenant policy: {policyErr}
              </p>
            )}
            {!tenantPolicy && !policyErr && (
              <p className="hint" style={{ fontSize: '0.8125rem' }}>Loading tenant policy…</p>
            )}
            {tenantPolicy && (
              <ScopeMatrix
                allowed={tenantPolicy.allowed_client_scopes}
                modes={scopeModes}
                onChange={setScopeModes}
                disabled={submitting}
              />
            )}
          </div>

          <SpecialScopesPanel clientID={client.client_id} />

          {!client.public && (
            <label style={{ display: 'flex', flexDirection: 'row', alignItems: 'flex-start', gap: '0.5rem' }}>
              <input
                type="checkbox"
                checked={requirePKCE}
                onChange={(e) => setRequirePKCE(e.target.checked)}
                disabled={submitting}
                style={{ marginTop: '0.25rem' }}
              />
              <span style={{ flex: 1 }}>
                Require PKCE
                <span style={{ display: 'block', color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
                  Layered defense even with a client_secret. Recommended on.
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
              First-party (operator-owned)
              <span style={{ display: 'block', color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
                Tick when this client belongs to you (the operator)
                rather than a third-party developer. Multiple clients
                may be flagged. Drives the "first-party" badge in the
                list and feeds Phase 7 consent rules.
              </span>
            </span>
          </label>

          <div className="panel" style={{ padding: '12px 16px' }}>
            <div style={{ fontSize: '0.875rem', fontWeight: 500, marginBottom: '6px' }}>
              Token lifetimes (per-client overrides)
            </div>
            <p className="hint" style={{ fontSize: '0.8125rem', marginTop: 0, marginBottom: '12px' }}>
              Leave blank to <em>inherit</em> the tenant ceiling from the
              Policy page. Type a duration (e.g. <code>30s</code>,{' '}
              <code>5m</code>, <code>1h</code>, <code>7d</code>) to override
              DOWN — the server rejects anything that exceeds the ceiling.
              Primary use: testing the OAuth refresh flow with sub-minute
              TTLs. Use the same flow with <code>akashic-cli clients
              update --access-token-ttl 30s</code> from a terminal.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <label>
                <div>Access token TTL <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>(blank = inherit)</span></div>
                <input
                  type="text"
                  value={accessTTLOverride}
                  onChange={(e) => setAccessTTLOverride(e.target.value)}
                  disabled={submitting}
                  placeholder="<inherited>"
                  style={{ width: '160px' }}
                />
              </label>
              <label>
                <div>Refresh token — sliding <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>(blank = inherit)</span></div>
                <input
                  type="text"
                  value={refreshSlidingTTLOverride}
                  onChange={(e) => setRefreshSlidingTTLOverride(e.target.value)}
                  disabled={submitting}
                  placeholder="<inherited>"
                  style={{ width: '160px' }}
                />
              </label>
              <label>
                <div>Refresh token — absolute (chain) <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>(blank = inherit)</span></div>
                <input
                  type="text"
                  value={refreshAbsoluteTTLOverride}
                  onChange={(e) => setRefreshAbsoluteTTLOverride(e.target.value)}
                  disabled={submitting}
                  placeholder="<inherited>"
                  style={{ width: '160px' }}
                />
              </label>
            </div>
          </div>
        </div>

        {error && (
          <p className="error" role="alert" style={{ marginTop: '1rem' }}>
            {error}
          </p>
        )}

        <div className="actions" style={{ marginTop: '1.5rem' }}>
          <button type="submit" disabled={submitting} className="primary">
            {submitting ? 'Saving…' : 'Save changes'}
          </button>
          <button type="button" onClick={onClose} disabled={submitting} className="secondary">
            Back to list
          </button>
        </div>
      </form>
    </div>
  );
}

// diffTTLOverride builds the right PATCH-payload contribution for a
// single TTL-override field. Three branches:
//
//   typed=""    + stored=null → no change
//   typed=""    + stored=<n>  → emit `clear_*: true` (revert to ceiling)
//   typed=<x>   + stored=null → parse + emit `*_seconds_override: <x>`
//   typed=<x>   + stored=<n>  → if differs, parse + emit override
//                                   if same, no change
//
// Throws on parse failure — caller surfaces as a UI banner. Caller
// supplies two callbacks (`setOverride` / `setClear`) so the
// function stays generic over which field it's diffing.
function diffTTLOverride(
  typed: string,
  stored: number | undefined,
  fieldLabel: string,
  setOverride: (n: number) => void,
  setClear: () => void
) {
  const trimmed = typed.trim();

  if (trimmed === '') {
    // User wants to inherit. Only emit the clear flag if there's
    // actually an override on the row to clear — emitting it when
    // the row is already null is a wasteful no-op write.
    if (stored != null) {
      setClear();
    }
    return;
  }

  // User typed something. Parse it; throws on bad input.
  const parsed = parseDurationToSeconds(trimmed, fieldLabel);
  if (parsed !== stored) {
    setOverride(parsed);
  }
}

/**
 * SpecialScopesPanel — Phase B (admin-side, READ-ONLY).
 *
 * Shows the scope-request history for the client being edited.
 * Submission is intentionally NOT here — special-scope requests
 * are submitted by client owners through the portal-side
 * `<akashic-clients>` widget, where the developer with operational
 * context lives. The admin web's role is review (the dedicated
 * Scope&nbsp;requests page in the sidebar).
 *
 * This panel exists in the operator-side ClientsEdit so the admin
 * has at-a-glance context: when reviewing or operationally
 * troubleshooting a client, "what scope requests has it submitted"
 * is right next to the rest of the client config.
 */
function SpecialScopesPanel({ clientID }: { clientID: string }) {
  const [history, setHistory] = useState<ScopeRequestView[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        const all = await ScopeRequestsApi.list();
        setHistory(all.filter((r) => r.client_id === clientID));
      } catch (e) {
        setErr((e as Error).message);
      }
    })();
  }, [clientID]);

  const specialHistory = (history ?? []).filter((r) => SPECIAL_SCOPES.has(r.scope));

  return (
    <div className="panel" style={{ padding: '12px 16px' }}>
      <div style={{ fontSize: '0.875rem', fontWeight: 500, marginBottom: '6px' }}>
        Special-scope requests (history)
      </div>
      <p className="hint" style={{ fontSize: '0.8125rem', marginTop: 0, marginBottom: '12px' }}>
        Submission lives in the portal-side <code>&lt;akashic-clients&gt;</code>{' '}
        widget — the client owner (developer) submits with their reason and
        proposed TTL policy. Review pending requests on the{' '}
        <strong>Scope&nbsp;requests</strong> page.
      </p>

      {err && <p className="error" style={{ fontSize: '0.8125rem' }}>{err}</p>}
      {history === null && !err && (
        <p className="hint" style={{ fontSize: '0.8125rem' }}>Loading history…</p>
      )}
      {history !== null && specialHistory.length === 0 && (
        <p className="hint" style={{ fontSize: '0.8125rem' }}>
          No special-scope requests have been submitted for this client.
        </p>
      )}
      {history !== null && specialHistory.length > 0 && (
        <ul style={{ listStyle: 'none', padding: 0, margin: 0, fontSize: '0.8125rem' }}>
          {specialHistory.map((r) => (
            <li key={r.id} style={{ padding: '0.25rem 0' }}>
              <code>{r.scope}</code> · <span className={`badge ${r.status}`}>{r.status}</span>
              {' · '}
              <span style={{ color: 'var(--text-muted)' }}>
                submitted {new Date(r.submitted_at).toLocaleString()}
              </span>
              {r.decision_note && (
                <span style={{ display: 'block', marginLeft: '1rem', fontStyle: 'italic', color: 'var(--text-muted)' }}>
                  Note: {r.decision_note}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// SPECIAL_SCOPES is the set of scope names that bypass the regular
// "tenant ceiling allows it" gate and require admin approval via
// the scope-request workflow. Mirrors `oauth.SpecialScopes` on the
// server. The ScopeMatrix filters these out of its rendered list so
// operators don't accidentally try to set them directly (server
// would reject with SPECIAL_SCOPE_REQUIRES_REQUEST anyway, but
// hiding them from the UI is a cleaner UX).
const SPECIAL_SCOPES = new Set(['offline_access']);

type ScopeMode = 'disabled' | 'required' | 'optional';

/**
 * ScopeMatrix renders one row per tenant-allowed scope. Each row is
 * a 3-radio (Disabled / Required / Optional) toggle group. Special
 * scopes (e.g. `offline_access`) are filtered out — they go through
 * the scope-request workflow rather than this form.
 *
 * Stateless wrt the tenant policy fetch: the parent owns the
 * `allowed` string + `modes` map and drives this component's value.
 * That keeps the rendering logic pure and easy to test.
 */
export function ScopeMatrix({
  allowed,
  modes,
  onChange,
  disabled,
}: {
  allowed: string;
  modes: Record<string, ScopeMode>;
  onChange: (next: Record<string, ScopeMode>) => void;
  disabled?: boolean;
}) {
  const tenantTokens = allowed
    .split(/\s+/)
    .filter(Boolean)
    .filter((t) => !SPECIAL_SCOPES.has(t))
    .sort();

  if (tenantTokens.length === 0) {
    return (
      <p className="hint" style={{ fontSize: '0.8125rem' }}>
        Tenant policy doesn't allow any non-special scopes. Edit the
        Policy page to add scopes before configuring this client.
      </p>
    );
  }

  const setMode = (scope: string, mode: ScopeMode) => {
    onChange({ ...modes, [scope]: mode });
  };

  return (
    <div className="scope-matrix" style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
      {tenantTokens.map((scope) => {
        const mode = modes[scope] ?? 'disabled';
        return (
          <div
            key={scope}
            style={{
              display: 'grid',
              gridTemplateColumns: '11rem repeat(3, auto)',
              alignItems: 'center',
              gap: '0.5rem',
              padding: '0.25rem 0.5rem',
              borderRadius: '4px',
              background: mode === 'disabled' ? 'transparent' : 'var(--surface)',
            }}
          >
            <code style={{ fontSize: '0.85rem' }}>{scope}</code>
            {(['disabled', 'required', 'optional'] as ScopeMode[]).map((opt) => (
              <label
                key={opt}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.25rem',
                  fontSize: '0.8125rem',
                  cursor: disabled ? 'not-allowed' : 'pointer',
                  opacity: disabled ? 0.6 : 1,
                }}
              >
                <input
                  type="radio"
                  name={`scope-${scope}`}
                  value={opt}
                  checked={mode === opt}
                  onChange={() => setMode(scope, opt)}
                  disabled={disabled}
                />
                <span style={{ textTransform: 'capitalize' }}>{opt}</span>
              </label>
            ))}
          </div>
        );
      })}
    </div>
  );
}
