import { useState } from 'react';
import {
  ClientsApi,
  type ApiError,
  type ClientView,
  type UpdateClientRequest,
} from '../api/client';

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
  const [allowedScopes, setAllowedScopes] = useState(client.allowed_scopes);
  const [requirePKCE, setRequirePKCE] = useState(client.require_pkce);
  const [isTenantPortal, setIsTenantPortal] = useState(client.is_tenant_portal);

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
    if (allowedScopes.trim() !== client.allowed_scopes) {
      req.allowed_scopes = allowedScopes.trim();
    }
    if (!client.public && requirePKCE !== client.require_pkce) {
      // SPA stays forced-true server-side regardless; only WEB
      // clients can toggle, so we only send for WEB.
      req.require_pkce = requirePKCE;
    }
    if (isTenantPortal !== client.is_tenant_portal) {
      req.is_tenant_portal = isTenantPortal;
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

          <label>
            <div>Allowed scopes <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>(space-separated)</span></div>
            <input
              type="text"
              value={allowedScopes}
              onChange={(e) => setAllowedScopes(e.target.value)}
              disabled={submitting}
              style={{ width: '100%' }}
            />
          </label>

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
