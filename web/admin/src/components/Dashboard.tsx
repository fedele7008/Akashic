import { useState } from 'react';
import { SessionApi, type ClientView, type SessionInfo } from '../api/client';
import { ClientsCreate } from './ClientsCreate';
import { ClientsList } from './ClientsList';
import { ClientsRotate } from './ClientsRotate';

/**
 * View state — discriminated union rather than separate booleans.
 * `target` is required only for the `rotate` view; the type-checker
 * rejects an invalid `{ kind: 'create', target: ... }` combo at the
 * compile boundary, which a `showCreate / showRotate / rotateTarget`
 * trio of booleans can't catch.
 */
type View =
  | { kind: 'list' }
  | { kind: 'create' }
  | { kind: 'rotate'; target: ClientView };

/**
 * Dashboard is the logged-in view. Phase 8b adds OAuth client
 * management as a primary affordance — register / list / delete /
 * rotate, mirroring `akashic-cli clients` for operators who prefer
 * the web UI.
 *
 * Three sub-views (`list`, `create`, `rotate`) handled by a state
 * machine that single-discriminates the rendered component. List
 * refreshes after a successful create or delete via the `refreshKey`
 * counter.
 */
export function Dashboard({ session }: { session: SessionInfo }) {
  const [loggingOut, setLoggingOut] = useState(false);
  const [view, setView] = useState<View>({ kind: 'list' });
  const [refreshKey, setRefreshKey] = useState(0);

  const canManageClients =
    session.user_type === 'admin' || session.user_type === 'root';

  const handleLogout = async () => {
    setLoggingOut(true);
    let authLogoutUrl = '';
    try {
      authLogoutUrl = await SessionApi.logout();
    } catch {
      // Even on logout error, navigate — the user wants OUT. Falling
      // back to '/' means the BFF session may already be cleared but
      // the auth-server session might survive; a future fresh login
      // would be silent. Acceptable degraded behavior compared to
      // "the button did nothing."
    }
    // If we got an auth_logout_url, navigate there. The auth-server
    // will clear ITS session and redirect the browser back to /,
    // landing on the App shell which re-renders the sign-in landing.
    // Without this hop, the auth-server's IdP session would persist
    // and the next Sign-in click would auto-log-in silently — which
    // is exactly the SSO behavior we DON'T want after explicit logout.
    window.location.href = authLogoutUrl || '/';
  };

  // Modal-style overlay for create / rotate. The list lives inline
  // in the dashboard so the operator can see what's registered at a
  // glance; full-screen takeover for the actions that need it
  // (registration form's many fields; rotation's shown-once panel).
  if (view.kind === 'create') {
    return (
      <ClientsCreate
        onClose={() => {
          // Bump refresh so the freshly-registered client appears in
          // the list when we return.
          setRefreshKey((k) => k + 1);
          setView({ kind: 'list' });
        }}
      />
    );
  }
  if (view.kind === 'rotate') {
    return (
      <ClientsRotate
        client={view.target}
        onClose={() => {
          // Refresh on close — even though the rotate action doesn't
          // change the row's listed fields, this keeps the list in
          // sync if anything else changed concurrently.
          setRefreshKey((k) => k + 1);
          setView({ kind: 'list' });
        }}
      />
    );
  }

  return (
    <div className="card">
      <h1>Akashic admin console</h1>
      <p className="hint">
        You're logged in as <strong>{session.username || session.user_id}</strong>{' '}
        ({session.user_type}).
      </p>

      <dl className="kv">
        <dt>User ID</dt>
        <dd><code>{session.user_id}</code></dd>
        <dt>Email</dt>
        <dd>{session.email || <span className="hint">(not set)</span>}</dd>
        <dt>Session issued</dt>
        <dd>{new Date(session.issued_at).toLocaleString()}</dd>
        <dt>Session expires</dt>
        <dd>{new Date(session.expires_at).toLocaleString()}</dd>
      </dl>

      {canManageClients && (
        <section style={{ marginTop: '1.5rem' }}>
          <h2 style={{ fontSize: '1.125rem' }}>OAuth clients</h2>
          <p className="hint">
            Register your tenant's primary portal (the post-bootstrap
            initialization step), or add additional WEB / SPA clients
            for sub-services that need to authenticate via Akashic.
          </p>
          <div className="actions">
            <button
              type="button"
              onClick={() => setView({ kind: 'create' })}
              className="primary"
            >
              Register a new client
            </button>
          </div>
          <ClientsList
            refreshKey={refreshKey}
            onRotate={(c) => setView({ kind: 'rotate', target: c })}
          />
        </section>
      )}

      <p className="hint" style={{ marginTop: '1.5rem' }}>
        Coming next — user administration, audit log viewer.
      </p>

      <div className="actions">
        <button onClick={handleLogout} disabled={loggingOut} className="secondary">
          {loggingOut ? 'Logging out…' : 'Log out'}
        </button>
      </div>
    </div>
  );
}
