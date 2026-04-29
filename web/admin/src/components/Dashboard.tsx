import { useState } from 'react';
import { SessionApi, type SessionInfo } from '../api/client';
import { ClientsCreate } from './ClientsCreate';

/**
 * Dashboard is the logged-in view. Phase 8b adds OAuth client
 * registration as a primary affordance — the same operator action
 * available via `akashic-cli clients create`, surfaced here for
 * operators who prefer the web UI.
 *
 * Future iterations: list registered clients (ClientsApi.list),
 * edit/delete via row actions, rotate secrets in-place. For now the
 * dashboard hosts only the create flow — covers the post-bootstrap
 * "register your tenant portal" initialization step end-to-end.
 */
export function Dashboard({ session }: { session: SessionInfo }) {
  const [loggingOut, setLoggingOut] = useState(false);
  const [showCreateClient, setShowCreateClient] = useState(false);

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

  // Modal-style overlay: when the create-client form is open, it
  // takes over the surface entirely. Avoids cramming the Dashboard
  // with a multi-section layout before the rest of Phase 8b lands.
  if (showCreateClient) {
    return <ClientsCreate onClose={() => setShowCreateClient(false)} />;
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
              onClick={() => setShowCreateClient(true)}
              className="primary"
            >
              Register a new client
            </button>
          </div>
        </section>
      )}

      <p className="hint" style={{ marginTop: '1.5rem' }}>
        Coming next — client list / edit / delete, user administration,
        audit log viewer.
      </p>

      <div className="actions">
        <button onClick={handleLogout} disabled={loggingOut} className="secondary">
          {loggingOut ? 'Logging out…' : 'Log out'}
        </button>
      </div>
    </div>
  );
}
