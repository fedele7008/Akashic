import { useState } from 'react';
import { SessionApi, type SessionInfo } from '../api/client';

/**
 * Dashboard is the placeholder logged-in view for Phase 7. It just
 * shows who is logged in and a logout button. The real admin
 * dashboard (clients, users, policies, audit) is Phase 8+.
 *
 * Why a placeholder lands now: Step 9 of Phase 7 wires up the OAuth
 * flow end-to-end. Without *some* logged-in surface to land on, we
 * can't visually confirm the flow worked. A minimal page is enough
 * to prove out the redirect/cookie/role-check chain.
 */
export function Dashboard({ session }: { session: SessionInfo }) {
  const [loggingOut, setLoggingOut] = useState(false);

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

      <p className="hint">
        Phase 7.5 dashboard coming soon — client management, user
        administration, audit log viewer.
      </p>

      <div className="actions">
        <button onClick={handleLogout} disabled={loggingOut} className="secondary">
          {loggingOut ? 'Logging out…' : 'Log out'}
        </button>
      </div>
    </div>
  );
}
