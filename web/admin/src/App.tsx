import { useEffect, useState } from 'react';
import {
  BootstrapApi,
  SessionApi,
  type BootstrapStatus,
  type SessionInfo,
} from './api/client';
import { BootstrapForm } from './components/BootstrapForm';
import { BootstrapAlreadyComplete } from './components/BootstrapAlreadyComplete';
import { Dashboard } from './components/Dashboard';

/**
 * App is the three-state shell:
 *
 *   loading                                    → spinner
 *   bootstrap not complete                     → BootstrapForm
 *   bootstrap complete + logged in             → Dashboard
 *   bootstrap complete + NOT logged in         → "Sign in" landing
 *                                                with redirect button
 *
 * The "redirect to /login" leg deliberately uses a button rather than
 * an automatic redirect on load. Reasons:
 *  - lets the user see what's happening before bouncing them out
 *  - avoids a redirect loop if /login is broken
 *  - matches the affordance pattern of any well-behaved consumer
 *    site (no surprise navigation)
 *
 * Phase 8+ will likely add a router so /admin/users, /admin/clients
 * etc. are real routes. For now everything lives inside this single
 * shell.
 */
export function App() {
  const [status, setStatus] = useState<BootstrapStatus | null>(null);
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [statusError, setStatusError] = useState<string | null>(null);

  useEffect(() => {
    // Fetch both in parallel — they're independent. Status is cached
    // on the server side, session is a Redis lookup; both are fast.
    Promise.all([BootstrapApi.status(), SessionApi.info()])
      .then(([s, sess]) => {
        setStatus(s);
        setSession(sess);
      })
      .catch((err) => setStatusError(err instanceof Error ? err.message : 'Unknown error'))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <div className="card"><p>Loading…</p></div>;
  }

  if (statusError) {
    return (
      <div className="card">
        <h1>Cannot reach Akashic server</h1>
        <p className="error">{statusError}</p>
        <p className="hint">
          Is the Akashic server running? Try{' '}
          <code>docker compose --profile app up -d</code>.
        </p>
      </div>
    );
  }

  // Bootstrap not yet complete → must finish that first.
  if (!status?.is_complete) {
    return <BootstrapForm />;
  }

  // Bootstrap complete + logged in → show admin dashboard.
  if (session) {
    return <Dashboard session={session} />;
  }

  // Bootstrap complete + NOT logged in → invite to sign in.
  return (
    <div className="card">
      <h1>Sign in to Akashic</h1>
      <p>Bootstrap is complete. Sign in with the root account or an admin account.</p>
      <p className="hint">
        Only users with role <code>root</code> or <code>admin</code> may access this console.
      </p>
      <div className="actions">
        <a href="/login" className="primary">Sign in</a>
      </div>
      {status && (
        <details>
          <summary>Bootstrap details</summary>
          <BootstrapAlreadyComplete status={status} />
        </details>
      )}
    </div>
  );
}
