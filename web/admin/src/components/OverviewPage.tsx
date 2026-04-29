import { useEffect, useState } from 'react';
import { ClientsApi, type ClientView, type SessionInfo } from '../api/client';
import type { Page } from './Sidebar';

/**
 * OverviewPage — the landing surface for a logged-in operator.
 *
 * Renders a grid of stat cards summarising the current deployment
 * state. Stats are derived client-side from a single
 * `GET /api/clients` fetch (no per-stat round-trip) — small enough
 * data volume that pre-aggregation server-side would be premature.
 *
 * Cards (left-to-right, then wrapping):
 *   1. Welcome — operator's identity + role
 *   2. OAuth clients total — clickable to navigate to Clients page
 *   3. Built-ins — count of server-managed clients (admin-bff toggle)
 *   4. Tenant clients — count of operator/CLI-registered
 *   5. Bootstrap status — "✓ Complete" (always true on this page;
 *      App.tsx routes pre-bootstrap operators to BootstrapForm)
 *
 * The grid uses CSS auto-fit + minmax(260px, 1fr) so cards reflow
 * naturally as the window narrows; no explicit breakpoints needed.
 */
export function OverviewPage({
  session,
  onNavigate,
}: {
  session: SessionInfo;
  onNavigate: (page: Page) => void;
}) {
  const [clients, setClients] = useState<ClientView[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const canManageClients =
    session.user_type === 'admin' || session.user_type === 'root';

  useEffect(() => {
    if (!canManageClients) return;
    ClientsApi.list()
      .then(setClients)
      .catch((e: Error) => setErr(e.message));
  }, [canManageClients]);

  const total = clients?.length ?? 0;
  const builtins = clients?.filter((c) => c.built_in).length ?? 0;
  const tenants = total - builtins;

  return (
    <>
      <div className="page-header">
        <div>
          <h2 className="page-header-title">Welcome back, {session.username || session.user_id}</h2>
          <p className="page-header-sub">
            Logged in as {session.user_type}. Session expires{' '}
            {new Date(session.expires_at).toLocaleString()}.
          </p>
        </div>
      </div>

      <div className="grid">
        <div className="panel">
          <h3>Account</h3>
          <p className="panel-value" style={{ fontSize: '1.125rem' }}>
            {session.username || session.user_id}
          </p>
          <p className="panel-sub">
            {session.email || <em>no email on file</em>} · {session.user_type}
          </p>
        </div>

        {canManageClients && (
          <div
            className="panel interactive"
            role="button"
            tabIndex={0}
            onClick={() => onNavigate('clients')}
            onKeyDown={(e) => {
              // Match the click handler on Enter/Space — operators
              // tab-navigating with the keyboard expect the same
              // affordance as click.
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                onNavigate('clients');
              }
            }}
          >
            <h3>OAuth clients</h3>
            <p className="panel-value">{clients === null ? '…' : total}</p>
            <p className="panel-sub">
              {err
                ? `Error: ${err}`
                : `Click to manage registrations →`}
            </p>
          </div>
        )}

        {canManageClients && (
          <div className="panel">
            <h3>Built-in clients</h3>
            <p className="panel-value">{clients === null ? '…' : builtins}</p>
            <p className="panel-sub">
              Server-managed (toggle <code>AKASHIC_OAUTH_ADMIN_BFF_ENABLED</code>).
            </p>
          </div>
        )}

        {canManageClients && (
          <div className="panel">
            <h3>Tenant clients</h3>
            <p className="panel-value">{clients === null ? '…' : tenants}</p>
            <p className="panel-sub">
              Operator-registered via CLI or this console.
            </p>
          </div>
        )}

        <div className="panel">
          <h3>Bootstrap</h3>
          <p className="panel-value" style={{ color: '#16a34a', fontSize: '1.5rem' }}>
            ✓ Complete
          </p>
          <p className="panel-sub">Root user provisioned, system operational.</p>
        </div>
      </div>
    </>
  );
}
