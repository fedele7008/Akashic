import { useState } from 'react';
import type { ClientView, SessionInfo } from '../api/client';
import { ClientsCreate } from './ClientsCreate';
import { ClientsList } from './ClientsList';
import { ClientsRotate } from './ClientsRotate';

/**
 * ClientsPage — wraps the OAuth client management flows in the
 * shell-aware layout. Pre-Phase-8b layout, these flows lived
 * directly in `Dashboard.tsx` with full-card takeovers; now the
 * shell (sidebar + topbar) stays visible while only the content
 * slot toggles between list / create / rotate.
 *
 * View state machine:
 *   list    → ClientsList renders the table; refreshKey re-fetches
 *   create  → ClientsCreate form
 *   rotate  → ClientsRotate (target client carries through)
 *
 * onClose handlers in create/rotate bump the refreshKey so the
 * list re-runs its fetch when we return — picks up the new row
 * (create) or the rotation timestamp change (rotate).
 */
type View =
  | { kind: 'list' }
  | { kind: 'create' }
  | { kind: 'rotate'; target: ClientView };

export function ClientsPage({ session }: { session: SessionInfo }) {
  const [view, setView] = useState<View>({ kind: 'list' });
  const [refreshKey, setRefreshKey] = useState(0);

  const canManage =
    session.user_type === 'admin' || session.user_type === 'root';

  if (!canManage) {
    return (
      <div className="panel">
        <h3>Permission denied</h3>
        <p className="panel-sub">
          Only admin or root users may manage OAuth clients.
        </p>
      </div>
    );
  }

  if (view.kind === 'create') {
    return (
      <ClientsCreate
        onClose={() => {
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
          setRefreshKey((k) => k + 1);
          setView({ kind: 'list' });
        }}
      />
    );
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h2 className="page-header-title">OAuth clients</h2>
          <p className="page-header-sub">
            Register your tenant's first-party apps and any third-party
            integrations here. Flag your own apps with "first-party" so
            they're distinguishable from developer-registered ones.
            Built-ins are server-managed; tenant rows can be rotated or
            deleted.
          </p>
        </div>
        <button
          type="button"
          className="primary"
          onClick={() => setView({ kind: 'create' })}
          style={{ marginTop: 0 }}
        >
          Register a new client
        </button>
      </div>

      <div className="panel" style={{ padding: 0 }}>
        <ClientsList
          refreshKey={refreshKey}
          onRotate={(c) => setView({ kind: 'rotate', target: c })}
        />
      </div>
    </>
  );
}
