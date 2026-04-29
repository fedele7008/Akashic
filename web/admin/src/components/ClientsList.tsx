import { useEffect, useState } from 'react';
import {
  ClientsApi,
  type ApiError,
  type ClientView,
} from '../api/client';

/**
 * ClientsList — table of every registered OAuth client.
 *
 * Fetches GET /api/clients on mount and after each successful
 * delete. Per-row actions:
 *   - Rotate secret  → calls onRotate(client) (parent shows a
 *                      takeover with the shown-once panel; can't
 *                      live inline because the secret needs the
 *                      full-screen treatment)
 *   - Delete         → inline confirmation (operator types the
 *                      client_id), then DELETE; refreshes on success
 *
 * Built-in rows (akashic-admin) get a "built-in" badge and no
 * action buttons — they're server-managed via env, not via this UI.
 * SPA rows hide the rotate button (no secret to rotate).
 */
export function ClientsList({
  onRotate,
  refreshKey,
}: {
  /** Parent-handled callback to show the rotation takeover. */
  onRotate: (client: ClientView) => void;
  /** Bumping this re-runs the fetch (parent flips it after create). */
  refreshKey: number;
}) {
  const [clients, setClients] = useState<ClientView[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  // Per-row delete state. The key is the client_id being deleted;
  // value is the operator-typed confirmation string. Storing this
  // here (rather than per-row component state) lets the parent
  // re-render the whole list without losing in-progress confirms.
  const [deleting, setDeleting] = useState<Record<string, string>>({});
  const [busyDelete, setBusyDelete] = useState<string | null>(null);

  const refresh = async () => {
    setErr(null);
    try {
      setClients(await ClientsApi.list());
    } catch (e) {
      const apiErr = (e as Error & { apiError?: ApiError }).apiError;
      setErr(apiErr?.message ?? (e as Error).message);
    }
  };

  useEffect(() => {
    void refresh();
  }, [refreshKey]);

  const startDelete = (id: string) => {
    setDeleting({ ...deleting, [id]: '' });
  };
  const cancelDelete = (id: string) => {
    const next = { ...deleting };
    delete next[id];
    setDeleting(next);
  };
  const confirmDelete = async (id: string) => {
    if (deleting[id] !== id) return;
    setBusyDelete(id);
    try {
      await ClientsApi.remove(id);
      cancelDelete(id);
      await refresh();
    } catch (e) {
      const apiErr = (e as Error & { apiError?: ApiError }).apiError;
      setErr(apiErr?.message ?? (e as Error).message);
    } finally {
      setBusyDelete(null);
    }
  };

  if (err) {
    return (
      <div style={{ marginTop: '1rem' }}>
        <p className="error">Could not load clients: {err}</p>
        <button type="button" onClick={() => void refresh()} className="secondary">
          Retry
        </button>
      </div>
    );
  }

  if (clients === null) {
    return <p className="hint" style={{ marginTop: '1rem' }}>Loading clients…</p>;
  }

  if (clients.length === 0) {
    return (
      <p className="hint" style={{ marginTop: '1rem' }}>
        No clients registered yet. Click "Register a new client" above to
        register your tenant's primary portal.
      </p>
    );
  }

  return (
    <div style={{ marginTop: '1rem', overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
        <thead>
          <tr style={{ textAlign: 'left', borderBottom: '1px solid rgba(255,255,255,0.15)' }}>
            <Th>Name</Th>
            <Th>Client ID</Th>
            <Th>Type</Th>
            <Th>Redirect URIs</Th>
            <Th style={{ textAlign: 'right' }}>Actions</Th>
          </tr>
        </thead>
        <tbody>
          {clients.map((c) => {
            const isDeleting = deleting[c.client_id] !== undefined;
            return (
              <tr
                key={c.client_id}
                style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}
              >
                <Td>
                  {c.name}
                  {c.built_in && (
                    <span style={{
                      display: 'inline-block',
                      marginLeft: '0.5rem',
                      padding: '0.125rem 0.375rem',
                      fontSize: '0.6875rem',
                      borderRadius: '0.25rem',
                      background: 'rgba(79, 140, 255, 0.15)',
                      color: 'var(--accent)',
                      verticalAlign: 'middle',
                    }}>built-in</span>
                  )}
                </Td>
                <Td><code style={{ fontSize: '0.8125rem' }}>{c.client_id}</code></Td>
                <Td>{c.client_type}</Td>
                <Td>
                  <code style={{
                    fontSize: '0.75rem',
                    wordBreak: 'break-all',
                    color: 'var(--text-muted)',
                  }}>
                    {c.redirect_uris}
                  </code>
                </Td>
                <Td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                  {c.built_in ? (
                    <span className="hint" style={{
                      fontSize: '0.75rem',
                      padding: 0,
                      background: 'transparent',
                      border: 'none',
                      margin: 0,
                    }}>
                      managed via env
                    </span>
                  ) : isDeleting ? (
                    <DeleteRow
                      clientID={c.client_id}
                      typed={deleting[c.client_id]}
                      onChange={(v) => setDeleting({ ...deleting, [c.client_id]: v })}
                      onConfirm={() => void confirmDelete(c.client_id)}
                      onCancel={() => cancelDelete(c.client_id)}
                      busy={busyDelete === c.client_id}
                    />
                  ) : (
                    <>
                      {!c.public && (
                        <button
                          type="button"
                          onClick={() => onRotate(c)}
                          className="secondary"
                          style={{ marginRight: '0.5rem', fontSize: '0.8125rem' }}
                        >
                          Rotate
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => startDelete(c.client_id)}
                        className="secondary"
                        style={{ fontSize: '0.8125rem', color: '#f87171' }}
                      >
                        Delete
                      </button>
                    </>
                  )}
                </Td>
              </tr>
            );
          })}
        </tbody>
      </table>

      <div style={{ marginTop: '0.75rem' }}>
        <button type="button" onClick={() => void refresh()} className="secondary"
          style={{ fontSize: '0.8125rem' }}>
          Refresh
        </button>
      </div>
    </div>
  );
}

function Th({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return (
    <th style={{
      padding: '0.5rem 0.5rem',
      fontWeight: 500,
      fontSize: '0.8125rem',
      color: 'var(--text-muted)',
      ...style,
    }}>
      {children}
    </th>
  );
}

function Td({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return (
    <td style={{ padding: '0.625rem 0.5rem', verticalAlign: 'top', ...style }}>
      {children}
    </td>
  );
}

/**
 * Inline delete confirmation: operator types the client_id, hits
 * Confirm. Same friction as the CLI's `clients delete <id>` prompt
 * — easy enough to do for a real action, just hard enough to
 * prevent accidents.
 */
function DeleteRow({
  clientID,
  typed,
  onChange,
  onConfirm,
  onCancel,
  busy,
}: {
  clientID: string;
  typed: string;
  onChange: (v: string) => void;
  onConfirm: () => void;
  onCancel: () => void;
  busy: boolean;
}) {
  const matches = typed === clientID;
  return (
    <div style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: '0.375rem',
    }}>
      <input
        type="text"
        autoFocus
        placeholder={`type ${clientID}`}
        value={typed}
        onChange={(e) => onChange(e.target.value)}
        disabled={busy}
        style={{
          fontSize: '0.75rem',
          padding: '0.25rem 0.5rem',
          fontFamily: 'ui-monospace, monospace',
          width: '14rem',
        }}
      />
      <button
        type="button"
        onClick={onConfirm}
        disabled={!matches || busy}
        className="primary"
        style={{
          fontSize: '0.75rem',
          padding: '0.25rem 0.5rem',
          background: matches ? '#dc2626' : undefined,
          opacity: matches && !busy ? 1 : 0.6,
        }}
      >
        {busy ? '…' : 'Confirm'}
      </button>
      <button type="button" onClick={onCancel} disabled={busy} className="secondary"
        style={{ fontSize: '0.75rem', padding: '0.25rem 0.5rem' }}>
        Cancel
      </button>
    </div>
  );
}
