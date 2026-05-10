import { useEffect, useState } from 'react';
import {
  ClientRegistrationRequestsApi,
  type ApiError,
  type ClientRegistrationRequestView,
} from '../api/client';

/**
 * ClientRegistrationRequestsPage — Phase 9e v2.
 *
 * Operator surface for the per-attempt client-registration approval
 * workflow. Tabs by status (pending / approved / rejected). Each
 * pending row carries the user's proposed client params (name,
 * type, redirect URIs, scopes); approve materializes a
 * `client_services` row owned by the requester, reject leaves the
 * row for audit.
 *
 * v2 doesn't allow editing params at review time. If the reviewer
 * wants changes, reject with a note instructing the user to
 * resubmit.
 */
type Tab = 'pending' | 'approved' | 'rejected';

export function ClientRegistrationRequestsPage() {
  const [tab, setTab] = useState<Tab>('pending');
  const [rows, setRows] = useState<ClientRegistrationRequestView[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = async () => {
    setErr(null);
    setRows(null);
    try {
      setRows(await ClientRegistrationRequestsApi.list(tab));
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab]);

  const approve = async (id: string) => {
    setBusyId(id);
    try {
      await ClientRegistrationRequestsApi.approve(id, notes[id] ?? '');
      await load();
    } catch (e) {
      const apiErr = e as Error & { apiError?: ApiError };
      setErr(apiErr.apiError?.message ?? apiErr.message);
    } finally {
      setBusyId(null);
    }
  };

  const reject = async (id: string) => {
    setBusyId(id);
    try {
      await ClientRegistrationRequestsApi.reject(id, notes[id] ?? '');
      await load();
    } catch (e) {
      const apiErr = e as Error & { apiError?: ApiError };
      setErr(apiErr.apiError?.message ?? apiErr.message);
    } finally {
      setBusyId(null);
    }
  };

  return (
    <>
      <div className="page-header">
        <div>
          <h2 className="page-header-title">Client-registration requests</h2>
          <p className="page-header-sub">
            When tenant policy requires approval, every user-side client
            registration lands here. Approving creates the OAuth client
            <em> as proposed</em>, owned by the requester. To alter
            params, reject with a note and ask the user to resubmit.
          </p>
        </div>
      </div>

      <div className="tabs" style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
        {(['pending', 'approved', 'rejected'] as Tab[]).map((t) => (
          <button
            key={t}
            type="button"
            className={`btn ${tab === t ? 'primary' : 'secondary'}`}
            onClick={() => setTab(t)}
            style={{ textTransform: 'capitalize' }}
          >
            {t}
          </button>
        ))}
      </div>

      {err && <p className="error" role="alert">{err}</p>}
      {!rows && !err && <p className="hint">Loading…</p>}
      {rows && rows.length === 0 && (
        <p className="hint">No {tab} requests.</p>
      )}

      {rows && rows.length > 0 && (
        <div className="cards" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {rows.map((row) => {
            const requester = row.requester_email
              || row.requester_display_name
              || row.user_id.slice(0, 8);
            return (
              <div key={row.id} className="panel" style={{ padding: '1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem' }}>
                  <div style={{ flex: 1 }}>
                    <h3 style={{ margin: 0, fontSize: '1rem' }}>
                      <code>{row.name}</code>{' '}
                      <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem', fontWeight: 400 }}>
                        ({row.client_type})
                      </span>
                    </h3>
                    <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                      from {requester}
                    </p>
                    <ParamGrid row={row} />
                    <p style={{ marginTop: '0.5rem', fontSize: '0.875rem' }}>
                      <strong>Reason:</strong> {row.reason}
                    </p>
                  </div>
                  <span className={`badge ${row.status}`}>{row.status}</span>
                </div>

                <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
                  Submitted {new Date(row.submitted_at).toLocaleString()}
                  {row.reviewed_at && (
                    <> · Reviewed {new Date(row.reviewed_at).toLocaleString()}
                    {row.reviewed_by ? ` by ${row.reviewed_by.slice(0, 8)}` : ''}</>
                  )}
                  {row.created_client_id && (
                    <> · Client <code>{row.created_client_id}</code></>
                  )}
                </p>
                {row.decision_note && (
                  <p style={{ marginTop: '0.5rem', fontSize: '0.8125rem', fontStyle: 'italic' }}>
                    <strong>Note:</strong> {row.decision_note}
                  </p>
                )}

                {tab === 'pending' && (
                  <div style={{ marginTop: '1rem' }}>
                    <input
                      type="text"
                      placeholder="Decision note (optional)"
                      value={notes[row.id] ?? ''}
                      onChange={(e) =>
                        setNotes((prev) => ({ ...prev, [row.id]: e.target.value }))
                      }
                      disabled={busyId === row.id}
                      style={{ width: '100%', marginBottom: '0.5rem' }}
                    />
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <button
                        type="button"
                        className="btn primary"
                        onClick={() => void approve(row.id)}
                        disabled={busyId === row.id}
                      >
                        {busyId === row.id ? 'Working…' : 'Approve'}
                      </button>
                      <button
                        type="button"
                        className="btn secondary"
                        onClick={() => void reject(row.id)}
                        disabled={busyId === row.id}
                      >
                        Reject
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </>
  );
}

function ParamGrid({ row }: { row: ClientRegistrationRequestView }) {
  const rows: Array<[string, React.ReactNode]> = [];
  rows.push(['Redirect URIs', <code>{row.redirect_uris}</code>]);
  if (row.required_scopes) rows.push(['Required scopes', <code>{row.required_scopes}</code>]);
  if (row.optional_scopes) rows.push(['Optional scopes', <code>{row.optional_scopes}</code>]);
  if (row.homepage_url) rows.push(['Homepage', <code>{row.homepage_url}</code>]);
  if (row.description) rows.push(['Description', <span>{row.description}</span>]);
  rows.push(['Require PKCE', <code>{row.require_pkce ? 'true' : 'false'}</code>]);
  return (
    <div style={{ marginTop: '0.5rem', display: 'grid', gridTemplateColumns: 'auto 1fr', columnGap: '0.75rem', rowGap: '0.25rem', fontSize: '0.8125rem' }}>
      {rows.map(([k, v], i) => (
        <div key={i} style={{ display: 'contents' }}>
          <span style={{ color: 'var(--text-muted)' }}>{k}:</span>
          <span style={{ wordBreak: 'break-all' }}>{v}</span>
        </div>
      ))}
    </div>
  );
}
