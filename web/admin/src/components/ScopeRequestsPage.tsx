import { useEffect, useState } from 'react';
import {
  ScopeRequestsApi,
  type ApiError,
  type ScopeRequestView,
} from '../api/client';
import { formatSecondsAsDuration } from './PolicyPage';

/**
 * ScopeRequestsPage — Phase B.
 *
 * Operator surface for the special-scope approval workflow. Tabs by
 * status (pending / approved / rejected). Pending requests get
 * approve + reject buttons; reviewed ones are read-only with the
 * decision note shown.
 *
 * Submission is done from the ClientsEdit page's "Special scopes"
 * panel (which knows the client_id context); this page is purely
 * the review surface.
 */
type Tab = 'pending' | 'approved' | 'rejected';

export function ScopeRequestsPage() {
  const [tab, setTab] = useState<Tab>('pending');
  const [rows, setRows] = useState<ScopeRequestView[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  // Per-row decision-note state, keyed by request id. Lets the
  // operator type a note, then click the corresponding action.
  const [notes, setNotes] = useState<Record<string, string>>({});
  // Per-row "submitting" so we can disable both buttons while a
  // single request is in flight without locking the whole page.
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = async () => {
    setErr(null);
    setRows(null);
    try {
      setRows(await ScopeRequestsApi.list(tab));
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab]);

  const review = async (id: string, action: 'approve' | 'reject') => {
    setBusyId(id);
    try {
      const note = notes[id] ?? '';
      if (action === 'approve') await ScopeRequestsApi.approve(id, note);
      else await ScopeRequestsApi.reject(id, note);
      // After review, the row leaves "pending" — refresh the list.
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
          <h2 className="page-header-title">Scope requests</h2>
          <p className="page-header-sub">
            Review and approve client requests for special scopes
            (e.g. <code>offline_access</code>). Approved requests
            unlock the scope on that client and apply the proposed
            TTL overrides clamped to the tenant ceiling.
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
          {rows.map((row) => (
            <div key={row.id} className="panel" style={{ padding: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem' }}>
                <div style={{ flex: 1 }}>
                  <h3 style={{ margin: 0, fontSize: '1rem' }}>
                    <code>{row.scope}</code>
                    {' '}
                    <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem', fontWeight: 400 }}>
                      for client <code>{row.client_id}</code>
                    </span>
                  </h3>
                  <p style={{ marginTop: '0.5rem', fontSize: '0.875rem' }}>
                    <strong>Reason:</strong> {row.reason}
                  </p>
                  {(row.proposed_access_token_ttl_seconds ||
                    row.proposed_refresh_token_sliding_ttl_seconds ||
                    row.proposed_refresh_token_absolute_ttl_seconds) && (
                    <p style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                      <strong>Proposed TTLs:</strong>{' '}
                      {row.proposed_access_token_ttl_seconds && (
                        <span>access {formatSecondsAsDuration(row.proposed_access_token_ttl_seconds)}{' · '}</span>
                      )}
                      {row.proposed_refresh_token_sliding_ttl_seconds && (
                        <span>refresh sliding {formatSecondsAsDuration(row.proposed_refresh_token_sliding_ttl_seconds)}{' · '}</span>
                      )}
                      {row.proposed_refresh_token_absolute_ttl_seconds && (
                        <span>refresh absolute {formatSecondsAsDuration(row.proposed_refresh_token_absolute_ttl_seconds)}</span>
                      )}
                    </p>
                  )}
                </div>
                <span className={`badge ${row.status}`}>{row.status}</span>
              </div>

              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
                Submitted {new Date(row.submitted_at).toLocaleString()}
                {row.submitted_by ? ` by ${row.submitted_by.slice(0, 8)}` : ''}
                {row.reviewed_at && (
                  <> · Reviewed {new Date(row.reviewed_at).toLocaleString()}
                  {row.reviewed_by ? ` by ${row.reviewed_by.slice(0, 8)}` : ''}</>
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
                      onClick={() => void review(row.id, 'approve')}
                      disabled={busyId === row.id}
                    >
                      {busyId === row.id ? 'Working…' : 'Approve'}
                    </button>
                    <button
                      type="button"
                      className="btn secondary"
                      onClick={() => void review(row.id, 'reject')}
                      disabled={busyId === row.id}
                    >
                      Reject
                    </button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </>
  );
}
