import { useEffect, useState } from 'react';
import {
  UsersApi,
  type ApiError,
  type ResetPasswordResult,
  type SessionInfo,
  type UpdateUserRequest,
  type UserListParams,
  type UserView,
} from '../api/client';
import { ConfirmModal } from './ConfirmModal';

/**
 * UsersPage — Phase 8c.2.
 *
 * Operator surface for managing user accounts:
 *   - Paginated list with filters (role, disabled, missing identity)
 *   - Promote / demote (root ⇄ admin ⇄ user)
 *   - Disable / enable (reversible "lock account")
 *   - Hard-delete (removes LDAP entry + PG row; gated by confirm)
 *
 * Cross-row invariants are enforced server-side (last-root rule).
 * Self-protection (no demoting / deleting yourself) is enforced at
 * the BFF; the FE only HIDES self-modifying buttons to keep the UI
 * honest about what's possible.
 */
export function UsersPage({ session }: { session: SessionInfo }) {
  const [users, setUsers] = useState<UserView[] | null>(null);
  const [total, setTotal] = useState(0);
  const [err, setErr] = useState<string | null>(null);
  const [filter, setFilter] = useState<UserListParams>({ limit: 50, offset: 0 });

  // Edit/delete modal state — null = no modal open.
  const [editing, setEditing] = useState<EditingState | null>(null);

  const refresh = async () => {
    setErr(null);
    try {
      const res = await UsersApi.list(filter);
      setUsers(res.users);
      setTotal(res.total);
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter]);

  const isSelf = (u: UserView) => u.id === session.user_id;

  return (
    <>
      <div className="page-header">
        <div>
          <h2 className="page-header-title">Users</h2>
          <p className="page-header-sub">
            Manage user accounts — promote / demote roles, disable
            (reversible) or hard-delete (LDAP + PG row, irreversible).
            The last root user can't be demoted or deleted; you can't
            modify your own account from here.
          </p>
        </div>
        <button type="button" onClick={refresh} className="secondary">
          Refresh
        </button>
      </div>

      {/* Filter row */}
      <div className="panel" style={{ marginBottom: '1rem', padding: '12px 16px' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', alignItems: 'center' }}>
          <label style={{ display: 'flex', flexDirection: 'row', gap: '6px', alignItems: 'center' }}>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>Role:</span>
            <select
              value={filter.user_type ?? ''}
              onChange={(e) =>
                setFilter({ ...filter, user_type: (e.target.value || undefined) as UserListParams['user_type'], offset: 0 })
              }
            >
              <option value="">All</option>
              <option value="root">root</option>
              <option value="admin">admin</option>
              <option value="user">user</option>
            </select>
          </label>
          <label style={{ display: 'flex', flexDirection: 'row', gap: '6px', alignItems: 'center' }}>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>Status:</span>
            <select
              value={
                filter.is_disabled === undefined ? '' : filter.is_disabled ? 'disabled' : 'enabled'
              }
              onChange={(e) => {
                const v = e.target.value;
                setFilter({
                  ...filter,
                  is_disabled: v === '' ? undefined : v === 'disabled',
                  offset: 0,
                });
              }}
            >
              <option value="">All</option>
              <option value="enabled">Enabled</option>
              <option value="disabled">Disabled</option>
            </select>
          </label>
          <label style={{ display: 'flex', flexDirection: 'row', gap: '6px', alignItems: 'center' }}>
            <input
              type="checkbox"
              checked={filter.missing_identity === true}
              onChange={(e) =>
                setFilter({
                  ...filter,
                  missing_identity: e.target.checked ? true : undefined,
                  offset: 0,
                })
              }
            />
            <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
              Missing in LDAP only
            </span>
          </label>
          <span style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            {users === null ? '…' : `${total} user${total === 1 ? '' : 's'}`}
          </span>
        </div>
      </div>

      {err && <p className="error">{err}</p>}

      {users === null && !err && (
        <p className="hint">Loading users…</p>
      )}

      {users !== null && users.length === 0 && (
        <p className="hint">No users match the current filters.</p>
      )}

      {users !== null && users.length > 0 && (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid rgba(255,255,255,0.15)' }}>
                <Th>User</Th>
                <Th>Role</Th>
                <Th>Status</Th>
                <Th>Last login</Th>
                <Th style={{ textAlign: 'right' }}>Actions</Th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
                  <Td>
                    {/* Email is the post-Phase-7.5 primary
                        identity. uid stays visible as a smaller
                        muted second line so an operator looking at
                        an LDAP entry can still match the row. When
                        LDAP is unreachable mid-list-render the
                        email is empty; we fall back to showing the
                        uid as the primary line so the row stays
                        legible. */}
                    {u.email ? (
                      <>
                        <div>{u.email}</div>
                        <code style={{
                          fontSize: '0.75rem',
                          color: 'var(--text-muted)',
                          display: 'block',
                          marginTop: '2px',
                        }}>
                          {extractUid(u.ldap_dn)}
                        </code>
                      </>
                    ) : (
                      <code style={{ fontSize: '0.8125rem' }}>
                        {extractUid(u.ldap_dn)}
                      </code>
                    )}
                    {isSelf(u) && (
                      <span style={badgeStyle('rgba(79, 140, 255, 0.18)', 'var(--accent)')}>
                        you
                      </span>
                    )}
                    {u.missing_identity && (
                      <span style={badgeStyle('rgba(245, 158, 11, 0.18)', '#f59e0b')}>
                        missing in LDAP
                      </span>
                    )}
                  </Td>
                  <Td>
                    <RoleBadge type={u.user_type} />
                  </Td>
                  <Td>
                    {u.is_disabled ? (
                      <span style={badgeStyle('rgba(255, 107, 107, 0.18)', 'var(--error)')}>
                        disabled
                      </span>
                    ) : (
                      <span style={{ color: 'var(--text-muted)' }}>active</span>
                    )}
                  </Td>
                  <Td>
                    <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
                      {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : '—'}
                    </span>
                  </Td>
                  <Td style={{ textAlign: 'right' }}>
                    {!isSelf(u) && (
                      <>
                        <button
                          type="button"
                          className="secondary"
                          onClick={() => setEditing({ kind: 'edit', user: u })}
                          style={{ marginRight: '0.5rem' }}
                        >
                          Edit
                        </button>
                        <button
                          type="button"
                          className="secondary"
                          onClick={() => setEditing({ kind: 'reset', user: u })}
                          style={{ marginRight: '0.5rem' }}
                          disabled={u.is_disabled}
                          title={u.is_disabled
                            ? 'Re-enable the account before resetting its password.'
                            : 'Issue a temporary password and force a reset on next sign-in.'}
                        >
                          Reset password
                        </button>
                        <button
                          type="button"
                          className="destructive"
                          onClick={() => setEditing({ kind: 'delete', user: u })}
                        >
                          Delete
                        </button>
                      </>
                    )}
                    {isSelf(u) && (
                      <span style={{ color: 'var(--text-subtle)', fontSize: '0.8125rem' }}>
                        (manage another admin to change you)
                      </span>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {users !== null && total > (filter.limit ?? 50) && (
        <div style={{ marginTop: '1rem', display: 'flex', gap: '8px', justifyContent: 'center' }}>
          <button
            type="button"
            className="secondary"
            disabled={(filter.offset ?? 0) === 0}
            onClick={() =>
              setFilter({ ...filter, offset: Math.max(0, (filter.offset ?? 0) - (filter.limit ?? 50)) })
            }
          >
            Previous
          </button>
          <button
            type="button"
            className="secondary"
            disabled={(filter.offset ?? 0) + (filter.limit ?? 50) >= total}
            onClick={() => setFilter({ ...filter, offset: (filter.offset ?? 0) + (filter.limit ?? 50) })}
          >
            Next
          </button>
        </div>
      )}

      {/* Edit dialog */}
      {editing?.kind === 'edit' && (
        <EditUserDialog
          user={editing.user}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            refresh();
          }}
        />
      )}

      {/* Delete confirm */}
      {editing?.kind === 'delete' && (
        <DeleteUserConfirm
          user={editing.user}
          onClose={() => setEditing(null)}
          onDeleted={() => {
            setEditing(null);
            refresh();
          }}
        />
      )}

      {/* Reset-password confirm */}
      {editing?.kind === 'reset' && (
        <ResetPasswordConfirm
          user={editing.user}
          onClose={() => setEditing(null)}
          onDone={(result) => setEditing({ kind: 'reset-result', user: editing.user, result })}
        />
      )}

      {/* Reset-password result (success: emailed banner, or plaintext copy) */}
      {editing?.kind === 'reset-result' && (
        <ResetPasswordResultModal
          user={editing.user}
          result={editing.result}
          onClose={() => setEditing(null)}
        />
      )}
    </>
  );
}

type EditingState =
  | { kind: 'edit'; user: UserView }
  | { kind: 'delete'; user: UserView }
  | { kind: 'reset'; user: UserView }
  | { kind: 'reset-result'; user: UserView; result: ResetPasswordResult };

/**
 * EditUserDialog — change role and/or disabled flag. Submits a PATCH
 * with only the fields that actually changed (matches the server's
 * "pointer-fields = leave-unchanged" semantics, so we don't
 * accidentally re-trigger DisabledBy bookkeeping).
 */
function EditUserDialog({
  user,
  onClose,
  onSaved,
}: {
  user: UserView;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [userType, setUserType] = useState(user.user_type);
  const [isDisabled, setIsDisabled] = useState(user.is_disabled);
  const [clientCountOffset, setClientCountOffset] = useState(user.client_count_offset);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setError(null);
    setBusy(true);
    const req: UpdateUserRequest = {};
    if (userType !== user.user_type) req.user_type = userType;
    if (isDisabled !== user.is_disabled) req.is_disabled = isDisabled;
    if (clientCountOffset !== user.client_count_offset) req.client_count_offset = clientCountOffset;
    if (Object.keys(req).length === 0) {
      onClose();
      return;
    }
    try {
      await UsersApi.patch(user.id, req);
      onSaved();
    } catch (e) {
      const err = e as Error & { apiError?: ApiError };
      setError(err.apiError?.message ?? err.message);
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" role="presentation" onClick={(e) => {
      if (e.target === e.currentTarget && !busy) onClose();
    }}>
      <div className="modal-dialog" role="dialog" aria-modal="true">
        <h3 className="modal-title">Edit {user.email || extractUid(user.ldap_dn)}</h3>
        <div className="modal-body">
          <label style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginBottom: '12px' }}>
            <span style={{ fontSize: '0.875rem' }}>Role</span>
            <select value={userType} onChange={(e) => setUserType(e.target.value as UserView['user_type'])}>
              <option value="root">root</option>
              <option value="admin">admin</option>
              <option value="user">user</option>
            </select>
          </label>
          <label style={{ display: 'flex', flexDirection: 'row', gap: '8px', alignItems: 'flex-start' }}>
            <input
              type="checkbox"
              checked={isDisabled}
              onChange={(e) => setIsDisabled(e.target.checked)}
              style={{ marginTop: '0.25rem' }}
            />
            <span>
              Disable account
              <span style={{ display: 'block', color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
                Locks sign-in. Reversible — uncheck to re-enable.
              </span>
            </span>
          </label>
          <label style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginTop: '12px' }}>
            <span style={{ fontSize: '0.875rem' }}>Client cap offset</span>
            <input
              type="number"
              value={clientCountOffset}
              onChange={(e) => setClientCountOffset(parseInt(e.target.value, 10) || 0)}
              style={{ width: '120px' }}
            />
            <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
              Signed adjustment to the tenant default. Effective cap =
              <code> max(0, default + offset)</code>. 0 = use the
              tenant default exactly. Negative values tighten this
              user; positive grants extra slots.
            </span>
          </label>
        </div>
        {error && <p className="error" role="alert" style={{ marginTop: '0.75rem' }}>{error}</p>}
        <div className="modal-actions">
          <button type="button" className="secondary" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button type="button" className="primary" onClick={submit} disabled={busy}>
            {busy ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  );
}

/**
 * DeleteUserConfirm — type-to-confirm modal for hard delete. Confirm
 * phrase is the user's uid (extracted from their LDAP DN), so the
 * operator has to look at the row they're deleting.
 */
function DeleteUserConfirm({
  user,
  onClose,
  onDeleted,
}: {
  user: UserView;
  onClose: () => void;
  onDeleted: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The type-to-confirm phrase stays the uid (short, stable, easy
  // to type) even though email is the user-facing identity. Email
  // would be 20+ chars to type for confirm; uid is a focused 8-12.
  // The body text includes the email so the operator can match it.
  const uid = extractUid(user.ldap_dn);
  const headline = user.email || uid;

  const submit = async () => {
    setError(null);
    setBusy(true);
    try {
      await UsersApi.remove(user.id);
      onDeleted();
    } catch (e) {
      const err = e as Error & { apiError?: ApiError };
      setError(err.apiError?.message ?? err.message);
      setBusy(false);
    }
  };

  return (
    <ConfirmModal
      open={true}
      title={`Delete ${headline}?`}
      body={
        <>
          <p>
            This removes <strong>{headline}</strong> (<code>{uid}</code>)'s
            LDAP entry and PG row immediately. The user will not be able
            to sign in; any existing sessions remain valid until they
            expire.
          </p>
          <p>
            This is <strong>not reversible</strong> — re-creating the
            account requires re-registering through signup.
          </p>
        </>
      }
      confirmPhrase={uid}
      confirmLabel={`Delete ${uid}`}
      destructive
      busy={busy}
      errorMessage={error}
      onConfirm={submit}
      onCancel={onClose}
    />
  );
}

/**
 * ResetPasswordConfirm — confirms intent before issuing a temp
 * password. Two-step UX (confirm → result modal) is deliberate: the
 * action is sensitive (revokes every active session for the target
 * user via RT cascade), and the result modal needs to land on a
 * different shape depending on whether the mailer is configured.
 */
function ResetPasswordConfirm({
  user,
  onClose,
  onDone,
}: {
  user: UserView;
  onClose: () => void;
  onDone: (result: ResetPasswordResult) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const headline = user.email || extractUid(user.ldap_dn);

  const submit = async () => {
    setError(null);
    setBusy(true);
    try {
      const result = await UsersApi.resetPassword(user.id);
      onDone(result);
    } catch (e) {
      const err = e as Error & { apiError?: ApiError };
      setError(err.apiError?.message ?? err.message);
      setBusy(false);
    }
  };

  return (
    <ConfirmModal
      open={true}
      title={`Reset password for ${headline}?`}
      body={
        <>
          <p>
            A new temporary password will be generated and stored
            in LDAP for <strong>{headline}</strong>. The next time
            they sign in, they'll be forced to choose a new
            password before the session begins.
          </p>
          <p>
            All of <strong>{headline}</strong>'s existing refresh
            tokens will be revoked, so any logged-in sessions will
            need to re-authenticate.
          </p>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            If email is configured, the temporary password is sent
            to the user. Otherwise it's shown to you once on the
            next screen so you can deliver it out-of-band.
          </p>
        </>
      }
      confirmLabel="Reset password"
      busy={busy}
      errorMessage={error}
      onConfirm={submit}
      onCancel={onClose}
    />
  );
}

/**
 * ResetPasswordResultModal — terminal state of the reset flow.
 * Two visually distinct branches:
 *   - sent=true   → "emailed to <addr>" success banner, OK button.
 *   - sent=false  → plaintext password in a copy box, with a
 *     warning banner explaining why (mailer off / no email / send
 *     failed) and one-click copy. The plaintext is the source of
 *     truth here — closing the modal loses it forever.
 */
function ResetPasswordResultModal({
  user,
  result,
  onClose,
}: {
  user: UserView;
  result: ResetPasswordResult;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const headline = user.email || extractUid(user.ldap_dn);

  const copy = async () => {
    if (!result.temp_password) return;
    try {
      await navigator.clipboard.writeText(result.temp_password);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // Older browsers / locked-down clipboard. Fall through —
      // the password is still visible in the dialog so the
      // operator can hand-copy it.
    }
  };

  const reasonLabel = (() => {
    switch (result.reason) {
      case 'mailer_not_configured':
        return 'Email is not configured for this deployment.';
      case 'no_email_on_ldap_entry':
        return 'This user has no email address on their LDAP entry.';
      case 'email_send_failed':
        return 'The email failed to send.';
      default:
        return null;
    }
  })();

  return (
    <div className="modal-backdrop" role="presentation" onClick={(e) => {
      if (e.target === e.currentTarget) onClose();
    }}>
      <div className="modal-dialog" role="dialog" aria-modal="true">
        <h3 className="modal-title">Password reset for {headline}</h3>
        <div className="modal-body">
          {result.sent ? (
            <>
              <p className="success" role="status">
                A temporary password was emailed to{' '}
                <strong>{result.email}</strong>.
              </p>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
                The user will be forced to set a new password the
                next time they sign in.
              </p>
            </>
          ) : (
            <>
              <p className="error" role="alert">
                {reasonLabel ?? 'The temporary password could not be emailed.'}{' '}
                Hand it to the user over a trusted channel; they'll
                be forced to change it on next sign-in.
              </p>
              <label style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <span style={{ fontSize: '0.875rem' }}>Temporary password</span>
                <input
                  type="text"
                  readOnly
                  value={result.temp_password ?? ''}
                  onFocus={(e) => e.currentTarget.select()}
                  style={{
                    fontFamily: 'SF Mono, Menlo, monospace',
                    fontSize: '0.95rem',
                    padding: '8px 10px',
                    width: '100%',
                  }}
                />
              </label>
              <button
                type="button"
                className="secondary"
                onClick={copy}
                style={{ marginTop: '8px' }}
              >
                {copied ? 'Copied!' : 'Copy to clipboard'}
              </button>
              <p style={{ marginTop: '12px', color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
                This is the only time this password will be shown.
                Closing this dialog discards it.
              </p>
            </>
          )}
        </div>
        <div className="modal-actions">
          <button type="button" className="primary" onClick={onClose}>
            Done
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Shared bits ──────────────────────────────────────────────────

function Th({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return (
    <th style={{ padding: '8px 12px', fontWeight: 600, color: 'var(--text-muted)', ...style }}>
      {children}
    </th>
  );
}

function Td({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return <td style={{ padding: '10px 12px', ...style }}>{children}</td>;
}

function RoleBadge({ type }: { type: UserView['user_type'] }) {
  const style = (() => {
    switch (type) {
      case 'root':
        return badgeStyle('rgba(168, 85, 247, 0.18)', '#a855f7');
      case 'admin':
        return badgeStyle('rgba(79, 140, 255, 0.18)', 'var(--accent)');
      default:
        return badgeStyle('rgba(255,255,255,0.06)', 'var(--text-muted)');
    }
  })();
  return <span style={style}>{type}</span>;
}

function badgeStyle(bg: string, fg: string): React.CSSProperties {
  return {
    display: 'inline-block',
    padding: '0.125rem 0.5rem',
    fontSize: '0.6875rem',
    borderRadius: '0.25rem',
    background: bg,
    color: fg,
    fontWeight: 500,
    marginLeft: '0.5rem',
    verticalAlign: 'middle',
  };
}

/** Pull the leftmost uid=... value out of an LDAP DN. The DN is
 *  the canonical row identifier but UI-unfriendly; the uid is what
 *  the operator typed when registering. Falls back to the raw DN
 *  if the format is unexpected. */
function extractUid(dn: string): string {
  const first = dn.split(',')[0] ?? '';
  const eq = first.indexOf('=');
  return eq > 0 ? first.slice(eq + 1).trim() : dn;
}
