import { useEffect, useState } from 'react';
import { ServerApi, type ApiError, type SystemStatus } from '../api/client';
import { ConfirmModal } from './ConfirmModal';

/**
 * ServerPage — Phase 8c.3.
 *
 * Operator control surface for the akashic server's lifecycle:
 *   - Snapshot of auth-server, api-server state + uptime + PID
 *   - Start / Stop / Restart for each subsystem
 *   - Reload config, reload TLS certs
 *   - Graceful shutdown of the whole app
 *
 * Each subsystem owns its row of buttons + state. State-changing
 * actions that affect *other users* go through a type-to-confirm
 * modal: stopping auth means sign-in stops working for everyone;
 * stopping api means the resource API is unreachable; quitting
 * shuts the whole deployment down. Restart is a brief outage but
 * recovers automatically — gated by a simple yes/no confirm.
 * Start/reload are recoverable / non-disruptive — no confirm.
 */
export function ServerPage() {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [statusErr, setStatusErr] = useState<string | null>(null);

  // Action state — describes the currently-pending confirm modal.
  // null = no modal open.
  const [pending, setPending] = useState<PendingAction | null>(null);
  // Result banner for the most recent completed action. Cleared on
  // any new action; auto-clears 5s after a success.
  const [actionResult, setActionResult] = useState<{
    kind: 'success' | 'error';
    message: string;
  } | null>(null);

  const refresh = async () => {
    setStatusErr(null);
    try {
      setStatus(await ServerApi.status());
    } catch (e) {
      setStatusErr((e as Error).message);
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  // Auto-clear success banners — error banners stay until next action.
  useEffect(() => {
    if (actionResult?.kind !== 'success') return;
    const t = setTimeout(() => setActionResult(null), 5000);
    return () => clearTimeout(t);
  }, [actionResult]);

  const runAction = async () => {
    if (!pending) return;
    setActionResult(null);
    setPending({ ...pending, busy: true, error: null });
    try {
      await pending.run();
      setPending(null);
      setActionResult({
        kind: 'success',
        message: pending.successMessage,
      });
      // Snapshot may have changed; refresh after a short delay so
      // the control plane has time to settle the state machine.
      setTimeout(refresh, 250);
    } catch (e) {
      const err = e as Error & { apiError?: ApiError };
      setPending({
        ...pending,
        busy: false,
        error: err.apiError?.message ?? err.message,
      });
    }
  };

  return (
    <>
      <div className="page-header">
        <div>
          <h2 className="page-header-title">Server</h2>
          <p className="page-header-sub">
            Lifecycle and config operations on the akashic server.
            Destructive actions (stop, shut down) require explicit
            confirmation by typing the action name.
          </p>
        </div>
        <button type="button" onClick={refresh} className="secondary">
          Refresh
        </button>
      </div>

      {actionResult && (
        <p
          className={actionResult.kind === 'success' ? 'success' : 'error'}
          role="status"
          style={{ marginBottom: '1rem' }}
        >
          {actionResult.message}
        </p>
      )}

      {/* Status snapshot */}
      <div className="panel" style={{ marginBottom: '1rem' }}>
        <h3>Status</h3>
        {statusErr && <p className="error">{statusErr}</p>}
        {!statusErr && status === null && <p className="hint">Loading…</p>}
        {status && (
          <dl className="kv">
            <dt>Auth server</dt>
            <dd>
              <StateBadge state={String(status.auth_server.state ?? 'unknown')} />
              {status.auth_server.address ? (
                <code style={{ marginLeft: '0.5rem', color: 'var(--text-muted)' }}>
                  {String(status.auth_server.address)}
                </code>
              ) : null}
            </dd>
            <dt>Control server</dt>
            <dd>
              <StateBadge state={String(status.control_server.state ?? 'unknown')} />
              {status.control_server.address ? (
                <code style={{ marginLeft: '0.5rem', color: 'var(--text-muted)' }}>
                  {String(status.control_server.address)}
                </code>
              ) : null}
            </dd>
            <dt>Uptime</dt>
            <dd>{status.uptime}</dd>
            <dt>PID</dt>
            <dd><code>{status.pid}</code></dd>
          </dl>
        )}
      </div>

      {/* Auth-server controls */}
      <div className="panel" style={{ marginBottom: '1rem' }}>
        <h3>Auth server (OIDC IdP)</h3>
        <p className="panel-sub">
          Hosts /authorize, /token, /userinfo, /login, /signup. Stopping
          this means sign-in is broken for everyone until it's started
          again.
        </p>
        <div className="actions" style={{ marginTop: '0.75rem' }}>
          <button
            type="button"
            className="secondary"
            onClick={() => setPending(makeStartAction('auth'))}
          >
            Start
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => setPending(makeRestartAction('auth'))}
          >
            Restart
          </button>
          <button
            type="button"
            className="destructive"
            onClick={() => setPending(makeStopAction('auth'))}
          >
            Stop
          </button>
        </div>
      </div>

      {/* API-server controls */}
      <div className="panel" style={{ marginBottom: '1rem' }}>
        <h3>API server (resource API)</h3>
        <p className="panel-sub">
          Bearer-authenticated /users, /clients, /widgets endpoints
          consumed by the portal and tenant widgets. Stopping breaks
          all bearer-auth API calls until restarted.
        </p>
        <div className="actions" style={{ marginTop: '0.75rem' }}>
          <button
            type="button"
            className="secondary"
            onClick={() => setPending(makeStartAction('api'))}
          >
            Start
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => setPending(makeRestartAction('api'))}
          >
            Restart
          </button>
          <button
            type="button"
            className="destructive"
            onClick={() => setPending(makeStopAction('api'))}
          >
            Stop
          </button>
        </div>
      </div>

      {/* Reload + shutdown */}
      <div className="grid">
        <div className="panel">
          <h3>Reload config</h3>
          <p className="panel-sub">
            Re-reads config.yaml + env. Subsystems pick up changes
            without a restart. Validation failures leave the previous
            config active.
          </p>
          <div className="actions" style={{ marginTop: '0.75rem' }}>
            <button
              type="button"
              className="secondary"
              onClick={() => setPending(makeReloadConfigAction())}
            >
              Reload
            </button>
          </div>
        </div>

        <div className="panel">
          <h3>Reload TLS certs</h3>
          <p className="panel-sub">
            Re-reads cert/key files for both auth and control servers.
            Used when Vault Agent rotated certs and the in-process
            watcher is disabled.
          </p>
          <div className="actions" style={{ marginTop: '0.75rem' }}>
            <button
              type="button"
              className="secondary"
              onClick={() => setPending(makeReloadTLSAction())}
            >
              Reload
            </button>
          </div>
        </div>

        <div className="panel">
          <h3>Shut down</h3>
          <p className="panel-sub" style={{ color: 'var(--error)' }}>
            Gracefully shuts down the entire akashic process. Container
            orchestrators (docker compose, kubernetes) typically restart
            it after exit.
          </p>
          <div className="actions" style={{ marginTop: '0.75rem' }}>
            <button
              type="button"
              className="destructive"
              onClick={() => setPending(makeQuitAction())}
            >
              Shut down…
            </button>
          </div>
        </div>
      </div>

      <ConfirmModal
        open={pending !== null}
        title={pending?.title ?? ''}
        body={pending?.body ?? null}
        confirmPhrase={pending?.confirmPhrase}
        confirmLabel={pending?.confirmLabel ?? 'Confirm'}
        destructive={pending?.destructive ?? false}
        busy={pending?.busy ?? false}
        errorMessage={pending?.error ?? null}
        onConfirm={runAction}
        onCancel={() => setPending(null)}
      />
    </>
  );
}

interface PendingAction {
  title: string;
  body: React.ReactNode;
  confirmPhrase?: string;
  confirmLabel?: string;
  destructive: boolean;
  successMessage: string;
  run: () => Promise<void>;
  busy?: boolean;
  error?: string | null;
}

// ─── Action factories ────────────────────────────────────────────
//
// Each factory captures the per-action policy: confirm phrase or
// not, destructive styling, success message, the API call. Keeping
// these inline (vs. a config table) reads better at the call sites
// and avoids a magic-string indirection.

function makeStartAction(svc: 'auth' | 'api'): PendingAction {
  const human = svc === 'auth' ? 'auth server' : 'API server';
  return {
    title: `Start the ${human}?`,
    body: (
      <p>
        This will start the {human} if it's currently stopped. No-ops
        if it's already running.
      </p>
    ),
    destructive: false,
    successMessage: `${capitalize(human)} start requested.`,
    run: async () => {
      if (svc === 'auth') await ServerApi.authStart();
      else await ServerApi.apiStart();
    },
  };
}

function makeRestartAction(svc: 'auth' | 'api'): PendingAction {
  const human = svc === 'auth' ? 'auth server' : 'API server';
  return {
    title: `Restart the ${human}?`,
    body: (
      <p>
        Restarts the {human}. Brief outage (typically &lt; 1s) — open
        sessions hold while in-flight requests drain, then resume on
        the new process.
      </p>
    ),
    destructive: false,
    successMessage: `${capitalize(human)} restart requested.`,
    run: async () => {
      if (svc === 'auth') await ServerApi.authRestart();
      else await ServerApi.apiRestart();
    },
  };
}

function makeStopAction(svc: 'auth' | 'api'): PendingAction {
  const human = svc === 'auth' ? 'auth server' : 'API server';
  const phrase = svc === 'auth' ? 'STOP AUTH SERVER' : 'STOP API SERVER';
  return {
    title: `Stop the ${human}?`,
    body: (
      <>
        <p>
          The {human} will stop accepting requests. {svc === 'auth'
            ? 'Sign-in will fail for everyone until you start it again.'
            : 'Bearer-authenticated API calls will fail until you start it again.'}
        </p>
        <p>This isn't recovered automatically — you'll need to come
          back here and start the service when you're ready.</p>
      </>
    ),
    confirmPhrase: phrase,
    confirmLabel: `Stop ${human}`,
    destructive: true,
    successMessage: `${capitalize(human)} stopped.`,
    run: async () => {
      if (svc === 'auth') await ServerApi.authStop();
      else await ServerApi.apiStop();
    },
  };
}

function makeReloadConfigAction(): PendingAction {
  return {
    title: 'Reload configuration?',
    body: (
      <p>
        Re-reads config.yaml + environment. Subsystems will pick up
        the new values; validation failures keep the previous config
        active.
      </p>
    ),
    destructive: false,
    successMessage: 'Configuration reloaded.',
    run: () => ServerApi.configReload(),
  };
}

function makeReloadTLSAction(): PendingAction {
  return {
    title: 'Reload TLS certificates?',
    body: (
      <p>
        Re-reads cert/key files from disk. Failed reloads keep the
        previous cert active — safe to retry.
      </p>
    ),
    destructive: false,
    successMessage: 'TLS certificates reloaded.',
    run: () => ServerApi.tlsReload(),
  };
}

function makeQuitAction(): PendingAction {
  return {
    title: 'Shut down akashic?',
    body: (
      <>
        <p>
          The entire akashic process (auth + api + control servers)
          will shut down gracefully. Container orchestrators typically
          restart the process after exit; bare-metal deployments will
          need a manual start.
        </p>
        <p>
          <strong>Your admin session will end</strong> when the auth
          server stops issuing tokens — you'll need to sign in again
          after the process comes back up.
        </p>
      </>
    ),
    confirmPhrase: 'SHUTDOWN AKASHIC',
    confirmLabel: 'Shut down',
    destructive: true,
    successMessage: 'Shutdown initiated. The server will exit shortly.',
    run: () => ServerApi.quit(),
  };
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Small status pill — green for running, amber for transitional,
 *  red for stopped/error. Falls back to muted gray for unknown. */
function StateBadge({ state }: { state: string }) {
  const lower = state.toLowerCase();
  let bg = 'rgba(255,255,255,0.06)';
  let fg = 'var(--text-muted)';
  if (lower === 'running') {
    bg = 'rgba(22, 163, 74, 0.18)';
    fg = '#16a34a';
  } else if (lower === 'starting' || lower === 'stopping') {
    bg = 'rgba(245, 158, 11, 0.18)';
    fg = '#f59e0b';
  } else if (lower === 'stopped' || lower === 'error') {
    bg = 'rgba(255, 107, 107, 0.18)';
    fg = '#ff6b6b';
  }
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '0.125rem 0.5rem',
        fontSize: '0.75rem',
        borderRadius: '0.25rem',
        background: bg,
        color: fg,
        fontWeight: 500,
        verticalAlign: 'middle',
      }}
    >
      {state}
    </span>
  );
}
