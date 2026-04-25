import { useEffect, useState } from 'react';
import { BootstrapApi, type BootstrapStatus } from './api/client';
import { BootstrapForm } from './components/BootstrapForm';
import { BootstrapAlreadyComplete } from './components/BootstrapAlreadyComplete';

/**
 * App is a tiny two-state shell:
 *   loading       → spinner
 *   is_complete   → BootstrapAlreadyComplete
 *   otherwise     → BootstrapForm
 *
 * No router (only one page in Phase 6), no auth context (no login
 * yet), no state library. Phase 7 expands this into a proper SPA.
 */
export function App() {
  const [status, setStatus] = useState<BootstrapStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [statusError, setStatusError] = useState<string | null>(null);

  useEffect(() => {
    BootstrapApi.status()
      .then(setStatus)
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

  if (status?.is_complete) {
    return <BootstrapAlreadyComplete status={status} />;
  }
  return <BootstrapForm />;
}
