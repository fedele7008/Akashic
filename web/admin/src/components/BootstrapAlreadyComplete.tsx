import type { BootstrapStatus } from '../api/client';

interface Props {
  status: BootstrapStatus;
}

/**
 * Shown after bootstrap is complete. Phase 6 has no login flow yet;
 * this view tells the operator "the bootstrap form is permanently
 * closed; further user management is via akashic-cli for now". Phase
 * 7 will replace this with a redirect to /login.
 */
export function BootstrapAlreadyComplete({ status }: Props) {
  return (
    <div className="card">
      <h1>Akashic — Bootstrap Complete</h1>
      <p className="subtitle">
        This deployment has already been bootstrapped.
      </p>

      {status.completed_at && (
        <p>
          Completed at: <code>{status.completed_at}</code>
        </p>
      )}

      <hr />

      <h2>What's next?</h2>
      <p>
        The web-based admin dashboard is coming in a future phase.
        For now, manage users via the <code>akashic-cli</code>:
      </p>
      <pre>
{`# Check server status
akashic-cli bootstrap status

# Create additional admin users (Phase 7+)
# (currently only the root user exists)`}
      </pre>
    </div>
  );
}
