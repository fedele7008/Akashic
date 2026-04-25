import { useState, FormEvent } from 'react';
import { BootstrapApi } from '../api/client';

/**
 * BootstrapForm — the only state-changing UI in Phase 6.
 *
 * The operator pastes the bootstrap token from server logs, fills in
 * their desired credentials, and submits. On success we reload the
 * page, which re-fetches status and shows the "already complete" view.
 */
export function BootstrapForm() {
  const [token, setToken] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);

    // Client-side password match check before round-trip. The server
    // doesn't validate this -- it's purely a UX courtesy so the user
    // doesn't burn a rate-limit slot on a typo.
    if (password !== confirm) {
      setError('Passwords do not match.');
      return;
    }

    setSubmitting(true);
    try {
      await BootstrapApi.createRoot({ token, username, email, password });
      // Success: re-fetch status to flip the UI state. window.location
      // .reload() works fine here -- there's no in-flight state worth
      // preserving and a clean reload guarantees fresh CSRF cookie etc.
      window.location.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Submission failed');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="card">
      <h1>Akashic Bootstrap</h1>
      <p className="subtitle">
        Create the first root user for this Akashic deployment.
      </p>
      <p className="hint">
        The bootstrap token is printed in the server logs on startup.
        Copy it from there and paste it below.
      </p>

      <form onSubmit={onSubmit} autoComplete="off">
        <label>
          <span>Bootstrap token</span>
          <input
            type="text"
            value={token}
            onChange={(e) => setToken(e.target.value.trim())}
            spellCheck={false}
            autoCapitalize="off"
            placeholder="64 hex characters from server logs"
            required
            disabled={submitting}
          />
        </label>

        <label>
          <span>Username</span>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            spellCheck={false}
            autoCapitalize="off"
            required
            disabled={submitting}
          />
        </label>

        <label>
          <span>Email</span>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            disabled={submitting}
          />
        </label>

        <label>
          <span>Password</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            disabled={submitting}
          />
        </label>

        <label>
          <span>Confirm password</span>
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
            disabled={submitting}
          />
        </label>

        {error && <div className="error" role="alert">{error}</div>}

        <button type="submit" disabled={submitting}>
          {submitting ? 'Creating root user…' : 'Create root user'}
        </button>
      </form>
    </div>
  );
}
