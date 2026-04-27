/**
 * /sign-in — drops the user straight into the OAuth flow.
 *
 * Why this exists as a Next page rather than a redirect from `/`:
 *   - Direct visits to /api/auth/authorize work but feel awkward
 *     (the URL has /api in it).
 *   - We want a stable, link-shareable URL the operator can hand
 *     out: "https://<deployment>/sign-in".
 *   - If sign-in came back from the auth server with an error
 *     (?error=...), this page also displays a friendly message
 *     instead of a stack trace.
 *
 * Implementation: the page issues an HTTP redirect via Next's
 * `redirect()` to /api/auth/authorize, preserving the optional
 * `return_to` and `error` query params. No client-side JS required.
 */

import { redirect } from "next/navigation";

interface Props {
  searchParams: Promise<{
    error?: string;
    return_to?: string;
  }>;
}

const ERROR_MESSAGES: Record<string, string> = {
  auth_failed: "Sign-in was cancelled or rejected by the identity provider.",
  bad_callback: "The sign-in callback was malformed. Please try again.",
  expired: "Your sign-in attempt expired. Please try again.",
  state_mismatch: "Sign-in state mismatch. Please try again.",
  token_exchange_failed: "Could not complete sign-in. Please retry shortly.",
  no_id_token: "Identity provider did not return an ID token.",
  invalid_id_token: "Identity provider returned an invalid ID token.",
  missing_sub: "Identity provider did not identify the user.",
  oauth_discovery_failed: "Sign-in is temporarily unavailable. Please retry shortly.",
};

export default async function SignInPage({ searchParams }: Props) {
  const params = await searchParams;

  // No error → just bounce into the OAuth flow.
  if (!params.error) {
    const next = params.return_to
      ? `/api/auth/authorize?return_to=${encodeURIComponent(params.return_to)}`
      : "/api/auth/authorize";
    redirect(next);
  }

  // With an error: render a friendly message + a "try again" button.
  const message =
    ERROR_MESSAGES[params.error] ?? "Sign-in failed. Please try again.";

  return (
    <section className="mx-auto flex max-w-md flex-col gap-6 px-4 py-16">
      <h1 className="text-2xl font-semibold">Couldn’t sign you in</h1>
      <p className="text-sm text-[var(--text-muted)]">{message}</p>
      <div className="flex gap-3">
        <a
          href="/api/auth/authorize"
          className="rounded-md bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white hover:opacity-90"
        >
          Try again
        </a>
        <a
          href="/"
          className="rounded-md border border-[var(--text-muted)]/30 px-4 py-2 text-sm text-[var(--text)] hover:bg-[var(--card)]"
        >
          Back to home
        </a>
      </div>
    </section>
  );
}
