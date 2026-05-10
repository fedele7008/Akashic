/**
 * /profile/connected-apps — mounts <akashic-connected-apps>. Lets
 * the signed-in user see every third-party OAuth client they've
 * approved, with a per-row revoke button. Phase 7.5.
 *
 * Same widget-only integration pattern as /profile/clients — the
 * page is a thin shell. The widget itself talks to
 * api.<tenant>/users/me/consents via the bearer-token cookie
 * bridge (auth.<tenant>/session/token), so the portal's BFF
 * stays out of this path.
 *
 * Built-ins (akashic-admin) and first-party clients
 * (IsTenantPortal=true) skip the consent screen entirely under
 * the hybrid policy, so they never appear here. This page
 * surfaces only third-party developer integrations the user has
 * approved.
 */

import Link from "next/link";

export default function ConnectedAppsPage() {
  return (
    <section className="mx-auto flex max-w-5xl flex-col gap-6 px-4 py-12">
      <header className="flex flex-col gap-1">
        <h1 className="text-2xl font-semibold">Connected apps</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Third-party apps you've approved to sign in with this
          account. Revoking removes their access — they'll need to
          ask permission again next time.
        </p>
      </header>

      <akashic-connected-apps />

      <p className="text-xs text-[var(--text-muted)]">
        <Link href="/profile" className="hover:underline">
          ← Back to profile
        </Link>
      </p>
    </section>
  );
}
