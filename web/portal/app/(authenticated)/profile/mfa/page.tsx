/**
 * /profile/mfa — mounts <akashic-mfa-settings>. Lets the signed-in
 * user toggle email-based MFA and manage the list of "remembered"
 * trusted browsers. Phase 9f.
 *
 * Same widget-only integration pattern as the rest of the
 * authenticated surface — the page is a thin shell. The widget
 * itself talks to api.<tenant>/users/me/mfa* via the bearer-token
 * cookie bridge.
 */

import Link from "next/link";

export default function MFAPage() {
  return (
    <section className="mx-auto flex max-w-5xl flex-col gap-6 px-4 py-12">
      <header className="flex flex-col gap-1">
        <h1 className="text-2xl font-semibold">Multi-factor authentication</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Add an email-based second step to your sign-ins. You can
          mark trusted browsers to skip the prompt for a bounded
          window.
        </p>
      </header>

      <akashic-mfa-settings />

      <p className="text-xs text-[var(--text-muted)]">
        <Link href="/profile" className="hover:underline">
          ← Back to profile
        </Link>
      </p>
    </section>
  );
}
