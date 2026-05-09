/**
 * /profile/change-id — mounts <akashic-change-id>. The widget calls
 * api.<tenant>/users/me/uid (PATCH) directly via the bearer exchange.
 * No portal-side BFF involvement.
 */

import Link from "next/link";

export default function ChangeIDPage() {
  return (
    <section className="mx-auto flex max-w-md flex-col gap-6 px-4 py-12">
      <header className="flex flex-col gap-1">
        <h1 className="text-2xl font-semibold">Change account ID</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Rotate your <code>id#TAG</code> handle. The operator-configured
          cooldown applies between successive changes.
        </p>
      </header>

      <akashic-change-id />

      <p className="text-xs text-[var(--text-muted)]">
        <Link href="/profile" className="hover:underline">
          ← Back to profile
        </Link>
      </p>
    </section>
  );
}
