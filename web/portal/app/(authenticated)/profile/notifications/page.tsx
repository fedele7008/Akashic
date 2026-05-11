/**
 * /profile/notifications — mounts
 * <akashic-notification-preferences>. Lets the signed-in user
 * toggle the two notification-email categories (sign-in activity
 * and approval/decision pings). Phase 9g.
 *
 * Same widget-only integration pattern as the rest of the
 * authenticated surface — the page is a thin shell. The widget
 * itself talks to api.<tenant>/users/me/notification-preferences
 * via the bearer-token cookie bridge.
 */

import Link from "next/link";

export default function NotificationsPage() {
  return (
    <section className="mx-auto flex max-w-5xl flex-col gap-6 px-4 py-12">
      <header className="flex flex-col gap-1">
        <h1 className="text-2xl font-semibold">Notification preferences</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Choose which workflow and account-activity emails you
          receive. Security emails are always sent.
        </p>
      </header>

      <akashic-notification-preferences />

      <p className="text-xs text-[var(--text-muted)]">
        <Link href="/profile" className="hover:underline">
          ← Back to profile
        </Link>
      </p>
    </section>
  );
}
