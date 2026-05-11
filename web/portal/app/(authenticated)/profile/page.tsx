/**
 * /profile — read + edit profile. Mounts <akashic-profile editable>.
 * The widget calls api.<tenant>/users/me directly via the bearer
 * exchange (POST auth.<tenant>/session/token under the hood). The
 * portal page itself does no API work — that's the demonstration.
 */

import Link from "next/link";

export default function ProfilePage() {
  return (
    <section className="mx-auto flex max-w-xl flex-col gap-8 px-4 py-12">
      <header>
        <h1 className="text-2xl font-semibold">Your profile</h1>
        <p className="mt-1 text-sm text-[var(--text-muted)]">
          Identity backed by your operator's LDAP directory.
        </p>
      </header>

      {/* Phase 9b: shows when email is unverified AND email is
          configured for this deployment. Renders nothing otherwise. */}
      <akashic-verify-email-banner />

      <akashic-profile editable />

      <div className="flex items-center justify-between rounded-md border border-[var(--text-muted)]/20 bg-[var(--card)] p-4 text-sm">
        <div>
          <p className="font-medium">Change password</p>
          <p className="text-[var(--text-muted)]">
            Updates your password in the directory.
          </p>
        </div>
        <Link
          href="/profile/password"
          className="rounded-md border border-[var(--text-muted)]/30 px-3 py-1.5 hover:bg-[var(--bg)]"
        >
          Open
        </Link>
      </div>

      <div className="flex items-center justify-between rounded-md border border-[var(--text-muted)]/20 bg-[var(--card)] p-4 text-sm">
        <div>
          <p className="font-medium">Two-factor authentication</p>
          <p className="text-[var(--text-muted)]">
            Add an email code as a second step at sign-in.
          </p>
        </div>
        <Link
          href="/profile/mfa"
          className="rounded-md border border-[var(--text-muted)]/30 px-3 py-1.5 hover:bg-[var(--bg)]"
        >
          Open
        </Link>
      </div>

      <div className="flex items-center justify-between rounded-md border border-[var(--text-muted)]/20 bg-[var(--card)] p-4 text-sm">
        <div>
          <p className="font-medium">Change ID / tag</p>
          <p className="text-[var(--text-muted)]">
            Rotate your <code>id#TAG</code> handle. Cooldown applies.
          </p>
        </div>
        <Link
          href="/profile/change-id"
          className="rounded-md border border-[var(--text-muted)]/30 px-3 py-1.5 hover:bg-[var(--bg)]"
        >
          Open
        </Link>
      </div>

      <div className="flex items-center justify-between rounded-md border border-[var(--text-muted)]/20 bg-[var(--card)] p-4 text-sm">
        <div>
          <p className="font-medium">OAuth clients</p>
          <p className="text-[var(--text-muted)]">
            Register integrations and manage their credentials.
          </p>
        </div>
        <Link
          href="/profile/clients"
          className="rounded-md border border-[var(--text-muted)]/30 px-3 py-1.5 hover:bg-[var(--bg)]"
        >
          Open
        </Link>
      </div>

      <div className="flex items-center justify-between rounded-md border border-[var(--text-muted)]/20 bg-[var(--card)] p-4 text-sm">
        <div>
          <p className="font-medium">Connected apps</p>
          <p className="text-[var(--text-muted)]">
            Review and revoke third-party apps you've signed into.
          </p>
        </div>
        <Link
          href="/profile/connected-apps"
          className="rounded-md border border-[var(--text-muted)]/30 px-3 py-1.5 hover:bg-[var(--bg)]"
        >
          Open
        </Link>
      </div>
    </section>
  );
}
