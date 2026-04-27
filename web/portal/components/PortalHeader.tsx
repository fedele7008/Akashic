/**
 * Top navigation header — session-adaptive.
 *
 * Branding on the left, nav on the right. The right side renders
 * differently based on whether the request has a live session:
 *
 *   - Signed out → "Sign in" link + "Sign up" CTA
 *   - Signed in  → user's name + Profile / Password / Sign out
 *
 * The `session` prop is passed by the layout. Layouts decide whether
 * to call `getSession()` (read-only) or `touchSession()` (refreshes
 * idle TTL), then forward the result here. The header itself does
 * no Redis I/O.
 */

import Link from "next/link";

import type { SessionPayload } from "../server/session";
import { env } from "../lib/env";

export function PortalHeader({ session }: { session: SessionPayload | null }) {
  return (
    <header className="border-b border-[var(--text-muted)]/15 bg-[var(--card)]">
      <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
        <Link
          href="/"
          className="text-base font-semibold text-[var(--text)] hover:opacity-80"
        >
          {env.brand.name}
        </Link>

        {session ? <AuthenticatedNav session={session} /> : <PublicNav />}
      </div>
    </header>
  );
}

function PublicNav() {
  return (
    <nav className="flex items-center gap-3 text-sm">
      <Link
        href="/sign-in"
        className="text-[var(--text-muted)] hover:text-[var(--text)]"
      >
        Sign in
      </Link>
      <Link
        href="/sign-up"
        className="rounded-md bg-[var(--accent)] px-3 py-1.5 text-white hover:opacity-90"
      >
        Sign up
      </Link>
    </nav>
  );
}

function AuthenticatedNav({ session }: { session: SessionPayload }) {
  // Username is a stable, always-present identifier. Display name (cn)
  // would be friendlier but it's stored in LDAP and we don't have it
  // on the session payload — Phase 9+ could add it.
  const display = session.username || session.user_id;
  return (
    <nav className="flex items-center gap-4 text-sm">
      <Link
        href="/profile"
        className="text-[var(--text-muted)] hover:text-[var(--text)]"
      >
        Profile
      </Link>
      <Link
        href="/profile/password"
        className="text-[var(--text-muted)] hover:text-[var(--text)]"
      >
        Password
      </Link>
      <span className="hidden text-[var(--text-muted)] sm:inline">·</span>
      <span className="hidden text-sm text-[var(--text-muted)] sm:inline">
        {display}
      </span>
      <a
        href="/api/auth/logout"
        className="rounded-md border border-[var(--text-muted)]/30 px-3 py-1.5 text-[var(--text)] hover:bg-[var(--bg)]"
      >
        Sign out
      </a>
    </nav>
  );
}
