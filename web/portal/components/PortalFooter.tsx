/**
 * Footer for all public-facing pages. Quiet — copyright + a couple
 * of useful links. Operator-rebrand-able copy via env vars.
 */

import Link from "next/link";

import { env } from "../lib/env";

export function PortalFooter() {
  const year = new Date().getFullYear();
  return (
    <footer className="border-t border-[var(--text-muted)]/15 bg-[var(--card)]/30">
      <div className="mx-auto flex max-w-5xl flex-col gap-3 px-4 py-6 text-xs text-[var(--text-muted)] sm:flex-row sm:items-center sm:justify-between">
        <p>
          © {year} {env.brand.name}. Powered by Akashic.
        </p>
        <nav className="flex gap-4">
          <Link href="/forgot" className="hover:text-[var(--text)]">
            Forgot password?
          </Link>
          <Link href="/sign-in" className="hover:text-[var(--text)]">
            Sign in
          </Link>
        </nav>
      </div>
    </footer>
  );
}
