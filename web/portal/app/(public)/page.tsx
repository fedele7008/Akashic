/**
 * Landing page — the bare deployment domain (`/`).
 *
 * Operator-rebrandable copy via env (`AKASHIC_PORTAL_BRAND_NAME`,
 * `AKASHIC_PORTAL_TAGLINE`, `AKASHIC_PORTAL_DESCRIPTION`).
 *
 * Session-aware CTAs: a signed-in visitor lands here too (e.g. if
 * they clicked the brand link in the header). For them we show
 * "Go to profile" instead of "Create account / Sign in" — both
 * latter would force them through a redundant OAuth round-trip.
 */

import Link from "next/link";

import { env } from "../../lib/env";
import { getSession } from "../../server/session";

export const dynamic = "force-dynamic";

export default async function LandingPage() {
  const session = await getSession();

  return (
    <section className="mx-auto flex max-w-3xl flex-col items-start gap-6 px-4 py-16 sm:py-24">
      <h1 className="text-4xl font-semibold leading-tight sm:text-5xl">
        {env.brand.tagline}
      </h1>
      <p className="text-base text-[var(--text-muted)] sm:text-lg">
        {env.brand.description}
      </p>
      <div className="mt-2 flex flex-wrap items-center gap-3">
        {session ? (
          <Link
            href="/profile"
            className="rounded-md bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white hover:opacity-90"
          >
            Go to profile
          </Link>
        ) : (
          <>
            <Link
              href="/sign-up"
              className="rounded-md bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white hover:opacity-90"
            >
              Create an account
            </Link>
            <Link
              href="/sign-in"
              className="rounded-md border border-[var(--text-muted)]/30 px-4 py-2 text-sm font-medium text-[var(--text)] hover:bg-[var(--card)]"
            >
              Sign in
            </Link>
          </>
        )}
      </div>
    </section>
  );
}
