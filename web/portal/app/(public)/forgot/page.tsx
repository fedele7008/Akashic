/**
 * /forgot — informational. Mounts <akashic-forgot-help> which fetches
 * `/users/forgot-password-help` from the api server itself.
 *
 * Phase 8 status: self-service password reset is deferred to Phase 9.
 * The widget displays whatever the api server's help endpoint says,
 * so this page becomes correct automatically when Phase 9 swaps in
 * a real recovery flow.
 */

import Link from "next/link";

export default function ForgotPage() {
  return (
    <section className="mx-auto flex max-w-md flex-col gap-6 px-4 py-16">
      <header className="flex flex-col gap-2">
        <h1 className="text-2xl font-semibold">Forgot your password?</h1>
      </header>

      <akashic-forgot-help />

      <div className="flex gap-3">
        <Link
          href="/sign-in"
          className="rounded-md bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white hover:opacity-90"
        >
          Back to sign in
        </Link>
        <Link
          href="/"
          className="rounded-md border border-[var(--text-muted)]/30 px-4 py-2 text-sm text-[var(--text)] hover:bg-[var(--card)]"
        >
          Home
        </Link>
      </div>
    </section>
  );
}
