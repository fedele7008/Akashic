/**
 * /sign-up — public registration. Now mounts <akashic-signup>
 * directly. The widget calls api.<tenant>/users/register itself
 * (no portal BFF involved); on success the SignUpWidget client
 * wrapper redirects to /sign-in to start the OAuth flow.
 */

import Link from "next/link";

import { SignUpWidget } from "../../../components/SignUpWidget";
import { env } from "../../../lib/env";

export default function SignUpPage() {
  return (
    <section className="mx-auto flex max-w-md flex-col gap-6 px-4 py-12">
      <header className="flex flex-col gap-2">
        <h1 className="text-2xl font-semibold">Create your {env.brand.name} account</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Already have one?{" "}
          <Link href="/sign-in" className="text-[var(--accent)] hover:underline">
            Sign in instead
          </Link>
          .
        </p>
      </header>

      <SignUpWidget />

      <p className="text-xs text-[var(--text-muted)]">
        By creating an account you agree to be governed by your operator's
        terms of service. Forgot your password?{" "}
        <Link href="/forgot" className="text-[var(--accent)] hover:underline">
          Recovery options
        </Link>
        .
      </p>
    </section>
  );
}
