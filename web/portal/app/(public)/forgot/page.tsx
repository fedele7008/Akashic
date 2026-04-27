/**
 * /forgot — informational only in Phase 8.
 *
 * Self-service password reset is deferred to Phase 9 (no email
 * channel yet). This page tells the user how to recover their
 * account in the meantime: contact the operator's support address
 * (configured via AKASHIC_PORTAL_SUPPORT_EMAIL).
 *
 * We also call the api server's `/users/forgot-password-help`
 * endpoint at render time so the message stays in lockstep with
 * what the backend says about its own state — when Phase 9 lands
 * and self-service goes live, that endpoint's response shape
 * changes and this page picks up the new copy automatically.
 */

import Link from "next/link";

import { apiCallPublic } from "../../../server/api-client";
import { env } from "../../../lib/env";

interface ForgotHelp {
  phase: number;
  self_service: boolean;
  support_contact: string;
  message: string;
}

export const dynamic = "force-dynamic"; // never cache; reflects backend state

export default async function ForgotPage() {
  const result = await apiCallPublic<ForgotHelp>("/users/forgot-password-help");
  const help: ForgotHelp =
    result.ok && result.data
      ? result.data
      : {
          phase: 8,
          self_service: false,
          support_contact: env.brand.supportEmail || "(operator not configured)",
          message:
            "Self-service password recovery is not yet available on this deployment.",
        };

  return (
    <section className="mx-auto flex max-w-md flex-col gap-6 px-4 py-16">
      <header className="flex flex-col gap-2">
        <h1 className="text-2xl font-semibold">Forgot your password?</h1>
      </header>

      <div className="rounded-md border border-[var(--text-muted)]/20 bg-[var(--card)] p-4 text-sm text-[var(--text)]">
        <p>{help.message}</p>
        {help.support_contact ? (
          <p className="mt-3 text-[var(--text-muted)]">
            Contact your operator at{" "}
            <span className="font-mono text-[var(--text)]">{help.support_contact}</span>{" "}
            to request a password reset.
          </p>
        ) : null}
      </div>

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
