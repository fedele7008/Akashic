/**
 * /profile/password — change password.
 */

import Link from "next/link";

import { ChangePasswordForm } from "../../../../components/ChangePasswordForm";

export default function ChangePasswordPage() {
  return (
    <section className="mx-auto flex max-w-md flex-col gap-6 px-4 py-12">
      <header className="flex flex-col gap-1">
        <h1 className="text-2xl font-semibold">Change password</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Updates your password in the operator’s identity directory.
        </p>
      </header>

      <ChangePasswordForm />

      <p className="text-xs text-[var(--text-muted)]">
        <Link href="/profile" className="hover:underline">
          ← Back to profile
        </Link>
      </p>
    </section>
  );
}
