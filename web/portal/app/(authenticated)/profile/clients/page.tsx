/**
 * /profile/clients — mounts <akashic-clients>. Lets the signed-in
 * user manage their own OAuth client registrations: register new
 * integrations, rotate secrets, delete clients they no longer use.
 *
 * Same widget-only integration pattern as the rest of the
 * authenticated surface — the page is a thin shell around the
 * widget. The widget itself talks to api.<tenant>/clients/* via the
 * bearer-token cookie bridge (auth.<tenant>/session/token), so the
 * portal's BFF doesn't sit on this path.
 */

import Link from "next/link";

export default function ClientsPage() {
  return (
    <section className="mx-auto flex max-w-5xl flex-col gap-6 px-4 py-12">
      <header className="flex flex-col gap-1">
        <h1 className="text-2xl font-semibold">Your OAuth clients</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Register integrations, rotate secrets, and remove clients
          you no longer use.
        </p>
      </header>

      <akashic-clients />

      <p className="text-xs text-[var(--text-muted)]">
        <Link href="/profile" className="hover:underline">
          ← Back to profile
        </Link>
      </p>
    </section>
  );
}
