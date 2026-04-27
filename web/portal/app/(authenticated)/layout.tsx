/**
 * Authenticated layout. Gates every (authenticated)/* page on a live
 * portal session: if the cookie+Redis pair is missing or expired,
 * the user gets bounced to /sign-in.
 *
 * Why the gate lives here, not in middleware: our session payload
 * is server-side (Redis DB 2) and the lookup uses the Node-only
 * `ioredis` client. Middleware runs in the Edge runtime, which can't
 * import Node built-ins. Layouts run in the Node runtime on every
 * request — the natural place to do this kind of stateful auth
 * check.
 *
 * Force-dynamic: the session check is per-request; we can't cache.
 *
 * Touches (refreshes) the idle TTL on every authenticated render —
 * active users stay logged in, idle ones expire on schedule.
 */

import { redirect } from "next/navigation";

import { PortalFooter } from "../../components/PortalFooter";
import { PortalHeader } from "../../components/PortalHeader";
import { touchSession } from "../../server/session";

export const dynamic = "force-dynamic";

export default async function AuthenticatedLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const session = await touchSession();
  if (!session) {
    redirect("/sign-in");
  }

  return (
    <div className="flex min-h-screen flex-col">
      <PortalHeader session={session} />
      <main className="flex-1">{children}</main>
      <PortalFooter />
    </div>
  );
}
