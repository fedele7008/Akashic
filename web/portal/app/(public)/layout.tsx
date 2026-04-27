/**
 * Layout for the (public) route group: landing, sign-up, sign-in,
 * forgot-password.
 *
 * Reads the current session (if any) and forwards it to PortalHeader
 * so the header adapts to authenticated visitors — they see their
 * profile menu instead of sign-in/sign-up CTAs even on public pages.
 *
 * Uses `getSession()` (read-only) rather than `touchSession()`:
 * visiting the public landing should NOT keep an idle session alive
 * — that would defeat the idle-TTL.
 */

import { PortalFooter } from "../../components/PortalFooter";
import { PortalHeader } from "../../components/PortalHeader";
import { getSession } from "../../server/session";

export const dynamic = "force-dynamic";

export default async function PublicLayout({ children }: { children: React.ReactNode }) {
  const session = await getSession();
  return (
    <div className="flex min-h-screen flex-col">
      <PortalHeader session={session} />
      <main className="flex-1">{children}</main>
      <PortalFooter />
    </div>
  );
}
