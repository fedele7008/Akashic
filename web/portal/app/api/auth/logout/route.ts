/**
 * /api/auth/logout — RP-initiated logout.
 *
 * Two-stage cleanup:
 *   1. Destroy the portal's own Redis-backed session and clear the
 *      sealed cookie.
 *   2. Send the browser to the auth server's `/logout` so the IdP-
 *      side session cookie also dies. We pass `post_logout_redirect_uri`
 *      so the user lands back at the portal's root after the round-trip.
 *
 * GET handler:
 *   Used by the "Sign out" link in the authenticated header. Returns
 *   a 303 redirect — appropriate for a navigation-style sign-out UX.
 *
 * POST handler:
 *   Returns JSON so JS callers (e.g. an "are you sure?" modal) can
 *   trigger logout without an immediate navigation, then drive the
 *   redirect themselves.
 */

import { NextRequest, NextResponse } from "next/server";

import { auditLog } from "../../../../server/audit";
import { destroySession, getSession } from "../../../../server/session";
import { env } from "../../../../lib/env";

/** Compute "https://portal-host/" from the OAuth redirect_uri config. */
function portalRoot(): string {
  try {
    const u = new URL(env.oauth.redirectUri);
    u.pathname = "/";
    u.search = "";
    u.hash = "";
    return u.toString();
  } catch {
    return "/";
  }
}

/** Build the auth-server logout URL with post-logout redirect + id_token_hint. */
function buildIdpLogoutUrl(idTokenHint: string | null): string | null {
  try {
    const issuer = new URL(env.oauth.issuer);
    issuer.pathname = "/logout";
    issuer.searchParams.set("post_logout_redirect_uri", portalRoot());
    if (idTokenHint) issuer.searchParams.set("id_token_hint", idTokenHint);
    return issuer.toString();
  } catch {
    // Issuer not configured (e.g. running in a test env that hasn't
    // set AKASHIC_OAUTH_ISSUER yet). Skip the IdP round-trip — the
    // portal session is the most-important piece anyway.
    return null;
  }
}

export async function GET(req: NextRequest) {
  const session = await getSession();
  const idTokenHint = session?.id_token ?? null;

  await destroySession();
  auditLog(req, "portal.signout", { outcome: "success" });

  const idpLogout = buildIdpLogoutUrl(idTokenHint);
  return NextResponse.redirect(idpLogout ?? portalRoot(), { status: 303 });
}

export async function POST(req: NextRequest) {
  const session = await getSession();
  const idTokenHint = session?.id_token ?? null;
  await destroySession();
  auditLog(req, "portal.signout", { outcome: "success" });

  const idpLogout = buildIdpLogoutUrl(idTokenHint);
  return NextResponse.json({
    success: true,
    data: {
      signed_out: true,
      idp_logout_url: idpLogout,
    },
  });
}
