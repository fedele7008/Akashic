/**
 * POST /api/auth/logout
 *
 * Destroys the portal session and (optionally) bounces the user to
 * the auth server's /logout endpoint so the auth-server session
 * cookie also clears. Returns JSON to the FE rather than 303 — the
 * FE chooses what to do next (typically window.location='/').
 *
 * GET is also accepted as a convenience for "log me out" links.
 */

import { NextRequest, NextResponse } from "next/server";

import { destroySession } from "../../../../server/session";
import { auditLog } from "../../../../server/audit";

async function handle(req: NextRequest) {
  await destroySession();
  auditLog(req, "portal.signout", { outcome: "success" });
  return NextResponse.json({ success: true, data: { signed_out: true } });
}

export const GET = handle;
export const POST = handle;
