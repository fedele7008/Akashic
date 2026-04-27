/**
 * Top-level Next.js middleware.
 *
 * Applies CSRF protection to all /api/* routes. The OAuth handlers
 * (/api/auth/authorize, /api/auth/callback) are deliberately
 * *exempt*: they're entered via redirect from the auth server, not
 * via a JS-driven fetch from our own FE, so the FE has no chance to
 * set the X-Akashic-CSRF header on the way in. The CSRF cookie is
 * still present (issued on prior requests) but we don't enforce it
 * on the OAuth round-trip.
 *
 * This file is a Next 15 convention — placed at the project root,
 * exporting `middleware` and a `config.matcher`.
 */

import { NextRequest, NextResponse } from "next/server";

import { applyCsrf } from "./server/csrf";

// Routes that should not run through the CSRF gate at all — middleware
// returns early without touching the response. We keep this list
// minimal because GET/HEAD/OPTIONS already bypass the CSRF *check*
// inside applyCsrf (safe methods just receive the cookie); only paths
// that must NOT receive the cookie at all need to live here.
//
// Currently empty — every /api/* path runs through applyCsrf, which
// is what bootstraps the cookie on the first /api/* GET (used by
// /api/health on form pages to seed the token before a POST).
const csrfExemptPrefixes: string[] = [];

export function middleware(req: NextRequest): NextResponse | undefined {
  const path = req.nextUrl.pathname;
  if (!path.startsWith("/api/")) return undefined;
  for (const prefix of csrfExemptPrefixes) {
    if (path.startsWith(prefix)) return undefined;
  }
  return applyCsrf(req);
}

export const config = {
  // Run middleware on /api/* only. Page routes and static assets
  // bypass it entirely — that's a meaningful perf win because most
  // requests on a public portal are page reads.
  matcher: ["/api/:path*"],
};
