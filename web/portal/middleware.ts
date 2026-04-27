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

const csrfExemptPrefixes = [
  // OAuth round-trip — entered by redirect from the auth server.
  "/api/auth/authorize",
  "/api/auth/callback",
  // Liveness — k8s-ish probes don't carry CSRF tokens.
  "/api/health",
];

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
