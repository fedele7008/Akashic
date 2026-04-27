/**
 * CSRF — double-submit cookie, identical scheme to admin-bff.
 *
 * On any /api/* request we ensure a cookie named `akashic_portal_csrf`
 * exists. The cookie is HttpOnly=false BY DESIGN: client-side code
 * reads it and echoes it back in `X-Akashic-CSRF` on every state-
 * changing call. We compare cookie vs header in constant time and
 * reject on mismatch.
 *
 * Why this works: same-origin code can read the cookie and set the
 * header; cross-origin code can do neither (cookies are origin-scoped
 * and JS-readable cookies aren't sent on cross-origin XHR by default).
 * SameSite=Strict on the cookie is belt-and-suspenders for older
 * browsers.
 */

import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

import { env } from "../lib/env";

// Web Crypto API — works in both Node ≥18 and Next.js Edge runtime,
// which is what the middleware actually executes in. We avoid
// `node:crypto.randomBytes` here because Edge bundles can't import
// Node built-ins.
function randomHex(byteLen: number): string {
  const buf = new Uint8Array(byteLen);
  crypto.getRandomValues(buf);
  let s = "";
  for (let i = 0; i < buf.length; i++) {
    s += buf[i].toString(16).padStart(2, "0");
  }
  return s;
}

export const CSRF_COOKIE_NAME = "akashic_portal_csrf";
export const CSRF_HEADER_NAME = "x-akashic-csrf";

const CSRF_TOKEN_BYTES = 32;

const safeMethods = new Set(["GET", "HEAD", "OPTIONS"]);

/**
 * Apply double-submit CSRF to a Next middleware request. Returns
 * either a NextResponse (rejecting the request, or just attaching a
 * fresh cookie) or `undefined` (let the route handler proceed).
 *
 * Designed to be called from `middleware.ts`'s top-level
 * `middleware()` function on requests that target /api/*.
 */
export function applyCsrf(req: NextRequest): NextResponse | undefined {
  // Always ensure the cookie exists. For idempotent methods that's the
  // entirety of our work — the next response will carry the Set-Cookie.
  const existing = req.cookies.get(CSRF_COOKIE_NAME)?.value;
  let issuedToken: string | undefined;
  if (!existing) {
    issuedToken = randomHex(CSRF_TOKEN_BYTES);
  }

  if (safeMethods.has(req.method)) {
    if (!issuedToken) return undefined; // existing cookie, no work
    const res = NextResponse.next();
    setCsrfCookie(res, issuedToken);
    return res;
  }

  // State-changing method: enforce match.
  const cookieValue = existing ?? issuedToken; // if the request had no cookie, the header definitely won't match the freshly minted one
  const headerValue = req.headers.get(CSRF_HEADER_NAME);

  if (!cookieValue || !headerValue || !timingSafeEqual(cookieValue, headerValue)) {
    return NextResponse.json(
      {
        success: false,
        error: {
          code: "CSRF_FAILED",
          message: "CSRF token missing or mismatched. Reload the page and try again.",
        },
      },
      { status: 403 },
    );
  }

  if (issuedToken) {
    const res = NextResponse.next();
    setCsrfCookie(res, issuedToken);
    return res;
  }
  return undefined;
}

function setCsrfCookie(res: NextResponse, token: string): void {
  res.cookies.set(CSRF_COOKIE_NAME, token, {
    path: "/",
    httpOnly: false,                       // FE must read this in JS
    secure: env.nodeEnv === "production",
    sameSite: "strict",
    maxAge: 60 * 60 * 24,                  // 24 h is plenty
  });
}

/**
 * Constant-time string compare. Avoids leaking the per-byte position
 * of the first mismatch to a timing-attacker.
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
