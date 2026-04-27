/**
 * GET /api/auth/callback
 *
 * The auth server redirects here after a successful /authorize. We:
 *   1. Read the pre-session cookie (carries state, nonce, code_verifier).
 *   2. Verify state.
 *   3. Exchange the code for tokens.
 *   4. Validate the id_token's nonce.
 *   5. Mint a Redis-backed session and seal a session cookie.
 *   6. Redirect the user to `return_to` (or `/` if absent).
 */

import { NextRequest, NextResponse } from "next/server";

import { exchangeCode, fetchUserInfo, getIdTokenClaims, resetOAuthCache } from "../../../../server/oauth";
import { clearPreSession, readPreSession } from "../../../../server/pre-session";
import { rotateAndCreateSession } from "../../../../server/session";
import { auditLog, resolveAuditIp } from "../../../../server/audit";
import { portalUrl } from "../../../../lib/env";

export async function GET(req: NextRequest) {
  const params = req.nextUrl.searchParams;

  // OAuth-protocol-level error from the auth server (user cancelled,
  // invalid_scope, etc.) lands here as ?error=... — short-circuit to
  // a clean failure page rather than trying to do an exchange.
  const protocolError = params.get("error");
  if (protocolError) {
    auditLog(req, "portal.signin.failure", {
      outcome: "fail",
      message: `${protocolError}: ${params.get("error_description") ?? ""}`.trim(),
    });
    await clearPreSession();
    return NextResponse.redirect(portalUrl("/sign-in?error=auth_failed"), {
      status: 303,
    });
  }

  const code = params.get("code");
  const state = params.get("state");

  if (!code || !state) {
    auditLog(req, "portal.signin.failure", {
      outcome: "fail",
      message: "missing code or state on callback",
    });
    return NextResponse.redirect(portalUrl("/sign-in?error=bad_callback"), {
      status: 303,
    });
  }

  const pre = await readPreSession();
  if (!pre) {
    auditLog(req, "portal.signin.failure", {
      outcome: "fail",
      message: "missing or expired pre-session cookie",
    });
    return NextResponse.redirect(portalUrl("/sign-in?error=expired"), {
      status: 303,
    });
  }

  let result;
  try {
    result = await exchangeCode({
      code,
      codeVerifier: pre.code_verifier,
      expectedState: pre.state,
      receivedState: state,
      expectedNonce: pre.nonce,
    });
  } catch (err) {
    // Discovery cache may be stale (issuer rotated keys). Reset and
    // surface to the user — they'll click sign-in again and the next
    // attempt will refresh discovery.
    resetOAuthCache();
    auditLog(req, "portal.signin.failure", {
      outcome: "fail",
      message: `token exchange threw: ${err instanceof Error ? err.message : String(err)}`,
    });
    await clearPreSession();
    return NextResponse.redirect(portalUrl("/sign-in?error=token_exchange_failed"), {
      status: 303,
    });
  }

  if (!result.ok) {
    auditLog(req, "portal.signin.failure", {
      outcome: "fail",
      message: `token exchange refused: ${result.code} ${result.message}`,
    });
    await clearPreSession();
    return NextResponse.redirect(
      portalUrl(`/sign-in?error=${encodeURIComponent(result.code.toLowerCase())}`),
      { status: 303 },
    );
  }

  const { tokens } = result;
  const accessToken = tokens.access_token;
  const idToken =
    typeof tokens.id_token === "string" && tokens.id_token.length > 0
      ? tokens.id_token
      : "";

  if (!idToken) {
    auditLog(req, "portal.signin.failure", {
      outcome: "fail",
      message: "no id_token in token response",
    });
    await clearPreSession();
    return NextResponse.redirect(portalUrl("/sign-in?error=no_id_token"), {
      status: 303,
    });
  }

  // The id_token's signature + nonce were already validated inside
  // exchangeCode (via expectedNonce). Just pull the parsed claims.
  const claims: Record<string, unknown> = getIdTokenClaims(result.tokens);

  // Pull additional profile fields from /userinfo so the session has a
  // populated email/username/user_type even if scope grants didn't put
  // them in the id_token.
  let userinfo: Record<string, unknown> = {};
  try {
    userinfo = await fetchUserInfo(accessToken);
  } catch {
    // Non-fatal: the id_token claims alone are enough to mint a
    // session. We log a softer warning rather than failing.
    auditLog(req, "portal.signin.userinfo_failed", { outcome: "warn" });
  }

  const sub = String(claims.sub ?? userinfo.sub ?? "");
  if (!sub) {
    auditLog(req, "portal.signin.failure", {
      outcome: "fail",
      message: "no sub claim",
    });
    await clearPreSession();
    return NextResponse.redirect(portalUrl("/sign-in?error=missing_sub"), {
      status: 303,
    });
  }

  // Compute access-token expiry. oauth4webapi normalises expires_in to
  // seconds; we convert to an ISO timestamp the session store can read.
  const expiresInSec = typeof tokens.expires_in === "number" ? tokens.expires_in : 3600;
  const accessExpires = new Date(Date.now() + expiresInSec * 1000).toISOString();

  await rotateAndCreateSession({
    user_id: sub,
    user_type: stringClaim(claims, userinfo, "user_type") || "user",
    username: stringClaim(claims, userinfo, "preferred_username"),
    email: stringClaim(claims, userinfo, "email"),
    access_token: accessToken,
    id_token: idToken,
    access_expires: accessExpires,
    ip: resolveAuditIp(req),
  });

  await clearPreSession();
  auditLog(req, "portal.signin.success", { outcome: "success" });

  // Bounce to return_to or root.
  const target = pre.return_to ?? "/";
  return NextResponse.redirect(portalUrl(target), { status: 303 });
}

function stringClaim(
  a: Record<string, unknown>,
  b: Record<string, unknown>,
  key: string,
): string {
  const v = a[key] ?? b[key];
  return typeof v === "string" ? v : "";
}
