/**
 * GET /api/auth/authorize
 *
 * Entry point for sign-in. Generates fresh PKCE/state/nonce, stashes
 * them in a sealed pre-session cookie, and redirects the browser to
 * the auth server's /authorize endpoint.
 *
 * Optional query param: `return_to=/some/path` — preserved through
 * the round-trip so that the callback handler can land the user back
 * where they started.
 */

import { NextRequest, NextResponse } from "next/server";

import {
  buildAuthorizeUrl,
  computeCodeChallenge,
  CredentialsMissingError,
  generateCodeVerifier,
  generateNonce,
  generateState,
} from "../../../../server/oauth";
import { writePreSession } from "../../../../server/pre-session";
import { auditLog } from "../../../../server/audit";

export async function GET(req: NextRequest) {
  const returnTo = sanitizeReturnTo(req.nextUrl.searchParams.get("return_to"));

  const state = generateState();
  const nonce = generateNonce();
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await computeCodeChallenge(codeVerifier);

  await writePreSession({
    state,
    nonce,
    code_verifier: codeVerifier,
    return_to: returnTo,
  });

  let url: string;
  try {
    url = await buildAuthorizeUrl({ state, nonce, codeChallenge });
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);

    // Distinguish "operator hasn't registered the sample yet" (an
    // actionable misconfiguration) from "real network/discovery
    // failure" (transient, retry / escalate). Same friendly browser
    // message; different machine-readable code + diagnostic detail.
    if (err instanceof CredentialsMissingError) {
      auditLog(req, "portal.signin.credentials_missing", {
        outcome: "fail",
        message: errMsg,
      });
      return NextResponse.json(
        {
          success: false,
          error: {
            code: "CREDENTIALS_MISSING",
            message: "Sign-in is unavailable: this sample hasn't been registered yet.",
            details: { hint: errMsg },
          },
        },
        { status: 503 },
      );
    }

    auditLog(req, "portal.signin.discovery_failed", {
      outcome: "fail",
      message: errMsg,
    });
    return NextResponse.json(
      {
        success: false,
        error: {
          code: "OAUTH_DISCOVERY_FAILED",
          message: "Sign-in is temporarily unavailable. Please retry shortly.",
          details: { hint: errMsg },
        },
      },
      { status: 503 },
    );
  }

  auditLog(req, "portal.signin.start", { outcome: "success" });
  return NextResponse.redirect(url, { status: 303 });
}

/**
 * Drop anything that isn't a relative path, to prevent open-redirect
 * attacks via a crafted return_to. The auth server has its own
 * separate redirect_uri allowlist, but we double-up here because the
 * portal is the one persisting the value across the round-trip.
 */
function sanitizeReturnTo(raw: string | null): string | undefined {
  if (!raw) return undefined;
  if (!raw.startsWith("/") || raw.startsWith("//")) return undefined;
  return raw;
}
