/**
 * Short-lived "pre-session" cookie used during the OAuth round-trip.
 *
 * Stores `state`, `nonce`, and `code_verifier` between the moment we
 * issue an authorize redirect and the moment the auth server lands
 * the user on /api/auth/callback. We can't use the regular Redis
 * session for this because:
 *   1. The user isn't authenticated yet — there's no sid to anchor on.
 *   2. The values are single-use and tiny, so the cookie ceiling
 *      isn't a concern.
 *
 * iron-session seals it with the same secret as the main session
 * cookie. TTL is short (5 minutes) — long enough for a slow human at
 * the login form, short enough to discourage replay.
 */

import { sealData, unsealData } from "iron-session";
import { cookies } from "next/headers";

import { env } from "../lib/env";

export interface PreSession {
  state: string;
  nonce: string;
  code_verifier: string;
  /** Optional path to redirect to after sign-in (relative). */
  return_to?: string;
  /** ISO-8601 of issuance. */
  issued_at: string;
}

const COOKIE_NAME = "akashic_portal_pre_session";
const TTL_SECONDS = 5 * 60;

const cookieOpts = {
  httpOnly: true,
  secure: env.nodeEnv === "production",
  sameSite: "lax" as const,
  path: "/",
};

export async function writePreSession(p: Omit<PreSession, "issued_at">): Promise<void> {
  const sealed = await sealData(
    { ...p, issued_at: new Date().toISOString() },
    { password: env.session.password, ttl: TTL_SECONDS },
  );
  const jar = await cookies();
  jar.set(COOKIE_NAME, sealed, { ...cookieOpts, maxAge: TTL_SECONDS });
}

export async function readPreSession(): Promise<PreSession | null> {
  const jar = await cookies();
  const raw = jar.get(COOKIE_NAME)?.value;
  if (!raw) return null;
  try {
    const obj = await unsealData<PreSession>(raw, {
      password: env.session.password,
      ttl: TTL_SECONDS,
    });
    if (
      !obj ||
      typeof obj.state !== "string" ||
      typeof obj.nonce !== "string" ||
      typeof obj.code_verifier !== "string"
    ) {
      return null;
    }
    return obj;
  } catch {
    return null;
  }
}

export async function clearPreSession(): Promise<void> {
  const jar = await cookies();
  jar.set(COOKIE_NAME, "", { ...cookieOpts, maxAge: 0 });
}
