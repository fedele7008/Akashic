/**
 * Portal session subsystem.
 *
 * Two-layer design:
 *
 *   Cookie (browser)  ←→  iron-session-sealed `{ sid }`
 *                                   │
 *                                   ▼
 *   Redis (server)    ←→  full session payload, keyed by sid
 *
 * The cookie carries only an opaque ID; the actual identity claims +
 * access token live in Redis (DB 2). This keeps the cookie small
 * (under 500 B) and gives us server-side revocation, which iron-
 * session's stand-alone "store everything in cookie" mode does NOT.
 *
 * TTL model mirrors the admin-bff's: idle TTL refreshes on activity,
 * absolute TTL is a hard ceiling. Both enforced server-side.
 */

import { sealData, unsealData } from "iron-session";
import { cookies } from "next/headers";
import type { ReadonlyRequestCookies } from "next/dist/server/web/spec-extension/adapters/request-cookies";
import { randomBytes } from "node:crypto";

import { env } from "../lib/env";
import { getRedis } from "../lib/redis";

/** Identity + token material parked in Redis under the session id. */
export interface SessionPayload {
  /** UUID of the user, from the OIDC `sub` claim. */
  user_id: string;
  /** "user" | "admin" | "root" — from the access token's user_type claim. */
  user_type: string;
  /** From the OIDC `preferred_username` claim. */
  username: string;
  /** From the OIDC `email` claim. */
  email: string;
  /** OAuth access token. Used by the api-client to call `api.akashic.local`. */
  access_token: string;
  /** ID token, kept for logout-hint and future use. */
  id_token: string;
  /** ISO-8601 instant when the access token expires. */
  access_expires: string;
  /** ISO-8601 instant when this session was created. */
  issued_at: string;
  /** ISO-8601 instant of the most recent activity. */
  last_activity_at: string;
  /** Client IP at session creation (informational, for audit). */
  ip: string;
}

/** Sealed inside the iron-session cookie. Tiny on purpose. */
interface SessionCookie {
  sid: string;
}

const REDIS_KEY_PREFIX = "akashic:bff:portal:session:";
const SESSION_ID_BYTES = 32;

/**
 * Global cookie options. iron-session adds its own cryptographic
 * envelope, so the cookie value itself is opaque ciphertext.
 */
const cookieOpts = {
  httpOnly: true,
  // Secure is forced true in production. In dev (HTTP) we leave it
  // off so local cookies actually stick — same trade-off the admin-bff
  // makes.
  secure: env.nodeEnv === "production",
  sameSite: "lax" as const,
  path: "/",
};

function redisKey(sid: string): string {
  return REDIS_KEY_PREFIX + sid;
}

function newSessionId(): string {
  // 32 bytes → 43 chars base64url. Plenty of entropy, fits comfortably
  // inside a sealed cookie even after iron-session's overhead.
  return randomBytes(SESSION_ID_BYTES).toString("base64url");
}

/** Sealed cookie helpers. */
async function sealCookie(c: SessionCookie): Promise<string> {
  return sealData(c, {
    password: env.session.password,
    ttl: env.session.absoluteSeconds,
  });
}

async function unsealCookie(raw: string): Promise<SessionCookie | null> {
  try {
    const obj = await unsealData<SessionCookie>(raw, {
      password: env.session.password,
      ttl: env.session.absoluteSeconds,
    });
    if (!obj || typeof obj.sid !== "string" || obj.sid.length === 0) {
      return null;
    }
    return obj;
  } catch {
    // Tampered, expired (iron-session enforces its own ttl), or simply
    // unparseable. Treat all of those as "no session".
    return null;
  }
}

/** Read the session ID from the request cookie. Null if absent/invalid. */
async function readSidFromCookie(
  jar?: ReadonlyRequestCookies,
): Promise<string | null> {
  const cookieJar = jar ?? (await cookies());
  const raw = cookieJar.get(env.session.cookieName)?.value;
  if (!raw) return null;
  const c = await unsealCookie(raw);
  return c?.sid ?? null;
}

/**
 * Fetch the current session WITHOUT bumping its idle TTL. Use this
 * for read-only inspections — render-time profile reads, audit
 * lookups, etc. Returns null on any failure (no session, expired,
 * tampered, Redis down). Callers must handle the null case.
 */
export async function getSession(): Promise<SessionPayload | null> {
  const sid = await readSidFromCookie();
  if (!sid) return null;

  const r = getRedis();
  const raw = await r.get(redisKey(sid));
  if (!raw) return null;

  let p: SessionPayload;
  try {
    p = JSON.parse(raw) as SessionPayload;
  } catch {
    return null;
  }

  // Idle expiry: if the last activity is older than the idle TTL,
  // the session is dead. Delete from Redis to keep storage tidy.
  const lastMs = Date.parse(p.last_activity_at);
  if (
    Number.isFinite(lastMs) &&
    Date.now() - lastMs > env.session.idleSeconds * 1000
  ) {
    await r.del(redisKey(sid));
    return null;
  }

  return p;
}

/**
 * Like getSession but bumps last_activity_at. Use this on every
 * authenticated handler that's not strictly read-only.
 */
export async function touchSession(): Promise<SessionPayload | null> {
  const sid = await readSidFromCookie();
  if (!sid) return null;
  const r = getRedis();
  const raw = await r.get(redisKey(sid));
  if (!raw) return null;

  let p: SessionPayload;
  try {
    p = JSON.parse(raw) as SessionPayload;
  } catch {
    return null;
  }

  // Idle check first (mirrors getSession).
  const lastMs = Date.parse(p.last_activity_at);
  if (
    Number.isFinite(lastMs) &&
    Date.now() - lastMs > env.session.idleSeconds * 1000
  ) {
    await r.del(redisKey(sid));
    return null;
  }

  // Compute remaining absolute TTL — never extend past issued_at + abs.
  const issuedMs = Date.parse(p.issued_at);
  const absRemainingSec = Math.floor(
    (issuedMs + env.session.absoluteSeconds * 1000 - Date.now()) / 1000,
  );
  if (absRemainingSec <= 0) {
    await r.del(redisKey(sid));
    return null;
  }

  p.last_activity_at = new Date().toISOString();
  await r.set(redisKey(sid), JSON.stringify(p), "EX", absRemainingSec);
  return p;
}

/**
 * Create a fresh session and write the sealed cookie. Returns the
 * session id (caller doesn't usually need it; provided so audit
 * loggers can correlate).
 */
export async function createSession(
  payload: Omit<SessionPayload, "issued_at" | "last_activity_at">,
): Promise<string> {
  const sid = newSessionId();
  const now = new Date().toISOString();
  const full: SessionPayload = {
    ...payload,
    issued_at: now,
    last_activity_at: now,
  };

  // Absolute TTL on the Redis key is the floor; idle is enforced
  // in code via the last_activity_at field.
  const r = getRedis();
  await r.set(
    redisKey(sid),
    JSON.stringify(full),
    "EX",
    env.session.absoluteSeconds,
  );

  const sealed = await sealCookie({ sid });
  const cookieJar = await cookies();
  cookieJar.set(env.session.cookieName, sealed, {
    ...cookieOpts,
    maxAge: env.session.absoluteSeconds,
  });

  return sid;
}

/**
 * Destroy the current session — Redis row + cookie. Idempotent: if
 * the cookie is already missing or the Redis key is gone, this is a
 * no-op.
 */
export async function destroySession(): Promise<void> {
  const sid = await readSidFromCookie();
  if (sid) {
    try {
      await getRedis().del(redisKey(sid));
    } catch {
      // If Redis is unreachable we still want to clear the cookie —
      // worst-case the Redis row hangs around until its absolute TTL
      // expires.
    }
  }
  const cookieJar = await cookies();
  cookieJar.set(env.session.cookieName, "", {
    ...cookieOpts,
    maxAge: 0,
  });
}

/**
 * Helper for OAuth callback / signup paths that just exchanged the
 * code for tokens and now need to mint a fresh session and redirect.
 * Prevents cookie-fixation by deleting any pre-existing session row
 * before writing the new one.
 */
export async function rotateAndCreateSession(
  payload: Omit<SessionPayload, "issued_at" | "last_activity_at">,
): Promise<string> {
  await destroySession();
  return createSession(payload);
}
