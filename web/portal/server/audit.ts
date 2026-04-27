/**
 * Portal-side audit logging.
 *
 * Mirrors the admin-bff's pattern: explicit field allowlist, JSON
 * lines to stdout (which docker captures and the Loki scraper picks
 * up). Anything not in the allowlist is silently dropped — that's
 * the safety property: a future contributor cannot accidentally log
 * a password or access token by sticking it in the `fields` map.
 *
 * Portal-side events only. The api server (port 8082) emits its own
 * server-side audit lines for the resource-level operations like
 * `user.password_changed`, `client.created`, etc.
 */

import type { NextRequest } from "next/server";

const fieldAllowlist = new Set<string>([
  // Auto-set on every entry.
  "timestamp",
  "request_id",
  "action",
  "path",
  "method",
  "remote_ip",
  "user_agent",
  "referer",

  // Caller-supplied fields. Each is benign.
  "outcome",         // "success" | "fail" | "warn" | "rate_limited"
  "message",         // free-form short reason
  "code",            // upstream error code if relevant
  "status",          // upstream HTTP status
  "duration_ms",
  "username",        // never the password
  "email",
  "client_id",       // OAuth client id, not secret
  "user_type",
]);

interface AuditFields {
  [k: string]: string | number | boolean | undefined;
}

/**
 * Emit one audit line to stdout. Synchronous JSON.stringify + a
 * single process.stdout.write keeps ordering reasonable without a
 * dedicated lock — Node's stdout is line-buffered when piped to a
 * terminal but unbuffered when piped to docker, which is what we
 * want.
 */
export function auditLog(req: NextRequest, action: string, fields: AuditFields = {}): void {
  const entry: Record<string, unknown> = {
    timestamp: new Date().toISOString(),
    action,
    path: req.nextUrl.pathname,
    method: req.method,
    remote_ip: resolveAuditIp(req),
    user_agent: req.headers.get("user-agent") ?? undefined,
  };
  const ref = req.headers.get("referer");
  if (ref) entry.referer = ref;

  for (const [k, v] of Object.entries(fields)) {
    if (fieldAllowlist.has(k) && v !== undefined) {
      entry[k] = v;
    }
  }

  // Single write, JSON-line. Failure here must not bubble — logging
  // is best-effort.
  try {
    process.stdout.write(JSON.stringify(entry) + "\n");
  } catch {
    // ignore
  }
}

/**
 * Best-effort client-IP resolution. Honours X-Forwarded-For from the
 * front proxy (which the akashic nginx-proxy sets after its own
 * X-Forwarded-* trust-chain validation), falling back to whatever
 * Next.js can derive from the connection.
 */
export function resolveAuditIp(req: NextRequest): string {
  const xff = req.headers.get("x-forwarded-for");
  if (xff) {
    // First entry in the comma-separated list is the original client.
    const first = xff.split(",")[0]?.trim();
    if (first) return first;
  }
  const xri = req.headers.get("x-real-ip");
  if (xri) return xri;
  // Next 15 exposes req.ip in some adapters; fallback to "unknown".
  // We don't access (req as any).ip here because Next 15 has been
  // tightening the API and that field isn't typed on NextRequest.
  return "unknown";
}
