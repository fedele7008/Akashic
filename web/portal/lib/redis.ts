/**
 * Singleton ioredis client for the portal.
 *
 * One client per Node process, lazily constructed on first use.
 * Connects to the Akashic Redis on logical DB 2 — separate from
 * the auth server (DB 0) and the admin-bff (DB 1) so an operator can
 * `FLUSHDB` portal sessions without touching the others.
 *
 * Connection rules pulled from env (see lib/env.ts):
 *   AKASHIC_PORTAL_REDIS_HOST/PORT/PASSWORD/TLS/DB
 *
 * TLS:
 *   When AKASHIC_PORTAL_REDIS_TLS=on (the default), ioredis is
 *   configured with `tls: {}` which uses the system trust store. The
 *   portal container has the akashic CA rooted via update-ca-cert at
 *   build time (Dockerfile), so cert validation succeeds without
 *   per-client cert paths.
 */

import Redis, { type Redis as RedisClient } from "ioredis";

import { env } from "./env";

let client: RedisClient | undefined;

export function getRedis(): RedisClient {
  if (client) return client;

  client = new Redis({
    host: env.redis.host,
    port: env.redis.port,
    password: env.redis.password || undefined,
    db: env.redis.db,
    // Empty TLS object = "use defaults"; Node trusts the akashic CA
    // because the portal's entrypoint installs it into the OS trust
    // store via update-ca-certificates before exec'ing node. See
    // services/portal/portal-entrypoint.sh.
    tls: env.redis.tls ? {} : undefined,
    // Don't keep retrying forever on first boot — fail fast so the
    // operator notices the misconfiguration.
    maxRetriesPerRequest: 3,
    enableReadyCheck: true,
    // ioredis logs to stderr by default; that lands in docker logs and
    // gets shipped via the existing Loki scraper.
  });

  client.on("error", (err) => {
    // We don't crash the process — the portal can degrade-without-Redis
    // for static pages. Handlers that touch the session will fail
    // explicitly and return 503 to the browser.
    console.error("[portal/redis] connection error:", err.message);
  });

  return client;
}
