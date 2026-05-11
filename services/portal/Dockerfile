# ──────────────────────────────────────────────────────────────────────
# Akashic portal — multi-stage Next.js build
#
# Three stages:
#   1. deps      — node 22-alpine, runs `npm ci` to populate node_modules
#   2. builder   — uses the deps + project source, runs `next build`
#                  (with output: 'standalone' → produces a self-contained
#                  bundle at .next/standalone/)
#   3. runner    — slim runtime, copies just the standalone bundle and
#                  the prerendered static assets. No npm in this stage.
#
# The standalone bundle includes a minimal node_modules with only the
# packages the runtime actually needs — which is dramatically smaller
# than the dev install. Final image weighs in around 200MB vs ~1GB
# for the naive approach.
# ──────────────────────────────────────────────────────────────────────

# ─── Stage 1: install deps ────────────────────────────────────────────
FROM node:22-alpine AS deps

WORKDIR /app

# Copy only package metadata first so this layer caches across
# source-only changes. Bumping a dependency invalidates this layer;
# editing a .tsx file does not.
COPY web/portal/package.json web/portal/package-lock.json ./
RUN npm ci --no-audit --no-fund

# ─── Stage 2: build ───────────────────────────────────────────────────
FROM node:22-alpine AS builder

WORKDIR /app

# Bring forward the resolved node_modules from stage 1.
COPY --from=deps /app/node_modules ./node_modules

# Copy the rest of the portal source. .dockerignore at the project
# root excludes test temp dirs, .env files, certs/, etc.
COPY web/portal/ ./

# `next build` produces .next/standalone/ (self-contained Node bundle)
# plus .next/static/ (the static assets). The runner stage copies
# both.
RUN npm run build

# ─── Stage 3: runtime ─────────────────────────────────────────────────
FROM node:22-alpine AS runner

# ca-certificates  — needed by update-ca-certificates so the entrypoint
#                    can install the akashic internal CA into the OS
#                    trust store. Once it's there, Node's TLS defaults
#                    Just Work for both fetch (api server) and ioredis
#                    — no NODE_EXTRA_CA_CERTS, no undici dispatcher
#                    plumbing.
# su-exec         — minimal "drop privileges and exec" tool. The
#                    entrypoint runs briefly as root to update certs,
#                    then drops to uid 10100 before exec'ing node.
RUN apk add --no-cache ca-certificates su-exec

# Run as a non-root user for the actual server process. Same uid/gid
# convention as the admin-bff (10100). The entrypoint starts as root
# (we don't set USER here) to update the cert trust store, then
# drops to akashic via su-exec.
RUN addgroup -g 10100 akashic && \
    adduser -D -u 10100 -G akashic akashic

WORKDIR /app

# Standalone output is the canonical Next.js Docker pattern. The
# directory layout it produces:
#   .next/standalone/        ← copy here as /app/
#   .next/standalone/server.js   (the entry point)
#   .next/static/            ← still need to be served, copy alongside
#   public/                  ← static-files dir
# COPY --from=builder --chown=akashic:akashic /app/public ./public
COPY --from=builder --chown=akashic:akashic /app/.next/standalone ./
COPY --from=builder --chown=akashic:akashic /app/.next/static ./.next/static

# Entrypoint runs as root (cert install) then drops to akashic.
COPY services/portal/portal-entrypoint.sh /usr/local/bin/portal-entrypoint.sh
RUN chmod +x /usr/local/bin/portal-entrypoint.sh

# NOTE: NO `USER akashic` here. The entrypoint script handles that
# transition itself (via su-exec) after running update-ca-certificates.

ENV PORT=3000
ENV HOSTNAME=0.0.0.0
EXPOSE 3000

# Default CMD is just the entrypoint's exec target; compose overrides
# `entrypoint:` to use portal-entrypoint.sh, which then exec's node.
CMD ["node", "server.js"]
