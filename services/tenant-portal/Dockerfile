# ──────────────────────────────────────────────────────────────────────
# Akashic tenant-portal — multi-stage Next.js build
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

# Run as a non-root user. The portal reads /certs and /keys but
# never writes to them, so it doesn't need root. Same uid/gid
# convention as the admin-bff (10100). Cross-container UID matters
# for shared volumes — see Phase 7 chapter 5 of the study guide.
RUN addgroup -g 10100 akashic && \
    adduser -D -u 10100 -G akashic akashic

WORKDIR /app

# Standalone output is the canonical Next.js Docker pattern. The
# directory layout it produces:
#   .next/standalone/        ← copy here as /app/
#   .next/standalone/server.js   (the entry point)
#   .next/static/            ← still need to be served, copy alongside
#   public/                  ← static-files dir
#
# The standalone output sets an internal port via env (PORT=3000 by
# default).
COPY --from=builder --chown=akashic:akashic /app/public ./public
COPY --from=builder --chown=akashic:akashic /app/.next/standalone ./
COPY --from=builder --chown=akashic:akashic /app/.next/static ./.next/static

USER akashic

ENV PORT=3000
ENV HOSTNAME=0.0.0.0
EXPOSE 3000

# Standalone bundle's entry point is server.js at the root.
CMD ["node", "server.js"]
