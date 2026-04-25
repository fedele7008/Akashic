# ──────────────────────────────────────────────────────────────────────
# Akashic admin-bff — multi-stage build
#
# Three stages:
#   1. fe-builder    — node + npm: vite build of the React FE
#   2. go-builder    — go: builds the binary, embedding the FE dist
#   3. runtime       — alpine: minimal image with the static binary
#
# The .dockerignore excludes the host's node_modules/ and dist/ from
# the build context, so the vite stage builds fresh inside the image.
# ──────────────────────────────────────────────────────────────────────

# ─── Stage 1: vite build ──────────────────────────────────────────────
FROM node:20-alpine AS fe-builder

WORKDIR /src

# Copy only package metadata first so the dep-install layer caches
# across source-only changes. Bumping a dependency invalidates this
# layer; editing a .tsx file does not.
COPY web/admin/package.json web/admin/package-lock.json ./web/admin/
RUN cd web/admin && npm ci

# Now copy the full FE source and build. Vite's outDir is configured
# to emit to ../../cmd/admin-bff/dist (see web/admin/vite.config.ts),
# so after this RUN the artifact lives at /src/cmd/admin-bff/dist/.
COPY web/admin/ ./web/admin/
RUN mkdir -p /src/cmd/admin-bff && cd web/admin && npm run build

# ─── Stage 2: go build ────────────────────────────────────────────────
FROM golang:1.24-alpine AS go-builder

WORKDIR /src

# Cache go module downloads
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the project. The .dockerignore excludes test temp
# dirs, .env files, secrets/, certs/ — see project root .dockerignore.
COPY . .

# Pull the vite-built FE from stage 1 into the cmd/admin-bff/ directory
# where main.go's //go:embed all:dist looks for it.
COPY --from=fe-builder /src/cmd/admin-bff/dist ./cmd/admin-bff/dist

# Build the static binary. -s -w strips debug symbols (~50% size cut)
# and CGO_ENABLED=0 makes the binary fully static so the alpine
# runtime stage doesn't need libc.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /out/admin-bff \
    ./cmd/admin-bff

# ─── Stage 3: runtime ─────────────────────────────────────────────────
FROM alpine:3.20

# ca-certificates for outbound HTTPS (control-plane connection uses our
# private CA but Vault Agent / future external integrations may use
# public CAs). tzdata is needed for AKASHIC_TZ to be meaningful.
RUN apk add --no-cache ca-certificates tzdata

# Run as a non-root user. The certs at /certs are mounted ro and
# world-readable for things this binary reads, so it doesn't need
# privileges. uid 10100 is arbitrary but well outside any system
# range to reduce collision risk.
RUN addgroup -g 10100 akashic && \
    adduser -D -u 10100 -G akashic akashic
USER akashic

COPY --from=go-builder /out/admin-bff /usr/local/bin/admin-bff

# The BFF reads its config from environment variables (see
# pkg/admin_bff/config.go). Defaults assume container-mode paths,
# so a typical deployment doesn't need any AKASHIC_BFF_* overrides
# beyond what docker-compose supplies.
EXPOSE 8082
ENTRYPOINT ["/usr/local/bin/admin-bff"]
