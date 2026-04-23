# ──────────────────────────────────────────────────────────────────────────────
# Akashic IDP server — multi-stage build
#
# Stage 1 compiles the static binary; stage 2 is a minimal Alpine image that
# just runs it. We keep Alpine (rather than distroless) so operators can `exec`
# in with a shell for troubleshooting TLS / cert-watcher behaviour.
# ──────────────────────────────────────────────────────────────────────────────
FROM golang:1.24-alpine AS builder

WORKDIR /src

# Copy module files first so the dep-download layer is cached across source edits.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source tree. .dockerignore excludes tmp/, certs/, .git,
# and other host-only artifacts to keep the build context small.
COPY . .

# CGO off → fully static binary. -s -w strips DWARF and symbol tables, cutting
# binary size roughly in half without impacting runtime behaviour.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /out/akashic \
    ./cmd/akashic

# ──────────────────────────────────────────────────────────────────────────────
FROM alpine:3.20

# ca-certificates is required for the Go stdlib's http client to verify
# external TLS endpoints (e.g. outbound OIDC calls if ever added). tzdata
# keeps AKASHIC_TZ meaningful.
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /out/akashic /usr/local/bin/akashic

# Drop to an unprivileged uid. /certs is mounted read-only from the certs
# volume (same one Vault Agent writes to), so uid 1000 can read everything
# issued with writeToFile ... "0644" permissions. The 0600 keys are owned
# by root but readable by us because we run as root inside the build stage,
# then chown-copy the binary. Pragmatic for dev; revisit for production.
#
# Keeping root for now — matches the pattern used by postgres/redis entrypoints.
WORKDIR /app

ENTRYPOINT ["/usr/local/bin/akashic"]
CMD ["run"]
