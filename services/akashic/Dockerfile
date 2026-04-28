# ──────────────────────────────────────────────────────────────────────────────
# Akashic IDP server — multi-stage build
#
# Three stages:
#   1. widget-builder  — builds the embeddable Web Component bundle
#                        (web/widgets/) that the api-server hosts at
#                        /widgets/akashic.js and /widgets/akashic-default.css
#   2. go-builder      — compiles the static Go binary
#   3. runtime         — minimal Alpine that runs the binary; widget
#                        artefacts copied into /usr/local/share/akashic-widgets/
# ──────────────────────────────────────────────────────────────────────────────

# ─── Stage 1: widget bundle ───────────────────────────────────────────────────
FROM node:22-alpine AS widget-builder

WORKDIR /widgets

# Copy package metadata first so the npm install layer caches across
# source edits.
COPY web/widgets/package.json web/widgets/package-lock.json* ./
RUN npm install --no-audit --no-fund

# Copy widget source and build. Output: dist/akashic.js + dist/akashic-default.css.
COPY web/widgets/ ./
RUN npm run build

# ─── Stage 2: Go binary ───────────────────────────────────────────────────────
FROM golang:1.24-alpine AS go-builder

WORKDIR /src

# Module deps first — caches across source edits.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source. .dockerignore excludes tmp/, certs/, .git, etc.
COPY . .

# CGO off → fully static binary. -s -w strips DWARF and symbol tables.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /out/akashic \
    ./cmd/akashic

# ─── Stage 3: runtime ─────────────────────────────────────────────────────────
FROM alpine:3.20

# ca-certificates for the Go stdlib's http client; tzdata for AKASHIC_TZ.
RUN apk add --no-cache ca-certificates tzdata

# Akashic binary.
COPY --from=go-builder /out/akashic /usr/local/bin/akashic

# Widget bundle artefacts. Served by api-server at /widgets/akashic.js
# and /widgets/akashic-default.css. Read-only at runtime.
COPY --from=widget-builder /widgets/dist /usr/local/share/akashic-widgets

WORKDIR /app

ENTRYPOINT ["/usr/local/bin/akashic"]
CMD ["run"]
