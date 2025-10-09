# Akashic IDP Server - Dockerfile
# Multi-stage build for efficient container images

# ============================================================================
# Stage 1: Builder - Compile Go application
# ============================================================================
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make bash

# Set working directory
WORKDIR /build

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
# CGO_ENABLED=0 for static binary, good for Alpine
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -o akashic \
    ./cmd/akashic

# Verify binary
RUN chmod +x akashic && ./akashic --version

# ============================================================================
# Stage 2: Runtime - Lightweight runtime container
# ============================================================================
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    bash \
    curl \
    openssl

# Create non-root user for running the application
RUN addgroup -g 1000 akashic && \
    adduser -u 1000 -G akashic -D -h /app akashic

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/akashic /usr/local/bin/akashic

# Copy configuration files
COPY --chown=akashic:akashic configs/ /app/configs/

# Create necessary directories with proper permissions
RUN mkdir -p /app/logs /app/certs && \
    chown -R akashic:akashic /app

# Switch to non-root user
USER akashic

# Expose ports
# 8080: Auth Server
# 8081: Control Server
EXPOSE 8080 8081

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command
ENTRYPOINT ["/usr/local/bin/akashic"]
CMD ["run", "--config", "/app/configs/config.yaml"]
