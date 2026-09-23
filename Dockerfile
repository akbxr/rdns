# ==============================================================================
# Stage 1: Build binary using official Rust Alpine image
# ==============================================================================
FROM rust:1.92-alpine AS builder

WORKDIR /usr/src/rdns

# Install build dependencies
RUN apk add --no-cache musl-dev perl make

# Copy manifest and lockfile first for layer caching
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build release binary
RUN cargo build --release

# ==============================================================================
# Stage 2: Final minimal runtime image (only ~20 MB)
# ==============================================================================
FROM alpine:3.21

# Install CA certificates for upstream TLS/DoH resolution
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy compiled binary from builder
COPY --from=builder /usr/src/rdns/target/release/rdns /usr/local/bin/rdns

# Expose ports:
# 53: DNS (UDP and TCP)
# 853: DoT (optional)
# 4000: HTTP API / DoH / Metrics
# 443: HTTPS DoH (optional)
EXPOSE 53/udp 53/tcp 853/tcp 4000/tcp 443/tcp

# Healthcheck probe using HTTP health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:4000/health || exit 1

ENTRYPOINT ["rdns"]
CMD ["start", "-c", "/app/config.yaml"]
