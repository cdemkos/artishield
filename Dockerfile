# ── Stage 1: Build ────────────────────────────────────────────────────────────
# Pin to a specific Rust version matching the declared MSRV.
FROM rust:1.88-slim-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Cache dependencies separately (layer invalidated only when Cargo files change)
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock

# Create dummy src to build deps
RUN mkdir -p src && echo 'fn main(){}' > src/main.rs && \
    echo 'pub fn dummy(){}' > src/lib.rs

# Build deps only (cached layer)
RUN cargo build --release --no-default-features || true

# Now copy real source
COPY src/ src/
COPY tests/ tests/

# Touch main.rs to force re-link
RUN touch src/main.rs src/lib.rs

# Build the real binary.
# Use --no-default-features to avoid arti network calls at build time.
# Enable arti-hooks at runtime by mounting a config with arti already running.
RUN cargo build --release --no-default-features && \
    strip target/release/artishield

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
# Pin to a specific Debian bookworm digest for reproducible builds.
FROM debian:bookworm-slim AS runtime

# ca-certificates: TLS in timing probes
# curl: used by HEALTHCHECK CMD
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN useradd -r -s /bin/false -d /opt/artishield artishield

WORKDIR /opt/artishield

# Copy binary
COPY --from=builder /build/target/release/artishield /usr/local/bin/artishield

# Bake the example config as the default.
# Override at runtime by bind-mounting your own artishield.toml:
#   -v ./artishield.toml:/opt/artishield/artishield.toml:ro
COPY artishield.toml.example /opt/artishield/artishield.toml

# Directory for SQLite DB
RUN mkdir -p /var/lib/artishield && \
    chown artishield:artishield /var/lib/artishield /opt/artishield

USER artishield

# Dashboard API + Prometheus metrics (same port, /metrics path)
EXPOSE 7878

VOLUME ["/var/lib/artishield", "/opt/artishield/GeoLite2-ASN.mmdb"]

# Liveness probe — matches the /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:7878/health || exit 1

# Metadata labels (OCI standard)
LABEL org.opencontainers.image.title="ArtiShield" \
      org.opencontainers.image.description="Threat-monitoring and mitigation layer for arti (Tor in Rust)" \
      org.opencontainers.image.source="https://github.com/cdemkos/artishield" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

ENTRYPOINT ["artishield"]
CMD ["--config", "/opt/artishield/artishield.toml"]
