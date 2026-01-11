# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2025 Sylvex. All rights reserved.
#
# TRAP - Transparent Rust Adapter for industrial Protocols
# Multi-stage Docker build for minimal production image

# =============================================================================
# Stage 1: Build
# =============================================================================
FROM rust:1.75-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    clang \
    libclang-dev \
    librocksdb-dev \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for build
RUN useradd -m -u 1000 builder
USER builder
WORKDIR /home/builder/app

# Cache dependencies by copying only Cargo files first
COPY --chown=builder:builder Cargo.toml Cargo.lock ./
COPY --chown=builder:builder crates/trap-core/Cargo.toml crates/trap-core/
COPY --chown=builder:builder crates/trap-config/Cargo.toml crates/trap-config/
COPY --chown=builder:builder crates/trap-buffer/Cargo.toml crates/trap-buffer/
COPY --chown=builder:builder crates/trap-api/Cargo.toml crates/trap-api/
COPY --chown=builder:builder crates/trap-bin/Cargo.toml crates/trap-bin/
COPY --chown=builder:builder crates/trap-modbus/Cargo.toml crates/trap-modbus/
COPY --chown=builder:builder crates/trap-tests/Cargo.toml crates/trap-tests/

# Create dummy src files to cache dependencies
RUN mkdir -p crates/trap-core/src && echo "pub fn dummy() {}" > crates/trap-core/src/lib.rs \
    && mkdir -p crates/trap-config/src && echo "pub fn dummy() {}" > crates/trap-config/src/lib.rs \
    && mkdir -p crates/trap-buffer/src && echo "pub fn dummy() {}" > crates/trap-buffer/src/lib.rs \
    && mkdir -p crates/trap-api/src && echo "pub fn dummy() {}" > crates/trap-api/src/lib.rs \
    && mkdir -p crates/trap-bin/src && echo "fn main() {}" > crates/trap-bin/src/main.rs \
    && mkdir -p crates/trap-modbus/src && echo "pub fn dummy() {}" > crates/trap-modbus/src/lib.rs \
    && mkdir -p crates/trap-tests/src && echo "pub fn dummy() {}" > crates/trap-tests/src/lib.rs

# Build dependencies (this layer is cached)
RUN cargo build --release --package trap-bin 2>/dev/null || true

# Copy actual source code
COPY --chown=builder:builder . .

# Touch files to ensure rebuild with actual sources
RUN find crates -name "*.rs" -exec touch {} +

# Build release binary
RUN cargo build --release --package trap-bin

# =============================================================================
# Stage 2: Runtime
# =============================================================================
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    librocksdb7.8 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r trap && useradd -r -g trap trap

# Create directories
RUN mkdir -p /app/data/buffer /app/logs /app/certs \
    && chown -R trap:trap /app

# Copy binary from builder
COPY --from=builder /home/builder/app/target/release/trap-bin /app/trap

# Copy default configuration
COPY --chown=trap:trap trap.example.yaml /app/trap.example.yaml

# Set working directory
WORKDIR /app

# Switch to non-root user
USER trap

# Expose API port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app/trap", "health", "--local"] || exit 1

# Default configuration path
ENV TRAP_CONFIG=/app/trap.yaml

# Default command
ENTRYPOINT ["/app/trap"]
CMD ["run", "--config", "/app/trap.yaml"]

# =============================================================================
# Labels
# =============================================================================
LABEL org.opencontainers.image.title="TRAP" \
      org.opencontainers.image.description="Transparent Rust Adapter for industrial Protocols" \
      org.opencontainers.image.vendor="Sylvex" \
      org.opencontainers.image.licenses="PolyForm-Noncommercial-1.0.0" \
      org.opencontainers.image.source="https://github.com/seadonggyun4/trap"
