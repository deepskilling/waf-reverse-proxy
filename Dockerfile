# Multi-stage build for optimal image size
FROM rust:1.75-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /usr/src/app

# Copy dependency files
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release && rm -rf src

# Copy source code
COPY src ./src

# Build the application
RUN touch src/main.rs && cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN groupadd -r wafproxy && useradd -r -g wafproxy wafproxy

# Create directories
RUN mkdir -p /app/config /app/logs /app/data \
    && chown -R wafproxy:wafproxy /app

# Copy binary from builder stage
COPY --from=builder /usr/src/app/target/release/waf-reverse-proxy /usr/local/bin/
COPY --from=builder --chown=wafproxy:wafproxy /usr/src/app/config.yaml /app/config/

# Switch to app user
USER wafproxy
WORKDIR /app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose ports
EXPOSE 8080 8081 9090

# Set environment variables
ENV RUST_LOG=info
ENV CONFIG_PATH=/app/config/config.yaml

# Run the application
CMD ["waf-reverse-proxy", "--config", "/app/config/config.yaml"]
