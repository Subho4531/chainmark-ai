# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Chainmark AI - Rust egress gateway (chainmark-proxy)
# ---------------------------------------------------------------------------
FROM rust:bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy workspace manifests and sources. Cargo.lock is intentionally optional
# because it is gitignored in this repository.
COPY Cargo.toml ./
COPY crates ./crates
COPY Cargo.lock* ./

RUN cargo build --release --locked -p chainmark-proxy 2>/dev/null \
    || cargo build --release -p chainmark-proxy

# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 chainmark

COPY --from=builder /app/target/release/chainmark-proxy /usr/local/bin/chainmark-proxy

USER chainmark
WORKDIR /home/chainmark

ENV CHAINMARK_HOST=0.0.0.0 \
    CHAINMARK_PORT=8000 \
    RUST_LOG=info

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

CMD ["chainmark-proxy"]
