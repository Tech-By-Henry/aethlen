# ---------- Build stage ----------
FROM rust:1.80-slim AS builder
WORKDIR /app

# System deps some crates need
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates git \
  && rm -rf /var/lib/apt/lists/*

# Copy manifests first for better cache use
COPY Cargo.toml Cargo.lock ./
COPY gateway/Cargo.toml gateway/Cargo.toml
COPY apps/aethlen_ai/Cargo.toml apps/aethlen_ai/Cargo.toml
COPY migration/Cargo.toml migration/Cargo.toml

# Prime dependency cache (dummy build)
RUN mkdir -p gateway/src && echo "fn main() {}" > gateway/src/main.rs
RUN cargo build --release -p gateway || true

# Build real binary
RUN rm -rf gateway/src
COPY . .
RUN cargo build --release -p gateway

# ---------- Runtime stage ----------
FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/gateway /usr/local/bin/gateway

ENV RUST_LOG=info
EXPOSE 8080
CMD ["gateway"]
