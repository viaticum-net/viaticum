# Stage 1: Build
FROM rust:1.94-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release -p viaticum

# Stage 2: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/viaticum /usr/local/bin/viaticum
ENV HOME=/home/viaticum
RUN mkdir -p /home/viaticum /data/files
WORKDIR /home/viaticum
CMD ["sleep", "infinity"]
