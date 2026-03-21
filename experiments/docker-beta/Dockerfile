# Stage 1: Build
FROM rust:1.85-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release -p syncback

# Stage 2: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/syncback /usr/local/bin/syncback
ENV HOME=/home/syncback
RUN mkdir -p /home/syncback /data/files
WORKDIR /home/syncback
CMD ["sleep", "infinity"]
