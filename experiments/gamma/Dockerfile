# Lightweight runtime container — binary is bind-mounted from host.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates procps && rm -rf /var/lib/apt/lists/*
ENV HOME=/home/syncback
RUN mkdir -p /home/syncback /data/files
WORKDIR /home/syncback
CMD ["sleep", "infinity"]
