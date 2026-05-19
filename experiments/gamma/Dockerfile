# Lightweight runtime container — binary is bind-mounted from host.
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y ca-certificates procps && rm -rf /var/lib/apt/lists/*
ENV HOME=/home/viaticum
RUN mkdir -p /home/viaticum /data/files
WORKDIR /home/viaticum
CMD ["sleep", "infinity"]
