#!/usr/bin/env python3
"""Generate Docker Compose file for gamma experiments with N nodes.

Binary is bind-mounted from host (target/release/syncback), not built inside Docker.
Build it first: cargo build --release -p syncback
"""

import argparse


def generate(n_nodes: int, out_path: str) -> None:
    services = []
    volumes = []

    for i in range(n_nodes):
        name = f"node-{i:02d}"
        services.append(f"""  {name}:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: gamma-{name}
    hostname: {name}
    volumes:
      - ../../target/release/syncback:/usr/local/bin/syncback:ro
      - {name}-data:/home/syncback/.syncback
      - {name}-files:/data/files
    networks:
      - gamma-net""")
        volumes.append(f"  {name}-data:")
        volumes.append(f"  {name}-files:")

    services.append("""  victoria:
    image: victoriametrics/victoria-metrics:latest
    container_name: gamma-victoria
    ports:
      - "8428:8428"
    volumes:
      - victoria-data:/victoria-metrics-data
    networks:
      - gamma-net

  grafana:
    image: grafana/grafana:latest
    container_name: gamma-grafana
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-data:/var/lib/grafana
      - ../docker-beta/grafana/provisioning:/etc/grafana/provisioning
    networks:
      - gamma-net""")

    volumes.append("  victoria-data:")
    volumes.append("  grafana-data:")

    compose = "services:\n" + "\n\n".join(services) + "\n"
    compose += "\nnetworks:\n  gamma-net:\n    driver: bridge\n"
    compose += "\nvolumes:\n" + "\n".join(volumes) + "\n"

    with open(out_path, "w") as f:
        f.write(compose)

    print(f"Generated {out_path} with {n_nodes} nodes + victoria + grafana")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--nodes", type=int, default=20)
    parser.add_argument("-o", "--output", default="experiments/gamma/compose.yml")
    args = parser.parse_args()
    generate(args.nodes, args.output)
