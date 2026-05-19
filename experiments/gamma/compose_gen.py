#!/usr/bin/env python3
"""Generate Docker Compose file for gamma experiments with N nodes.

Binary is bind-mounted from host (target/release/viaticum), not built inside Docker.
Build it first: cargo build --release -p viaticum
"""

import argparse


def generate(n_nodes: int, out_path: str, include_metrics: bool = True) -> None:
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
      - ../../target/release/viaticum:/usr/local/bin/viaticum:ro
      - {name}-data:/home/viaticum/.viaticum
      - {name}-files:/data/files
    networks:
      - gamma-net""")
        volumes.append(f"  {name}-data:")
        volumes.append(f"  {name}-files:")

    if include_metrics:
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

    suffix = " + victoria + grafana" if include_metrics else ""
    print(f"Generated {out_path} with {n_nodes} nodes{suffix}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--nodes", type=int, default=20)
    parser.add_argument("-o", "--output", default="experiments/gamma/compose.yml")
    args = parser.parse_args()
    generate(args.nodes, args.output)
