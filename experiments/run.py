#!/usr/bin/env python3
"""
SyncBack experiment CLI.

Usage:
    python experiments/run.py smoke          # run smoke test
    python experiments/run.py --build smoke  # build images first, then run
    python experiments/run.py --list         # list available scenarios
"""

import argparse
import sys
import time
from pathlib import Path

# Add experiments/ to path so runner and scenarios are importable
sys.path.insert(0, str(Path(__file__).parent))

from runner import Cluster, MetricsCollector
from scenarios.smoke import SmokeScenario


SCENARIOS = {
    "smoke": SmokeScenario,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="SyncBack experiment runner")
    parser.add_argument("scenario", nargs="?", help="Scenario to run")
    parser.add_argument("--build", action="store_true", help="Build Docker images first")
    parser.add_argument("--list", action="store_true", help="List available scenarios")
    parser.add_argument("--keep", action="store_true",
                        help="Keep containers running after the scenario")
    parser.add_argument("--metrics-db", default="experiments/results/metrics.db",
                        help="Path to metrics SQLite database")
    args = parser.parse_args()

    if args.list:
        print("Available scenarios:")
        for name in SCENARIOS:
            print(f"  {name}")
        return

    if not args.scenario:
        parser.print_help()
        return

    if args.scenario not in SCENARIOS:
        print(f"Unknown scenario: {args.scenario}")
        print(f"Available: {', '.join(SCENARIOS.keys())}")
        sys.exit(1)

    # Project root is the parent of experiments/
    project_dir = str(Path(__file__).parent.parent)

    cluster = Cluster(
        compose_file="experiments/docker/compose.yml",
        project_dir=project_dir,
    )
    metrics = MetricsCollector(args.metrics_db)

    try:
        if args.build:
            cluster.build()

        print("Starting cluster...")
        cluster.up()

        # Give containers a moment to fully start before issuing commands
        time.sleep(2)

        scenario_cls = SCENARIOS[args.scenario]
        scenario = scenario_cls(cluster, metrics)
        success = scenario.run()

        if not success:
            sys.exit(1)

    finally:
        metrics.close()
        if not args.keep:
            print("\nTearing down cluster...")
            cluster.down()
        else:
            print("\nContainers kept running (use 'docker compose down' to stop)")


if __name__ == "__main__":
    main()
