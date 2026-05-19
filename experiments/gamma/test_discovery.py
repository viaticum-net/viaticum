#!/usr/bin/env python3
"""
Test peer discovery: nodes start with only 2 bootstrap addresses,
must discover the rest via PeerDiscoveryRequest/Response.

Usage:
    python experiments/gamma/test_discovery.py [-n 10]
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

PROJECT_DIR = str(Path(__file__).parent.parent.parent)
COMPOSE_FILE = "experiments/gamma/compose.yml"


def docker(*args, timeout=30):
    return subprocess.run(
        ["docker"] + list(args),
        capture_output=True, text=True, timeout=timeout
    )


def exec_node(name, *args, timeout=30):
    r = docker("exec", f"gamma-{name}", *args, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"{name}: {r.stderr.strip()}")
    return r.stdout.strip()


def exec_node_quiet(name, *args, timeout=30):
    try:
        return exec_node(name, *args, timeout=timeout)
    except Exception:
        return ""


def exec_node_bg(name, *args):
    docker("exec", "-d", f"gamma-{name}", *args)


def compose(*args, timeout=120):
    return subprocess.run(
        ["docker", "compose", "-f", COMPOSE_FILE] + list(args),
        cwd=PROJECT_DIR, capture_output=True, text=True, timeout=timeout
    )


def node_status(name):
    raw = exec_node(name, "viaticum", "status", "--json")
    return json.loads(raw)


def main():
    parser = argparse.ArgumentParser(description="Test peer discovery")
    parser.add_argument("-n", "--nodes", type=int, default=10)
    args = parser.parse_args()

    n = args.nodes
    print(f"=== Peer Discovery Test: {n} nodes ===\n")

    # Generate compose and start containers
    sys.path.insert(0, str(Path(__file__).parent))
    from compose_gen import generate
    generate(n, os.path.join(PROJECT_DIR, COMPOSE_FILE))

    compose("down", "-v", timeout=60)
    r = compose("up", "-d", timeout=120)
    if r.returncode != 0:
        print(f"compose up failed: {r.stderr}")
        sys.exit(1)
    time.sleep(3)

    # Phase 1: Init all nodes
    print("Phase 1: Init")
    for i in range(n):
        name = f"node-{i:02d}"
        try:
            exec_node(name, "viaticum", "init")
        except RuntimeError as e:
            if "already initialized" not in str(e):
                raise
    print(f"  {n} nodes initialized\n")

    # Phase 2: Start seed nodes (node-00, node-01) — they connect to each other
    print("Phase 2: Start seed nodes (node-00, node-01)")
    for i in range(2):
        name = f"node-{i:02d}"
        # No bootstrap peers for seeds — they connect manually
        config = """[network]
enable_relay = false
"""
        exec_node(name, "sh", "-c",
                  f"cat > /home/viaticum/.viaticum/config.toml << 'EOF'\n{config}EOF")
        exec_node_bg(name, "sh", "-c",
                     "RUST_LOG=info viaticum daemon --time-scale 1000 "
                     "--watch-dir /data/files >/tmp/daemon.log 2>&1")

    time.sleep(5)

    # Connect seeds to each other
    addr_00 = node_status("node-00").get("node_addr", "")
    addr_01 = node_status("node-01").get("node_addr", "")
    print(f"  node-00 addr: {addr_00[:40]}...")
    print(f"  node-01 addr: {addr_01[:40]}...")
    exec_node("node-00", "viaticum", "connect", addr_01, timeout=15)
    print("  seeds connected\n")

    # Phase 3: Start remaining nodes with bootstrap_peers = [node-00, node-01]
    print(f"Phase 3: Start nodes 02..{n-1:02d} with bootstrap = [node-00, node-01]")

    for i in range(2, n):
        name = f"node-{i:02d}"
        config = f"""[network]
enable_relay = false
bootstrap_peers = ["{addr_00}", "{addr_01}"]
"""
        exec_node(name, "sh", "-c",
                  f"cat > /home/viaticum/.viaticum/config.toml << 'EOF'\n{config}EOF")
        exec_node_bg(name, "sh", "-c",
                     "RUST_LOG=info viaticum daemon --time-scale 1000 "
                     "--watch-dir /data/files >/tmp/daemon.log 2>&1")

    print(f"  {n - 2} nodes started with bootstrap config")
    print("  Waiting for discovery...")

    # Phase 4: Wait and check peer counts
    for wait in [10, 20, 30, 45, 60]:
        time.sleep(wait if wait == 10 else wait - [10, 20, 30, 45][[ 10, 20, 30, 45, 60].index(wait) - 1])
        counts = []
        for i in range(n):
            name = f"node-{i:02d}"
            try:
                s = node_status(name)
                counts.append(s.get("peer_count", 0))
            except Exception:
                counts.append(-1)

        min_peers = min(c for c in counts if c >= 0)
        max_peers = max(counts)
        avg_peers = sum(c for c in counts if c >= 0) / sum(1 for c in counts if c >= 0)
        offline = sum(1 for c in counts if c < 0)

        print(f"\n  [{wait}s] peers: min={min_peers} max={max_peers} avg={avg_peers:.1f} offline={offline}")
        for i in range(n):
            name = f"node-{i:02d}"
            mark = " " if counts[i] >= 0 else "X"
            print(f"    {mark} {name}: {counts[i]} peers")

        # Success: all nodes found at least n/2 peers
        if min_peers >= n // 2:
            print(f"\n  SUCCESS: all nodes have >= {n//2} peers at {wait}s")
            break
    else:
        print(f"\n  PARTIAL: not all nodes reached {n//2} peers in 60s")

    # Final state
    print(f"\n=== Final State ===")
    for i in range(n):
        name = f"node-{i:02d}"
        try:
            s = node_status(name)
            peers = s.get("peer_count", 0)
            identity = s.get("node_identity", "")[:16]
            print(f"  {name}: {peers} peers, id={identity}...")
        except Exception:
            print(f"  {name}: OFFLINE")

    print(f"\nContainers still running. To stop: docker compose -f {COMPOSE_FILE} down -v")


if __name__ == "__main__":
    main()
