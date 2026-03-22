#!/usr/bin/env python3
"""
Gamma experiment: trust evolution with behavior archetypes.

Usage:
    python experiments/gamma/run.py [--nodes 20] [--time-scale 1000] [--duration 1800]

Archetypes:
    reliable   (40%) — always online, full storage
    flaky      (40%) — cycles on/off (3 min on, 3 min off)
    freeloader (20%) — always online, minimal storage (1 GB quota)
"""

import argparse
import json
import os
import random
import subprocess
import sys
import time
from pathlib import Path


# ── Config ────────────────────────────────────────────────────────────────────

COMPOSE_FILE = "experiments/gamma/compose.yml"
PROJECT_DIR = str(Path(__file__).parent.parent.parent)

ARCHETYPES = {
    "reliable":   {"fraction": 0.4, "quota_gb": 100, "behavior": "always_on"},
    "flaky":      {"fraction": 0.4, "quota_gb": 100, "behavior": "cycle",
                   "on_secs": 180, "off_secs": 180},
    "freeloader": {"fraction": 0.2, "quota_gb": 1,   "behavior": "always_on"},
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def docker(*args, **kwargs):
    timeout = kwargs.pop("timeout", 30)
    result = subprocess.run(
        ["docker"] + list(args),
        capture_output=True, text=True, timeout=timeout, **kwargs
    )
    return result

def exec_node(name: str, *args, timeout: int = 30) -> str:
    r = docker("exec", f"gamma-{name}", *args, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"{name}: {r.stderr.strip()}")
    return r.stdout.strip()

def exec_node_bg(name: str, *args):
    docker("exec", "-d", f"gamma-{name}", *args)

def compose(*args, timeout=120):
    return subprocess.run(
        ["docker", "compose", "-f", COMPOSE_FILE] + list(args),
        cwd=PROJECT_DIR, capture_output=True, text=True, timeout=timeout
    )

def node_status(name: str) -> dict:
    raw = exec_node(name, "syncback", "status", "--json")
    return json.loads(raw)

def node_addr(name: str) -> str:
    s = node_status(name)
    return s.get("node_addr", "")


# ── Assignment ────────────────────────────────────────────────────────────────

def assign_archetypes(n_nodes: int) -> list[dict]:
    """Assign archetypes to nodes. Returns list of {name, archetype, ...}."""
    nodes = []
    idx = 0
    for arch_name, cfg in ARCHETYPES.items():
        count = max(1, round(n_nodes * cfg["fraction"]))
        for _ in range(count):
            if idx >= n_nodes:
                break
            nodes.append({
                "name": f"node-{idx:02d}",
                "archetype": arch_name,
                **cfg,
            })
            idx += 1
    # Fill remaining with reliable
    while idx < n_nodes:
        nodes.append({
            "name": f"node-{idx:02d}",
            "archetype": "reliable",
            **ARCHETYPES["reliable"],
        })
        idx += 1
    return nodes


# ── Phases ────────────────────────────────────────────────────────────────────

def phase_init(nodes: list[dict]):
    """Initialize all nodes (random identity)."""
    print("\n=== Phase: Init ===")
    for n in nodes:
        try:
            out = exec_node(n["name"], "syncback", "init")
            print(f"  {n['name']} ({n['archetype']}): init ok")
        except RuntimeError as e:
            if "already initialized" in str(e):
                print(f"  {n['name']} ({n['archetype']}): already initialized")
            else:
                raise


def phase_config(nodes: list[dict], time_scale: int):
    """Write config.toml with metrics and archetype-specific quota."""
    print("\n=== Phase: Config ===")
    for n in nodes:
        config = f"""[metrics]
enabled = true
push_url = "http://victoria:8428/api/v1/import/prometheus"
push_interval_secs = 15

[storage]
soft_quota_gb = {n['quota_gb']}.0

[network]
enable_relay = false
"""
        exec_node(n["name"], "sh", "-c",
                  f"cat > /home/syncback/.syncback/config.toml << 'EOFCFG'\n{config}EOFCFG")
    print(f"  config written to {len(nodes)} nodes")


def phase_start_daemons(nodes: list[dict], time_scale: int):
    """Start daemons on all nodes."""
    print(f"\n=== Phase: Start daemons (time_scale={time_scale}) ===")
    for n in nodes:
        exec_node_bg(n["name"], "sh", "-c",
                     f"RUST_LOG=info syncback daemon --time-scale {time_scale} --watch-dir /data/files "
                     f">/tmp/daemon.log 2>&1")
    # Wait for all to be ready
    time.sleep(5)
    ready = 0
    for n in nodes:
        try:
            node_status(n["name"])
            ready += 1
        except Exception:
            pass
    print(f"  {ready}/{len(nodes)} daemons ready")


def phase_connect(nodes: list[dict]):
    """Connect all nodes into a mesh via node-00 as hub."""
    print("\n=== Phase: Connect ===")
    hub = nodes[0]["name"]

    # Get all addrs first
    addrs = {}
    for n in nodes:
        try:
            addrs[n["name"]] = node_addr(n["name"])
        except Exception as e:
            print(f"  WARNING: can't get addr for {n['name']}: {e}")

    # Hub connects to all others
    connected = 0
    for n in nodes[1:]:
        addr = addrs.get(n["name"])
        if not addr:
            continue
        try:
            exec_node(hub, "syncback", "connect", addr, timeout=30)
            connected += 1
        except Exception as e:
            print(f"  WARNING: {hub} -> {n['name']} failed: {e}")
        time.sleep(0.5)

    print(f"  {hub} connected to {connected} peers")

    # Also cross-connect a few others for resilience
    time.sleep(2)
    hub_addr = addrs.get(hub, "")
    cross = 0
    for n in nodes[1:min(6, len(nodes))]:
        if hub_addr:
            try:
                exec_node(n["name"], "syncback", "connect", hub_addr, timeout=15)
                cross += 1
            except Exception:
                pass
    print(f"  {cross} cross-connections established")


def phase_create_files(nodes: list[dict]):
    """Create test files on reliable nodes for backup."""
    print("\n=== Phase: Create files ===")
    reliable = [n for n in nodes if n["archetype"] == "reliable"]
    for n in reliable[:3]:  # first 3 reliable nodes create files
        exec_node(n["name"], "sh", "-c",
                  "for i in $(seq 1 5); do "
                  "dd if=/dev/urandom of=/data/files/test_$i.dat bs=1024 count=50 2>/dev/null; "
                  "done")
        print(f"  {n['name']}: 5 files created (50KB each)")
    time.sleep(3)


def phase_behavior_loop(nodes: list[dict], duration_secs: int, time_scale: int):
    """Run the behavior loop: stop/start flaky nodes on cycles."""
    print(f"\n=== Phase: Behavior loop ({duration_secs}s) ===")

    flaky = [n for n in nodes if n["archetype"] == "flaky"]
    if not flaky:
        print("  No flaky nodes, sleeping...")
        time.sleep(duration_secs)
        return

    # Track state: True = running, False = stopped
    state = {n["name"]: True for n in flaky}
    # Stagger start: offset each flaky node by a few seconds
    next_toggle = {}
    for i, n in enumerate(flaky):
        # First toggle at random offset so they don't all flip at once
        next_toggle[n["name"]] = time.time() + random.uniform(10, n.get("on_secs", 180))

    start_time = time.time()
    tick = 0

    while time.time() - start_time < duration_secs:
        now = time.time()
        elapsed = int(now - start_time)

        # Check each flaky node
        for n in flaky:
            name = n["name"]
            if now >= next_toggle[name]:
                if state[name]:
                    # Stop daemon
                    try:
                        exec_node(name, "sh", "-c",
                                  "kill $(cat /tmp/daemon.pid 2>/dev/null) 2>/dev/null; "
                                  "killall syncback 2>/dev/null || true")
                    except Exception:
                        pass
                    state[name] = False
                    next_toggle[name] = now + n.get("off_secs", 180) + random.uniform(-30, 30)
                else:
                    # Restart daemon
                    exec_node_bg(name, "sh", "-c",
                                 f"RUST_LOG=info syncback daemon --time-scale {time_scale} "
                                 f"--watch-dir /data/files >>/tmp/daemon.log 2>&1")
                    state[name] = True
                    next_toggle[name] = now + n.get("on_secs", 180) + random.uniform(-30, 30)

        # Status report every 60 seconds
        tick += 1
        if tick % 6 == 0:
            online = sum(1 for v in state.values() if v)
            total_online = len(nodes) - len(flaky) + online
            sim_weeks = (elapsed * time_scale) / 604800
            print(f"  [{elapsed}s real, ~{sim_weeks:.1f} sim weeks] "
                  f"{total_online}/{len(nodes)} online, "
                  f"flaky: {online}/{len(flaky)} up")

        time.sleep(10)

    print(f"  Behavior loop complete ({duration_secs}s)")


def phase_report(nodes: list[dict]):
    """Print final trust scores grouped by archetype."""
    print("\n=== Final Report ===")
    by_arch = {}
    for n in nodes:
        arch = n["archetype"]
        if arch not in by_arch:
            by_arch[arch] = []
        try:
            s = node_status(n["name"])
            # This node's own peer_count and trust from other nodes' perspective
            by_arch[arch].append({
                "name": n["name"],
                "peers": s.get("peer_count", 0),
                "holding": s.get("holding_bytes", 0),
                "placements": s.get("placement_alive", 0),
                "pos_challenged": s.get("pos_total_challenges", 0),
                "pos_passed": s.get("pos_total_passes", 0),
            })
        except Exception as e:
            by_arch[arch].append({"name": n["name"], "error": str(e)})

    for arch, entries in by_arch.items():
        print(f"\n  [{arch}]")
        for e in entries:
            if "error" in e:
                print(f"    {e['name']}: OFFLINE ({e['error'][:50]})")
            else:
                pass_rate = (e["pos_passed"] / e["pos_challenged"] * 100
                             if e["pos_challenged"] > 0 else 0)
                print(f"    {e['name']}: peers={e['peers']} "
                      f"holding={e['holding']//1024}KB "
                      f"pos={e['pos_passed']}/{e['pos_challenged']} ({pass_rate:.0f}%)")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Gamma experiment: trust archetypes")
    parser.add_argument("-n", "--nodes", type=int, default=20)
    parser.add_argument("-t", "--time-scale", type=int, default=1000)
    parser.add_argument("-d", "--duration", type=int, default=1800,
                        help="Behavior loop duration in seconds (default: 1800 = 30 min)")
    parser.add_argument("--build", action="store_true", help="Build Docker images first")
    parser.add_argument("--skip-setup", action="store_true",
                        help="Skip init/config/connect (resume behavior loop)")
    args = parser.parse_args()

    print(f"Gamma experiment: {args.nodes} nodes, time_scale={args.time_scale}, "
          f"duration={args.duration}s")
    print(f"Simulated time: ~{args.duration * args.time_scale / 604800:.1f} weeks")

    # Generate compose
    from compose_gen import generate
    generate(args.nodes, os.path.join(PROJECT_DIR, COMPOSE_FILE))

    nodes = assign_archetypes(args.nodes)
    print(f"\nArchetypes:")
    for arch in ARCHETYPES:
        count = sum(1 for n in nodes if n["archetype"] == arch)
        print(f"  {arch}: {count} nodes")

    if args.build:
        print("\n=== Building images ===")
        compose("build", timeout=600)

    print("\n=== Starting containers ===")
    r = compose("up", "-d", timeout=120)
    if r.returncode != 0:
        print(f"compose up failed: {r.stderr}")
        sys.exit(1)
    time.sleep(3)

    if not args.skip_setup:
        phase_init(nodes)
        phase_config(nodes, args.time_scale)
        phase_start_daemons(nodes, args.time_scale)
        phase_connect(nodes)
        phase_create_files(nodes)
    else:
        print("\n  (skipping setup, resuming behavior loop)")

    phase_behavior_loop(nodes, args.duration, args.time_scale)
    phase_report(nodes)

    print(f"\nDone. Grafana: http://YOUR-LAN-IP:3001")
    print(f"Containers still running. To stop: docker compose -f {COMPOSE_FILE} down -v")


if __name__ == "__main__":
    main()
