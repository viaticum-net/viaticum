#!/usr/bin/env python3
"""
Gamma experiment: trust evolution with behavior archetypes.

Usage:
    python experiments/gamma/run.py [--nodes 20] [--time-scale 1000] [--duration 7200]

Archetypes:
    reliable   (40%) — always online, full storage
    flaky      (40%) — cycles on/off (3 min on, 3 min off)
    freeloader (20%) — always online, minimal storage (1 GB quota)

Output:
    experiments/gamma/results/<run_id>/snapshots.jsonl  — periodic status snapshots
    experiments/gamma/results/<run_id>/events.jsonl      — lifecycle events
    experiments/gamma/results/<run_id>/report.txt        — final summary
"""

import argparse
import json
import os
import random
import subprocess
import sys
import time
from datetime import datetime, timezone
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

SNAPSHOT_INTERVAL = 60  # seconds between data collection snapshots


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

def exec_node_quiet(name: str, *args, timeout: int = 30) -> str:
    try:
        return exec_node(name, *args, timeout=timeout)
    except Exception:
        return ""

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

def node_status_safe(name: str) -> dict | None:
    try:
        return node_status(name)
    except Exception:
        return None

def node_addr(name: str) -> str:
    s = node_status(name)
    return s.get("node_addr", "")


# ── Data Collection ──────────────────────────────────────────────────────────

class DataCollector:
    """Writes structured JSONL snapshots and events."""

    def __init__(self, results_dir: Path):
        self.results_dir = results_dir
        results_dir.mkdir(parents=True, exist_ok=True)
        self.snap_file = open(results_dir / "snapshots.jsonl", "a")
        self.event_file = open(results_dir / "events.jsonl", "a")
        self.start_time = time.time()

    def close(self):
        self.snap_file.close()
        self.event_file.close()

    def elapsed(self) -> float:
        return time.time() - self.start_time

    def event(self, event_type: str, node: str = "", details: str = ""):
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "elapsed_s": round(self.elapsed(), 1),
            "event": event_type,
            "node": node,
            "details": details,
        }
        self.event_file.write(json.dumps(rec) + "\n")
        self.event_file.flush()

    def snapshot_all(self, nodes: list[dict], time_scale: int):
        """Take status snapshot from all nodes."""
        ts = datetime.now(timezone.utc).isoformat()
        elapsed = round(self.elapsed(), 1)
        sim_weeks = round(elapsed * time_scale / 604800, 2)

        for n in nodes:
            s = node_status_safe(n["name"])
            if s is None:
                continue

            # Per-peer trust data
            peer_trusts = []
            for p in s.get("peers", []):
                peer_trusts.append({
                    "id": p.get("identity_hex", "")[:16],
                    "trust": round(p.get("trust", 0), 4),
                    "trust_p": round(p.get("trust_p", 0), 4),
                    "trust_i": round(p.get("trust_i", 0), 4),
                    "trust_s": round(p.get("trust_s", 0), 4),
                    "bytes_we_store": p.get("bytes_we_store", 0),
                    "bytes_peer_stores": p.get("bytes_peer_stores", 0),
                })

            rec = {
                "ts": ts,
                "elapsed_s": elapsed,
                "sim_weeks": sim_weeks,
                "node": n["name"],
                "archetype": n["archetype"],
                "peer_count": s.get("peer_count", 0),
                "avg_trust": round(s.get("avg_trust", 0), 4),
                "holding_bytes": s.get("holding_bytes", 0),
                "backed_up_files": s.get("backed_up_files", 0),
                "backed_up_bytes": s.get("backed_up_bytes", 0),
                "placement_count": s.get("placement_count", 0),
                "placement_alive": s.get("placement_alive", 0),
                "placement_lost": s.get("placement_lost", 0),
                "blocks_ok": s.get("blocks_ok", 0),
                "blocks_at_risk": s.get("blocks_at_risk", 0),
                "pos_total_challenges": s.get("pos_total_challenges", 0),
                "pos_total_passes": s.get("pos_total_passes", 0),
                "peers": peer_trusts,
            }
            self.snap_file.write(json.dumps(rec) + "\n")

        self.snap_file.flush()


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

def phase_init(nodes: list[dict], dc: DataCollector):
    """Initialize all nodes (random identity)."""
    print("\n=== Phase: Init ===")
    for n in nodes:
        try:
            exec_node(n["name"], "syncback", "init")
            print(f"  {n['name']} ({n['archetype']}): init ok")
        except RuntimeError as e:
            if "already initialized" in str(e):
                print(f"  {n['name']} ({n['archetype']}): already initialized")
            else:
                raise
    dc.event("init_complete", details=f"{len(nodes)} nodes initialized")


def phase_config(nodes: list[dict], time_scale: int, dc: DataCollector):
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
    dc.event("config_complete", details=f"{len(nodes)} configs written")


def phase_start_daemons(nodes: list[dict], time_scale: int, dc: DataCollector):
    """Start daemons on all nodes."""
    print(f"\n=== Phase: Start daemons (time_scale={time_scale}) ===")
    for n in nodes:
        exec_node_bg(n["name"], "sh", "-c",
                     f"RUST_LOG=info syncback daemon --time-scale {time_scale} --watch-dir /data/files "
                     f">/tmp/daemon.log 2>&1")
    # Wait for all to be ready
    time.sleep(8)
    ready = 0
    for n in nodes:
        try:
            node_status(n["name"])
            ready += 1
        except Exception:
            pass
    print(f"  {ready}/{len(nodes)} daemons ready")
    dc.event("daemons_started", details=f"{ready}/{len(nodes)} ready")


def phase_connect_mesh(nodes: list[dict], dc: DataCollector):
    """Connect nodes in mesh topology: each node connects to 3+ others.

    Strategy: ring + random shortcuts.
    1. Ring: node[i] connects to node[(i+1) % n]
    2. Each node connects to 2 additional random nodes
    This gives each node >= 3 peers (enough for placement).
    """
    print("\n=== Phase: Connect (mesh) ===")
    n = len(nodes)

    # Get all addrs first
    addrs = {}
    for nd in nodes:
        try:
            addrs[nd["name"]] = node_addr(nd["name"])
        except Exception as e:
            print(f"  WARNING: can't get addr for {nd['name']}: {e}")

    connected_pairs = set()

    def try_connect(src_name: str, dst_name: str) -> bool:
        pair = tuple(sorted([src_name, dst_name]))
        if pair in connected_pairs:
            return True
        dst_addr = addrs.get(dst_name)
        if not dst_addr:
            return False
        try:
            exec_node(src_name, "syncback", "connect", dst_addr, timeout=15)
            connected_pairs.add(pair)
            return True
        except Exception:
            return False

    # 1. Ring: each node connects to next
    ring_ok = 0
    for i in range(n):
        j = (i + 1) % n
        if try_connect(nodes[i]["name"], nodes[j]["name"]):
            ring_ok += 1
        time.sleep(0.3)
    print(f"  Ring: {ring_ok}/{n} connections")

    # 2. Random shortcuts: each node connects to 2 more random peers
    shortcut_ok = 0
    for i in range(n):
        targets = random.sample(range(n), min(4, n))
        added = 0
        for j in targets:
            if j == i or j == (i+1) % n or j == (i-1) % n:
                continue
            if try_connect(nodes[i]["name"], nodes[j]["name"]):
                shortcut_ok += 1
                added += 1
            if added >= 2:
                break
            time.sleep(0.2)

    print(f"  Shortcuts: {shortcut_ok} additional connections")
    print(f"  Total unique pairs: {len(connected_pairs)}")

    time.sleep(3)

    # Verify: each node should have >= 3 peers
    low_peers = []
    for nd in nodes:
        s = node_status_safe(nd["name"])
        if s and s.get("peer_count", 0) < 2:
            low_peers.append(nd["name"])
    if low_peers:
        print(f"  WARNING: nodes with < 2 peers: {low_peers}")

    dc.event("connect_complete",
             details=f"{len(connected_pairs)} pairs, low_peer_nodes={len(low_peers)}")


def phase_create_files(nodes: list[dict], dc: DataCollector):
    """Create test files on reliable nodes for backup."""
    print("\n=== Phase: Create files ===")
    reliable = [n for n in nodes if n["archetype"] == "reliable"]
    files_per_node = 5
    file_size_kb = 50
    for n in reliable[:min(5, len(reliable))]:
        exec_node(n["name"], "sh", "-c",
                  f"for i in $(seq 1 {files_per_node}); do "
                  f"dd if=/dev/urandom of=/data/files/test_$i.dat bs=1024 count={file_size_kb} 2>/dev/null; "
                  f"done")
        print(f"  {n['name']}: {files_per_node} files ({file_size_kb}KB each)")
    time.sleep(3)
    dc.event("files_created",
             details=f"{min(5, len(reliable))} nodes × {files_per_node} files × {file_size_kb}KB")


def phase_behavior_loop(nodes: list[dict], duration_secs: int, time_scale: int,
                        dc: DataCollector):
    """Run the behavior loop: stop/start flaky nodes on cycles + collect data."""
    print(f"\n=== Phase: Behavior loop ({duration_secs}s, ~{duration_secs * time_scale / 604800:.1f} sim weeks) ===")

    flaky = [n for n in nodes if n["archetype"] == "flaky"]

    # Track state: True = running, False = stopped
    state = {n["name"]: True for n in flaky}
    next_toggle = {}
    for n in flaky:
        next_toggle[n["name"]] = time.time() + random.uniform(10, n.get("on_secs", 180))

    start_time = time.time()
    last_snapshot = 0
    last_report = 0

    while time.time() - start_time < duration_secs:
        now = time.time()
        elapsed = int(now - start_time)

        # Toggle flaky nodes
        for n in flaky:
            name = n["name"]
            if now >= next_toggle[name]:
                if state[name]:
                    try:
                        exec_node(name, "sh", "-c",
                                  "killall syncback 2>/dev/null || true")
                    except Exception:
                        pass
                    state[name] = False
                    off_time = n.get("off_secs", 180) + random.uniform(-30, 30)
                    next_toggle[name] = now + off_time
                    dc.event("flaky_stop", node=name,
                             details=f"off for {off_time:.0f}s")
                else:
                    exec_node_bg(name, "sh", "-c",
                                 f"RUST_LOG=info syncback daemon --time-scale {time_scale} "
                                 f"--watch-dir /data/files >>/tmp/daemon.log 2>&1")
                    state[name] = True
                    on_time = n.get("on_secs", 180) + random.uniform(-30, 30)
                    next_toggle[name] = now + on_time
                    dc.event("flaky_start", node=name,
                             details=f"on for {on_time:.0f}s")

                    # Reconnect to a few peers after restart
                    time.sleep(2)
                    _reconnect_flaky(name, nodes)

        # Collect data every SNAPSHOT_INTERVAL seconds
        if elapsed - last_snapshot >= SNAPSHOT_INTERVAL:
            dc.snapshot_all(nodes, time_scale)
            last_snapshot = elapsed

        # Console report every 120 seconds
        if elapsed - last_report >= 120:
            online = sum(1 for v in state.values() if v)
            total_online = len(nodes) - len(flaky) + online
            sim_weeks = elapsed * time_scale / 604800
            print(f"  [{elapsed}s real, ~{sim_weeks:.1f} sim weeks] "
                  f"{total_online}/{len(nodes)} online, "
                  f"flaky: {online}/{len(flaky)} up")
            last_report = elapsed

        time.sleep(10)

    # Final snapshot
    dc.snapshot_all(nodes, time_scale)
    dc.event("behavior_loop_complete",
             details=f"{duration_secs}s elapsed, "
                     f"~{duration_secs * time_scale / 604800:.1f} sim weeks")
    print(f"  Behavior loop complete ({duration_secs}s)")


def _reconnect_flaky(name: str, nodes: list[dict]):
    """After a flaky node restarts, reconnect it to 2 random other nodes."""
    others = [n for n in nodes if n["name"] != name]
    targets = random.sample(others, min(3, len(others)))
    for t in targets:
        try:
            addr = node_addr(t["name"])
            if addr:
                exec_node(name, "syncback", "connect", addr, timeout=10)
        except Exception:
            pass


def phase_report(nodes: list[dict], dc: DataCollector) -> str:
    """Collect final report. Returns report text."""
    print("\n=== Final Report ===")
    lines = []
    lines.append("=" * 70)
    lines.append("GAMMA EXPERIMENT — FINAL REPORT")
    lines.append(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"Elapsed: {dc.elapsed():.0f}s")
    lines.append("=" * 70)

    by_arch: dict[str, list[dict]] = {}
    for n in nodes:
        arch = n["archetype"]
        by_arch.setdefault(arch, [])
        s = node_status_safe(n["name"])
        if s is None:
            by_arch[arch].append({"name": n["name"], "online": False})
            continue

        by_arch[arch].append({
            "name": n["name"],
            "online": True,
            "peers": s.get("peer_count", 0),
            "holding_kb": s.get("holding_bytes", 0) // 1024,
            "backed_files": s.get("backed_up_files", 0),
            "backed_bytes": s.get("backed_up_bytes", 0),
            "placement_alive": s.get("placement_alive", 0),
            "placement_lost": s.get("placement_lost", 0),
            "pos_challenged": s.get("pos_total_challenges", 0),
            "pos_passed": s.get("pos_total_passes", 0),
            "blocks_ok": s.get("blocks_ok", 0),
            "blocks_at_risk": s.get("blocks_at_risk", 0),
            "avg_trust": s.get("avg_trust", 0),
            "peer_trusts": [
                {
                    "id": p.get("identity_hex", "")[:16],
                    "trust": round(p.get("trust", 0), 4),
                    "p": round(p.get("trust_p", 0), 4),
                    "i": round(p.get("trust_i", 0), 4),
                    "s": round(p.get("trust_s", 0), 4),
                }
                for p in s.get("peers", [])
            ],
        })

    for arch, entries in by_arch.items():
        lines.append(f"\n--- [{arch}] ({len(entries)} nodes) ---")
        online_entries = [e for e in entries if e.get("online")]
        offline_entries = [e for e in entries if not e.get("online")]

        if offline_entries:
            lines.append(f"  OFFLINE: {[e['name'] for e in offline_entries]}")

        for e in online_entries:
            pos_ch = e.get("pos_challenged", 0)
            pos_pa = e.get("pos_passed", 0)
            pos_rate = f"{pos_pa}/{pos_ch} ({pos_pa/pos_ch*100:.0f}%)" if pos_ch > 0 else "0/0"
            lines.append(
                f"  {e['name']}: peers={e['peers']} "
                f"holding={e['holding_kb']}KB "
                f"placements={e['placement_alive']}/{e['placement_alive']+e['placement_lost']} alive "
                f"pos={pos_rate} "
                f"blocks={e['blocks_ok']}ok/{e['blocks_at_risk']}risk "
                f"avg_trust={e['avg_trust']:.4f}"
            )

        # Aggregate stats for this archetype
        if online_entries:
            avg_holding = sum(e["holding_kb"] for e in online_entries) / len(online_entries)
            total_pos_ch = sum(e.get("pos_challenged", 0) for e in online_entries)
            total_pos_pa = sum(e.get("pos_passed", 0) for e in online_entries)
            avg_trust = sum(e.get("avg_trust", 0) for e in online_entries) / len(online_entries)
            pos_rate_agg = f"{total_pos_pa/total_pos_ch*100:.1f}%" if total_pos_ch > 0 else "n/a"
            lines.append(
                f"  AGGREGATE: avg_holding={avg_holding:.0f}KB "
                f"total_pos={total_pos_pa}/{total_pos_ch} ({pos_rate_agg}) "
                f"avg_trust_received={avg_trust:.4f}"
            )

    # Trust matrix: how each archetype views others
    lines.append("\n--- Trust Matrix (observer → subject avg trust) ---")
    # For each observer archetype, compute avg trust given to each subject archetype
    # We need to match peer identity to archetype
    identity_to_arch = {}
    for n in nodes:
        s = node_status_safe(n["name"])
        if s:
            identity_to_arch[s.get("node_identity", "")[:16]] = n["archetype"]

    for obs_arch in by_arch:
        obs_entries = [e for e in by_arch[obs_arch] if e.get("online")]
        trust_by_subj: dict[str, list[float]] = {}
        for e in obs_entries:
            for pt in e.get("peer_trusts", []):
                subj_arch = identity_to_arch.get(pt["id"], "?")
                trust_by_subj.setdefault(subj_arch, []).append(pt["trust"])
        parts = []
        for subj_arch in ["reliable", "flaky", "freeloader"]:
            vals = trust_by_subj.get(subj_arch, [])
            if vals:
                parts.append(f"{subj_arch}={sum(vals)/len(vals):.4f}")
            else:
                parts.append(f"{subj_arch}=n/a")
        lines.append(f"  {obs_arch:12s} → {', '.join(parts)}")

    report = "\n".join(lines)
    print(report)
    return report


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Gamma experiment: trust archetypes")
    parser.add_argument("-n", "--nodes", type=int, default=20)
    parser.add_argument("-t", "--time-scale", type=int, default=1000)
    parser.add_argument("-d", "--duration", type=int, default=7200,
                        help="Behavior loop duration in seconds (default: 7200 = 2 hours)")
    parser.add_argument("--build", action="store_true", help="Build Docker images first")
    parser.add_argument("--skip-setup", action="store_true",
                        help="Skip init/config/connect (resume behavior loop)")
    parser.add_argument("--run-id", type=str, default=None,
                        help="Custom run ID (default: timestamp)")
    args = parser.parse_args()

    run_id = args.run_id or datetime.now().strftime("%Y%m%d-%H%M%S")
    results_dir = Path(PROJECT_DIR) / "experiments" / "gamma" / "results" / run_id

    print(f"Gamma experiment: {args.nodes} nodes, time_scale={args.time_scale}, "
          f"duration={args.duration}s")
    print(f"Simulated time: ~{args.duration * args.time_scale / 604800:.1f} weeks")
    print(f"Results: {results_dir}")

    dc = DataCollector(results_dir)

    # Save experiment config
    config = {
        "run_id": run_id,
        "nodes": args.nodes,
        "time_scale": args.time_scale,
        "duration_secs": args.duration,
        "sim_weeks": round(args.duration * args.time_scale / 604800, 1),
        "archetypes": ARCHETYPES,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(results_dir / "config.json", "w") as f:
        json.dump(config, f, indent=2)

    # Generate compose
    sys.path.insert(0, str(Path(__file__).parent))
    from compose_gen import generate
    generate(args.nodes, os.path.join(PROJECT_DIR, COMPOSE_FILE))

    nodes = assign_archetypes(args.nodes)
    # Save node assignment
    with open(results_dir / "nodes.json", "w") as f:
        json.dump(nodes, f, indent=2)

    print(f"\nArchetypes:")
    for arch in ARCHETYPES:
        count = sum(1 for n in nodes if n["archetype"] == arch)
        print(f"  {arch}: {count} nodes")

    if args.build:
        print("\n=== Building syncback binary ===")
        r = subprocess.run(
            ["cargo", "build", "--release", "-p", "syncback"],
            cwd=PROJECT_DIR, timeout=600,
        )
        if r.returncode != 0:
            sys.exit(1)
        print("\n=== Building runtime images ===")
        r = compose("build", timeout=120)
        if r.returncode != 0:
            print(f"Image build failed: {r.stderr}")
            sys.exit(1)

    # Verify binary exists
    binary = os.path.join(PROJECT_DIR, "target", "release", "syncback")
    if not os.path.isfile(binary):
        print(f"ERROR: {binary} not found. Run with --build first.")
        sys.exit(1)

    print("\n=== Starting containers ===")
    r = compose("up", "-d", timeout=120)
    if r.returncode != 0:
        print(f"compose up failed: {r.stderr}")
        sys.exit(1)
    time.sleep(3)

    try:
        if not args.skip_setup:
            phase_init(nodes, dc)
            phase_config(nodes, args.time_scale, dc)
            phase_start_daemons(nodes, args.time_scale, dc)
            phase_connect_mesh(nodes, dc)
            phase_create_files(nodes, dc)
        else:
            print("\n  (skipping setup, resuming behavior loop)")

        # Initial snapshot before behavior starts
        dc.snapshot_all(nodes, args.time_scale)

        phase_behavior_loop(nodes, args.duration, args.time_scale, dc)
        report = phase_report(nodes, dc)

        # Save report
        with open(results_dir / "report.txt", "w") as f:
            f.write(report)

    finally:
        dc.close()

    print(f"\nDone. Results: {results_dir}")
    print(f"Grafana: http://YOUR-LAN-IP:3001")
    print(f"Containers still running. To stop: docker compose -f {COMPOSE_FILE} down -v")


if __name__ == "__main__":
    main()
