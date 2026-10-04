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
    "reliable":   {"fraction": 0.4, "quota_gb": 20, "behavior": "always_on"},
    "flaky":      {"fraction": 0.4, "quota_gb": 20, "behavior": "cycle",
                   "on_secs": 180, "off_secs": 180},
    "freeloader": {"fraction": 0.2, "quota_gb": 5,  "behavior": "always_on"},
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
    raw = exec_node(name, "viaticum", "status", "--json")
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
                "device_id": s.get("device_id", ""),
                "node_identity": s.get("node_identity", "")[:16],
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
            exec_node(n["name"], "viaticum", "init")
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
                  f"cat > /home/viaticum/.viaticum/config.toml << 'EOFCFG'\n{config}EOFCFG")
    print(f"  config written to {len(nodes)} nodes")
    dc.event("config_complete", details=f"{len(nodes)} configs written")


def phase_start_daemons(nodes: list[dict], time_scale: int, dc: DataCollector):
    """Start daemons on all nodes."""
    print(f"\n=== Phase: Start daemons (time_scale={time_scale}) ===")
    for n in nodes:
        exec_node_bg(n["name"], "sh", "-c",
                     f"RUST_LOG=info viaticum daemon --time-scale {time_scale} --watch-dir /data/files "
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
            exec_node(src_name, "viaticum", "connect", dst_addr, timeout=15)
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


# Owner profiles model different real-world user patterns. Each is assigned to
# one reliable seeder. `initial` runs once at setup; `ongoing` fires every
# `interval_secs` of REAL time during the behavior loop.
OWNER_PROFILES = {
    # Backup of an archive image — single large file that stresses both
    # SymbolTransfer chunking AND the offer-budget bootstrap path (a fresh owner
    # can't commit a 2 GB file without earned credit).
    "archive_dump": {
        "initial":  [{"prefix": "backup", "count": 1,   "size_kb": 2_000_000, "subdir": "archives"}],
        "ongoing":  None,
    },
    # Photographer: many medium photos, adds new ones every cycle.
    "photographer": {
        "initial":  [{"prefix": "img",    "count": 120, "size_kb": 8_000,     "subdir": "photos"}],
        "ongoing":  {"interval_secs": 90,  "items": [
                        {"prefix": "img_new", "count": 3, "size_kb": 8_000, "subdir": "photos"}]},
    },
    # Document worker: many small files; constant trickle of updates.
    "document_user": {
        "initial":  [{"prefix": "doc",    "count": 300, "size_kb": 100,       "subdir": "docs"},
                     {"prefix": "sheet",  "count": 30,  "size_kb": 500,       "subdir": "docs"}],
        "ongoing":  {"interval_secs": 60, "items": [
                        {"prefix": "doc_new",  "count": 10, "size_kb": 100, "subdir": "docs"}]},
    },
    # Mixed user: a project export, photos, configs.
    "mixed": {
        "initial":  [{"prefix": "export", "count": 1,   "size_kb": 500_000,   "subdir": "export"},
                     {"prefix": "photo",  "count": 30,  "size_kb": 10_000,    "subdir": "photos"},
                     {"prefix": "cfg",    "count": 100, "size_kb": 100,       "subdir": "configs"}],
        "ongoing":  {"interval_secs": 120, "items": [
                        {"prefix": "extra", "count": 5, "size_kb": 1_000, "subdir": "misc"}]},
    },
    # Video editor: several large clips.
    "video_chunks": {
        "initial":  [{"prefix": "clip",   "count": 10,  "size_kb": 150_000,   "subdir": "video"}],
        "ongoing":  {"interval_secs": 180, "items": [
                        {"prefix": "clip_new", "count": 1, "size_kb": 150_000, "subdir": "video"}]},
    },
}


def _create_files(node_name: str, items: list[dict], tag: str) -> int:
    """Create files for a single node according to a list of item specs.
    Returns total bytes written."""
    total_bytes = 0
    parts = []
    for item in items:
        sub = item.get("subdir", "").strip("/")
        path = f"/data/files/{sub}".rstrip("/")
        # Use short label for new files in the ongoing phase to avoid collisions.
        label = f"{tag}-{int(time.time())}" if tag else ""
        parts.append(
            f"mkdir -p {path}; "
            f"for i in $(seq 1 {item['count']}); do "
            f"dd if=/dev/urandom of={path}/{item['prefix']}_{label}_$i.bin "
            f"bs=1024 count={item['size_kb']} 2>/dev/null; done"
        )
        total_bytes += item["count"] * item["size_kb"] * 1024
    cmd = " && ".join(parts)
    exec_node(node_name, "sh", "-c", cmd, timeout=600)
    return total_bytes


def phase_create_files(nodes: list[dict], dc: DataCollector):
    """Initial seeding for each reliable owner using its assigned profile."""
    print("\n=== Phase: Create files (per owner profile) ===")
    reliable = [n for n in nodes if n["archetype"] == "reliable"]
    profile_names = list(OWNER_PROFILES.keys())
    seeders = reliable[:min(len(profile_names), len(reliable))]
    for idx, n in enumerate(seeders):
        profile_name = profile_names[idx]
        profile = OWNER_PROFILES[profile_name]
        n["owner_profile"] = profile_name
        bytes_written = _create_files(n["name"], profile["initial"], tag="init")
        print(f"  {n['name']} <{profile_name}>: {bytes_written/1_048_576:.1f} MB seeded")
        dc.event("files_seeded", node=n["name"],
                 details=f"profile={profile_name} bytes={bytes_written}")
    time.sleep(3)


def _run_ongoing_user_activity(nodes: list[dict], dc: DataCollector,
                               last_fired: dict[str, float]) -> None:
    """During behavior loop: trigger periodic file creation per owner profile."""
    now = time.time()
    for n in nodes:
        profile_name = n.get("owner_profile")
        if not profile_name:
            continue
        spec = OWNER_PROFILES[profile_name].get("ongoing")
        if not spec:
            continue
        last = last_fired.get(n["name"], 0)
        if now - last < spec["interval_secs"]:
            continue
        try:
            bytes_written = _create_files(n["name"], spec["items"], tag="ongoing")
            dc.event("user_added_files", node=n["name"],
                     details=f"profile={profile_name} bytes={bytes_written}")
            last_fired[n["name"]] = now
        except Exception as e:
            dc.event("user_added_files_failed", node=n["name"], details=str(e))


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

    # Track last ongoing-user-activity firing per owner.
    last_user_activity: dict[str, float] = {}

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
                                  "killall viaticum 2>/dev/null || true")
                    except Exception:
                        pass
                    state[name] = False
                    off_time = n.get("off_secs", 180) + random.uniform(-30, 30)
                    next_toggle[name] = now + off_time
                    dc.event("flaky_stop", node=name,
                             details=f"off for {off_time:.0f}s")
                else:
                    exec_node_bg(name, "sh", "-c",
                                 f"RUST_LOG=info viaticum daemon --time-scale {time_scale} "
                                 f"--watch-dir /data/files >>/tmp/daemon.log 2>&1")
                    state[name] = True
                    on_time = n.get("on_secs", 180) + random.uniform(-30, 30)
                    next_toggle[name] = now + on_time
                    dc.event("flaky_start", node=name,
                             details=f"on for {on_time:.0f}s")

                    # Reconnect to a few peers after restart
                    time.sleep(2)
                    _reconnect_flaky(name, nodes)

        # Periodic user-driven file creation per owner profile.
        _run_ongoing_user_activity(nodes, dc, last_user_activity)

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
                exec_node(name, "viaticum", "connect", addr, timeout=10)
        except Exception:
            pass


def id_to_node_preview(nodes: list[dict]) -> dict[str, str]:
    """Map device_id (first 8 bytes hex) → node name. Used by phase_report
    to label peers from the reporter's status snapshots."""
    out: dict[str, str] = {}
    for n in nodes:
        s = node_status_safe(n["name"])
        if s:
            key = s.get("device_id") or s.get("node_identity", "")[:16]
            if key:
                out[key] = n["name"]
    return out


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
                    "bytes_we_store": p.get("bytes_we_store", 0),
                    "bytes_peer_stores": p.get("bytes_peer_stores", 0),
                    "pos_ch": p.get("pos_challenges_recent", 0),
                    "pos_pa": p.get("pos_passes_recent", 0),
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

    # Trust matrix: how each archetype views others.
    # Filter to observers that actually issue PoS (i.e. own placements) — non-owner
    # observers have only the initial trust default (0.03) and smear the signal.
    lines.append("\n--- Trust Matrix (active-owner observer → subject avg trust) ---")
    identity_to_arch = {}
    for n in nodes:
        s = node_status_safe(n["name"])
        if s:
            key = s.get("device_id") or s.get("node_identity", "")[:16]
            if key:
                identity_to_arch[key] = n["archetype"]

    # Identify which devices are "active owners" (have placements) — the
    # subjects-that-are-owners skew the S component because they make us
    # store for them, which yields pairwise asymmetry.
    owner_device_ids: set[str] = set()
    for obs_arch in by_arch:
        for e in by_arch[obs_arch]:
            if e.get("online") and e.get("placement_alive", 0) > 0:
                # Look up this node's device_id.
                for key, name in [(k, v) for k, v in id_to_node_preview(nodes).items()]:
                    if name == e["name"]:
                        owner_device_ids.add(key)

    for obs_arch in by_arch:
        obs_entries = [
            e for e in by_arch[obs_arch]
            if e.get("online") and e.get("placement_alive", 0) > 0
        ]
        if not obs_entries:
            lines.append(f"  {obs_arch:12s} → (no active owners in this archetype)")
            continue
        # Bucket subjects by (archetype, is_owner) to separate the S-asymmetry
        # effect. Mixed averages obscure which group is actually misbehaving.
        trust_plain: dict[str, list[float]] = {}
        trust_owner: dict[str, list[float]] = {}
        for e in obs_entries:
            for pt in e.get("peer_trusts", []):
                subj_arch = identity_to_arch.get(pt["id"], "?")
                bucket = trust_owner if pt["id"] in owner_device_ids else trust_plain
                bucket.setdefault(subj_arch, []).append(pt["trust"])

        def fmt(d):
            parts_ = []
            for subj_arch in ["reliable", "flaky", "freeloader"]:
                vals = d.get(subj_arch, [])
                if vals:
                    parts_.append(f"{subj_arch}={sum(vals)/len(vals):.4f} (n={len(vals)})")
                else:
                    parts_.append(f"{subj_arch}=n/a")
            return ", ".join(parts_)

        lines.append(f"  {obs_arch:12s} → non-owner subjects: {fmt(trust_plain)}")
        if any(trust_owner.values()):
            lines.append(f"  {obs_arch:12s} → owner  subjects: {fmt(trust_owner)}")

    # Per-peer breakdown for each active owner. Useful to sanity-check the
    # trust-matrix aggregate (where high-trust peers can outweigh low ones).
    id_to_node = id_to_node_preview(nodes)

    lines.append("\n--- Per-peer trust (active owners) ---")
    any_owner = False
    for obs_arch in by_arch:
        for e in by_arch[obs_arch]:
            if not (e.get("online") and e.get("placement_alive", 0) > 0):
                continue
            any_owner = True
            profile = next(
                (n.get("owner_profile", "?") for n in nodes if n["name"] == e["name"]),
                "?",
            )
            lines.append(
                f"\n  {e['name']} <{obs_arch}/{profile}> "
                f"placements={e['placement_alive']} pos={e.get('pos_passed',0)}/{e.get('pos_challenged',0)}"
            )
            lines.append(
                f"    {'peer':18} {'arch':12} {'P':>6} {'I':>6} {'S':>6} {'combined':>9} "
                f"{'held (MB)':>10} {'stores (MB)':>12} {'pos recent':>12}"
            )
            peers_sorted = sorted(
                e.get("peer_trusts", []),
                key=lambda p: p.get("trust", 0),
                reverse=True,
            )
            for pt in peers_sorted:
                subj_arch = identity_to_arch.get(pt["id"], "?")
                subj_name = id_to_node.get(pt["id"], "?")
                pos_ch = pt.get("pos_ch", 0)
                pos_pa = pt.get("pos_pa", 0)
                pos_rate = (
                    f"{pos_pa}/{pos_ch} ({pos_pa / pos_ch * 100:.0f}%)"
                    if pos_ch > 0 else "-"
                )
                lines.append(
                    f"    {pt['id']:18} {subj_arch[:8] + '/' + subj_name:12} "
                    f"{pt['p']:>6.3f} {pt['i']:>6.3f} {pt['s']:>6.3f} {pt['trust']:>9.4f} "
                    f"{pt.get('bytes_peer_stores', 0)/1_048_576:>10.1f} "
                    f"{pt.get('bytes_we_store', 0)/1_048_576:>12.1f} "
                    f"{pos_rate:>12}"
                )
    if not any_owner:
        lines.append("  (no active owners)")

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
        print("\n=== Building viaticum binary ===")
        r = subprocess.run(
            ["cargo", "build", "--release", "-p", "viaticum"],
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
    binary = os.path.join(PROJECT_DIR, "target", "release", "viaticum")
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
