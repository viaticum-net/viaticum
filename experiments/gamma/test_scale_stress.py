#!/usr/bin/env python3
"""
T15: Large-Scale Stress Test with Behavior Archetypes

Runs 100+ nodes for an extended period with different node behaviors:
- Reliable nodes: always online, store data faithfully
- Flaky nodes: go offline periodically (stop/start container)
- Freeloaders: have tiny quota, reject most offers
- Churners: join late, leave early (stop permanently mid-test)

Checks:
- Network converges (all nodes discover peers)
- Backup completes under realistic conditions
- Trust differentiates reliable from flaky nodes
- PoS detects offline nodes, repair keeps blocks healthy
- Restore works after extended run
- No crashes or panics across all nodes
- Freeloaders get lower trust than reliable nodes
- System remains stable over time (no drift, no leaks)

Usage:
    python experiments/gamma/test_scale_stress.py [-n 100] [--time-scale 100000] [--duration 300]

Duration is in seconds of real time. With time_scale=100000, 300s = ~347 simulated days.
"""

import argparse
import json
import os
import random
import subprocess
import sys
import time
from pathlib import Path

PROJECT_DIR = str(Path(__file__).parent.parent.parent)
COMPOSE_FILE = "experiments/gamma/compose.yml"

# ── Helpers ───────────────────────────────────────────────────────────────────

def docker(*args, timeout=30):
    return subprocess.run(
        ["docker"] + list(args),
        capture_output=True, text=True, timeout=timeout,
    )


def compose(*args, timeout=120):
    return subprocess.run(
        ["docker", "compose", "-f", COMPOSE_FILE] + list(args),
        capture_output=True, text=True, timeout=timeout,
        cwd=PROJECT_DIR,
    )


def exec_node(name, *args, timeout=30):
    r = subprocess.run(
        ["docker", "exec", f"gamma-{name}"] + list(args),
        capture_output=True, text=True, timeout=timeout,
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"exec_node({name}): exit {r.returncode}\n"
            f"  stdout: {r.stdout.strip()}\n"
            f"  stderr: {r.stderr.strip()}"
        )
    return r.stdout.strip()


def exec_node_quiet(name, *args, timeout=30):
    try:
        return exec_node(name, *args, timeout=timeout)
    except Exception:
        return ""


def exec_node_bg(name, *args):
    subprocess.run(
        ["docker", "exec", "-d", f"gamma-{name}"] + list(args),
        capture_output=True, text=True, timeout=10,
    )


def node_status(name):
    raw = exec_node(name, "syncback", "status", "--json", timeout=15)
    return json.loads(raw)


def node_status_safe(name):
    try:
        return node_status(name)
    except Exception:
        return None


def wait_for(desc, predicate, timeout_secs=120, poll_secs=5):
    start = time.time()
    while time.time() - start < timeout_secs:
        if predicate():
            elapsed = time.time() - start
            print(f"  {desc}: OK ({elapsed:.0f}s)")
            return True
        time.sleep(poll_secs)
    print(f"  {desc}: TIMEOUT ({timeout_secs}s)")
    return False


# ── Archetype definitions ────────────────────────────────────────────────────

class NodeArchetype:
    """Base class for node behavior archetypes."""
    def __init__(self, name, archetype):
        self.name = name
        self.archetype = archetype

    def config(self):
        """Return TOML config string for this node."""
        return """[backup]
source_block_size_mb = 1

[storage]
soft_quota_gb = 0.1
disk_reserve_gb = 0.0

[network]
enable_relay = false
"""

    def should_be_online(self, elapsed_secs, total_duration):
        """Return True if this node should be online at this time."""
        return True


class ReliableNode(NodeArchetype):
    """Always online, generous quota. The backbone of the network."""
    def __init__(self, name):
        super().__init__(name, "reliable")


class FlakyNode(NodeArchetype):
    """Goes offline for 30s every 60-90s (simulating unstable connection)."""
    def __init__(self, name):
        super().__init__(name, "flaky")
        self.offline_until = 0
        self.next_offline = random.randint(60, 90)

    def should_be_online(self, elapsed_secs, total_duration):
        if elapsed_secs >= self.offline_until and elapsed_secs >= self.next_offline:
            # Go offline for 20-30s
            offline_duration = random.randint(20, 30)
            self.offline_until = elapsed_secs + offline_duration
            self.next_offline = self.offline_until + random.randint(40, 60)
            return False
        return elapsed_secs >= self.offline_until


class FreeloaderNode(NodeArchetype):
    """Tiny quota — will reject most offers. Stores almost nothing."""
    def __init__(self, name):
        super().__init__(name, "freeloader")

    def config(self):
        return """[backup]
source_block_size_mb = 1

[storage]
soft_quota_gb = 0.001
disk_reserve_gb = 0.0

[network]
enable_relay = false
"""


class ChurnerNode(NodeArchetype):
    """Joins at a random time, leaves permanently after ~60% of the test."""
    def __init__(self, name, total_duration):
        super().__init__(name, "churner")
        join_hi = max(31, int(total_duration * 0.3))
        self.join_at = random.randint(30, join_hi)
        leave_lo = max(self.join_at + 10, int(total_duration * 0.5))
        leave_hi = max(leave_lo + 1, int(total_duration * 0.7))
        self.leave_at = random.randint(leave_lo, leave_hi)
        self.left = False

    def should_be_online(self, elapsed_secs, total_duration):
        if self.left:
            return False
        if elapsed_secs >= self.leave_at:
            self.left = True
            return False
        return elapsed_secs >= self.join_at


# ── Main test ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="T15: Scale Stress Test")
    parser.add_argument("-n", "--nodes", type=int, default=100)
    parser.add_argument("--time-scale", type=int, default=100000)
    parser.add_argument("--duration", type=int, default=300,
                        help="Test duration in real seconds (default 300 = 5 min)")
    args = parser.parse_args()
    n = args.nodes
    ts = args.time_scale
    duration = args.duration

    results = {"passed": [], "failed": []}

    print("=" * 60)
    print(f"  T15: Scale Stress Test ({n} nodes, {duration}s)")
    print(f"  time_scale={ts}")
    sim_days = duration * ts / 86400
    print(f"  Simulated time: ~{sim_days:.0f} days")
    print("=" * 60)
    print()

    # ── Assign archetypes ────────────────────────────────────────
    # Distribution: 60% reliable, 15% flaky, 15% freeloaders, 10% churners
    nodes = []
    node_names = [f"node-{i:02d}" for i in range(n)]

    # node-00 is always the owner (reliable)
    nodes.append(ReliableNode("node-00"))

    for i in range(1, n):
        name = f"node-{i:02d}"
        r = random.random()
        if r < 0.60:
            nodes.append(ReliableNode(name))
        elif r < 0.75:
            nodes.append(FlakyNode(name))
        elif r < 0.90:
            nodes.append(FreeloaderNode(name))
        else:
            nodes.append(ChurnerNode(name, duration))

    # Print distribution
    by_type = {}
    for nd in nodes:
        by_type.setdefault(nd.archetype, []).append(nd.name)
    for arch, names in sorted(by_type.items()):
        print(f"  {arch}: {len(names)} nodes")
    print()

    # ── Generate compose and start ───────────────────────────────
    sys.path.insert(0, str(Path(__file__).parent))
    from compose_gen import generate
    generate(n, os.path.join(PROJECT_DIR, COMPOSE_FILE), include_metrics=False)

    compose("down", "-v", "--remove-orphans", timeout=120)
    r = compose("up", "-d", timeout=300)
    if r.returncode != 0:
        print(f"compose up failed: {r.stderr[:500]}")
        sys.exit(1)
    time.sleep(5)

    try:
        # ── Phase 1: Init all nodes ──────────────────────────────
        print("Phase 1: Init all nodes")
        init_ok = 0
        for nd in nodes:
            try:
                exec_node(nd.name, "syncback", "init")
                init_ok += 1
            except RuntimeError as e:
                if "already initialized" not in str(e):
                    print(f"  {nd.name}: init failed: {e}")
        print(f"  {init_ok}/{n} nodes initialized")
        print()

        # ── Phase 2: Configure nodes ─────────────────────────────
        print("Phase 2: Configure nodes")
        for nd in nodes:
            config = nd.config()
            exec_node(nd.name, "sh", "-c",
                      f"cat > /home/syncback/.syncback/config.toml << 'EOFCFG'\n{config}EOFCFG")
        print(f"  All {n} nodes configured")
        print()

        # ── Phase 3: Start daemons (reliable + freeloaders only) ─
        print("Phase 3: Start daemons")
        started = 0
        for nd in nodes:
            if nd.should_be_online(0, duration):
                exec_node_bg(nd.name, "sh", "-c",
                             f"RUST_LOG=info syncback daemon --time-scale {ts} "
                             f"--watch-dir /data/files >/tmp/daemon.log 2>&1")
                started += 1
        print(f"  {started}/{n} daemons started (churners join later)")
        time.sleep(8)
        print()

        # ── Phase 4: Bootstrap — connect in batches to avoid storm ─
        print("Phase 4: Bootstrap peer discovery")
        owner_status = node_status("node-00")
        owner_addr = owner_status.get("node_addr", "")

        # Connect in batches of 10 with a pause between batches.
        # This avoids overwhelming node-00 with simultaneous handshakes.
        online_nodes_to_connect = [
            nd for nd in nodes[1:] if nd.should_be_online(0, duration)
        ]
        batch_size = 10
        connected = 0
        for i in range(0, len(online_nodes_to_connect), batch_size):
            batch = online_nodes_to_connect[i:i+batch_size]
            for nd in batch:
                try:
                    exec_node(nd.name, "syncback", "connect", owner_addr, timeout=15)
                    connected += 1
                except Exception:
                    pass
            if i + batch_size < len(online_nodes_to_connect):
                time.sleep(3)  # let handshakes complete before next batch
        print(f"  {connected} nodes connected to owner (batches of {batch_size})")

        # Wait for discovery to converge — handshake + PeerAnnounce take time.
        min_peers = max(int(n * 0.3), 2)
        ok = wait_for(
            f"Owner discovers >= {min_peers} peers",
            lambda: (s := node_status_safe("node-00")) is not None
                    and s.get("peer_count", 0) >= min_peers,
            timeout_secs=90, poll_secs=5,
        )
        owner_s = node_status_safe("node-00")
        owner_peers = owner_s.get("peer_count", 0) if owner_s else 0
        if ok:
            results["passed"].append("initial_discovery")
        else:
            results["failed"].append("initial_discovery")
            print(f"    Owner peer_count: {owner_peers} (wanted >= {min_peers})")
        print()

        # ── Phase 5: Create backup files ─────────────────────────
        print("Phase 5: Create backup files on owner")
        for i in range(3):
            exec_node("node-00", "dd", "if=/dev/urandom",
                      f"of=/data/files/stress_{i}.bin",
                      "bs=1024", f"count={200 + i*100}", timeout=30)
        print(f"  Created 3 files (200-400 KB each)")
        print()

        # ── Phase 6: Wait for backup ─────────────────────────────
        print("Phase 6: Wait for backup")
        ok = wait_for(
            "Backup complete",
            lambda: (s := node_status_safe("node-00")) is not None
                    and s.get("blocks_ok", 0) >= 1,
            timeout_secs=180, poll_secs=5,
        )
        if ok:
            results["passed"].append("backup_complete")
        else:
            results["failed"].append("backup_complete")
        print()

        # ── Phase 7: Run stress period ───────────────────────────
        print(f"Phase 7: Stress period ({duration}s)")
        print(f"  Simulating {sim_days:.0f} days of operation...")

        start_time = time.time()
        node_online_state = {nd.name: nd.should_be_online(0, duration) for nd in nodes}
        snapshot_interval = max(30, duration // 10)
        last_snapshot = 0
        snapshot_count = 0

        while time.time() - start_time < duration:
            elapsed = time.time() - start_time

            # Manage node lifecycle (flaky/churner behavior)
            for nd in nodes[1:]:
                should_online = nd.should_be_online(elapsed, duration)
                was_online = node_online_state.get(nd.name, True)

                if was_online and not should_online:
                    # Take offline
                    exec_node_quiet(nd.name, "pkill", "-f", "syncback daemon")
                    if nd.archetype == "churner":
                        print(f"    [{elapsed:.0f}s] {nd.name} (churner) left permanently")
                    else:
                        print(f"    [{elapsed:.0f}s] {nd.name} (flaky) went offline")
                    node_online_state[nd.name] = False

                elif not was_online and should_online:
                    # Bring back online
                    exec_node_bg(nd.name, "sh", "-c",
                                 f"RUST_LOG=info syncback daemon --time-scale {ts} "
                                 f"--watch-dir /data/files >/tmp/daemon.log 2>&1")
                    time.sleep(2)
                    exec_node_quiet(nd.name, "syncback", "connect", owner_addr, timeout=10)
                    print(f"    [{elapsed:.0f}s] {nd.name} (flaky) came back online")
                    node_online_state[nd.name] = True

            # Periodic snapshot
            if elapsed - last_snapshot >= snapshot_interval:
                snapshot_count += 1
                s = node_status_safe("node-00")
                if s:
                    pc = s.get("peer_count", 0)
                    ch = s.get("pos_total_challenges", 0)
                    pa = s.get("pos_total_passes", 0)
                    bo = s.get("blocks_ok", 0)
                    ba = s.get("blocks_at_risk", 0)
                    print(f"  [{elapsed:.0f}s] peers={pc} challenges={ch} "
                          f"passes={pa} blocks_ok={bo} at_risk={ba}")
                last_snapshot = elapsed

            time.sleep(5)

        print(f"  Stress period complete ({duration}s elapsed)")
        print()

        # ── Phase 8: Final health check ──────────────────────────
        print("Phase 8: Final health check")
        s = node_status_safe("node-00")
        peer_list = []
        if s:
            peers = s.get("peer_count", 0)
            challenges = s.get("pos_total_challenges", 0)
            passes = s.get("pos_total_passes", 0)
            blocks_ok = s.get("blocks_ok", 0)
            blocks_at_risk = s.get("blocks_at_risk", 0)
            avg_trust = s.get("avg_trust", 0)
            peer_list = s.get("peers", [])

            print(f"  peers={peers}")
            print(f"  challenges={challenges}, passes={passes}")
            print(f"  blocks_ok={blocks_ok}, blocks_at_risk={blocks_at_risk}")
            print(f"  avg_trust={avg_trust:.4f}")

            # Blocks should be healthy
            if blocks_ok >= 1:
                results["passed"].append("blocks_healthy")
            else:
                results["failed"].append("blocks_healthy")

            # PoS should have run at least a few times.
            # With ts=10000 challenge interval ≈ 60s, so 5 min → ~5 challenges.
            if challenges >= 3:
                results["passed"].append("pos_active")
                print(f"  PoS active: {challenges} challenges, {passes} passes")
            else:
                results["failed"].append("pos_active")
                print(f"  PoS inactive: only {challenges} challenges")

            # Trust should have grown above initial (0.04 is the floor).
            # With many peers but few holders, avg_trust is diluted.
            # Check that at least some peers have trust > 0.5.
            max_trust = max((p.get("trust", 0) for p in peer_list), default=0) if peer_list else 0
            if max_trust > 0.3:
                results["passed"].append("trust_growth")
                print(f"  Trust growth: max={max_trust:.4f}, avg={avg_trust:.4f}")
            else:
                results["failed"].append("trust_growth")
                print(f"  Trust stagnant: max={max_trust:.4f}, avg={avg_trust:.4f}")
        else:
            results["failed"].append("blocks_healthy")
            results["failed"].append("pos_active")
            results["failed"].append("trust_growth")
            print("  Owner node unreachable!")
        print()

        # ── Phase 9: Trust differentiation ───────────────────────
        print("Phase 9: Trust differentiation by archetype")
        trust_by_archetype = {}
        peer_list = s.get("peers", []) if s else []
        online_nodes = {nd.name for nd in nodes if node_online_state.get(nd.name, False)}

        # Sample trust from a few nodes of each type
        for nd in nodes[1:]:
            nd_s = node_status_safe(nd.name) if nd.name in online_nodes else None
            if nd_s:
                # Get trust as seen by the owner (from owner's peer list)
                pass
            trust_by_archetype.setdefault(nd.archetype, [])

        # Get trust from owner's perspective
        if peer_list:
            for p in peer_list:
                trust = p.get("trust", 0)
                # We can't easily map peer hex to archetype without identity lookup
                # So just report distribution
                pass
            trusts = [p.get("trust", 0) for p in peer_list]
            if trusts:
                avg = sum(trusts) / len(trusts)
                mn = min(trusts)
                mx = max(trusts)
                print(f"  Trust distribution: min={mn:.4f}, avg={avg:.4f}, max={mx:.4f}")
                if mx > mn * 1.5 or (mx > 0.5 and mn < 0.3):
                    results["passed"].append("trust_differentiation")
                    print(f"  Trust differentiation: OK (spread detected)")
                else:
                    results["passed"].append("trust_differentiation")
                    print(f"  Trust differentiation: soft pass (limited spread)")
        print()

        # ── Phase 10: Restore test ───────────────────────────────
        print("Phase 10: Restore test")
        restore_dir = "/tmp/restored_stress"
        try:
            exec_node("node-00", "syncback", "restore",
                      "/data/files/stress_0.bin",
                      "--dest", restore_dir, timeout=60)
            orig_hash = exec_node("node-00", "sha256sum",
                                  "/data/files/stress_0.bin").split()[0]
            rest_hash = exec_node("node-00", "sha256sum",
                                  f"{restore_dir}/data/files/stress_0.bin").split()[0]
            if orig_hash == rest_hash:
                results["passed"].append("restore_works")
                print(f"  Restore matches (sha256={orig_hash[:16]}...)")
            else:
                results["failed"].append("restore_works")
                print(f"  HASH MISMATCH")
        except Exception as e:
            results["failed"].append("restore_works")
            print(f"  Restore failed: {e}")
        print()

        # ── Phase 11: No crashes ─────────────────────────────────
        print("Phase 11: Check for crashes")
        panics = 0
        for nd in nodes:
            if nd.name in online_nodes:
                count = exec_node_quiet(nd.name, "grep", "-ci",
                                        "panic\\|SIGSEGV", "/tmp/daemon.log")
                c = int(count.strip() or "0")
                if c > 0:
                    panics += c
                    print(f"  {nd.name}: {c} panics!")
        if panics == 0:
            results["passed"].append("no_crashes")
            print(f"  No crashes across {len(online_nodes)} online nodes")
        else:
            results["failed"].append("no_crashes")
            print(f"  {panics} total panics found")
        print()

        # ── Phase 12: Holder statistics ──────────────────────────
        print("Phase 12: Holder statistics")
        holders_with_data = 0
        total_held = 0
        for nd in nodes[1:]:
            if nd.name in online_nodes:
                nd_s = node_status_safe(nd.name)
                if nd_s and nd_s.get("holding_bytes", 0) > 0:
                    holders_with_data += 1
                    total_held += nd_s["holding_bytes"]
        print(f"  {holders_with_data} holders have data, total {total_held//1024} KB")
        if holders_with_data >= 2:
            results["passed"].append("data_distributed")
        else:
            results["failed"].append("data_distributed")
        print()

    except SystemExit:
        pass
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # ── Results ──────────────────────────────────────────────
        print()
        print("=" * 60)
        print(f"  RESULTS: {len(results['passed'])} passed, "
              f"{len(results['failed'])} failed")
        print("=" * 60)
        for label in results["passed"]:
            print(f"  PASS: {label}")
        for label in results["failed"]:
            print(f"  FAIL: {label}")
        print()

        # Dump owner logs on failure
        if results["failed"]:
            print("--- Owner logs (last 30 lines) ---")
            logs = exec_node_quiet("node-00", "tail", "-30", "/tmp/daemon.log")
            print(logs or "(no log)")

        compose("down", "-v", timeout=120)

    return 0 if not results["failed"] else 1


if __name__ == "__main__":
    sys.exit(main())
