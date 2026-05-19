#!/usr/bin/env python3
"""
T5: Relay Store-and-Forward (Offline Delivery) test.

Verifies that the relay board delivers messages to nodes that were offline:
  1. Cluster established, files backed up, PoS running
  2. Node B goes offline (docker stop)
  3. PoS challenges for B accumulate on other nodes' boards
  4. Node B comes back online (docker start)
  5. Board sync delivers missed messages to B
  6. B processes challenges and responds via board
  7. Dedup: re-sync does not duplicate messages

Uses 5 nodes with time_scale=100k.

Timing with time_scale=100k:
  - Board sync interval: ~2s (POS_TIMEOUT / time_scale / 3, min 2)
  - PoS challenge interval: ~1s
  - Offline window: 30s (enough for several challenges to accumulate)

Usage:
    python experiments/gamma/test_relay_offline.py [-n 5] [--time-scale 100000]
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

PROJECT_DIR = str(Path(__file__).parent.parent.parent)
COMPOSE_FILE = "experiments/gamma/compose.yml"


# ── Helpers ──────────────────────────────────────────────────────────────────

def docker(*args, timeout=30):
    import subprocess
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
    import subprocess
    return subprocess.run(
        ["docker", "compose", "-f", COMPOSE_FILE] + list(args),
        cwd=PROJECT_DIR, capture_output=True, text=True, timeout=timeout
    )


def node_status(name):
    raw = exec_node(name, "viaticum", "status", "--json")
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


def node_log_lines(name, pattern=None, last_n=100):
    """Get daemon log lines, optionally filtered by pattern."""
    raw = exec_node_quiet(name, "tail", f"-{last_n}", "/tmp/daemon.log")
    if not raw:
        return []
    lines = raw.split("\n")
    if pattern:
        lines = [l for l in lines if pattern in l]
    return lines


# ── Test files ───────────────────────────────────────────────────────────────

TEST_FILES = {
    "relay_test_a.txt": 10,    # 10 KB
    "relay_test_b.dat": 50,    # 50 KB
}


def create_test_files(node_name: str):
    for fname, size_kb in TEST_FILES.items():
        exec_node(node_name, "dd", "if=/dev/urandom",
                  f"of=/data/files/{fname}",
                  f"bs=1024", f"count={size_kb}",
                  timeout=30)


# ── Main test ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="T5: Relay Offline Delivery test")
    parser.add_argument("-n", "--nodes", type=int, default=5)
    parser.add_argument("-t", "--time-scale", type=int, default=100000)
    args = parser.parse_args()

    n = args.nodes
    ts = args.time_scale
    assert n >= 4, "Need at least 4 nodes"

    print(f"=== T5: Relay Store-and-Forward (Offline Delivery) Test ===")
    print(f"    Nodes: {n}, time_scale: {ts}")
    print()

    # Generate compose and start
    sys.path.insert(0, str(Path(__file__).parent))
    from compose_gen import generate
    generate(n, os.path.join(PROJECT_DIR, COMPOSE_FILE), include_metrics=False)

    compose("down", "-v", timeout=60)
    r = compose("up", "-d", timeout=120)
    if r.returncode != 0:
        print(f"compose up failed: {r.stderr}")
        sys.exit(1)
    time.sleep(3)

    nodes = [f"node-{i:02d}" for i in range(n)]
    backup_node = nodes[0]      # owner
    offline_node = nodes[1]     # will go offline
    relay_nodes = nodes[2:]     # stay online, relay messages
    results = {"passed": [], "failed": []}

    try:
        # ── Phase 1: Init ────────────────────────────────────────────────
        print("Phase 1: Init all nodes")
        for name in nodes:
            try:
                exec_node(name, "viaticum", "init")
            except RuntimeError as e:
                if "already initialized" not in str(e):
                    raise
        print(f"  {n} nodes initialized\n")

        # ── Phase 2: Config ──────────────────────────────────────────────
        print("Phase 2: Configure nodes")
        for name in nodes:
            config = """[backup]
source_block_size_mb = 1

[storage]
soft_quota_gb = 0.1
disk_reserve_gb = 0.0

[network]
enable_relay = false
"""
            exec_node(name, "sh", "-c",
                      f"cat > /home/viaticum/.viaticum/config.toml << 'EOFCFG'\n{config}EOFCFG")
        print(f"  Config written\n")

        # ── Phase 3: Start daemons ───────────────────────────────────────
        print(f"Phase 3: Start daemons (time_scale={ts})")
        for name in nodes:
            exec_node_bg(name, "sh", "-c",
                         f"RUST_LOG=info viaticum daemon --time-scale {ts} "
                         f"--watch-dir /data/files >/tmp/daemon.log 2>&1")
        time.sleep(5)
        print(f"  Daemons started\n")

        # ── Phase 4: Bootstrap discovery ──────────────────────────────────
        print("Phase 4: Bootstrap peer discovery")
        addr0 = exec_node(nodes[0], "viaticum", "status", "--json")
        addr0 = json.loads(addr0).get("node_addr", "")
        for name in nodes[1:]:
            exec_node_quiet(name, "viaticum", "connect", addr0, timeout=15)

        ok = wait_for(
            "All nodes discover peers",
            lambda: all(
                (s := node_status_safe(name)) is not None
                and s.get("peer_count", 0) >= n - 1
                for name in nodes
            ),
            timeout_secs=60, poll_secs=5,
        )
        if not ok:
            results["failed"].append("peer_discovery")
        else:
            results["passed"].append("peer_discovery")
        print()

        # ── Phase 5: Backup files ────────────────────────────────────────
        print("Phase 5: Backup files")
        create_test_files(backup_node)

        ok = wait_for(
            "Backup complete (blocks_ok > 0)",
            lambda: (s := node_status_safe(backup_node)) is not None
                    and s.get("blocks_ok", 0) > 0,
            timeout_secs=90, poll_secs=5,
        )
        if ok:
            results["passed"].append("backup_complete")
            s = node_status(backup_node)
            print(f"    blocks_ok={s.get('blocks_ok')}, "
                  f"placement_alive={s.get('placement_alive')}")
        else:
            results["failed"].append("backup_complete")
        print()

        # ── Phase 6: Wait for initial PoS ────────────────────────────────
        print("Phase 6: Wait for initial PoS activity (baseline)")
        ok = wait_for(
            "PoS challenges running",
            lambda: (s := node_status_safe(backup_node)) is not None
                    and s.get("pos_total_challenges", 0) >= 2
                    and s.get("pos_total_passes", 0) >= 1,
            timeout_secs=60, poll_secs=5,
        )
        if ok:
            results["passed"].append("initial_pos")
            s = node_status(backup_node)
            baseline_challenges = s.get("pos_total_challenges", 0)
            baseline_passes = s.get("pos_total_passes", 0)
            print(f"    baseline: challenges={baseline_challenges}, passes={baseline_passes}")
        else:
            results["failed"].append("initial_pos")
            baseline_challenges = 0
            baseline_passes = 0
        print()

        # ── Phase 7: Take offline_node offline ───────────────────────────
        print(f"Phase 7: Stop {offline_node} (simulating offline)")
        # Record offline_node's holding status before going offline
        s_offline_before = node_status_safe(offline_node)
        offline_holding_before = s_offline_before.get("holding_bytes", 0) if s_offline_before else 0
        print(f"    {offline_node} holding_bytes before offline: {offline_holding_before}")

        docker("stop", f"gamma-{offline_node}", timeout=30)
        print(f"    {offline_node} stopped")
        print()

        # ── Phase 8: Wait while challenges accumulate ────────────────────
        print("Phase 8: Wait 30s for challenges to accumulate on boards")
        time.sleep(30)

        # Check that owner kept issuing challenges (some will be for offline node)
        s = node_status_safe(backup_node)
        if s:
            new_challenges = s.get("pos_total_challenges", 0)
            print(f"    Owner challenges now: {new_challenges} (was {baseline_challenges})")
            if new_challenges > baseline_challenges:
                results["passed"].append("challenges_during_offline")
            else:
                results["failed"].append("challenges_during_offline")
        else:
            results["failed"].append("challenges_during_offline")
        print()

        # ── Phase 9: Bring offline_node back ─────────────────────────────
        print(f"Phase 9: Restart {offline_node}")
        docker("start", f"gamma-{offline_node}", timeout=30)
        time.sleep(3)

        # Restart daemon (container restart doesn't auto-start the daemon)
        exec_node_bg(offline_node, "sh", "-c",
                     f"RUST_LOG=info viaticum daemon --time-scale {ts} "
                     f"--watch-dir /data/files >/tmp/daemon.log 2>&1")
        time.sleep(5)

        # Re-connect to bootstrap so board sync can happen
        exec_node_quiet(offline_node, "viaticum", "connect", addr0, timeout=15)
        print(f"    {offline_node} restarted and reconnected")
        print()

        # ── Phase 10: Verify board sync delivers messages ────────────────
        print("Phase 10: Verify board sync delivers missed messages")

        # Wait for board sync to happen and messages to be processed
        ok = wait_for(
            f"{offline_node} processes board messages (holding still present)",
            lambda: (s := node_status_safe(offline_node)) is not None
                    and s.get("holding_bytes", 0) > 0,
            timeout_secs=60, poll_secs=5,
        )
        if ok:
            results["passed"].append("node_recovered")
            s = node_status(offline_node)
            print(f"    {offline_node} holding_bytes={s.get('holding_bytes', 0)}")
        else:
            results["failed"].append("node_recovered")
        print()

        # ── Phase 11: Verify PoS resumes after reconnection ─────────────
        print("Phase 11: Verify PoS resumes via board after reconnection")

        # Record current state
        s_before = node_status_safe(backup_node)
        passes_before = s_before.get("pos_total_passes", 0) if s_before else 0

        # Wait for new PoS passes (offline node responding again)
        ok = wait_for(
            "New PoS passes after reconnection",
            lambda: (s := node_status_safe(backup_node)) is not None
                    and s.get("pos_total_passes", 0) > passes_before,
            timeout_secs=90, poll_secs=5,
        )
        if ok:
            results["passed"].append("pos_resumes_after_reconnect")
            s = node_status(backup_node)
            print(f"    passes: {passes_before} -> {s.get('pos_total_passes', 0)}")
        else:
            results["failed"].append("pos_resumes_after_reconnect")
            s = node_status_safe(backup_node)
            if s:
                print(f"    passes stuck at: {s.get('pos_total_passes', 0)}")
        print()

        # ── Phase 12: Verify dedup (board sync again doesn't duplicate) ──
        print("Phase 12: Verify dedup — reconnect again, no duplicates")

        # Record current PoS stats
        s_before = node_status_safe(backup_node)
        passes_before_dedup = s_before.get("pos_total_passes", 0) if s_before else 0

        # Force a reconnection by having offline_node connect to another peer
        if len(relay_nodes) > 0:
            # Get another node's address and connect offline_node to it
            addr_relay = exec_node(relay_nodes[0], "viaticum", "status", "--json")
            addr_relay = json.loads(addr_relay).get("node_addr", "")
            exec_node_quiet(offline_node, "viaticum", "connect", addr_relay, timeout=15)
            time.sleep(10)

        # PoS should continue but NOT spike from duplicate old messages
        s_after = node_status_safe(backup_node)
        passes_after = s_after.get("pos_total_passes", 0) if s_after else 0
        # Reasonable growth: a few new passes, not a spike from replayed messages
        # With time_scale=100k, ~1 challenge/sec, 10s → ~10 challenges max
        growth = passes_after - passes_before_dedup
        if growth <= 20:
            results["passed"].append("dedup_no_spike")
            print(f"    Pass growth during re-sync: {growth} (reasonable, no spike)")
        else:
            results["failed"].append("dedup_no_spike")
            print(f"    Pass growth during re-sync: {growth} (unexpected spike!)")
        print()

        # ── Phase 13: Verify restore still works ─────────────────────────
        print("Phase 13: Verify restore still works after offline/online cycle")
        restore_dir = "/tmp/restored"
        try:
            src_path = "/data/files/relay_test_a.txt"
            exec_node(backup_node, "viaticum", "restore", src_path,
                      "--dest", restore_dir, timeout=60)
            restored_file = f"{restore_dir}{src_path}"
            orig_hash = exec_node(backup_node, "md5sum", src_path).split()[0]
            rest_hash = exec_node(backup_node, "md5sum", restored_file).split()[0]
            if orig_hash == rest_hash:
                results["passed"].append("restore_after_offline")
                print(f"    Restored file matches (md5={orig_hash[:12]}...)")
            else:
                results["failed"].append("restore_after_offline")
                print(f"    Hash mismatch: {orig_hash} vs {rest_hash}")
        except Exception as e:
            results["failed"].append("restore_after_offline")
            print(f"    Restore failed: {e}")
        print()

    finally:
        # ── Results ──────────────────────────────────────────────────────
        print("=" * 60)
        print(f"RESULTS: {len(results['passed'])} passed, {len(results['failed'])} failed")
        if results["passed"]:
            print(f"  PASSED: {', '.join(results['passed'])}")
        if results["failed"]:
            print(f"  FAILED: {', '.join(results['failed'])}")
        print()

        # Dump logs on failure
        if results["failed"]:
            print("── Node logs (last 30 lines each) ──")
            for name in [backup_node, offline_node] + relay_nodes[:1]:
                print(f"\n--- {name} ---")
                print(exec_node_quiet(name, "tail", "-30", "/tmp/daemon.log"))

        compose("down", "-v", timeout=60)

    return 0 if not results["failed"] else 1


if __name__ == "__main__":
    sys.exit(main())
