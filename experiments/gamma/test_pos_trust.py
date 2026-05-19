#!/usr/bin/env python3
"""
T3: PoS + Trust growth test.

Verifies that after backup:
  - PoS scheduler issues challenges to holders
  - Holders respond with proof data
  - Trust P and I components grow from initial values
  - Combined trust exceeds 1.0 after sufficient PoS history

Uses T2 as setup (backup must work), then observes trust evolution.

Trust formula: combined = (KP*P + KI*I) * clamp(S, 0.1, 1.0)
  KP=0.4, KI=1.75, initial P=0.1, I=0, S=1.0 → initial combined=0.04
  After perfect PoS: P=1.0, I=1.0 → combined=2.15

Usage:
    python experiments/gamma/test_pos_trust.py [-n 5] [--time-scale 100000]
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


def node_addr(name):
    s = node_status(name)
    return s.get("node_addr", "")


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


# ── Test files (same as T2, smaller set) ─────────────────────────────────────

TEST_FILES = {
    "small_a.txt": 10,    # KB
    "medium.dat":  100,
}


def create_test_files(node_name: str):
    for fname, size_kb in TEST_FILES.items():
        exec_node(node_name, "dd", "if=/dev/urandom",
                  f"of=/data/files/{fname}",
                  f"bs=1024", f"count={size_kb}",
                  timeout=30)


# ── Main test ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="T3: PoS + Trust growth test")
    parser.add_argument("-n", "--nodes", type=int, default=5)
    parser.add_argument("-t", "--time-scale", type=int, default=100000)
    args = parser.parse_args()

    n = args.nodes
    ts = args.time_scale
    assert n >= 3, "Need at least 3 nodes"

    print(f"=== T3: PoS + Trust Growth Test ===")
    print(f"    Nodes: {n}, time_scale: {ts}")
    print(f"    Block size: 1 MB, soft quota: 0.1 GB")
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
    backup_node = nodes[0]
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
        print(f"  Config written (block_size=1MB, quota=100MB)\n")

        # ── Phase 3: Start daemons ───────────────────────────────────────
        print(f"Phase 3: Start daemons (time_scale={ts})")
        for name in nodes:
            exec_node_bg(name, "sh", "-c",
                         f"RUST_LOG=info viaticum daemon --time-scale {ts} "
                         f"--watch-dir /data/files >/tmp/daemon.log 2>&1")
        time.sleep(8)

        ready = 0
        for name in nodes:
            if node_status_safe(name):
                ready += 1
        print(f"  {ready}/{n} daemons ready\n")
        if ready < n:
            print("  ERROR: not all daemons started")
            sys.exit(1)

        # ── Phase 4: Connect mesh ────────────────────────────────────────
        print("Phase 4: Connect nodes")
        addrs = {}
        for name in nodes:
            addrs[name] = node_addr(name)

        connected = set()
        for i in range(n):
            j = (i + 1) % n
            pair = tuple(sorted([nodes[i], nodes[j]]))
            if pair not in connected:
                try:
                    exec_node(nodes[i], "viaticum", "connect", addrs[nodes[j]], timeout=15)
                    connected.add(pair)
                except Exception:
                    pass
                time.sleep(0.3)

        time.sleep(3)

        for name in nodes:
            s = node_status_safe(name)
            peers = s.get("peer_count", 0) if s else 0
            print(f"  {name}: {peers} peers")
        print()

        # ── Phase 5: Create test files & wait for backup ─────────────────
        print(f"Phase 5: Create test files on {backup_node} and wait for backup")
        create_test_files(backup_node)

        def check_backed_up():
            s = node_status_safe(backup_node)
            if not s:
                return False
            backed = s.get("backed_up_files", 0)
            placements = s.get("placement_alive", 0)
            holdings_total = 0
            for name in nodes[1:]:
                hs = node_status_safe(name)
                if hs:
                    holdings_total += hs.get("holding_bytes", 0)
            return backed >= len(TEST_FILES) and placements > 0 and holdings_total > 0

        ok = wait_for("Backup complete", check_backed_up, timeout_secs=180, poll_secs=10)
        if not ok:
            print("  FATAL: backup failed, cannot test PoS")
            results["failed"].append("backup_prerequisite")
            raise RuntimeError("Backup prerequisite failed")
        print()

        # ── Phase 6: Record initial trust state ──────────────────────────
        print("Phase 6: Record initial trust state")
        s = node_status(backup_node)
        initial_pos_total = s.get("pos_total_challenges", 0)
        initial_avg_trust = s.get("avg_trust", 0.0)

        print(f"  Initial pos_total_challenges: {initial_pos_total}")
        print(f"  Initial avg_trust: {initial_avg_trust:.4f}")

        # Print initial per-peer trust
        for peer in s.get("peers", []):
            print(f"  Peer {peer['identity_hex']}: "
                  f"trust={peer['trust']:.4f} "
                  f"P={peer.get('trust_p', 0):.4f} "
                  f"I={peer.get('trust_i', 0):.4f} "
                  f"S={peer.get('trust_s', 0):.4f} "
                  f"pos_recent={peer.get('pos_challenges_recent', 0)}")
        print()

        # ── Phase 7: Wait for PoS challenges to fire ────────────────────
        # With time_scale=100k, scheduler interval = max(3600/100000, 1) = 1s
        # Challenges should fire every second. Wait for several rounds.
        print("Phase 7: Wait for PoS challenges (60s)")
        print("  (scheduler fires every ~1s at time_scale=100k)")

        def check_pos_activity():
            s = node_status_safe(backup_node)
            if not s:
                return False
            total = s.get("pos_total_challenges", 0)
            passes = s.get("pos_total_passes", 0)
            print(f"    pos_total: challenges={total} passes={passes}")
            return total >= 5  # at least 5 challenges fired

        ok = wait_for("PoS challenges firing", check_pos_activity,
                      timeout_secs=120, poll_secs=10)
        if ok:
            results["passed"].append("pos_challenges_issued")
        else:
            results["failed"].append("pos_challenges_issued")
        print()

        # ── Phase 8: Check trust growth ──────────────────────────────────
        print("Phase 8: Check trust growth")
        # Wait a bit more for trust to accumulate
        time.sleep(30)

        s = node_status(backup_node)
        final_pos_total = s.get("pos_total_challenges", 0)
        final_pos_passes = s.get("pos_total_passes", 0)
        final_avg_trust = s.get("avg_trust", 0.0)

        print(f"  Final pos_total_challenges: {final_pos_total}")
        print(f"  Final pos_total_passes: {final_pos_passes}")
        print(f"  Final avg_trust: {final_avg_trust:.4f}")

        # Check 1: Trust P grew from initial (0.1)
        trust_p_grew = False
        trust_above_one = False
        any_pos_passes = final_pos_passes > 0

        for peer in s.get("peers", []):
            p = peer.get("trust_p", 0)
            i = peer.get("trust_i", 0)
            combined = peer.get("trust", 0)
            pos_ch = peer.get("pos_challenges_recent", 0)
            pos_pa = peer.get("pos_passes_recent", 0)
            print(f"  Peer {peer['identity_hex']}: "
                  f"trust={combined:.4f} "
                  f"P={p:.4f} I={i:.4f} S={peer.get('trust_s', 0):.4f} "
                  f"pos_recent: {pos_ch} challenged, {pos_pa} passed")

            # P should have grown beyond initial 0.1
            if p > 0.15:
                trust_p_grew = True
            # Combined trust should exceed 1.0 with perfect PoS
            # (0.4*1.0 + 1.75*1.0) * 1.0 = 2.15
            if combined > 1.0:
                trust_above_one = True

        print()

        # Check 2: PoS passes happened
        if any_pos_passes:
            print(f"  PoS passes occurred ({final_pos_passes}): OK")
            results["passed"].append("pos_passes_recorded")
        else:
            print(f"  No PoS passes recorded: FAIL")
            results["failed"].append("pos_passes_recorded")

        # Check 3: Trust P component grew
        if trust_p_grew:
            print(f"  Trust P grew beyond initial 0.1: OK")
            results["passed"].append("trust_p_growth")
        else:
            print(f"  Trust P did not grow: FAIL")
            results["failed"].append("trust_p_growth")

        # Check 4: Combined trust exceeds 1.0
        if trust_above_one:
            print(f"  Combined trust > 1.0 achieved: OK")
            results["passed"].append("trust_above_one")
        else:
            print(f"  Combined trust never exceeded 1.0: FAIL")
            results["failed"].append("trust_above_one")

        # Check 5: Pass rate is reasonable (> 50%)
        if final_pos_total > 0:
            pass_rate = final_pos_passes / final_pos_total
            if pass_rate > 0.5:
                print(f"  Pass rate {pass_rate:.1%}: OK")
                results["passed"].append("pass_rate_reasonable")
            else:
                print(f"  Pass rate {pass_rate:.1%} too low: FAIL")
                results["failed"].append("pass_rate_reasonable")
        else:
            results["failed"].append("pass_rate_reasonable")

        print()

        # ── Phase 9: Verify challenge count adapts to trust ──────────────
        print("Phase 9: Challenge frequency analysis")
        # With low trust, challenges_per_week should be higher
        # With trust approaching 1.0, trust_factor = 2.0 - 1.0 = 1.0
        # With initial trust ~0.04, trust_factor = 2.0 - 0.04 ≈ 2.0
        # So initially challenges should be ~2x compared to high-trust state
        # We can't directly measure frequency change, but we verify challenges happened
        print(f"  Total challenges issued: {final_pos_total}")
        print(f"  Total passes: {final_pos_passes}")
        if final_pos_total > 0:
            print(f"  Overall pass rate: {final_pos_passes/final_pos_total:.1%}")
        print()

        # ── Final Report ─────────────────────────────────────────────────
        print("=" * 60)
        print("RESULTS")
        print("=" * 60)
        for test in results["passed"]:
            print(f"  PASS  {test}")
        for test in results["failed"]:
            print(f"  FAIL  {test}")

        total = len(results["passed"]) + len(results["failed"])
        passed = len(results["passed"])
        print(f"\n  {passed}/{total} tests passed")

        if results["failed"]:
            print("\n  SOME TESTS FAILED")
            print("\n--- Daemon logs (backup node, last 50 lines) ---")
            logs = exec_node_quiet(backup_node, "tail", "-50", "/tmp/daemon.log")
            print(logs)
            # Also show one holder's logs
            print(f"\n--- Daemon logs ({nodes[1]}, last 30 lines) ---")
            logs = exec_node_quiet(nodes[1], "tail", "-30", "/tmp/daemon.log")
            print(logs)
            sys.exit(1)
        else:
            print("\n  ALL TESTS PASSED")

    except Exception as e:
        print(f"\nFATAL ERROR: {e}")
        print(f"\n--- Daemon logs ({backup_node}, last 30 lines) ---")
        logs = exec_node_quiet(backup_node, "tail", "-30", "/tmp/daemon.log")
        print(logs)
        raise

    finally:
        print(f"\nContainers still running. To stop: docker compose -f {COMPOSE_FILE} down -v")


if __name__ == "__main__":
    main()
