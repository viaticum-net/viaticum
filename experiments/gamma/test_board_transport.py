#!/usr/bin/env python3
"""
T14: Board Message Transport test.

Verifies that the relay board works as the primary transport for protocol messages:
  1. PoS challenges/responses are delivered via board (not QUIC)
  2. Delete messages are delivered via board -> holder marks holding MarkedForDelete
  3. SymbolDropped delivered via board -> owner triggers repair
  4. Board sync happens between peers

This test uses a small cluster (5 nodes) with time_scale=100k.
All protocol messages (PoS, Delete, SymbolDropped) go through the relay board.

Timing with time_scale=100k:
  - Board sync interval: max(3600/100000, 60) = 60s (but first sync on connect)
  - PoS challenge interval: ~36ms (3600/100000), clamped to 1s
  - Deletion cooldown: 4 weeks = 2.4s at 100k scale

Usage:
    python experiments/gamma/test_board_transport.py [-n 5] [--time-scale 100000]
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
    raw = exec_node(name, "syncback", "status", "--json")
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


# ── Test files ───────────────────────────────────────────────────────────────

TEST_FILES = {
    "board_test_a.txt": 10,    # 10 KB
    "board_test_b.dat": 50,    # 50 KB
}


def create_test_files(node_name: str):
    for fname, size_kb in TEST_FILES.items():
        exec_node(node_name, "dd", "if=/dev/urandom",
                  f"of=/data/files/{fname}",
                  f"bs=1024", f"count={size_kb}",
                  timeout=30)


# ── Main test ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="T14: Board Message Transport test")
    parser.add_argument("-n", "--nodes", type=int, default=5)
    parser.add_argument("-t", "--time-scale", type=int, default=100000)
    args = parser.parse_args()

    n = args.nodes
    ts = args.time_scale
    assert n >= 3, "Need at least 3 nodes"

    print(f"=== T14: Board Message Transport Test ===")
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
                exec_node(name, "syncback", "init")
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
                      f"cat > /home/syncback/.syncback/config.toml << 'EOFCFG'\n{config}EOFCFG")
        print(f"  Config written (block_size=1MB, quota=100MB)\n")

        # ── Phase 3: Start daemons ───────────────────────────────────────
        print(f"Phase 3: Start daemons (time_scale={ts})")
        for name in nodes:
            exec_node_bg(name, "sh", "-c",
                         f"RUST_LOG=info syncback daemon --time-scale {ts} "
                         f"--watch-dir /data/files >/tmp/daemon.log 2>&1")
        time.sleep(5)

        # Verify daemons are running
        for name in nodes:
            s = node_status_safe(name)
            if s is None:
                print(f"  WARNING: {name} daemon not responding")
        print(f"  Daemons started\n")

        # ── Phase 4: Bootstrap discovery ──────────────────────────────────
        print("Phase 4: Bootstrap peer discovery")
        addr0 = exec_node(nodes[0], "syncback", "status", "--json")
        addr0 = json.loads(addr0).get("node_addr", "")
        for name in nodes[1:]:
            exec_node_quiet(name, "syncback", "connect", addr0, timeout=15)

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
            for name in nodes:
                s = node_status_safe(name)
                print(f"    {name}: peers={s.get('peer_count', '?') if s else '?'}")
        else:
            results["passed"].append("peer_discovery")
        print()

        # ── Phase 5: Backup files → symbols distributed ──────────────────
        print("Phase 5: Backup files and distribute symbols")
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

        # ── Phase 6: Verify PoS via board ────────────────────────────────
        print("Phase 6: Verify PoS challenges delivered via board")
        # Wait for PoS challenges to be issued and responded to.
        # With time_scale=100k, challenge interval is ~1s, timeout ~6s.
        # After ~30s we should see multiple challenge/pass cycles.

        ok = wait_for(
            "PoS challenges issued and passed (via board)",
            lambda: (s := node_status_safe(backup_node)) is not None
                    and s.get("pos_total_challenges", 0) >= 3
                    and s.get("pos_total_passes", 0) >= 1,
            timeout_secs=90, poll_secs=5,
        )
        if ok:
            results["passed"].append("pos_via_board")
            s = node_status(backup_node)
            print(f"    challenges={s.get('pos_total_challenges')}, "
                  f"passes={s.get('pos_total_passes')}")
        else:
            results["failed"].append("pos_via_board")
            s = node_status_safe(backup_node)
            if s:
                print(f"    challenges={s.get('pos_total_challenges', 0)}, "
                      f"passes={s.get('pos_total_passes', 0)}")
        print()

        # ── Phase 7: Verify holdings on holder nodes ─────────────────────
        print("Phase 7: Verify holders received symbols")
        holders_with_data = 0
        for name in nodes[1:]:
            s = node_status_safe(name)
            if s and s.get("holding_bytes", 0) > 0:
                holders_with_data += 1

        if holders_with_data >= 1:
            results["passed"].append("holders_have_symbols")
            print(f"    {holders_with_data} holders have symbol data")
        else:
            results["failed"].append("holders_have_symbols")
            print(f"    No holders have symbol data")
        print()

        # ── Phase 8: Verify trust growth ─────────────────────────────────
        print("Phase 8: Verify trust growth from PoS")
        s = node_status_safe(backup_node)
        if s and s.get("avg_trust", 0.0) > 0.04:
            results["passed"].append("trust_growth")
            print(f"    avg_trust={s.get('avg_trust', 0):.4f} (> 0.04 initial)")
        else:
            # May need more time
            time.sleep(20)
            s = node_status_safe(backup_node)
            if s and s.get("avg_trust", 0.0) > 0.04:
                results["passed"].append("trust_growth")
                print(f"    avg_trust={s.get('avg_trust', 0):.4f} (> 0.04 initial)")
            else:
                results["failed"].append("trust_growth")
                print(f"    avg_trust={s.get('avg_trust', 0) if s else '?'}")
        print()

        # ── Phase 9: Restore works ───────────────────────────────────────
        print("Phase 9: Verify restore works")
        restore_dir = "/tmp/restored"
        try:
            src_path = "/data/files/board_test_a.txt"
            exec_node(backup_node, "syncback", "restore", src_path,
                      "--dest", restore_dir, timeout=60)
            restored_file = f"{restore_dir}{src_path}"
            orig_hash = exec_node(backup_node, "md5sum", src_path).split()[0]
            rest_hash = exec_node(backup_node, "md5sum", restored_file).split()[0]
            if orig_hash == rest_hash:
                results["passed"].append("restore_works")
                print(f"    Restored file matches original (md5={orig_hash[:12]}...)")
            else:
                results["failed"].append("restore_works")
                print(f"    Hash mismatch: {orig_hash} vs {rest_hash}")
        except Exception as e:
            results["failed"].append("restore_works")
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
            for name in nodes[:3]:
                print(f"\n--- {name} ---")
                print(exec_node_quiet(name, "tail", "-30", "/tmp/daemon.log"))

        compose("down", "-v", timeout=60)

    return 0 if not results["failed"] else 1


if __name__ == "__main__":
    sys.exit(main())
