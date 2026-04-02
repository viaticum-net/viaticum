#!/usr/bin/env python3
"""
T2: Backup + Restore test.

Verifies the full data path: file creation → watcher → packing → encrypt →
erasure encode → placement → symbol transfer → restore → bytewise compare.

Uses small block size (1 MB) and tight quotas for fast iteration.

Usage:
    python experiments/gamma/test_backup_restore.py [-n 5] [--time-scale 100000]
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


# ── Helpers ──────────────────────────────────────────────────────────────────

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
    raw = exec_node(name, "syncback", "status", "--json")
    return json.loads(raw)


def node_status_safe(name):
    try:
        return node_status(name)
    except Exception:
        return None


def node_addr(name):
    s = node_status(name)
    return s.get("node_addr", "")


def node_files(name):
    """Get list of backed-up files via CLI."""
    raw = exec_node(name, "syncback", "files")
    return raw


def wait_for(desc, predicate, timeout_secs=120, poll_secs=5):
    """Poll predicate() until it returns True or timeout."""
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
    "small_a.txt": 10,    # KB
    "small_b.txt": 10,
    "medium.dat":  100,
    "large.bin":   500,
}


def create_test_files(node_name: str):
    """Create test files on a node using /dev/urandom."""
    for fname, size_kb in TEST_FILES.items():
        exec_node(node_name, "dd", "if=/dev/urandom",
                  f"of=/data/files/{fname}",
                  f"bs=1024", f"count={size_kb}",
                  timeout=30)


def get_file_hash_on_node(node_name: str, path: str) -> str:
    """Get SHA-256 hash of a file on a node."""
    return exec_node(node_name, "sha256sum", path).split()[0]


# ── Main test ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="T2: Backup + Restore test")
    parser.add_argument("-n", "--nodes", type=int, default=5)
    parser.add_argument("-t", "--time-scale", type=int, default=100000)
    args = parser.parse_args()

    n = args.nodes
    ts = args.time_scale
    assert n >= 3, "Need at least 3 nodes"

    print(f"=== T2: Backup + Restore Test ===")
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
    backup_node = nodes[0]  # node-00 creates files and backs them up
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
            config = f"""[backup]
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

        # Ring + each node connects to node-00
        connected = set()
        for i in range(n):
            j = (i + 1) % n
            pair = tuple(sorted([nodes[i], nodes[j]]))
            if pair not in connected:
                try:
                    exec_node(nodes[i], "syncback", "connect", addrs[nodes[j]], timeout=15)
                    connected.add(pair)
                except Exception:
                    pass
                time.sleep(0.3)

        time.sleep(3)

        # Verify connections
        for name in nodes:
            s = node_status_safe(name)
            peers = s.get("peer_count", 0) if s else 0
            print(f"  {name}: {peers} peers")
        print()

        # ── Phase 5: Create test files on backup node ────────────────────
        print(f"Phase 5: Create test files on {backup_node}")
        create_test_files(backup_node)

        # Record original hashes
        original_hashes = {}
        for fname, size_kb in TEST_FILES.items():
            h = get_file_hash_on_node(backup_node, f"/data/files/{fname}")
            original_hashes[fname] = h
            print(f"  {fname}: {size_kb} KB, sha256={h[:16]}...")
        print()

        # ── Phase 6: Wait for backup ─────────────────────────────────────
        print("Phase 6: Wait for backup pipeline")
        expected_files = len(TEST_FILES)

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
            print(f"    files={backed}/{expected_files} "
                  f"placements_alive={placements} "
                  f"holder_bytes={holdings_total}")
            return backed >= expected_files and placements > 0 and holdings_total > 0

        ok = wait_for("Backup complete", check_backed_up, timeout_secs=180, poll_secs=10)
        if ok:
            results["passed"].append("backup_files_registered")
        else:
            results["failed"].append("backup_files_registered")
        print()

        # ── Phase 7: Check placement distribution ────────────────────────
        print("Phase 7: Check placement distribution")
        s = node_status(backup_node)
        placement_alive = s.get("placement_alive", 0)
        placement_count = s.get("placement_count", 0)
        backed_up_files = s.get("backed_up_files", 0)

        print(f"  Backed up files: {backed_up_files}")
        print(f"  Placements: {placement_alive} alive / {placement_count} total")

        # Check holders actually received symbols
        holders_with_data = 0
        for name in nodes[1:]:
            hs = node_status_safe(name)
            if hs and hs.get("holding_bytes", 0) > 0:
                holders_with_data += 1
                print(f"  {name}: holding {hs['holding_bytes']} bytes")

        if holders_with_data >= 2:
            print(f"  Symbols distributed to {holders_with_data} holders: OK")
            results["passed"].append("placement_distributed")
        else:
            print(f"  Only {holders_with_data} holders have data: FAIL")
            results["failed"].append("placement_distributed")
        print()

        # ── Phase 8: Early restore — escrow should DENY ──────────────────
        print("Phase 8: Early restore (escrow should deny)")

        # Symbols are cleaned up after delivery, so restore goes to holders.
        # Escrow budget hasn't accrued yet → expect denial.
        early_restore_dir = "/tmp/restored_early"
        exec_node(backup_node, "mkdir", "-p", early_restore_dir)
        first_file = list(TEST_FILES.keys())[0]
        src_path = f"/data/files/{first_file}"
        restored_file = f"{early_restore_dir}/{src_path.lstrip('/')}"

        try:
            exec_node(backup_node, "syncback", "restore", src_path,
                      "--dest", early_restore_dir, timeout=30)
        except Exception:
            pass
        time.sleep(3)  # let async restore attempt complete

        early_exists = False
        try:
            exec_node(backup_node, "test", "-f", restored_file)
            early_exists = True
        except Exception:
            pass

        if not early_exists:
            print(f"  Early restore of {first_file}: DENIED (correct)")
            results["passed"].append("escrow_denies_early_restore")
        else:
            print(f"  Early restore of {first_file}: SUCCEEDED (escrow not enforced)")
            results["failed"].append("escrow_denies_early_restore")
        print()

        # ── Phase 9: Wait for escrow budget to accrue ────────────────────
        # Budget = stored_gb_days / k_factor. At time_scale=100000 with ~786KB stored,
        # ~10s real time ≈ 11.6 simulated days → budget ≈ 0.0013 GB >> file size.
        wait_secs = 15
        print(f"Phase 9: Wait {wait_secs}s for escrow budget to accrue")
        time.sleep(wait_secs)
        print()

        # ── Phase 10: Restore after escrow budget accrued ────────────────
        print("Phase 10: Restore files (escrow should allow)")
        restore_ok = 0
        restore_fail = 0

        restore_dir = "/tmp/restored"
        exec_node(backup_node, "mkdir", "-p", restore_dir)

        for fname in TEST_FILES:
            src_path = f"/data/files/{fname}"
            restored_file = f"{restore_dir}/{src_path.lstrip('/')}"
            try:
                out = exec_node(backup_node, "syncback", "restore", src_path,
                                "--dest", restore_dir, timeout=60)
                print(f"  restore {fname}: {out}")

                # Wait for async restore to write the file
                for _ in range(10):
                    try:
                        exec_node(backup_node, "test", "-f", restored_file)
                        break
                    except Exception:
                        time.sleep(1)

                # Compare hash
                restored_hash = get_file_hash_on_node(backup_node, restored_file)
                if restored_hash == original_hashes[fname]:
                    print(f"    hash match: OK")
                    restore_ok += 1
                else:
                    print(f"    HASH MISMATCH: original={original_hashes[fname][:16]}... "
                          f"restored={restored_hash[:16]}...")
                    restore_fail += 1
            except Exception as e:
                print(f"  restore {fname}: FAILED — {e}")
                restore_fail += 1

        if restore_ok == len(TEST_FILES) and restore_fail == 0:
            print(f"\n  All {restore_ok} files restored correctly: OK")
            results["passed"].append("restore_bytewise_match")
        else:
            print(f"\n  Restore: {restore_ok} ok, {restore_fail} failed")
            results["failed"].append("restore_bytewise_match")
        print()

        # ── Phase 11: Health check ────────────────────────────────────
        print("Phase 11: Block health check")
        s = node_status(backup_node)
        at_risk = s.get("blocks_at_risk", 0)
        if at_risk == 0:
            results["passed"].append("blocks_not_at_risk")
            print(f"    blocks_at_risk=0: OK")
        else:
            results["failed"].append("blocks_not_at_risk")
            print(f"    blocks_at_risk={at_risk}: FAIL")
        print()

        # ── Phase 12: Negative restore (nonexistent file) ────────────
        print("Phase 12: Negative test — restore nonexistent file")
        try:
            out = exec_node(backup_node, "syncback", "restore",
                            "/data/files/does_not_exist.txt",
                            "--dest", "/tmp/neg_restore", timeout=30)
            # CLI may return 0 even for unknown files (known issue).
            # Check that no actual file was produced.
            check = exec_node_quiet(backup_node, "ls",
                                    "/tmp/neg_restore/data/files/does_not_exist.txt")
            if not check:
                results["passed"].append("negative_restore_no_output")
                print(f"    Restore produced no output file (correct)")
            else:
                results["failed"].append("negative_restore_no_output")
                print(f"    Restore produced a file for nonexistent path (bug)")
        except RuntimeError:
            results["passed"].append("negative_restore_no_output")
            print(f"    Restore correctly rejected nonexistent file")
        print()

        # ── Phase 13: Check status consistency ───────────────────────
        print("Phase 13: Status consistency checks")

        # Owner should have blocks_ok > 0
        s = node_status(backup_node)
        blocks_ok = s.get("blocks_ok", 0)
        blocks_at_risk = s.get("blocks_at_risk", 0)
        if blocks_ok > 0:
            print(f"  blocks_ok={blocks_ok}, blocks_at_risk={blocks_at_risk}: OK")
            results["passed"].append("blocks_healthy")
        else:
            print(f"  blocks_ok={blocks_ok}: no healthy blocks!")
            results["failed"].append("blocks_healthy")

        # Check effective_quota is set
        for name in nodes:
            hs = node_status_safe(name)
            if hs:
                eq = hs.get("effective_quota_bytes", 0)
                used = hs.get("used_bytes", 0)
                if eq > 0:
                    print(f"  {name}: quota={eq // 1024 // 1024}MB used={used // 1024}KB")

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
            # Dump logs from backup node for debugging
            print("\n--- Daemon logs (backup node, last 50 lines) ---")
            logs = exec_node_quiet(backup_node, "tail", "-50", "/tmp/daemon.log")
            print(logs)
            sys.exit(1)
        else:
            print("\n  ALL TESTS PASSED")

    except Exception as e:
        print(f"\nFATAL ERROR: {e}")
        # Dump logs
        print(f"\n--- Daemon logs ({backup_node}, last 30 lines) ---")
        logs = exec_node_quiet(backup_node, "tail", "-30", "/tmp/daemon.log")
        print(logs)
        raise

    finally:
        print(f"\nContainers still running. To stop: docker compose -f {COMPOSE_FILE} down -v")


if __name__ == "__main__":
    main()
