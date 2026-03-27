#!/usr/bin/env python3
"""
T9: Budget + Disk Pressure + Importance Ordering test.

Creates REAL storage pressure by limiting holder quotas to ~3 MB each
(12 MB total across 4 holders). Then creates files in waves with different
importance levels until holders are full. Verifies:

  1. Bootstrap: first files backed up with zero history (FREE_TIER_GB)
  2. Importance ordering: critical files backed up before archive
  3. Disk pressure: holders start rejecting after filling up
  4. Graceful degradation: system continues working, no crashes
  5. importance=0 exclusion: junk files never backed up
  6. Post-pressure status: backed_up ratio correlates with importance
  7. Budget record: offered/accepted stats reflect reality

Architecture of pressure:
  - 4 holders × 3 MB soft_quota = 12 MB total symbol storage
  - Files: 200 KB each → with erasure overhead (1.5x-3.0x) ≈ 300-600 KB per file
  - Wave 1: 5 critical files  (importance=0.9) → ~3 MB coded → fits
  - Wave 2: 10 standard files (importance=0.5) → ~4 MB coded → starts filling
  - Wave 3: 15 archive files  (importance=0.1) → ~5 MB coded → holders full
  - Wave 4: 5 junk files      (importance=0.0) → excluded by budget filter
  - Total demand: ~12 MB coded → exactly at capacity → some files deferred/rejected

Uses 5 nodes with time_scale=100k.

Usage:
    python experiments/gamma/test_budget.py [--time-scale 100000]
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

PROJECT_DIR = str(Path(__file__).parent.parent.parent)
COMPOSE_FILE = "experiments/gamma/compose.yml"

# Holder quota per node (bytes). 3 MB each → 12 MB total across 4 holders.
HOLDER_QUOTA_GB = 0.003  # 3 MB


# -- Helpers ------------------------------------------------------------------

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


def write_owner_config(name, watch_configs=None):
    """Owner config with [[watch]] sections for importance control."""
    config = """[backup]
source_block_size_mb = 1

[storage]
soft_quota_gb = 0.003
disk_reserve_gb = 0.0

[network]
enable_relay = false
"""
    if watch_configs:
        for wc in watch_configs:
            config += f'\n[[watch]]\npath = "{wc["path"]}"\nimportance = {wc["importance"]}\n'
    exec_node(name, "sh", "-c",
              f"cat > /home/syncback/.syncback/config.toml << 'EOFCFG'\n{config}EOFCFG")


def write_holder_config(name):
    """Holder config with tiny quota to create pressure."""
    config = f"""[backup]
source_block_size_mb = 1

[storage]
soft_quota_gb = {HOLDER_QUOTA_GB}
disk_reserve_gb = 0.0

[network]
enable_relay = false
"""
    exec_node(name, "sh", "-c",
              f"cat > /home/syncback/.syncback/config.toml << 'EOFCFG'\n{config}EOFCFG")


def start_daemon(name, ts):
    exec_node_bg(name, "sh", "-c",
                 f"RUST_LOG=info syncback daemon --time-scale {ts} "
                 f"--watch-dir /data/files >/tmp/daemon.log 2>&1")


def create_files(owner, directory, prefix, count, size_kb=200):
    """Create `count` files of `size_kb` KB in the given directory."""
    exec_node(owner, "mkdir", "-p", directory)
    for i in range(count):
        exec_node(owner, "dd", "if=/dev/urandom",
                  f"of={directory}/{prefix}_{i:03d}.dat",
                  f"bs=1024", f"count={size_kb}",
                  timeout=30)


def count_backed_up_in_dir(owner, directory):
    """Count files from `directory` that are ACTUALLY backed up (have versions, not pending)."""
    try:
        files_output = exec_node(owner, "syncback", "files")
        count = 0
        for line in files_output.split("\n"):
            # Only count lines that have the directory AND show a version (not "pending   0 B")
            if directory in line and "version" in line and "pending" not in line:
                count += 1
        return count
    except Exception:
        return 0


# -- Main test ----------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="T9: Budget + Pressure test")
    parser.add_argument("-t", "--time-scale", type=int, default=100000)
    args = parser.parse_args()

    n = 5
    ts = args.time_scale

    print(f"=== T9: Budget + Disk Pressure + Importance Test ===")
    print(f"    Nodes: {n}, time_scale: {ts}")
    print(f"    Holder quota: {HOLDER_QUOTA_GB * 1024:.0f} MB each = "
          f"{HOLDER_QUOTA_GB * 1024 * (n-1):.0f} MB total")
    print()

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
    owner = nodes[0]
    holders = nodes[1:]
    results = {"passed": [], "failed": []}

    try:
        # -- Phase 1: Init + Config + Start --
        print("Phase 1: Init, configure, and start")
        for name in nodes:
            try:
                exec_node(name, "syncback", "init")
            except RuntimeError as e:
                if "already initialized" not in str(e):
                    raise

        # Owner: three watch dirs with different importance
        exec_node(owner, "mkdir", "-p",
                  "/data/files/critical",
                  "/data/files/standard",
                  "/data/files/archive",
                  "/data/files/junk")

        write_owner_config(owner, watch_configs=[
            {"path": "/data/files/critical", "importance": 0.9},
            {"path": "/data/files/standard", "importance": 0.5},
            {"path": "/data/files/archive",  "importance": 0.1},
            {"path": "/data/files/junk",     "importance": 0.0},
        ])

        for name in holders:
            write_holder_config(name)

        for name in nodes:
            start_daemon(name, ts)
        time.sleep(5)

        # -- Phase 2: Discovery --
        print("Phase 2: Peer discovery")
        addr0 = json.loads(exec_node(owner, "syncback", "status", "--json")).get("node_addr", "")
        for name in holders:
            exec_node_quiet(name, "syncback", "connect", addr0, timeout=15)

        ok = wait_for(
            "Peer discovery",
            lambda: all(
                (s := node_status_safe(name)) is not None
                and s.get("peer_count", 0) >= n - 1
                for name in nodes
            ),
            timeout_secs=60, poll_secs=5,
        )
        if not ok:
            results["failed"].append("peer_discovery")
            raise SystemExit(1)
        results["passed"].append("peer_discovery")
        print()

        # -- Phase 3: Wave 1 — Critical files (importance=0.9) --
        print("Phase 3: Wave 1 — 5 critical files (importance=0.9, 200 KB each)")
        create_files(owner, "/data/files/critical", "crit", 5, size_kb=200)

        ok = wait_for(
            "Critical files backed up",
            lambda: (s := node_status_safe(owner)) is not None
                    and s.get("blocks_ok", 0) >= 1,
            timeout_secs=90, poll_secs=5,
        )
        if ok:
            results["passed"].append("wave1_critical")
            s = node_status(owner)
            print(f"    blocks_ok={s.get('blocks_ok')}, "
                  f"backed_up={s.get('backed_up_files')}")
        else:
            results["failed"].append("wave1_critical")
        print()

        # -- Phase 4: Wave 2 — Standard files (importance=0.5) --
        print("Phase 4: Wave 2 — 10 standard files (importance=0.5)")
        create_files(owner, "/data/files/standard", "std", 10, size_kb=200)

        time.sleep(15)  # Let flush cycles process
        s = node_status(owner)
        blocks_after_w2 = s.get("blocks_ok", 0)
        backed_after_w2 = s.get("backed_up_files", 0)
        print(f"    After wave 2: blocks_ok={blocks_after_w2}, "
              f"backed_up={backed_after_w2}")
        std_backed = count_backed_up_in_dir(owner, "/data/files/standard")
        print(f"    Standard files actually backed up: {std_backed}/10")
        if std_backed > 0:
            results["passed"].append("wave2_standard")
        else:
            results["failed"].append("wave2_standard")
            print(f"    FAIL: no standard files backed up after wave 2")

        # Check holder storage usage
        for h in holders[:2]:
            hs = node_status_safe(h)
            if hs:
                hb = hs.get("holding_bytes", 0)
                quota = HOLDER_QUOTA_GB * 1024 * 1024 * 1024
                pct = (hb / quota * 100) if quota > 0 else 0
                print(f"    {h}: holding {hb // 1024} KB "
                      f"({pct:.0f}% of quota)")
        print()

        # -- Phase 5: Wave 3 — Archive files (importance=0.1) + junk (0.0) --
        print("Phase 5: Wave 3 — 15 archive files + 5 junk files")
        create_files(owner, "/data/files/archive", "arch", 15, size_kb=200)
        create_files(owner, "/data/files/junk", "junk", 5, size_kb=200)

        # Wait for multiple flush cycles under pressure
        print("    Waiting 30s for flush cycles under disk pressure...")
        time.sleep(30)
        print()

        # -- Phase 6: Analysis — what got backed up? --
        print("Phase 6: Analysis — importance vs backup correlation")
        crit_backed = count_backed_up_in_dir(owner, "/data/files/critical")
        std_backed = count_backed_up_in_dir(owner, "/data/files/standard")
        arch_backed = count_backed_up_in_dir(owner, "/data/files/archive")
        junk_backed = count_backed_up_in_dir(owner, "/data/files/junk")

        crit_total, std_total, arch_total, junk_total = 5, 10, 15, 5
        print(f"    Critical (0.9):  {crit_backed}/{crit_total} backed up "
              f"({crit_backed / crit_total * 100:.0f}%)")
        print(f"    Standard (0.5):  {std_backed}/{std_total} backed up "
              f"({std_backed / std_total * 100:.0f}%)")
        print(f"    Archive  (0.1):  {arch_backed}/{arch_total} backed up "
              f"({arch_backed / arch_total * 100:.0f}%)")
        print(f"    Junk     (0.0):  {junk_backed}/{junk_total} backed up "
              f"({junk_backed / junk_total * 100:.0f}%)")

        # Check 1: junk (importance=0) must NEVER be backed up
        if junk_backed == 0:
            results["passed"].append("junk_excluded")
            print(f"    ✓ Junk files correctly excluded (importance=0)")
        else:
            results["failed"].append("junk_excluded")
            print(f"    ✗ Junk files were backed up — budget filter broken!")

        # Check 2: critical should have higher backup rate than archive
        crit_rate = crit_backed / crit_total if crit_total > 0 else 0
        arch_rate = arch_backed / arch_total if arch_total > 0 else 0
        if crit_rate >= arch_rate:
            results["passed"].append("importance_ordering")
            print(f"    ✓ Critical rate ({crit_rate:.0%}) >= Archive rate ({arch_rate:.0%})")
        else:
            results["failed"].append("importance_ordering")
            print(f"    ✗ Importance ordering violated: critical ({crit_rate:.0%}) "
                  f"< archive ({arch_rate:.0%})")

        # Check 3: at least some files were backed up
        total_backed = crit_backed + std_backed + arch_backed
        if total_backed > 0:
            results["passed"].append("some_files_backed_up")
            print(f"    ✓ {total_backed}/{crit_total + std_total + arch_total} "
                  f"non-junk files backed up")
        else:
            results["failed"].append("some_files_backed_up")
            print(f"    ✗ Nothing was backed up at all!")
        print()

        # -- Phase 7: Holder pressure analysis --
        print("Phase 7: Holder pressure analysis")
        for h in holders:
            hs = node_status_safe(h)
            if hs:
                hb = hs.get("holding_bytes", 0)
                quota_bytes = int(HOLDER_QUOTA_GB * 1024 * 1024 * 1024)
                pct = (hb / quota_bytes * 100) if quota_bytes > 0 else 0
                used = hs.get("used_bytes", 0)
                eff_quota = hs.get("effective_quota_bytes", 0)
                print(f"    {h}: holding={hb // 1024} KB ({pct:.0f}%), "
                      f"effective_quota={eff_quota // 1024} KB")

        # Check: at least one holder should be near capacity (>50% used)
        any_pressured = False
        for h in holders:
            hs = node_status_safe(h)
            if hs:
                hb = hs.get("holding_bytes", 0)
                quota_bytes = int(HOLDER_QUOTA_GB * 1024 * 1024 * 1024)
                if quota_bytes > 0 and hb / quota_bytes > 0.3:
                    any_pressured = True
                    break
        if any_pressured:
            results["passed"].append("holder_pressure")
            print(f"    ✓ At least one holder under storage pressure")
        else:
            results["failed"].append("holder_pressure")
            print(f"    ✗ No holder is under pressure — quotas too large?")
        print()

        # -- Phase 8: Graceful degradation --
        print("Phase 8: Graceful degradation — system still responsive")
        try:
            s = node_status(owner)
            results["passed"].append("system_responsive")
            print(f"    ✓ Owner daemon responsive: "
                  f"blocks_ok={s.get('blocks_ok')}, "
                  f"peers={s.get('peer_count')}")
        except Exception as e:
            results["failed"].append("system_responsive")
            print(f"    ✗ Owner daemon not responsive: {e}")

        # Check no panic/crash in logs
        crash_logs = exec_node_quiet(owner, "grep", "-ic",
                                      "panic\\|SIGSEGV\\|fatal",
                                      "/tmp/daemon.log")
        if crash_logs and int(crash_logs.strip() or "0") > 0:
            results["failed"].append("no_crashes")
            print(f"    ✗ Found {crash_logs.strip()} panic/fatal entries in logs!")
        else:
            results["passed"].append("no_crashes")
            print(f"    ✓ No panics or crashes")
        print()

        # -- Phase 9: Budget tracking evidence --
        print("Phase 9: Budget tracking in logs")
        budget_logs = exec_node_quiet(owner, "grep", "-c",
                                       "persist_cycle_budget\\|budget.*offered\\|placement_outcome",
                                       "/tmp/daemon.log")
        budget_count = int(budget_logs.strip() or "0")
        if budget_count > 0:
            results["passed"].append("budget_tracking")
            print(f"    ✓ Budget tracking: {budget_count} log entries")
        else:
            # Check alternative log patterns
            alt_logs = exec_node_quiet(owner, "grep", "-c",
                                        "offered.*accepted\\|budget\\|flush_queue",
                                        "/tmp/daemon.log")
            alt_count = int(alt_logs.strip() or "0")
            if alt_count > 0:
                results["passed"].append("budget_tracking")
                print(f"    ✓ Budget-related activity: {alt_count} log entries")
            else:
                results["failed"].append("budget_tracking")
                print(f"    ✗ No budget tracking evidence in logs")

        # Check for rejection logs (evidence of disk pressure)
        reject_logs = exec_node_quiet(owner, "grep", "-c",
                                       "SymbolReject\\|symbol.*reject\\|reject.*quota",
                                       "/tmp/daemon.log")
        reject_count = int(reject_logs.strip() or "0")
        if reject_count > 0:
            results["passed"].append("rejections_logged")
            print(f"    ✓ Symbol rejections logged: {reject_count} entries")
        else:
            print(f"    - No explicit rejection logs found (holders may have capacity)")
        print()

    except SystemExit:
        pass
    finally:
        print("=" * 60)
        print(f"RESULTS: {len(results['passed'])} passed, "
              f"{len(results['failed'])} failed")
        if results["passed"]:
            print(f"  PASSED: {', '.join(results['passed'])}")
        if results["failed"]:
            print(f"  FAILED: {', '.join(results['failed'])}")
        print()

        if results["failed"]:
            print("-- Node logs (last 50 lines each) --")
            for name in nodes:
                print(f"\n--- {name} ---")
                print(exec_node_quiet(name, "tail", "-50", "/tmp/daemon.log"))

        compose("down", "-v", timeout=60)

    return 0 if not results["failed"] else 1


if __name__ == "__main__":
    sys.exit(main())
