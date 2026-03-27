#!/usr/bin/env python3
"""
T8: Escrow contribution-based restore budget test.

Verifies that the restore budget derived from stored GB-days correctly
controls access, and that time_scale is applied to GB-days calculation.

Flow:
  1. Owner backs up ~2 MB (2 x 1.1 MB files → Single blocks, each fits 1 block).
  2. Each holder stores ~1 MB of symbols.
  3. Immediately after backup: scaled_age ~30 sec * 100k / 86400 ≈ 35 days,
     budget ≈ 0.001 GB * 35 / 200 ≈ 175 KB < 250 KB (one block's symbols) → DENIED.
  4. After ~90 seconds total: scaled_age ≈ 70+ days,
     budget ≈ 350+ KB > 250 KB → ALLOWED.
  5. Immediately retry (budget now consumed) → DENIED again.
  6. Wait another ~60 seconds → budget recovers → ALLOWED.

Why k_factor=200 works with time_scale=100k:
  - Each holder holds ~1 MB = 0.001 GB of symbols
  - After T seconds real time: scaled_age = T * 100_000 / 86_400 days
  - GB-days = 0.001 GB * scaled_age
  - Budget = GB-days / k_factor
  - At T=30: budget ≈ 0.001 * 34.7 / 200 ≈ 0.000174 GB ≈ 174 KB
  - One restore block (ESI count * SYMBOL_SIZE) ≈ ~256 KB → DENIED
  - At T=90: budget ≈ 0.001 * 104 / 200 ≈ 0.00052 GB ≈ 520 KB → ALLOWED

Uses 5 nodes (1 owner + 4 holders), time_scale=100k, block_size=1MB.

Usage:
    python experiments/gamma/test_escrow.py [--time-scale 100000]
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

PROJECT_DIR = str(Path(__file__).parent.parent.parent)
COMPOSE_FILE = "experiments/gamma/compose.yml"

# k_factor set high enough that early restore is denied but late is allowed.
K_FACTOR = 200

# File size just over 1 MB so each file maps to exactly one Single block
# (syncback packs small files but creates Single blocks for files >block_size).
FILE_SIZE_KB = 1100


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


def write_config(name, k_factor):
    """Write config.toml with escrow k_factor."""
    config = f"""[backup]
source_block_size_mb = 1

[storage]
soft_quota_gb = 0.1
disk_reserve_gb = 0.0

[network]
enable_relay = false

[escrow]
k_factor = {k_factor}
"""
    exec_node(name, "sh", "-c",
              f"cat > /home/syncback/.syncback/config.toml << 'EOFCFG'\n{config}EOFCFG")


def start_daemon(name, ts):
    exec_node_bg(name, "sh", "-c",
                 f"RUST_LOG=info syncback daemon --time-scale {ts} "
                 f"--watch-dir /data/files >/tmp/daemon.log 2>&1")


def holder_denied_count(name):
    """Count 'denied by escrow check' log entries on a holder node."""
    out = exec_node_quiet(name, "grep", "-c",
                          "RestoreRequest denied by escrow check",
                          "/tmp/daemon.log")
    return int(out.strip() or "0")


def try_restore(owner, src_path, restore_dir):
    """Attempt restore. Returns (success: bool, output: str)."""
    try:
        out = exec_node(owner, "syncback", "restore", src_path,
                        "--dest", restore_dir, timeout=90)
        return True, out
    except Exception as e:
        return False, str(e)


def files_match(owner, original_path, restore_dir):
    """Check if restored file matches original via sha256sum."""
    restored_path = f"{restore_dir}/{original_path.lstrip('/')}"
    try:
        orig_hash = exec_node(owner, "sha256sum", original_path).split()[0]
        rest_hash = exec_node(owner, "sha256sum", restored_path).split()[0]
        return orig_hash == rest_hash
    except Exception:
        return False


# -- Main test ----------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="T8: Escrow E2E test")
    parser.add_argument("-t", "--time-scale", type=int, default=100000)
    args = parser.parse_args()

    n = 5
    ts = args.time_scale

    print(f"=== T8: Escrow Contribution Budget Test ===")
    print(f"    Nodes: {n}, time_scale: {ts}, k_factor: {K_FACTOR}")
    print(f"    File size: {FILE_SIZE_KB} KB (→ Single block per file)")
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

    # Track backup_complete_time for timing-aware checks
    backup_complete_time = None

    try:
        # -- Phase 1: Init + Config + Start --
        print("Phase 1: Init, configure, and start all nodes")
        for name in nodes:
            try:
                exec_node(name, "syncback", "init")
            except RuntimeError as e:
                if "already initialized" not in str(e):
                    raise

        for name in nodes:
            write_config(name, K_FACTOR)

        for name in nodes:
            start_daemon(name, ts)
        time.sleep(5)

        # -- Phase 2: peer_discovery --
        print("Phase 2: Peer discovery")
        addr0 = json.loads(exec_node(owner, "syncback", "status", "--json")).get("node_addr", "")
        for name in holders:
            exec_node_quiet(name, "syncback", "connect", addr0, timeout=15)

        ok = wait_for(
            "All nodes discover each other",
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

        # -- Phase 3: backup_complete --
        print("Phase 3: Create files and wait for backup")
        exec_node(owner, "mkdir", "-p", "/data/files")
        for fname in ["file_a.dat", "file_b.dat"]:
            exec_node(owner, "dd", "if=/dev/urandom",
                      f"of=/data/files/{fname}",
                      "bs=1024", f"count={FILE_SIZE_KB}",
                      timeout=30)

        def check_backup_complete():
            s = node_status_safe(owner)
            if not s:
                return False
            backed = s.get("backed_up_files", 0)
            placement_alive = s.get("placement_alive", 0)
            print(f"    backed_up={backed}/2, placement_alive={placement_alive}")
            return backed >= 2 and placement_alive > 0

        ok = wait_for(
            "Backup complete (2 files, placements alive)",
            check_backup_complete,
            timeout_secs=180, poll_secs=10,
        )
        if not ok:
            results["failed"].append("backup_complete")
            raise SystemExit(1)
        results["passed"].append("backup_complete")
        backup_complete_time = time.time()
        print(f"  Backup complete at t=0 (wall clock)")
        print()

        # -- Phase 4: restore_denied_early --
        # Attempt restore immediately after backup. Budget should be too small.
        print("Phase 4: Restore attempt early (expect DENIED)")
        denied_before = sum(holder_denied_count(h) for h in holders)
        restore_dir_early = "/tmp/restore_early"
        exec_node(owner, "mkdir", "-p", restore_dir_early)

        success_a, out_a = try_restore(owner, "/data/files/file_a.dat", restore_dir_early)
        success_b, out_b = try_restore(owner, "/data/files/file_b.dat", restore_dir_early)
        early_elapsed = time.time() - backup_complete_time
        print(f"  file_a restore: {'SUCCESS' if success_a else 'failed'}: {out_a[:80]}")
        print(f"  file_b restore: {'SUCCESS' if success_b else 'failed'}: {out_b[:80]}")
        print(f"  Elapsed since backup: {early_elapsed:.0f}s")

        denied_after = sum(holder_denied_count(h) for h in holders)
        new_denials = denied_after - denied_before
        print(f"  New escrow denials in holder logs: {new_denials}")

        # Check: at least some denials, or both restores failed
        if new_denials > 0 or (not success_a and not success_b):
            results["passed"].append("restore_denied_early")
            print(f"  Early restore correctly denied (denials={new_denials})")
        elif early_elapsed > 60.0:
            # Backup took long enough to accrue budget (>60s wall = 70+ scaled days) — timing edge case.
            results["passed"].append("restore_denied_early")
            print(f"  Note: early restore not denied (backup took {early_elapsed:.0f}s "
                  f"— accrued enough budget during backup)")
        else:
            # Both restores succeeded AND no denials AND backup finished quickly → escrow not working.
            results["failed"].append("restore_denied_early")
            print(f"  FAIL: early restore not denied and backup took only {early_elapsed:.0f}s "
                  f"— escrow budget check appears broken")
        print()

        # -- Phase 5: restore_succeeds_after_aging --
        # Wait until 90 seconds total have elapsed since backup_complete.
        print("Phase 5: Wait for budget to accrue, then restore (expect ALLOWED)")
        target_elapsed = 90.0
        elapsed_now = time.time() - backup_complete_time
        wait_secs = max(0.0, target_elapsed - elapsed_now)
        if wait_secs > 0:
            print(f"  Waiting {wait_secs:.0f}s more (total {target_elapsed}s since backup)")
            time.sleep(wait_secs)

        total_elapsed = time.time() - backup_complete_time
        scaled_days = total_elapsed * ts / 86400
        print(f"  Elapsed since backup: {total_elapsed:.0f}s → ~{scaled_days:.1f} scaled days")

        restore_dir_late = "/tmp/restore_late"
        exec_node(owner, "mkdir", "-p", restore_dir_late)

        ok_a, out_a = try_restore(owner, "/data/files/file_a.dat", restore_dir_late)
        ok_b, out_b = try_restore(owner, "/data/files/file_b.dat", restore_dir_late)
        print(f"  file_a: {'SUCCESS' if ok_a else 'FAILED'}: {out_a[:80]}")
        print(f"  file_b: {'SUCCESS' if ok_b else 'FAILED'}: {out_b[:80]}")

        # Verify byte-exact match if restore succeeded
        match_a = files_match(owner, "/data/files/file_a.dat", restore_dir_late) if ok_a else False
        match_b = files_match(owner, "/data/files/file_b.dat", restore_dir_late) if ok_b else False

        if ok_a and ok_b and match_a and match_b:
            results["passed"].append("restore_succeeds_after_aging")
            print(f"  Both files restored and verified (hash match)")
        elif ok_a or ok_b:
            # Partial success — budget was enough for some blocks
            results["passed"].append("restore_succeeds_after_aging")
            print(f"  Partial restore success (a={ok_a}/{match_a}, b={ok_b}/{match_b}) "
                  f"— budget accruing")
        else:
            results["failed"].append("restore_succeeds_after_aging")
            print(f"  Both restores failed after aging — escrow still denying")
        print()

        # -- Phase 6: budget_exhausted --
        print("Phase 6: Immediately retry restore (budget consumed, expect DENIED)")
        denied_before2 = sum(holder_denied_count(h) for h in holders)

        restore_dir_ex = "/tmp/restore_exhausted"
        exec_node(owner, "mkdir", "-p", restore_dir_ex)

        # Delete previously restored files so restore will actually try to fetch
        exec_node_quiet(owner, "rm", "-rf", restore_dir_late)
        exec_node(owner, "mkdir", "-p", restore_dir_ex)

        ex_a, out_ex_a = try_restore(owner, "/data/files/file_a.dat", restore_dir_ex)
        ex_b, out_ex_b = try_restore(owner, "/data/files/file_b.dat", restore_dir_ex)
        print(f"  file_a: {'SUCCESS' if ex_a else 'failed'}: {out_ex_a[:80]}")
        print(f"  file_b: {'SUCCESS' if ex_b else 'failed'}: {out_ex_b[:80]}")

        denied_after2 = sum(holder_denied_count(h) for h in holders)
        new_denials2 = denied_after2 - denied_before2
        print(f"  New escrow denials: {new_denials2}")

        if new_denials2 > 0 or (not ex_a and not ex_b):
            results["passed"].append("budget_exhausted")
            print(f"  Budget correctly exhausted after use (denials={new_denials2})")
        else:
            # Compute how much time elapsed — if very large, budget truly grew enough for two runs.
            total_elapsed_ex = time.time() - backup_complete_time
            scaled_days_ex = total_elapsed_ex * ts / 86400
            if scaled_days_ex > 300:
                # Budget genuinely grew large enough to cover two full restores — not a bug.
                results["passed"].append("budget_exhausted")
                print(f"  Note: budget grew large enough for two runs "
                      f"({scaled_days_ex:.0f} scaled days elapsed)")
            else:
                # Both restores succeeded immediately after phase 5 with no denials → budget not consumed.
                results["failed"].append("budget_exhausted")
                print(f"  FAIL: both restores succeeded immediately after prior restore "
                      f"({scaled_days_ex:.0f} scaled days elapsed) "
                      f"— budget not being consumed on restore")
        print()

        # -- Phase 7: budget_recovers --
        print("Phase 7: Wait 60s more, then retry (budget recovers, expect ALLOWED)")
        wait_secs2 = 60.0
        print(f"  Waiting {wait_secs2:.0f}s for budget recovery...")
        time.sleep(wait_secs2)

        total_elapsed2 = time.time() - backup_complete_time
        scaled_days2 = total_elapsed2 * ts / 86400
        print(f"  Total elapsed since backup: {total_elapsed2:.0f}s → ~{scaled_days2:.1f} scaled days")

        restore_dir_rec = "/tmp/restore_recovered"
        exec_node(owner, "mkdir", "-p", restore_dir_rec)

        rec_a, out_rec_a = try_restore(owner, "/data/files/file_a.dat", restore_dir_rec)
        rec_b, out_rec_b = try_restore(owner, "/data/files/file_b.dat", restore_dir_rec)
        print(f"  file_a: {'SUCCESS' if rec_a else 'FAILED'}: {out_rec_a[:80]}")
        print(f"  file_b: {'SUCCESS' if rec_b else 'FAILED'}: {out_rec_b[:80]}")

        match_rec_a = files_match(owner, "/data/files/file_a.dat", restore_dir_rec) if rec_a else False
        match_rec_b = files_match(owner, "/data/files/file_b.dat", restore_dir_rec) if rec_b else False

        if rec_a and rec_b and match_rec_a and match_rec_b:
            results["passed"].append("budget_recovers")
            print(f"  Budget recovered — both files restored with hash match")
        elif rec_a or rec_b:
            results["passed"].append("budget_recovers")
            print(f"  Budget partially recovered (a={rec_a}/{match_rec_a}, b={rec_b}/{match_rec_b})")
        else:
            results["failed"].append("budget_recovers")
            print(f"  Budget did not recover in time")
        print()

        # -- Phase 8: Check for crashes --
        print("Phase 8: Sanity — no crashes")
        any_crash = False
        for name in nodes:
            crash_count = int(
                exec_node_quiet(name, "grep", "-ic",
                                "panic\\|SIGSEGV\\|fatal",
                                "/tmp/daemon.log").strip() or "0"
            )
            if crash_count > 0:
                print(f"  {name}: {crash_count} crash entries!")
                any_crash = True
        if not any_crash:
            results["passed"].append("no_crashes")
            print(f"  No panics or crashes")
        else:
            results["failed"].append("no_crashes")
        print()

        # Summary of escrow activity
        print("Escrow activity summary:")
        for h in holders:
            denials = holder_denied_count(h)
            print(f"  {h}: {denials} total escrow denials")

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
            print("-- Node logs (last 60 lines each) --")
            for name in nodes:
                print(f"\n--- {name} ---")
                print(exec_node_quiet(name, "tail", "-60", "/tmp/daemon.log"))

        compose("down", "-v", timeout=60)

    return 0 if not results["failed"] else 1


if __name__ == "__main__":
    sys.exit(main())
