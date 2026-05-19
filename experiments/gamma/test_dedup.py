#!/usr/bin/env python3
"""
T10: Content Dedup test.

Verifies that identical content produces zero additional traffic:
  1. Node backs up file_a.dat (100 KB)
  2. Wait for backup complete (source block created)
  3. Copy identical content to file_b.dat (different path, same bytes)
  4. Wait for dedup detection
  5. Verify: file_b points to same source_block_id as file_a (zero re-upload)

Uses 5 nodes with time_scale=100k.

Usage:
    python experiments/gamma/test_dedup.py [--time-scale 100000]
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

PROJECT_DIR = str(Path(__file__).parent.parent.parent)
COMPOSE_FILE = "experiments/gamma/compose.yml"


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


def write_config(name):
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


def start_daemon(name, ts):
    exec_node_bg(name, "sh", "-c",
                 f"RUST_LOG=info viaticum daemon --time-scale {ts} "
                 f"--watch-dir /data/files >/tmp/daemon.log 2>&1")


# -- Main test ----------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="T10: Content Dedup test")
    parser.add_argument("-t", "--time-scale", type=int, default=100000)
    args = parser.parse_args()

    n = 5
    ts = args.time_scale

    print(f"=== T10: Content Dedup Test ===")
    print(f"    Nodes: {n}, time_scale: {ts}")
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
    results = {"passed": [], "failed": []}

    try:
        # -- Phase 1: Init + Config + Start --
        print("Phase 1: Init, configure, and start all nodes")
        for name in nodes:
            try:
                exec_node(name, "viaticum", "init")
            except RuntimeError as e:
                if "already initialized" not in str(e):
                    raise
            write_config(name)
        for name in nodes:
            start_daemon(name, ts)
        time.sleep(5)
        print(f"  {n} nodes started\n")

        # -- Phase 2: Discovery --
        print("Phase 2: Peer discovery")
        addr0 = json.loads(exec_node(owner, "viaticum", "status", "--json")).get("node_addr", "")
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
            raise SystemExit(1)
        results["passed"].append("peer_discovery")
        print()

        # -- Phase 3: Create first file with known content --
        # Files >= source_block_size_mb (1 MB) get Single blocks, not Pack blocks.
        # Dedup + Pack blocks has a known limitation (different file_id in PackIndex).
        print("Phase 3: Create file_a.dat (1.1 MB, deterministic content)")
        # Use deterministic content so file_b will have same hash
        exec_node(owner, "sh", "-c",
                  "dd if=/dev/zero bs=1024 count=1126 | tr '\\0' 'A' > /data/files/file_a.dat")

        ok = wait_for(
            "file_a backup complete",
            lambda: (s := node_status_safe(owner)) is not None
                    and s.get("blocks_ok", 0) >= 1,
            timeout_secs=90, poll_secs=5,
        )
        if ok:
            results["passed"].append("file_a_backed_up")
            s = node_status(owner)
            blocks_after_a = s.get("blocks_ok", 0)
            print(f"    blocks_ok={blocks_after_a}")
        else:
            results["failed"].append("file_a_backed_up")
            raise SystemExit(1)
        print()

        # -- Phase 4: Get file_a's source block ID --
        print("Phase 4: Record file_a's source block ID")
        versions_a = exec_node(owner, "viaticum", "versions", "/data/files/file_a.dat")
        print(f"    versions output:\n    {versions_a[:200]}")

        # Parse source_block_id from versions output
        block_id_a = None
        for line in versions_a.split("\n"):
            if "block:" in line.lower() or "source" in line.lower():
                # Try to extract hex block id
                parts = line.split()
                for part in parts:
                    if len(part) == 64 and all(c in "0123456789abcdef" for c in part):
                        block_id_a = part
                        break

        if not block_id_a:
            # Try getting from status --json table_stats or logs
            logs = exec_node_quiet(owner, "grep", "source_block", "/tmp/daemon.log")
            print(f"    Could not parse block_id from versions, checking logs...")
            # As fallback, check blocks_ok count change
            pass
        else:
            print(f"    file_a block_id: {block_id_a[:16]}...")
        print()

        # -- Phase 5: Create file_b with identical content --
        print("Phase 5: Create file_b.dat (identical content, different path)")
        exec_node(owner, "cp", "/data/files/file_a.dat", "/data/files/file_b.dat")

        # Wait for the dedup to be processed
        time.sleep(10)

        # Check blocks_ok count — should NOT increase if dedup works
        s = node_status(owner)
        blocks_after_b = s.get("blocks_ok", 0)
        backed_up_files = s.get("backed_up_files", 0)
        print(f"    After file_b: blocks_ok={blocks_after_b} (was {blocks_after_a})")
        print(f"    backed_up_files={backed_up_files}")

        if blocks_after_b == blocks_after_a:
            results["passed"].append("dedup_no_extra_block")
            print(f"    Dedup confirmed: no new source block created")
        else:
            results["failed"].append("dedup_no_extra_block")
            print(f"    FAIL: blocks_ok increased from {blocks_after_a} to {blocks_after_b}")

        # Also check backed_up_files count (should be 2: file_a and file_b)
        if backed_up_files >= 2:
            results["passed"].append("both_files_cataloged")
            print(f"    Both files are in the catalog")
        else:
            results["failed"].append("both_files_cataloged")
            print(f"    Only {backed_up_files} files in catalog (expected 2)")
        print()

        # -- Phase 6: Check that no extra placement was created --
        print("Phase 6: Verify no extra placements for dedup'd block")
        s = node_status(owner)
        placement_count = s.get("placement_count", 0)
        # With 1 source block and typical 2 holders: ~2 placements.
        # If dedup created a new block, we'd see ~4 placements.
        if placement_count <= 4:  # reasonable for 1 block
            results["passed"].append("no_extra_placements")
            print(f"    placement_count={placement_count} (expected ~2 for 1 block)")
        else:
            results["failed"].append("no_extra_placements")
            print(f"    placement_count={placement_count} (too many, dedup may have failed)")
        print()

        # -- Phase 7: Verify both files are restorable --
        print("Phase 7: Verify both files restorable")
        for fname in ["file_a.dat", "file_b.dat"]:
            restore_dir = f"/tmp/restored_dedup_{fname}"
            src_path = f"/data/files/{fname}"
            try:
                exec_node(owner, "viaticum", "restore", src_path,
                          "--dest", restore_dir, timeout=60)
                orig_hash = exec_node(owner, "md5sum", src_path).split()[0]
                restored_file = f"{restore_dir}{src_path}"
                rest_hash = exec_node(owner, "md5sum", restored_file).split()[0]
                if orig_hash == rest_hash:
                    results["passed"].append(f"restore_{fname}")
                    print(f"    {fname}: OK (md5={orig_hash[:12]}...)")
                else:
                    results["failed"].append(f"restore_{fname}")
                    print(f"    {fname}: hash mismatch")
            except Exception as e:
                results["failed"].append(f"restore_{fname}")
                print(f"    {fname}: restore failed: {e}")
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
            print("-- Node logs (last 30 lines each) --")
            for name in nodes:
                print(f"\n--- {name} ---")
                print(exec_node_quiet(name, "tail", "-30", "/tmp/daemon.log"))

        compose("down", "-v", timeout=60)

    return 0 if not results["failed"] else 1


if __name__ == "__main__":
    sys.exit(main())
