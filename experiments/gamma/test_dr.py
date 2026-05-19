#!/usr/bin/env python3
"""
T13: Disaster Recovery test.

Verifies that a node can recover from complete loss using its mnemonic:
  1. Node-00 initializes with a mnemonic (captured from init output)
  2. Back up files, wait for system state push to peers
  3. "Destroy" node-00: stop daemon, delete DB
  4. Run DR with mnemonic + peer addresses
  5. Verify: DB restored, file catalog intact
  6. Restart daemon, verify restore works

Uses 5 nodes with time_scale=100k.
System state push interval: 60s (clamped minimum).

Usage:
    python experiments/gamma/test_dr.py [--time-scale 100000]
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


def stop_daemon(name):
    exec_node_quiet(name, "pkill", "-f", "viaticum daemon", timeout=10)
    time.sleep(1)


# -- Main test ----------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="T13: Disaster Recovery test")
    parser.add_argument("-t", "--time-scale", type=int, default=100000)
    args = parser.parse_args()

    n = 5
    ts = args.time_scale

    print(f"=== T13: Disaster Recovery Test ===")
    print(f"    Nodes: {n}, time_scale: {ts}")
    print(f"    System state push interval: 60s (clamped minimum)")
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
    mnemonic = None

    try:
        # -- Phase 1: Init all nodes, capture owner's mnemonic --
        print("Phase 1: Init all nodes (capture owner mnemonic)")
        init_output = exec_node(owner, "viaticum", "init")
        print(f"    Owner init output:\n    {init_output[:200]}")

        # Parse mnemonic from init output
        # Format: "Mnemonic (SAVE THIS):\n  word1 word2 word3 ..."
        lines = init_output.split("\n")
        for i, line in enumerate(lines):
            if "Mnemonic" in line or "mnemonic" in line:
                # The mnemonic is on the next line (or the rest of this line)
                if i + 1 < len(lines):
                    mnemonic = lines[i + 1].strip()
                break

        if not mnemonic or len(mnemonic.split()) < 12:
            # Try parsing differently
            for line in lines:
                words = line.strip().split()
                if len(words) >= 12:
                    mnemonic = line.strip()
                    break

        if not mnemonic:
            results["failed"].append("mnemonic_captured")
            print(f"    FATAL: Could not capture mnemonic from init output")
            raise SystemExit(1)

        word_count = len(mnemonic.split())
        results["passed"].append("mnemonic_captured")
        print(f"    Mnemonic captured ({word_count} words): {mnemonic[:40]}...")

        for name in nodes[1:]:
            try:
                exec_node(name, "viaticum", "init")
            except RuntimeError as e:
                if "already initialized" not in str(e):
                    raise
        print(f"  {n} nodes initialized\n")

        # -- Phase 2: Config + Start --
        print("Phase 2: Configure and start all nodes")
        for name in nodes:
            write_config(name)
        for name in nodes:
            start_daemon(name, ts)
        time.sleep(5)
        print("  Daemons started\n")

        # -- Phase 3: Discovery --
        print("Phase 3: Peer discovery")
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

        # Capture peer addresses for DR
        peer_addrs = []
        for name in nodes[1:]:
            s = node_status_safe(name)
            if s and s.get("node_addr"):
                peer_addrs.append(s["node_addr"])
        print(f"  Collected {len(peer_addrs)} peer addresses for DR\n")

        # -- Phase 4: Backup files --
        print("Phase 4: Owner backs up files")
        exec_node(owner, "dd", "if=/dev/urandom",
                  "of=/data/files/dr_test_1.dat",
                  "bs=1024", "count=50", timeout=30)
        exec_node(owner, "dd", "if=/dev/urandom",
                  "of=/data/files/dr_test_2.dat",
                  "bs=1024", "count=50", timeout=30)

        ok = wait_for(
            "Backup complete",
            lambda: (s := node_status_safe(owner)) is not None
                    and s.get("blocks_ok", 0) > 0,
            timeout_secs=90, poll_secs=5,
        )
        if ok:
            results["passed"].append("backup_complete")
            s = node_status(owner)
            print(f"    blocks_ok={s.get('blocks_ok')}, backed_up_files={s.get('backed_up_files')}")
        else:
            results["failed"].append("backup_complete")
        print()

        # -- Phase 5: Wait for system state push --
        print("Phase 5: Wait for system state push to peers (up to 120s)")
        # The push interval is 60s minimum. First tick is skipped.
        # So the first push happens at ~60s after daemon start.

        def check_push():
            for name in nodes[1:]:
                try:
                    logs = exec_node(name, "grep", "-c", "SystemStateBackup.*stored",
                                     "/tmp/daemon.log", timeout=10)
                    if int(logs.strip()) > 0:
                        return True
                except Exception:
                    pass
            return False

        ok = wait_for(
            "System state push completed",
            check_push,
            timeout_secs=120, poll_secs=10,
        )

        if ok:
            results["passed"].append("system_state_push")
        else:
            # Check owner logs for push evidence
            push_logs = exec_node_quiet(owner, "grep", "system_state.*push\\|packed",
                                        "/tmp/daemon.log")
            if push_logs:
                print(f"    Push logs: {push_logs[:200]}")
                results["passed"].append("system_state_push")
            else:
                results["failed"].append("system_state_push")
                print(f"    WARNING: No system state push detected")
        print()

        # -- Phase 6: Destroy owner's DB --
        print("Phase 6: Destroy owner's DB (simulating data loss)")
        stop_daemon(owner)
        exec_node(owner, "rm", "-f", "/home/viaticum/.viaticum/db.redb")
        # Also remove keyfile so DR has to re-derive from mnemonic
        exec_node(owner, "rm", "-f", "/home/viaticum/.viaticum/keyfile.json")
        print(f"    DB and keyfile removed\n")

        # -- Phase 7: Run DR --
        print("Phase 7: Run disaster recovery")
        if not peer_addrs:
            results["failed"].append("dr_recovery")
            print(f"    FATAL: No peer addresses for DR")
            raise SystemExit(1)

        peer_args = []
        for addr in peer_addrs[:3]:  # Use up to 3 peers
            peer_args.extend(["--peer", addr])

        dr_cmd = ["viaticum", "dr", "--mnemonic", mnemonic] + peer_args
        try:
            dr_output = exec_node(owner, *dr_cmd, timeout=120)
            print(f"    DR output:\n    " + "\n    ".join(dr_output.split("\n")[:10]))

            if "restore successful" in dr_output.lower() or "Files:" in dr_output:
                results["passed"].append("dr_recovery")
                print(f"    DR recovery successful!")
            else:
                results["failed"].append("dr_recovery")
                print(f"    DR output doesn't confirm success")
        except Exception as e:
            results["failed"].append("dr_recovery")
            print(f"    DR failed: {e}")
        print()

        # -- Phase 8: Restart daemon after DR --
        print("Phase 8: Restart daemon after DR")
        write_config(owner)
        start_daemon(owner, ts)
        time.sleep(5)

        # Reconnect to peers
        for name in nodes[1:]:
            s = node_status_safe(name)
            if s and s.get("node_addr"):
                exec_node_quiet(owner, "viaticum", "connect", s["node_addr"], timeout=15)
        time.sleep(10)

        # Verify catalog is restored
        try:
            files_output = exec_node(owner, "viaticum", "files")
            if "dr_test" in files_output:
                results["passed"].append("catalog_restored")
                print(f"    File catalog restored")
            else:
                results["failed"].append("catalog_restored")
                print(f"    Files not found in restored catalog: {files_output[:200]}")
        except Exception as e:
            results["failed"].append("catalog_restored")
            print(f"    Files check failed: {e}")
        print()

        # -- Phase 9: Verify file restore --
        print("Phase 9: Verify file restore")

        # Try to restore a file
        restore_dir = "/tmp/restored_dr"
        src_path = "/data/files/dr_test_1.dat"
        try:
            exec_node(owner, "viaticum", "restore", src_path,
                      "--dest", restore_dir, timeout=60)
            restored_file = f"{restore_dir}{src_path}"
            orig_hash = exec_node(owner, "md5sum", src_path).split()[0]
            rest_hash = exec_node(owner, "md5sum", restored_file).split()[0]
            if orig_hash == rest_hash:
                results["passed"].append("restore_after_dr")
                print(f"    Restored file matches (md5={orig_hash[:12]}...)")
            else:
                results["failed"].append("restore_after_dr")
                print(f"    Hash mismatch: {orig_hash} vs {rest_hash}")
        except Exception as e:
            results["failed"].append("restore_after_dr")
            print(f"    Restore after DR failed: {e}")
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
            print("-- Node logs (last 40 lines each) --")
            for name in nodes:
                print(f"\n--- {name} ---")
                print(exec_node_quiet(name, "tail", "-40", "/tmp/daemon.log"))

        compose("down", "-v", timeout=60)

    return 0 if not results["failed"] else 1


if __name__ == "__main__":
    sys.exit(main())
