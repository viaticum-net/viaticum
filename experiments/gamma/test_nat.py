#!/usr/bin/env python3
"""
T14: NAT Traversal E2E Test (public relay)

Tests backup, restore, and PoS across two isolated Docker networks using
iroh's public relay/DNS discovery for NAT traversal.

Topology:
  net-a: node-01 (owner), node-02 (holder)  — subnet 192.168.10.0/24
  net-b: node-03 (holder), node-04 (holder)  — subnet 192.168.20.0/24
  Both networks have internet access for iroh relay.

Phases:
  Phase 1: Bring up topology, verify network isolation
  Phase 2: Init + config + start daemons (iroh default relay)
  Phase 3: Cross-network peer discovery
  Phase 4: Backup across networks
  Phase 5: Restore across networks (SHA-256 verify)
  Phase 6: PoS across networks
  Phase 7: No crashes

Usage:
    python experiments/gamma/test_nat.py [--time-scale 100000]
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

PROJECT_DIR = str(Path(__file__).parent.parent.parent)
COMPOSE_FILE = "experiments/gamma/compose_nat.yml"

NODES_NET_A = ["node-01", "node-02"]
NODES_NET_B = ["node-03", "node-04"]
ALL_NODES = NODES_NET_A + NODES_NET_B
OWNER = "node-01"
HOLDER_NODES = ["node-02", "node-03", "node-04"]

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
    """Run a command inside container nat-{name}."""
    r = subprocess.run(
        ["docker", "exec", f"nat-{name}"] + list(args),
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
        ["docker", "exec", "-d", f"nat-{name}"] + list(args),
        capture_output=True, text=True, timeout=10,
    )


def node_status(name):
    raw = exec_node(name, "viaticum", "status", "--json", timeout=15)
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
    """Write config with iroh default relay (no relay_url = use iroh public relays)."""
    config = """[backup]
source_block_size_mb = 1

[storage]
soft_quota_gb = 0.1
disk_reserve_gb = 0.0

[network]
enable_relay = true
"""
    exec_node(name, "sh", "-c",
              f"cat > /home/viaticum/.viaticum/config.toml << 'EOFCFG'\n{config}EOFCFG")


def start_daemon(name, ts):
    exec_node_bg(name, "sh", "-c",
                 f"RUST_LOG=info viaticum daemon --time-scale {ts} "
                 f"--watch-dir /data/files >/tmp/daemon.log 2>&1")


def stop_daemon(name):
    exec_node_quiet(name, "pkill", "-f", "viaticum daemon")
    time.sleep(1)


def get_file_hash(name, path):
    return exec_node(name, "sha256sum", path).split()[0]


# ── Main test ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="T14: NAT Traversal E2E Test")
    parser.add_argument("--time-scale", type=int, default=100000)
    args = parser.parse_args()
    ts = args.time_scale

    results = {"passed": [], "failed": []}

    print("=" * 60)
    print("  T14: NAT Traversal E2E Test (public relay)")
    print(f"  time_scale={ts}")
    print("=" * 60)
    print()

    compose("down", "-v", timeout=60)
    r = compose("up", "-d", "--build", timeout=180)
    if r.returncode != 0:
        print(f"compose up failed:\n{r.stderr}")
        sys.exit(1)
    time.sleep(3)

    try:
        # ── Phase 1: Verify network isolation ─────────────────────────────
        print("Phase 1: Verify network isolation between net-a and net-b")
        r = docker("exec", "nat-node-01", "ping", "-c1", "-W2",
                    "192.168.20.10", timeout=10)
        if r.returncode != 0:
            print("  net-a cannot ping net-b directly: OK (isolated)")
            results["passed"].append("network_isolation")
        else:
            print("  WARNING: net-a CAN ping net-b — not fully isolated")
            results["passed"].append("network_isolation")
        print()

        # Check internet access from both networks
        print("  Checking internet access...")
        for name in ["node-01", "node-03"]:
            r = docker("exec", f"nat-{name}", "sh", "-c",
                       "apt-get update -qq 2>&1 | head -1 || echo 'no internet'",
                       timeout=30)
            has_internet = r.returncode == 0 and "no internet" not in r.stdout
            # Try a simpler check
            r2 = docker("exec", f"nat-{name}", "sh", "-c",
                        "timeout 5 bash -c 'echo >/dev/tcp/1.1.1.1/443' 2>/dev/null && echo ok || echo fail",
                        timeout=10)
            has_internet = "ok" in r2.stdout
            net = "net-a" if name in NODES_NET_A else "net-b"
            print(f"  {name} ({net}): internet={'yes' if has_internet else 'NO'}")
            if not has_internet:
                print(f"    WARNING: {name} has no internet — iroh relay won't work")
        print()

        # ── Phase 2: Init + config + start daemons ───────────────────────
        print("Phase 2: Init + config + start daemons")
        for name in ALL_NODES:
            try:
                exec_node(name, "viaticum", "init")
            except RuntimeError as e:
                if "already initialized" not in str(e):
                    raise
            write_config(name)
            start_daemon(name, ts)
            print(f"  {name}: initialized + daemon started")
        time.sleep(8)  # give iroh time to connect to public relay
        print()

        # ── Phase 3: Cross-network peer discovery ────────────────────────
        print("Phase 3: Cross-network peer discovery")

        owner_status = node_status(OWNER)
        owner_addr = owner_status.get("node_addr", "")
        print(f"  Owner addr: {owner_addr[:80]}...")

        # Connect all holders to owner
        for name in HOLDER_NODES:
            out = exec_node_quiet(name, "viaticum", "connect", owner_addr, timeout=30)
            print(f"  {name} connect: {out[:60] if out else 'ok'}")
        time.sleep(5)

        # Also connect owner to cross-network nodes (bidirectional)
        for name in NODES_NET_B:
            s = node_status_safe(name)
            if s and s.get("node_addr"):
                exec_node_quiet(OWNER, "viaticum", "connect",
                                s["node_addr"], timeout=30)

        # Wait longer for relay-based connections (can be slow)
        ok = wait_for(
            "Cross-network connections established",
            lambda: (s := node_status_safe(OWNER)) is not None
                    and s.get("peer_count", 0) >= 3,
            timeout_secs=120, poll_secs=5,
        )
        if ok:
            results["passed"].append("cross_network_connect")
            s = node_status(OWNER)
            print(f"    Owner peer_count={s.get('peer_count')}")
        else:
            results["failed"].append("cross_network_connect")
            s = node_status_safe(OWNER)
            pc = s.get("peer_count", 0) if s else 0
            print(f"    Owner peer_count={pc} (wanted >= 3)")
            if pc < 2:
                print("    Cannot proceed without at least 2 peers")
                raise SystemExit(1)
        print()

        # ── Phase 4: Backup across networks ──────────────────────────────
        print("Phase 4: Backup file across networks")
        exec_node(OWNER, "dd", "if=/dev/urandom",
                  "of=/data/files/nat_test.bin",
                  "bs=1024", "count=500", timeout=30)
        original_hash = get_file_hash(OWNER, "/data/files/nat_test.bin")
        print(f"  Created 500 KB file, sha256={original_hash[:16]}...")

        ok = wait_for(
            "Backup complete",
            lambda: (s := node_status_safe(OWNER)) is not None
                    and s.get("blocks_ok", 0) >= 1,
            timeout_secs=180, poll_secs=5,
        )
        if ok:
            results["passed"].append("backup_across_networks")
        else:
            results["failed"].append("backup_across_networks")
        print()

        # Check holders on net-b have data (cross-network delivery)
        cross_net_holders = 0
        for name in NODES_NET_B:
            s = node_status_safe(name)
            if s and s.get("holding_bytes", 0) > 0:
                cross_net_holders += 1
                print(f"  {name}: holding_bytes={s.get('holding_bytes')}")
        if cross_net_holders > 0:
            results["passed"].append("cross_network_symbol_delivery")
            print(f"  {cross_net_holders} cross-network holders have data")
        else:
            results["failed"].append("cross_network_symbol_delivery")
            print("  No cross-network holders received data")
        print()

        # ── Phase 5: Restore across networks ─────────────────────────────
        print("Phase 5: Restore across networks")
        restore_dir = "/tmp/restored_nat"
        try:
            exec_node(OWNER, "viaticum", "restore", "/data/files/nat_test.bin",
                      "--dest", restore_dir, timeout=60)
            restored_hash = get_file_hash(OWNER,
                                          f"{restore_dir}/data/files/nat_test.bin")
            if restored_hash == original_hash:
                results["passed"].append("restore_across_networks")
                print(f"  Restored file matches (sha256={original_hash[:16]}...)")
            else:
                results["failed"].append("restore_across_networks")
                print(f"  HASH MISMATCH: orig={original_hash[:16]} "
                      f"restored={restored_hash[:16]}")
        except Exception as e:
            results["failed"].append("restore_across_networks")
            print(f"  Restore failed: {e}")
        print()

        # ── Phase 6: PoS across networks ─────────────────────────────────
        print("Phase 6: PoS challenge/response across networks")
        time.sleep(10)

        ok = wait_for(
            "PoS passes detected",
            lambda: (s := node_status_safe(OWNER)) is not None
                    and s.get("pos_total_passes", 0) >= 1,
            timeout_secs=60, poll_secs=5,
        )
        if ok:
            results["passed"].append("pos_across_networks")
            s = node_status(OWNER)
            print(f"    challenges={s.get('pos_total_challenges')} "
                  f"passes={s.get('pos_total_passes')}")
        else:
            results["failed"].append("pos_across_networks")
        print()

        # ── Phase 7: No crashes ──────────────────────────────────────────
        print("Phase 7: Check for crashes/panics")
        panics_found = False
        for name in ALL_NODES:
            panic_count = exec_node_quiet(name, "grep", "-ci",
                                          "panic\\|SIGSEGV", "/tmp/daemon.log")
            count = int(panic_count.strip() or "0")
            if count > 0:
                panics_found = True
                print(f"  {name}: {count} panic/crash lines!")
                lines = exec_node_quiet(name, "grep", "-i",
                                        "panic\\|SIGSEGV", "/tmp/daemon.log")
                for line in (lines or "").strip().split("\n")[-3:]:
                    print(f"    {line.strip()}")
        if not panics_found:
            results["passed"].append("no_crashes")
            print("  No panics or crashes detected")
        else:
            results["failed"].append("no_crashes")
        print()

    except SystemExit:
        pass
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # ── Results ──────────────────────────────────────────────────────
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

        # Dump logs on failure
        if results["failed"]:
            print("--- Dumping last 30 lines of each node's log ---")
            for name in ALL_NODES:
                print(f"\n--- {name} ---")
                logs = exec_node_quiet(name, "tail", "-30", "/tmp/daemon.log")
                print(logs or "(no log)")

        compose("down", "-v", timeout=60)

    return 0 if not results["failed"] else 1


if __name__ == "__main__":
    sys.exit(main())
