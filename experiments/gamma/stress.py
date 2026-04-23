#!/usr/bin/env python3
"""Post-warm-up stress scenarios that try to break the system.

Assumes `python run.py` already completed and left 20 containers up in the
gamma compose. Each scenario issues disruptions via `docker exec`, then polls
status to see what broke.

Usage:
    python stress.py --scenario mass_kill_holders
    python stress.py --scenario restore_flood
    python stress.py --scenario restart_owner
    python stress.py --scenario rapid_modification
    python stress.py --scenario long_flaky_off
"""

import argparse
import json
import random
import subprocess
import sys
import time
from pathlib import Path

RESULTS_DIR = Path(__file__).parent / "results"


def run(cmd: list[str], check: bool = False, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=check)


def node_status(name: str) -> dict | None:
    r = run(["docker", "exec", f"gamma-{name}", "syncback", "status", "--json"])
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


def node_alive(name: str) -> bool:
    # Match the full command line, not the exe name, so we don't count
    # <defunct> zombies (kernel keeps them in proc table until reaped, and
    # our PID 1 is `sleep infinity` which never reaps).
    r = run(["docker", "exec", f"gamma-{name}", "pgrep", "-f", "syncback daemon"])
    return r.returncode == 0


def kill_node(name: str) -> None:
    # `killall` is psmisc, not installed in the minimal Ubuntu container; use pkill
    # from procps. `-9 -f "syncback daemon"` avoids also killing short-lived CLI
    # invocations like `syncback status` started by our own inspection commands.
    run(["docker", "exec", f"gamma-{name}", "sh", "-c",
         "pkill -9 -f 'syncback daemon' 2>/dev/null || true"])


def start_node(name: str, time_scale: int = 20000) -> None:
    subprocess.run(
        ["docker", "exec", "-d", f"gamma-{name}", "sh", "-c",
         f"RUST_LOG=info syncback daemon --time-scale {time_scale} --watch-dir /data/files >>/tmp/daemon.log 2>&1"],
        check=False,
    )


def owner_names() -> list[str]:
    """Nodes that had files seeded (first 5 reliable by convention)."""
    return [f"node-{i:02d}" for i in range(0, 5)]


def holder_only_names() -> list[str]:
    return [f"node-{i:02d}" for i in range(5, 20)]


def collect_report(nodes: list[str], outfile: Path) -> dict:
    summary = {}
    for n in nodes:
        s = node_status(n)
        if s:
            summary[n] = {
                "holding_mb": s["holding_bytes"] // 1_048_576,
                "placement_alive": s["placement_alive"],
                "placement_count": s["placement_count"],
                "placement_lost": s["placement_lost"],
                "blocks_ok": s["blocks_ok"],
                "blocks_at_risk": s["blocks_at_risk"],
                "pos_total_passes": s["pos_total_passes"],
                "pos_total_challenges": s["pos_total_challenges"],
                "peer_count": s["peer_count"],
                "avg_trust": round(s["avg_trust"], 4),
                "daemon_alive": True,
            }
        else:
            summary[n] = {"daemon_alive": False}
    outfile.write_text(json.dumps(summary, indent=2))
    return summary


# ── Scenarios ────────────────────────────────────────────────────────────────

def scenario_mass_kill_holders(args):
    """Kill 10 of 15 holder-only nodes and watch placements transition Lost → repair."""
    victims = random.sample(holder_only_names(), 10)
    print(f"[stress] Killing 10 holders: {victims}")
    baseline = collect_report(owner_names(), args.out / "mass_kill_baseline.json")
    print(f"[stress] Baseline for owners: {json.dumps(baseline, indent=2)}")

    for v in victims:
        kill_node(v)
    print("[stress] Victims killed. Waiting 300s for repair cycle...")
    time.sleep(300)

    post = collect_report(owner_names() + victims, args.out / "mass_kill_post.json")
    print(f"[stress] Post-kill state:\n{json.dumps(post, indent=2)}")

    # Analyse: for each owner, how many placements transitioned Lost?
    for owner in owner_names():
        b = baseline.get(owner, {})
        p = post.get(owner, {})
        if b and p and b.get("daemon_alive") and p.get("daemon_alive"):
            lost_delta = p.get("placement_lost", 0) - b.get("placement_lost", 0)
            risk_delta = p.get("blocks_at_risk", 0) - b.get("blocks_at_risk", 0)
            print(f"  {owner}: +{lost_delta} Lost placements, +{risk_delta} blocks at risk")


def scenario_restart_owner(args):
    """Restart a reliable owner mid-stream — does pending state survive?"""
    target = "node-01"
    print(f"[stress] Baseline for {target}")
    before = node_status(target)
    print(f"  placements={before['placement_alive']}/{before['placement_count']} "
          f"pos={before['pos_total_passes']}/{before['pos_total_challenges']}")

    print(f"[stress] Killing {target}...")
    kill_node(target)
    time.sleep(5)
    assert not node_alive(target), f"{target} should be down"

    print(f"[stress] Waiting 60s with owner offline...")
    time.sleep(60)

    print(f"[stress] Restarting {target}...")
    start_node(target, time_scale=args.time_scale)
    time.sleep(15)

    after = node_status(target)
    if not after:
        print(f"[stress] ERROR: {target} did not come back up")
        return
    print(f"[stress] {target} back up:")
    print(f"  placements={after['placement_alive']}/{after['placement_count']} "
          f"pos={after['pos_total_passes']}/{after['pos_total_challenges']} "
          f"peer_count={after['peer_count']}")

    # Wait 3 more minutes, then compare
    time.sleep(180)
    final = node_status(target)
    print(f"[stress] After 3 more min:")
    print(f"  placements={final['placement_alive']}/{final['placement_count']} "
          f"pos={final['pos_total_passes']}/{final['pos_total_challenges']} "
          f"peer_count={final['peer_count']}")


def scenario_rapid_modification(args):
    """Hammer owner node-01 with 1 new photo per second for 120s."""
    target = "node-01"
    print(f"[stress] {target}: rapid file creation 1Hz for 120s (photo stream)")

    # Background loop inside container
    subprocess.run(
        ["docker", "exec", "-d", f"gamma-{target}", "sh", "-c",
         "mkdir -p /data/files/stream; "
         "for i in $(seq 1 120); do "
         "  dd if=/dev/urandom of=/data/files/stream/hot_$i.bin bs=1M count=2 2>/dev/null; "
         "  sleep 1; "
         "done"],
        check=False,
    )
    time.sleep(135)  # 120s generation + 15s settling

    s = node_status(target)
    print(f"[stress] After rapid stream: files={s['backed_up_files']} "
          f"placements={s['placement_alive']}/{s['placement_count']} "
          f"at_risk={s['blocks_at_risk']} "
          f"pos_rate={s['pos_total_passes']}/{s['pos_total_challenges']}")


def scenario_restore_flood(args):
    """All 5 owners initiate restore of their first file simultaneously."""
    owners = owner_names()
    print("[stress] Initiating concurrent restores on all 5 owners")

    for o in owners:
        # Parse text output of `syncback files` — grab first path on a line
        # starting with two spaces (indented file entries).
        r = run(["docker", "exec", f"gamma-{o}", "syncback", "files"])
        if r.returncode != 0:
            print(f"  {o}: files query failed")
            continue
        first_path = None
        for line in r.stdout.splitlines():
            if line.startswith("  /"):
                # format: "  /path/to/file   1 version   ..."
                parts = line.strip().split()
                if parts:
                    first_path = parts[0]
                    break
        if not first_path:
            print(f"  {o}: no files to restore")
            continue
        out = f"/tmp/restored_{o}.bin"
        subprocess.run(
            ["docker", "exec", "-d", f"gamma-{o}", "sh", "-c",
             f"syncback restore '{first_path}' --dest {out} >/tmp/restore.log 2>&1"],
            check=False,
        )
        print(f"  {o}: restore of {first_path} kicked off → {out}")

    time.sleep(120)

    for o in owners:
        r = run(["docker", "exec", f"gamma-{o}", "sh", "-c",
                 "ls -la /tmp/restored_*.bin 2>/dev/null; echo ---log:; tail -3 /tmp/restore.log 2>/dev/null"])
        print(f"  {o}:\n{r.stdout.strip()[:400]}")


def scenario_long_flaky_off(args):
    """Force ALL flaky nodes offline for a long duration to trigger PresumedLost."""
    flaky = [f"node-{i:02d}" for i in range(8, 16)]
    print(f"[stress] Killing all {len(flaky)} flaky nodes for 600s")
    for f in flaky:
        kill_node(f)
    time.sleep(600)
    print("[stress] After 600s down, checking owner placements:")
    for o in owner_names():
        s = node_status(o)
        if s:
            print(f"  {o}: alive={s['placement_alive']} lost={s['placement_lost']} at_risk={s['blocks_at_risk']}")


# ── Main ─────────────────────────────────────────────────────────────────────

def scenario_bitrot(args):
    """Corrupt a symbol on one holder; verify PoS catches it and repair kicks in."""
    target_holder = "node-05"
    print(f"[stress] Corrupting one symbol on {target_holder}")

    # Find a non-empty block directory on the holder
    r = run(["docker", "exec", f"gamma-{target_holder}", "sh", "-c",
             "ls /home/syncback/.syncback/holdings/ 2>/dev/null | head -3"])
    if not r.stdout.strip():
        print(f"[stress] {target_holder} has no holdings, skipping")
        return
    block_dir = r.stdout.strip().splitlines()[0]

    r = run(["docker", "exec", f"gamma-{target_holder}", "sh", "-c",
             f"ls /home/syncback/.syncback/holdings/{block_dir}/*.bin 2>/dev/null | head -1"])
    if not r.stdout.strip():
        print(f"[stress] block dir {block_dir} empty, skipping")
        return
    sym_path = r.stdout.strip().splitlines()[0]

    # Flip random bytes: write header+padding over first 64 bytes
    print(f"[stress] Corrupting {sym_path}")
    subprocess.run(
        ["docker", "exec", f"gamma-{target_holder}", "sh", "-c",
         f"dd if=/dev/urandom of={sym_path} bs=64 count=1 conv=notrunc 2>/dev/null"],
        check=False,
    )

    print("[stress] Waiting 300s for next PoS cycle to catch + repair...")
    time.sleep(300)

    # Check if repair fired — look for NACK / repair log lines on any owner
    for o in owner_names():
        r = run(["docker", "exec", f"gamma-{o}", "sh", "-c",
                 r"""sed -r 's/\x1b\[[0-9;]*m//g' /tmp/daemon.log | grep -iE 'PosHashNack|repair: triggered|mark_placement_lost|fail \{' | tail -3"""])
        out = r.stdout.strip()
        if out:
            print(f"  {o}:\n{out}")
        else:
            print(f"  {o}: no nack/repair log")


def scenario_delete_cascade(args):
    """Delete all backed-up files from an owner, verify placement cleanup."""
    target = "node-01"
    print(f"[stress] Deleting all stream files on {target} to trigger cascade")

    before = node_status(target)
    print(f"  before: files={before['backed_up_files']} placements={before['placement_alive']}")

    # Remove the files on disk — watcher should detect DirtyKind::Deleted.
    subprocess.run(
        ["docker", "exec", f"gamma-{target}", "sh", "-c",
         "rm -rf /data/files/stream /data/files/photos 2>/dev/null || true"],
        check=False,
    )
    print("[stress] Files removed from disk, waiting 300s for cleanup...")
    time.sleep(300)

    after = node_status(target)
    print(f"  after: files={after['backed_up_files']} placements={after['placement_alive']}")
    print(f"  delta: files {before['backed_up_files']}→{after['backed_up_files']} "
          f"placements {before['placement_alive']}→{after['placement_alive']}")

    # Any holder should report deletion happening
    for h in holder_only_names()[:3]:
        r = run(["docker", "exec", f"gamma-{h}", "sh", "-c",
                 r"""sed -r 's/\x1b\[[0-9;]*m//g' /tmp/daemon.log | grep -iE 'DeleteMsg|holding.*drop|removed holding' | tail -3"""])
        if r.stdout.strip():
            print(f"  {h}:\n{r.stdout.strip()}")


SCENARIOS = {
    "mass_kill_holders": scenario_mass_kill_holders,
    "restart_owner": scenario_restart_owner,
    "rapid_modification": scenario_rapid_modification,
    "restore_flood": scenario_restore_flood,
    "long_flaky_off": scenario_long_flaky_off,
    "bitrot": scenario_bitrot,
    "delete_cascade": scenario_delete_cascade,
}


def main():
    parser = argparse.ArgumentParser(description="Stress scenarios on running gamma cluster")
    parser.add_argument("--scenario", required=True, choices=list(SCENARIOS.keys()))
    parser.add_argument("--time-scale", type=int, default=20000)
    parser.add_argument("--out-dir", type=str, default=None)
    args = parser.parse_args()

    random.seed()
    run_id = time.strftime("%Y%m%d-%H%M%S")
    args.out = Path(args.out_dir) if args.out_dir else RESULTS_DIR / f"stress-{args.scenario}-{run_id}"
    args.out.mkdir(parents=True, exist_ok=True)
    print(f"[stress] Output dir: {args.out}")

    fn = SCENARIOS[args.scenario]
    fn(args)
    print("[stress] Scenario done")


if __name__ == "__main__":
    main()
