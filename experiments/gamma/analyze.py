#!/usr/bin/env python3
"""
Analyze gamma experiment results from JSONL snapshots.

Usage:
    python experiments/gamma/analyze.py experiments/gamma/results/<run_id>/
"""

import json
import sys
from collections import defaultdict
from pathlib import Path


def load_snapshots(path: Path) -> list[dict]:
    records = []
    with open(path / "snapshots.jsonl") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def load_events(path: Path) -> list[dict]:
    records = []
    events_path = path / "events.jsonl"
    if events_path.exists():
        with open(events_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    return records


def analyze(results_dir: Path):
    snapshots = load_snapshots(results_dir)
    events = load_events(results_dir)

    if not snapshots:
        print("No snapshots found.")
        return

    config_path = results_dir / "config.json"
    if config_path.exists():
        config = json.loads(config_path.read_text())
        print(f"Run: {config.get('run_id', '?')}")
        print(f"Nodes: {config.get('nodes', '?')}, time_scale: {config.get('time_scale', '?')}")
        print(f"Duration: {config.get('duration_secs', '?')}s real, "
              f"~{config.get('sim_weeks', '?')} sim weeks")
    print()

    # Group snapshots by time bucket
    times = sorted(set(s["elapsed_s"] for s in snapshots))

    # Latest snapshot per node
    latest: dict[str, dict] = {}
    for s in snapshots:
        latest[s["node"]] = s

    # ── Per-archetype summary at end ──
    print("=" * 70)
    print("FINAL STATE (latest snapshot)")
    print("=" * 70)

    by_arch: dict[str, list[dict]] = defaultdict(list)
    for node, s in sorted(latest.items()):
        by_arch[s["archetype"]].append(s)

    for arch in ["reliable", "flaky", "freeloader"]:
        entries = by_arch.get(arch, [])
        if not entries:
            continue
        print(f"\n  [{arch}] ({len(entries)} nodes)")

        for e in entries:
            pos_ch = e.get("pos_total_challenges", 0)
            pos_pa = e.get("pos_total_passes", 0)
            pos_rate = f"{pos_pa}/{pos_ch} ({pos_pa/pos_ch*100:.0f}%)" if pos_ch > 0 else "0/0"
            print(f"    {e['node']}: "
                  f"peers={e['peer_count']} "
                  f"holding={e['holding_bytes']//1024}KB "
                  f"backed={e['backed_up_files']}files/{e['backed_up_bytes']//1024}KB "
                  f"placements={e['placement_alive']}/{e['placement_alive']+e['placement_lost']} "
                  f"pos={pos_rate} "
                  f"blocks={e['blocks_ok']}ok/{e['blocks_at_risk']}risk")

        # Aggregates
        avg_holding = sum(e["holding_bytes"] for e in entries) / len(entries) / 1024
        total_ch = sum(e.get("pos_total_challenges", 0) for e in entries)
        total_pa = sum(e.get("pos_total_passes", 0) for e in entries)
        pos_agg = f"{total_pa/total_ch*100:.1f}%" if total_ch > 0 else "n/a"
        avg_trust = sum(e.get("avg_trust", 0) for e in entries) / len(entries)
        print(f"    ── avg_holding={avg_holding:.0f}KB "
              f"pos_rate={pos_agg} "
              f"avg_trust={avg_trust:.4f}")

    # ── Trust evolution over time ──
    print("\n" + "=" * 70)
    print("TRUST EVOLUTION OVER TIME")
    print("=" * 70)

    # Group by (time, archetype) → list of avg_trust values
    time_arch_trust: dict[float, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    for s in snapshots:
        time_arch_trust[s["elapsed_s"]][s["archetype"]].append(s.get("avg_trust", 0))

    # Sample at ~10 time points
    if len(times) > 10:
        sample_times = [times[i * len(times) // 10] for i in range(10)] + [times[-1]]
    else:
        sample_times = times

    print(f"\n  {'elapsed':>8s} {'sim_wk':>7s}  {'reliable':>10s} {'flaky':>10s} {'freeloader':>10s}")
    print(f"  {'─' * 8} {'─' * 7}  {'─' * 10} {'─' * 10} {'─' * 10}")
    for t in sample_times:
        sim_wk = snapshots[0].get("sim_weeks", 0) if t == times[0] else t / times[-1] * snapshots[-1].get("sim_weeks", 0) if times[-1] > 0 else 0
        # Find nearest snapshot time
        arch_vals = time_arch_trust.get(t, {})
        parts = []
        for arch in ["reliable", "flaky", "freeloader"]:
            vals = arch_vals.get(arch, [])
            if vals:
                parts.append(f"{sum(vals)/len(vals):10.4f}")
            else:
                parts.append(f"{'n/a':>10s}")

        # Compute sim_weeks from the snapshot
        snap_at_t = [s for s in snapshots if s["elapsed_s"] == t]
        sw = snap_at_t[0].get("sim_weeks", 0) if snap_at_t else 0
        print(f"  {t:8.0f} {sw:7.2f}  {'  '.join(parts)}")

    # ── Placement health over time ──
    print("\n" + "=" * 70)
    print("PLACEMENT HEALTH OVER TIME (reliable nodes only)")
    print("=" * 70)

    reliable_nodes = [n for n, s in latest.items() if s["archetype"] == "reliable"]
    time_placement: dict[float, dict[str, int]] = {}
    for s in snapshots:
        if s["node"] in reliable_nodes:
            t = s["elapsed_s"]
            if t not in time_placement:
                time_placement[t] = {"alive": 0, "lost": 0, "ok": 0, "risk": 0}
            time_placement[t]["alive"] += s.get("placement_alive", 0)
            time_placement[t]["lost"] += s.get("placement_lost", 0)
            time_placement[t]["ok"] += s.get("blocks_ok", 0)
            time_placement[t]["risk"] += s.get("blocks_at_risk", 0)

    print(f"\n  {'elapsed':>8s} {'sim_wk':>7s}  {'alive':>6s} {'lost':>6s} {'ok':>6s} {'risk':>6s}")
    print(f"  {'─' * 8} {'─' * 7}  {'─' * 6} {'─' * 6} {'─' * 6} {'─' * 6}")
    for t in sample_times:
        p = time_placement.get(t, {})
        snap_at_t = [s for s in snapshots if s["elapsed_s"] == t]
        sw = snap_at_t[0].get("sim_weeks", 0) if snap_at_t else 0
        print(f"  {t:8.0f} {sw:7.2f}  "
              f"{p.get('alive', 0):6d} {p.get('lost', 0):6d} "
              f"{p.get('ok', 0):6d} {p.get('risk', 0):6d}")

    # ── Flaky node events ──
    flaky_events = [e for e in events if e["event"] in ("flaky_stop", "flaky_start")]
    if flaky_events:
        print(f"\n  Flaky toggles: {len(flaky_events)} total")
        stops = sum(1 for e in flaky_events if e["event"] == "flaky_stop")
        starts = sum(1 for e in flaky_events if e["event"] == "flaky_start")
        print(f"    stops={stops}, restarts={starts}")

    # ── Per-peer trust at end (detailed) ──
    print("\n" + "=" * 70)
    print("PER-PEER TRUST (from reliable node-00 perspective)")
    print("=" * 70)

    # Get node identities from latest snapshots
    node_id_to_name = {}
    for node, s in latest.items():
        # Build map from peers array in other nodes' snapshots
        pass

    # Just show node-00's peer list
    n0 = latest.get("node-00")
    if n0 and n0.get("peers"):
        print(f"\n  {'peer_id':>16s}  {'trust':>7s}  {'P':>6s}  {'I':>6s}  {'S':>6s}  {'we_store':>10s}  {'they_store':>10s}")
        print(f"  {'─' * 16}  {'─' * 7}  {'─' * 6}  {'─' * 6}  {'─' * 6}  {'─' * 10}  {'─' * 10}")
        for p in sorted(n0["peers"], key=lambda x: -x.get("trust", 0)):
            print(f"  {p['id']:>16s}  {p['trust']:7.4f}  {p['trust_p']:6.4f}  "
                  f"{p['trust_i']:6.4f}  {p['trust_s']:6.4f}  "
                  f"{p.get('bytes_we_store', 0)//1024:>8d}KB  "
                  f"{p.get('bytes_peer_stores', 0)//1024:>8d}KB")

    print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <results_dir>")
        sys.exit(1)
    analyze(Path(sys.argv[1]))
