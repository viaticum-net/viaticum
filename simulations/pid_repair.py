"""
Viaticum Simulation #3: D-component as Early Warning for Repair

Question: Does monitoring the D (derivative/trend) component of peer reputation
allow earlier repair initiation and improve data survival?

Hypothesis: PI-only repair triggers when P drops below threshold (peer already bad).
PID repair triggers when D goes negative (peer is declining, not yet bad).
Earlier repair = fewer concurrent shard losses = better survival.

Model:
- N peers with DYNAMIC reliability (can change over time — the key difference)
- Peer lifecycle: stable → declining → departed (or recovered)
- Two repair strategies compared:
  A) PI-trigger: repair when P_score < threshold
  B) PID-trigger: repair when D_score < negative threshold (earlier)
- Same erasure coding, same churn, same everything else
- Metric: file survival rate, repair lead time, false positive rate

Usage:
    python pid_repair.py                     # default comparison
    python pid_repair.py --sweep --jobs 24   # parameter sweep
"""

import argparse
import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path

import numpy as np
from joblib import Parallel, delayed


@dataclass
class Config:
    n_peers: int = 200
    n_files: int = 1000
    n_days: int = 365 * 3
    n_seeds: int = 100
    # Erasure coding
    k: int = 6
    n_shards: int = 10
    # Churn — peers go through lifecycle
    annual_churn: float = 0.3
    decline_duration_days: int = 30   # how long decline phase lasts
    # Peer reliability
    healthy_reliability: float = 0.95
    declining_reliability_start: float = 0.90
    declining_reliability_end: float = 0.20
    # PID parameters (from experiment 1)
    p_window: int = 30
    # Repair
    repair_delay_days: int = 7
    check_interval_days: int = 7
    # Trigger thresholds
    pi_threshold: float = 0.6       # PI: repair when P < this
    d_threshold: float = -0.015     # PID: repair when D < this (negative = declining)


class PeerState:
    """Tracks the lifecycle of one peer."""
    HEALTHY = 0
    DECLINING = 1
    DEPARTED = 2

    def __init__(self, peer_id, rng, config):
        self.id = peer_id
        self.state = self.HEALTHY
        self.true_reliability = config.healthy_reliability
        self.decline_day = -1
        self.depart_day = -1
        self._schedule_departure(rng, config, start_day=0)

    def _schedule_departure(self, rng, config, start_day):
        p_leave_daily = 1.0 - (1.0 - config.annual_churn) ** (1.0 / 365.0)
        days_until_leave = rng.geometric(p_leave_daily)
        self.depart_day = start_day + days_until_leave
        self.decline_day = self.depart_day - config.decline_duration_days

    def update(self, day, config):
        if self.state == self.DEPARTED:
            return
        if day >= self.depart_day:
            self.state = self.DEPARTED
            self.true_reliability = 0.0
        elif day >= self.decline_day:
            self.state = self.DECLINING
            progress = (day - self.decline_day) / config.decline_duration_days
            self.true_reliability = (
                config.declining_reliability_start * (1 - progress)
                + config.declining_reliability_end * progress
            )
        else:
            self.state = self.HEALTHY
            self.true_reliability = config.healthy_reliability

    def is_online(self):
        return self.state != self.DEPARTED


def simulate_one(config: Config, seed: int):
    """Run one simulation comparing PI vs PID repair strategies."""
    rng = np.random.default_rng(seed)

    # Initialize peers
    peers = [PeerState(i, rng, config) for i in range(config.n_peers)]
    next_peer_id = config.n_peers

    # Initialize files — shards placed on random peers
    online_ids = [p.id for p in peers if p.is_online()]
    file_shards_pi = []   # strategy A: PI-triggered repair
    file_shards_pid = []  # strategy B: PID-triggered repair
    for _ in range(config.n_files):
        holders = list(rng.choice(online_ids, size=config.n_shards, replace=False))
        file_shards_pi.append(holders.copy())
        file_shards_pid.append(holders.copy())

    file_alive_pi = np.ones(config.n_files, dtype=bool)
    file_alive_pid = np.ones(config.n_files, dtype=bool)

    # PID tracking per peer (observer's view)
    p_scores = np.full(config.n_peers + 1000, 0.95)  # pre-allocate
    i_scores = np.full(config.n_peers + 1000, 0.95)
    d_scores = np.zeros(config.n_peers + 1000)
    prev_p = np.full(config.n_peers + 1000, 0.95)
    window_buf = np.ones((config.p_window, config.n_peers + 1000))

    # Pending repairs: (file_idx, completion_day, new_holders)
    pending_pi = []
    pending_pid = []

    # Metrics
    repairs_pi = 0
    repairs_pid = 0
    early_detections = 0  # times PID triggered before PI would have

    checkpoints = [365, 365*2, 365*3]
    survival_pi_at = {}
    survival_pid_at = {}

    for day in range(config.n_days):
        # --- Update peer lifecycles ---
        for peer in peers:
            peer.update(day, config)

        # --- Add new peers (monthly) ---
        if day > 0 and day % 30 == 0:
            for _ in range(10):
                new_peer = PeerState(next_peer_id, rng, config)
                new_peer._schedule_departure(rng, config, start_day=day)
                peers.append(new_peer)
                next_peer_id += 1

        # --- Proof-of-storage checks (daily, for PID tracking) ---
        for peer in peers:
            pid = peer.id
            if pid >= len(p_scores):
                continue
            if peer.is_online():
                check = 1.0 if rng.random() < peer.true_reliability else 0.0
            else:
                check = 0.0

            # Rolling window P
            window_buf[day % config.p_window, pid] = check
            filled = min(day + 1, config.p_window)
            p_scores[pid] = window_buf[:filled, pid].mean()

            # Cumulative I
            i_scores[pid] = (i_scores[pid] * day + check) / (day + 1)

            # D: rate of change
            d_scores[pid] = p_scores[pid] - prev_p[pid]
            prev_p[pid] = p_scores[pid]

        # --- Complete pending repairs ---
        def complete_repairs(pending, file_shards, file_alive):
            still_pending = []
            completed = 0
            for (fidx, comp_day, new_holders) in pending:
                if day >= comp_day and file_alive[fidx]:
                    for pid in new_holders:
                        # Check peer still online
                        peer_obj = None
                        for p in peers:
                            if p.id == pid:
                                peer_obj = p
                                break
                        if peer_obj and peer_obj.is_online():
                            if len(file_shards[fidx]) < config.n_shards:
                                file_shards[fidx].append(pid)
                                completed += 1
                elif day < comp_day:
                    still_pending.append((fidx, comp_day, new_holders))
            return still_pending, completed

        pending_pi, rep = complete_repairs(pending_pi, file_shards_pi, file_alive_pi)
        repairs_pi += rep
        pending_pid, rep = complete_repairs(pending_pid, file_shards_pid, file_alive_pid)
        repairs_pid += rep

        # --- Check files and trigger repairs (periodic) ---
        if day % config.check_interval_days == 0:
            online_set = set(p.id for p in peers if p.is_online())
            available = [p.id for p in peers if p.is_online()
                         and p.state == PeerState.HEALTHY]

            for fidx in range(config.n_files):
                # --- Strategy A: PI-trigger ---
                if file_alive_pi[fidx]:
                    live = [pid for pid in file_shards_pi[fidx] if pid in online_set]
                    if len(live) < config.k:
                        file_alive_pi[fidx] = False
                    else:
                        file_shards_pi[fidx] = live
                        # PI trigger: any shard holder with P < threshold?
                        suspect = [pid for pid in live
                                   if p_scores[pid] < config.pi_threshold]
                        missing = config.n_shards - len(live) + len(suspect)
                        if missing > 0 and available:
                            current = set(file_shards_pi[fidx])
                            cands = [p for p in available if p not in current]
                            if cands:
                                n_new = min(missing, len(cands))
                                new_h = list(rng.choice(cands, size=n_new, replace=False))
                                pending_pi.append((fidx, day + config.repair_delay_days, new_h))

                # --- Strategy B: PID-trigger ---
                if file_alive_pid[fidx]:
                    live = [pid for pid in file_shards_pid[fidx] if pid in online_set]
                    if len(live) < config.k:
                        file_alive_pid[fidx] = False
                    else:
                        file_shards_pid[fidx] = live
                        # PID trigger: any shard holder with D < threshold?
                        suspect_d = [pid for pid in live
                                     if d_scores[pid] < config.d_threshold]
                        # Also PI trigger as fallback
                        suspect_p = [pid for pid in live
                                     if p_scores[pid] < config.pi_threshold]
                        suspect = list(set(suspect_d + suspect_p))

                        # Track early detection
                        d_only = set(suspect_d) - set(suspect_p)
                        if d_only:
                            early_detections += len(d_only)

                        missing = config.n_shards - len(live) + len(suspect)
                        if missing > 0 and available:
                            current = set(file_shards_pid[fidx])
                            cands = [p for p in available if p not in current]
                            if cands:
                                n_new = min(missing, len(cands))
                                new_h = list(rng.choice(cands, size=n_new, replace=False))
                                pending_pid.append((fidx, day + config.repair_delay_days, new_h))

        # --- Record checkpoints ---
        if (day + 1) in checkpoints:
            survival_pi_at[day + 1] = float(file_alive_pi.sum()) / config.n_files
            survival_pid_at[day + 1] = float(file_alive_pid.sum()) / config.n_files

    return {
        "pi_survival": survival_pi_at,
        "pid_survival": survival_pid_at,
        "pi_final": float(file_alive_pi.sum()) / config.n_files,
        "pid_final": float(file_alive_pid.sum()) / config.n_files,
        "pi_repairs": repairs_pi,
        "pid_repairs": repairs_pid,
        "early_detections": early_detections,
    }


def run_experiment(config: Config, n_jobs: int = 1):
    """Run Monte Carlo comparison."""
    t0 = time.time()

    if n_jobs == 1:
        results = [simulate_one(config, seed) for seed in range(config.n_seeds)]
    else:
        results = Parallel(n_jobs=n_jobs)(
            delayed(simulate_one)(config, seed)
            for seed in range(config.n_seeds)
        )

    elapsed = time.time() - t0

    pi_finals = [r["pi_final"] for r in results]
    pid_finals = [r["pid_final"] for r in results]
    pi_repairs = [r["pi_repairs"] for r in results]
    pid_repairs = [r["pid_repairs"] for r in results]
    early = [r["early_detections"] for r in results]

    # Checkpoint aggregation
    all_days = set()
    for r in results:
        all_days.update(r["pi_survival"].keys())

    checkpoints = {}
    for d in sorted(all_days):
        pi_vals = [r["pi_survival"].get(d, np.nan) for r in results]
        pid_vals = [r["pid_survival"].get(d, np.nan) for r in results]
        pi_vals = [v for v in pi_vals if not np.isnan(v)]
        pid_vals = [v for v in pid_vals if not np.isnan(v)]
        if pi_vals and pid_vals:
            checkpoints[int(d)] = {
                "pi_mean": float(np.mean(pi_vals)),
                "pid_mean": float(np.mean(pid_vals)),
                "pi_p5": float(np.percentile(pi_vals, 5)),
                "pid_p5": float(np.percentile(pid_vals, 5)),
            }

    return {
        "config": asdict(config),
        "elapsed_sec": elapsed,
        "checkpoints": checkpoints,
        "pi_final_mean": float(np.mean(pi_finals)),
        "pid_final_mean": float(np.mean(pid_finals)),
        "pi_final_p5": float(np.percentile(pi_finals, 5)),
        "pid_final_p5": float(np.percentile(pid_finals, 5)),
        "pi_final_min": float(np.min(pi_finals)),
        "pid_final_min": float(np.min(pid_finals)),
        "pi_repairs_mean": float(np.mean(pi_repairs)),
        "pid_repairs_mean": float(np.mean(pid_repairs)),
        "early_detections_mean": float(np.mean(early)),
    }


def print_summary(result: dict):
    cfg = result["config"]
    print(f"Config: {cfg['n_peers']} peers, {cfg['n_files']} files, "
          f"{cfg['n_days']//365}y")
    print(f"Erasure: {cfg['k']}-of-{cfg['n_shards']}, "
          f"churn: {cfg['annual_churn']*100:.0f}%/y, "
          f"decline: {cfg['decline_duration_days']}d")
    print(f"PI threshold: P<{cfg['pi_threshold']}, "
          f"PID threshold: D<{cfg['d_threshold']}")
    print(f"Seeds: {cfg['n_seeds']}, runtime: {result['elapsed_sec']:.1f}s")
    print()

    print("Survival comparison (PI vs PID):")
    for day, stats in sorted(result["checkpoints"].items()):
        years = day / 365
        diff = stats["pid_mean"] - stats["pi_mean"]
        print(f"  Year {years:.0f}: PI={stats['pi_mean']*100:.2f}% "
              f"PID={stats['pid_mean']*100:.2f}% "
              f"(delta={diff*100:+.2f}%)")

    print()
    pi_f = result["pi_final_mean"]
    pid_f = result["pid_final_mean"]
    diff = pid_f - pi_f
    print(f"Final:  PI={pi_f*100:.2f}% (p5={result['pi_final_p5']*100:.1f}%, "
          f"min={result['pi_final_min']*100:.1f}%)")
    print(f"        PID={pid_f*100:.2f}% (p5={result['pid_final_p5']*100:.1f}%, "
          f"min={result['pid_final_min']*100:.1f}%)")
    print(f"        Delta: {diff*100:+.2f}%")
    print()
    print(f"Repairs: PI={result['pi_repairs_mean']:.0f}, "
          f"PID={result['pid_repairs_mean']:.0f}")
    print(f"Early detections (D caught before P): "
          f"{result['early_detections_mean']:.0f}/run")


def save_results(result: dict, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2))
    print(f"\nResults saved to {path}")


def _evaluate_sweep(n_peers, n_files, k, n_shards, churn, decline,
                    repair_delay, d_thresh, n_days, n_seeds):
    cfg = Config(
        n_peers=n_peers, n_files=n_files, k=k, n_shards=n_shards,
        annual_churn=churn, decline_duration_days=decline,
        repair_delay_days=repair_delay,
        d_threshold=d_thresh, n_days=n_days, n_seeds=n_seeds,
    )
    res = run_experiment(cfg, n_jobs=1)
    return {
        "k": k, "n": n_shards, "churn": churn,
        "decline": decline, "repair_delay": repair_delay,
        "d_thresh": d_thresh,
        "pi_3y": res["pi_final_mean"],
        "pid_3y": res["pid_final_mean"],
        "delta": res["pid_final_mean"] - res["pi_final_mean"],
        "early_det": res["early_detections_mean"],
    }


def run_sweep(base_config: Config, output_dir: Path, n_jobs: int = 1):
    churn_rates = [0.5, 0.7]
    decline_durations = [14, 30]
    repair_delays = [7, 14, 30]
    d_thresholds = [-0.005, -0.01, -0.02]

    tasks = []
    for churn in churn_rates:
        for decline in decline_durations:
            for repair_delay in repair_delays:
                for d_thresh in d_thresholds:
                    tasks.append((
                        base_config.n_peers, base_config.n_files,
                        base_config.k, base_config.n_shards,
                        churn, decline, repair_delay, d_thresh,
                        base_config.n_days, 30,
                    ))

    total = len(tasks)
    print(f"Sweep: {total} configs, {n_jobs} jobs\n")

    if n_jobs == 1:
        results_table = []
        for i, t in enumerate(tasks, 1):
            r = _evaluate_sweep(*t)
            results_table.append(r)
            print(f"  [{i}/{total}] churn={r['churn']*100:.0f}% "
                  f"decl={r['decline']}d rep={r['repair_delay']}d "
                  f"D<{r['d_thresh']} "
                  f"→ PI={r['pi_3y']*100:.1f}% PID={r['pid_3y']*100:.1f}% "
                  f"delta={r['delta']*100:+.2f}%")
    else:
        t0 = time.time()
        results_table = Parallel(n_jobs=n_jobs, verbose=10)(
            delayed(_evaluate_sweep)(*t) for t in tasks
        )
        elapsed = time.time() - t0
        print(f"\nSweep completed in {elapsed:.1f}s")

    results_table.sort(key=lambda r: -r["delta"])

    print("\n=== TOP CONFIGS BY PID ADVANTAGE ===")
    print(f"{'churn':>6} {'decl':>5} {'rep':>4} {'d_thr':>7} "
          f"{'PI_3y%':>7} {'PID_3y%':>8} {'delta%':>7} {'early':>6}")
    for r in results_table[:15]:
        print(f"{r['churn']*100:>5.0f}% {r['decline']:>4}d {r['repair_delay']:>3}d "
              f"{r['d_thresh']:>7.3f} "
              f"{r['pi_3y']*100:>6.1f}% {r['pid_3y']*100:>7.1f}% "
              f"{r['delta']*100:>+6.2f}% {r['early_det']:>5.0f}")

    sweep_path = output_dir / "sweep_results.json"
    sweep_path.parent.mkdir(parents=True, exist_ok=True)
    sweep_path.write_text(json.dumps(results_table, indent=2))
    print(f"\nFull sweep saved to {sweep_path}")


def main():
    parser = argparse.ArgumentParser(description="PID Repair Early Warning")
    parser.add_argument("--peers", type=int, default=200)
    parser.add_argument("--files", type=int, default=1000)
    parser.add_argument("--days", type=int, default=365*3)
    parser.add_argument("--seeds", type=int, default=100)
    parser.add_argument("--k", type=int, default=6)
    parser.add_argument("--n-shards", type=int, default=10)
    parser.add_argument("--churn", type=float, default=0.5)
    parser.add_argument("--decline", type=int, default=30)
    parser.add_argument("--repair-delay", type=int, default=7)
    parser.add_argument("--d-threshold", type=float, default=-0.015)
    parser.add_argument("--sweep", action="store_true")
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--output", type=str, default="results/pid_repair")
    args = parser.parse_args()

    config = Config(
        n_peers=args.peers, n_files=args.files, n_days=args.days,
        n_seeds=args.seeds, k=args.k, n_shards=args.n_shards,
        annual_churn=args.churn, decline_duration_days=args.decline,
        repair_delay_days=args.repair_delay, d_threshold=args.d_threshold,
    )

    output_dir = Path(args.output)

    if args.sweep:
        print("=== PID vs PI REPAIR SWEEP ===\n")
        run_sweep(config, output_dir, n_jobs=args.jobs)
    else:
        print("=== PID vs PI REPAIR COMPARISON ===\n")
        result = run_experiment(config, n_jobs=args.jobs)
        print_summary(result)
        save_results(result, output_dir / "run.json")


if __name__ == "__main__":
    main()
