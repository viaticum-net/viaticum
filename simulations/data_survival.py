"""
SyncBack Simulation #2: Data Survival Under Churn

Question: What fraction of files survive 1-5 years with 30-50% annual churn?
How does erasure coding (k-of-n) affect survival?

Model:
- N peers, each with exponential or Weibull on/off sessions
- Each file = k-of-n erasure coded shards on n distinct peers
- File is LOST when fewer than k shards are on live peers simultaneously
- Repair process: when owner detects missing shards, places new ones
  - Repair has latency (days, not instant — cold backup model)
  - Repair requires k live shards to reconstruct
- Churn: annual churn rate → per-day leave probability

Metrics:
- File survival rate at 1, 2, 5 years
- Mean Time To Data Loss (MTTDL)
- Repair traffic (shards repaired per year)

Usage:
    python data_survival.py                          # default run
    python data_survival.py --churn 0.5              # 50% annual churn
    python data_survival.py --sweep --jobs 24        # parameter sweep
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
    n_peers: int = 500
    n_files: int = 1000
    n_days: int = 365 * 3        # 3 years
    n_seeds: int = 100
    # Erasure coding
    k: int = 5                    # need k shards to reconstruct
    n: int = 15                   # total shards per file
    # Churn
    annual_churn: float = 0.3     # 30% of peers leave per year
    rejoin_prob: float = 0.5      # probability a departed peer comes back
    rejoin_delay_days: int = 30   # mean days before rejoin
    # Repair
    repair_delay_days: int = 7    # days between detection and repair completion
    check_interval_days: int = 7  # how often owner checks shard health
    # Network growth
    new_peers_per_month: int = 10  # new peers joining


def annual_churn_to_daily(annual_churn: float) -> float:
    """Convert annual churn rate to daily leave probability."""
    # P(leave in year) = 1 - (1 - p_daily)^365 = annual_churn
    # p_daily = 1 - (1 - annual_churn)^(1/365)
    return 1.0 - (1.0 - annual_churn) ** (1.0 / 365.0)


def simulate_one(config: Config, seed: int):
    """Simulate data survival for one run.

    Returns dict with survival stats.
    """
    rng = np.random.default_rng(seed)

    # Peer state: True = online, False = offline/departed
    n_total_peers = config.n_peers + config.new_peers_per_month * (config.n_days // 30)
    peer_online = np.zeros(n_total_peers, dtype=bool)
    peer_online[:config.n_peers] = True
    peer_active = np.zeros(n_total_peers, dtype=bool)  # ever joined
    peer_active[:config.n_peers] = True
    peer_rejoin_day = np.full(n_total_peers, -1, dtype=int)  # scheduled rejoin
    next_peer_id = config.n_peers

    p_leave = annual_churn_to_daily(config.annual_churn)

    # File shards: file_shards[f] = list of peer_ids holding shards
    file_shards = []
    active_peers = np.where(peer_online)[0]
    for _ in range(config.n_files):
        holders = rng.choice(active_peers, size=config.n, replace=False)
        file_shards.append(list(holders))

    # Track file state
    file_alive = np.ones(config.n_files, dtype=bool)
    # Pending repairs: list of (file_idx, completion_day)
    pending_repairs = []

    # Metrics
    survival_at = {}  # day -> survival fraction
    total_repairs = 0
    check_points = [365, 365*2, 365*3, 365*5]

    for day in range(config.n_days):
        # --- Churn: peers leave ---
        online_mask = peer_online.copy()
        for pid in np.where(online_mask)[0]:
            if rng.random() < p_leave:
                peer_online[pid] = False
                # Schedule potential rejoin
                if rng.random() < config.rejoin_prob:
                    delay = rng.geometric(1.0 / config.rejoin_delay_days)
                    peer_rejoin_day[pid] = day + delay

        # --- Rejoin: peers come back ---
        rejoining = np.where(peer_rejoin_day == day)[0]
        for pid in rejoining:
            peer_online[pid] = True
            peer_rejoin_day[pid] = -1

        # --- New peers join (monthly) ---
        if day > 0 and day % 30 == 0:
            for _ in range(config.new_peers_per_month):
                if next_peer_id < n_total_peers:
                    peer_online[next_peer_id] = True
                    peer_active[next_peer_id] = True
                    next_peer_id += 1

        # --- Complete pending repairs ---
        still_pending = []
        for (fidx, completion_day, new_holders) in pending_repairs:
            if day >= completion_day and file_alive[fidx]:
                # Add new shards (only if peers still online)
                for pid in new_holders:
                    if peer_online[pid] and len(file_shards[fidx]) < config.n:
                        file_shards[fidx].append(pid)
                total_repairs += len(new_holders)
            elif day < completion_day:
                still_pending.append((fidx, completion_day, new_holders))
        pending_repairs = still_pending

        # --- Owner checks shard health (periodic) ---
        if day % config.check_interval_days == 0:
            online_set = set(np.where(peer_online)[0])
            available_for_repair = np.where(peer_online)[0]

            for fidx in range(config.n_files):
                if not file_alive[fidx]:
                    continue

                # Count live shards
                live = [pid for pid in file_shards[fidx] if pid in online_set]
                n_live = len(live)

                if n_live < config.k:
                    # FILE LOST: can't reconstruct
                    file_alive[fidx] = False
                    continue

                # Remove dead shards from tracking
                file_shards[fidx] = live

                # Need repair?
                missing = config.n - n_live
                if missing > 0 and len(available_for_repair) > 0:
                    # Pick new holders (not already holding this file)
                    current = set(file_shards[fidx])
                    candidates = [p for p in available_for_repair if p not in current]
                    if candidates:
                        n_new = min(missing, len(candidates))
                        new_holders = rng.choice(candidates, size=n_new, replace=False)
                        completion = day + config.repair_delay_days
                        pending_repairs.append((fidx, completion, list(new_holders)))

        # --- Record survival at checkpoints ---
        if (day + 1) in check_points:
            survival_at[day + 1] = float(file_alive.sum()) / config.n_files

    # Final stats
    return {
        "survival": survival_at,
        "final_alive": int(file_alive.sum()),
        "final_rate": float(file_alive.sum()) / config.n_files,
        "total_repairs": total_repairs,
        "repairs_per_file_per_year": total_repairs / config.n_files / (config.n_days / 365),
    }


def run_experiment(config: Config, n_jobs: int = 1):
    """Run Monte Carlo experiment."""
    t0 = time.time()

    if n_jobs == 1:
        results = [simulate_one(config, seed) for seed in range(config.n_seeds)]
    else:
        results = Parallel(n_jobs=n_jobs)(
            delayed(simulate_one)(config, seed)
            for seed in range(config.n_seeds)
        )

    elapsed = time.time() - t0

    # Aggregate
    final_rates = [r["final_rate"] for r in results]
    repairs = [r["repairs_per_file_per_year"] for r in results]

    # Survival at checkpoints
    all_days = set()
    for r in results:
        all_days.update(r["survival"].keys())
    survival_stats = {}
    for d in sorted(all_days):
        vals = [r["survival"].get(d, np.nan) for r in results]
        vals = [v for v in vals if not np.isnan(v)]
        if vals:
            survival_stats[int(d)] = {
                "mean": float(np.mean(vals)),
                "std": float(np.std(vals)),
                "min": float(np.min(vals)),
                "p5": float(np.percentile(vals, 5)),
            }

    return {
        "config": asdict(config),
        "elapsed_sec": elapsed,
        "survival_at_checkpoints": survival_stats,
        "final_rate_mean": float(np.mean(final_rates)),
        "final_rate_std": float(np.std(final_rates)),
        "final_rate_min": float(np.min(final_rates)),
        "final_rate_p5": float(np.percentile(final_rates, 5)),
        "repairs_per_file_year_mean": float(np.mean(repairs)),
    }


def print_summary(result: dict):
    """Print human-readable summary."""
    cfg = result["config"]
    print(f"Config: {cfg['n_peers']} peers, {cfg['n_files']} files, "
          f"{cfg['n_days']} days ({cfg['n_days']//365}y)")
    print(f"Erasure: {cfg['k']}-of-{cfg['n']}, "
          f"churn: {cfg['annual_churn']*100:.0f}%/year, "
          f"repair delay: {cfg['repair_delay_days']}d, "
          f"check interval: {cfg['check_interval_days']}d")
    print(f"Seeds: {cfg['n_seeds']}, runtime: {result['elapsed_sec']:.1f}s")
    print()

    print("Survival rate:")
    for day, stats in sorted(result["survival_at_checkpoints"].items()):
        years = day / 365
        print(f"  Year {years:.0f}: {stats['mean']*100:.2f}% "
              f"(worst: {stats['min']*100:.1f}%, "
              f"p5: {stats['p5']*100:.1f}%)")

    print()
    print(f"Final: {result['final_rate_mean']*100:.2f}% survive "
          f"(p5: {result['final_rate_p5']*100:.1f}%, "
          f"min: {result['final_rate_min']*100:.1f}%)")
    print(f"Repair traffic: {result['repairs_per_file_year_mean']:.1f} "
          f"shards/file/year")


def save_results(result: dict, path: Path):
    """Save results to JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2))
    print(f"\nResults saved to {path}")


def _evaluate_config(n_peers, n_files, k, n, churn, repair_delay,
                     check_interval, n_days, n_seeds):
    """Evaluate single config for sweep."""
    cfg = Config(
        n_peers=n_peers, n_files=n_files, k=k, n=n,
        annual_churn=churn, repair_delay_days=repair_delay,
        check_interval_days=check_interval, n_days=n_days,
        n_seeds=n_seeds,
    )
    res = run_experiment(cfg, n_jobs=1)
    return {
        "k": k, "n": n, "churn": churn,
        "repair_delay": repair_delay, "check_interval": check_interval,
        "survival_1y": res["survival_at_checkpoints"].get(365, {}).get("mean", -1),
        "survival_3y": res["final_rate_mean"],
        "survival_3y_p5": res["final_rate_p5"],
        "repairs_per_year": res["repairs_per_file_year_mean"],
    }


def run_sweep(base_config: Config, output_dir: Path, n_jobs: int = 1):
    """Sweep erasure coding params and churn rates."""
    # Erasure coding configs: (k, n)
    coding_configs = [
        (3, 10),   # low redundancy
        (5, 15),   # standard (documents)
        (4, 10),   # photos
        (6, 10),   # video (low overhead)
        (3, 20),   # high redundancy (critical documents)
    ]
    churn_rates = [0.1, 0.2, 0.3, 0.5]
    repair_delays = [3, 7, 14]

    tasks = []
    for k, n in coding_configs:
        for churn in churn_rates:
            for delay in repair_delays:
                tasks.append((
                    base_config.n_peers, base_config.n_files,
                    k, n, churn, delay,
                    base_config.check_interval_days,
                    base_config.n_days, 30,  # fewer seeds for sweep
                ))

    total = len(tasks)
    print(f"Sweep: {total} configs, {n_jobs} jobs\n")

    if n_jobs == 1:
        results_table = []
        for i, t in enumerate(tasks, 1):
            r = _evaluate_config(*t)
            results_table.append(r)
            print(f"  [{i}/{total}] {r['k']}-of-{r['n']} "
                  f"churn={r['churn']*100:.0f}% "
                  f"delay={r['repair_delay']}d "
                  f"→ 1y={r['survival_1y']*100:.1f}% "
                  f"3y={r['survival_3y']*100:.1f}%")
    else:
        t0 = time.time()
        results_table = Parallel(n_jobs=n_jobs, verbose=10)(
            delayed(_evaluate_config)(*t) for t in tasks
        )
        elapsed = time.time() - t0
        print(f"\nSweep completed in {elapsed:.1f}s")

    # Sort by 3-year survival
    results_table.sort(key=lambda r: -r["survival_3y"])

    print("\n=== RESULTS (sorted by 3-year survival) ===")
    print(f"{'k-of-n':>7} {'churn':>6} {'delay':>5} "
          f"{'1y%':>7} {'3y%':>7} {'3y_p5%':>7} {'repairs/y':>9}")
    for r in results_table:
        s1 = f"{r['survival_1y']*100:.1f}" if r['survival_1y'] > 0 else "n/a"
        print(f"{r['k']}-of-{r['n']:>2} "
              f"{r['churn']*100:>5.0f}% {r['repair_delay']:>4}d "
              f"{s1:>7} {r['survival_3y']*100:>6.1f}% "
              f"{r['survival_3y_p5']*100:>6.1f}% "
              f"{r['repairs_per_year']:>8.1f}")

    sweep_path = output_dir / "sweep_results.json"
    sweep_path.parent.mkdir(parents=True, exist_ok=True)
    sweep_path.write_text(json.dumps(results_table, indent=2))
    print(f"\nFull sweep saved to {sweep_path}")


def main():
    parser = argparse.ArgumentParser(description="Data Survival Under Churn")
    parser.add_argument("--peers", type=int, default=500)
    parser.add_argument("--files", type=int, default=1000)
    parser.add_argument("--days", type=int, default=365*3)
    parser.add_argument("--seeds", type=int, default=100)
    parser.add_argument("--k", type=int, default=5)
    parser.add_argument("--n", type=int, default=15)
    parser.add_argument("--churn", type=float, default=0.3)
    parser.add_argument("--repair-delay", type=int, default=7)
    parser.add_argument("--check-interval", type=int, default=7)
    parser.add_argument("--sweep", action="store_true")
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--output", type=str, default="results/data_survival")
    args = parser.parse_args()

    output_dir = Path(args.output)

    config = Config(
        n_peers=args.peers,
        n_files=args.files,
        n_days=args.days,
        n_seeds=args.seeds,
        k=args.k,
        n=args.n,
        annual_churn=args.churn,
        repair_delay_days=args.repair_delay,
        check_interval_days=args.check_interval,
    )

    if args.sweep:
        print("=== DATA SURVIVAL PARAMETER SWEEP ===\n")
        run_sweep(config, output_dir, n_jobs=args.jobs)
    else:
        print("=== DATA SURVIVAL UNDER CHURN ===\n")
        result = run_experiment(config, n_jobs=args.jobs)
        print_summary(result)
        save_results(result, output_dir / "run.json")


if __name__ == "__main__":
    main()
