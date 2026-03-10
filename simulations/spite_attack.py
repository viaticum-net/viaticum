"""
SyncBack Simulation #7: Targeted Spite Attack ("Обиженка")

Question: How many colluding nodes are needed to deny restore to a specific target?
How long must they wait, and what is the ROI?

Model:
- N honest peers + M attacker nodes. Both groups already have 6 months of honest
  reputation at simulation start (attacker nodes are ex-partners, rivals — real nodes
  that have been participating honestly for a long time).
- Attacker strategy: behave normally in all repair cycles (maintain high trust),
  but when TARGET requests restore, refuse to serve their shards.
- Target has n_files files, each erasure coded as k-of-n_shards shards distributed
  across the network using trust-weighted placement with subnet rate limit.
- Simulation runs weekly repair cycles for wait_years. Shards fail randomly; the
  repair process selects high-trust peers — attacker nodes compete for target's shards.
- At the end: target's disk fails. Attacker nodes refuse. File is lost if
  (surviving shards - attacker shards) < k.

Key differences from Sybil (Exp 04):
- Attacker nodes ALREADY have high trust at simulation start (not zero).
- Only ONE user is targeted (not network-wide).
- Attacker reliability = honest_reliability (they are real nodes, just refusing one user).
- Cost model uses GB-years (not GB-months), reflecting a years-long wait.

Metrics:
- p_restore_denied: probability target cannot restore a given file
- attacker_shards_per_file: mean attacker shards on target's files
- attack_cost_gb_years: M * wait_years * storage_per_node_gb
- roi: (files denied) / (GB-years)

Usage:
    python spite_attack.py                    # default run
    python spite_attack.py --sweep --jobs 4   # parameter sweep
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
    n_honest_peers: int = 500
    n_attackers: int = 20
    n_files: int = 1000
    n_seeds: int = 100
    # Erasure coding profile
    k: int = 5
    n_shards: int = 15
    # Attacker network topology
    attacker_subnets: int = 3     # how many /24 blocks attacker controls
    subnet_limit: int = 1         # max shards per /24 per file
    # How long attacker waits before target needs restore
    wait_years: float = 2.0
    # PID parameters (Kp=0.5, Ki=2.0)
    kp: float = 0.5
    ki: float = 2.0
    p_window: int = 30            # P: rolling window in days
    # Initial reputation buildup before simulation begins (both honest + attacker)
    initial_reputation_months: int = 6
    # Peer reliability (same for honest and attacker — attackers are real nodes)
    honest_reliability: float = 0.95
    # Repair cycle — weekly, as per cold backup model
    repair_interval_days: int = 7
    # Shard degradation: probability a shard needs repair each cycle
    shard_failure_prob: float = 0.02
    # Attack cost model
    storage_per_node_gb: float = 100.0


def _assign_subnets(n_honest: int, n_attackers: int, attacker_subnets: int) -> np.ndarray:
    # Honest peers: each in their own /24 (maximally spread).
    # Attacker nodes: distributed evenly across attacker_subnets blocks.
    n_total = n_honest + n_attackers
    subnets = np.empty(n_total, dtype=np.int32)
    subnets[:n_honest] = np.arange(n_honest)
    sybil_subnet_ids = n_honest + (np.arange(n_attackers) % attacker_subnets)
    subnets[n_honest:] = sybil_subnet_ids
    return subnets


def _build_pid_trust(n_total: int, reliability: np.ndarray, config: Config,
                     rng: np.random.Generator, n_days: int) -> np.ndarray:
    # Simulate PID trust accumulation over n_days.
    # All nodes (honest and attacker) use the same reliability during buildup —
    # attackers are behaving honestly here.
    p_score = np.full(n_total, 0.5)
    i_score = np.full(n_total, 0.5)
    window_buf = np.zeros((config.p_window, n_total))

    for t in range(n_days):
        checks = (rng.random(n_total) < reliability).astype(np.float64)
        window_buf[t % config.p_window] = checks
        filled = min(t + 1, config.p_window)
        p_score = window_buf[:filled].mean(axis=0)
        i_score = (i_score * t + checks) / (t + 1)

    return config.kp * p_score + config.ki * i_score


def _place_shards(n_shards: int, subnet_limit: int, trust: np.ndarray,
                  subnets: np.ndarray, excluded: set,
                  rng: np.random.Generator) -> list[int]:
    # Place n_shards shards on distinct peers using trust-weighted sampling with
    # subnet rate limit. excluded: peer IDs already holding a shard for this file.
    selected: list[int] = []
    subnet_counts: dict[int, int] = {}

    remaining = [
        i for i in range(len(trust))
        if i not in excluded and trust[i] > 0
    ]

    while len(selected) < n_shards and remaining:
        weights = np.array([trust[i] for i in remaining], dtype=np.float64)
        total_w = weights.sum()
        if total_w <= 0:
            break
        probs = weights / total_w
        idx = int(rng.choice(len(remaining), p=probs))
        peer = remaining[idx]
        subnet = subnets[peer]

        if subnet_counts.get(subnet, 0) < subnet_limit:
            selected.append(peer)
            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1

        remaining.pop(idx)
        # Remove all peers in a now-full subnet
        if subnet_counts.get(subnet, 0) >= subnet_limit:
            remaining = [p for p in remaining if subnets[p] != subnet]

    return selected


def simulate_one(config: Config, seed: int) -> dict:
    """Run one spite attack simulation. Returns per-run metrics."""
    rng = np.random.default_rng(seed)

    n_total = config.n_honest_peers + config.n_attackers
    is_attacker = np.zeros(n_total, dtype=bool)
    is_attacker[config.n_honest_peers:] = True

    subnets = _assign_subnets(config.n_honest_peers, config.n_attackers,
                               config.attacker_subnets)

    # All nodes have the same reliability — attackers are real peers that
    # cooperate normally with everyone except the target at restore time.
    reliability = np.full(n_total, config.honest_reliability)

    # Phase 0: initial reputation buildup (6 months).
    # Both honest and attacker nodes participate honestly and accumulate trust.
    initial_days = config.initial_reputation_months * 30
    trust = _build_pid_trust(n_total, reliability, config, rng, initial_days)

    # Place target's files using the already-established trust scores.
    # This reflects that the target stored their files after meeting these peers.
    file_shards: list[list[int]] = []
    for _ in range(config.n_files):
        holders = _place_shards(
            config.n_shards, config.subnet_limit,
            trust, subnets, set(), rng
        )
        file_shards.append(holders)

    # Phase 1: wait phase — attacker waits wait_years for target's disk to fail.
    # Weekly repair cycles run continuously. Attacker nodes behave honestly with
    # all peers (including the target's shards they hold). Over time, through
    # normal churn and repair, attackers may accumulate more shards of target's files.
    n_repair_cycles = int(config.wait_years * 365 / config.repair_interval_days)

    # Trust grows slowly over the wait period (attackers keep behaving honestly)
    # We recompute trust after the full wait period for placement decisions.
    # During repair cycles we use progressively updated trust snapshots at roughly
    # quarterly intervals to avoid recomputing every cycle (expensive).
    snapshot_interval = max(1, n_repair_cycles // 8)

    for cycle in range(n_repair_cycles):
        # Refresh trust snapshot periodically
        if cycle % snapshot_interval == 0:
            days_so_far = initial_days + cycle * config.repair_interval_days
            trust = _build_pid_trust(n_total, reliability, config, rng, days_so_far)

        for fidx in range(config.n_files):
            holders = file_shards[fidx]
            survived = [
                p for p in holders
                if rng.random() > config.shard_failure_prob
            ]
            n_lost = config.n_shards - len(survived)
            if n_lost > 0 and len(survived) >= config.k:
                new_shards = _place_shards(
                    n_lost, config.subnet_limit,
                    trust, subnets, set(survived), rng
                )
                file_shards[fidx] = survived + new_shards
            else:
                file_shards[fidx] = survived

    # Phase 2: target's disk fails — they need to restore.
    # Attacker nodes refuse to serve their shards of the target's files.
    # File survives if (total_shards - attacker_shards) >= k.
    files_denied = 0
    attacker_shard_counts: list[int] = []

    for fidx in range(config.n_files):
        holders = file_shards[fidx]
        n_attacker_shards = sum(1 for p in holders if is_attacker[p])
        n_honest_shards = len(holders) - n_attacker_shards
        attacker_shard_counts.append(n_attacker_shards)

        if n_honest_shards < config.k:
            files_denied += 1

    attacker_arr = np.array(attacker_shard_counts)
    p_denied = files_denied / config.n_files

    # Cost model: M nodes x wait_years x storage_per_node_gb
    attack_cost_gb_years = (
        config.n_attackers * config.wait_years * config.storage_per_node_gb
    )

    # ROI: files denied per GB-year of cost
    roi = files_denied / attack_cost_gb_years if attack_cost_gb_years > 0 else 0.0

    # Final trust for comparison
    total_days = initial_days + int(config.wait_years * 365)
    final_trust = _build_pid_trust(n_total, reliability, config, rng, total_days)

    return {
        "p_restore_denied": p_denied,
        "files_denied": files_denied,
        "attacker_shards_per_file_mean": float(attacker_arr.mean()),
        "attacker_shards_per_file_max": int(attacker_arr.max()) if len(attacker_arr) else 0,
        "p_file_with_any_attacker": float((attacker_arr > 0).mean()),
        "attacker_trust_mean": float(final_trust[is_attacker].mean()),
        "honest_trust_mean": float(final_trust[~is_attacker].mean()),
        "attack_cost_gb_years": attack_cost_gb_years,
        "roi_files_per_gb_year": roi,
    }


def run_experiment(config: Config, n_jobs: int = 1) -> dict:
    """Run Monte Carlo experiment across seeds."""
    t0 = time.time()

    if n_jobs == 1:
        results = [simulate_one(config, seed) for seed in range(config.n_seeds)]
    else:
        results = Parallel(n_jobs=n_jobs)(
            delayed(simulate_one)(config, seed)
            for seed in range(config.n_seeds)
        )

    elapsed = time.time() - t0

    denied = [r["p_restore_denied"] for r in results]
    attacker_shards = [r["attacker_shards_per_file_mean"] for r in results]
    attacker_trust = [r["attacker_trust_mean"] for r in results]
    honest_trust = [r["honest_trust_mean"] for r in results]
    roi_values = [r["roi_files_per_gb_year"] for r in results]

    return {
        "config": asdict(config),
        "elapsed_sec": elapsed,
        "p_restore_denied_mean": float(np.mean(denied)),
        "p_restore_denied_std": float(np.std(denied)),
        "p_restore_denied_p5": float(np.percentile(denied, 5)),
        "p_restore_denied_p95": float(np.percentile(denied, 95)),
        "p_restore_denied_max": float(np.max(denied)),
        "attacker_shards_per_file_mean": float(np.mean(attacker_shards)),
        "p_file_with_any_attacker": float(np.mean(
            [r["p_file_with_any_attacker"] for r in results]
        )),
        "attacker_trust_mean": float(np.mean(attacker_trust)),
        "honest_trust_mean": float(np.mean(honest_trust)),
        "attack_cost_gb_years": results[0]["attack_cost_gb_years"],
        "roi_files_per_gb_year_mean": float(np.mean(roi_values)),
    }


def print_summary(result: dict) -> None:
    """Print key attack metrics."""
    cfg = result["config"]
    print(f"Config: {cfg['n_honest_peers']} honest + {cfg['n_attackers']} attackers "
          f"({cfg['attacker_subnets']} subnets), {cfg['n_files']} target files")
    print(f"Erasure: {cfg['k']}-of-{cfg['n_shards']}, "
          f"wait: {cfg['wait_years']} years, "
          f"initial_reputation: {cfg['initial_reputation_months']} months, "
          f"subnet_limit: {cfg['subnet_limit']} shard/subnet")
    print(f"Seeds: {cfg['n_seeds']}, runtime: {result['elapsed_sec']:.1f}s")
    print()

    p = result["p_restore_denied_mean"]
    print(f"P(restore_denied): mean={p*100:.2f}%  "
          f"p5={result['p_restore_denied_p5']*100:.2f}%  "
          f"p95={result['p_restore_denied_p95']*100:.2f}%  "
          f"max={result['p_restore_denied_max']*100:.2f}%")
    print(f"Attacker shards/file (mean): {result['attacker_shards_per_file_mean']:.2f} "
          f"/ {cfg['n_shards']} total "
          f"(max per subnet: {cfg['attacker_subnets']})")
    print(f"Files with >=1 attacker shard: {result['p_file_with_any_attacker']*100:.1f}%")
    print()
    print(f"Trust after wait period:  "
          f"attackers={result['attacker_trust_mean']:.3f}  "
          f"honest={result['honest_trust_mean']:.3f}")
    tolerance = cfg['n_shards'] - cfg['k']
    print(f"Tolerance: file survives up to {tolerance} withheld shards "
          f"(n - k = {cfg['n_shards']} - {cfg['k']})")
    print()
    cost = result["attack_cost_gb_years"]
    roi = result["roi_files_per_gb_year_mean"]
    print(f"Attack cost: {cost:.0f} GB-years "
          f"({cfg['n_attackers']} nodes x {cfg['wait_years']:.0f}yr "
          f"x {cfg['storage_per_node_gb']:.0f}GB)")
    print(f"ROI: {roi:.4f} files denied per GB-year")


def save_results(result: dict, path: Path) -> None:
    """Save results to JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2))
    print(f"\nResults saved to {path}")


def _evaluate_sweep(n_honest: int, n_attackers: int, n_files: int,
                    k: int, n_shards: int, attacker_subnets: int,
                    wait_years: float, n_seeds: int,
                    kp: float, ki: float, p_window: int) -> dict:
    cfg = Config(
        n_honest_peers=n_honest,
        n_attackers=n_attackers,
        n_files=n_files,
        k=k,
        n_shards=n_shards,
        attacker_subnets=attacker_subnets,
        wait_years=wait_years,
        n_seeds=n_seeds,
        kp=kp,
        ki=ki,
        p_window=p_window,
    )
    res = run_experiment(cfg, n_jobs=1)
    return {
        "n_attackers": n_attackers,
        "attacker_subnets": attacker_subnets,
        "wait_years": wait_years,
        "k": k,
        "n_shards": n_shards,
        "p_restore_denied_mean": res["p_restore_denied_mean"],
        "p_restore_denied_p95": res["p_restore_denied_p95"],
        "attacker_shards_per_file": res["attacker_shards_per_file_mean"],
        "attack_cost_gb_years": res["attack_cost_gb_years"],
        "roi_files_per_gb_year": res["roi_files_per_gb_year_mean"],
        "attacker_trust": res["attacker_trust_mean"],
        "honest_trust": res["honest_trust_mean"],
    }


def run_sweep(base_config: Config, output_dir: Path, n_jobs: int = 1) -> None:
    """Sweep n_attackers, attacker_subnets, wait_years across two erasure profiles."""
    n_attackers_values = [5, 10, 20, 50, 100]
    attacker_subnets_values = [1, 3, 5, 10]
    wait_years_values = [1, 2, 5]
    erasure_profiles = [(5, 15), (7, 10)]

    tasks = []
    for k, n_shards in erasure_profiles:
        for n_attackers in n_attackers_values:
            for attacker_subnets in attacker_subnets_values:
                for wait_years in wait_years_values:
                    tasks.append((
                        base_config.n_honest_peers,
                        n_attackers,
                        base_config.n_files,
                        k, n_shards,
                        attacker_subnets,
                        float(wait_years),
                        30,  # fewer seeds per config in sweep
                        base_config.kp,
                        base_config.ki,
                        base_config.p_window,
                    ))

    total = len(tasks)
    print(f"Sweep: {total} configs, {n_jobs} jobs\n")

    if n_jobs == 1:
        results_table = []
        for i, t in enumerate(tasks, 1):
            r = _evaluate_sweep(*t)
            results_table.append(r)
            print(f"  [{i}/{total}] attackers={r['n_attackers']:>3} "
                  f"subnets={r['attacker_subnets']:>2} "
                  f"wait={r['wait_years']:>2.0f}yr "
                  f"{r['k']}-of-{r['n_shards']:>2} "
                  f"-> p_denied={r['p_restore_denied_mean']*100:.2f}% "
                  f"(p95={r['p_restore_denied_p95']*100:.2f}%) "
                  f"roi={r['roi_files_per_gb_year']:.4f}")
    else:
        t0 = time.time()
        results_table = Parallel(n_jobs=n_jobs, verbose=10)(
            delayed(_evaluate_sweep)(*t) for t in tasks
        )
        elapsed = time.time() - t0
        print(f"\nSweep completed in {elapsed:.1f}s")
        for r in results_table:
            print(f"  attackers={r['n_attackers']:>3} "
                  f"subnets={r['attacker_subnets']:>2} "
                  f"wait={r['wait_years']:>2.0f}yr "
                  f"{r['k']}-of-{r['n_shards']:>2} "
                  f"-> p_denied={r['p_restore_denied_mean']*100:.2f}% "
                  f"roi={r['roi_files_per_gb_year']:.4f}")

    # Sort by p_restore_denied descending
    results_table.sort(key=lambda r: -r["p_restore_denied_mean"])

    print("\n=== TOP 15 MOST DANGEROUS CONFIGURATIONS ===")
    print(f"{'attackers':>10} {'subnets':>8} {'wait_yr':>8} {'k-of-n':>7} "
          f"{'p_denied%':>10} {'p95%':>7} {'atk_shards':>11} "
          f"{'cost(GB-yr)':>12}")
    for r in results_table[:15]:
        print(f"{r['n_attackers']:>10} {r['attacker_subnets']:>8} "
              f"{r['wait_years']:>7.0f} "
              f"{r['k']}-of-{r['n_shards']:<4} "
              f"{r['p_restore_denied_mean']*100:>9.2f}% "
              f"{r['p_restore_denied_p95']*100:>6.2f}% "
              f"{r['attacker_shards_per_file']:>11.2f} "
              f"{r['attack_cost_gb_years']:>11.0f}")

    # Sort by ROI (damage per GB-year spent)
    results_table.sort(key=lambda r: -r["roi_files_per_gb_year"])
    print("\n=== TOP 10 BEST ROI ATTACKS ===")
    print(f"{'attackers':>10} {'subnets':>8} {'wait_yr':>8} {'k-of-n':>7} "
          f"{'p_denied%':>10} {'cost(GB-yr)':>12} {'roi(files/GB-yr)':>18}")
    for r in results_table[:10]:
        print(f"{r['n_attackers']:>10} {r['attacker_subnets']:>8} "
              f"{r['wait_years']:>7.0f} "
              f"{r['k']}-of-{r['n_shards']:<4} "
              f"{r['p_restore_denied_mean']*100:>9.2f}% "
              f"{r['attack_cost_gb_years']:>11.0f} "
              f"{r['roi_files_per_gb_year']:>17.4f}")

    sweep_path = output_dir / "sweep_results.json"
    sweep_path.parent.mkdir(parents=True, exist_ok=True)
    sweep_path.write_text(json.dumps(results_table, indent=2))
    print(f"\nFull sweep saved to {sweep_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Spite Attack (Targeted) on P2P Backup"
    )
    parser.add_argument("--honest-peers", type=int, default=500)
    parser.add_argument("--attackers", type=int, default=20)
    parser.add_argument("--files", type=int, default=1000)
    parser.add_argument("--seeds", type=int, default=100)
    parser.add_argument("--k", type=int, default=5)
    parser.add_argument("--n-shards", type=int, default=15)
    parser.add_argument("--attacker-subnets", type=int, default=1,
                        help="Number of /24 blocks attacker controls")
    parser.add_argument("--subnet-limit", type=int, default=1,
                        help="Max shards per /24 subnet per file")
    parser.add_argument("--wait-years", type=float, default=2.0,
                        help="Years attacker waits before target needs restore")
    parser.add_argument("--initial-reputation-months", type=int, default=6,
                        help="Months of honest participation before simulation start")
    parser.add_argument("--kp", type=float, default=0.5)
    parser.add_argument("--ki", type=float, default=2.0)
    parser.add_argument("--window", type=int, default=30,
                        help="P rolling window in days")
    parser.add_argument("--sweep", action="store_true",
                        help="Run parameter sweep over attackers/subnets/wait")
    parser.add_argument("--jobs", type=int, default=1,
                        help="Parallel jobs (cores)")
    parser.add_argument("--output", type=str, default="results/spite_attack")
    args = parser.parse_args()

    output_dir = Path(args.output)
    if args.sweep:
        output_dir = Path("results/spite_sweep")

    config = Config(
        n_honest_peers=args.honest_peers,
        n_attackers=args.attackers,
        n_files=args.files,
        n_seeds=args.seeds,
        k=args.k,
        n_shards=args.n_shards,
        attacker_subnets=args.attacker_subnets,
        subnet_limit=args.subnet_limit,
        wait_years=args.wait_years,
        initial_reputation_months=args.initial_reputation_months,
        kp=args.kp,
        ki=args.ki,
        p_window=args.window,
    )

    if args.sweep:
        print("=== SPITE ATTACK PARAMETER SWEEP ===\n")
        run_sweep(config, output_dir, n_jobs=args.jobs)
    else:
        print("=== SPITE ATTACK SIMULATION ===\n")
        result = run_experiment(config, n_jobs=args.jobs)
        print_summary(result)
        save_results(result, output_dir / "run.json")


if __name__ == "__main__":
    main()
