"""
SyncBack Simulation #4: Sybil Attack Against P2P Backup with PID Reputation

Question: Can a Sybil attacker cause file loss by building reputation honestly
then refusing to serve shards on restore?

Model:
- N honest peers + M sybil nodes controlled by attacker
- Sybils stored across limited /24 subnets; subnet rate-limit: 1 shard per /24 per file
- Phase 1 (buildup): sybils behave honestly, accumulate PID trust
  - Weekly repair cycles replace degraded shards; high-trust sybils are preferred
- Phase 2 (attack): target's disk fails; sybil shards are silently dropped
- File survives if (n_shards - sybil_shards_on_file) >= k

Key metrics:
- P(file_loss) vs n_sybils
- P(file_loss) vs reputation_buildup_months (sybil infiltration via repair)
- Attack cost: sybils * months * storage_per_sybil_GB
- Sensitivity to sybil_subnets (subnet diversity limit)

Usage:
    python sybil_attack.py                    # default run
    python sybil_attack.py --sweep --jobs 24  # parameter sweep
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
    n_sybils: int = 100
    n_files: int = 1000
    n_seeds: int = 100
    # Erasure coding — documents profile by default
    k: int = 5
    n_shards: int = 15
    # Sybil network topology
    sybil_subnets: int = 3        # how many /24 blocks attacker controls
    subnet_limit: int = 1         # max shards per /24 per file
    # Reputation buildup phase
    reputation_months: int = 6
    # PID parameters (from experiment 1: Kp=0.5, Ki=2.0 converge in ~40 days)
    kp: float = 0.5
    ki: float = 2.0
    p_window: int = 30            # P: rolling window in days
    # Honest peer reliability
    honest_reliability: float = 0.95
    # Repair cycle — weekly, as per cold backup model
    repair_interval_days: int = 7
    # Shard degradation: probability a shard needs repair each cycle
    # Models peer churn, disk failures during buildup period
    shard_failure_prob: float = 0.02
    # Attack cost model
    storage_per_sybil_gb: float = 100.0


def _assign_subnets(n_honest: int, n_sybils: int, sybil_subnets: int,
                    rng: np.random.Generator) -> np.ndarray:
    # Each peer gets a /24 subnet ID (integer). Honest peers get unique subnets
    # (one peer per /24 is a simplification; what matters is that honest peers
    # don't cluster). Sybils share sybil_subnets blocks.
    #
    # We model honest subnets as IDs 0..n_honest-1 (one per peer — maximally
    # spread), and sybil subnets as IDs n_honest..n_honest+sybil_subnets-1.
    n_total = n_honest + n_sybils
    subnets = np.empty(n_total, dtype=np.int32)

    # Honest peers: each in its own /24
    subnets[:n_honest] = np.arange(n_honest)

    # Sybil peers: distributed across sybil_subnets blocks
    # Spread them as evenly as possible
    sybil_subnet_ids = n_honest + (np.arange(n_sybils) % sybil_subnets)
    subnets[n_honest:] = sybil_subnet_ids

    return subnets


def _build_pid_trust(n_total: int, is_sybil: np.ndarray, config: Config,
                     rng: np.random.Generator) -> np.ndarray:
    # Simulate PID trust accumulation over reputation_months.
    # Sybils always pass (reliability=1.0), honest peers pass with honest_reliability.
    # Returns final trust score per peer.
    n_days = config.reputation_months * 30

    p_score = np.full(n_total, 0.5)
    i_score = np.full(n_total, 0.5)
    window_buf = np.zeros((config.p_window, n_total))

    reliability = np.where(is_sybil, 1.0, config.honest_reliability)

    for t in range(n_days):
        checks = (rng.random(n_total) < reliability).astype(np.float64)

        # P: rolling window average
        window_buf[t % config.p_window] = checks
        filled = min(t + 1, config.p_window)
        p_score = window_buf[:filled].mean(axis=0)

        # I: cumulative average
        i_score = (i_score * t + checks) / (t + 1)

    trust = config.kp * p_score + config.ki * i_score
    return trust


def _place_shards(n_shards: int, subnet_limit: int, trust: np.ndarray,
                  subnets: np.ndarray, excluded: set,
                  rng: np.random.Generator) -> list[int]:
    # Place n_shards shards on distinct peers with subnet rate limit.
    # Selection is trust-weighted (higher trust = more likely to be chosen).
    # excluded: peer IDs already holding a shard for this file.
    #
    # Returns list of peer IDs selected (may be < n_shards if not enough eligible).
    n_total = len(trust)
    selected = []
    subnet_counts: dict[int, int] = {}

    # Build candidate mask: not excluded, trust > 0
    eligible = np.array([
        i for i in range(n_total)
        if i not in excluded and trust[i] > 0
    ], dtype=np.int32)

    if len(eligible) == 0:
        return selected

    # Weighted sampling without replacement, respecting subnet limit.
    # Strategy: iteratively sample from remaining eligible candidates.
    remaining = list(eligible)
    selected_set = set(excluded)

    while len(selected) < n_shards and remaining:
        # Compute weights for remaining candidates
        weights = np.array([trust[i] for i in remaining], dtype=np.float64)
        total_w = weights.sum()
        if total_w <= 0:
            break
        probs = weights / total_w

        # Sample one peer
        idx = rng.choice(len(remaining), p=probs)
        peer = remaining[idx]
        subnet = subnets[peer]

        # Check subnet limit
        if subnet_counts.get(subnet, 0) < subnet_limit:
            selected.append(peer)
            selected_set.add(peer)
            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1

        # Remove from candidates (selected or subnet-full)
        remaining.pop(idx)
        # Also remove other peers from full subnets
        if subnet_counts.get(subnet, 0) >= subnet_limit:
            remaining = [p for p in remaining if subnets[p] != subnet]

    return selected


def simulate_one(config: Config, seed: int) -> dict:
    """Run one Sybil attack simulation. Returns per-run metrics."""
    rng = np.random.default_rng(seed)

    n_total = config.n_honest_peers + config.n_sybils
    is_sybil = np.zeros(n_total, dtype=bool)
    is_sybil[config.n_honest_peers:] = True

    subnets = _assign_subnets(
        config.n_honest_peers, config.n_sybils, config.sybil_subnets, rng
    )

    # Phase 1: reputation buildup
    # First, build initial trust (day-0 placement uses uniform trust, since
    # sybils have no reputation yet when they first join)
    initial_trust = np.ones(n_total, dtype=np.float64)

    # Place files on the network at time 0 with flat trust (no reputation yet)
    file_shards: list[list[int]] = []
    for _ in range(config.n_files):
        holders = _place_shards(
            config.n_shards, config.subnet_limit,
            initial_trust, subnets, set(), rng
        )
        file_shards.append(holders)

    # Simulate buildup: weekly repair cycles use trust-weighted placement.
    # Sybils behave honestly throughout buildup, accumulating high trust.
    # We rebuild trust progressively across the repair cycles.
    n_repair_cycles = (config.reputation_months * 30) // config.repair_interval_days

    for cycle in range(n_repair_cycles):
        # Trust at this point in buildup (cycles are evenly spaced over buildup)
        days_elapsed = (cycle + 1) * config.repair_interval_days
        months_elapsed = days_elapsed / 30
        partial_config = Config(
            n_honest_peers=config.n_honest_peers,
            n_sybils=config.n_sybils,
            n_files=config.n_files,
            n_seeds=1,
            k=config.k,
            n_shards=config.n_shards,
            sybil_subnets=config.sybil_subnets,
            subnet_limit=config.subnet_limit,
            reputation_months=max(1, int(months_elapsed)),
            kp=config.kp,
            ki=config.ki,
            p_window=config.p_window,
            honest_reliability=config.honest_reliability,
            repair_interval_days=config.repair_interval_days,
            shard_failure_prob=config.shard_failure_prob,
            storage_per_sybil_gb=config.storage_per_sybil_gb,
        )
        trust = _build_pid_trust(n_total, is_sybil, partial_config, rng)

        # Each shard fails independently with shard_failure_prob
        for fidx in range(config.n_files):
            holders = file_shards[fidx]
            survived = [
                p for p in holders
                if rng.random() > config.shard_failure_prob
            ]
            n_lost = config.n_shards - len(survived)
            if n_lost > 0 and len(survived) >= config.k:
                # Repair: place n_lost new shards on trust-weighted peers
                new_shards = _place_shards(
                    n_lost, config.subnet_limit,
                    trust, subnets, set(survived), rng
                )
                file_shards[fidx] = survived + new_shards
            else:
                file_shards[fidx] = survived

    # Final trust at end of buildup
    final_trust = _build_pid_trust(n_total, is_sybil, config, rng)

    # Phase 2: attack — target's disk fails, requests restore
    # Sybil nodes refuse to return shards. Count how many sybil shards each file has.
    files_lost = 0
    sybil_shard_counts: list[int] = []

    for fidx in range(config.n_files):
        holders = file_shards[fidx]
        n_sybil_shards = sum(1 for p in holders if is_sybil[p])
        n_honest_shards = len(holders) - n_sybil_shards
        sybil_shard_counts.append(n_sybil_shards)

        # File is lost if honest shards available < k
        if n_honest_shards < config.k:
            files_lost += 1

    sybil_arr = np.array(sybil_shard_counts)
    p_loss = files_lost / config.n_files

    # Attack cost: sybils * months * storage
    attack_cost_gb_months = (
        config.n_sybils * config.reputation_months * config.storage_per_sybil_gb
    )

    # Mean trust of sybils vs honest peers at end of buildup
    sybil_trust_mean = float(final_trust[is_sybil].mean())
    honest_trust_mean = float(final_trust[~is_sybil].mean())

    return {
        "p_loss": p_loss,
        "files_lost": files_lost,
        "mean_sybil_shards_per_file": float(sybil_arr.mean()),
        "max_sybil_shards_per_file": int(sybil_arr.max()) if len(sybil_arr) else 0,
        "p_file_with_any_sybil": float((sybil_arr > 0).mean()),
        "sybil_trust_mean": sybil_trust_mean,
        "honest_trust_mean": honest_trust_mean,
        "attack_cost_gb_months": attack_cost_gb_months,
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

    p_losses = [r["p_loss"] for r in results]
    sybil_shards = [r["mean_sybil_shards_per_file"] for r in results]
    sybil_trust = [r["sybil_trust_mean"] for r in results]
    honest_trust = [r["honest_trust_mean"] for r in results]

    return {
        "config": asdict(config),
        "elapsed_sec": elapsed,
        "p_loss_mean": float(np.mean(p_losses)),
        "p_loss_std": float(np.std(p_losses)),
        "p_loss_p5": float(np.percentile(p_losses, 5)),
        "p_loss_p95": float(np.percentile(p_losses, 95)),
        "p_loss_max": float(np.max(p_losses)),
        "mean_sybil_shards_mean": float(np.mean(sybil_shards)),
        "sybil_trust_mean": float(np.mean(sybil_trust)),
        "honest_trust_mean": float(np.mean(honest_trust)),
        "attack_cost_gb_months": results[0]["attack_cost_gb_months"],
        "p_file_with_any_sybil": float(np.mean([r["p_file_with_any_sybil"] for r in results])),
    }


def print_summary(result: dict) -> None:
    """Print key attack metrics."""
    cfg = result["config"]
    print(f"Config: {cfg['n_honest_peers']} honest + {cfg['n_sybils']} sybils "
          f"({cfg['sybil_subnets']} subnets), {cfg['n_files']} files")
    print(f"Erasure: {cfg['k']}-of-{cfg['n_shards']}, "
          f"buildup: {cfg['reputation_months']} months, "
          f"subnet_limit: {cfg['subnet_limit']} shard/subnet")
    print(f"Seeds: {cfg['n_seeds']}, runtime: {result['elapsed_sec']:.1f}s")
    print()

    p = result["p_loss_mean"]
    print(f"P(file_loss):  mean={p*100:.2f}%  "
          f"p5={result['p_loss_p5']*100:.2f}%  "
          f"p95={result['p_loss_p95']*100:.2f}%  "
          f"max={result['p_loss_max']*100:.2f}%")
    print(f"Sybil shards/file (mean): {result['mean_sybil_shards_mean']:.2f} "
          f"/ {cfg['n_shards']} total "
          f"(max per subnet: {cfg['sybil_subnets']})")
    print(f"Files with >=1 sybil shard: {result['p_file_with_any_sybil']*100:.1f}%")
    print()
    print(f"Trust at end of buildup:  "
          f"sybils={result['sybil_trust_mean']:.3f}  "
          f"honest={result['honest_trust_mean']:.3f}")
    max_infiltration = cfg['n_shards'] - cfg['k']
    print(f"Tolerance: file survives up to {max_infiltration} sybil shards "
          f"(n - k = {cfg['n_shards']} - {cfg['k']})")
    print(f"Attack cost: {result['attack_cost_gb_months']:.0f} GB-months "
          f"({cfg['n_sybils']} sybils x {cfg['reputation_months']}mo "
          f"x {cfg['storage_per_sybil_gb']:.0f}GB)")


def save_results(result: dict, path: Path) -> None:
    """Save results to JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2))
    print(f"\nResults saved to {path}")


def _evaluate_sweep(n_honest: int, n_sybils: int, n_files: int, k: int,
                    n_shards: int, sybil_subnets: int, reputation_months: int,
                    n_seeds: int, kp: float, ki: float, p_window: int) -> dict:
    cfg = Config(
        n_honest_peers=n_honest,
        n_sybils=n_sybils,
        n_files=n_files,
        k=k,
        n_shards=n_shards,
        sybil_subnets=sybil_subnets,
        reputation_months=reputation_months,
        n_seeds=n_seeds,
        kp=kp,
        ki=ki,
        p_window=p_window,
    )
    res = run_experiment(cfg, n_jobs=1)
    return {
        "n_sybils": n_sybils,
        "sybil_subnets": sybil_subnets,
        "reputation_months": reputation_months,
        "k": k,
        "n_shards": n_shards,
        "p_loss_mean": res["p_loss_mean"],
        "p_loss_p95": res["p_loss_p95"],
        "mean_sybil_shards": res["mean_sybil_shards_mean"],
        "attack_cost_gb_months": res["attack_cost_gb_months"],
        "sybil_trust": res["sybil_trust_mean"],
        "honest_trust": res["honest_trust_mean"],
    }


def run_sweep(base_config: Config, output_dir: Path, n_jobs: int = 1) -> None:
    """Sweep n_sybils, sybil_subnets, reputation_months across two erasure profiles."""
    n_sybils_values = [10, 50, 100, 200, 500]
    sybil_subnets_values = [1, 3, 5, 10]
    reputation_months_values = [3, 6, 12]
    # Two erasure coding profiles from the spec
    erasure_profiles = [(5, 15), (6, 10)]

    tasks = []
    for k, n_shards in erasure_profiles:
        for n_sybils in n_sybils_values:
            for sybil_subnets in sybil_subnets_values:
                for rep_months in reputation_months_values:
                    tasks.append((
                        base_config.n_honest_peers,
                        n_sybils,
                        base_config.n_files,
                        k, n_shards,
                        sybil_subnets,
                        rep_months,
                        30,  # fewer seeds for sweep
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
            print(f"  [{i}/{total}] sybils={r['n_sybils']:>3} "
                  f"subnets={r['sybil_subnets']:>2} "
                  f"months={r['reputation_months']:>2} "
                  f"{r['k']}-of-{r['n_shards']:>2} "
                  f"-> p_loss={r['p_loss_mean']*100:.2f}% "
                  f"(p95={r['p_loss_p95']*100:.2f}%) "
                  f"cost={r['attack_cost_gb_months']:.0f}GB-mo")
    else:
        t0 = time.time()
        results_table = Parallel(n_jobs=n_jobs, verbose=10)(
            delayed(_evaluate_sweep)(*t) for t in tasks
        )
        elapsed = time.time() - t0
        print(f"\nSweep completed in {elapsed:.1f}s")
        for r in results_table:
            print(f"  sybils={r['n_sybils']:>3} "
                  f"subnets={r['sybil_subnets']:>2} "
                  f"months={r['reputation_months']:>2} "
                  f"{r['k']}-of-{r['n_shards']:>2} "
                  f"-> p_loss={r['p_loss_mean']*100:.2f}% "
                  f"cost={r['attack_cost_gb_months']:.0f}GB-mo")

    # Sort by p_loss descending (worst cases first)
    results_table.sort(key=lambda r: -r["p_loss_mean"])

    print("\n=== TOP 15 MOST DANGEROUS CONFIGURATIONS ===")
    print(f"{'sybils':>7} {'subnets':>8} {'months':>7} {'k-of-n':>7} "
          f"{'p_loss%':>8} {'p95%':>7} {'sybil_shards':>13} "
          f"{'cost(GB-mo)':>12}")
    for r in results_table[:15]:
        print(f"{r['n_sybils']:>7} {r['sybil_subnets']:>8} "
              f"{r['reputation_months']:>7} "
              f"{r['k']}-of-{r['n_shards']:<4} "
              f"{r['p_loss_mean']*100:>7.2f}% "
              f"{r['p_loss_p95']*100:>6.2f}% "
              f"{r['mean_sybil_shards']:>12.2f} "
              f"{r['attack_cost_gb_months']:>11.0f}")

    # Also show by attack cost efficiency (p_loss / cost)
    for r in results_table:
        cost = r["attack_cost_gb_months"]
        r["efficiency"] = r["p_loss_mean"] / cost if cost > 0 else 0.0

    results_table.sort(key=lambda r: -r["efficiency"])
    print("\n=== TOP 10 MOST COST-EFFICIENT ATTACKS ===")
    print(f"{'sybils':>7} {'subnets':>8} {'months':>7} {'k-of-n':>7} "
          f"{'p_loss%':>8} {'cost(GB-mo)':>12} {'efficiency':>11}")
    for r in results_table[:10]:
        print(f"{r['n_sybils']:>7} {r['sybil_subnets']:>8} "
              f"{r['reputation_months']:>7} "
              f"{r['k']}-of-{r['n_shards']:<4} "
              f"{r['p_loss_mean']*100:>7.2f}% "
              f"{r['attack_cost_gb_months']:>11.0f} "
              f"{r['efficiency']*1e6:>10.3f}e-6")

    sweep_path = output_dir / "sweep_results.json"
    sweep_path.parent.mkdir(parents=True, exist_ok=True)
    sweep_path.write_text(json.dumps(results_table, indent=2))
    print(f"\nFull sweep saved to {sweep_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Sybil Attack on P2P Backup")
    parser.add_argument("--honest-peers", type=int, default=500)
    parser.add_argument("--sybils", type=int, default=100)
    parser.add_argument("--files", type=int, default=1000)
    parser.add_argument("--seeds", type=int, default=100)
    parser.add_argument("--k", type=int, default=5)
    parser.add_argument("--n-shards", type=int, default=15)
    parser.add_argument("--sybil-subnets", type=int, default=3,
                        help="Number of /24 blocks attacker controls")
    parser.add_argument("--subnet-limit", type=int, default=1,
                        help="Max shards per /24 subnet per file")
    parser.add_argument("--reputation-months", type=int, default=6,
                        help="Months sybils behave honestly before attack")
    parser.add_argument("--kp", type=float, default=0.5)
    parser.add_argument("--ki", type=float, default=2.0)
    parser.add_argument("--window", type=int, default=30,
                        help="P rolling window in days")
    parser.add_argument("--sweep", action="store_true",
                        help="Run parameter sweep over sybils/subnets/months")
    parser.add_argument("--jobs", type=int, default=1,
                        help="Parallel jobs (cores)")
    parser.add_argument("--output", type=str, default="results/sybil_attack")
    args = parser.parse_args()

    output_dir = Path(args.output)

    config = Config(
        n_honest_peers=args.honest_peers,
        n_sybils=args.sybils,
        n_files=args.files,
        n_seeds=args.seeds,
        k=args.k,
        n_shards=args.n_shards,
        sybil_subnets=args.sybil_subnets,
        subnet_limit=args.subnet_limit,
        reputation_months=args.reputation_months,
        kp=args.kp,
        ki=args.ki,
        p_window=args.window,
    )

    if args.sweep:
        print("=== SYBIL ATTACK PARAMETER SWEEP ===\n")
        run_sweep(config, output_dir, n_jobs=args.jobs)
    else:
        print("=== SYBIL ATTACK SIMULATION ===\n")
        result = run_experiment(config, n_jobs=args.jobs)
        print_summary(result)
        save_results(result, output_dir / "run.json")


if __name__ == "__main__":
    main()
