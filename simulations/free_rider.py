"""
Viaticum Simulation #5: Free-rider Detection

Question: Does PI reputation automatically prevent free-riding?
Can a free-rider game the system by storing just enough to maintain minimum reputation?

Model:
- N honest peers + F free-riders
- Honest peers: store shards for others reliably (~0.95), back up their own data
- Free-riders: store little or nothing (configurable: 0%, 10%, 25%, 50% of expected),
  but attempt to back up their own data on honest peers
- PI trust: trust = 0.5*P + 2.0*I, P = 30-day rolling window, I = cumulative average
- Trust gate: peers only store new shards for others whose trust exceeds threshold
- Weekly repair cycles replace degraded/lost shards using trust-weighted placement

Key findings this measures:
- Do free-riders get naturally excluded (trust drops below threshold)?
- How fast does exclusion happen (months)?
- Can a partial free-rider (25% compliance) maintain network access?
- What is the collateral impact on honest peers?

Usage:
    python free_rider.py                    # default single run
    python free_rider.py --sweep --jobs 8   # parameter sweep
    python free_rider.py --freerider-reliability 0.25  # gaming free-rider
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
    n_honest_peers: int = 200
    n_freeriders: int = 50
    n_files: int = 500          # files per group (honest and freerider each have this many)
    n_seeds: int = 100
    # Erasure coding
    k: int = 5
    n_shards: int = 15
    # PI trust parameters (from experiment 1: kp=0.5, ki=2.0 are optimal)
    kp: float = 0.5
    ki: float = 2.0
    p_window: int = 30          # P: rolling window in days
    # Peer reliability
    honest_reliability: float = 0.95
    freerider_reliability: float = 0.0   # 0=store nothing, 0.5=store half
    # Trust gate: minimum trust to be selected as a new shard holder during repair
    trust_threshold: float = 0.3
    # Simulation duration
    n_months: int = 12
    # Repair: weekly cycles, matching cold backup model
    repair_interval_days: int = 7
    # Shard degradation per repair cycle (models churn, disk failures)
    shard_failure_prob: float = 0.02


def _compute_pi_trust(
    checks_history: np.ndarray,
    kp: float,
    ki: float,
    p_window: int,
) -> np.ndarray:
    """Compute PI trust from full check history.

    checks_history: shape (n_days, n_peers), values 0.0 or 1.0
    Returns trust array of shape (n_peers,).
    """
    n_days, n_peers = checks_history.shape

    if n_days == 0:
        return np.full(n_peers, 0.5)

    # P: rolling window average over last p_window days
    window_start = max(0, n_days - p_window)
    p_score = checks_history[window_start:].mean(axis=0)

    # I: cumulative average over all history
    i_score = checks_history.mean(axis=0)

    return kp * p_score + ki * i_score


def simulate_one(config: Config, seed: int) -> dict:
    """Run one free-rider simulation. Returns per-run metrics."""
    rng = np.random.default_rng(seed)

    n_honest = config.n_honest_peers
    n_free = config.n_freeriders
    n_total = n_honest + n_free

    # Peer indices: 0..n_honest-1 = honest, n_honest..n_total-1 = free-riders
    is_freerider = np.zeros(n_total, dtype=bool)
    is_freerider[n_honest:] = True

    # Per-peer storage reliability (used in proof-of-storage checks)
    reliability = np.where(is_freerider, config.freerider_reliability,
                           config.honest_reliability)

    # Files: each group owns config.n_files files
    # honest_files: owned by honest peers (indices 0..n_files-1)
    # freerider_files: owned by free-riders (indices n_files..2*n_files-1)
    n_files_total = config.n_files * 2

    # Initial shard placement: trust-neutral (all peers start at 0.5 baseline)
    # Shards are placed uniformly at random across all peers.
    # file_shards[f] = list of peer IDs holding shards for file f
    file_shards: list[list[int]] = []
    all_peers = np.arange(n_total)
    for _ in range(n_files_total):
        holders = rng.choice(all_peers, size=min(config.n_shards, n_total),
                             replace=False).tolist()
        file_shards.append(holders)

    # Track check history for PI trust calculation.
    # We keep a rolling buffer of last p_window days to compute P,
    # plus a running cumulative mean for I.
    # Shape: (p_window, n_total) circular buffer for P
    p_buffer = np.zeros((config.p_window, n_total))
    # Cumulative stats for I
    i_sum = np.zeros(n_total)
    total_checks = 0

    # Track trust trajectory month by month
    trust_history: list[np.ndarray] = []

    # Track when each free-rider first drops below threshold (months)
    # -1 = never dropped below threshold
    freerider_exclusion_month = np.full(n_free, -1, dtype=np.int32)
    freerider_excluded = np.zeros(n_free, dtype=bool)

    n_days_total = config.n_months * 30
    n_repair_cycles = n_days_total // config.repair_interval_days

    # Simulate day by day, with repair every repair_interval_days
    current_trust = np.full(n_total, 0.5)  # initial trust

    for day in range(n_days_total):
        # Daily proof-of-storage check: each peer passes with their reliability
        checks = (rng.random(n_total) < reliability).astype(np.float64)

        # Update circular P buffer
        p_buffer[day % config.p_window] = checks

        # Update I (cumulative average, numerically stable)
        i_sum += checks
        total_checks += 1

        # Compute current trust
        filled = min(total_checks, config.p_window)
        p_score = p_buffer[:filled].mean(axis=0)
        i_score = i_sum / total_checks
        current_trust = config.kp * p_score + config.ki * i_score

        # Weekly repair cycle
        if (day + 1) % config.repair_interval_days == 0:
            # Shard failure: each shard independently fails with shard_failure_prob
            for fidx in range(n_files_total):
                holders = file_shards[fidx]
                # Keep shards that didn't fail
                survived = [
                    p for p in holders
                    if rng.random() > config.shard_failure_prob
                ]
                n_lost = config.n_shards - len(survived)

                if n_lost > 0 and len(survived) >= config.k:
                    # Repair: place replacement shards using trust-weighted placement
                    # with trust gate — only peers above threshold are eligible
                    existing = set(survived)

                    # Determine which file group this is
                    # freerider_files = indices n_files..2*n_files-1
                    # When placing shards FOR a free-rider's file, the decision
                    # is made by honest peers who check if the requester's trust
                    # is above threshold. We model this at the file level:
                    # free-rider files can only be repaired if the REQUESTING
                    # peer (the free-rider owner) has sufficient trust to
                    # get other peers to cooperate.
                    #
                    # For honest files: free-riders can be shard holders only if
                    # their trust is above threshold (honest peers won't store
                    # for low-trust peers either, but they CAN store, the issue
                    # is whether free-riders accept the storage request).
                    # Actually the trust gate works the other way: when picking
                    # a NEW holder for a shard, the file owner selects from
                    # candidates whose trust exceeds the threshold.

                    is_fr_file = fidx >= config.n_files

                    if is_fr_file:
                        # For free-rider files: honest peers check the average
                        # trust of free-riders (the requester group). If free-
                        # riders have low trust, honest peers decline to store.
                        # Simplified: we gate on the MEAN trust of the owner
                        # group. Owner is the free-rider group.
                        owner_trust = current_trust[n_honest:].mean()
                        if owner_trust < config.trust_threshold:
                            # Honest peers decline to store for low-trust owners.
                            # Only other free-riders (who might have enough
                            # capacity) can store — but free-riders also don't
                            # reliably store for each other. We model this as:
                            # no effective repair (free-rider shards stay lost).
                            file_shards[fidx] = survived
                            continue

                    # Eligible candidates: trust above threshold, not already holding
                    candidate_mask = (
                        (current_trust >= config.trust_threshold) &
                        ~np.isin(all_peers, list(existing))
                    )
                    candidates = all_peers[candidate_mask]

                    if len(candidates) == 0:
                        file_shards[fidx] = survived
                        continue

                    # Trust-weighted selection
                    weights = current_trust[candidates]
                    total_w = weights.sum()
                    if total_w <= 0:
                        file_shards[fidx] = survived
                        continue

                    n_place = min(n_lost, len(candidates))
                    probs = weights / total_w
                    chosen = rng.choice(candidates, size=n_place, replace=False,
                                        p=probs)
                    file_shards[fidx] = survived + chosen.tolist()
                else:
                    file_shards[fidx] = survived

        # Record monthly trust snapshot
        if (day + 1) % 30 == 0:
            month_idx = (day + 1) // 30 - 1
            trust_history.append(current_trust.copy())

            # Check which free-riders dropped below threshold this month
            fr_trust = current_trust[n_honest:]
            for fi in range(n_free):
                if not freerider_excluded[fi] and fr_trust[fi] < config.trust_threshold:
                    freerider_exclusion_month[fi] = month_idx + 1  # 1-indexed
                    freerider_excluded[fi] = True

    # Final state assessment
    honest_files_alive = 0
    freerider_files_alive = 0

    for fidx in range(config.n_files):
        # Honest file: count available shards
        live = len(file_shards[fidx])
        if live >= config.k:
            honest_files_alive += 1

    for fidx in range(config.n_files, n_files_total):
        live = len(file_shards[fidx])
        if live >= config.k:
            freerider_files_alive += 1

    honest_survival = honest_files_alive / config.n_files
    freerider_survival = freerider_files_alive / config.n_files

    # Final trust values
    final_trust = current_trust
    freerider_trust_mean = float(final_trust[n_honest:].mean())
    honest_trust_mean = float(final_trust[:n_honest].mean())

    # months_to_exclusion: when did the AVERAGE free-rider trust first drop below
    # threshold? Use the first month where mean free-rider trust < threshold.
    months_to_exclusion = -1
    for mi, t in enumerate(trust_history):
        fr_mean = t[n_honest:].mean()
        if fr_mean < config.trust_threshold:
            months_to_exclusion = mi + 1  # 1-indexed month
            break

    # freerider_partners_mean: at end of simulation, how many honest peers
    # have trust above threshold for free-riders? Since trust is global (each
    # peer's reputation is observed by all), this equals the count of
    # free-riders with trust >= threshold.
    fr_above_threshold = int((final_trust[n_honest:] >= config.trust_threshold).sum())
    # Partners = honest peers that would store for a free-rider.
    # Since trust is symmetric in our model (one global trust score per peer),
    # if a free-rider's trust is above threshold, ALL honest peers would store
    # for them. We report mean partners per free-rider.
    freerider_partners_mean = float(
        n_honest if fr_above_threshold > 0 else 0
    )
    # More precise: fraction of freeriders still above threshold * n_honest
    fr_above_frac = float((final_trust[n_honest:] >= config.trust_threshold).mean())
    freerider_partners_mean = fr_above_frac * n_honest

    return {
        "freerider_file_survival": freerider_survival,
        "honest_file_survival": honest_survival,
        "freerider_trust_mean": freerider_trust_mean,
        "honest_trust_mean": honest_trust_mean,
        "months_to_exclusion": months_to_exclusion,
        "freerider_partners_mean": freerider_partners_mean,
        "fr_above_threshold_frac": fr_above_frac,
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

    def _agg(key: str) -> dict:
        vals = [r[key] for r in results]
        arr = np.array(vals, dtype=np.float64)
        return {
            "mean": float(arr.mean()),
            "std": float(arr.std()),
            "p5": float(np.percentile(arr, 5)),
            "p95": float(np.percentile(arr, 95)),
        }

    # months_to_exclusion: -1 means never excluded; compute fraction excluded
    excl_months = [r["months_to_exclusion"] for r in results]
    excluded_runs = [m for m in excl_months if m >= 0]
    frac_excluded = len(excluded_runs) / len(excl_months)
    mean_excl_month = float(np.mean(excluded_runs)) if excluded_runs else -1.0

    return {
        "config": asdict(config),
        "elapsed_sec": elapsed,
        "n_seeds": config.n_seeds,
        "freerider_file_survival": _agg("freerider_file_survival"),
        "honest_file_survival": _agg("honest_file_survival"),
        "freerider_trust": _agg("freerider_trust_mean"),
        "honest_trust": _agg("honest_trust_mean"),
        "freerider_partners": _agg("freerider_partners_mean"),
        "fr_above_threshold_frac": _agg("fr_above_threshold_frac"),
        "months_to_exclusion_mean": mean_excl_month,
        "frac_runs_excluded": frac_excluded,
    }


def print_summary(result: dict) -> None:
    """Print key free-rider metrics."""
    cfg = result["config"]
    print(f"Config: {cfg['n_honest_peers']} honest + {cfg['n_freeriders']} free-riders, "
          f"{cfg['n_files']} files each, {cfg['n_months']} months")
    print(f"Erasure: {cfg['k']}-of-{cfg['n_shards']}, "
          f"freerider reliability: {cfg['freerider_reliability']*100:.0f}%, "
          f"trust threshold: {cfg['trust_threshold']:.2f}")
    print(f"PI weights: kp={cfg['kp']}, ki={cfg['ki']}, "
          f"P-window={cfg['p_window']}d")
    print(f"Seeds: {result['n_seeds']}, runtime: {result['elapsed_sec']:.1f}s")
    print()

    fs = result["freerider_file_survival"]
    hs = result["honest_file_survival"]
    ft = result["freerider_trust"]
    ht = result["honest_trust"]
    fp = result["freerider_partners"]
    fa = result["fr_above_threshold_frac"]

    print("File survival after simulation:")
    print(f"  Free-riders:  {fs['mean']*100:.1f}%  "
          f"(p5={fs['p5']*100:.1f}%, p95={fs['p95']*100:.1f}%)")
    print(f"  Honest peers: {hs['mean']*100:.1f}%  "
          f"(p5={hs['p5']*100:.1f}%, p95={hs['p95']*100:.1f}%)")
    print()

    print("Trust at end of simulation:")
    print(f"  Free-riders:  {ft['mean']:.3f}  "
          f"(p5={ft['p5']:.3f}, p95={ft['p95']:.3f})  "
          f"[threshold={cfg['trust_threshold']:.2f}]")
    print(f"  Honest peers: {ht['mean']:.3f}  "
          f"(p5={ht['p5']:.3f}, p95={ht['p95']:.3f})")
    print()

    print("Exclusion dynamics:")
    m = result["months_to_exclusion_mean"]
    excl_str = f"month {m:.1f}" if m >= 0 else "never"
    print(f"  Mean trust of free-riders drops below threshold: {excl_str}")
    print(f"  Runs where exclusion occurred: {result['frac_runs_excluded']*100:.0f}%")
    print(f"  Free-riders still above threshold (end): "
          f"{fa['mean']*100:.1f}% "
          f"(p5={fa['p5']*100:.1f}%, p95={fa['p95']*100:.1f}%)")
    print(f"  Honest partners willing to store (end): "
          f"{fp['mean']:.0f} / {cfg['n_honest_peers']}")


def save_results(result: dict, path: Path) -> None:
    """Save results to JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2))
    print(f"\nResults saved to {path}")


def _evaluate_sweep(
    n_honest: int,
    n_freeriders: int,
    n_files: int,
    k: int,
    n_shards: int,
    freerider_reliability: float,
    trust_threshold: float,
    n_months: int,
    n_seeds: int,
    kp: float,
    ki: float,
    p_window: int,
    honest_reliability: float,
    shard_failure_prob: float,
    repair_interval_days: int,
) -> dict:
    """Evaluate a single sweep configuration. Sequential inner loop."""
    cfg = Config(
        n_honest_peers=n_honest,
        n_freeriders=n_freeriders,
        n_files=n_files,
        k=k,
        n_shards=n_shards,
        freerider_reliability=freerider_reliability,
        trust_threshold=trust_threshold,
        n_months=n_months,
        n_seeds=n_seeds,
        kp=kp,
        ki=ki,
        p_window=p_window,
        honest_reliability=honest_reliability,
        shard_failure_prob=shard_failure_prob,
        repair_interval_days=repair_interval_days,
    )
    res = run_experiment(cfg, n_jobs=1)
    return {
        "n_freeriders": n_freeriders,
        "freerider_pct": n_freeriders / (n_honest + n_freeriders),
        "freerider_reliability": freerider_reliability,
        "trust_threshold": trust_threshold,
        "freerider_survival_mean": res["freerider_file_survival"]["mean"],
        "honest_survival_mean": res["honest_file_survival"]["mean"],
        "freerider_trust_mean": res["freerider_trust"]["mean"],
        "honest_trust_mean": res["honest_trust"]["mean"],
        "months_to_exclusion": res["months_to_exclusion_mean"],
        "frac_excluded": res["frac_runs_excluded"],
        "fr_above_threshold_frac": res["fr_above_threshold_frac"]["mean"],
        "freerider_partners_mean": res["freerider_partners"]["mean"],
    }


def run_sweep(base_config: Config, output_dir: Path, n_jobs: int = 1) -> None:
    """Sweep freerider proportions, reliability levels, and trust thresholds."""
    total_peers = base_config.n_honest_peers + base_config.n_freeriders

    # Free-rider proportions: 5%, 10%, 20%, 40% of total peers
    freerider_proportions = [0.05, 0.10, 0.20, 0.40]
    freerider_reliabilities = [0.0, 0.1, 0.25, 0.5]
    trust_thresholds = [0.3, 0.5, 0.7]

    tasks = []
    for fr_prop in freerider_proportions:
        n_fr = max(1, int(total_peers * fr_prop))
        n_honest = total_peers - n_fr
        for fr_rel in freerider_reliabilities:
            for threshold in trust_thresholds:
                tasks.append((
                    n_honest,
                    n_fr,
                    base_config.n_files,
                    base_config.k,
                    base_config.n_shards,
                    fr_rel,
                    threshold,
                    base_config.n_months,
                    30,  # fewer seeds for sweep
                    base_config.kp,
                    base_config.ki,
                    base_config.p_window,
                    base_config.honest_reliability,
                    base_config.shard_failure_prob,
                    base_config.repair_interval_days,
                ))

    total = len(tasks)
    print(f"Sweep: {total} configs "
          f"({len(freerider_proportions)} proportions x "
          f"{len(freerider_reliabilities)} reliabilities x "
          f"{len(trust_thresholds)} thresholds), "
          f"{n_jobs} jobs\n")

    if n_jobs == 1:
        results_table = []
        for i, t in enumerate(tasks, 1):
            r = _evaluate_sweep(*t)
            results_table.append(r)
            print(f"  [{i:>3}/{total}] "
                  f"fr%={r['freerider_pct']*100:.0f}% "
                  f"rel={r['freerider_reliability']*100:.0f}% "
                  f"thr={r['trust_threshold']:.1f} "
                  f"-> fr_surv={r['freerider_survival_mean']*100:.1f}% "
                  f"h_surv={r['honest_survival_mean']*100:.1f}% "
                  f"excl_mo={r['months_to_exclusion']:.1f}")
    else:
        t0 = time.time()
        results_table = Parallel(n_jobs=n_jobs, verbose=10)(
            delayed(_evaluate_sweep)(*t) for t in tasks
        )
        elapsed = time.time() - t0
        print(f"\nSweep completed in {elapsed:.1f}s")
        for r in results_table:
            print(f"  fr%={r['freerider_pct']*100:.0f}% "
                  f"rel={r['freerider_reliability']*100:.0f}% "
                  f"thr={r['trust_threshold']:.1f} "
                  f"-> fr_surv={r['freerider_survival_mean']*100:.1f}% "
                  f"h_surv={r['honest_survival_mean']*100:.1f}% "
                  f"excl_mo={r['months_to_exclusion']:.1f}")

    # Sort by free-rider survival (ascending — worst outcomes for free-riders first,
    # i.e., the configurations where the trust mechanism works best)
    results_table.sort(key=lambda r: r["freerider_survival_mean"])

    print("\n=== BEST EXCLUSION (lowest free-rider file survival) ===")
    print(f"{'fr%':>5} {'rel%':>5} {'thr':>5} "
          f"{'fr_surv%':>9} {'h_surv%':>8} "
          f"{'fr_trust':>9} {'excl_mo':>8} {'partners':>9}")
    for r in results_table[:15]:
        excl = f"{r['months_to_exclusion']:.1f}" if r["months_to_exclusion"] >= 0 else "never"
        print(f"{r['freerider_pct']*100:>4.0f}% "
              f"{r['freerider_reliability']*100:>4.0f}% "
              f"{r['trust_threshold']:>5.1f} "
              f"{r['freerider_survival_mean']*100:>8.1f}% "
              f"{r['honest_survival_mean']*100:>7.1f}% "
              f"{r['freerider_trust_mean']:>8.3f} "
              f"{excl:>8} "
              f"{r['freerider_partners_mean']:>8.1f}")

    # Also show: which free-rider reliabilities allow gaming (survival > 50%)
    gaming = [r for r in results_table if r["freerider_survival_mean"] > 0.5]
    gaming.sort(key=lambda r: -r["freerider_reliability"])
    if gaming:
        print(f"\n=== GAMING SCENARIOS (free-rider survival > 50%) ===")
        print(f"{'fr%':>5} {'rel%':>5} {'thr':>5} "
              f"{'fr_surv%':>9} {'h_surv%':>8} {'fr_trust':>9}")
        for r in gaming[:10]:
            print(f"{r['freerider_pct']*100:>4.0f}% "
                  f"{r['freerider_reliability']*100:>4.0f}% "
                  f"{r['trust_threshold']:>5.1f} "
                  f"{r['freerider_survival_mean']*100:>8.1f}% "
                  f"{r['honest_survival_mean']*100:>7.1f}% "
                  f"{r['freerider_trust_mean']:>8.3f}")

    sweep_path = output_dir / "sweep_results.json"
    sweep_path.parent.mkdir(parents=True, exist_ok=True)
    sweep_path.write_text(json.dumps(results_table, indent=2))
    print(f"\nFull sweep saved to {sweep_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Free-rider Detection in P2P Backup")
    parser.add_argument("--honest-peers", type=int, default=200,
                        help="Number of honest peers")
    parser.add_argument("--freeriders", type=int, default=50,
                        help="Number of free-rider peers")
    parser.add_argument("--files", type=int, default=500,
                        help="Files per group (honest and freerider each have this many)")
    parser.add_argument("--seeds", type=int, default=100,
                        help="Monte Carlo seeds (single run mode)")
    parser.add_argument("--k", type=int, default=5,
                        help="Minimum shards to reconstruct file")
    parser.add_argument("--n-shards", type=int, default=15,
                        help="Total shards per file")
    parser.add_argument("--freerider-reliability", type=float, default=0.0,
                        help="Free-rider storage reliability (0=none, 0.5=half)")
    parser.add_argument("--honest-reliability", type=float, default=0.95,
                        help="Honest peer storage reliability")
    parser.add_argument("--trust-threshold", type=float, default=0.3,
                        help="Minimum trust score to be selected as shard holder")
    parser.add_argument("--months", type=int, default=12,
                        help="Simulation duration in months")
    parser.add_argument("--kp", type=float, default=0.5,
                        help="PI controller P weight")
    parser.add_argument("--ki", type=float, default=2.0,
                        help="PI controller I weight")
    parser.add_argument("--window", type=int, default=30,
                        help="P rolling window in days")
    parser.add_argument("--shard-failure-prob", type=float, default=0.02,
                        help="Per-shard failure probability per repair cycle")
    parser.add_argument("--sweep", action="store_true",
                        help="Run parameter sweep over freerider proportions, "
                             "reliabilities, and trust thresholds")
    parser.add_argument("--jobs", type=int, default=1,
                        help="Parallel jobs for sweep (cores)")
    parser.add_argument("--output", type=str, default="results/free_rider",
                        help="Output directory for results")
    args = parser.parse_args()

    output_dir = Path(args.output)
    if args.sweep:
        output_dir = Path("results/free_rider_sweep")

    config = Config(
        n_honest_peers=args.honest_peers,
        n_freeriders=args.freeriders,
        n_files=args.files,
        n_seeds=args.seeds,
        k=args.k,
        n_shards=args.n_shards,
        freerider_reliability=args.freerider_reliability,
        honest_reliability=args.honest_reliability,
        trust_threshold=args.trust_threshold,
        n_months=args.months,
        kp=args.kp,
        ki=args.ki,
        p_window=args.window,
        shard_failure_prob=args.shard_failure_prob,
    )

    if args.sweep:
        print("=== FREE-RIDER DETECTION PARAMETER SWEEP ===\n")
        run_sweep(config, output_dir, n_jobs=args.jobs)
    else:
        print("=== FREE-RIDER DETECTION SIMULATION ===\n")
        result = run_experiment(config, n_jobs=args.jobs)
        print_summary(result)
        save_results(result, output_dir / "run.json")


if __name__ == "__main__":
    main()
