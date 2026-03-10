"""
SyncBack Simulation #15: PI+S Convergence

Question: Can adding a storage-ratio term S fix the ranking failures of PI-only
trust (Experiment 13), where Hoarder ranked #2 instead of #5?

New formula being tested:
    trust = kp * P_weekly + ki * I + ks * S

    P_weekly = rolling 4-week window of weekly binary scores.
               weekly_score[w] = 1.0 if peer passed >= 1 check in week w, else 0.0
               P = mean of last 4 complete weekly scores.

    I = cumulative average of all weekly scores (non-decaying).

    S = storage_ratio clamped to [0, 2.0].
        storage_ratio = gb_stored_for_others / gb_stored_by_others
        In simulation: fixed archetype attribute.

Archetypes (same as Experiment 13):
    1. Reliable   (40%): 99% daily, storage_ratio=1.0
    2. Weekend    (20%): 95% Fri-Sun, 30% Mon-Thu, storage_ratio=1.0
    3. Seasonal   (15%): 95% Sep-May, 20% Jun-Aug, storage_ratio=1.0
    4. Nomad      (10%): ~50% random blocks, storage_ratio=1.0
    5. Hoarder    (10%): 90% daily, storage_ratio=0.2
    6. Freeloader  (5%): 80% daily, storage_ratio=0.1

Actual usefulness ranking (lower = more useful):
    Reliable=1, Weekend=2, Seasonal=3, Nomad=4, Hoarder=5, Freeloader=5

Parameter sweep:
    kp: [0.3, 0.5, 0.7]    (3)
    ki: [1.5, 2.0, 2.5]    (3)
    ks: [0.0, 0.3, 0.5, 1.0, 1.5, 2.0]  (6)
    Total: 54 configurations

Usage:
    python pis_convergence.py                  # default run, 1 job
    python pis_convergence.py --jobs 4         # parallel across configs
    python pis_convergence.py --seeds 10       # quick smoke test
    python pis_convergence.py --output results/pis_convergence
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import NamedTuple

import numpy as np
from joblib import Parallel, delayed
from scipy.stats import kendalltau


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class Config:
    n_peers: int = 200
    n_days: int = 1825          # 5 years (60 months at 30d/month = 1800d, +25 buffer)
    n_seeds: int = 30
    kp: float = 0.5
    ki: float = 2.0
    ks: float = 1.0
    # P_weekly: rolling window over last N complete weeks
    p_weeks_window: int = 4
    # Archetype distribution: fractions must sum to 1.0
    # [Reliable, Weekend, Seasonal, Nomad, Hoarder, Freeloader]
    archetype_fractions: tuple[float, ...] = (0.40, 0.20, 0.15, 0.10, 0.10, 0.05)
    # Nomad block parameters
    nomad_on_mean: float = 3.5
    nomad_off_mean: float = 3.5


ARCHETYPE_NAMES: list[str] = [
    "Reliable",
    "Weekend",
    "Seasonal",
    "Nomad",
    "Hoarder",
    "Freeloader",
]

# Per-archetype fixed storage_ratio (gb_stored_for_others / gb_stored_by_others)
ARCHETYPE_STORAGE_RATIO: list[float] = [1.0, 1.0, 1.0, 1.0, 0.2, 0.1]

# Actual usefulness rank: lower = more useful. Hoarder and Freeloader tied at 5.
ACTUAL_USEFULNESS_RANK: list[int] = [1, 2, 3, 4, 5, 5]

# Months at which we record Kendall's tau snapshots
SNAPSHOT_MONTHS: list[int] = [6, 12, 24, 36, 48, 60]


# ---------------------------------------------------------------------------
# Parameter sweep grid
# ---------------------------------------------------------------------------

KP_VALUES: list[float] = [0.3, 0.5, 0.7]
KI_VALUES: list[float] = [1.5, 2.0, 2.5]
KS_VALUES: list[float] = [0.0, 0.3, 0.5, 1.0, 1.5, 2.0]


def sweep_configs(base: Config) -> list[Config]:
    """Generate all 54 sweep configurations from the base config."""
    configs = []
    for kp in KP_VALUES:
        for ki in KI_VALUES:
            for ks in KS_VALUES:
                cfg = Config(
                    n_peers=base.n_peers,
                    n_days=base.n_days,
                    n_seeds=base.n_seeds,
                    kp=kp,
                    ki=ki,
                    ks=ks,
                    p_weeks_window=base.p_weeks_window,
                    archetype_fractions=base.archetype_fractions,
                    nomad_on_mean=base.nomad_on_mean,
                    nomad_off_mean=base.nomad_off_mean,
                )
                configs.append(cfg)
    return configs


# ---------------------------------------------------------------------------
# Reliability matrix (identical to behavior_models.py, with corrected archetypes)
# ---------------------------------------------------------------------------

def _make_nomad_schedule(
    n_days: int,
    on_mean: float,
    off_mean: float,
    rng: np.random.Generator,
) -> np.ndarray:
    """Generate binary ON/OFF schedule for a Nomad peer (geometric block lengths)."""
    schedule = np.zeros(n_days)
    day = 0
    online = rng.random() < 0.5
    while day < n_days:
        duration = int(rng.geometric(p=1.0 / (on_mean if online else off_mean)))
        end = min(day + duration, n_days)
        if online:
            schedule[day:end] = 1.0
        day = end
        online = not online
    return schedule


def build_reliability_matrix(
    n_peers: int,
    n_days: int,
    archetype_ids: np.ndarray,
    config: Config,
    rng: np.random.Generator,
) -> np.ndarray:
    """Build (n_peers, n_days) matrix of daily check-pass probabilities.

    Archetype parameters match Experiment 13 / task specification exactly:
      - Weekend: 95% Fri-Sun (dow 4,5,6), 30% Mon-Thu (dow 0-3)
      - Seasonal: 95% Sep-May (doy 1-151, 244-365), 20% Jun-Aug (doy 152-243)
      - Nomad:    geometric ON/OFF blocks, 100% when online
      - Hoarder:  90% daily (storage imbalance is captured via S, not reliability)
      - Freeloader: 80% daily
    """
    rel = np.zeros((n_peers, n_days))
    day_indices = np.arange(n_days)
    doy = (day_indices % 365) + 1   # 1..365, simulation starts Jan 1
    dow = day_indices % 7           # 0=Mon .. 6=Sun

    for peer_idx in range(n_peers):
        atype = int(archetype_ids[peer_idx])

        if atype == 0:
            rel[peer_idx, :] = 0.99

        elif atype == 1:
            is_high = dow >= 4      # Fri=4, Sat=5, Sun=6
            rel[peer_idx, :] = np.where(is_high, 0.95, 0.30)

        elif atype == 2:
            is_summer = (doy >= 152) & (doy <= 243)
            rel[peer_idx, :] = np.where(is_summer, 0.20, 0.95)

        elif atype == 3:
            schedule = _make_nomad_schedule(
                n_days, config.nomad_on_mean, config.nomad_off_mean, rng
            )
            rel[peer_idx, :] = schedule

        elif atype == 4:
            rel[peer_idx, :] = 0.90

        elif atype == 5:
            rel[peer_idx, :] = 0.80

    return rel


# ---------------------------------------------------------------------------
# PI+S trust computation (weekly aggregation)
# ---------------------------------------------------------------------------

def _compute_pis_trust(
    week_scores_buffer: np.ndarray,
    n_complete_weeks: int,
    i_sum_weekly: np.ndarray,
    s_scores: np.ndarray,
    kp: float,
    ki: float,
    ks: float,
    p_weeks_window: int,
) -> np.ndarray:
    """Compute PI+S trust from weekly state.

    week_scores_buffer: circular buffer, shape (p_weeks_window, n_peers).
                        Contains binary weekly scores (1 if any pass that week).
    n_complete_weeks:   number of complete weeks processed so far.
    i_sum_weekly:       cumulative sum of weekly scores, shape (n_peers,).
    s_scores:           per-peer S term (clamped storage ratio), shape (n_peers,).
    """
    if n_complete_weeks == 0:
        n_peers = len(i_sum_weekly)
        return np.zeros(n_peers)

    filled = min(n_complete_weeks, p_weeks_window)
    p_score = week_scores_buffer[:filled].mean(axis=0)
    i_score = i_sum_weekly / n_complete_weeks
    return kp * p_score + ki * i_score + ks * s_scores


# ---------------------------------------------------------------------------
# Core simulation
# ---------------------------------------------------------------------------

def simulate_one(config: Config, seed: int) -> dict[str, object]:
    """Run one Monte Carlo trial. Returns per-archetype trust at snapshot months."""
    rng = np.random.default_rng(seed)

    n = config.n_peers
    n_days = config.n_days

    # Assign archetype IDs
    fractions = np.array(config.archetype_fractions)
    counts = np.round(fractions * n).astype(int)
    counts[-1] = n - counts[:-1].sum()
    archetype_ids = np.repeat(np.arange(len(ARCHETYPE_NAMES)), counts)
    assert len(archetype_ids) == n

    # Build reliability matrix
    rel_matrix = build_reliability_matrix(n, n_days, archetype_ids, config, rng)

    # Per-peer S scores (fixed, clamped to [0, 2.0])
    storage_ratios = np.array([
        ARCHETYPE_STORAGE_RATIO[int(a)] for a in archetype_ids
    ])
    s_scores = np.clip(storage_ratios, 0.0, 2.0)

    # Weekly state
    p_weeks_window = config.p_weeks_window
    week_scores_buffer = np.zeros((p_weeks_window, n))
    i_sum_weekly = np.zeros(n)
    n_complete_weeks = 0

    # Accumulate daily checks within current week
    current_week_any_pass = np.zeros(n, dtype=bool)

    # Snapshot months: convert to day indices (end of 30-day month = day month*30 - 1)
    snapshot_day_set = {m * 30 - 1 for m in SNAPSHOT_MONTHS if m * 30 <= n_days}

    # trust_at_snapshot[m_idx][archetype] = list of mean trust per archetype
    # We return raw archetype-level means for this seed.
    trust_snapshots: dict[int, list[float]] = {}  # month -> [trust per archetype]

    for day in range(n_days):
        # Daily proof-of-storage checks
        checks = rng.random(n) < rel_matrix[:, day]
        current_week_any_pass |= checks

        # End of week (every 7 days starting from day 6, 13, 20, ...)
        if (day + 1) % 7 == 0:
            week_score = current_week_any_pass.astype(np.float64)
            slot = n_complete_weeks % p_weeks_window
            week_scores_buffer[slot] = week_score
            i_sum_weekly += week_score
            n_complete_weeks += 1
            current_week_any_pass = np.zeros(n, dtype=bool)

        # Monthly snapshot
        if day in snapshot_day_set:
            month = (day + 1) // 30  # 1-based month number

            # For the current (possibly incomplete) week, compute a partial
            # weekly score so snapshots mid-week are not completely blind.
            days_in_current_partial_week = (day + 1) % 7
            if days_in_current_partial_week == 0:
                # Just completed a week; use committed state
                trust = _compute_pis_trust(
                    week_scores_buffer, n_complete_weeks, i_sum_weekly,
                    s_scores, config.kp, config.ki, config.ks, p_weeks_window,
                )
            else:
                # Include partial week as a prospective score
                partial_score = current_week_any_pass.astype(np.float64)
                temp_n = n_complete_weeks + 1
                temp_i_sum = i_sum_weekly + partial_score
                slot = n_complete_weeks % p_weeks_window
                # Temporarily put partial score into the buffer copy
                temp_buffer = week_scores_buffer.copy()
                temp_buffer[slot] = partial_score
                trust = _compute_pis_trust(
                    temp_buffer, temp_n, temp_i_sum,
                    s_scores, config.kp, config.ki, config.ks, p_weeks_window,
                )

            month_trust = []
            for atype in range(len(ARCHETYPE_NAMES)):
                mask = archetype_ids == atype
                if mask.sum() > 0:
                    month_trust.append(float(trust[mask].mean()))
                else:
                    month_trust.append(0.0)
            trust_snapshots[month] = month_trust

    return {"trust_snapshots": trust_snapshots}


# ---------------------------------------------------------------------------
# Experiment runner for a single config
# ---------------------------------------------------------------------------

def run_config(config: Config, n_jobs: int = 1) -> dict[str, object]:
    """Run Monte Carlo over all seeds for one config. Returns aggregated results."""
    t0 = time.time()

    if n_jobs == 1:
        all_results = [simulate_one(config, seed) for seed in range(config.n_seeds)]
    else:
        all_results = Parallel(n_jobs=n_jobs)(
            delayed(simulate_one)(config, seed) for seed in range(config.n_seeds)
        )

    elapsed = time.time() - t0

    n_archetypes = len(ARCHETYPE_NAMES)

    # Aggregate over seeds for each snapshot month
    # trust_mean[month][archetype], trust_std[month][archetype]
    trust_mean: dict[int, list[float]] = {}
    trust_std: dict[int, list[float]] = {}

    valid_months = [m for m in SNAPSHOT_MONTHS if m * 30 <= config.n_days]
    for month in valid_months:
        # Collect trust vectors across seeds for this month
        seed_trusts = []
        for r in all_results:
            snaps = r["trust_snapshots"]  # type: ignore[index]
            if month in snaps:
                seed_trusts.append(snaps[month])

        if seed_trusts:
            arr = np.array(seed_trusts)          # (n_seeds, n_archetypes)
            trust_mean[month] = arr.mean(axis=0).tolist()
            trust_std[month] = arr.std(axis=0).tolist()
        else:
            trust_mean[month] = [0.0] * n_archetypes
            trust_std[month] = [0.0] * n_archetypes

    return {
        "trust_mean": trust_mean,
        "trust_std": trust_std,
        "elapsed_sec": elapsed,
        "valid_months": valid_months,
    }


# ---------------------------------------------------------------------------
# Sweep runner: run all 54 configs in parallel at the config level
# ---------------------------------------------------------------------------

def _run_config_seed(config: Config, seed: int) -> tuple[float, float, int, int, int, dict[int, list[float]]]:
    """Worker: run one (config, seed) pair. Returns (kp, ki, ks, seed, ..., snapshots)."""
    result = simulate_one(config, seed)
    return (config.kp, config.ki, config.ks, seed,
            id(config), result["trust_snapshots"])  # type: ignore[return-value]


class SweepResult(NamedTuple):
    kp: float
    ki: float
    ks: float
    tau_by_month: dict[int, float]   # month -> tau
    trust_mean: dict[int, list[float]]
    trust_std: dict[int, list[float]]


def run_sweep(base_config: Config, n_jobs: int = 1) -> list[SweepResult]:
    """Run the full parameter sweep. Returns one SweepResult per config."""
    configs = sweep_configs(base_config)
    valid_months = [m for m in SNAPSHOT_MONTHS if m * 30 <= base_config.n_days]
    n_archetypes = len(ARCHETYPE_NAMES)

    print(f"Running sweep: {len(configs)} configs x {base_config.n_seeds} seeds "
          f"x {base_config.n_days} days x {base_config.n_peers} peers")
    print(f"Total tasks: {len(configs) * base_config.n_seeds} (seed-level jobs)")

    # Build flat list of (config, seed) tasks for maximum parallelism
    tasks: list[tuple[Config, int]] = [
        (cfg, seed)
        for cfg in configs
        for seed in range(base_config.n_seeds)
    ]

    t0 = time.time()

    if n_jobs == 1:
        raw_results = [simulate_one(cfg, seed) for cfg, seed in tasks]
    else:
        raw_results = Parallel(n_jobs=n_jobs)(
            delayed(simulate_one)(cfg, seed) for cfg, seed in tasks
        )

    elapsed = time.time() - t0
    print(f"All seeds done in {elapsed:.1f}s")

    # Group results by (kp, ki, ks)
    n_seeds = base_config.n_seeds
    sweep_results: list[SweepResult] = []

    for cfg_idx, cfg in enumerate(configs):
        seed_results = raw_results[cfg_idx * n_seeds: (cfg_idx + 1) * n_seeds]

        trust_mean: dict[int, list[float]] = {}
        trust_std: dict[int, list[float]] = {}

        for month in valid_months:
            seed_trusts = []
            for r in seed_results:
                snaps = r["trust_snapshots"]  # type: ignore[index]
                if month in snaps:
                    seed_trusts.append(snaps[month])

            if seed_trusts:
                arr = np.array(seed_trusts)
                trust_mean[month] = arr.mean(axis=0).tolist()
                trust_std[month] = arr.std(axis=0).tolist()
            else:
                trust_mean[month] = [0.0] * n_archetypes
                trust_std[month] = [0.0] * n_archetypes

        tau_by_month = {
            month: _kendall_tau(trust_mean[month])
            for month in valid_months
        }

        sweep_results.append(SweepResult(
            kp=cfg.kp,
            ki=cfg.ki,
            ks=cfg.ks,
            tau_by_month=tau_by_month,
            trust_mean=trust_mean,
            trust_std=trust_std,
        ))

    return sweep_results


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def _kendall_tau(trust_scores_list: list[float]) -> float:
    """Kendall's tau between trust scores and actual usefulness.

    Higher trust should correlate with lower (better) actual rank.
    We negate the actual ranks so both arrays have "higher = better" direction.
    """
    trust_scores = np.array(trust_scores_list)
    actual_ranks = np.array(ACTUAL_USEFULNESS_RANK)
    tau, _ = kendalltau(trust_scores, -actual_ranks)
    return float(tau)


def rank_archetypes_by_trust(trust_scores: list[float]) -> list[int]:
    """Return 1-based ranks (rank 1 = highest trust) for each archetype."""
    arr = np.array(trust_scores)
    order = np.argsort(-arr)
    ranks = np.empty(len(arr), dtype=int)
    for rank, idx in enumerate(order, 1):
        ranks[idx] = rank
    return ranks.tolist()


def find_best_config(sweep_results: list[SweepResult], target_month: int = 60) -> SweepResult:
    """Return the config with the highest Kendall's tau at target_month."""
    return max(sweep_results, key=lambda r: r.tau_by_month.get(target_month, -2.0))


def find_pi_only_config(sweep_results: list[SweepResult]) -> SweepResult | None:
    """Find the PI-only baseline (ks=0.0, kp=0.5, ki=2.0) from sweep results."""
    for r in sweep_results:
        if r.ks == 0.0 and r.kp == 0.5 and r.ki == 2.0:
            return r
    # Fallback: any ks=0 config
    for r in sweep_results:
        if r.ks == 0.0:
            return r
    return None


# ---------------------------------------------------------------------------
# Output / reporting
# ---------------------------------------------------------------------------

def print_sweep_summary(sweep_results: list[SweepResult]) -> None:
    """Print tau at month 60 for all 54 configs, sorted descending."""
    print("\n=== SWEEP SUMMARY: Kendall's tau at Month 60 ===")
    print(f"{'kp':>6} {'ki':>6} {'ks':>6}  "
          + "  ".join(f"M{m:>2}" for m in SNAPSHOT_MONTHS))
    print("-" * (6 + 6 + 6 + 3 + len(SNAPSHOT_MONTHS) * 8))

    sorted_results = sorted(
        sweep_results,
        key=lambda r: r.tau_by_month.get(60, -2.0),
        reverse=True,
    )
    for sr in sorted_results:
        tau_cells = "  ".join(
            f"{sr.tau_by_month.get(m, float('nan')):>5.2f}"
            for m in SNAPSHOT_MONTHS
        )
        print(f"{sr.kp:>6.1f} {sr.ki:>6.1f} {sr.ks:>6.1f}  {tau_cells}")


def print_trust_table(
    trust_mean: dict[int, list[float]],
    trust_std: dict[int, list[float]],
    month: int,
    kp: float,
    ki: float,
    ks: float,
) -> None:
    """Print trust table for a given month with PI+S scores and ranks."""
    scores = trust_mean[month]
    stds = trust_std[month]
    pi_ranks = rank_archetypes_by_trust(scores)
    actual_ranks = ACTUAL_USEFULNESS_RANK
    tau = _kendall_tau(scores)

    print(f"\n=== PI+S TRUST BY ARCHETYPE (Month {month}, "
          f"kp={kp}, ki={ki}, ks={ks}) ===")
    print(f"{'Archetype':<16} {'Trust':>8} {'Std':>8} "
          f"{'PI+S rank':>10} {'Actual rank':>12}")
    print("-" * 58)

    order = np.argsort(actual_ranks)
    for i in order:
        name = ARCHETYPE_NAMES[i]
        print(f"{name:<16} {scores[i]:>8.3f} {stds[i]:>8.3f} "
              f"{pi_ranks[i]:>10d} {actual_ranks[i]:>12d}")

    print(f"\nKendall's tau at month {month}: {tau:.3f}")
    print("  (tau=1.0 = perfect alignment, tau=0 = random, tau<0 = inverted)")


def print_monthly_trajectory(
    trust_mean: dict[int, list[float]],
    kp: float,
    ki: float,
    ks: float,
) -> None:
    """Print trust at each snapshot month for the best config."""
    print(f"\n=== MONTHLY TRUST TRAJECTORY (kp={kp}, ki={ki}, ks={ks}) ===")
    header = f"{'Month':>6}"
    for name in ARCHETYPE_NAMES:
        header += f"  {name:>10}"
    header += f"  {'Tau':>6}"
    print(header)
    print("-" * (6 + 12 * len(ARCHETYPE_NAMES) + 9))

    for month in sorted(trust_mean.keys()):
        row = f"{month:>6}"
        for atype in range(len(ARCHETYPE_NAMES)):
            row += f"  {trust_mean[month][atype]:>10.3f}"
        tau = _kendall_tau(trust_mean[month])
        row += f"  {tau:>6.3f}"
        print(row)


def print_comparison(
    best: SweepResult,
    pi_only: SweepResult | None,
) -> None:
    """Print head-to-head comparison of best PI+S vs PI-only baseline."""
    print("\n=== COMPARISON: Best PI+S vs PI-only (ks=0.0) ===")
    print(f"{'Config':<28} " + "  ".join(f"M{m:>2}" for m in SNAPSHOT_MONTHS))
    print("-" * (28 + len(SNAPSHOT_MONTHS) * 8))

    best_label = f"PI+S kp={best.kp} ki={best.ki} ks={best.ks}"
    best_taus = "  ".join(
        f"{best.tau_by_month.get(m, float('nan')):>5.2f}"
        for m in SNAPSHOT_MONTHS
    )
    print(f"{best_label:<28} {best_taus}")

    if pi_only is not None:
        pi_label = f"PI   kp={pi_only.kp} ki={pi_only.ki} ks=0.0"
        pi_taus = "  ".join(
            f"{pi_only.tau_by_month.get(m, float('nan')):>5.2f}"
            for m in SNAPSHOT_MONTHS
        )
        print(f"{pi_label:<28} {pi_taus}")

        print("\nDelta (PI+S minus PI-only):")
        deltas = "  ".join(
            f"{best.tau_by_month.get(m, 0.0) - pi_only.tau_by_month.get(m, 0.0):>+5.2f}"
            for m in SNAPSHOT_MONTHS
        )
        print(f"{'':28} {deltas}")
    else:
        print("PI-only baseline not found in sweep results.")

    # Archetype-level ranks at month 60
    print(f"\nArchetype ranking at Month 60:")
    print(f"{'Archetype':<16} {'Actual':>8} {'PI+S rank':>10}", end="")
    if pi_only is not None:
        print(f" {'PI rank':>8}", end="")
    print()
    print("-" * (16 + 8 + 10 + (9 if pi_only else 0)))

    actual_order = np.argsort(ACTUAL_USEFULNESS_RANK)
    best_ranks60 = rank_archetypes_by_trust(best.trust_mean.get(60, [0.0] * 6))
    pi_ranks60 = (
        rank_archetypes_by_trust(pi_only.trust_mean.get(60, [0.0] * 6))
        if pi_only else None
    )

    for i in actual_order:
        line = (f"{ARCHETYPE_NAMES[i]:<16} {ACTUAL_USEFULNESS_RANK[i]:>8} "
                f"{best_ranks60[i]:>10}")
        if pi_ranks60 is not None:
            line += f" {pi_ranks60[i]:>8}"
        print(line)


def print_summary(
    base_config: Config,
    sweep_results: list[SweepResult],
    elapsed_total: float,
) -> None:
    """Print complete experiment summary."""
    print(f"\nConfig: {base_config.n_peers} peers, {base_config.n_days} days "
          f"({base_config.n_days // 30} months), {base_config.n_seeds} seeds")
    print(f"P_weekly window: {base_config.p_weeks_window} weeks")
    print(f"Archetype distribution: "
          + ", ".join(
              f"{ARCHETYPE_NAMES[i]}={base_config.archetype_fractions[i]*100:.0f}%"
              for i in range(len(ARCHETYPE_NAMES))
          ))
    print(f"Total runtime: {elapsed_total:.1f}s")
    print(f"Sweep: {len(KP_VALUES)}x{len(KI_VALUES)}x{len(KS_VALUES)} = "
          f"{len(sweep_results)} configs")

    print_sweep_summary(sweep_results)

    best = find_best_config(sweep_results, target_month=60)
    pi_only = find_pi_only_config(sweep_results)

    print(f"\n>>> BEST CONFIG: kp={best.kp}, ki={best.ki}, ks={best.ks}")
    print(f"    tau at month 60 = {best.tau_by_month.get(60, float('nan')):.3f}")

    # Full trust table at months 6, 12, 24, 36, 48, 60 for best config
    valid_months = sorted(best.trust_mean.keys())
    for month in [6, 12, 24, 36, 48, 60]:
        if month in best.trust_mean:
            print_trust_table(best.trust_mean, best.trust_std, month,
                              best.kp, best.ki, best.ks)

    print_monthly_trajectory(best.trust_mean, best.kp, best.ki, best.ks)
    print_comparison(best, pi_only)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_results(
    base_config: Config,
    sweep_results: list[SweepResult],
    elapsed_total: float,
    path: Path,
) -> None:
    """Save full sweep results to JSON."""
    best = find_best_config(sweep_results, target_month=60)
    pi_only = find_pi_only_config(sweep_results)

    output = {
        "experiment": "15: PI+S Convergence",
        "base_config": asdict(base_config),
        "archetype_names": ARCHETYPE_NAMES,
        "archetype_storage_ratio": ARCHETYPE_STORAGE_RATIO,
        "actual_usefulness_rank": ACTUAL_USEFULNESS_RANK,
        "snapshot_months": SNAPSHOT_MONTHS,
        "elapsed_total_sec": elapsed_total,
        "sweep": [
            {
                "kp": sr.kp,
                "ki": sr.ki,
                "ks": sr.ks,
                "tau_by_month": {str(k): v for k, v in sr.tau_by_month.items()},
                "trust_mean": {str(k): v for k, v in sr.trust_mean.items()},
                "trust_std": {str(k): v for k, v in sr.trust_std.items()},
            }
            for sr in sweep_results
        ],
        "best_config": {
            "kp": best.kp,
            "ki": best.ki,
            "ks": best.ks,
            "tau_at_month_60": best.tau_by_month.get(60, None),
        },
        "pi_only_baseline": {
            "kp": pi_only.kp if pi_only else None,
            "ki": pi_only.ki if pi_only else None,
            "ks": 0.0,
            "tau_at_month_60": pi_only.tau_by_month.get(60, None) if pi_only else None,
        },
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(output, indent=2))
    print(f"\nResults saved to {path}")


def plot_results(
    sweep_results: list[SweepResult],
    base_config: Config,
    output_dir: Path,
) -> None:
    """Generate plots if matplotlib is available."""
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed, skipping plots")
        return

    output_dir.mkdir(parents=True, exist_ok=True)
    best = find_best_config(sweep_results, target_month=60)
    pi_only = find_pi_only_config(sweep_results)

    colors = ["#2196F3", "#FF9800", "#9C27B0", "#795548", "#F44336", "#4CAF50"]
    linestyles = ["-", "--", "-.", ":", "-", "--"]
    months = sorted(best.trust_mean.keys())

    # Plot 1: Trust trajectories for best config
    fig, ax = plt.subplots(figsize=(12, 6))
    for i, name in enumerate(ARCHETYPE_NAMES):
        mean = [best.trust_mean[m][i] for m in months]
        std = [best.trust_std[m][i] for m in months]
        mean_arr = np.array(mean)
        std_arr = np.array(std)
        ax.plot(months, mean_arr, color=colors[i], linestyle=linestyles[i],
                linewidth=2, label=name)
        ax.fill_between(months, mean_arr - std_arr, mean_arr + std_arr,
                        color=colors[i], alpha=0.1)

    ax.set_xlabel("Month")
    ax.set_ylabel("PI+S Trust Score")
    ax.set_title(
        f"Trust Trajectories: Best PI+S Config\n"
        f"(kp={best.kp}, ki={best.ki}, ks={best.ks}, "
        f"{base_config.n_seeds} seeds)"
    )
    ax.legend(loc="lower right")
    ax.grid(True, alpha=0.3)

    traj_path = output_dir / "pis_trust_trajectories.png"
    fig.savefig(traj_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Plot saved to {traj_path}")

    # Plot 2: Kendall's tau at month 60 as function of ks, per (kp, ki) pair
    fig, axes = plt.subplots(1, len(KI_VALUES), figsize=(14, 5), sharey=True)
    for col, ki_val in enumerate(KI_VALUES):
        ax = axes[col]
        for kp_val in KP_VALUES:
            ks_vals = []
            taus_60 = []
            for sr in sweep_results:
                if sr.kp == kp_val and sr.ki == ki_val:
                    ks_vals.append(sr.ks)
                    taus_60.append(sr.tau_by_month.get(60, float("nan")))
            sorted_pairs = sorted(zip(ks_vals, taus_60))
            xs = [p[0] for p in sorted_pairs]
            ys = [p[1] for p in sorted_pairs]
            ax.plot(xs, ys, "o-", label=f"kp={kp_val}", linewidth=1.5)

        ax.axhline(0.8, color="green", linestyle="--", alpha=0.5, label="tau=0.8")
        ax.set_xlabel("ks (storage weight)")
        ax.set_title(f"ki={ki_val}")
        ax.set_ylim(-0.2, 1.1)
        ax.grid(True, alpha=0.3)
        if col == 0:
            ax.set_ylabel("Kendall's tau @ Month 60")
        ax.legend(fontsize=8)

    fig.suptitle("PI+S Sweep: Kendall's tau at Month 60 by (kp, ki, ks)")
    sweep_path = output_dir / "pis_sweep_tau60.png"
    fig.savefig(sweep_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Plot saved to {sweep_path}")

    # Plot 3: tau trajectory comparison — best PI+S vs PI-only
    if pi_only is not None:
        fig, ax = plt.subplots(figsize=(10, 5))
        best_months = sorted(best.tau_by_month.keys())
        best_taus = [best.tau_by_month[m] for m in best_months]
        ax.plot(best_months, best_taus, "b-o", linewidth=2,
                label=f"PI+S kp={best.kp} ki={best.ki} ks={best.ks}")

        pi_months = sorted(pi_only.tau_by_month.keys())
        pi_taus = [pi_only.tau_by_month[m] for m in pi_months]
        ax.plot(pi_months, pi_taus, "r--s", linewidth=2,
                label=f"PI-only kp={pi_only.kp} ki={pi_only.ki}")

        ax.axhline(0.8, color="green", linestyle=":", alpha=0.6, label="tau=0.8")
        ax.axhline(0.0, color="gray", linestyle="-", alpha=0.3)
        ax.set_xlabel("Month")
        ax.set_ylabel("Kendall's tau")
        ax.set_title("Ranking Quality: Best PI+S vs PI-only\n"
                     "(tau=1.0 = perfect, tau=0 = random, tau<0 = inverted)")
        ax.legend()
        ax.set_ylim(-0.2, 1.1)
        ax.grid(True, alpha=0.3)

        cmp_path = output_dir / "pis_vs_pi_comparison.png"
        fig.savefig(cmp_path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        print(f"Plot saved to {cmp_path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SyncBack Experiment 15: PI+S Convergence"
    )
    parser.add_argument("--peers", type=int, default=200,
                        help="Total number of peers (default: 200)")
    parser.add_argument("--days", type=int, default=1825,
                        help="Simulation duration in days (default: 1825 = 5 years)")
    parser.add_argument("--seeds", type=int, default=30,
                        help="Monte Carlo seeds per config (default: 30)")
    parser.add_argument("--weeks-window", type=int, default=4,
                        help="P_weekly rolling window in weeks (default: 4)")
    parser.add_argument("--jobs", type=int, default=1,
                        help="Parallel jobs for joblib (default: 1)")
    parser.add_argument("--output", type=str, default="results/pis_convergence",
                        help="Output directory (default: results/pis_convergence)")
    parser.add_argument("--no-plot", action="store_true",
                        help="Skip plot generation")
    args = parser.parse_args()

    output_dir = Path(args.output)

    base_config = Config(
        n_peers=args.peers,
        n_days=args.days,
        n_seeds=args.seeds,
        p_weeks_window=args.weeks_window,
    )

    print("=== SYNCBACK EXPERIMENT 15: PI+S CONVERGENCE ===\n")
    print("Testing: trust = kp * P_weekly + ki * I + ks * S")
    print(f"P_weekly: rolling {args.weeks_window}-week window of binary weekly scores")
    print("S: storage_ratio = gb_stored_for_others / gb_stored_by_others (clamped [0,2])")
    print()

    t0 = time.time()
    sweep_results = run_sweep(base_config, n_jobs=args.jobs)
    elapsed_total = time.time() - t0

    print_summary(base_config, sweep_results, elapsed_total)
    save_results(base_config, sweep_results, elapsed_total,
                 output_dir / "run.json")

    if not args.no_plot:
        plot_results(sweep_results, base_config, output_dir)


if __name__ == "__main__":
    main()
