"""
Viaticum Simulation #13: Behavior Models / Archetypes

Question: What realistic node behavior models should we use?
Does PI reputation correctly rank diverse behavioral archetypes?

Model:
- 200 peers distributed across 6 behavioral archetypes
- Each archetype has a distinct reliability function r(t) that returns
  the probability of passing a proof-of-storage check on day t
- PI trust: trust = 0.5*P + 2.0*I, P = 30-day rolling window, I = cumulative average
- Simulation runs for 24 months (730 days) with daily resolution

Archetypes:
  1. Reliable      (99%)  - always-on desktop/NAS
  2. Weekend       (70%)  - online evenings and weekends
  3. Seasonal      (80%)  - student: high during semester, low in summer
  4. Nomad         (50%)  - laptop, random ON/OFF blocks of 1-7 days
  5. Hoarder       (90%)  - reliable online but minimal spare storage capacity
  6. Freeloader    (80%)  - online often but stores very little

Key finding this measures:
- Does PI rank archetypes in the "right" usefulness order?
- How quickly does trust recover after seasonal absence?
- Does PI detect storage imbalance (Hoarder/Freeloader) or only uptime?

Usage:
    python behavior_models.py                    # default run
    python behavior_models.py --jobs 4           # use 4 cores
    python behavior_models.py --seeds 100        # more Monte Carlo runs
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path

import numpy as np
from joblib import Parallel, delayed
from scipy.stats import kendalltau


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class Config:
    n_peers: int = 200
    n_days: int = 730           # 24 months
    n_seeds: int = 30           # Monte Carlo runs
    # PI trust parameters (established in experiment 1)
    kp: float = 0.5
    ki: float = 2.0
    p_window: int = 30          # P: rolling window in days
    # Archetype distribution: fractions must sum to 1.0
    # [Reliable, Weekend, Seasonal, Nomad, Hoarder, Freeloader]
    archetype_fractions: tuple = (0.40, 0.20, 0.15, 0.10, 0.10, 0.05)
    # Nomad block parameters (geometric distribution for ON/OFF durations)
    nomad_on_mean: float = 3.5  # mean days ON
    nomad_off_mean: float = 3.5 # mean days OFF


ARCHETYPE_NAMES = [
    "Reliable",
    "Weekend",
    "Seasonal",
    "Nomad",
    "Hoarder",
    "Freeloader",
]

# "Actual usefulness" ranking (lower = better, 1-indexed)
# Reliable > Weekend > Seasonal > Nomad > Hoarder ~ Freeloader
# Hoarder and Freeloader both rank 5 (tied) due to storage issues.
# For Kendall's tau we use a numeric score: lower = more useful to network.
ACTUAL_USEFULNESS_RANK = [1, 2, 3, 4, 5, 5]   # per archetype index


# ---------------------------------------------------------------------------
# Reliability functions
# ---------------------------------------------------------------------------

def _make_nomad_schedule(n_days: int, on_mean: float, off_mean: float,
                         rng: np.random.Generator) -> np.ndarray:
    """Generate a binary ON/OFF schedule for a Nomad peer.

    ON and OFF block durations are drawn from a geometric distribution.
    Returns an array of shape (n_days,) with values 0.0 or the base
    reliability when online.
    """
    schedule = np.zeros(n_days)
    day = 0
    online = rng.random() < 0.5  # start randomly ON or OFF
    while day < n_days:
        if online:
            # Geometric: p = 1/mean; clip to [1, n_days]
            duration = int(rng.geometric(p=1.0 / on_mean))
        else:
            duration = int(rng.geometric(p=1.0 / off_mean))
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
    """Build a (n_peers, n_days) matrix of daily reliability values r(t).

    Each cell contains the probability that peer i passes a storage check
    on day t. Values are in [0, 1].
    """
    rel = np.zeros((n_peers, n_days))
    day_indices = np.arange(n_days)

    # Day-of-year: simulation starts on Jan 1
    # Day-of-week: 0=Monday ... 6=Sunday
    doy = (day_indices % 365) + 1          # 1..365
    dow = day_indices % 7                  # 0..6

    for peer_idx in range(n_peers):
        atype = archetype_ids[peer_idx]

        if atype == 0:
            # Reliable: constant 99%
            rel[peer_idx, :] = 0.99

        elif atype == 1:
            # Weekend Warrior: 0.95 on evenings/weekends, 0.30 on weekday daytime
            # Model: Mon-Thu as "low", Fri-Sun as "high"
            is_high = (dow >= 4)  # Fri=4, Sat=5, Sun=6
            rel[peer_idx, :] = np.where(is_high, 0.95, 0.30)

        elif atype == 2:
            # Seasonal (student): 0.95 during semester (Sep-May = doy 1-151, 244-365)
            # 0.20 during summer (Jun-Aug = doy 152-243)
            is_summer = (doy >= 152) & (doy <= 243)
            rel[peer_idx, :] = np.where(is_summer, 0.20, 0.95)

        elif atype == 3:
            # Nomad: random ON/OFF blocks; base reliability when ON = 1.0
            # (online or offline — no partial states)
            schedule = _make_nomad_schedule(
                n_days, config.nomad_on_mean, config.nomad_off_mean, rng
            )
            rel[peer_idx, :] = schedule * 1.0

        elif atype == 4:
            # Hoarder: 90% uptime (reliable for checks) but provides only
            # 20% of expected storage capacity. The PI controller only sees
            # the check result, NOT the storage capacity imbalance.
            # This archetype exposes the gap in the current trust model.
            rel[peer_idx, :] = 0.90

        elif atype == 5:
            # Freeloader: 80% online, stores only 10% of what they request.
            # Same gap: PI sees uptime, not the storage ratio.
            rel[peer_idx, :] = 0.80

    return rel


# ---------------------------------------------------------------------------
# PI trust computation
# ---------------------------------------------------------------------------

def compute_pi_trust(
    checks_history: np.ndarray,
    t: int,
    p_buffer: np.ndarray,
    i_sum: np.ndarray,
    kp: float,
    ki: float,
    p_window: int,
) -> np.ndarray:
    """Compute PI trust scores from rolling P buffer and cumulative I.

    checks_history is unused here (we use incremental buffers instead).
    t: current day index (0-based), used for I denominator.
    p_buffer: circular buffer shape (p_window, n_peers).
    i_sum: cumulative sum of checks, shape (n_peers,).
    """
    n_days_filled = t + 1
    filled = min(n_days_filled, p_window)
    p_score = p_buffer[:filled].mean(axis=0)
    i_score = i_sum / n_days_filled
    return kp * p_score + ki * i_score


# ---------------------------------------------------------------------------
# Core simulation
# ---------------------------------------------------------------------------

def simulate_one(config: Config, seed: int) -> dict:
    """Run one Monte Carlo trial. Returns per-archetype trust trajectories."""
    rng = np.random.default_rng(seed)

    n = config.n_peers
    n_days = config.n_days

    # Assign archetype IDs to peers
    fractions = np.array(config.archetype_fractions)
    counts = np.round(fractions * n).astype(int)
    # Adjust rounding error on last archetype
    counts[-1] = n - counts[:-1].sum()
    archetype_ids = np.repeat(np.arange(len(ARCHETYPE_NAMES)), counts)
    assert len(archetype_ids) == n

    # Build full reliability matrix (n_peers x n_days)
    rel_matrix = build_reliability_matrix(n, n_days, archetype_ids, config, rng)

    # PI trust state
    p_buffer = np.zeros((config.p_window, n))
    i_sum = np.zeros(n)

    # Monthly snapshots: trust per archetype (mean across peers of that type)
    # months 1..24
    n_months = n_days // 30
    # trust_monthly[month_idx][archetype_idx] = mean trust
    trust_monthly: list[list[float]] = []

    for day in range(n_days):
        # Proof-of-storage check: Bernoulli(r(t)) per peer
        checks = (rng.random(n) < rel_matrix[:, day]).astype(np.float64)

        # Update P circular buffer
        p_buffer[day % config.p_window] = checks

        # Update I cumulative sum
        i_sum += checks

        # End of each 30-day month: record trust snapshot
        if (day + 1) % 30 == 0:
            filled = min(day + 1, config.p_window)
            p_score = p_buffer[:filled].mean(axis=0)
            i_score = i_sum / (day + 1)
            trust = config.kp * p_score + config.ki * i_score

            # Per-archetype mean trust
            month_trust = []
            for atype in range(len(ARCHETYPE_NAMES)):
                mask = archetype_ids == atype
                if mask.sum() > 0:
                    month_trust.append(float(trust[mask].mean()))
                else:
                    month_trust.append(0.0)
            trust_monthly.append(month_trust)

    return {
        "trust_monthly": trust_monthly,  # list of 24 lists of 6 floats
    }


# ---------------------------------------------------------------------------
# Experiment runner
# ---------------------------------------------------------------------------

def run_experiment(config: Config, n_jobs: int = 1) -> dict:
    """Run Monte Carlo experiment. Returns aggregated results."""
    t0 = time.time()

    if n_jobs == 1:
        all_results = [
            simulate_one(config, seed) for seed in range(config.n_seeds)
        ]
    else:
        all_results = Parallel(n_jobs=n_jobs)(
            delayed(simulate_one)(config, seed)
            for seed in range(config.n_seeds)
        )

    elapsed = time.time() - t0

    n_months = config.n_days // 30
    n_archetypes = len(ARCHETYPE_NAMES)

    # Aggregate: shape (n_seeds, n_months, n_archetypes)
    trust_array = np.array([r["trust_monthly"] for r in all_results])

    # Mean and std across seeds: shape (n_months, n_archetypes)
    trust_mean = trust_array.mean(axis=0)
    trust_std = trust_array.std(axis=0)

    return {
        "trust_mean": trust_mean,    # (n_months, n_archetypes)
        "trust_std": trust_std,
        "elapsed_sec": elapsed,
        "n_seeds": config.n_seeds,
        "n_months": n_months,
    }


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def compute_kendall_tau_at_month(
    trust_mean: np.ndarray,
    month_idx: int,
) -> float:
    """Compute Kendall's tau between PI trust ranking and actual usefulness.

    trust_mean: shape (n_months, n_archetypes)
    month_idx: 0-based index into trust_mean (month 12 = index 11)

    Actual usefulness rank: lower is better (Reliable=1, ..., Freeloader=5).
    Tau > 0 means PI trust correlates with actual usefulness (inverted:
    higher trust = lower rank number = more useful).
    """
    pi_scores = trust_mean[month_idx]           # higher = more trusted
    actual_ranks = np.array(ACTUAL_USEFULNESS_RANK)  # lower = more useful
    # Negate actual ranks so higher = more useful (aligns with trust direction)
    tau, _ = kendalltau(pi_scores, -actual_ranks)
    return float(tau)


def rank_archetypes_by_trust(trust_scores: np.ndarray) -> list[int]:
    """Return 1-based ranks (1 = highest trust) for each archetype."""
    # argsort descending
    order = np.argsort(-trust_scores)
    ranks = np.empty(len(trust_scores), dtype=int)
    for rank, idx in enumerate(order, 1):
        ranks[idx] = rank
    return ranks.tolist()


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_trust_table(
    trust_mean: np.ndarray,
    trust_std: np.ndarray,
    month: int,
) -> None:
    """Print trust table for a given month (1-based)."""
    month_idx = month - 1
    scores = trust_mean[month_idx]
    stds = trust_std[month_idx]
    pi_ranks = rank_archetypes_by_trust(scores)
    actual_ranks = ACTUAL_USEFULNESS_RANK

    tau = compute_kendall_tau_at_month(trust_mean, month_idx)

    print(f"\n=== TRUST BY ARCHETYPE (Month {month}) ===")
    print(f"{'Archetype':<16} {'Trust_mean':>10} {'Trust_std':>10} "
          f"{'PI_rank':>8} {'Actual_rank':>12}")
    print("-" * 60)
    # Print in actual usefulness order for readability
    order = np.argsort(actual_ranks)
    for i in order:
        name = ARCHETYPE_NAMES[i]
        print(f"{name:<16} {scores[i]:>10.3f} {stds[i]:>10.3f} "
              f"{pi_ranks[i]:>8d} {actual_ranks[i]:>12d}")
    print()
    print(f"Kendall's tau at month {month}: {tau:.3f}")
    print(f"  (tau=1.0 = perfect alignment, tau=0 = random, "
          f"tau<0 = inverted ranking)")


def print_trajectory_table(
    trust_mean: np.ndarray,
    n_months: int,
) -> None:
    """Print monthly trust trajectory for each archetype."""
    print("\n=== MONTHLY TRUST TRAJECTORIES ===")
    header = f"{'Month':>6}"
    for name in ARCHETYPE_NAMES:
        header += f"  {name:>10}"
    print(header)
    print("-" * (6 + 12 * len(ARCHETYPE_NAMES)))

    for m in range(n_months):
        row = f"{m + 1:>6}"
        for atype in range(len(ARCHETYPE_NAMES)):
            row += f"  {trust_mean[m, atype]:>10.3f}"
        print(row)


def print_seasonal_analysis(
    trust_mean: np.ndarray,
    trust_std: np.ndarray,
) -> None:
    """Analyze seasonal archetype: summer penalty and September recovery."""
    seasonal_idx = 2  # Seasonal archetype
    scores = trust_mean[:, seasonal_idx]

    # Summer months in simulation (months 6-8 and 18-20, roughly):
    # Year 1 summer: months 6-8 (Jun-Aug of the simulated year)
    # Year 2 summer: months 18-20
    # Semester months: 1-5, 9-12 (Jan-May, Sep-Dec)

    print("\n=== SEASONAL ARCHETYPE ANALYSIS ===")
    print("Month-by-month trust for Seasonal peer:")
    print(f"{'Month':>6} {'Trust':>8} {'Phase':>18}")
    print("-" * 36)

    for m in range(len(scores)):
        # Determine phase: summer = months 6-8 and 18-20
        month_in_year = (m % 12) + 1  # 1-12
        if 6 <= month_in_year <= 8:
            phase = "SUMMER (low)"
        elif month_in_year == 9:
            phase = "Sep recovery"
        else:
            phase = "semester"
        print(f"{m + 1:>6} {scores[m]:>8.3f} {phase:>18}")

    # Summer drop: compare month 5 (end of semester) to month 8 (end of summer)
    # Year 1
    if len(scores) >= 8:
        drop_y1 = scores[4] - scores[7]  # month 5 vs month 8
        recovery_m9 = scores[8] - scores[7] if len(scores) >= 9 else float("nan")
        print(f"\nYear 1: trust drop May->Aug = {drop_y1:+.3f}")
        print(f"Year 1: trust recovery Aug->Sep = {recovery_m9:+.3f}")

    # Year 2
    if len(scores) >= 20:
        drop_y2 = scores[16] - scores[19]  # month 17 vs month 20
        recovery_y2 = scores[20] - scores[19] if len(scores) >= 21 else float("nan")
        print(f"Year 2: trust drop May->Aug = {drop_y2:+.3f}")
        print(f"Year 2: trust recovery Aug->Sep = {recovery_y2:+.3f}")


def print_storage_fairness_analysis(
    trust_mean: np.ndarray,
    trust_std: np.ndarray,
) -> None:
    """Highlight the Hoarder/Freeloader gap in PI trust measurement."""
    print("\n=== STORAGE FAIRNESS: THE PI CONTROLLER'S BLIND SPOT ===")
    print()

    # At month 12 and 24, compare archetypes with similar uptime but
    # different storage behavior
    hoarder_idx = 4
    freeloader_idx = 5
    reliable_idx = 0

    for month in [12, 24]:
        m = month - 1
        scores = trust_mean[m]
        pi_ranks = rank_archetypes_by_trust(scores)

        print(f"Month {month}:")
        print(f"  Reliable   (99% uptime, full storage): "
              f"trust={scores[reliable_idx]:.3f}, PI rank #{pi_ranks[reliable_idx]}")
        print(f"  Hoarder    (90% uptime, 20% capacity): "
              f"trust={scores[hoarder_idx]:.3f}, PI rank #{pi_ranks[hoarder_idx]}")
        print(f"  Freeloader (80% uptime, 10% capacity): "
              f"trust={scores[freeloader_idx]:.3f}, PI rank #{pi_ranks[freeloader_idx]}")

        # The gap: Hoarder has 90% uptime → should rank just below Seasonal (80% avg)
        # But Hoarder only contributes 20% of expected storage.
        # PI doesn't see this → Hoarder is over-trusted relative to actual usefulness.
        hoarder_actual_rank = ACTUAL_USEFULNESS_RANK[hoarder_idx]
        hoarder_pi_rank = pi_ranks[hoarder_idx]
        gap = hoarder_actual_rank - hoarder_pi_rank  # positive = over-trusted
        if gap > 0:
            print(f"  -> Hoarder OVER-TRUSTED by {gap} rank position(s): "
                  f"PI ranks them #{hoarder_pi_rank}, actual usefulness #{hoarder_actual_rank}")
        elif gap < 0:
            print(f"  -> Hoarder under-trusted by {-gap} rank position(s)")
        else:
            print(f"  -> Hoarder ranked correctly")
        print()

    print("CONCLUSION: The PI controller measures check reliability (uptime),")
    print("NOT storage contribution. Hoarder and Freeloader can maintain")
    print("high trust scores despite contributing far less storage than they")
    print("consume. A storage-balance term must be added to the trust formula")
    print("to penalize this imbalance (see experiment 5: free_rider.py).")


def print_summary(config: Config, results: dict) -> None:
    """Print full experiment summary."""
    print(f"Config: {config.n_peers} peers, {config.n_days} days "
          f"({config.n_days // 30} months), {config.n_seeds} seeds")
    print(f"PI weights: kp={config.kp}, ki={config.ki}, "
          f"P-window={config.p_window}d")
    print(f"Archetype distribution: "
          + ", ".join(
              f"{ARCHETYPE_NAMES[i]}={config.archetype_fractions[i]*100:.0f}%"
              for i in range(len(ARCHETYPE_NAMES))
          ))
    print(f"Runtime: {results['elapsed_sec']:.1f}s")

    trust_mean = results["trust_mean"]
    trust_std = results["trust_std"]
    n_months = results["n_months"]

    # Trust tables at months 6, 12, 18, 24
    for month in [6, 12, 18, 24]:
        if month <= n_months:
            print_trust_table(trust_mean, trust_std, month)

    # Kendall's tau timeline
    print("\n=== KENDALL'S TAU OVER TIME ===")
    print(f"{'Month':>6} {'Tau':>8}  {'Assessment':}")
    print("-" * 42)
    for m in range(n_months):
        tau = compute_kendall_tau_at_month(trust_mean, m)
        if tau >= 0.8:
            assessment = "strong alignment"
        elif tau >= 0.6:
            assessment = "moderate alignment"
        elif tau >= 0.4:
            assessment = "weak alignment"
        elif tau >= 0.0:
            assessment = "near-random"
        else:
            assessment = "INVERTED (PI disagrees)"
        print(f"{m + 1:>6} {tau:>8.3f}  {assessment}")

    # Seasonal analysis
    print_seasonal_analysis(trust_mean, trust_std)

    # Storage fairness
    print_storage_fairness_analysis(trust_mean, trust_std)

    # Monthly trajectory table
    print_trajectory_table(trust_mean, n_months)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_results(config: Config, results: dict, path: Path) -> None:
    """Save results to JSON for later analysis/plotting."""
    output = {
        "config": asdict(config),
        "archetype_names": ARCHETYPE_NAMES,
        "actual_usefulness_rank": ACTUAL_USEFULNESS_RANK,
        "elapsed_sec": results["elapsed_sec"],
        "n_seeds": results["n_seeds"],
        "n_months": results["n_months"],
        # (n_months, n_archetypes) as nested lists
        "trust_mean": results["trust_mean"].tolist(),
        "trust_std": results["trust_std"].tolist(),
        # Kendall's tau per month
        "kendall_tau": [
            compute_kendall_tau_at_month(results["trust_mean"], m)
            for m in range(results["n_months"])
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(output, indent=2))
    print(f"\nResults saved to {path}")


def plot_results(results: dict, config: Config, output_dir: Path) -> None:
    """Generate plots if matplotlib is available."""
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed, skipping plots")
        return

    trust_mean = results["trust_mean"]   # (n_months, n_archetypes)
    trust_std = results["trust_std"]
    n_months = results["n_months"]
    months = np.arange(1, n_months + 1)

    colors = ["#2196F3", "#FF9800", "#9C27B0", "#795548", "#F44336", "#4CAF50"]
    linestyles = ["-", "--", "-.", ":", "-", "--"]

    # Plot 1: Trust trajectories for all archetypes
    fig, ax = plt.subplots(figsize=(12, 6))
    for i, name in enumerate(ARCHETYPE_NAMES):
        mean = trust_mean[:, i]
        std = trust_std[:, i]
        ax.plot(months, mean, color=colors[i], linestyle=linestyles[i],
                linewidth=2, label=name)
        ax.fill_between(months, mean - std, mean + std,
                        color=colors[i], alpha=0.1)

    # Mark summer periods (months 6-8 and 18-20)
    for start, end in [(5.5, 8.5), (17.5, 20.5)]:
        ax.axvspan(start, end, color="yellow", alpha=0.15, label="_summer")

    ax.set_xlabel("Month")
    ax.set_ylabel("PI Trust Score (kp*P + ki*I)")
    ax.set_title(
        f"Trust Trajectories by Behavioral Archetype\n"
        f"(kp={config.kp}, ki={config.ki}, P-window={config.p_window}d, "
        f"{config.n_seeds} seeds)"
    )
    ax.legend(loc="lower right")
    ax.set_xlim(1, n_months)
    ax.grid(True, alpha=0.3)

    traj_path = output_dir / "trust_trajectories.png"
    output_dir.mkdir(parents=True, exist_ok=True)
    fig.savefig(traj_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Plot saved to {traj_path}")

    # Plot 2: Kendall's tau over time
    taus = [
        compute_kendall_tau_at_month(trust_mean, m)
        for m in range(n_months)
    ]
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(months, taus, "b-o", markersize=4, linewidth=1.5)
    ax.axhline(0.8, color="green", linestyle="--", alpha=0.6, label="tau=0.8")
    ax.axhline(0.0, color="red", linestyle="-", alpha=0.3, label="tau=0")
    ax.set_xlabel("Month")
    ax.set_ylabel("Kendall's tau")
    ax.set_title(
        "Ranking Quality: PI Trust vs Actual Usefulness\n"
        "(tau=1.0 = perfect, tau=0 = random, tau<0 = inverted)"
    )
    ax.legend()
    ax.set_ylim(-0.2, 1.1)
    ax.set_xlim(1, n_months)
    ax.grid(True, alpha=0.3)

    tau_path = output_dir / "kendall_tau.png"
    fig.savefig(tau_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Plot saved to {tau_path}")

    # Plot 3: Seasonal archetype zoomed — trust vs time with semester/summer bands
    seasonal_idx = 2
    fig, ax = plt.subplots(figsize=(12, 4))
    mean = trust_mean[:, seasonal_idx]
    std = trust_std[:, seasonal_idx]
    ax.plot(months, mean, color=colors[seasonal_idx], linewidth=2, label="Seasonal")
    ax.fill_between(months, mean - std, mean + std,
                    color=colors[seasonal_idx], alpha=0.2)

    for start, end in [(5.5, 8.5), (17.5, 20.5)]:
        ax.axvspan(start, end, color="yellow", alpha=0.3, label="Summer")

    ax.set_xlabel("Month")
    ax.set_ylabel("PI Trust Score")
    ax.set_title("Seasonal Archetype: Trust During Semester vs Summer Absence")
    ax.legend()
    ax.grid(True, alpha=0.3)

    seasonal_path = output_dir / "seasonal_analysis.png"
    fig.savefig(seasonal_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Plot saved to {seasonal_path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Viaticum Experiment 13: Behavior Models / Archetypes"
    )
    parser.add_argument("--peers", type=int, default=200,
                        help="Total number of peers")
    parser.add_argument("--days", type=int, default=730,
                        help="Simulation duration in days (730 = 24 months)")
    parser.add_argument("--seeds", type=int, default=30,
                        help="Number of Monte Carlo seeds")
    parser.add_argument("--kp", type=float, default=0.5,
                        help="PI controller P weight")
    parser.add_argument("--ki", type=float, default=2.0,
                        help="PI controller I weight")
    parser.add_argument("--window", type=int, default=30,
                        help="P rolling window in days")
    parser.add_argument("--jobs", type=int, default=1,
                        help="Parallel jobs (cores)")
    parser.add_argument("--output", type=str, default="results/behavior_models",
                        help="Output directory")
    parser.add_argument("--no-plot", action="store_true",
                        help="Skip plot generation")
    args = parser.parse_args()

    output_dir = Path(args.output)

    config = Config(
        n_peers=args.peers,
        n_days=args.days,
        n_seeds=args.seeds,
        kp=args.kp,
        ki=args.ki,
        p_window=args.window,
    )

    print("=== VIATICUM EXPERIMENT 13: BEHAVIOR MODELS / ARCHETYPES ===\n")

    results = run_experiment(config, n_jobs=args.jobs)
    print_summary(config, results)
    save_results(config, results, output_dir / "run.json")

    if not args.no_plot:
        plot_results(results, config, output_dir)


if __name__ == "__main__":
    main()
