"""
Viaticum Simulation #18: Corrected Individual Node Perspective (PI+S formula)

Redo of Experiment 14 (node_perspective.py) with:
  - Corrected trust formula: trust = kp*P + ki*I + ks*S
  - Weekly check cadence (not daily rolling window)
  - D-trigger with hysteresis (2 consecutive bad weeks before repair)
  - Six peer archetypes with realistic behavior patterns

Trust formula:
    Weekly check aggregation:
        Each week: run 7 daily Bernoulli checks per peer.
        weekly_pass = 1 if any check passes, else 0.
    P = mean of last 4 weekly scores (4-week rolling window)
    I = cumulative mean of ALL weekly scores (non-decaying)
    S = storage_ratio (fixed per peer or dynamic for protagonist), clamped [0, 2.0]
    trust = kp * P + ki * I + ks * S

D-component with hysteresis:
    D = P[this_week] - P[last_week]  (computed from weekly P values)
    Require 2 consecutive weeks of D < -0.05 to trigger repair.
    This replaces the daily D < -0.01 single-trigger from Exp 14.

Peer archetypes (Scenario 1):
    Reliable  (40): daily_rel=0.95, off_frac=0.00, S=1.0
    Weekend   (25): daily_rel=0.95, off_frac=0.30, S=1.0  (30% of weeks offline)
    Seasonal  (15): daily_rel=0.95, off_frac=0.20, S=1.0  (20% of weeks offline)
    Nomad     (10): daily_rel=0.00, off_frac=0.50, S=1.0  (online 50% of weeks)
    Hoarder    (7): daily_rel=0.90, off_frac=0.00, S=0.2
    Freeloader (3): daily_rel=0.80, off_frac=0.00, S=0.1

    For bimodal peers (off_frac > 0): each week is independently an "off-week"
    with probability off_frac (all 7 daily checks fail). On-weeks run normally.
    For Nomad: daily_rel=0 but off_frac=0.50 means 50% of weeks are fully offline.

Three scenarios:
    1 — Flaky Partners: protagonist (Reliable) vs 100 archetype peers, 12 months
    2 — Vacation: protagonist offline 14 days, measure PI+S trust drop/recovery
    3 — Disk Pressure: protagonist S decreases as it evicts partners' shards

Usage:
    python pis_perspective.py --scenario 1
    python pis_perspective.py --scenario 2
    python pis_perspective.py --scenario 3
    python pis_perspective.py --all
    python pis_perspective.py --all --seeds 50 --jobs 4
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass, asdict
from math import comb
from pathlib import Path

import numpy as np
from joblib import Parallel, delayed


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class Config:
    # Erasure coding (5-of-15)
    k: int = 5
    n_shards: int = 15

    # PI+S controller weights
    kp: float = 0.5
    ki: float = 2.0
    ks: float = 1.0

    # Weekly P window (number of weekly scores)
    p_window_weeks: int = 4

    # D hysteresis: consecutive bad weeks required to trigger repair
    d_threshold: float = -0.05
    d_hysteresis: int = 2

    # Repair cycle
    repair_interval_days: int = 7   # = 1 week

    # Scenario 1: archetype counts and parameters
    s1_n_reliable: int = 40
    s1_n_weekend: int = 25
    s1_n_seasonal: int = 15
    s1_n_nomad: int = 10
    s1_n_hoarder: int = 7
    s1_n_freeloader: int = 3
    # total = 100

    s1_reliable_rel: float = 0.95
    s1_reliable_s: float = 1.0

    s1_weekend_on_rel: float = 0.95
    s1_weekend_off_frac: float = 0.30  # fraction of weeks where peer is offline
    s1_weekend_s: float = 1.0

    s1_seasonal_on_rel: float = 0.95
    s1_seasonal_off_frac: float = 0.20
    s1_seasonal_s: float = 1.0

    # Nomad: 50% of weeks fully offline, online weeks at 0.95
    s1_nomad_on_rel: float = 0.95
    s1_nomad_off_frac: float = 0.50
    s1_nomad_s: float = 1.0

    s1_hoarder_rel: float = 0.90
    s1_hoarder_s: float = 0.2

    s1_freeloader_rel: float = 0.80
    s1_freeloader_s: float = 0.1

    s1_duration_months: int = 12
    s1_annual_churn: float = 0.30
    s1_decline_weeks: int = 4       # decline phase in weeks (was 30 days ≈ 4 weeks)

    # Scenario 2: vacation
    s2_n_peers: int = 100
    s2_peer_reliability: float = 0.90
    s2_peer_s: float = 1.0
    s2_pre_vacation_months: int = 6
    s2_vacation_days: int = 14      # 2 weeks
    s2_post_vacation_months: int = 3

    # Scenario 3: disk pressure
    s3_n_peers: int = 100
    s3_peer_reliability: float = 0.90
    s3_duration_months: int = 18
    s3_initial_partners: int = 30
    s3_disk_slots: int = 100
    s3_initial_free_frac: float = 0.50
    s3_growth_slots_per_month: float = 3.0

    # Monte Carlo
    n_seeds: int = 50

    # Output
    output_dir: str = "results/pis_perspective"


# ---------------------------------------------------------------------------
# Archetype helpers
# ---------------------------------------------------------------------------

@dataclass
class Archetype:
    """Describes a peer archetype's weekly check behavior."""
    name: str
    on_rel: float       # daily reliability when online
    off_frac: float     # probability of being fully offline in a given week
    s_val: float        # storage ratio (fixed)


def build_archetypes(config: Config) -> list[Archetype]:
    return [
        Archetype("Reliable",   config.s1_reliable_rel,   0.0,                       config.s1_reliable_s),
        Archetype("Weekend",    config.s1_weekend_on_rel,  config.s1_weekend_off_frac, config.s1_weekend_s),
        Archetype("Seasonal",   config.s1_seasonal_on_rel, config.s1_seasonal_off_frac, config.s1_seasonal_s),
        Archetype("Nomad",      config.s1_nomad_on_rel,    config.s1_nomad_off_frac,   config.s1_nomad_s),
        Archetype("Hoarder",    config.s1_hoarder_rel,    0.0,                       config.s1_hoarder_s),
        Archetype("Freeloader", config.s1_freeloader_rel,  0.0,                       config.s1_freeloader_s),
    ]


def build_peer_arrays(
    config: Config,
    archetypes: list[Archetype],
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Return (on_rel, off_frac, s_val) arrays for all 100 peers."""
    counts = [
        config.s1_n_reliable,
        config.s1_n_weekend,
        config.s1_n_seasonal,
        config.s1_n_nomad,
        config.s1_n_hoarder,
        config.s1_n_freeloader,
    ]
    n_peers = sum(counts)
    on_rel = np.empty(n_peers)
    off_frac = np.empty(n_peers)
    s_val = np.empty(n_peers)
    idx = 0
    for arch, count in zip(archetypes, counts):
        on_rel[idx:idx + count] = arch.on_rel
        off_frac[idx:idx + count] = arch.off_frac
        s_val[idx:idx + count] = arch.s_val
        idx += count
    return on_rel, off_frac, s_val


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _restore_prob(n_placed: int, k: int, per_shard_avail: float = 0.97) -> float:
    """P(at least k of n_placed shards available) via exact binomial."""
    if n_placed < k:
        return 0.0
    p = per_shard_avail
    total = 0.0
    for s in range(k, n_placed + 1):
        total += comb(n_placed, s) * (p ** s) * ((1.0 - p) ** (n_placed - s))
    return min(1.0, total)


def _weekly_check(
    n_peers: int,
    on_rel: np.ndarray,
    off_frac: np.ndarray,
    peer_online: np.ndarray,
    rng: np.random.Generator,
) -> np.ndarray:
    """Simulate one week of checks for n_peers. Returns weekly_pass (float 0/1).

    For each peer:
      - If peer_online is False: weekly_pass = 0.0
      - Else: draw if this is an off-week (Bernoulli with off_frac).
        If off-week: weekly_pass = 0.0
        Else: run 7 daily Bernoulli checks; weekly_pass = 1 if any passes.
    """
    # Determine which peers are in an off-week
    off_week = rng.random(n_peers) < off_frac

    # For on-weeks: P(any of 7 daily checks passes) = 1 - (1 - on_rel)^7
    # Vectorized: draw 7 rows and OR them
    daily = rng.random((7, n_peers)) < on_rel[np.newaxis, :]  # shape (7, n_peers)
    any_pass = daily.any(axis=0).astype(np.float64)

    # Apply off-week and offline masks
    weekly_pass = np.where(off_week, 0.0, any_pass)
    weekly_pass = np.where(peer_online, weekly_pass, 0.0)
    return weekly_pass


def _compute_trust(
    w_buf: np.ndarray,      # shape (p_window_weeks, n_peers) — circular buffer
    n_filled: int,
    i_sum: np.ndarray,      # shape (n_peers,)
    total_weeks: int,
    s_val: np.ndarray,      # shape (n_peers,)
    config: Config,
) -> tuple[np.ndarray, np.ndarray]:
    """Return (p_score, trust) arrays for all peers."""
    p_score = w_buf[:n_filled].mean(axis=0)
    i_score = i_sum / max(1, total_weeks)
    s_clamped = np.clip(s_val, 0.0, 2.0)
    trust = config.kp * p_score + config.ki * i_score + config.ks * s_clamped
    return p_score, trust


def _warm_start_weekly(
    n_peers: int,
    on_rel: np.ndarray,
    off_frac: np.ndarray,
    warmup_weeks: int,
    p_window_weeks: int,
    rng: np.random.Generator,
) -> tuple[np.ndarray, np.ndarray, int]:
    """Run warmup_weeks of weekly checks. Return (w_buf, i_sum, total_weeks).

    w_buf   shape (p_window_weeks, n_peers)  — circular buffer (partially filled)
    i_sum   shape (n_peers,)                 — cumulative sum of weekly passes
    total_weeks int                          — total weeks completed
    """
    w_buf = np.zeros((p_window_weeks, n_peers))
    i_sum = np.zeros(n_peers)
    peer_online = np.ones(n_peers, dtype=bool)

    for w in range(warmup_weeks):
        passes = _weekly_check(n_peers, on_rel, off_frac, peer_online, rng)
        slot = w % p_window_weeks
        w_buf[slot] = passes
        i_sum += passes

    return w_buf, i_sum, warmup_weeks


# ---------------------------------------------------------------------------
# Scenario 1: Flaky Partners (with archetypes)
# ---------------------------------------------------------------------------

def _simulate_s1_one(config: Config, seed: int) -> dict:
    """Single run for Scenario 1: protagonist (Reliable) vs archetype peers.

    Peers go through a lifecycle: healthy -> declining -> departed.
    Decline phase: off_frac ramps toward 1.0 over s1_decline_weeks weeks.
    D-trigger uses hysteresis: 2 consecutive weekly D < -0.05 to trigger.
    """
    rng = np.random.default_rng(seed)

    archetypes = build_archetypes(config)
    on_rel, off_frac_base, s_val = build_peer_arrays(config, archetypes)
    n_peers = len(on_rel)

    n_weeks = config.s1_duration_months * 4   # ~4 weeks per month
    p_window = config.p_window_weeks

    # Warm-start: 8 weeks at base reliability
    warmup_weeks = 8
    w_buf, i_sum, total_weeks = _warm_start_weekly(
        n_peers, on_rel, off_frac_base, warmup_weeks, p_window, rng
    )

    # Protagonist's shards: assign random holders
    shard_holders = rng.integers(0, n_peers, size=config.n_shards).tolist()

    # Peer departure lifecycle
    p_depart_weekly = 1.0 - (1.0 - config.s1_annual_churn) ** (1.0 / 52.0)
    depart_week = np.full(n_peers, -1, dtype=np.int64)
    decline_start = np.full(n_peers, -1, dtype=np.int64)
    peer_online = np.ones(n_peers, dtype=bool)

    for i in range(n_peers):
        weeks_until = int(rng.geometric(p_depart_weekly))
        if weeks_until < n_weeks:
            depart_week[i] = weeks_until
            decline_start[i] = max(0, weeks_until - config.s1_decline_weeks)

    # Current off_frac per peer (changes during decline)
    current_off_frac = off_frac_base.copy()

    # Previous P score for D computation (initialized at warm-start)
    n_filled_init = min(warmup_weeks, p_window)
    p_score_prev: np.ndarray = w_buf[:n_filled_init].mean(axis=0)

    # D-hysteresis state per shard: how many consecutive bad-D weeks
    shard_bad_d_count: list[int] = [0] * config.n_shards

    # Monthly accumulators (1 month = 4 weeks)
    month_own_shards: list[float] = []
    month_at_risk: list[float] = []
    month_repairs: list[float] = []
    month_d_warnings: list[float] = []
    month_p_restore: list[float] = []
    m_repairs = 0
    m_d_warnings = 0

    # D-warning accuracy tracking
    # A "D-warning" fires when the 2nd consecutive bad week triggers repair.
    # True positive: peer departs within 4 weeks of trigger week.
    all_d_warnings: list[tuple[int, int]] = []  # (trigger_week, peer_idx)

    # Last p_score for each peer (for D computation at weekly boundary)
    p_score_cur: np.ndarray = p_score_prev.copy()

    for week in range(n_weeks):
        # --- Update peer lifecycle ---
        for i in range(n_peers):
            if depart_week[i] >= 0 and week >= int(depart_week[i]) and peer_online[i]:
                peer_online[i] = False
                current_off_frac[i] = 1.0
            elif (
                decline_start[i] >= 0
                and week >= int(decline_start[i])
                and peer_online[i]
            ):
                progress = (week - int(decline_start[i])) / max(1, config.s1_decline_weeks)
                progress = min(1.0, progress)
                # off_frac ramps from base toward 1.0 during decline
                current_off_frac[i] = (
                    off_frac_base[i] * (1.0 - progress) + 1.0 * progress
                )
            else:
                current_off_frac[i] = off_frac_base[i]

        # --- Weekly check ---
        passes = _weekly_check(n_peers, on_rel, current_off_frac, peer_online, rng)

        slot = total_weeks % p_window
        w_buf[slot] = passes
        i_sum += passes
        total_weeks += 1
        n_filled = min(total_weeks, p_window)

        # Compute P and trust
        p_score_cur = w_buf[:n_filled].mean(axis=0)
        i_score = i_sum / total_weeks
        s_clamped = np.clip(s_val, 0.0, 2.0)
        trust = config.kp * p_score_cur + config.ki * i_score + config.ks * s_clamped

        # D per peer (week-over-week delta of P)
        d_score: np.ndarray = p_score_cur - p_score_prev

        # --- Repair cycle (every week, since repair_interval = 7 days = 1 week) ---
        for si in range(config.n_shards):
            holder = shard_holders[si]
            if holder < 0:
                continue

            # Reactive repair: holder departed
            if not peer_online[holder]:
                current_holders = {h for h in shard_holders if h >= 0}
                candidates = [
                    p for p in range(n_peers)
                    if peer_online[p] and p not in current_holders
                ]
                if candidates:
                    w_arr = np.array([float(trust[p]) for p in candidates])
                    best = candidates[int(np.argmax(w_arr))]
                    shard_holders[si] = best
                else:
                    shard_holders[si] = -1
                m_repairs += 1
                shard_bad_d_count[si] = 0
                continue

            # D-hysteresis logic
            d_val = float(d_score[holder])
            if d_val < config.d_threshold:
                shard_bad_d_count[si] += 1
            else:
                shard_bad_d_count[si] = 0

            if shard_bad_d_count[si] >= config.d_hysteresis:
                # Triggered: attempt preemptive repair
                current_holders = {h for h in shard_holders if h >= 0}
                candidates = [
                    p for p in range(n_peers)
                    if peer_online[p]
                    and p not in current_holders
                    and float(trust[p]) > float(trust[holder])
                ]
                if candidates:
                    w_arr = np.array([float(trust[p]) for p in candidates])
                    best = candidates[int(np.argmax(w_arr))]
                    shard_holders[si] = best
                    m_repairs += 1
                # Record D-warning (fire at trigger moment)
                m_d_warnings += 1
                all_d_warnings.append((week, holder))
                shard_bad_d_count[si] = 0

        # --- Monthly snapshot (every 4 weeks) ---
        if (week + 1) % 4 == 0:
            n_own = sum(1 for h in shard_holders if h >= 0)
            at_risk = sum(
                1 for h in shard_holders
                if h >= 0 and (
                    float(p_score_cur[h]) < 0.70 or not peer_online[h]
                )
            )
            p_restore = _restore_prob(n_own, config.k)
            month_own_shards.append(float(n_own))
            month_at_risk.append(float(at_risk))
            month_repairs.append(float(m_repairs))
            month_d_warnings.append(float(m_d_warnings))
            month_p_restore.append(p_restore)
            m_repairs = 0
            m_d_warnings = 0

        p_score_prev = p_score_cur.copy()

    # D-warning accuracy
    # True positive: peer actually departs within 4 weeks of warning
    true_positives = 0
    false_positives = 0
    for warn_w, peer in all_d_warnings:
        dep = int(depart_week[peer])
        if dep >= 0 and dep <= warn_w + 4:
            true_positives += 1
        else:
            false_positives += 1

    total_warnings = true_positives + false_positives
    tp_rate = true_positives / max(1, total_warnings)
    fp_rate = false_positives / max(1, total_warnings)
    total_warnings_per_year = total_warnings * (52.0 / n_weeks) if n_weeks > 0 else 0.0

    return {
        "month_own_shards": month_own_shards,
        "month_at_risk": month_at_risk,
        "month_repairs": month_repairs,
        "month_d_warnings": month_d_warnings,
        "month_p_restore": month_p_restore,
        "total_d_warnings": total_warnings,
        "d_warnings_per_year": total_warnings_per_year,
        "tp_rate": tp_rate,
        "fp_rate": fp_rate,
    }


def run_scenario1(config: Config, n_jobs: int = 1) -> dict:
    """Monte Carlo for Scenario 1."""
    t0 = time.time()
    seeds = list(range(config.n_seeds))

    if n_jobs == 1:
        runs = [_simulate_s1_one(config, s) for s in seeds]
    else:
        runs = Parallel(n_jobs=n_jobs)(
            delayed(_simulate_s1_one)(config, s) for s in seeds
        )

    elapsed = time.time() - t0
    n_months = config.s1_duration_months

    def _stat(vals: list[float]) -> dict:
        arr = np.array(vals, dtype=float)
        return {
            "mean": float(arr.mean()),
            "std": float(arr.std()),
            "p5": float(np.percentile(arr, 5)),
            "p95": float(np.percentile(arr, 95)),
        }

    monthly: list[dict] = []
    for m in range(n_months):
        monthly.append({
            "month": m + 1,
            "own_shards": _stat([r["month_own_shards"][m] for r in runs
                                  if m < len(r["month_own_shards"])]),
            "at_risk": _stat([r["month_at_risk"][m] for r in runs
                               if m < len(r["month_at_risk"])]),
            "repairs": _stat([r["month_repairs"][m] for r in runs
                               if m < len(r["month_repairs"])]),
            "d_warnings": _stat([r["month_d_warnings"][m] for r in runs
                                  if m < len(r["month_d_warnings"])]),
            "p_restore": _stat([r["month_p_restore"][m] for r in runs
                                 if m < len(r["month_p_restore"])]),
        })

    return {
        "scenario": 1,
        "experiment": 18,
        "config": asdict(config),
        "elapsed_sec": elapsed,
        "monthly": monthly,
        "d_warnings_per_year": _stat([r["d_warnings_per_year"] for r in runs]),
        "tp_rate": _stat([r["tp_rate"] for r in runs]),
        "fp_rate": _stat([r["fp_rate"] for r in runs]),
        # Exp 14 reference values for comparison
        "exp14_ref": {
            "fp_rate": 0.91,
            "d_warnings_per_year": None,
        },
    }


def print_scenario1(result: dict) -> None:
    cfg = result["config"]
    n_peers = (
        cfg["s1_n_reliable"] + cfg["s1_n_weekend"] + cfg["s1_n_seasonal"]
        + cfg["s1_n_nomad"] + cfg["s1_n_hoarder"] + cfg["s1_n_freeloader"]
    )
    print("=== SCENARIO 1: FLAKY PARTNERS (Exp 18, PI+S formula) ===")
    print(
        f"Network: {n_peers} peers  "
        f"[{cfg['s1_n_reliable']} Reliable, {cfg['s1_n_weekend']} Weekend, "
        f"{cfg['s1_n_seasonal']} Seasonal, {cfg['s1_n_nomad']} Nomad, "
        f"{cfg['s1_n_hoarder']} Hoarder, {cfg['s1_n_freeloader']} Freeloader]"
    )
    print(
        f"Protagonist: Reliable archetype (rel={cfg['s1_reliable_rel']}, S={cfg['s1_reliable_s']})"
    )
    print(
        f"Duration: {cfg['s1_duration_months']} months  |  "
        f"Churn: {cfg['s1_annual_churn']*100:.0f}%/yr  |  "
        f"Seeds: {cfg['n_seeds']}  |  Runtime: {result['elapsed_sec']:.1f}s"
    )
    print(
        f"D-hysteresis: {cfg['d_hysteresis']} consecutive weeks < {cfg['d_threshold']}  "
        f"(Exp 14 used single-day D < -0.01)"
    )
    print()
    hdr = (
        f"{'Month':>6}  {'OwnShards':>9}  {'AtRisk':>6}  "
        f"{'Repairs':>7}  {'D-warns':>7}  {'P_restore':>9}"
    )
    print(hdr)
    print("-" * len(hdr))
    for row in result["monthly"]:
        m = row["month"]
        own = row["own_shards"]["mean"]
        risk = row["at_risk"]["mean"]
        rep = row["repairs"]["mean"]
        dw = row["d_warnings"]["mean"]
        pr = row["p_restore"]["mean"]
        print(
            f"{m:>6}  {own:>9.1f}  {risk:>6.1f}  "
            f"{rep:>7.2f}  {dw:>7.2f}  {pr*100:>8.1f}%"
        )
    print()
    dwy = result["d_warnings_per_year"]
    tp = result["tp_rate"]
    fp = result["fp_rate"]
    print(
        f"D-warning events:    avg {dwy['mean']:.1f}/year  "
        f"[p5={dwy['p5']:.1f}, p95={dwy['p95']:.1f}]"
    )
    print(
        f"True positive rate:  {tp['mean']*100:.0f}%  "
        f"(D warned before departure, peer departed within 4 weeks)"
    )
    print(
        f"False positive rate: {fp['mean']*100:.0f}%  "
        f"(D warned but peer did NOT depart within 4 weeks)"
    )
    print()
    exp14_fp = result["exp14_ref"]["fp_rate"]
    improvement = (exp14_fp - fp["mean"]) / exp14_fp * 100.0 if exp14_fp > 0 else 0.0
    print(f"vs Exp 14 (PI-only):  FP rate {exp14_fp*100:.0f}% -> {fp['mean']*100:.0f}%  "
          f"({'improvement' if improvement > 0 else 'regression'}: {abs(improvement):.0f}%)")


# ---------------------------------------------------------------------------
# Scenario 2: Vacation (14 days = 2 weeks offline)
# ---------------------------------------------------------------------------

def _simulate_s2_one(config: Config, seed: int) -> dict:
    """Single run for Scenario 2: protagonist goes offline for 14 days (2 weeks).

    Key change from Exp 14: with weekly cadence, missing 2 weeks means P drops
    from ~1.0 to (4-2)/4 = 0.50 after the 4-week window fills in the zeros
    (if all 4 slots were 1.0 before). Less punishing than the 30-day daily
    rolling window where 14 zeros drag P to (30-14)/30 ~ 0.53 but with
    the I component stabilizing faster due to cumulative averaging.
    """
    rng = np.random.default_rng(seed)

    n_peers = config.s2_n_peers
    peer_on_rel = np.full(n_peers, config.s2_peer_reliability)
    peer_off_frac = np.zeros(n_peers)
    peer_s_val = np.full(n_peers, config.s2_peer_s)
    peer_online_bg = np.ones(n_peers, dtype=bool)

    p_window = config.p_window_weeks

    pre_vac_weeks = config.s2_pre_vacation_months * 4
    vac_weeks = (config.s2_vacation_days + 6) // 7   # 14 days -> 2 weeks
    post_vac_weeks = config.s2_post_vacation_months * 4

    # Warm-start background peers (pre-vacation)
    bg_w_buf, bg_i_sum, bg_total_weeks = _warm_start_weekly(
        n_peers, peer_on_rel, peer_off_frac, pre_vac_weeks, p_window, rng
    )

    # Protagonist trust state (pre-vacation warm-start)
    prot_w_buf = np.zeros(p_window)
    prot_i_sum = 0.0
    prot_total = 0

    for w in range(pre_vac_weeks):
        # Protagonist is reliable (0.95) and online
        daily_checks = rng.random(7) < 0.95
        prot_pass = float(daily_checks.any())
        slot = prot_total % p_window
        prot_w_buf[slot] = prot_pass
        prot_i_sum += prot_pass
        prot_total += 1

    prot_p_filled = min(prot_total, p_window)
    prot_p_score_pre = float(prot_w_buf[:prot_p_filled].mean())
    prot_i_score_pre = float(prot_i_sum / max(1, prot_total))
    prot_s_pre = 1.0  # fixed S for protagonist (she stores for others)
    prot_trust_pre = (
        config.kp * prot_p_score_pre
        + config.ki * prot_i_score_pre
        + config.ks * prot_s_pre
    )

    # Shards placed on background peers
    shard_holders = rng.integers(0, n_peers, size=config.n_shards).tolist()

    # Snapshots: (label, week_abs, trust, p_score, i_score, s_val, n_own, p_restore)
    snapshots: list[tuple[str, int, float, float, float, float, int, float]] = []

    def _snap(label: str, week_abs: int, s_protagonist: float) -> None:
        filled = min(prot_total, p_window)
        ps = float(prot_w_buf[:filled].mean()) if filled > 0 else 0.0
        is_ = float(prot_i_sum / max(1, prot_total))
        tr = config.kp * ps + config.ki * is_ + config.ks * min(s_protagonist, 2.0)
        n_own = sum(1 for h in shard_holders if h >= 0)
        pr = _restore_prob(n_own, config.k)
        snapshots.append((label, week_abs, tr, ps, is_, s_protagonist, n_own, pr))

    _snap("Pre-vacation", pre_vac_weeks - 1, prot_s_pre)

    protagonist_online = True
    # S stays 1.0 throughout vacation scenario (we don't model S decay here)
    prot_s = 1.0

    for week_offset in range(vac_weeks + post_vac_weeks):
        abs_week = pre_vac_weeks + week_offset
        on_vacation = week_offset < vac_weeks

        if on_vacation:
            protagonist_online = False
            prot_pass = 0.0
        else:
            protagonist_online = True
            daily_checks = rng.random(7) < 0.95
            prot_pass = float(daily_checks.any())

        slot = prot_total % p_window
        prot_w_buf[slot] = prot_pass
        prot_i_sum += prot_pass
        prot_total += 1

        # Background peers
        bg_passes = _weekly_check(
            n_peers, peer_on_rel, peer_off_frac, peer_online_bg, rng
        )
        bg_slot = bg_total_weeks % p_window
        bg_w_buf[bg_slot] = bg_passes
        bg_i_sum += bg_passes
        bg_total_weeks += 1

        bg_filled = min(bg_total_weeks, p_window)
        bg_p_score = bg_w_buf[:bg_filled].mean(axis=0)
        bg_i_score = bg_i_sum / bg_total_weeks
        bg_trust = (
            config.kp * bg_p_score
            + config.ki * bg_i_score
            + config.ks * np.clip(peer_s_val, 0.0, 2.0)
        )

        # Natural shard failure and repair (~1% per week)
        for si in range(config.n_shards):
            h = shard_holders[si]
            if h < 0:
                continue
            if rng.random() < 0.01:
                shard_holders[si] = -1
                if protagonist_online:
                    current = {h2 for h2 in shard_holders if h2 >= 0}
                    cands = [p for p in range(n_peers) if p not in current]
                    if cands:
                        w_arr = np.array([float(bg_trust[p]) for p in cands])
                        best = cands[int(np.argmax(w_arr))]
                        shard_holders[si] = best

        # Key week snapshots
        w = week_offset
        if w == 0:
            _snap("Vacation w1", abs_week, prot_s)
        elif w == vac_weeks - 1:
            _snap(f"Vacation w{vac_weeks}", abs_week, prot_s)
        elif w == vac_weeks:
            _snap("Post w1", abs_week, prot_s)
        elif w == vac_weeks + 1:
            _snap("Post w2", abs_week, prot_s)
        elif w == vac_weeks + 3:
            _snap("Post w4", abs_week, prot_s)
        elif w == vac_weeks + post_vac_weeks - 1:
            _snap(f"Post w{post_vac_weeks}", abs_week, prot_s)

    return {
        "snapshots": snapshots,
        "prot_trust_pre": float(prot_trust_pre),
        "prot_p_pre": float(prot_p_score_pre),
        "prot_i_pre": float(prot_i_score_pre),
    }


def run_scenario2(config: Config, n_jobs: int = 1) -> dict:
    """Monte Carlo for Scenario 2."""
    t0 = time.time()
    seeds = list(range(config.n_seeds))

    if n_jobs == 1:
        runs = [_simulate_s2_one(config, s) for s in seeds]
    else:
        runs = Parallel(n_jobs=n_jobs)(
            delayed(_simulate_s2_one)(config, s) for s in seeds
        )

    elapsed = time.time() - t0

    def _stat(vals: list[float]) -> dict:
        arr = np.array(vals, dtype=float)
        return {
            "mean": float(arr.mean()),
            "std": float(arr.std()),
            "p5": float(np.percentile(arr, 5)),
            "p95": float(np.percentile(arr, 95)),
        }

    label_order: list[str] = []
    label_data: dict[str, dict[str, list[float]]] = {}

    for run in runs:
        for label, week, trust, ps, is_, sv, n_own, pr in run["snapshots"]:
            if label not in label_data:
                label_order.append(label)
                label_data[label] = {
                    "week": [], "trust": [], "p_score": [],
                    "i_score": [], "s_val": [], "n_own": [], "p_restore": [],
                }
            label_data[label]["week"].append(float(week))
            label_data[label]["trust"].append(float(trust))
            label_data[label]["p_score"].append(float(ps))
            label_data[label]["i_score"].append(float(is_))
            label_data[label]["s_val"].append(float(sv))
            label_data[label]["n_own"].append(float(n_own))
            label_data[label]["p_restore"].append(float(pr))

    aggregated: list[dict] = []
    for label in label_order:
        d = label_data[label]
        aggregated.append({
            "label": label,
            "week": _stat(d["week"]),
            "trust": _stat(d["trust"]),
            "p_score": _stat(d["p_score"]),
            "i_score": _stat(d["i_score"]),
            "s_val": _stat(d["s_val"]),
            "n_own": _stat(d["n_own"]),
            "p_restore": _stat(d["p_restore"]),
        })

    pre_trusts = [r["prot_trust_pre"] for r in runs]

    vac_label = f"Vacation w{(config.s2_vacation_days + 6) // 7}"
    trust_loss: list[float] = []
    if vac_label in label_data:
        vac_trusts = label_data[vac_label]["trust"]
        for i, r in enumerate(runs):
            if i < len(vac_trusts):
                trust_loss.append(r["prot_trust_pre"] - vac_trusts[i])

    return {
        "scenario": 2,
        "experiment": 18,
        "config": asdict(config),
        "elapsed_sec": elapsed,
        "snapshots": aggregated,
        "pre_vacation_trust": _stat(pre_trusts),
        "trust_loss_during_vacation": _stat(trust_loss) if trust_loss else {},
        # Exp 14 reference: with 30-day daily window, 14 offline days
        # P drops from ~0.95 to ~(16*0.95)/30 ~ 0.51 and I diluted slowly
        "exp14_ref": {
            "trust_pre": 2.425,     # approx: 0.5*0.95 + 2.0*0.95
            "trust_at_vac_end": 1.3,  # rough: P~0.51 -> 0.5*0.51 + 2.0*0.93
        },
    }


def print_scenario2(result: dict) -> None:
    cfg = result["config"]
    vac_weeks = (cfg["s2_vacation_days"] + 6) // 7
    print("=== SCENARIO 2: VACATION (14 days = 2 weeks offline) (Exp 18, PI+S) ===")
    print(
        f"Network: {cfg['s2_n_peers']} peers @{cfg['s2_peer_reliability']} reliability, "
        f"S={cfg['s2_peer_s']}"
    )
    print(
        f"Phase: {cfg['s2_pre_vacation_months']}mo pre + {cfg['s2_vacation_days']}d vacation "
        f"({vac_weeks}w) + {cfg['s2_post_vacation_months']}mo post"
    )
    print(f"Seeds: {cfg['n_seeds']}  |  Runtime: {result['elapsed_sec']:.1f}s")

    pre_t = result["pre_vacation_trust"]
    print(
        f"\nPre-vacation trust:  "
        f"{pre_t['mean']:.3f}  [p5={pre_t['p5']:.3f}, p95={pre_t['p95']:.3f}]"
    )

    if result["trust_loss_during_vacation"]:
        tl = result["trust_loss_during_vacation"]
        print(
            f"Trust loss (vacation end vs pre): "
            f"{tl['mean']:.3f}  [p5={tl['p5']:.3f}, p95={tl['p95']:.3f}]"
        )

    print()
    hdr = (
        f"{'Phase':<18}  {'Week':>4}  {'Trust':>6}  {'P_score':>7}  "
        f"{'I_score':>7}  {'S':>5}  {'OwnShards':>9}  {'P_restore':>9}"
    )
    print(hdr)
    print("-" * len(hdr))

    for row in result["snapshots"]:
        label = row["label"]
        week = row["week"]["mean"]
        trust = row["trust"]["mean"]
        ps = row["p_score"]["mean"]
        is_ = row["i_score"]["mean"]
        sv = row["s_val"]["mean"]
        n_own = row["n_own"]["mean"]
        pr = row["p_restore"]["mean"]
        print(
            f"{label:<18}  {week:>4.0f}  {trust:>6.3f}  {ps:>7.3f}  "
            f"{is_:>7.3f}  {sv:>5.2f}  {n_own:>9.1f}  {pr*100:>8.1f}%"
        )

    print()
    exp14 = result["exp14_ref"]
    print(
        f"vs Exp 14 (PI-only, daily window):  "
        f"pre-trust ~{exp14['trust_pre']:.2f} vs {result['pre_vacation_trust']['mean']:.3f} (Exp 18 higher due to +S)"
    )
    if result["trust_loss_during_vacation"]:
        tl = result["trust_loss_during_vacation"]
        print(
            f"  Trust drop at vacation end: Exp 14 ~{exp14['trust_pre'] - exp14['trust_at_vac_end']:.2f}  "
            f"vs Exp 18: {tl['mean']:.3f}"
        )


# ---------------------------------------------------------------------------
# Scenario 3: Disk Pressure (S decreases as protagonist evicts)
# ---------------------------------------------------------------------------

def _simulate_s3_one(config: Config, seed: int) -> dict:
    """Single run for Scenario 3: disk fills up; S drops as protagonist evicts.

    S model:
        S = stored_for_count / initial_stored_for_count, clamped [0, 2.0]
        As protagonist evicts partners' shards, stored_for_count falls,
        S falls, and protagonist's trust (as seen by others) falls.

    This creates a feedback: protagonist loses trust due to S drop, which
    makes it harder to place own shards on high-trust peers.
    (We model this from protagonist's self-view for UX purposes.)
    """
    rng = np.random.default_rng(seed)

    n_peers = config.s3_n_peers
    peer_on_rel = np.full(n_peers, config.s3_peer_reliability)
    peer_off_frac = np.zeros(n_peers)
    peer_s_val = np.ones(n_peers)   # background peers assumed S=1.0
    peer_online = np.ones(n_peers, dtype=bool)

    n_weeks = config.s3_duration_months * 4
    p_window = config.p_window_weeks

    # Warm-start background peers (6 weeks)
    warmup_weeks = 6
    bg_w_buf, bg_i_sum, bg_total_weeks = _warm_start_weekly(
        n_peers, peer_on_rel, peer_off_frac, warmup_weeks, p_window, rng
    )

    # Protagonist warm-start
    prot_w_buf = np.zeros(p_window)
    prot_i_sum = 0.0
    prot_total = 0
    for w in range(warmup_weeks):
        daily_checks = rng.random(7) < 0.95
        prot_pass = float(daily_checks.any())
        slot = prot_total % p_window
        prot_w_buf[slot] = prot_pass
        prot_i_sum += prot_pass
        prot_total += 1

    # Protagonist's own shards placed on peers
    shard_holders = rng.integers(0, n_peers, size=config.n_shards).tolist()

    # Protagonist storage: stores shards for s3_initial_partners partners
    all_peer_ids = list(range(n_peers))
    rng.shuffle(all_peer_ids)
    stored_for: list[int] = list(all_peer_ids[:config.s3_initial_partners])
    initial_stored = len(stored_for)

    # Disk model
    disk_slots = config.s3_disk_slots
    initial_used_local = int(disk_slots * (1.0 - config.s3_initial_free_frac)) - initial_stored
    initial_used_local = max(0, initial_used_local)

    total_evictions = 0
    month_evictions_this = 0

    # Monthly snapshots
    month_free_pct: list[float] = []
    month_stored_for: list[float] = []
    month_own_shards: list[float] = []
    month_trust: list[float] = []
    month_s_val: list[float] = []
    month_evictions: list[float] = []
    month_p_restore: list[float] = []

    for week in range(n_weeks):
        # Disk usage (linear growth, week-based)
        weeks_elapsed = week + warmup_weeks
        used_local = initial_used_local + config.s3_growth_slots_per_month * (weeks_elapsed / 4.0)
        used_local = min(used_local, disk_slots)
        used_stored = len(stored_for)
        free = disk_slots - used_local - used_stored
        free_pct = max(0.0, free / disk_slots)

        # Protagonist S: fraction of original commitments still stored
        prot_s = float(len(stored_for)) / max(1, initial_stored)
        prot_s = min(prot_s, 2.0)

        # Background peer checks
        bg_passes = _weekly_check(
            n_peers, peer_on_rel, peer_off_frac, peer_online, rng
        )
        slot = bg_total_weeks % p_window
        bg_w_buf[slot] = bg_passes
        bg_i_sum += bg_passes
        bg_total_weeks += 1
        bg_filled = min(bg_total_weeks, p_window)
        bg_p_score = bg_w_buf[:bg_filled].mean(axis=0)
        bg_i_score = bg_i_sum / bg_total_weeks
        bg_trust = (
            config.kp * bg_p_score
            + config.ki * bg_i_score
            + config.ks * np.clip(peer_s_val, 0.0, 2.0)
        )

        # Protagonist check
        daily_checks = rng.random(7) < 0.95
        prot_pass = float(daily_checks.any())
        prot_slot = prot_total % p_window
        prot_w_buf[prot_slot] = prot_pass
        prot_i_sum += prot_pass
        prot_total += 1

        # Eviction and repair (weekly)
        committed_capacity = int(disk_slots * 0.95) - int(used_local)
        committed_capacity = max(0, committed_capacity)

        if len(stored_for) > committed_capacity:
            n_evict = len(stored_for) - committed_capacity
            peer_trusts = [float(bg_trust[p]) for p in stored_for]
            evict_order = np.argsort(peer_trusts)  # ascending: lowest first
            evict_indices = {int(evict_order[i]) for i in range(n_evict)}
            new_stored = [
                p for idx, p in enumerate(stored_for)
                if idx not in evict_indices
            ]
            evicted = len(stored_for) - len(new_stored)
            total_evictions += evicted
            month_evictions_this += evicted
            stored_for = new_stored

        # Repair own shards (natural failures)
        for si in range(config.n_shards):
            h = shard_holders[si]
            if h < 0:
                continue
            if rng.random() < 0.01:  # ~1% per week
                shard_holders[si] = -1
                current = {h2 for h2 in shard_holders if h2 >= 0}
                cands = [p for p in range(n_peers) if p not in current]
                if cands:
                    w_arr = np.array([float(bg_trust[p]) for p in cands])
                    best = cands[int(np.argmax(w_arr))]
                    shard_holders[si] = best

        # Monthly snapshot (every 4 weeks)
        if (week + 1) % 4 == 0:
            prot_filled = min(prot_total, p_window)
            prot_p_m = float(prot_w_buf[:prot_filled].mean())
            prot_i_m = float(prot_i_sum / max(1, prot_total))
            prot_trust_m = config.kp * prot_p_m + config.ki * prot_i_m + config.ks * prot_s

            n_own = sum(1 for h in shard_holders if h >= 0)
            pr = _restore_prob(n_own, config.k)

            month_free_pct.append(free_pct)
            month_stored_for.append(float(len(stored_for)))
            month_own_shards.append(float(n_own))
            month_trust.append(prot_trust_m)
            month_s_val.append(prot_s)
            month_evictions.append(float(month_evictions_this))
            month_p_restore.append(pr)
            month_evictions_this = 0

    return {
        "month_free_pct": month_free_pct,
        "month_stored_for": month_stored_for,
        "month_own_shards": month_own_shards,
        "month_trust": month_trust,
        "month_s_val": month_s_val,
        "month_evictions": month_evictions,
        "month_p_restore": month_p_restore,
        "total_evictions": float(total_evictions),
    }


def run_scenario3(config: Config, n_jobs: int = 1) -> dict:
    """Monte Carlo for Scenario 3."""
    t0 = time.time()
    seeds = list(range(config.n_seeds))

    if n_jobs == 1:
        runs = [_simulate_s3_one(config, s) for s in seeds]
    else:
        runs = Parallel(n_jobs=n_jobs)(
            delayed(_simulate_s3_one)(config, s) for s in seeds
        )

    elapsed = time.time() - t0
    n_months = config.s3_duration_months

    def _stat(vals: list[float]) -> dict:
        arr = np.array(vals, dtype=float)
        return {
            "mean": float(arr.mean()),
            "std": float(arr.std()),
            "p5": float(np.percentile(arr, 5)),
            "p95": float(np.percentile(arr, 95)),
        }

    monthly: list[dict] = []
    for m in range(n_months):
        monthly.append({
            "month": m + 1,
            "free_pct": _stat([r["month_free_pct"][m] for r in runs
                                if m < len(r["month_free_pct"])]),
            "stored_for": _stat([r["month_stored_for"][m] for r in runs
                                  if m < len(r["month_stored_for"])]),
            "own_shards": _stat([r["month_own_shards"][m] for r in runs
                                  if m < len(r["month_own_shards"])]),
            "trust": _stat([r["month_trust"][m] for r in runs
                             if m < len(r["month_trust"])]),
            "s_val": _stat([r["month_s_val"][m] for r in runs
                             if m < len(r["month_s_val"])]),
            "evictions": _stat([r["month_evictions"][m] for r in runs
                                 if m < len(r["month_evictions"])]),
            "p_restore": _stat([r["month_p_restore"][m] for r in runs
                                 if m < len(r["month_p_restore"])]),
        })

    return {
        "scenario": 3,
        "experiment": 18,
        "config": asdict(config),
        "elapsed_sec": elapsed,
        "monthly": monthly,
        "total_evictions": _stat([r["total_evictions"] for r in runs]),
    }


def print_scenario3(result: dict) -> None:
    cfg = result["config"]
    print("=== SCENARIO 3: DISK PRESSURE (Exp 18, S decreases on eviction) ===")
    print(
        f"Network: {cfg['s3_n_peers']} peers  "
        f"| Disk: {cfg['s3_disk_slots']} slots, "
        f"{cfg['s3_initial_free_frac']*100:.0f}% initially free"
    )
    print(
        f"Growth: {cfg['s3_growth_slots_per_month']:.1f} slots/month  "
        f"| Initial partners: {cfg['s3_initial_partners']}"
    )
    print(
        f"S model: protagonist S = stored_for / {cfg['s3_initial_partners']} "
        f"(S drops as evictions accumulate)"
    )
    print(
        f"Duration: {cfg['s3_duration_months']} months  "
        f"| Seeds: {cfg['n_seeds']}  "
        f"| Runtime: {result['elapsed_sec']:.1f}s"
    )
    print()
    hdr = (
        f"{'Month':>6}  {'FreeSpace%':>10}  {'StoredFor':>9}  {'S':>5}  "
        f"{'OwnShards':>9}  {'Trust':>6}  {'Evictions':>9}  {'P_restore':>9}"
    )
    print(hdr)
    print("-" * len(hdr))

    highlight = {1, 6, 12, 15, 18}
    for row in result["monthly"]:
        m = row["month"]
        if m not in highlight and m % 3 != 0:
            continue
        free = row["free_pct"]["mean"]
        sf = row["stored_for"]["mean"]
        sv = row["s_val"]["mean"]
        own = row["own_shards"]["mean"]
        tr = row["trust"]["mean"]
        ev = row["evictions"]["mean"]
        pr = row["p_restore"]["mean"]
        print(
            f"{m:>6}  {free*100:>9.1f}%  {sf:>9.1f}  {sv:>5.2f}  "
            f"{own:>9.1f}  {tr:>6.3f}  {ev:>9.2f}  {pr*100:>8.1f}%"
        )

    te = result["total_evictions"]
    print()
    print(
        f"Total evictions over {cfg['s3_duration_months']} months: "
        f"avg {te['mean']:.1f}  [p5={te['p5']:.1f}, p95={te['p95']:.1f}]"
    )
    print()

    # Find trust at month 1 and month 18 for comparison
    trust_m1 = next(
        (r["trust"]["mean"] for r in result["monthly"] if r["month"] == 1), None
    )
    trust_m18 = next(
        (r["trust"]["mean"] for r in result["monthly"] if r["month"] == 18), None
    )
    s_m1 = next(
        (r["s_val"]["mean"] for r in result["monthly"] if r["month"] == 1), None
    )
    s_m18 = next(
        (r["s_val"]["mean"] for r in result["monthly"] if r["month"] == 18), None
    )
    if trust_m1 is not None and trust_m18 is not None:
        print(
            f"Trust trajectory: month 1 = {trust_m1:.3f} -> month 18 = {trust_m18:.3f}  "
            f"(delta = {trust_m18 - trust_m1:+.3f})"
        )
    if s_m1 is not None and s_m18 is not None:
        print(
            f"S trajectory:     month 1 = {s_m1:.3f} -> month 18 = {s_m18:.3f}  "
            f"(S penalizes evictors transparently)"
        )
    print()
    print(
        "vs Exp 14 (PI-only): Exp 14 did not model S; trust was unaffected by eviction."
    )
    print(
        "  Exp 18 shows trust penalty from S when protagonist stores less for others."
    )


# ---------------------------------------------------------------------------
# Save
# ---------------------------------------------------------------------------

def save_results(result: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2))
    print(f"\nResults saved to {path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Viaticum Exp 18: Corrected Individual Node Perspective (PI+S)"
    )
    parser.add_argument(
        "--scenario", type=int, choices=[1, 2, 3],
        help="Which scenario to run (1, 2, or 3)"
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Run all three scenarios"
    )
    parser.add_argument(
        "--seeds", type=int, default=50,
        help="Monte Carlo seeds (default: 50)"
    )
    parser.add_argument(
        "--jobs", type=int, default=1,
        help="Parallel jobs (joblib, default: 1)"
    )
    parser.add_argument(
        "--output", type=str, default="results/pis_perspective",
        help="Output directory"
    )
    parser.add_argument("--k", type=int, default=5)
    parser.add_argument("--n-shards", type=int, default=15)
    parser.add_argument("--kp", type=float, default=0.5)
    parser.add_argument("--ki", type=float, default=2.0)
    parser.add_argument("--ks", type=float, default=1.0)
    parser.add_argument("--d-threshold", type=float, default=-0.05)
    parser.add_argument("--d-hysteresis", type=int, default=2,
                        help="Consecutive bad D-weeks to trigger repair (default: 2)")
    args = parser.parse_args()

    if not args.scenario and not args.all:
        parser.error("Specify --scenario 1/2/3 or --all")

    config = Config(
        k=args.k,
        n_shards=args.n_shards,
        kp=args.kp,
        ki=args.ki,
        ks=args.ks,
        d_threshold=args.d_threshold,
        d_hysteresis=args.d_hysteresis,
        n_seeds=args.seeds,
        output_dir=args.output,
    )

    output_dir = Path(args.output)
    scenarios_to_run = [args.scenario] if args.scenario else [1, 2, 3]

    for scenario_id in scenarios_to_run:
        print()
        if scenario_id == 1:
            result = run_scenario1(config, n_jobs=args.jobs)
            print_scenario1(result)
            save_results(result, output_dir / "scenario1.json")

        elif scenario_id == 2:
            result = run_scenario2(config, n_jobs=args.jobs)
            print_scenario2(result)
            save_results(result, output_dir / "scenario2.json")

        elif scenario_id == 3:
            result = run_scenario3(config, n_jobs=args.jobs)
            print_scenario3(result)
            save_results(result, output_dir / "scenario3.json")


if __name__ == "__main__":
    main()
