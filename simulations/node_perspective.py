"""
SyncBack Simulation #14: Individual Node Perspective

Question: What does the system look like from one node's point of view?
What are the UX-relevant events and timelines?

Three scenarios:

  Scenario 1 — Honest protagonist with flaky partners
    Protagonist is reliable (0.95), network of 100 peers (mixed reliability).
    Protagonist's 15 shards distributed randomly. Track D-warnings, repairs,
    partner churn events.
    UX question: "how often does the user see warnings about their data being moved?"

  Scenario 2 — Vacation (protagonist offline for 14 days)
    Protagonist reliable for 6 months, offline 14 days, then returns.
    Track trust P/I scores before/during/after absence, shard health.
    UX question: "will I lose data on vacation? How much trust do I lose?"

  Scenario 3 — Disk pressure (disk fills up over 18 months)
    Protagonist starts 50% free, local files grow ~3%/month.
    When free space < commitments, evict shards for lowest-trust partners.
    UX question: "what happens when my disk fills up? Do I get penalized?"

Trust model (PI controller):
    trust = 0.5 * P + 2.0 * I
    P = 30-day rolling window mean of daily check results
    I = cumulative average of all checks
    D = P[t] - P[t-1]  (trend; D < -0.01 triggers early-warning)

Erasure coding: 5-of-15 shards.
Repair cycle: weekly.

Usage:
    python node_perspective.py --scenario 1
    python node_perspective.py --scenario 2
    python node_perspective.py --scenario 3
    python node_perspective.py --all
    python node_perspective.py --all --seeds 50 --jobs 4
"""

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

    # PI controller
    kp: float = 0.5
    ki: float = 2.0
    p_window: int = 30          # days

    # D-component early-warning threshold
    d_threshold: float = -0.01

    # Repair cycle
    repair_interval_days: int = 7

    # Scenario 1: flaky partners
    s1_n_peers: int = 100
    s1_reliable_frac: float = 0.60
    s1_reliable_rel: float = 0.95
    s1_moderate_frac: float = 0.25
    s1_moderate_rel: float = 0.80
    # remaining fraction = flaky at 0.50
    s1_flaky_rel: float = 0.50
    s1_duration_months: int = 12
    # Annual churn probability per peer
    s1_annual_churn: float = 0.30
    # Decline phase duration before departure (days)
    s1_decline_days: int = 30

    # Scenario 2: vacation
    s2_n_peers: int = 100
    s2_peer_reliability: float = 0.90
    s2_pre_vacation_months: int = 6
    s2_vacation_days: int = 14
    s2_post_vacation_months: int = 3
    # Total = 6*30 + 14 + 3*30 ~= 9 months

    # Scenario 3: disk pressure
    s3_n_peers: int = 100
    s3_peer_reliability: float = 0.90
    s3_duration_months: int = 18
    # Protagonist stores shards for this many partners initially
    s3_initial_partners: int = 30
    # Free disk: starts at 0.50, model as fraction of capacity (100 shard slots)
    s3_disk_slots: int = 100    # total capacity in shard-slots
    s3_initial_free_frac: float = 0.50
    # Local files grow at this many shard-slots / month
    # 50% free = 50 slots initially; 3%/month growth ~ 3 slots/month
    s3_growth_slots_per_month: float = 3.0

    # Monte Carlo
    n_seeds: int = 50

    # Output
    output_dir: str = "results/node_perspective"


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


def _warm_start(
    n_peers: int,
    reliability: np.ndarray,
    warmup_days: int,
    p_window: int,
    rng: np.random.Generator,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Run warmup_days of daily checks for peers. Return (p_buf, i_sum, p_prev).

    p_buf  shape (p_window, n_peers)  — rolling window buffer (filled)
    i_sum  shape (n_peers,)           — cumulative sum of all checks
    p_prev shape (n_peers,)           — P score from previous day
    """
    p_buf = np.zeros((p_window, n_peers))
    i_sum = np.zeros(n_peers)
    p_prev = np.zeros(n_peers)

    for d in range(warmup_days):
        checks = (rng.random(n_peers) < reliability).astype(np.float64)
        slot = d % p_window
        p_buf[slot] = checks
        i_sum += checks
        filled = min(d + 1, p_window)
        p_prev = p_buf[:filled].mean(axis=0)

    return p_buf, i_sum, p_prev



# ---------------------------------------------------------------------------
# Scenario 1: Flaky Partners
# ---------------------------------------------------------------------------

def _simulate_s1_one(config: Config, seed: int) -> dict:
    """Single run for Scenario 1: honest protagonist, mixed-reliability partners.

    Peers go through a lifecycle: healthy -> declining -> departed.
    The declining phase is what D-component detects early.
    Base reliability determines each peer's healthy-state reliability.
    During decline, reliability drops linearly from healthy to ~0.10 over
    s1_decline_days days, then peer departs (reliability = 0).
    """
    rng = np.random.default_rng(seed)

    n_peers = config.s1_n_peers
    n_reliable = int(n_peers * config.s1_reliable_frac)
    n_moderate = int(n_peers * config.s1_moderate_frac)

    # Base (healthy) reliability per peer
    base_reliability = np.empty(n_peers)
    base_reliability[:n_reliable] = config.s1_reliable_rel
    base_reliability[n_reliable:n_reliable + n_moderate] = config.s1_moderate_rel
    base_reliability[n_reliable + n_moderate:] = config.s1_flaky_rel

    n_days = config.s1_duration_months * 30
    p_window = config.p_window

    # Peer trust state (warm-start with 60 days at base reliability)
    warmup_days = 60
    p_buf, i_sum, _ = _warm_start(n_peers, base_reliability, warmup_days, p_window, rng)
    total_days = warmup_days

    # Protagonist's 15 shards: assign random holders
    shard_holders = rng.integers(0, n_peers, size=config.n_shards).tolist()

    # Peer departure lifecycle
    # Each peer: healthy until decline_start_day, declining until depart_day
    # depart_day = -1 means no departure in this simulation
    p_depart_daily = 1.0 - (1.0 - config.s1_annual_churn) ** (1.0 / 365.0)
    depart_day = np.full(n_peers, -1, dtype=np.int64)
    decline_start = np.full(n_peers, -1, dtype=np.int64)
    peer_online = np.ones(n_peers, dtype=bool)

    for i in range(n_peers):
        days_until = int(rng.geometric(p_depart_daily))
        if days_until < n_days:
            depart_day[i] = days_until
            decline_start[i] = max(0, days_until - config.s1_decline_days)

    # Current effective reliability (changes during decline phase)
    current_reliability = base_reliability.copy()

    # D-score tracking: daily delta of 30-day rolling P mean
    ws_filled = min(warmup_days, p_window)
    p_score_current: np.ndarray = p_buf[:ws_filled].mean(axis=0)
    p_score_prev_day: np.ndarray = p_score_current.copy()
    d_score: np.ndarray = np.zeros(n_peers)

    # Active D-warnings per shard: shard_idx -> (warn_day, peer_idx)
    d_warn_day: dict[int, tuple[int, int]] = {}

    # Monthly accumulators
    month_own_shards: list[float] = []
    month_at_risk: list[float] = []
    month_repairs: list[float] = []
    month_d_warnings: list[float] = []
    month_p_restore: list[float] = []
    m_repairs = 0
    m_d_warnings = 0

    # D-warning accuracy tracking
    all_d_warnings: list[tuple[int, int]] = []  # (warn_day, peer_idx)

    for day in range(n_days):
        # --- Update peer lifecycle ---
        for i in range(n_peers):
            if depart_day[i] >= 0 and day >= int(depart_day[i]) and peer_online[i]:
                peer_online[i] = False
                current_reliability[i] = 0.0
            elif decline_start[i] >= 0 and day >= int(decline_start[i]) and peer_online[i]:
                # Declining: reliability drops linearly base_rel -> 0.10
                progress = (
                    (day - int(decline_start[i]))
                    / max(1, config.s1_decline_days)
                )
                progress = min(1.0, progress)
                current_reliability[i] = (
                    base_reliability[i] * (1.0 - progress)
                    + 0.10 * progress
                )
            else:
                current_reliability[i] = base_reliability[i]

        # --- Daily checks (protagonist's probes of its shard holders) ---
        checks = np.where(
            peer_online,
            (rng.random(n_peers) < current_reliability).astype(np.float64),
            0.0,
        )

        slot = total_days % p_window
        p_buf[slot] = checks
        total_days += 1
        n_filled = min(total_days, p_window)
        i_sum += checks

        # Recompute P score and D score
        p_score_current = p_buf[:n_filled].mean(axis=0)
        d_score = p_score_current - p_score_prev_day
        p_score_prev_day = p_score_current.copy()

        i_score = i_sum / total_days
        trust = config.kp * p_score_current + config.ki * i_score

        # --- Weekly repair cycle ---
        if (day + 1) % config.repair_interval_days == 0:
            for si in range(config.n_shards):
                holder = shard_holders[si]
                if holder < 0:
                    continue

                # Holder departed: reactive repair
                if not peer_online[holder]:
                    current_holders = set(h for h in shard_holders if h >= 0)
                    candidates = [
                        p for p in range(n_peers)
                        if peer_online[p] and p not in current_holders
                    ]
                    if candidates:
                        w = np.array([float(trust[p]) for p in candidates])
                        best = candidates[int(np.argmax(w))]
                        shard_holders[si] = best
                    else:
                        shard_holders[si] = -1
                    m_repairs += 1
                    d_warn_day.pop(si, None)
                    continue

                d_val = float(d_score[holder])

                # New D-warning: holder is declining
                if d_val < config.d_threshold and si not in d_warn_day:
                    d_warn_day[si] = (day, holder)
                    m_d_warnings += 1
                    all_d_warnings.append((day, holder))
                elif d_val >= 0.0 and si in d_warn_day:
                    d_warn_day.pop(si, None)

                # Preemptive repair after sustained D-warning (one repair cycle)
                if si in d_warn_day:
                    warn_day_val, warned_peer = d_warn_day[si]
                    if (day - warn_day_val) >= config.repair_interval_days:
                        current_holders = set(h for h in shard_holders if h >= 0)
                        candidates = [
                            p for p in range(n_peers)
                            if peer_online[p]
                            and p not in current_holders
                            and float(trust[p]) > float(trust[warned_peer])
                        ]
                        if candidates:
                            w = np.array([float(trust[p]) for p in candidates])
                            best = candidates[int(np.argmax(w))]
                            shard_holders[si] = best
                            m_repairs += 1
                        d_warn_day.pop(si, None)

        # --- Monthly snapshot ---
        if (day + 1) % 30 == 0:
            n_own = sum(1 for h in shard_holders if h >= 0)
            # At risk: holder is declining or offline
            at_risk = sum(
                1 for h in shard_holders
                if h >= 0 and (
                    float(p_score_current[h]) < 0.70
                    or not peer_online[h]
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

    # D-warning accuracy
    true_positives = 0
    false_positives = 0
    for warn_d, peer in all_d_warnings:
        dep = int(depart_day[peer])
        if dep >= 0 and dep <= warn_d + 30:
            true_positives += 1
        else:
            false_positives += 1

    total_warnings = true_positives + false_positives
    tp_rate = true_positives / max(1, total_warnings)
    fp_rate = false_positives / max(1, total_warnings)
    total_warnings_per_year = total_warnings * (365.0 / n_days) if n_days > 0 else 0.0

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
        "config": asdict(config),
        "elapsed_sec": elapsed,
        "monthly": monthly,
        "d_warnings_per_year": _stat([r["d_warnings_per_year"] for r in runs]),
        "tp_rate": _stat([r["tp_rate"] for r in runs]),
        "fp_rate": _stat([r["fp_rate"] for r in runs]),
    }


def print_scenario1(result: dict) -> None:
    cfg = result["config"]
    print("=== SCENARIO 1: FLAKY PARTNERS ===")
    print(f"Network: {cfg['s1_n_peers']} peers  "
          f"({cfg['s1_reliable_frac']*100:.0f}% reliable @{cfg['s1_reliable_rel']}, "
          f"{cfg['s1_moderate_frac']*100:.0f}% moderate @{cfg['s1_moderate_rel']}, "
          f"{(1-cfg['s1_reliable_frac']-cfg['s1_moderate_frac'])*100:.0f}% flaky @{cfg['s1_flaky_rel']})")
    print(f"Duration: {cfg['s1_duration_months']} months  |  "
          f"Seeds: {cfg['n_seeds']}  |  Runtime: {result['elapsed_sec']:.1f}s")
    print()
    hdr = (f"{'Month':>6}  {'OwnShards':>9}  {'AtRisk':>6}  "
           f"{'Repairs':>7}  {'D-warns':>7}  {'P_restore':>9}")
    print(hdr)
    print("-" * len(hdr))
    for row in result["monthly"]:
        m = row["month"]
        own = row["own_shards"]["mean"]
        risk = row["at_risk"]["mean"]
        rep = row["repairs"]["mean"]
        dw = row["d_warnings"]["mean"]
        pr = row["p_restore"]["mean"]
        print(f"{m:>6}  {own:>9.1f}  {risk:>6.1f}  "
              f"{rep:>7.2f}  {dw:>7.2f}  {pr*100:>8.1f}%")
    print()
    dwy = result["d_warnings_per_year"]
    tp = result["tp_rate"]
    fp = result["fp_rate"]
    print(f"D-warning events:    avg {dwy['mean']:.1f}/year  "
          f"[p5={dwy['p5']:.1f}, p95={dwy['p95']:.1f}]")
    print(f"True positive rate:  {tp['mean']*100:.0f}%  "
          f"(D warned before departure, peer departed within 30d)")
    print(f"False positive rate: {fp['mean']*100:.0f}%  "
          f"(D warned but peer did NOT depart within 30d)")


# ---------------------------------------------------------------------------
# Scenario 2: Vacation
# ---------------------------------------------------------------------------

def _simulate_s2_one(config: Config, seed: int) -> dict:
    """Single run for Scenario 2: protagonist goes offline for 14 days."""
    rng = np.random.default_rng(seed)

    n_peers = config.s2_n_peers
    reliability = np.full(n_peers, config.s2_peer_reliability)

    pre_vac_days = config.s2_pre_vacation_months * 30
    vac_days = config.s2_vacation_days
    post_vac_days = config.s2_post_vacation_months * 30
    n_days = pre_vac_days + vac_days + post_vac_days

    p_window = config.p_window

    # Protagonist trust tracking (no warm-start: starts fresh)
    prot_p_buf = np.zeros(p_window)
    prot_i_sum = 0.0
    prot_total = 0

    # Background peer trust (warm-started with pre_vac_days)
    bg_p_buf, bg_i_sum, bg_p_prev = _warm_start(
        n_peers, reliability, pre_vac_days, p_window, rng
    )
    bg_total = pre_vac_days

    # Protagonist: also warm-started with pre_vac_days of reliable behavior
    prot_check_hist = rng.random(pre_vac_days) < 0.95
    for d in range(pre_vac_days):
        slot = d % p_window
        prot_p_buf[slot] = float(prot_check_hist[d])
        prot_i_sum += float(prot_check_hist[d])
        prot_total += 1

    prot_p_filled = min(prot_total, p_window)
    prot_p_score = prot_p_buf[:prot_p_filled].mean()
    prot_i_score = prot_i_sum / prot_total
    prot_trust_pre = config.kp * prot_p_score + config.ki * prot_i_score

    # Shard holders: all placed on pre-existing peers
    shard_holders = rng.integers(0, n_peers, size=config.n_shards).tolist()

    # Snapshot: (phase_label, day_abs, trust, p_score, i_score, n_own, p_restore)
    snapshots: list[tuple[str, int, float, float, float, int, float]] = []

    def _snap(label: str, day: int) -> None:
        filled = min(prot_total, p_window)
        ps = prot_p_buf[:filled].mean() if filled > 0 else 0.0
        is_ = prot_i_sum / max(1, prot_total)
        tr = config.kp * ps + config.ki * is_
        n_own = sum(1 for h in shard_holders if h >= 0)
        pr = _restore_prob(n_own, config.k)
        snapshots.append((label, day, tr, ps, is_, n_own, pr))

    # Capture pre-vacation baseline (day pre_vac_days - 1)
    _snap("Pre-vacation", pre_vac_days - 1)

    # Run vacation phase
    protagonist_online = True
    for day_offset in range(vac_days + post_vac_days):
        abs_day = pre_vac_days + day_offset
        on_vacation = day_offset < vac_days

        if on_vacation:
            protagonist_online = False
            prot_check = 0.0
        else:
            protagonist_online = True
            prot_check = float(rng.random() < 0.95)

        # Update protagonist trust
        slot = prot_total % p_window
        prot_p_buf[slot] = prot_check
        prot_i_sum += prot_check
        prot_total += 1

        # Background peers
        bg_checks = (rng.random(n_peers) < reliability).astype(np.float64)
        bg_slot = bg_total % p_window
        bg_p_buf[bg_slot] = bg_checks
        bg_i_sum += bg_checks
        bg_total += 1

        # Weekly repair of own shards (shards are maintained by network even
        # while protagonist is away — other peers do not evict immediately)
        if (abs_day + 1) % config.repair_interval_days == 0:
            bg_filled = min(bg_total, p_window)
            bg_p_score_arr = bg_p_buf[:bg_filled].mean(axis=0)
            bg_i_arr = bg_i_sum / bg_total
            bg_trust = config.kp * bg_p_score_arr + config.ki * bg_i_arr

            # Shards on failed peers (simulate small natural failure rate)
            for si in range(config.n_shards):
                h = shard_holders[si]
                if h < 0:
                    continue
                # Natural shard failure (~1% per week)
                if rng.random() < 0.01:
                    shard_holders[si] = -1
                    # If protagonist is online, immediately try to repair
                    if protagonist_online:
                        current = set(h2 for h2 in shard_holders if h2 >= 0)
                        cands = [p for p in range(n_peers) if p not in current]
                        if cands:
                            w = np.array([float(bg_trust[p]) for p in cands])
                            best = cands[int(np.argmax(w))]
                            shard_holders[si] = best

        # Key day snapshots
        vac_day = day_offset  # 0-indexed within vacation+post
        if vac_day == 0:
            _snap("Vacation d1", abs_day)
        elif vac_day == 6:
            _snap("Vacation d7", abs_day)
        elif vac_day == vac_days - 1:
            _snap(f"Vacation d{vac_days}", abs_day)
        elif vac_day == vac_days:
            _snap("Post d1", abs_day)
        elif vac_day == vac_days + 6:
            _snap("Post d7", abs_day)
        elif vac_day == vac_days + 29:
            _snap("Post d30", abs_day)

    return {
        "snapshots": snapshots,
        "prot_trust_pre": prot_trust_pre,
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

    # Aggregate snapshots by label (order preserved from first run)
    # Labels are deterministic given the code path
    label_order: list[str] = []
    label_data: dict[str, dict[str, list[float]]] = {}

    for run in runs:
        for label, day, trust, ps, is_, n_own, pr in run["snapshots"]:
            if label not in label_data:
                label_order.append(label)
                label_data[label] = {
                    "day": [], "trust": [], "p_score": [],
                    "i_score": [], "n_own": [], "p_restore": [],
                }
            label_data[label]["day"].append(float(day))
            label_data[label]["trust"].append(trust)
            label_data[label]["p_score"].append(ps)
            label_data[label]["i_score"].append(is_)
            label_data[label]["n_own"].append(float(n_own))
            label_data[label]["p_restore"].append(pr)

    aggregated: list[dict] = []
    for label in label_order:
        d = label_data[label]
        aggregated.append({
            "label": label,
            "day": _stat(d["day"]),
            "trust": _stat(d["trust"]),
            "p_score": _stat(d["p_score"]),
            "i_score": _stat(d["i_score"]),
            "n_own": _stat(d["n_own"]),
            "p_restore": _stat(d["p_restore"]),
        })

    pre_trusts = [r["prot_trust_pre"] for r in runs]
    trust_loss = [
        r["prot_trust_pre"] - label_data.get(
            f"Vacation d{config.s2_vacation_days}", {"trust": [r["prot_trust_pre"]]}
        )["trust"][i]
        for i, r in enumerate(runs)
        if f"Vacation d{config.s2_vacation_days}" in label_data
    ]

    return {
        "scenario": 2,
        "config": asdict(config),
        "elapsed_sec": elapsed,
        "snapshots": aggregated,
        "pre_vacation_trust": _stat(pre_trusts),
        "trust_loss_during_vacation": _stat(trust_loss) if trust_loss else {},
    }


def print_scenario2(result: dict) -> None:
    cfg = result["config"]
    vac_days = cfg["s2_vacation_days"]
    print("=== SCENARIO 2: VACATION (14 days offline) ===")
    print(f"Network: {cfg['s2_n_peers']} peers @{cfg['s2_peer_reliability']} reliability")
    print(f"Phase: {cfg['s2_pre_vacation_months']}mo pre + {vac_days}d vacation "
          f"+ {cfg['s2_post_vacation_months']}mo post")
    print(f"Seeds: {cfg['n_seeds']}  |  Runtime: {result['elapsed_sec']:.1f}s")

    pre_t = result["pre_vacation_trust"]
    print(f"\nPre-vacation trust:  "
          f"{pre_t['mean']:.3f}  [p5={pre_t['p5']:.3f}, p95={pre_t['p95']:.3f}]")

    if result["trust_loss_during_vacation"]:
        tl = result["trust_loss_during_vacation"]
        print(f"Trust loss (vacation end vs pre): "
              f"{tl['mean']:.3f}  [p5={tl['p5']:.3f}, p95={tl['p95']:.3f}]")

    print()
    hdr = (f"{'Phase':<18}  {'Day':>4}  {'Trust':>6}  {'P_score':>7}  "
           f"{'I_score':>7}  {'OwnShards':>9}  {'P_restore':>9}")
    print(hdr)
    print("-" * len(hdr))

    for row in result["snapshots"]:
        label = row["label"]
        day = row["day"]["mean"]
        trust = row["trust"]["mean"]
        ps = row["p_score"]["mean"]
        is_ = row["i_score"]["mean"]
        n_own = row["n_own"]["mean"]
        pr = row["p_restore"]["mean"]
        print(f"{label:<18}  {day:>4.0f}  {trust:>6.3f}  {ps:>7.3f}  "
              f"{is_:>7.3f}  {n_own:>9.1f}  {pr*100:>8.1f}%")


# ---------------------------------------------------------------------------
# Scenario 3: Disk Pressure
# ---------------------------------------------------------------------------

def _simulate_s3_one(config: Config, seed: int) -> dict:
    """Single run for Scenario 3: disk fills up over 18 months."""
    rng = np.random.default_rng(seed)

    n_peers = config.s3_n_peers
    reliability = np.full(n_peers, config.s3_peer_reliability)
    n_days = config.s3_duration_months * 30
    p_window = config.p_window

    # Warm-start background peers (3 months)
    warmup_days = 90
    bg_p_buf, bg_i_sum, bg_p_prev = _warm_start(
        n_peers, reliability, warmup_days, p_window, rng
    )
    bg_total = warmup_days

    # Compute initial trust for peers
    bg_p_score = bg_p_buf[:min(bg_total, p_window)].mean(axis=0)
    bg_i_score = bg_i_sum / bg_total
    trust = config.kp * bg_p_score + config.ki * bg_i_score

    # Protagonist trust state (also warm-started with 3 months)
    prot_p_buf = np.zeros(p_window)
    prot_i_sum = 0.0
    prot_total = 0
    for d in range(warmup_days):
        check = float(rng.random() < 0.95)
        slot = d % p_window
        prot_p_buf[slot] = check
        prot_i_sum += check
        prot_total += 1

    # Protagonist's own shards — placed on peers
    shard_holders = rng.integers(0, n_peers, size=config.n_shards).tolist()

    # Protagonist's storage: stores shards for s3_initial_partners partners
    # stored_for[i] = peer index
    all_peer_ids = list(range(n_peers))
    rng.shuffle(all_peer_ids)
    stored_for: list[int] = list(all_peer_ids[:config.s3_initial_partners])
    initial_stored = len(stored_for)  # = s3_initial_partners

    # Disk model:
    # disk_slots = total capacity (e.g., 100 shard-slots)
    # used_by_local = local files growing over time
    # used_by_stored = shards we store for others = len(stored_for)
    # free = disk_slots - used_by_local - used_by_stored
    # Initially: used_by_local = disk_slots * (1 - initial_free_frac) - initial_stored
    disk_slots = config.s3_disk_slots
    initial_used_local = int(disk_slots * (1.0 - config.s3_initial_free_frac)) - initial_stored
    initial_used_local = max(0, initial_used_local)

    total_evictions = 0

    # Monthly snapshots
    month_free_pct: list[float] = []
    month_stored_for: list[float] = []
    month_own_shards: list[float] = []
    month_trust: list[float] = []
    month_evictions: list[float] = []
    month_p_restore: list[float] = []

    month_evictions_this: int = 0

    for day in range(n_days):
        month = day // 30

        # --- Background peer checks ---
        bg_checks = (rng.random(n_peers) < reliability).astype(np.float64)
        slot = bg_total % p_window
        bg_p_buf[slot] = bg_checks
        bg_i_sum += bg_checks
        bg_total += 1
        bg_filled = min(bg_total, p_window)
        bg_p_score = bg_p_buf[:bg_filled].mean(axis=0)
        bg_i_score = bg_i_sum / bg_total
        trust = config.kp * bg_p_score + config.ki * bg_i_score

        # --- Protagonist check ---
        prot_check = float(rng.random() < 0.95)
        prot_slot = prot_total % p_window
        prot_p_buf[prot_slot] = prot_check
        prot_i_sum += prot_check
        prot_total += 1

        # --- Disk usage ---
        # Local files grow linearly: +growth_slots_per_month / 30 per day
        months_elapsed = (day + warmup_days) / 30.0
        used_local = initial_used_local + config.s3_growth_slots_per_month * months_elapsed
        used_local = min(used_local, disk_slots)
        used_stored = len(stored_for)
        free = disk_slots - used_local - used_stored
        free_pct = max(0.0, free / disk_slots)

        # --- Weekly repair / eviction cycle ---
        if (day + 1) % config.repair_interval_days == 0:
            # Compute protagonist trust
            prot_filled = min(prot_total, p_window)
            prot_p_score = float(prot_p_buf[:prot_filled].mean())
            prot_i_score = float(prot_i_sum / prot_total)
            prot_trust = config.kp * prot_p_score + config.ki * prot_i_score

            # Eviction: if used_local + len(stored_for) > disk_slots - buffer
            # Buffer: keep at least 5% free for repair overhead
            committed_capacity = int(disk_slots * 0.95) - int(used_local)
            committed_capacity = max(0, committed_capacity)

            if len(stored_for) > committed_capacity:
                n_evict = len(stored_for) - committed_capacity
                # Evict lowest-trust partners first
                peer_trusts = [float(trust[p]) for p in stored_for]
                evict_order = np.argsort(peer_trusts)  # ascending: lowest first
                evict_indices = set(int(evict_order[i]) for i in range(n_evict))
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
                if rng.random() < 0.01:  # ~1% per week failure
                    shard_holders[si] = -1
                    current = set(h2 for h2 in shard_holders if h2 >= 0)
                    cands = [p for p in range(n_peers) if p not in current]
                    if cands:
                        w_arr = np.array([float(trust[p]) for p in cands])
                        best = cands[int(np.argmax(w_arr))]
                        shard_holders[si] = best

        # --- Monthly snapshot ---
        if (day + 1) % 30 == 0:
            prot_filled = min(prot_total, p_window)
            prot_p_score_m = float(prot_p_buf[:prot_filled].mean())
            prot_i_score_m = float(prot_i_sum / prot_total)
            prot_trust_m = config.kp * prot_p_score_m + config.ki * prot_i_score_m

            n_own = sum(1 for h in shard_holders if h >= 0)
            pr = _restore_prob(n_own, config.k)
            month_free_pct.append(free_pct)
            month_stored_for.append(float(len(stored_for)))
            month_own_shards.append(float(n_own))
            month_trust.append(prot_trust_m)
            month_evictions.append(float(month_evictions_this))
            month_p_restore.append(pr)
            month_evictions_this = 0

    return {
        "month_free_pct": month_free_pct,
        "month_stored_for": month_stored_for,
        "month_own_shards": month_own_shards,
        "month_trust": month_trust,
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
            "evictions": _stat([r["month_evictions"][m] for r in runs
                                 if m < len(r["month_evictions"])]),
            "p_restore": _stat([r["month_p_restore"][m] for r in runs
                                 if m < len(r["month_p_restore"])]),
        })

    return {
        "scenario": 3,
        "config": asdict(config),
        "elapsed_sec": elapsed,
        "monthly": monthly,
        "total_evictions": _stat([r["total_evictions"] for r in runs]),
    }


def print_scenario3(result: dict) -> None:
    cfg = result["config"]
    print("=== SCENARIO 3: DISK PRESSURE ===")
    print(f"Network: {cfg['s3_n_peers']} peers  "
          f"| Disk: {cfg['s3_disk_slots']} slots, "
          f"{cfg['s3_initial_free_frac']*100:.0f}% initially free")
    print(f"Growth: {cfg['s3_growth_slots_per_month']:.1f} slots/month  "
          f"| Initial partners: {cfg['s3_initial_partners']}")
    print(f"Duration: {cfg['s3_duration_months']} months  "
          f"| Seeds: {cfg['n_seeds']}  "
          f"| Runtime: {result['elapsed_sec']:.1f}s")
    print()
    hdr = (f"{'Month':>6}  {'FreeSpace%':>10}  {'StoredFor':>9}  "
           f"{'OwnShards':>9}  {'Trust':>6}  {'Evictions':>9}  {'P_restore':>9}")
    print(hdr)
    print("-" * len(hdr))

    # Print subset of months for readability
    highlight = {1, 6, 12, 15, 18}
    for row in result["monthly"]:
        m = row["month"]
        if m not in highlight and m % 3 != 0:
            continue
        free = row["free_pct"]["mean"]
        sf = row["stored_for"]["mean"]
        own = row["own_shards"]["mean"]
        tr = row["trust"]["mean"]
        ev = row["evictions"]["mean"]
        pr = row["p_restore"]["mean"]
        print(f"{m:>6}  {free*100:>9.1f}%  {sf:>9.1f}  "
              f"{own:>9.1f}  {tr:>6.3f}  {ev:>9.2f}  {pr*100:>8.1f}%")

    te = result["total_evictions"]
    print()
    print(f"Total evictions over {cfg['s3_duration_months']} months: "
          f"avg {te['mean']:.1f}  [p5={te['p5']:.1f}, p95={te['p95']:.1f}]")


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
        description="SyncBack Exp 14: Individual Node Perspective"
    )
    parser.add_argument(
        "--scenario", type=int, choices=[1, 2, 3],
        help="Which scenario to run (1, 2, or 3)"
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Run all three scenarios"
    )
    parser.add_argument("--seeds", type=int, default=50,
                        help="Monte Carlo seeds (default: 50)")
    parser.add_argument("--jobs", type=int, default=1,
                        help="Parallel jobs (joblib, default: 1)")
    parser.add_argument("--output", type=str, default="results/node_perspective",
                        help="Output directory")
    parser.add_argument("--k", type=int, default=5)
    parser.add_argument("--n-shards", type=int, default=15)
    parser.add_argument("--kp", type=float, default=0.5)
    parser.add_argument("--ki", type=float, default=2.0)
    parser.add_argument("--d-threshold", type=float, default=-0.01)
    args = parser.parse_args()

    if not args.scenario and not args.all:
        parser.error("Specify --scenario 1/2/3 or --all")

    config = Config(
        k=args.k,
        n_shards=args.n_shards,
        kp=args.kp,
        ki=args.ki,
        d_threshold=args.d_threshold,
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
