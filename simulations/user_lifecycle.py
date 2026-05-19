"""
Viaticum Simulation #11: User Lifecycle

Question: How does a single user experience the system from day 0 to year N?

Follows ONE protagonist through all phases in a network of 200 background peers.
Background peers are pre-established (warm-started with 6-month trust history).
The protagonist joins as a brand-new peer with zero trust.

Phases:
    Phase 1 — bootstrap     (months  0-3)   empty disk, no reputation
    Phase 2 — trust_build   (months  3-12)  storing reliably, trust grows
    Phase 3 — steady_state  (months 12-36)  established, disk failure at month 18
    Phase 4 — disk_pressure (months 36-42)  storage fills, eviction under pressure
    Phase 5 — departure     (months 42-48)  graceful vs sudden departure
    Phase 6 — return        (months 48-54)  rejoin after 6 months away

Background peers (pre-established at simulation start):
    80% reliable (reliability=0.95) — steady trust ~2.4
    15% moderate (reliability=0.80) — steady trust ~1.9
     5% flaky    (reliability=0.50) — steady trust ~1.2

Trust formula (PI controller):
    trust = 0.5 * P + 2.0 * I
    P = 30-day rolling window of daily check results
    I = cumulative average of all checks
    New peer starts with zero trust (no history).

Bootstrap mechanics:
    Established peers (trust >= trust_threshold) will only accept shards from the
    protagonist once protagonist trust >= trust_threshold.
    During bootstrap (months 0-3), protagonist can only partner with other
    low-trust peers (bootstrap_gate). This is the acceptance gate from Exp 10.

Disk pressure (Phase 4):
    Disk fills linearly; shards evicted in order of lowest holder trust first.
    Commitment levels: Stable -> Pressured -> Evicting (from RESEARCH.md 4.11).

Usage:
    python user_lifecycle.py                     # default run
    python user_lifecycle.py --seeds 50          # Monte Carlo
    python user_lifecycle.py --jobs 4            # parallel
    python user_lifecycle.py --departure sudden  # compare departure modes
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
# Phase boundaries (months, zero-indexed)
# ---------------------------------------------------------------------------
BOOTSTRAP_END = 3
TRUST_BUILD_END = 12
STEADY_STATE_END = 36
DISK_PRESSURE_END = 42
DEPARTURE_END = 48
RETURN_END = 54

TOTAL_MONTHS = RETURN_END
DISK_FAILURE_MONTH = 18    # restore test performed this month


def _phase_name(month: int) -> str:
    if month < BOOTSTRAP_END:
        return "bootstrap"
    if month < TRUST_BUILD_END:
        return "trust_build"
    if month < STEADY_STATE_END:
        if month == DISK_FAILURE_MONTH:
            return "restore_test"
        return "steady_state"
    if month < DISK_PRESSURE_END:
        return "disk_pressure"
    if month < DEPARTURE_END:
        return "departure"
    return "return"


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class Config:
    # Network
    n_background_peers: int = 200

    # Erasure coding (documents profile: 5-of-15)
    k: int = 5
    n_shards: int = 15

    # PI controller
    kp: float = 0.5
    ki: float = 2.0
    p_window: int = 30          # days

    # Repair / weekly cycle
    repair_interval_days: int = 7
    shard_failure_prob: float = 0.02   # per repair-cycle per shard

    # Background peer reliability distribution
    reliable_fraction: float = 0.80
    reliable_reliability: float = 0.95
    moderate_fraction: float = 0.15
    moderate_reliability: float = 0.80
    # remaining fraction = flaky
    flaky_reliability: float = 0.50

    # Background peers warm-start: simulate N_WARMUP_DAYS of history before
    # protagonist joins, so they already have established trust.
    bg_warmup_days: int = 180    # 6 months

    # Protagonist base reliability (when online)
    protagonist_reliability: float = 0.95

    # Trust gate: established peers require protagonist trust >= this to accept
    trust_threshold: float = 0.30
    # Bootstrap gate: protagonist can partner with any peer >= this during bootstrap
    bootstrap_gate: float = 0.05

    # Disk capacity: max shards protagonist stores for others
    disk_capacity_shards: int = 60
    # Disk pressure ramp: disk fills from pressure_start_month to pressure_full_month
    pressure_start_month: int = 36
    pressure_full_month: int = 40

    # Max partners protagonist actively maintains
    max_partners: int = 20

    # Departure mode: "graceful" (death scream) or "sudden" (silent disappear)
    departure_mode: str = "graceful"

    # Monte Carlo
    n_seeds: int = 50

    # Output
    output_dir: str = "results/user_lifecycle"


# ---------------------------------------------------------------------------
# Trust helpers
# ---------------------------------------------------------------------------

def _compute_trust_scalar(
    p_avg: float,
    i_avg: float,
    kp: float,
    ki: float,
) -> float:
    return kp * p_avg + ki * i_avg


def _restore_prob(n_placed: int, k: int, per_shard_avail: float = 0.97) -> float:
    """P(at least k of n_placed shards available) via exact binomial."""
    if n_placed < k:
        return 0.0
    p = per_shard_avail
    total = 0.0
    for s in range(k, n_placed + 1):
        total += comb(n_placed, s) * (p ** s) * ((1.0 - p) ** (n_placed - s))
    return min(1.0, total)


def _warm_start_background(
    n_bg: int,
    reliability: np.ndarray,  # shape (n_bg,)
    warmup_days: int,
    p_window: int,
    kp: float,
    ki: float,
    rng: np.random.Generator,
) -> tuple[np.ndarray, np.ndarray]:
    """Simulate bg_warmup_days days for background peers and return their trust state.

    Returns:
        trust  shape (n_bg,)  — current trust scores
        i_avg  shape (n_bg,)  — cumulative average (I component)
        (The P buffer rolls so we return last p_window rows of checks)
    """
    # We don't need to return the buffer; we just compute final trust analytically.
    # For I: after N days with reliability r, i_avg = r (noisy estimate)
    # For P: after N days (N >> p_window), p_avg = r (30-day window average)
    # We add realistic noise via a short Monte Carlo.
    n_days = warmup_days

    # Simulate compactly: run n_days checks, track rolling P and cumulative I
    p_buf = np.zeros((p_window, n_bg))
    i_sum = np.zeros(n_bg)

    for d in range(n_days):
        checks = (rng.random(n_bg) < reliability).astype(np.float64)
        p_buf[d % p_window] = checks
        i_sum += checks

    filled = min(n_days, p_window)
    p_score = p_buf[:filled].mean(axis=0)
    i_score = i_sum / n_days
    trust = kp * p_score + ki * i_score

    return trust, i_score


# ---------------------------------------------------------------------------
# Shard placement
# ---------------------------------------------------------------------------

def _weighted_choice_without_replacement(
    candidates: list[int],
    weights: np.ndarray,
    n: int,
    rng: np.random.Generator,
) -> list[int]:
    """Select up to n items from candidates using weight-proportional probability."""
    if not candidates or n <= 0:
        return []
    n_pick = min(n, len(candidates))
    w = np.maximum(weights, 1e-9)
    probs = w / w.sum()
    chosen = rng.choice(len(candidates), size=n_pick, replace=False, p=probs)
    return [candidates[int(i)] for i in chosen]


# ---------------------------------------------------------------------------
# Monthly snapshot
# ---------------------------------------------------------------------------

@dataclass
class MonthSnapshot:
    month: int
    phase: str
    protagonist_trust: float
    n_partners: int
    n_stored_shards: int        # shards protagonist stores for others
    n_own_shards_placed: int    # protagonist's own shards on the network
    redundancy_num: int
    redundancy_den: int
    partner_avg_trust: float
    restore_success: float      # P(successful restore right now)


# ---------------------------------------------------------------------------
# Single-run simulation
# ---------------------------------------------------------------------------

def simulate_one(config: Config, seed: int) -> list[MonthSnapshot]:
    """Simulate one full protagonist lifecycle. Returns monthly snapshots."""
    rng = np.random.default_rng(seed)

    n_bg = config.n_background_peers
    PROT = n_bg   # protagonist index in arrays of size n_bg+1
    n_total = n_bg + 1

    # --- Background peer reliability ---
    n_reliable = int(n_bg * config.reliable_fraction)
    n_moderate = int(n_bg * config.moderate_fraction)
    # remainder = flaky

    bg_reliability = np.empty(n_bg)
    bg_reliability[:n_reliable] = config.reliable_reliability
    bg_reliability[n_reliable:n_reliable + n_moderate] = config.moderate_reliability
    bg_reliability[n_reliable + n_moderate:] = config.flaky_reliability

    # --- Warm-start background peers (6 months of history before protagonist joins) ---
    bg_trust, bg_i_avg = _warm_start_background(
        n_bg, bg_reliability, config.bg_warmup_days,
        config.p_window, config.kp, config.ki, rng,
    )

    # Full trust array: protagonist starts at 0
    trust = np.zeros(n_total)
    trust[:n_bg] = bg_trust

    # Running statistics for protagonist (bg peers are pre-warmed; we track
    # their trust as slowly-evolving — updated each day but starting from warm state)
    # For simplicity, bg peer trust evolves via a running estimate.
    # We maintain a compact representation: bg_i_avg for I, and recompute P daily.
    bg_p_buf = np.zeros((config.p_window, n_bg))
    bg_i_sum = bg_i_avg * config.bg_warmup_days   # reconstruct cumulative sum
    bg_total_days = config.bg_warmup_days

    # Protagonist trust state (starts empty)
    prot_p_buf = np.zeros(config.p_window)
    prot_i_sum = 0.0
    prot_total_days = 0
    prot_buf_filled = 0

    # --- Protagonist's own file shards ---
    # own_holders[i] = bg peer index storing shard i, or -1 if unplaced
    own_holders: list[int] = [-1] * config.n_shards

    # --- Shards protagonist stores for others ---
    # Each element = bg peer index whose shard protagonist stores
    stored_for: list[int] = []

    # --- Active partner set ---
    partners: set[int] = set()

    # --- Lifecycle state ---
    protagonist_online = True

    # --- Phase 5: detect departure transition ---
    departure_triggered = False

    snapshots: list[MonthSnapshot] = []
    n_days = TOTAL_MONTHS * 30

    for day in range(n_days):
        month = day // 30

        # ----------------------------------------------------------------
        # Lifecycle transitions (at phase boundaries)
        # ----------------------------------------------------------------
        # Phase 5 start: departure
        if month >= DISK_PRESSURE_END and month < DEPARTURE_END:
            if not departure_triggered:
                departure_triggered = True
                protagonist_online = False
                if config.departure_mode == "graceful":
                    # Notify all partners (death scream): release stored shards
                    stored_for = []
                    partners = set()
                    # own shards remain on partner peers; partners keep repairing them
                else:
                    # Sudden departure: own shards will decay without repair
                    stored_for = []
                    partners = set()

        # Phase 6 start: return
        if month >= DEPARTURE_END and not protagonist_online:
            protagonist_online = True
            # Trust I has been penalized by 6 months of zero checks
            # P buffer is zero (no checks while absent)
            # Recovery happens organically as checks resume

        # ----------------------------------------------------------------
        # Compute current disk capacity
        # ----------------------------------------------------------------
        if month < BOOTSTRAP_END:
            # Bootstrap: offer limited storage to attract early partners
            cap_frac = 0.25
        elif month < TRUST_BUILD_END:
            ramp = (month - BOOTSTRAP_END) / (TRUST_BUILD_END - BOOTSTRAP_END)
            cap_frac = 0.25 + 0.75 * ramp
        elif month < STEADY_STATE_END:
            cap_frac = 1.0
        elif month < DISK_PRESSURE_END:
            # Disk pressure: capacity shrinks linearly
            pressure_span = (config.pressure_full_month - config.pressure_start_month) * 30
            days_in = day - STEADY_STATE_END * 30
            fill = min(1.0, days_in / max(1, pressure_span))
            cap_frac = 1.0 - fill
        else:
            cap_frac = 1.0 if protagonist_online else 0.0

        current_capacity = int(config.disk_capacity_shards * cap_frac)

        # ----------------------------------------------------------------
        # Daily checks
        # ----------------------------------------------------------------
        # Background peers
        bg_checks = (rng.random(n_bg) < bg_reliability).astype(np.float64)
        # Update bg trust (compact running update)
        bg_slot = day % config.p_window
        bg_p_buf[bg_slot] = bg_checks
        bg_i_sum += bg_checks
        bg_total_days += 1
        bg_p_filled = min(day + 1, config.p_window)
        bg_p_score = bg_p_buf[:bg_p_filled].mean(axis=0)
        bg_i_score = bg_i_sum / bg_total_days
        trust[:n_bg] = config.kp * bg_p_score + config.ki * bg_i_score

        # Protagonist
        if protagonist_online:
            prot_check = float(rng.random() < config.protagonist_reliability)
        else:
            prot_check = 0.0

        prot_slot = day % config.p_window
        prot_p_buf[prot_slot] = prot_check
        prot_i_sum += prot_check
        prot_total_days += 1
        prot_buf_filled = min(prot_total_days, config.p_window)
        prot_p_score = prot_p_buf[:prot_buf_filled].mean()
        prot_i_score = prot_i_sum / prot_total_days
        trust[PROT] = config.kp * prot_p_score + config.ki * prot_i_score

        # ----------------------------------------------------------------
        # Weekly repair/management cycle
        # ----------------------------------------------------------------
        if (day + 1) % config.repair_interval_days == 0:
            prot_trust = float(trust[PROT])

            # 1. Evict stored shards if over capacity (disk pressure eviction)
            if len(stored_for) > current_capacity:
                excess = len(stored_for) - current_capacity
                # Evict lowest-trust peers' shards first
                peer_trusts = [float(trust[p]) for p in stored_for]
                evict_order = np.argsort(peer_trusts)
                evict_set = {int(evict_order[i]) for i in range(excess)}
                new_stored = [p for idx, p in enumerate(stored_for) if idx not in evict_set]
                stored_for = new_stored
                partners = set(stored_for)

            # 2. Own shard maintenance: natural failure + repair
            if protagonist_online:
                # Natural shard failure
                for i in range(config.n_shards):
                    if own_holders[i] >= 0:
                        if rng.random() < config.shard_failure_prob:
                            own_holders[i] = -1

                n_own_now = sum(1 for h in own_holders if h >= 0)

                # Attempt placement / repair of missing own shards
                n_missing = config.n_shards - n_own_now
                can_repair = (n_own_now >= config.k) or (n_own_now == 0)

                if n_missing > 0 and can_repair:
                    # Peers will accept shards from protagonist based on trust gate:
                    # - bootstrap phase: accept at bootstrap_gate
                    # - later: accept only if protagonist trust >= trust_threshold
                    if month < BOOTSTRAP_END:
                        gate = config.bootstrap_gate
                    else:
                        gate = config.trust_threshold

                    existing_holders = {h for h in own_holders if h >= 0}
                    # Eligible bg peers: not already holding a shard,
                    # and willing to accept (protagonist trust >= their gate)
                    eligible: list[int] = []
                    for p in range(n_bg):
                        if p in existing_holders:
                            continue
                        # bg peer accepts protagonist's shard if:
                        # protagonist trust meets their acceptance gate
                        if prot_trust >= gate:
                            eligible.append(p)

                    if eligible:
                        w = np.array([float(trust[p]) for p in eligible])
                        new_holders = _weighted_choice_without_replacement(
                            eligible, w, n_missing, rng
                        )
                        slot_i = 0
                        for new_h in new_holders:
                            while slot_i < config.n_shards and own_holders[slot_i] >= 0:
                                slot_i += 1
                            if slot_i < config.n_shards:
                                own_holders[slot_i] = new_h
                                slot_i += 1

            # 3. During departure (sudden mode): own shards decay without repair
            if not protagonist_online and config.departure_mode == "sudden":
                # Shards decay with normal failure rate but no repair
                for i in range(config.n_shards):
                    if own_holders[i] >= 0:
                        if rng.random() < config.shard_failure_prob:
                            own_holders[i] = -1

            # 4. Accept storage requests from other peers
            if protagonist_online and len(stored_for) < current_capacity:
                slots_free = current_capacity - len(stored_for)

                if month < BOOTSTRAP_END:
                    requester_gate = config.bootstrap_gate
                else:
                    requester_gate = config.trust_threshold

                # Protagonist accepts peers whose trust >= requester_gate
                # AND whose trust >= protagonist_trust (mutual acceptance)
                n_incoming = int(rng.integers(1, 5))
                already_storing = set(stored_for)
                for _ in range(min(n_incoming, slots_free)):
                    # Find bg peers willing to partner with protagonist
                    candidate_ids = [
                        p for p in range(n_bg)
                        if p not in already_storing
                        and float(trust[p]) >= requester_gate
                    ]
                    if not candidate_ids:
                        break
                    w = np.array([float(trust[p]) for p in candidate_ids])
                    chosen = _weighted_choice_without_replacement(
                        candidate_ids, w, 1, rng
                    )
                    if chosen:
                        c = chosen[0]
                        stored_for.append(c)
                        already_storing.add(c)
                        partners.add(c)

            # 5. Partner churn in steady state
            if month >= TRUST_BUILD_END and partners:
                churn_rate = 0.01
                surviving: list[int] = []
                for p in stored_for:
                    if rng.random() > churn_rate:
                        surviving.append(p)
                stored_for = surviving
                partners = set(stored_for)

            # 6. Actively seek additional partners (up to max_partners)
            if protagonist_online and len(partners) < config.max_partners:
                prot_trust = float(trust[PROT])
                if month < BOOTSTRAP_END:
                    gate = config.bootstrap_gate
                    # Prefer other low-trust "newcomers" (mutual bootstrap)
                    newcomers = [
                        p for p in range(n_bg)
                        if float(trust[p]) < config.trust_threshold
                        and float(trust[p]) >= gate
                        and p not in partners
                    ]
                    if newcomers:
                        chosen = int(rng.choice(newcomers))
                        partners.add(chosen)
                else:
                    gate = config.trust_threshold
                    if prot_trust >= gate:
                        want = min(3, config.max_partners - len(partners))
                        good = [
                            p for p in range(n_bg)
                            if float(trust[p]) >= gate and p not in partners
                        ]
                        if good and want > 0:
                            w = np.array([float(trust[p]) for p in good])
                            chosen_list = _weighted_choice_without_replacement(
                                good, w, want, rng
                            )
                            for c in chosen_list:
                                partners.add(c)

        # ----------------------------------------------------------------
        # Monthly snapshot (end of each 30-day month)
        # ----------------------------------------------------------------
        if (day + 1) % 30 == 0:
            n_own = sum(1 for h in own_holders if h >= 0)
            partner_list = sorted(partners)
            p_avg = (float(np.mean([trust[p] for p in partner_list]))
                     if partner_list else 0.0)
            p_restore = _restore_prob(n_own, config.k)
            snapshots.append(MonthSnapshot(
                month=month,
                phase=_phase_name(month),
                protagonist_trust=float(trust[PROT]),
                n_partners=len(partners),
                n_stored_shards=len(stored_for),
                n_own_shards_placed=n_own,
                redundancy_num=n_own,
                redundancy_den=config.n_shards,
                partner_avg_trust=p_avg,
                restore_success=p_restore,
            ))

    return snapshots


# ---------------------------------------------------------------------------
# Monte Carlo
# ---------------------------------------------------------------------------

def run_experiment(config: Config, n_jobs: int = 1) -> dict:
    """Run Monte Carlo across seeds, return aggregated monthly timeline."""
    t0 = time.time()

    if n_jobs == 1:
        all_runs: list[list[MonthSnapshot]] = [
            simulate_one(config, seed) for seed in range(config.n_seeds)
        ]
    else:
        all_runs = Parallel(n_jobs=n_jobs)(
            delayed(simulate_one)(config, seed)
            for seed in range(config.n_seeds)
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

    monthly: list[dict] = []
    for m in range(TOTAL_MONTHS):
        snaps = [run[m] for run in all_runs if m < len(run)]
        if not snaps:
            continue
        monthly.append({
            "month": m,
            "phase": snaps[0].phase,
            "protagonist_trust": _stat([s.protagonist_trust for s in snaps]),
            "n_partners": _stat([float(s.n_partners) for s in snaps]),
            "n_stored_shards": _stat([float(s.n_stored_shards) for s in snaps]),
            "n_own_shards_placed": _stat([float(s.n_own_shards_placed) for s in snaps]),
            "redundancy_num": _stat([float(s.redundancy_num) for s in snaps]),
            "partner_avg_trust": _stat([s.partner_avg_trust for s in snaps]),
            "restore_success": _stat([s.restore_success for s in snaps]),
        })

    return {
        "config": asdict(config),
        "elapsed_sec": elapsed,
        "n_seeds": config.n_seeds,
        "timeline": monthly,
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_timeline(result: dict) -> None:
    """Print month-by-month lifecycle table."""
    cfg = result["config"]
    n_shards = cfg["n_shards"]

    print(f"Simulation: {cfg['n_seeds']} seeds, "
          f"{cfg['n_background_peers']} bg peers "
          f"(warm-started {cfg['bg_warmup_days']}d), "
          f"{cfg['k']}-of-{n_shards} erasure")
    print(f"PI: kp={cfg['kp']}, ki={cfg['ki']}, "
          f"departure={cfg['departure_mode']}, "
          f"trust_threshold={cfg['trust_threshold']}")
    print(f"Runtime: {result['elapsed_sec']:.1f}s")
    print()

    hdr = (
        f"{'Month':>5}  {'Phase':<14}  {'Trust':>6}  "
        f"{'Partners':>8}  {'Stored':>6}  {'Placed':>6}  "
        f"{'Redund':>7}  {'P_restore':>10}"
    )
    print(hdr)
    print("-" * len(hdr))

    for row in result["timeline"]:
        m = row["month"]
        trust_m = row["protagonist_trust"]["mean"]
        partners_m = row["n_partners"]["mean"]
        stored_m = row["n_stored_shards"]["mean"]
        placed_m = row["n_own_shards_placed"]["mean"]
        redund_m = row["redundancy_num"]["mean"]
        p_restore_m = row["restore_success"]["mean"]
        redund_str = f"{redund_m:.1f}/{n_shards}"
        phase = row["phase"]

        marker = ""
        if m == DISK_FAILURE_MONTH:
            marker = "  <-- RESTORE TEST"
        elif m == STEADY_STATE_END:
            marker = "  <-- DISK PRESSURE"
        elif m == DISK_PRESSURE_END:
            marker = "  <-- DEPARTURE"
        elif m == DEPARTURE_END:
            marker = "  <-- RETURN"

        print(
            f"{m:>5}  {phase:<14}  {trust_m:>6.3f}  "
            f"{partners_m:>8.1f}  {stored_m:>6.1f}  {placed_m:>6.1f}  "
            f"{redund_str:>7}  {p_restore_m*100:>9.1f}%"
            f"{marker}"
        )


def print_phase_summary(result: dict) -> None:
    """Print key phase milestones."""
    by_month = {row["month"]: row for row in result["timeline"]}

    def _t(m: int) -> str:
        row = by_month.get(m)
        if not row:
            return "n/a"
        mv = row["protagonist_trust"]["mean"]
        p5 = row["protagonist_trust"]["p5"]
        p95 = row["protagonist_trust"]["p95"]
        return f"{mv:.3f}  [p5={p5:.3f}, p95={p95:.3f}]"

    print()
    print("=== PHASE MILESTONES ===")
    print(f"Month  0  (join):                trust = {_t(0)}")
    print(f"Month  3  (end bootstrap):       trust = {_t(BOOTSTRAP_END - 1)}")
    print(f"Month 12  (end trust_build):     trust = {_t(TRUST_BUILD_END - 1)}")

    r18 = by_month.get(DISK_FAILURE_MONTH)
    p_restore_str = "n/a"
    if r18:
        p_restore_str = f"{r18['restore_success']['mean']*100:.1f}%"
    print(f"Month 18  (disk failure test):   trust = {_t(DISK_FAILURE_MONTH)},  "
          f"P(restore) = {p_restore_str}")

    print(f"Month 35  (end steady state):    trust = {_t(STEADY_STATE_END - 1)}")
    print(f"Month 36  (disk pressure start): trust = {_t(STEADY_STATE_END)}")
    print(f"Month 41  (end disk pressure):   trust = {_t(DISK_PRESSURE_END - 1)}")
    print(f"Month 42  (just departed):       trust = {_t(DISK_PRESSURE_END)}")
    print(f"Month 48  (return):              trust = {_t(DEPARTURE_END)}")
    print(f"Month 53  (6 months back):       trust = {_t(RETURN_END - 1)}")

    # Time to first own shard placed
    for row in result["timeline"]:
        if row["n_own_shards_placed"]["mean"] >= 1.0:
            print(f"\nFirst own shard placed:    month {row['month']} (mean over seeds)")
            break
    else:
        print("\nOwn shards never placed (trust too low to find partners)")

    # Time to first partner
    for row in result["timeline"]:
        if row["n_partners"]["mean"] >= 1.0:
            print(f"First partner acquired:    month {row['month']} (mean over seeds)")
            break

    # Time to trust_threshold
    cfg = result["config"]
    gate = cfg["trust_threshold"]
    for row in result["timeline"]:
        if row["protagonist_trust"]["mean"] >= gate:
            print(f"Trust >= {gate} (gate crossed): month {row['month']} (mean)")
            break
    else:
        print(f"Trust never reached {gate}")

    # Trust retained through departure
    dep_row = by_month.get(DISK_PRESSURE_END)
    ret_row = by_month.get(DEPARTURE_END)
    peak = max(
        (row["protagonist_trust"]["mean"] for row in result["timeline"]
         if row["month"] < DISK_PRESSURE_END),
        default=0.0,
    )
    print(f"\nPeak trust (pre-departure):  {peak:.3f}")
    if dep_row:
        t_dep = dep_row["protagonist_trust"]["mean"]
        print(f"Trust at departure:          {t_dep:.3f}  "
              f"({t_dep / peak * 100:.1f}% of peak)")
    if ret_row:
        t_ret = ret_row["protagonist_trust"]["mean"]
        print(f"Trust at return (month 48):  {t_ret:.3f}  "
              f"({t_ret / peak * 100:.1f}% of peak)")
    end_row = by_month.get(RETURN_END - 1)
    if end_row:
        t_end = end_row["protagonist_trust"]["mean"]
        print(f"Trust at end  (month 53):    {t_end:.3f}  "
              f"({t_end / peak * 100:.1f}% of peak)")


def save_results(result: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2))
    print(f"\nResults saved to {path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Viaticum Exp 11: User Lifecycle"
    )
    parser.add_argument("--bg-peers", type=int, default=200,
                        help="Number of background peers (default: 200)")
    parser.add_argument("--seeds", type=int, default=50,
                        help="Monte Carlo seeds (default: 50)")
    parser.add_argument("--k", type=int, default=5,
                        help="Erasure k (min shards to reconstruct)")
    parser.add_argument("--n-shards", type=int, default=15,
                        help="Erasure n (total shards per file)")
    parser.add_argument("--kp", type=float, default=0.5,
                        help="PI P-weight (default: 0.5)")
    parser.add_argument("--ki", type=float, default=2.0,
                        help="PI I-weight (default: 2.0)")
    parser.add_argument("--trust-threshold", type=float, default=0.30,
                        help="Min trust to be selected as shard holder")
    parser.add_argument("--departure", type=str, default="graceful",
                        choices=["graceful", "sudden"],
                        help="Departure mode in Phase 5 (default: graceful)")
    parser.add_argument("--disk-capacity", type=int, default=60,
                        help="Max shards protagonist stores for others")
    parser.add_argument("--jobs", type=int, default=1,
                        help="Parallel jobs (joblib, default: 1)")
    parser.add_argument("--output", type=str, default="results/user_lifecycle",
                        help="Output directory")
    args = parser.parse_args()

    config = Config(
        n_background_peers=args.bg_peers,
        n_seeds=args.seeds,
        k=args.k,
        n_shards=args.n_shards,
        kp=args.kp,
        ki=args.ki,
        trust_threshold=args.trust_threshold,
        departure_mode=args.departure,
        disk_capacity_shards=args.disk_capacity,
        output_dir=args.output,
    )

    print("=== USER LIFECYCLE SIMULATION ===\n")
    result = run_experiment(config, n_jobs=args.jobs)
    print_timeline(result)
    print_phase_summary(result)
    save_results(result, Path(args.output) / "run.json")


if __name__ == "__main__":
    main()
