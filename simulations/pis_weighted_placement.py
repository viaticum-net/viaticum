"""
Viaticum Experiment 26: Weighted Shard Placement

Tests whether concentrating shards on high-trust partners (core + insurance
layers) improves file survival over the current equal-weight placement.

Three configurations:
  EQUAL:    adaptive n + multiplicative S + no gate + escrow (Exp 25 FULL)
            shard placement = proportional to trust (current behavior)
  WEIGHTED: same as EQUAL but with weighted shard placement
            each partner gets n_i = round(n_total * w_i') shards
            w_i = p_i^alpha, alpha=2.0, p_i = clip(trust_i/MAX_TRUST, 0.1, 1.0)
  S2:       fixed n=15 + additive S (kp=0.3, ki=1.5, ks=0.3) + gate + escrow
            (Series 2 baseline, from Exp 25)

Scenarios:
  A: Baseline -- 10K nodes, 10 years, 25% churn, 6 archetypes + HitAndRun (15%)
  D: Free-rider flood -- 40% of arrivals are free-riders

New metrics:
  shard_concentration -- Gini coefficient of per-partner shard allocation
  shard_dist_* -- mean, std, max shards per partner

Usage:
    python pis_weighted_placement.py --scenario all --seeds 20 --jobs 24
    python pis_weighted_placement.py --scenario A --seeds 3 --jobs 4
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np
from joblib import Parallel, delayed
from scipy.stats import binom as binom_dist
from scipy.stats import kendalltau


# ---------------------------------------------------------------------------
# Archetype definitions (7 types including HitAndRun)
# ---------------------------------------------------------------------------

ARCHETYPE_NAMES = [
    "Reliable",    # rank 1 (most useful)
    "Weekend",     # rank 2
    "Seasonal",    # rank 3
    "Nomad",       # rank 4
    "Hoarder",     # rank 5 (high uptime, low storage contribution)
    "Freeloader",  # rank 6
    "HitAndRun",   # rank 7 (adversarial)
]
N_ARCHETYPES = len(ARCHETYPE_NAMES)

# Honest archetypes (0..5), HitAndRun = 6
N_HONEST_ARCHETYPES = 6

# Expected usefulness rank (lower = more useful, 1-indexed). HitAndRun excluded from tau.
ACTUAL_USEFULNESS_RANK = [1, 2, 3, 4, 5, 6]

# Storage offer ratio per archetype: gb_stored_for_others / gb_stored_by_others
# Pairwise S_AB = STORAGE_RATIOS[B] / max(STORAGE_RATIOS[A], _S_EPS)
STORAGE_RATIOS = np.array([1.0, 1.0, 1.0, 1.0, 0.2, 0.1, 0.0], dtype=np.float64)

# Archetype probabilities for baseline (can be overridden per scenario)
ARCHETYPE_PROBS_BASELINE = np.array([0.30, 0.20, 0.12, 0.08, 0.10, 0.05, 0.15])

# File size options for honest nodes; HitAndRun always gets FILE_SIZE_HAR
FILE_SIZES_HONEST = np.array([2.0, 10.0, 60.0])
FILE_SIZE_HAR = 10.0  # HitAndRun always targets 10 GB

# Archetype index constants
_IDX_HOARDER = 4
_IDX_FREELOADER = 5
_IDX_HAR = 6


# ---------------------------------------------------------------------------
# Trust formula constants
# ---------------------------------------------------------------------------

KP = 0.5
KI = 2.0
S_CLAMP_MIN = 0.1
S_CLAMP_MAX = 1.0
_S_EPS = 0.01

# Series-2-best additive S parameters (kp=0.3, ki=1.5, ks=0.3)
S2_KP = 0.3
S2_KI = 1.5
S2_KS = 0.3
S2_ACCEPTANCE_GATE_I = 0.3


# ---------------------------------------------------------------------------
# Erasure coding parameters
# ---------------------------------------------------------------------------

K = 5              # minimum shards for recovery
BASE_N = 15        # fixed n for Series-2 config
MAX_SHARD_SLOTS = 60  # must be >= max possible adaptive n
TARGET_SURVIVAL = 0.9999  # target for adaptive n binomial computation
ADAPTIVE_N_MAX = 50
ADAPTIVE_RECALC_INTERVAL = 4  # weeks between adaptive n recalculations

# Weighted placement parameters
WEIGHTED_ALPHA = 2.0          # w_i = p_i ^ alpha
MAX_SHARDS_PER_PARTNER = 6    # cap: single partner cannot hold more than this many shards


# ---------------------------------------------------------------------------
# Network parameters
# ---------------------------------------------------------------------------

MAX_NODES = 10_000
INITIAL_NODES = 200
ANNUAL_CHURN = 0.25
N_YEARS = 10
N_WEEKS = N_YEARS * 52
TARGET_PARTNERS = 15

# Escrow: minimum weeks-in-network per file-size tier
ESCROW_TIER1_WEEKS = 4    # file_size in (1, 5] GB
ESCROW_TIER2_WEEKS = 13   # file_size in (5, 50] GB
ESCROW_TIER3_WEEKS = 26   # file_size > 50 GB

# HitAndRun: leaves after this many total weeks without successful restore
HAR_PATIENCE_WEEKS = 4

# tau snapshot years
TAU_YEARS = [1, 3, 5, 7, 10]

# Max trust value for normalization in adaptive n (kp*1 + ki*1)*1.0 = 2.5
_MAX_TRUST = (KP + KI) * 1.0


# ---------------------------------------------------------------------------
# Precomputed adaptive n lookup table
# ---------------------------------------------------------------------------

def _build_adaptive_n_table() -> np.ndarray:
    """
    Precompute lookup table: avg_p_bucket -> minimum n.

    avg_p quantized into 100 buckets over [0.1, 1.0].
    Uses scipy.binom to find minimum n s.t. P(Binom(n, avg_p) >= K) >= TARGET_SURVIVAL.
    """
    n_buckets = 100
    p_values = np.linspace(0.1, 1.0, n_buckets)
    table = np.full(n_buckets, K * 5, dtype=np.int32)
    for i, avg_p in enumerate(p_values):
        for n in range(K, K * 10 + 1):
            if binom_dist.sf(K - 1, n, float(avg_p)) >= TARGET_SURVIVAL:
                table[i] = min(n, ADAPTIVE_N_MAX)
                break
    return table


_ADAPTIVE_N_TABLE = _build_adaptive_n_table()
_TABLE_P_MIN = 0.1
_TABLE_P_MAX = 1.0
_TABLE_N_BUCKETS = len(_ADAPTIVE_N_TABLE)


def compute_adaptive_n(partner_trusts: np.ndarray) -> int:
    """
    Minimum n s.t. P(Binom(n, avg_p) >= K) >= TARGET_SURVIVAL.

    avg_p = mean(clip(trust / MAX_TRUST, 0.1, 1.0))
    """
    if len(partner_trusts) == 0:
        return K * 3
    avg_p = float(np.mean(np.clip(partner_trusts / _MAX_TRUST, 0.1, 1.0)))
    idx = int(
        (avg_p - _TABLE_P_MIN) / (_TABLE_P_MAX - _TABLE_P_MIN)
        * (_TABLE_N_BUCKETS - 1)
        + 0.5
    )
    idx = max(0, min(idx, _TABLE_N_BUCKETS - 1))
    n = int(_ADAPTIVE_N_TABLE[idx])
    return min(n, ADAPTIVE_N_MAX)


# ---------------------------------------------------------------------------
# Trust formula helpers
# ---------------------------------------------------------------------------

def trust_full(
    p_b: float | np.ndarray,
    i_b: float | np.ndarray,
    s_ab: float | np.ndarray,
) -> float | np.ndarray:
    """Full model: trust = (KP*P + KI*I) * clamp(S, 0.1, 1.0)"""
    pi = KP * p_b + KI * i_b
    s_c = np.clip(s_ab, S_CLAMP_MIN, S_CLAMP_MAX)
    return pi * s_c


def trust_s2(
    p_b: float | np.ndarray,
    i_b: float | np.ndarray,
    s_ab: float | np.ndarray,
) -> float | np.ndarray:
    """Series-2: trust = S2_KP*P + S2_KI*I + S2_KS*S (additive)"""
    return S2_KP * p_b + S2_KI * i_b + S2_KS * s_ab


def pairwise_s(
    arch_observer: int | np.ndarray,
    arch_target: int | np.ndarray,
) -> float | np.ndarray:
    """S_AB = STORAGE_RATIOS[target] / max(STORAGE_RATIOS[observer], eps)"""
    r_obs = STORAGE_RATIOS[arch_observer]
    r_tgt = STORAGE_RATIOS[arch_target]
    return r_tgt / np.maximum(r_obs, _S_EPS)


# ---------------------------------------------------------------------------
# Escrow helpers
# ---------------------------------------------------------------------------

def can_restore(file_size_gb: float, weeks_in_network: int) -> bool:
    """Return True if the node has served enough time to restore its file."""
    if file_size_gb <= 1.0:
        return True
    if file_size_gb <= 5.0:
        return weeks_in_network >= ESCROW_TIER1_WEEKS
    if file_size_gb <= 50.0:
        return weeks_in_network >= ESCROW_TIER2_WEEKS
    return weeks_in_network >= ESCROW_TIER3_WEEKS


# ---------------------------------------------------------------------------
# Gini coefficient helper
# ---------------------------------------------------------------------------

def gini_coefficient(values: np.ndarray) -> float:
    """
    Gini coefficient of a non-negative array.
    Returns 0 for perfectly equal distribution, approaches 1 for maximal concentration.
    Formula: G = (2 * sum(i * x_i)) / (n * sum(x_i)) - (n+1)/n
    where x_i is sorted ascending and i is 1-indexed.
    """
    v = values.astype(np.float64)
    if v.sum() == 0.0 or len(v) <= 1:
        return 0.0
    v_sorted = np.sort(v)
    n = len(v_sorted)
    index = np.arange(1, n + 1, dtype=np.float64)
    return float(
        (2.0 * (index * v_sorted).sum()) / (n * v_sorted.sum()) - (n + 1.0) / n
    )


# ---------------------------------------------------------------------------
# Weekly pass probabilities per archetype
# ---------------------------------------------------------------------------

def _build_weekly_pass_probs(n_weeks: int) -> np.ndarray:
    """
    Precompute P(pass weekly check) per archetype per week.
    Shape: (N_ARCHETYPES, n_weeks).
    """
    week_idx = np.arange(n_weeks)
    week_in_year = week_idx % 52
    probs = np.zeros((N_ARCHETYPES, n_weeks), dtype=np.float64)

    # 0: Reliable -- 99% daily
    probs[0, :] = 1.0 - (1.0 - 0.99) ** 7

    # 1: Weekend -- 95% Fri-Sun, 30% Mon-Thu
    p_fail_we = (1.0 - 0.95) ** 3 * (1.0 - 0.30) ** 4
    probs[1, :] = 1.0 - p_fail_we

    # 2: Seasonal -- 95% non-summer, 20% summer (weeks 22-35)
    is_summer = (week_in_year >= 22) & (week_in_year <= 35)
    r_seasonal = np.where(is_summer, 0.20, 0.95)
    probs[2, :] = 1.0 - (1.0 - r_seasonal) ** 7

    # 3: Nomad -- 50% weekly availability
    probs[3, :] = 0.50

    # 4: Hoarder -- 90% daily
    probs[4, :] = 1.0 - (1.0 - 0.90) ** 7

    # 5: Freeloader -- 80% daily
    probs[5, :] = 1.0 - (1.0 - 0.80) ** 7

    # 6: HitAndRun -- 80% daily (motivated to stay online)
    probs[6, :] = 1.0 - (1.0 - 0.80) ** 7

    return probs


# ---------------------------------------------------------------------------
# Simulation configuration
# ---------------------------------------------------------------------------

@dataclass
class ModelConfig:
    """Which model variant to run."""
    label: str                         # "EQUAL", "WEIGHTED", or "S2"
    adaptive_n: bool                   # True = binomial adaptive n; False = fixed n=15
    multiplicative_s: bool             # True = full model; False = additive S2
    acceptance_gate: bool              # True = S2 gate (I < 0.3 -> newcomer pool)
    weighted_placement: bool = False   # True = concentrate shards on high-trust partners


EQUAL_MODEL = ModelConfig(
    label="EQUAL",
    adaptive_n=True,
    multiplicative_s=True,
    acceptance_gate=False,
    weighted_placement=False,
)

WEIGHTED_MODEL = ModelConfig(
    label="WEIGHTED",
    adaptive_n=True,
    multiplicative_s=True,
    acceptance_gate=False,
    weighted_placement=True,
)

S2_BEST = ModelConfig(
    label="S2",
    adaptive_n=False,
    multiplicative_s=False,
    acceptance_gate=True,
    weighted_placement=False,
)


@dataclass
class ScenarioParams:
    """Scenario-level parameters injected into simulate_one."""
    name: str                            # "A" or "D"

    # Network size / duration
    max_nodes: int = MAX_NODES
    n_weeks: int = N_WEEKS

    # Archetype probabilities (can be overridden for scenario D)
    archetype_probs: np.ndarray = field(
        default_factory=lambda: ARCHETYPE_PROBS_BASELINE.copy()
    )


# ---------------------------------------------------------------------------
# Core simulation
# ---------------------------------------------------------------------------

def simulate_one(
    model: ModelConfig,
    scenario: ScenarioParams,
    seed: int,
) -> dict:
    """
    Run one full simulation under the given model and scenario.

    Returns a dict with metrics keyed by year and overall attack metrics.
    """
    rng = np.random.default_rng(seed)

    # Capacity: a bit above max_nodes to handle transient spikes
    cap = scenario.max_nodes + 500
    n_weeks = scenario.n_weeks
    pw = 4  # P window: 4 weeks

    archetype = np.full(cap, -1, dtype=np.int8)
    alive = np.zeros(cap, dtype=bool)
    join_week = np.full(cap, -1, dtype=np.int32)

    p_buf = np.zeros((cap, pw), dtype=np.float64)
    p_buf_pos = np.zeros(cap, dtype=np.int32)
    p_buf_filled = np.zeros(cap, dtype=np.int32)
    i_sum = np.zeros(cap, dtype=np.float64)
    i_count = np.zeros(cap, dtype=np.int32)
    p_val = np.zeros(cap, dtype=np.float64)
    i_val = np.zeros(cap, dtype=np.float64)

    file_size = np.zeros(cap, dtype=np.float64)
    shards = np.full((cap, MAX_SHARD_SLOTS), -1, dtype=np.int32)
    shards_n = np.zeros(cap, dtype=np.int32)
    desired_n = np.full(cap, BASE_N, dtype=np.int32)
    file_alive = np.ones(cap, dtype=bool)

    har_total_weeks = np.zeros(cap, dtype=np.int32)
    har_succeeded = np.zeros(cap, dtype=bool)

    # Partnerships: set of partner IDs per node
    partners: list[set[int]] = [set() for _ in range(cap)]

    weekly_pass_probs = _build_weekly_pass_probs(n_weeks)
    weekly_churn = 1.0 - (1.0 - ANNUAL_CHURN) ** (1.0 / 52.0)

    # ID management
    next_id = 0
    free_ids: list[int] = []

    def _alloc() -> Optional[int]:
        nonlocal next_id
        if free_ids:
            return free_ids.pop()
        if next_id < cap:
            nid = next_id
            next_id += 1
            return nid
        return None

    def _pick_archetype() -> int:
        return int(rng.choice(N_ARCHETYPES, p=scenario.archetype_probs))

    def _pick_file_size(atype: int) -> float:
        if atype == _IDX_HAR:
            return FILE_SIZE_HAR
        return float(rng.choice(FILE_SIZES_HONEST))

    def _add_node(nid: int, week: int, atype: Optional[int] = None) -> None:
        if atype is None:
            atype = _pick_archetype()
        archetype[nid] = atype
        alive[nid] = True
        join_week[nid] = week
        p_buf[nid, :] = 0.0
        p_buf_pos[nid] = 0
        p_buf_filled[nid] = 0
        i_sum[nid] = 0.0
        i_count[nid] = 0
        p_val[nid] = 0.0
        i_val[nid] = 0.0
        file_size[nid] = _pick_file_size(atype)
        shards[nid, :] = -1
        shards_n[nid] = 0
        desired_n[nid] = BASE_N
        file_alive[nid] = True
        har_total_weeks[nid] = 0
        har_succeeded[nid] = False
        partners[nid] = set()

    def _remove_node(nid: int) -> None:
        alive[nid] = False
        for pid in partners[nid]:
            partners[pid].discard(nid)
        partners[nid].clear()
        free_ids.append(nid)

    def _node_trust_fn(
        p_b: float | np.ndarray,
        i_b: float | np.ndarray,
        s_ab: float | np.ndarray,
    ) -> float | np.ndarray:
        """Dispatch to the correct trust formula for this model."""
        if model.multiplicative_s:
            return trust_full(p_b, i_b, s_ab)
        return trust_s2(p_b, i_b, s_ab)

    def _compute_trust_and_p_arr(
        nid: int,
        candidate_arr: np.ndarray,
    ) -> tuple[np.ndarray, np.ndarray]:
        """
        Compute trust values and survival probabilities for candidate_arr
        from the perspective of nid.
        Returns (t_vals, p_arr) both shape (len(candidate_arr),).
        """
        a_nid = int(archetype[nid])
        r_nid = float(STORAGE_RATIOS[a_nid])
        r_cands = STORAGE_RATIOS[archetype[candidate_arr]]
        s_vals = np.clip(r_cands / max(r_nid, _S_EPS), S_CLAMP_MIN, S_CLAMP_MAX)
        t_vals = np.maximum(
            _node_trust_fn(p_val[candidate_arr], i_val[candidate_arr], s_vals), 0.01
        )
        p_arr = np.clip(t_vals / _MAX_TRUST, 0.1, 1.0)
        return t_vals, p_arr

    def _weighted_alloc(
        n_total: int,
        p_arr: np.ndarray,
        n_candidates: int,
    ) -> np.ndarray:
        """
        Compute shard allocation array of shape (n_candidates,) summing to n_total.
        Each slot i gets weight = p_arr[i] ^ WEIGHTED_ALPHA.
        Partners are already sorted by trust descending (caller's responsibility).
        No partner gets more than MAX_SHARDS_PER_PARTNER.
        """
        weights = p_arr ** WEIGHTED_ALPHA
        weights_sum = weights.sum()
        if weights_sum == 0.0:
            # Fallback: equal allocation
            alloc = np.full(n_candidates, n_total // n_candidates, dtype=np.int32)
            alloc[: n_total % n_candidates] += 1
            return alloc

        weights_norm = weights / weights_sum
        raw_alloc = n_total * weights_norm
        alloc = np.round(raw_alloc).astype(np.int32)

        # Enforce cap
        alloc = np.minimum(alloc, MAX_SHARDS_PER_PARTNER)

        # Adjust total to match n_total
        diff = n_total - int(alloc.sum())
        if diff > 0:
            # Add to highest-weight partners that are not yet at cap
            for i in range(n_candidates):
                if diff <= 0:
                    break
                if alloc[i] < MAX_SHARDS_PER_PARTNER:
                    alloc[i] += 1
                    diff -= 1
        elif diff < 0:
            # Remove from lowest-weight partners
            for i in range(n_candidates - 1, -1, -1):
                if diff >= 0:
                    break
                if alloc[i] > 0:
                    alloc[i] -= 1
                    diff += 1

        return alloc

    def _place_shards_initial(nid: int) -> None:
        """Initial shard placement from nid's partners."""
        dn = int(desired_n[nid])
        current_n = int(shards_n[nid])
        needed = dn - current_n
        if needed <= 0:
            return

        available = [h for h in partners[nid] if alive[h]]
        if not available:
            return

        arr = np.array(available, dtype=np.int32)

        if model.weighted_placement:
            _place_shards_weighted_initial(nid, arr, dn)
        else:
            # Equal placement: pick up to 'needed' new partners, one shard each
            current_holders = set(int(shards[nid, j]) for j in range(current_n))
            eligible = arr[~np.isin(arr, list(current_holders))]
            if eligible.size == 0:
                return
            n_pick = min(needed, eligible.size, MAX_SHARD_SLOTS - current_n)
            if n_pick <= 0:
                return
            if eligible.size <= n_pick:
                chosen = eligible
            else:
                t_vals, _ = _compute_trust_and_p_arr(nid, eligible)
                probs = t_vals / t_vals.sum()
                idxs = rng.choice(eligible.size, size=n_pick, replace=False, p=probs)
                chosen = eligible[idxs]
            pos = current_n
            for h in chosen:
                shards[nid, pos] = int(h)
                pos += 1
            shards_n[nid] = pos

    def _place_shards_weighted_initial(
        nid: int,
        partner_arr: np.ndarray,
        n_total: int,
    ) -> None:
        """
        Weighted initial placement: concentrate n_total shards on partners
        sorted by trust. Partners can hold multiple shards.
        Replaces the entire shard slate (called when shards_n == 0).
        """
        if partner_arr.size < K:
            return

        n_use = min(partner_arr.size, MAX_SHARD_SLOTS)
        t_vals, p_arr = _compute_trust_and_p_arr(nid, partner_arr)

        # Sort descending by trust
        order = np.argsort(-t_vals)
        sorted_partners = partner_arr[order[:n_use]]
        sorted_p = p_arr[order[:n_use]]

        n_total_capped = min(n_total, MAX_SHARD_SLOTS)
        alloc = _weighted_alloc(n_total_capped, sorted_p, len(sorted_partners))

        pos = 0
        for i in range(len(sorted_partners)):
            n_shards = int(alloc[i])
            if n_shards == 0:
                break  # array is sorted desc, no more shards to assign
            partner_id = int(sorted_partners[i])
            for _ in range(n_shards):
                if pos >= MAX_SHARD_SLOTS:
                    break
                shards[nid, pos] = partner_id
                pos += 1
            if pos >= MAX_SHARD_SLOTS:
                break
        shards_n[nid] = pos

    def _repair_shards(nid: int) -> None:
        """
        Remove dead holders, replace missing shards up to desired_n.
        No-op if file is irrecoverable (live < K).
        Dispatches to weighted or equal-weight variant.
        """
        dn = int(desired_n[nid])
        sn = int(shards_n[nid])

        # Compact dead holders
        kept = [
            int(shards[nid, j])
            for j in range(sn)
            if shards[nid, j] >= 0 and alive[shards[nid, j]]
        ]
        n_alive = len(kept)
        shards[nid, :n_alive] = kept
        shards[nid, n_alive:sn] = -1
        shards_n[nid] = n_alive

        if n_alive < K:
            # File lost or insufficient shards to repair from
            return

        n_lost = dn - n_alive
        if n_lost <= 0:
            return

        if model.weighted_placement:
            _repair_shards_weighted(nid, kept, n_lost, dn)
        else:
            _repair_shards_equal(nid, kept, n_lost)

    def _repair_shards_equal(
        nid: int,
        kept: list[int],
        n_lost: int,
    ) -> None:
        """Equal-weight repair: pick replacement partners uniformly by trust."""
        n_alive = len(kept)
        current_holders_set: set[int] = set(kept)
        current_holders_set.add(nid)

        active_arr = np.where(alive)[0]
        candidates_mask = ~np.isin(active_arr, list(current_holders_set))
        candidates = active_arr[candidates_mask]
        if candidates.size == 0:
            return

        n_pick = min(n_lost, candidates.size, MAX_SHARD_SLOTS - n_alive)
        if n_pick <= 0:
            return

        t_vals, _ = _compute_trust_and_p_arr(nid, candidates)
        probs = t_vals / t_vals.sum()
        new_holders = rng.choice(candidates, size=n_pick, replace=False, p=probs)

        pos = n_alive
        for h in new_holders:
            shards[nid, pos] = int(h)
            pos += 1
        shards_n[nid] = pos

    def _repair_shards_weighted(
        nid: int,
        kept: list[int],
        n_lost: int,
        desired: int,
    ) -> None:
        """
        Weighted repair: recompute allocation over all alive partners and
        redistribute so that partners with high trust get more shards.

        Strategy: compute desired allocation for all alive partners, then
        compare with current allocation (kept) and add/remove to converge.
        """
        n_alive = len(kept)

        # Build candidate set: alive partners + any kept holders still alive
        # (kept holders that left the partner set but remain alive should not lose shards)
        candidate_set: set[int] = set(p for p in partners[nid] if alive[p])
        candidate_set.update(h for h in kept if alive[h])
        candidate_set.discard(nid)
        if len(candidate_set) < K:
            return

        all_partners = np.array(sorted(candidate_set), dtype=np.int32)
        n_part = len(all_partners)

        t_vals, p_arr = _compute_trust_and_p_arr(nid, all_partners)

        # Sort descending by trust
        order = np.argsort(-t_vals)
        sorted_partners = all_partners[order]
        sorted_p = p_arr[order]

        n_total_target = min(desired, MAX_SHARD_SLOTS)
        n_use = min(n_part, MAX_SHARD_SLOTS)
        sorted_partners = sorted_partners[:n_use]
        sorted_p = sorted_p[:n_use]

        target_alloc = _weighted_alloc(n_total_target, sorted_p, len(sorted_partners))

        # Count current allocations per partner
        current_count: dict[int, int] = {}
        for h in kept:
            current_count[h] = current_count.get(h, 0) + 1

        # Build new shard list by filling to target allocation
        pos = 0
        for i in range(len(sorted_partners)):
            pid = int(sorted_partners[i])
            want = int(target_alloc[i])
            have = current_count.get(pid, 0)
            give = max(want, have)  # never remove live shards; only add
            give = min(give, MAX_SHARDS_PER_PARTNER, MAX_SHARD_SLOTS - pos)
            for _ in range(give):
                if pos >= MAX_SHARD_SLOTS:
                    break
                shards[nid, pos] = pid
                pos += 1
            if pos >= MAX_SHARD_SLOTS:
                break

        shards_n[nid] = pos

    def _update_partnerships(active_ids: np.ndarray) -> None:
        """
        Trust-weighted partnership formation for underfull nodes.
        Batched at 300/week to keep the sim fast.
        Full model: no gate. S2 model: acceptance gate (I < 0.3 -> newcomer pool).
        """
        on_count = np.array(
            [len(partners[int(nid)]) for nid in active_ids], dtype=np.int32
        )
        underfull_mask = on_count < TARGET_PARTNERS
        underfull = active_ids[underfull_mask]
        if underfull.size == 0:
            return
        if underfull.size > 300:
            underfull = rng.choice(underfull, size=300, replace=False)

        active_set = set(int(x) for x in active_ids)

        for pid in underfull:
            pid = int(pid)
            n_needed = TARGET_PARTNERS - len(partners[pid])
            if n_needed <= 0:
                continue

            existing = partners[pid]

            candidates = [
                c for c in active_set
                if c != pid
                and c not in existing
                and len(partners[c]) < TARGET_PARTNERS
            ]

            if model.acceptance_gate and float(i_val[pid]) < S2_ACCEPTANCE_GATE_I:
                gated = [c for c in candidates if float(i_val[c]) <= S2_ACCEPTANCE_GATE_I]
                if gated:
                    candidates = gated

            if not candidates:
                continue

            arr = np.array(candidates, dtype=np.int32)
            t_vals, _ = _compute_trust_and_p_arr(pid, arr)
            probs = t_vals / t_vals.sum()
            n_pick = min(n_needed, len(candidates))
            chosen = rng.choice(arr, size=n_pick, replace=False, p=probs)
            for cid in chosen:
                cid = int(cid)
                partners[pid].add(cid)
                partners[cid].add(pid)

    # -----------------------------------------------------------------------
    # Bootstrap
    # -----------------------------------------------------------------------

    for _ in range(INITIAL_NODES):
        nid = _alloc()
        if nid is not None:
            _add_node(nid, 0)

    # -----------------------------------------------------------------------
    # Metric tracking
    # -----------------------------------------------------------------------

    year_metrics: dict[int, dict] = {}

    har_total = 0
    har_success_count = 0

    overhead_samples: list[float] = []

    bootstrap_times: list[float] = []
    bootstrap_tracked: set[int] = set()
    bootstrap_done: set[int] = set()
    BOOTSTRAP_MAX_SAMPLES = 300

    # Shard concentration samples (per year-end snapshot)
    # List of Gini values across nodes with shards
    concentration_by_year: dict[int, list[float]] = {}

    # -----------------------------------------------------------------------
    # Main weekly loop
    # -----------------------------------------------------------------------
    for week in range(n_weeks):
        year = week // 52 + 1  # 1-indexed year for this week
        weeks_in_year = week % 52

        # ----- 1. Growth -----
        n_active = int(alive.sum())
        if n_active < scenario.max_nodes:
            if week < 52:
                n_new_target = 30
            elif week < 2 * 52:
                n_new_target = 80
            else:
                n_new_target = 50
            n_new = min(n_new_target, scenario.max_nodes - n_active)
            for _ in range(n_new):
                nid = _alloc()
                if nid is None:
                    break
                _add_node(nid, week)
                atype = int(archetype[nid])
                if atype == _IDX_HAR:
                    har_total += 1
                if week > 0 and atype < _IDX_HAR and len(bootstrap_tracked) < BOOTSTRAP_MAX_SAMPLES:
                    bootstrap_tracked.add(nid)

        # ----- 2. Churn (natural, skip HitAndRun -- they self-manage) -----
        active_ids = np.where(alive)[0]
        if active_ids.size > 0:
            har_mask = archetype[active_ids] == _IDX_HAR
            non_har = active_ids[~har_mask]
            if non_har.size > 0:
                churn_mask = rng.random(non_har.size) < weekly_churn
                for nid in non_har[churn_mask]:
                    _remove_node(int(nid))

        # ----- 3. Weekly check scores -----
        active_ids = np.where(alive)[0]
        if active_ids.size == 0:
            continue

        active_arch = archetype[active_ids]
        week_scores = np.zeros(active_ids.size, dtype=np.float64)

        for atype_idx in range(N_ARCHETYPES):
            grp = np.where(active_arch == atype_idx)[0]
            if grp.size == 0:
                continue
            p_w = float(weekly_pass_probs[atype_idx, week % (N_YEARS * 52)])
            week_scores[grp] = (rng.random(grp.size) < p_w).astype(np.float64)

        # ----- 4. Update P circular buffer -----
        pos = p_buf_pos[active_ids]
        p_buf[active_ids, pos] = week_scores
        p_buf_pos[active_ids] = (pos + 1) % pw
        filled = p_buf_filled[active_ids]
        p_buf_filled[active_ids] = np.minimum(filled + 1, pw)

        # ----- 5. Update I -----
        i_sum[active_ids] += week_scores
        i_count[active_ids] += 1

        # ----- 6. Recompute P and I arrays -----
        p_buf_sum = p_buf[active_ids, :].sum(axis=1)
        pf = p_buf_filled[active_ids].astype(np.float64)
        p_val[active_ids] = np.where(pf > 0, p_buf_sum / pf, 0.0)

        ic = i_count[active_ids].astype(np.float64)
        i_val[active_ids] = np.where(ic > 0, i_sum[active_ids] / ic, 0.0)

        # ----- 7. Partnership formation -----
        _update_partnerships(active_ids)

        # ----- 8. Adaptive n recalculation (every 4 weeks) -----
        if model.adaptive_n and week % ADAPTIVE_RECALC_INTERVAL == 0:
            MAX_PART_SAMPLE = 10
            for nid in active_ids:
                nid = int(nid)
                part_list = list(partners[nid])
                if not part_list:
                    desired_n[nid] = K * 3
                    continue
                if len(part_list) > MAX_PART_SAMPLE:
                    idxs = rng.choice(len(part_list), MAX_PART_SAMPLE, replace=False)
                    sample = [part_list[i] for i in idxs]
                else:
                    sample = part_list
                arr = np.array(sample, dtype=np.int32)
                arr = arr[alive[arr]]
                if len(arr) == 0:
                    desired_n[nid] = K * 3
                    continue
                a_nid = int(archetype[nid])
                r_nid = float(STORAGE_RATIOS[a_nid])
                r_cands = STORAGE_RATIOS[archetype[arr]]
                s_vals = np.clip(r_cands / max(r_nid, _S_EPS), S_CLAMP_MIN, S_CLAMP_MAX)
                t_vals = np.maximum(
                    _node_trust_fn(p_val[arr], i_val[arr], s_vals), 0.0
                )
                desired_n[nid] = compute_adaptive_n(t_vals)

        # ----- 9. Shard placement for nodes without shards -----
        for nid in active_ids:
            nid = int(nid)
            if int(shards_n[nid]) == 0 and len(partners[nid]) >= K:
                _place_shards_initial(nid)

        # ----- 10. Weekly repair (sample 10% of active nodes) -----
        if active_ids.size > 0:
            repair_count = max(1, active_ids.size // 10)
            repair_sample = rng.choice(
                active_ids,
                size=min(repair_count, active_ids.size),
                replace=False,
            )
            for nid in repair_sample:
                nid = int(nid)
                if file_alive[nid]:
                    _repair_shards(nid)

        # ----- 11. File loss detection -----
        sn = shards_n[active_ids]
        has_shards = sn > 0
        if has_shards.any():
            nodes_with_shards = active_ids[has_shards]
            for nid in nodes_with_shards:
                nid = int(nid)
                n_s = int(shards_n[nid])
                live = sum(
                    1 for j in range(n_s)
                    if shards[nid, j] >= 0 and alive[shards[nid, j]]
                )
                if live < K and file_alive[nid]:
                    file_alive[nid] = False

        # ----- 12. Bootstrap tracking -----
        for nid in list(bootstrap_tracked - bootstrap_done):
            if not alive[nid]:
                bootstrap_done.add(nid)
                continue
            n_s = int(shards_n[nid])
            live = sum(
                1 for j in range(n_s)
                if shards[nid, j] >= 0 and alive[shards[nid, j]]
            )
            if live >= K:
                weeks_since_join = week - int(join_week[nid])
                fsz = float(file_size[nid])
                if can_restore(fsz, weeks_since_join):
                    bootstrap_times.append(float(weeks_since_join))
                    bootstrap_done.add(nid)

        # ----- 13. HitAndRun logic -----
        har_ids = active_ids[archetype[active_ids] == _IDX_HAR]
        to_remove_har: list[int] = []
        for nid in har_ids:
            nid = int(nid)
            if har_succeeded[nid]:
                to_remove_har.append(nid)
                continue
            har_total_weeks[nid] += 1
            weeks_in_net = int(har_total_weeks[nid])
            fsz = float(file_size[nid])
            n_s = int(shards_n[nid])
            live = sum(
                1 for j in range(n_s)
                if shards[nid, j] >= 0 and alive[shards[nid, j]]
            )
            if live >= K and can_restore(fsz, weeks_in_net):
                har_succeeded[nid] = True
                har_success_count += 1
                to_remove_har.append(nid)
            elif har_total_weeks[nid] >= HAR_PATIENCE_WEEKS:
                to_remove_har.append(nid)
        for nid in to_remove_har:
            if alive[nid]:
                _remove_node(nid)

        # ----- 14. Storage overhead sample -----
        if active_ids.size > 0:
            sample_n = min(100, active_ids.size)
            sample_ids = rng.choice(active_ids, size=sample_n, replace=False)
            honest_sample = sample_ids[archetype[sample_ids] < _IDX_HAR]
            if honest_sample.size > 0:
                mean_sn = float(shards_n[honest_sample].mean())
                overhead_samples.append(mean_sn / K)

        # ----- 15. Year-end snapshots -----
        is_year_end = (week + 1) % 52 == 0
        snap_year = (week + 1) // 52
        if is_year_end and snap_year in TAU_YEARS:
            active_ids_snap = np.where(alive)[0]
            honest_snap = active_ids_snap[
                archetype[active_ids_snap] < _IDX_HAR
            ]

            # File survival
            if honest_snap.size > 0:
                survival = float(file_alive[honest_snap].mean())
            else:
                survival = float("nan")

            # Kendall's tau
            tau_val = _compute_tau(
                active_ids_snap, archetype, p_val, i_val,
                partners, model,
            )

            # Free-rider file survival (scenario D)
            honest_survival = float("nan")
            freerider_survival = float("nan")
            if honest_snap.size > 0:
                honest_mask = archetype[honest_snap] < _IDX_FREELOADER
                fr_mask = archetype[honest_snap] == _IDX_FREELOADER
                if honest_mask.any():
                    honest_survival = float(file_alive[honest_snap[honest_mask]].mean())
                if fr_mask.any():
                    freerider_survival = float(file_alive[honest_snap[fr_mask]].mean())

            # Shard concentration: Gini coefficient per node, then mean
            gini_vals: list[float] = []
            if model.weighted_placement and honest_snap.size > 0:
                sample_nodes = honest_snap
                if sample_nodes.size > 200:
                    sample_nodes = rng.choice(sample_nodes, size=200, replace=False)
                for nid in sample_nodes:
                    nid = int(nid)
                    n_s = int(shards_n[nid])
                    if n_s < K:
                        continue
                    # Count shards per partner
                    from collections import Counter
                    holder_counts = Counter(
                        int(shards[nid, j]) for j in range(n_s) if shards[nid, j] >= 0
                    )
                    if len(holder_counts) < 2:
                        continue
                    counts_arr = np.array(list(holder_counts.values()), dtype=np.float64)
                    gini_vals.append(gini_coefficient(counts_arr))
            elif not model.weighted_placement and honest_snap.size > 0:
                # Equal model: all 1 shard per partner -> Gini = 0 by definition
                # Still measure to confirm
                sample_nodes = honest_snap
                if sample_nodes.size > 200:
                    sample_nodes = rng.choice(sample_nodes, size=200, replace=False)
                for nid in sample_nodes:
                    nid = int(nid)
                    n_s = int(shards_n[nid])
                    if n_s < K:
                        continue
                    from collections import Counter
                    holder_counts = Counter(
                        int(shards[nid, j]) for j in range(n_s) if shards[nid, j] >= 0
                    )
                    if len(holder_counts) < 2:
                        continue
                    counts_arr = np.array(list(holder_counts.values()), dtype=np.float64)
                    gini_vals.append(gini_coefficient(counts_arr))

            mean_gini = float(np.mean(gini_vals)) if gini_vals else 0.0
            concentration_by_year[snap_year] = gini_vals

            # Per-partner shard count distribution
            shard_dist = _compute_shard_dist(honest_snap, shards, shards_n)

            year_metrics[snap_year] = {
                "year": snap_year,
                "file_survival": survival,
                "kendall_tau": tau_val,
                "n_active": int(honest_snap.size),
                "honest_survival": honest_survival,
                "freerider_survival": freerider_survival,
                "shard_concentration_gini": mean_gini,
                "shard_dist_mean": shard_dist["mean"],
                "shard_dist_std": shard_dist["std"],
                "shard_dist_max": shard_dist["max"],
            }

    # -----------------------------------------------------------------------
    # Post-simulation aggregation
    # -----------------------------------------------------------------------

    har_success_rate = har_success_count / max(har_total, 1)
    mean_overhead = float(np.mean(overhead_samples)) if overhead_samples else float("nan")
    mean_bootstrap = float(np.mean(bootstrap_times)) if bootstrap_times else float("nan")

    return {
        "year_metrics": year_metrics,
        "har_success_rate": har_success_rate,
        "har_total": har_total,
        "mean_overhead": mean_overhead,
        "mean_bootstrap_weeks": mean_bootstrap,
        "seed": seed,
    }


def _compute_shard_dist(
    honest_snap: np.ndarray,
    shards: np.ndarray,
    shards_n: np.ndarray,
) -> dict:
    """
    Compute per-partner shard count distribution across sampled honest nodes.
    Returns dict with mean, std, max of per-partner shard counts.
    """
    from collections import Counter
    all_counts: list[int] = []
    sample = honest_snap
    if sample.size > 500:
        # Use the first 500 to avoid slow path
        sample = sample[:500]
    for nid in sample:
        nid = int(nid)
        n_s = int(shards_n[nid])
        if n_s == 0:
            continue
        holder_counts = Counter(
            int(shards[nid, j]) for j in range(n_s) if shards[nid, j] >= 0
        )
        all_counts.extend(holder_counts.values())
    if not all_counts:
        return {"mean": float("nan"), "std": float("nan"), "max": float("nan")}
    arr = np.array(all_counts, dtype=np.float64)
    return {
        "mean": float(arr.mean()),
        "std": float(arr.std()),
        "max": float(arr.max()),
    }


def _compute_tau(
    active_ids: np.ndarray,
    archetype: np.ndarray,
    p_val: np.ndarray,
    i_val: np.ndarray,
    partners: list[set[int]],
    model: ModelConfig,
) -> float:
    """
    Compute Kendall's tau between observed archetype trust ranking
    and expected usefulness ranking (honest archetypes 0..5 only).
    """
    active_set = set(int(x) for x in active_ids)
    arch_trust_sum = np.zeros(N_HONEST_ARCHETYPES, dtype=np.float64)
    arch_trust_count = np.zeros(N_HONEST_ARCHETYPES, dtype=np.int32)

    for target_arch in range(N_HONEST_ARCHETYPES):
        target_nodes = active_ids[archetype[active_ids] == target_arch]
        if target_nodes.size == 0:
            continue
        r_b = float(STORAGE_RATIOS[target_arch])
        for b in target_nodes:
            b = int(b)
            p_b = float(p_val[b])
            i_b = float(i_val[b])
            for a in partners[b]:
                if a not in active_set:
                    continue
                a_arch = int(archetype[a])
                if a_arch >= N_HONEST_ARCHETYPES:
                    continue
                r_a = float(STORAGE_RATIOS[a_arch])
                s_ab = r_b / max(r_a, _S_EPS)
                if model.multiplicative_s:
                    t = float(trust_full(p_b, i_b, s_ab))
                else:
                    t = float(trust_s2(p_b, i_b, s_ab))
                arch_trust_sum[target_arch] += t
                arch_trust_count[target_arch] += 1

    arch_trust = np.where(
        arch_trust_count > 0,
        arch_trust_sum / np.maximum(arch_trust_count, 1),
        0.0,
    )

    expected = -np.array(ACTUAL_USEFULNESS_RANK, dtype=float)
    tau, _ = kendalltau(arch_trust, expected)
    return float(tau) if not np.isnan(tau) else 0.0


# ---------------------------------------------------------------------------
# Multi-seed runner
# ---------------------------------------------------------------------------

def run_scenario_model(
    model: ModelConfig,
    scenario: ScenarioParams,
    n_seeds: int,
    n_jobs: int,
) -> dict:
    """Run Monte Carlo for one (model, scenario) pair and aggregate results."""
    seeds = list(range(n_seeds))

    if n_jobs == 1 or n_seeds == 1:
        runs = [simulate_one(model, scenario, s) for s in seeds]
    else:
        runs = Parallel(n_jobs=n_jobs)(
            delayed(simulate_one)(model, scenario, s) for s in seeds
        )

    # Aggregate year metrics
    all_years: dict[int, list[dict]] = {}
    for run in runs:
        for yr, ym in run["year_metrics"].items():
            all_years.setdefault(yr, []).append(ym)

    def _mean_key(snaps: list[dict], key: str) -> float:
        vals = [s[key] for s in snaps if key in s and not (
            isinstance(s[key], float) and np.isnan(s[key])
        )]
        return float(np.mean(vals)) if vals else float("nan")

    agg_years: dict[int, dict] = {}
    for yr in sorted(all_years.keys()):
        snaps = all_years[yr]
        agg_years[yr] = {
            "year": yr,
            "file_survival": _mean_key(snaps, "file_survival"),
            "kendall_tau": _mean_key(snaps, "kendall_tau"),
            "n_active": int(np.mean([s["n_active"] for s in snaps])),
            "honest_survival": _mean_key(snaps, "honest_survival"),
            "freerider_survival": _mean_key(snaps, "freerider_survival"),
            "shard_concentration_gini": _mean_key(snaps, "shard_concentration_gini"),
            "shard_dist_mean": _mean_key(snaps, "shard_dist_mean"),
            "shard_dist_std": _mean_key(snaps, "shard_dist_std"),
            "shard_dist_max": _mean_key(snaps, "shard_dist_max"),
        }

    har_rates = [r["har_success_rate"] for r in runs]
    overheads = [r["mean_overhead"] for r in runs if not np.isnan(r["mean_overhead"])]
    bootstraps = [r["mean_bootstrap_weeks"] for r in runs if not np.isnan(r["mean_bootstrap_weeks"])]

    return {
        "model": model.label,
        "scenario": scenario.name,
        "year_metrics": agg_years,
        "har_success_rate": float(np.mean(har_rates)),
        "har_success_rate_std": float(np.std(har_rates)),
        "mean_overhead": float(np.mean(overheads)) if overheads else float("nan"),
        "mean_bootstrap_weeks": float(np.mean(bootstraps)) if bootstraps else float("nan"),
        "n_seeds": n_seeds,
    }


# ---------------------------------------------------------------------------
# Scenario builders
# ---------------------------------------------------------------------------

def _make_scenario_a() -> ScenarioParams:
    """Baseline: no attacks, 6 archetypes + 15% HitAndRun."""
    return ScenarioParams(name="A")


def _make_scenario_d() -> ScenarioParams:
    """Free-rider flood: 40% of new arrivals are free-riders."""
    scale = 0.45 / 0.80
    honest_probs = np.array([0.30, 0.20, 0.12, 0.08, 0.10]) * scale
    new_probs = np.concatenate([honest_probs, [0.40, 0.15]])
    new_probs = new_probs / new_probs.sum()
    return ScenarioParams(name="D", archetype_probs=new_probs)


SCENARIO_BUILDERS = {
    "A": _make_scenario_a,
    "D": _make_scenario_d,
}


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def _fmt(v: float, pct: bool = False, decimals: int = 2, width: int = 8) -> str:
    if np.isnan(v):
        return " " * (width - 3) + "n/a"
    if pct:
        return f"{v * 100:{width}.{decimals}f}%"
    return f"{v:{width}.{decimals}f}"


def print_scenario_results(
    scenario_name: str,
    scenario_desc: str,
    equal_result: dict,
    weighted_result: dict,
    s2_result: dict,
) -> None:
    print(f"\n{'=' * 78}")
    print(f"SCENARIO {scenario_name}: {scenario_desc}")
    print(f"{'=' * 78}")

    # Year-by-year survival and tau table
    print(
        f"\n{'Year':<6} {'EQUAL surv':>12} {'WEIGHTED surv':>14} {'S2 surv':>9} "
        f"{'EQUAL tau':>10} {'WGT tau':>9}"
    )
    print("-" * 62)
    for yr in TAU_YEARS:
        em = equal_result["year_metrics"].get(yr, {})
        wm = weighted_result["year_metrics"].get(yr, {})
        sm = s2_result["year_metrics"].get(yr, {})
        e_surv = em.get("file_survival", float("nan"))
        w_surv = wm.get("file_survival", float("nan"))
        s_surv = sm.get("file_survival", float("nan"))
        e_tau = em.get("kendall_tau", float("nan"))
        w_tau = wm.get("kendall_tau", float("nan"))
        print(
            f"  {yr:<4d} {_fmt(e_surv, pct=True):>12} {_fmt(w_surv, pct=True):>14} "
            f"{_fmt(s_surv, pct=True):>9} "
            f"{_fmt(e_tau, pct=False):>10} {_fmt(w_tau, pct=False):>9}"
        )

    # Scalar metrics
    print()
    metrics = [
        ("HitAndRun success",      "har_success_rate",      True),
        ("Storage overhead (n/k)", "mean_overhead",         False),
        ("Bootstrap time (weeks)", "mean_bootstrap_weeks",  False),
    ]
    for label, key, is_pct in metrics:
        ev = equal_result.get(key, float("nan"))
        wv = weighted_result.get(key, float("nan"))
        sv = s2_result.get(key, float("nan"))
        print(
            f"  {label:<30} EQUAL={_fmt(ev, pct=is_pct)} "
            f"WEIGHTED={_fmt(wv, pct=is_pct)} S2={_fmt(sv, pct=is_pct)}"
        )

    # Shard concentration (year 10)
    print()
    print("  Shard concentration (Gini, year 10):")
    em10 = equal_result["year_metrics"].get(10, {})
    wm10 = weighted_result["year_metrics"].get(10, {})
    e_gini = em10.get("shard_concentration_gini", float("nan"))
    w_gini = wm10.get("shard_concentration_gini", float("nan"))
    e_dmean = em10.get("shard_dist_mean", float("nan"))
    w_dmean = wm10.get("shard_dist_mean", float("nan"))
    e_dmax = em10.get("shard_dist_max", float("nan"))
    w_dmax = wm10.get("shard_dist_max", float("nan"))
    print(
        f"    EQUAL:    Gini={_fmt(e_gini).strip()}, "
        f"mean_spc={_fmt(e_dmean).strip()}, max_spc={_fmt(e_dmax).strip()}"
    )
    print(
        f"    WEIGHTED: Gini={_fmt(w_gini).strip()}, "
        f"mean_spc={_fmt(w_dmean).strip()}, max_spc={_fmt(w_dmax).strip()}"
    )

    # Scenario D extras
    if scenario_name == "D":
        print()
        print("  Free-rider flood (year 10):")
        sm10 = s2_result["year_metrics"].get(10, {})
        e_hon = em10.get("honest_survival", float("nan"))
        e_fr = em10.get("freerider_survival", float("nan"))
        w_hon = wm10.get("honest_survival", float("nan"))
        w_fr = wm10.get("freerider_survival", float("nan"))
        s_hon = sm10.get("honest_survival", float("nan"))
        s_fr = sm10.get("freerider_survival", float("nan"))
        print(f"    Honest surv:     EQUAL={_fmt(e_hon, pct=True)} WEIGHTED={_fmt(w_hon, pct=True)} S2={_fmt(s_hon, pct=True)}")
        print(f"    Freeloader surv: EQUAL={_fmt(e_fr, pct=True)} WEIGHTED={_fmt(w_fr, pct=True)} S2={_fmt(s_fr, pct=True)}")


def print_summary_table(all_results: dict[str, dict[str, dict]]) -> None:
    """Print a compact summary across all scenarios."""
    print(f"\n{'=' * 78}")
    print("SUMMARY: EQUAL vs WEIGHTED vs S2 (year 10 file survival)")
    print(f"{'=' * 78}")
    print(
        f"{'Scenario':<12} {'EQUAL surv%':>12} {'WGT surv%':>10} {'S2 surv%':>10} "
        f"{'EQ tau':>8} {'WGT tau':>8} {'WGT Gini':>10}"
    )
    print("-" * 72)

    scenario_descs = {
        "A": "Baseline",
        "D": "Free-rider flood",
    }

    for sc in ["A", "D"]:
        if sc not in all_results:
            continue
        er = all_results[sc].get("EQUAL", {})
        wr = all_results[sc].get("WEIGHTED", {})
        sr = all_results[sc].get("S2", {})
        em10 = er.get("year_metrics", {}).get(10, {})
        wm10 = wr.get("year_metrics", {}).get(10, {})
        sm10 = sr.get("year_metrics", {}).get(10, {})
        e_surv = em10.get("file_survival", float("nan"))
        w_surv = wm10.get("file_survival", float("nan"))
        s_surv = sm10.get("file_survival", float("nan"))
        e_tau = em10.get("kendall_tau", float("nan"))
        w_tau = wm10.get("kendall_tau", float("nan"))
        w_gini = wm10.get("shard_concentration_gini", float("nan"))
        desc = scenario_descs.get(sc, sc)
        print(
            f"  {sc} {desc:<11} "
            f"{_fmt(e_surv, pct=True, decimals=1):>12} "
            f"{_fmt(w_surv, pct=True, decimals=1):>10} "
            f"{_fmt(s_surv, pct=True, decimals=1):>10} "
            f"{_fmt(e_tau, pct=False, decimals=3):>8} "
            f"{_fmt(w_tau, pct=False, decimals=3):>8} "
            f"{_fmt(w_gini, pct=False, decimals=3):>10}"
        )


# ---------------------------------------------------------------------------
# JSON serialization
# ---------------------------------------------------------------------------

def _convert(obj: object) -> object:
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.floating):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    if isinstance(obj, dict):
        return {str(k): _convert(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_convert(v) for v in obj]
    return obj


def save_results(
    all_results: dict[str, dict[str, dict]],
    n_seeds: int,
    output_dir: Path,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "pis_weighted_placement_results.json"

    payload = {
        "experiment": 26,
        "description": "Weighted Shard Placement: concentrated vs equal-weight placement",
        "equal_model": {
            "trust": "multiplicative_S: (0.5*P + 2.0*I) * clamp(S, 0.1, 1.0)",
            "n": "adaptive (binomial lookup, TARGET_SURVIVAL=0.9999)",
            "gate": "none",
            "escrow": "ON (T1=4wk, T2=13wk, T3=26wk)",
            "placement": "proportional to trust (one shard per partner)",
        },
        "weighted_model": {
            "trust": "same as EQUAL",
            "n": "same as EQUAL (adaptive)",
            "gate": "none",
            "escrow": "ON",
            "placement": f"w_i = p_i^{WEIGHTED_ALPHA}, deterministic concentration, cap={MAX_SHARDS_PER_PARTNER}",
        },
        "s2_model": {
            "trust": "additive_S: 0.3*P + 1.5*I + 0.3*S",
            "n": "fixed 15",
            "gate": "I < 0.3",
            "escrow": "ON",
            "placement": "equal-weight",
        },
        "network": {
            "max_nodes": MAX_NODES,
            "n_years": N_YEARS,
            "annual_churn": ANNUAL_CHURN,
            "k": K,
        },
        "scenarios": ["A (baseline)", "D (free-rider flood)"],
        "n_seeds": n_seeds,
        "results": _convert(all_results),
    }

    path.write_text(json.dumps(payload, indent=2))
    print(f"\nResults saved to {path}", flush=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_scenarios(arg: str) -> list[str]:
    if arg.lower() == "all":
        return list(SCENARIO_BUILDERS.keys())
    parts = [p.strip().upper() for p in arg.split(",")]
    unknown = [p for p in parts if p not in SCENARIO_BUILDERS]
    if unknown:
        raise ValueError(f"Unknown scenarios: {unknown}. Valid: {list(SCENARIO_BUILDERS)}")
    return parts


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Viaticum Experiment 26: Weighted Shard Placement"
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default="all",
        help="Scenario(s) to run: A|D|all or comma-separated (default: all)",
    )
    parser.add_argument(
        "--seeds",
        type=int,
        default=20,
        help="Monte Carlo seeds per (scenario, model) pair (default: 20)",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=24,
        help="Parallel jobs (default: 24, for remote server)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="results/pis_weighted_placement",
        help="Output directory for JSON results",
    )
    args = parser.parse_args()

    try:
        scenarios_to_run = _parse_scenarios(args.scenario)
    except ValueError as e:
        print(f"Error: {e}")
        return

    print("=== VIATICUM EXPERIMENT 26: WEIGHTED SHARD PLACEMENT ===", flush=True)
    print(f"Scenarios: {scenarios_to_run}", flush=True)
    print(
        f"Network: {MAX_NODES} nodes, {N_YEARS} years ({N_WEEKS} weeks), "
        f"25% annual churn",
        flush=True,
    )
    print("EQUAL:    proportional-to-trust placement (one shard per partner)", flush=True)
    print(
        f"WEIGHTED: concentrated placement (w=p^{WEIGHTED_ALPHA}, cap={MAX_SHARDS_PER_PARTNER} shards/partner)",
        flush=True,
    )
    print("S2:       additive S (0.3/1.5/0.3) + fixed n=15 + gate + escrow", flush=True)
    print(f"Seeds: {args.seeds}, Jobs: {args.jobs}", flush=True)
    print(flush=True)

    scenario_descs = {
        "A": "Baseline (no attacks)",
        "D": "Free-rider flood (40% of arrivals)",
    }

    all_results: dict[str, dict[str, dict]] = {}
    t_total = time.time()

    for sc_name in scenarios_to_run:
        scenario = SCENARIO_BUILDERS[sc_name]()
        desc = scenario_descs.get(sc_name, sc_name)
        all_results[sc_name] = {}

        for model in [EQUAL_MODEL, WEIGHTED_MODEL, S2_BEST]:
            print(
                f"Running Scenario {sc_name} [{desc}] -- {model.label} model ...",
                flush=True,
            )
            t0 = time.time()
            result = run_scenario_model(model, scenario, args.seeds, args.jobs)
            elapsed = time.time() - t0
            all_results[sc_name][model.label] = result

            ym10 = result["year_metrics"].get(10, {})
            surv10 = ym10.get("file_survival", float("nan"))
            tau10 = ym10.get("kendall_tau", float("nan"))
            gini10 = ym10.get("shard_concentration_gini", float("nan"))
            print(
                f"  Done in {elapsed:.1f}s | "
                f"year10 survival={_fmt(surv10, pct=True).strip()} "
                f"tau={_fmt(tau10).strip()} "
                f"overhead={_fmt(result['mean_overhead']).strip()}x "
                f"HAR={_fmt(result['har_success_rate'], pct=True).strip()} "
                f"gini={_fmt(gini10).strip()}",
                flush=True,
            )

        if all(m in all_results[sc_name] for m in ["EQUAL", "WEIGHTED", "S2"]):
            print_scenario_results(
                sc_name,
                desc,
                all_results[sc_name]["EQUAL"],
                all_results[sc_name]["WEIGHTED"],
                all_results[sc_name]["S2"],
            )

    print(f"\nTotal runtime: {time.time() - t_total:.1f}s", flush=True)

    if len(scenarios_to_run) > 1:
        print_summary_table(all_results)

    save_results(all_results, args.seeds, Path(args.output))


if __name__ == "__main__":
    main()
