"""
SyncBack Experiment 25: Full Model Integration

Acceptance test combining ALL best configurations from Experiments 21-24:
  - Multiplicative S: trust = (kp*P + ki*I) * clamp(S, 0.1, 1.0), kp=0.5, ki=2.0
  - Pairwise S: S_AB = STORAGE_RATIOS[B] / max(STORAGE_RATIOS[A], 0.01)
  - Adaptive n: n = f(avg_partner_trust) via binomial lookup table (Exp 21)
  - No acceptance gate: any peer gets shards immediately
  - No eviction: partnerships end only through churn (Exp 23)
  - Escrow: restore gated by weeks_in_network (T1=4wk, T2=13wk, T3=26wk)

Five scenarios:
  A: Baseline -- 10K nodes, 10 years, 25% churn, 6 archetypes + HitAndRun (15%)
  B: Sybil -- 200 sybils appear at year 2, fake storage (S=0.1), 10 subnets
  C: Mass departure -- 30% simultaneous departure shock at year 5
  D: Free-rider flood -- 40% of arrivals are free-riders
  E: Spite attack -- 50 colluding attackers target one file, wait 3 years

Each scenario runs two configurations:
  FULL: adaptive n + multiplicative S + no gate + escrow  (Exp 21-24 winner)
  S2:   fixed n=15 + additive S (kp=0.3, ki=1.5, ks=0.3) + gate + escrow  (Series 2 best)

Usage:
    python pis_integration.py --scenario all --seeds 20 --jobs 24
    python pis_integration.py --scenario A --seeds 3 --jobs 4    # quick test
    python pis_integration.py --scenario B,C --seeds 5 --jobs 8
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
# (copied from pis_adaptive_n.py, self-contained)
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
    label: str                    # "FULL" or "S2"
    adaptive_n: bool              # True = binomial adaptive n; False = fixed n=15
    multiplicative_s: bool        # True = full model; False = additive S2
    acceptance_gate: bool         # True = S2 gate (I < 0.3 → newcomer pool)


FULL_MODEL = ModelConfig(
    label="FULL",
    adaptive_n=True,
    multiplicative_s=True,
    acceptance_gate=False,
)

S2_BEST = ModelConfig(
    label="S2",
    adaptive_n=False,
    multiplicative_s=False,
    acceptance_gate=True,
)


@dataclass
class ScenarioParams:
    """Scenario-level parameters injected into simulate_one."""
    name: str                            # "A".."E"

    # Network size / duration
    max_nodes: int = MAX_NODES
    n_weeks: int = N_WEEKS

    # Archetype probabilities (can be overridden for scenario D)
    archetype_probs: np.ndarray = field(
        default_factory=lambda: ARCHETYPE_PROBS_BASELINE.copy()
    )

    # Sybil attack (scenario B)
    sybil_on: bool = False
    n_sybils: int = 200
    n_sybil_subnets: int = 10
    sybil_start_year: int = 2

    # Mass departure shock (scenario C)
    mass_departure_on: bool = False
    mass_departure_year: int = 5
    mass_departure_fraction: float = 0.30

    # Spite attack (scenario E)
    spite_on: bool = False
    n_spite_attackers: int = 50
    spite_wait_years: int = 3


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

    Per-node state arrays (pre-allocated to max_nodes + overhead):
      archetype[i]          -- archetype index 0..6, -1 = inactive
      alive[i]              -- currently active
      join_week[i]          -- week node joined
      p_buf[i, :pw]         -- circular buffer for P (last 4 weeks of binary scores)
      p_buf_pos[i]          -- next write position
      p_buf_filled[i]       -- filled slots (capped at pw)
      i_sum[i]              -- cumulative sum of weekly scores
      i_count[i]            -- weeks counted
      p_val[i]              -- current P (mean of circular buffer)
      i_val[i]              -- current I (cumulative mean)
      file_size[i]          -- file size in GB
      shards[i, :SLOTS]     -- partner IDs holding shards (-1 = empty)
      shards_n[i]           -- number of occupied shard slots
      desired_n[i]          -- target shard count (adaptive or fixed)
      file_alive[i]         -- True if file still recoverable
      is_sybil[i]           -- True for sybil nodes (scenario B)
      is_spite[i]           -- True for spite attackers (scenario E)
      har_total_weeks[i]    -- weeks alive as HitAndRun
      har_succeeded[i]      -- did this HAR node restore?

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

    is_sybil = np.zeros(cap, dtype=bool)
    is_spite = np.zeros(cap, dtype=bool)

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
        is_sybil[nid] = False
        is_spite[nid] = False
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

    def _place_shards_initial(nid: int) -> None:
        """Initial shard placement from nid's partners."""
        dn = int(desired_n[nid])
        current_n = int(shards_n[nid])
        needed = dn - current_n
        if needed <= 0:
            return

        current_holders = set(int(shards[nid, j]) for j in range(current_n))
        available = [
            h for h in partners[nid]
            if h not in current_holders and alive[h]
        ]
        if not available:
            return

        n_pick = min(needed, len(available), MAX_SHARD_SLOTS - current_n)
        if n_pick <= 0:
            return

        a_nid = int(archetype[nid])
        r_nid = float(STORAGE_RATIOS[a_nid])

        if len(available) <= n_pick:
            chosen = list(available)
        else:
            arr = np.array(available, dtype=np.int32)
            r_cands = STORAGE_RATIOS[archetype[arr]]
            s_vals = np.clip(r_cands / max(r_nid, _S_EPS), S_CLAMP_MIN, S_CLAMP_MAX)
            t_vals = np.maximum(
                _node_trust_fn(p_val[arr], i_val[arr], s_vals), 0.01
            )
            probs = t_vals / t_vals.sum()
            idxs = rng.choice(len(available), size=n_pick, replace=False, p=probs)
            chosen = [available[int(i)] for i in idxs]

        pos = current_n
        for h in chosen:
            shards[nid, pos] = h
            pos += 1
        shards_n[nid] = pos

    def _repair_shards(nid: int) -> None:
        """
        Remove dead holders, replace missing shards up to desired_n.
        No-op if file is irrecoverable (live < K).
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

        a_nid = int(archetype[nid])
        r_nid = float(STORAGE_RATIOS[a_nid])
        r_cands = STORAGE_RATIOS[archetype[candidates]]
        s_vals = np.clip(r_cands / max(r_nid, _S_EPS), S_CLAMP_MIN, S_CLAMP_MAX)
        t_vals = np.maximum(
            _node_trust_fn(p_val[candidates], i_val[candidates], s_vals), 0.01
        )
        probs = t_vals / t_vals.sum()
        new_holders = rng.choice(candidates, size=n_pick, replace=False, p=probs)

        pos = n_alive
        for h in new_holders:
            shards[nid, pos] = int(h)
            pos += 1
        shards_n[nid] = pos

    def _update_partnerships(active_ids: np.ndarray) -> None:
        """
        Trust-weighted partnership formation for underfull nodes.
        Batched at 300/week to keep the sim fast.
        Full model: no gate. S2 model: acceptance gate (I < 0.3 → newcomer pool).
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

            a_pid = int(archetype[pid])
            r_pid = float(STORAGE_RATIOS[a_pid])
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
            r_cands = STORAGE_RATIOS[archetype[arr]]
            s_vals = np.clip(r_cands / max(r_pid, _S_EPS), S_CLAMP_MIN, S_CLAMP_MAX)
            t_vals = np.maximum(
                _node_trust_fn(p_val[arr], i_val[arr], s_vals), 0.01
            )
            probs = t_vals / t_vals.sum()
            n_pick = min(n_needed, len(candidates))
            chosen = rng.choice(arr, size=n_pick, replace=False, p=probs)
            for cid in chosen:
                cid = int(cid)
                partners[pid].add(cid)
                partners[cid].add(pid)

    # -----------------------------------------------------------------------
    # Scenario-specific setup
    # -----------------------------------------------------------------------

    # Spite: choose a target file once the network has been running for spite_wait_years
    spite_target_node: int = -1
    spite_attackers: list[int] = []

    # Sybil: track denial rate against a "target file" owned by one honest node
    sybil_target_node: int = -1
    sybil_denial_weeks: int = 0
    sybil_check_weeks: int = 0

    # Bootstrap
    for _ in range(INITIAL_NODES):
        nid = _alloc()
        if nid is not None:
            _add_node(nid, 0)

    # -----------------------------------------------------------------------
    # Metric tracking
    # -----------------------------------------------------------------------

    # Per-year snapshots at TAU_YEARS
    year_metrics: dict[int, dict] = {}

    # HitAndRun stats
    har_total = 0
    har_success_count = 0

    # Storage overhead samples (weekly)
    overhead_samples: list[float] = []

    # Bootstrap time: weeks from join until first K live shards (honest newcomers)
    bootstrap_times: list[float] = []
    bootstrap_tracked: set[int] = set()   # nodes we are tracking
    bootstrap_done: set[int] = set()
    BOOTSTRAP_MAX_SAMPLES = 300

    # Mass departure recovery tracking (scenario C)
    mass_departure_done = False
    post_shock_survival: dict[int, float] = {}  # year -> survival rate after shock

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
                # Register bootstrap candidates (honest, joined after week 0)
                if week > 0 and atype < _IDX_HAR and len(bootstrap_tracked) < BOOTSTRAP_MAX_SAMPLES:
                    bootstrap_tracked.add(nid)

        # ----- 2. Sybil injection (scenario B) -----
        if scenario.sybil_on and year == scenario.sybil_start_year and weeks_in_year == 0 and not is_sybil.any():
            n_per_subnet = scenario.n_sybils // scenario.n_sybil_subnets
            for _ in range(scenario.n_sybils):
                nid = _alloc()
                if nid is None:
                    break
                # Sybil: freeloader archetype (low storage), starts with good P/I appearance
                _add_node(nid, week, atype=_IDX_FREELOADER)
                is_sybil[nid] = True
                # Override storage ratio perspective: sybils fake full storage
                # The punishment: their actual S as seen by others is S=0.1 (freeloader)
                # They cannot actually hold shards reliably (they churn fast)

            # Choose an honest node as the sybil "denial target"
            honest_ids = np.where(alive & ~is_sybil)[0]
            if len(honest_ids) > 0:
                sybil_target_node = int(rng.choice(honest_ids))

        # ----- 3. Churn (natural, skip HitAndRun -- they self-manage) -----
        active_ids = np.where(alive)[0]
        if active_ids.size > 0:
            har_mask = archetype[active_ids] == _IDX_HAR
            non_har = active_ids[~har_mask]
            if non_har.size > 0:
                churn_mask = rng.random(non_har.size) < weekly_churn
                for nid in non_har[churn_mask]:
                    _remove_node(int(nid))

        # Sybil fast churn: sybils leave after 4 weeks (they have no long-term intent)
        if scenario.sybil_on:
            sybil_ids = np.where(alive & is_sybil)[0]
            for nid in sybil_ids:
                weeks_alive = week - int(join_week[nid])
                if weeks_alive >= 4 and rng.random() < 0.5:
                    _remove_node(int(nid))

        # ----- 4. Mass departure shock (scenario C) -----
        if (
            scenario.mass_departure_on
            and year == scenario.mass_departure_year
            and weeks_in_year == 0
            and not mass_departure_done
        ):
            mass_departure_done = True
            active_ids_snap = np.where(alive)[0]
            # Exclude HitAndRun and sybils from the shock cohort
            honest_ids_snap = active_ids_snap[
                (archetype[active_ids_snap] < _IDX_HAR) & ~is_sybil[active_ids_snap]
            ]
            n_depart = int(len(honest_ids_snap) * scenario.mass_departure_fraction)
            if n_depart > 0:
                departing = rng.choice(honest_ids_snap, size=n_depart, replace=False)
                for nid in departing:
                    _remove_node(int(nid))
            print(
                f"  [seed={seed}] Mass departure at week {week}: "
                f"{n_depart}/{len(honest_ids_snap)} nodes left",
                flush=True,
            )

        # ----- 5. Weekly check scores -----
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

        # ----- 6. Update P circular buffer -----
        pos = p_buf_pos[active_ids]
        p_buf[active_ids, pos] = week_scores
        p_buf_pos[active_ids] = (pos + 1) % pw
        filled = p_buf_filled[active_ids]
        p_buf_filled[active_ids] = np.minimum(filled + 1, pw)

        # ----- 7. Update I -----
        i_sum[active_ids] += week_scores
        i_count[active_ids] += 1

        # ----- 8. Recompute P and I arrays -----
        p_buf_sum = p_buf[active_ids, :].sum(axis=1)
        pf = p_buf_filled[active_ids].astype(np.float64)
        p_val[active_ids] = np.where(pf > 0, p_buf_sum / pf, 0.0)

        ic = i_count[active_ids].astype(np.float64)
        i_val[active_ids] = np.where(ic > 0, i_sum[active_ids] / ic, 0.0)

        # ----- 9. Partnership formation -----
        _update_partnerships(active_ids)

        # ----- 10. Adaptive n recalculation (every 4 weeks) -----
        if model.adaptive_n and week % ADAPTIVE_RECALC_INTERVAL == 0:
            MAX_PART_SAMPLE = 10
            for nid in active_ids:
                nid = int(nid)
                part_list = list(partners[nid])
                if not part_list:
                    desired_n[nid] = K * 3
                    continue
                a_nid = int(archetype[nid])
                r_nid = float(STORAGE_RATIOS[a_nid])
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
                r_cands = STORAGE_RATIOS[archetype[arr]]
                s_vals = np.clip(r_cands / max(r_nid, _S_EPS), S_CLAMP_MIN, S_CLAMP_MAX)
                t_vals = np.maximum(
                    _node_trust_fn(p_val[arr], i_val[arr], s_vals), 0.0
                )
                desired_n[nid] = compute_adaptive_n(t_vals)

        # ----- 11. Shard placement for nodes without shards -----
        for nid in active_ids:
            nid = int(nid)
            if int(shards_n[nid]) == 0 and len(partners[nid]) >= K:
                _place_shards_initial(nid)

        # ----- 12. Weekly repair (sample 10% of active nodes) -----
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

        # ----- 13. File loss detection (vectorized) -----
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

        # ----- 14. Bootstrap tracking -----
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
                # For FULL model (escrow on), effective bootstrap includes escrow wait
                fsz = float(file_size[nid])
                if can_restore(fsz, weeks_since_join):
                    bootstrap_times.append(float(weeks_since_join))
                    bootstrap_done.add(nid)

        # ----- 15. HitAndRun logic -----
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

        # ----- 16. Spite attack setup (scenario E) -----
        if (
            scenario.spite_on
            and spite_target_node < 0
            and year > scenario.spite_wait_years
        ):
            # Choose a target and inject spite attackers who will try to flood
            # the target's shard holders to deny restore
            honest_ids = np.where(alive & (archetype < _IDX_HAR) & ~is_spite)[0]
            if honest_ids.size > 0:
                spite_target_node = int(rng.choice(honest_ids))
                # Add spite attackers as Freeloader archetype (they're online but don't store)
                for _ in range(scenario.n_spite_attackers):
                    anid = _alloc()
                    if anid is None:
                        break
                    _add_node(anid, week, atype=_IDX_FREELOADER)
                    is_spite[anid] = True
                    spite_attackers.append(anid)
                print(
                    f"  [seed={seed}] Spite attack: target={spite_target_node}, "
                    f"attackers={len(spite_attackers)} at week {week}",
                    flush=True,
                )

        # Spite attackers try to hold the target file's shards and refuse to serve
        # In this model: spite attackers are in the network, taking up partnership slots
        # from the target node, but with trust ~0 (freeloader archetype gets low trust)
        if scenario.spite_on and spite_target_node >= 0 and alive[spite_target_node]:
            sybil_check_weeks += 1
            n_s = int(shards_n[spite_target_node])
            live = sum(
                1 for j in range(n_s)
                if shards[spite_target_node, j] >= 0
                and alive[shards[spite_target_node, j]]
                and not is_spite[shards[spite_target_node, j]]
            )
            if live < K:
                sybil_denial_weeks += 1

        # Sybil: check if target file is accessible (sybil denial rate)
        if scenario.sybil_on and sybil_target_node >= 0 and alive[sybil_target_node]:
            sybil_check_weeks += 1
            n_s = int(shards_n[sybil_target_node])
            # Denial: not enough non-sybil live shards
            live_honest = sum(
                1 for j in range(n_s)
                if shards[sybil_target_node, j] >= 0
                and alive[shards[sybil_target_node, j]]
                and not is_sybil[shards[sybil_target_node, j]]
            )
            if live_honest < K:
                sybil_denial_weeks += 1

        # ----- 17. Storage overhead sample -----
        if active_ids.size > 0:
            sample_n = min(100, active_ids.size)
            sample_ids = rng.choice(active_ids, size=sample_n, replace=False)
            honest_sample = sample_ids[archetype[sample_ids] < _IDX_HAR]
            if honest_sample.size > 0:
                mean_sn = float(shards_n[honest_sample].mean())
                overhead_samples.append(mean_sn / K)

        # ----- 18. Year-end snapshots -----
        is_year_end = (week + 1) % 52 == 0
        snap_year = (week + 1) // 52
        if is_year_end and snap_year in TAU_YEARS:
            active_ids_snap = np.where(alive)[0]
            honest_snap = active_ids_snap[
                (archetype[active_ids_snap] < _IDX_HAR)
                & ~is_sybil[active_ids_snap]
                & ~is_spite[active_ids_snap]
            ]

            # File survival
            if honest_snap.size > 0:
                survival = float(file_alive[honest_snap].mean())
            else:
                survival = float("nan")

            # Kendall's tau: trust ranking vs expected usefulness ranking
            tau_val = _compute_tau(
                snap_year, active_ids_snap, archetype, p_val, i_val,
                partners, is_sybil, is_spite, model,
            )

            # Free-rider file survival (scenario D): compare honest vs freeloader
            honest_survival = float("nan")
            freerider_survival = float("nan")
            if honest_snap.size > 0:
                honest_mask = archetype[honest_snap] < _IDX_FREELOADER
                fr_mask = archetype[honest_snap] == _IDX_FREELOADER
                if honest_mask.any():
                    honest_survival = float(file_alive[honest_snap[honest_mask]].mean())
                if fr_mask.any():
                    freerider_survival = float(file_alive[honest_snap[fr_mask]].mean())

            year_metrics[snap_year] = {
                "year": snap_year,
                "file_survival": survival,
                "kendall_tau": tau_val,
                "n_active": int(honest_snap.size),
                "honest_survival": honest_survival,
                "freerider_survival": freerider_survival,
            }

    # -----------------------------------------------------------------------
    # Post-simulation aggregation
    # -----------------------------------------------------------------------

    har_success_rate = har_success_count / max(har_total, 1)
    mean_overhead = float(np.mean(overhead_samples)) if overhead_samples else float("nan")
    mean_bootstrap = float(np.mean(bootstrap_times)) if bootstrap_times else float("nan")
    denial_rate = sybil_denial_weeks / max(sybil_check_weeks, 1)

    return {
        "year_metrics": year_metrics,
        "har_success_rate": har_success_rate,
        "har_total": har_total,
        "mean_overhead": mean_overhead,
        "mean_bootstrap_weeks": mean_bootstrap,
        "denial_rate": denial_rate,  # sybil or spite denial rate
        "seed": seed,
    }


def _compute_tau(
    year: int,
    active_ids: np.ndarray,
    archetype: np.ndarray,
    p_val: np.ndarray,
    i_val: np.ndarray,
    partners: list[set[int]],
    is_sybil: np.ndarray,
    is_spite: np.ndarray,
    model: ModelConfig,
) -> float:
    """
    Compute Kendall's tau between observed archetype trust ranking
    and expected usefulness ranking (honest archetypes 0..5 only).

    Mean incoming trust per archetype = average trust that honest partners
    assign to nodes of that archetype.
    """
    active_set = set(int(x) for x in active_ids)
    arch_trust_sum = np.zeros(N_HONEST_ARCHETYPES, dtype=np.float64)
    arch_trust_count = np.zeros(N_HONEST_ARCHETYPES, dtype=np.int32)

    for target_arch in range(N_HONEST_ARCHETYPES):
        target_nodes = active_ids[
            (archetype[active_ids] == target_arch)
            & ~is_sybil[active_ids]
            & ~is_spite[active_ids]
        ]
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
                if a_arch >= N_HONEST_ARCHETYPES or is_sybil[a] or is_spite[a]:
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
        }

    # Aggregate scalar metrics
    har_rates = [r["har_success_rate"] for r in runs]
    overheads = [r["mean_overhead"] for r in runs if not np.isnan(r["mean_overhead"])]
    bootstraps = [r["mean_bootstrap_weeks"] for r in runs if not np.isnan(r["mean_bootstrap_weeks"])]
    denials = [r["denial_rate"] for r in runs]

    return {
        "model": model.label,
        "scenario": scenario.name,
        "year_metrics": agg_years,
        "har_success_rate": float(np.mean(har_rates)),
        "har_success_rate_std": float(np.std(har_rates)),
        "mean_overhead": float(np.mean(overheads)) if overheads else float("nan"),
        "mean_bootstrap_weeks": float(np.mean(bootstraps)) if bootstraps else float("nan"),
        "denial_rate": float(np.mean(denials)),
        "denial_rate_std": float(np.std(denials)),
        "n_seeds": n_seeds,
    }


# ---------------------------------------------------------------------------
# Scenario builders
# ---------------------------------------------------------------------------

def _make_scenario_a() -> ScenarioParams:
    """Baseline: no attacks, 6 archetypes + 15% HitAndRun."""
    return ScenarioParams(name="A")


def _make_scenario_b() -> ScenarioParams:
    """Sybil: 200 sybil nodes appear at year 2, 10 subnets."""
    return ScenarioParams(
        name="B",
        sybil_on=True,
        n_sybils=200,
        n_sybil_subnets=10,
        sybil_start_year=2,
    )


def _make_scenario_c() -> ScenarioParams:
    """Mass departure: 30% of nodes leave simultaneously at year 5."""
    return ScenarioParams(
        name="C",
        mass_departure_on=True,
        mass_departure_year=5,
        mass_departure_fraction=0.30,
    )


def _make_scenario_d() -> ScenarioParams:
    """Free-rider flood: 40% of new arrivals are free-riders."""
    # Override archetype probs: collapse HAR share, inflate Freeloader to 40%
    # Original baseline: [0.30, 0.20, 0.12, 0.08, 0.10, 0.05, 0.15] -> sum=1.0
    # New: Freeloader=0.40, reduce others proportionally (keep HAR=0.15)
    # Honest pool (indices 0..4): was 0.80 total -> reduce to 0.45 total
    # Scale [0.30, 0.20, 0.12, 0.08, 0.10] by (0.45/0.80):
    scale = 0.45 / 0.80
    honest_probs = np.array([0.30, 0.20, 0.12, 0.08, 0.10]) * scale
    new_probs = np.concatenate([honest_probs, [0.40, 0.15]])
    new_probs = new_probs / new_probs.sum()  # normalize to exactly 1.0
    return ScenarioParams(name="D", archetype_probs=new_probs)


def _make_scenario_e() -> ScenarioParams:
    """Spite attack: 50 colluding attackers target one file, wait 3 years."""
    return ScenarioParams(
        name="E",
        spite_on=True,
        n_spite_attackers=50,
        spite_wait_years=3,
    )


SCENARIO_BUILDERS = {
    "A": _make_scenario_a,
    "B": _make_scenario_b,
    "C": _make_scenario_c,
    "D": _make_scenario_d,
    "E": _make_scenario_e,
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
    full_result: dict,
    s2_result: dict,
) -> None:
    print(f"\n{'=' * 70}")
    print(f"SCENARIO {scenario_name}: {scenario_desc}")
    print(f"{'=' * 70}")

    # Year-by-year survival and tau table
    print(f"\n{'Year':<6} {'FULL surv':>10} {'S2 surv':>10} {'FULL tau':>10} {'S2 tau':>9}")
    print("-" * 48)
    for yr in TAU_YEARS:
        fm = full_result["year_metrics"].get(yr, {})
        sm = s2_result["year_metrics"].get(yr, {})
        f_surv = fm.get("file_survival", float("nan"))
        s_surv = sm.get("file_survival", float("nan"))
        f_tau = fm.get("kendall_tau", float("nan"))
        s_tau = sm.get("kendall_tau", float("nan"))
        print(
            f"  {yr:<4d} {_fmt(f_surv, pct=True):>10} {_fmt(s_surv, pct=True):>10} "
            f"{_fmt(f_tau, pct=False):>10} {_fmt(s_tau, pct=False):>9}"
        )

    # Scalar metrics
    print()
    metrics = [
        ("HitAndRun success", "har_success_rate", True),
        ("Storage overhead (n/k)", "mean_overhead", False),
        ("Bootstrap time (weeks)", "mean_bootstrap_weeks", False),
        ("Denial rate", "denial_rate", True),
    ]
    for label, key, is_pct in metrics:
        fv = full_result.get(key, float("nan"))
        sv = s2_result.get(key, float("nan"))
        print(f"  {label:<30} FULL={_fmt(fv, pct=is_pct)} | S2={_fmt(sv, pct=is_pct)}")

    # Scenario-specific extras
    if scenario_name == "D":
        print()
        print("  Free-rider flood (year 10):")
        fm10 = full_result["year_metrics"].get(10, {})
        sm10 = s2_result["year_metrics"].get(10, {})
        f_hon = fm10.get("honest_survival", float("nan"))
        f_fr = fm10.get("freerider_survival", float("nan"))
        s_hon = sm10.get("honest_survival", float("nan"))
        s_fr = sm10.get("freerider_survival", float("nan"))
        print(f"    Honest survival:     FULL={_fmt(f_hon, pct=True)} | S2={_fmt(s_hon, pct=True)}")
        print(f"    Freeloader survival: FULL={_fmt(f_fr, pct=True)} | S2={_fmt(s_fr, pct=True)}")


def print_summary_table(all_results: dict[str, dict[str, dict]]) -> None:
    """Print a compact summary across all scenarios."""
    print(f"\n{'=' * 70}")
    print("SUMMARY: FULL MODEL vs SERIES-2 BEST (year 10 file survival)")
    print(f"{'=' * 70}")
    print(f"{'Scenario':<12} {'FULL surv%':>11} {'S2 surv%':>11} {'FULL tau':>10} {'S2 tau':>9} {'FULL HAR%':>10} {'S2 HAR%':>9}")
    print("-" * 74)

    scenario_descs = {
        "A": "Baseline",
        "B": "Sybil attack",
        "C": "Mass departure",
        "D": "Free-rider flood",
        "E": "Spite attack",
    }

    for sc in ["A", "B", "C", "D", "E"]:
        if sc not in all_results:
            continue
        fr = all_results[sc].get("FULL", {})
        sr = all_results[sc].get("S2", {})
        fm10 = fr.get("year_metrics", {}).get(10, {})
        sm10 = sr.get("year_metrics", {}).get(10, {})
        f_surv = fm10.get("file_survival", float("nan"))
        s_surv = sm10.get("file_survival", float("nan"))
        f_tau = fm10.get("kendall_tau", float("nan"))
        s_tau = sm10.get("kendall_tau", float("nan"))
        f_har = fr.get("har_success_rate", float("nan"))
        s_har = sr.get("har_success_rate", float("nan"))
        desc = scenario_descs.get(sc, sc)
        print(
            f"  {sc} {desc:<11} "
            f"{_fmt(f_surv, pct=True, decimals=1):>11} "
            f"{_fmt(s_surv, pct=True, decimals=1):>11} "
            f"{_fmt(f_tau, pct=False, decimals=3):>10} "
            f"{_fmt(s_tau, pct=False, decimals=3):>9} "
            f"{_fmt(f_har, pct=True, decimals=1):>10} "
            f"{_fmt(s_har, pct=True, decimals=1):>9}"
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
    path = output_dir / "pis_integration_results.json"

    payload = {
        "experiment": 25,
        "description": "Full Model Integration: acceptance test for Exp 21-24 combined",
        "full_model": {
            "trust": "multiplicative_S: (0.5*P + 2.0*I) * clamp(S, 0.1, 1.0)",
            "n": "adaptive (binomial lookup, TARGET_SURVIVAL=0.9999)",
            "gate": "none",
            "eviction": "none",
            "escrow": "ON (T1=4wk, T2=13wk, T3=26wk)",
        },
        "s2_best": {
            "trust": "additive_S: 0.3*P + 1.5*I + 0.3*S",
            "n": "fixed 15",
            "gate": "I < 0.3",
            "eviction": "none",
            "escrow": "ON",
        },
        "network": {
            "max_nodes": MAX_NODES,
            "n_years": N_YEARS,
            "annual_churn": ANNUAL_CHURN,
            "k": K,
        },
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
        description="SyncBack Experiment 25: Full Model Integration"
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default="all",
        help="Scenario(s) to run: A|B|C|D|E|all or comma-separated (default: all)",
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
        default="results/pis_integration",
        help="Output directory for JSON results",
    )
    args = parser.parse_args()

    try:
        scenarios_to_run = _parse_scenarios(args.scenario)
    except ValueError as e:
        print(f"Error: {e}")
        return

    print("=== SYNCBACK EXPERIMENT 25: FULL MODEL INTEGRATION ===", flush=True)
    print(f"Scenarios: {scenarios_to_run}", flush=True)
    print(
        f"Network: {MAX_NODES} nodes, {N_YEARS} years ({N_WEEKS} weeks), "
        f"25% annual churn",
        flush=True,
    )
    print("FULL: multiplicative S + adaptive n + no gate + escrow", flush=True)
    print("S2:   additive S (0.3/1.5/0.3) + fixed n=15 + gate + escrow", flush=True)
    print(f"Seeds: {args.seeds}, Jobs: {args.jobs}", flush=True)
    print(flush=True)

    scenario_descs = {
        "A": "Baseline (no attacks)",
        "B": "Sybil attack (200 sybils, year 2)",
        "C": "Mass departure (30% shock at year 5)",
        "D": "Free-rider flood (40% of arrivals)",
        "E": "Spite attack (50 colluding, 3yr wait)",
    }

    all_results: dict[str, dict[str, dict]] = {}
    t_total = time.time()

    for sc_name in scenarios_to_run:
        scenario = SCENARIO_BUILDERS[sc_name]()
        desc = scenario_descs.get(sc_name, sc_name)
        all_results[sc_name] = {}

        for model in [FULL_MODEL, S2_BEST]:
            print(
                f"Running Scenario {sc_name} [{desc}] — {model.label} model ...",
                flush=True,
            )
            t0 = time.time()
            result = run_scenario_model(model, scenario, args.seeds, args.jobs)
            elapsed = time.time() - t0
            all_results[sc_name][model.label] = result

            # Quick inline summary
            ym10 = result["year_metrics"].get(10, {})
            surv10 = ym10.get("file_survival", float("nan"))
            tau10 = ym10.get("kendall_tau", float("nan"))
            print(
                f"  Done in {elapsed:.1f}s | "
                f"year10 survival={_fmt(surv10, pct=True).strip()} "
                f"tau={_fmt(tau10).strip()} "
                f"overhead={_fmt(result['mean_overhead']).strip()}x "
                f"HAR={_fmt(result['har_success_rate'], pct=True).strip()}",
                flush=True,
            )

        # Per-scenario comparison table
        if "FULL" in all_results[sc_name] and "S2" in all_results[sc_name]:
            print_scenario_results(
                sc_name,
                desc,
                all_results[sc_name]["FULL"],
                all_results[sc_name]["S2"],
            )

    print(f"\nTotal runtime: {time.time() - t_total:.1f}s", flush=True)

    if len(scenarios_to_run) > 1:
        print_summary_table(all_results)

    save_results(all_results, args.seeds, Path(args.output))


if __name__ == "__main__":
    main()
