"""
Viaticum Experiment 21: Adaptive Shard Count

Question: Does adapting the erasure coding shard count (n in k-of-n) based on
partner trust levels improve file survival rates while reducing storage overhead,
compared to a fixed n=15 policy?

Scenarios compared:
  1. Fixed n=15, acceptance gate ON  (current model baseline)
  2. Fixed n=15, acceptance gate OFF  (newcomers get shards immediately)
  3. Adaptive n, acceptance gate OFF  (n tracks partner trust, newcomers included)
  4. Adaptive n, acceptance gate ON   (belt and suspenders)

Trust formula (multiplicative S):
  trust_AB = (kp * P_B + ki * I_B) * clamp(S_AB, 0.1, 1.0)
  S_AB = STORAGE_RATIOS[B] / max(STORAGE_RATIOS[A], 0.01)
  kp=0.5, ki=2.0

File survival model:
  - 1 abstract file per node, k=5 required shards
  - Shards tracked via compact shard matrix (cap x MAX_SHARD_SLOTS)
  - Each week: shard survives iff holder alive AND passed weekly check
  - File lost when live shard count < k
  - Repair: live < desired_n and live >= k -> repair completes in 2 weeks

Metrics per scenario (years 1, 3, 5):
  - File survival rate
  - Mean storage overhead (actual n / k)
  - Bootstrap time: weeks until newcomer first has >= k live shards
  - Wasted storage: shards on churned partners / total shards ever placed

Usage:
    python pis_adaptive_n.py --seeds 10 --jobs 6
    python pis_adaptive_n.py --seeds 2 --jobs 2   # quick test
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np
from joblib import Parallel, delayed
from scipy.stats import binom


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ARCHETYPE_NAMES = ["Reliable", "Weekend", "Seasonal", "Nomad", "Hoarder", "Freeloader"]
ARCHETYPE_PROBS = np.array([0.35, 0.25, 0.15, 0.10, 0.10, 0.05])
STORAGE_RATIOS = np.array([1.0, 1.0, 1.0, 1.0, 0.2, 0.1], dtype=np.float64)
N_ARCHETYPES = len(ARCHETYPE_NAMES)

K_SHARDS = 5           # minimum shards for recovery
FIXED_N = 15           # fixed redundancy target
MAX_SHARD_SLOTS = 52   # must be >= max possible adaptive n (K*10+1=51)
MAX_TRUST = 2.5        # (kp*1 + ki*1) * 1.0 = 2.5
KP = 0.5
KI = 2.0
TARGET_SURVIVAL = 0.9999  # binomial reliability target for adaptive n
REPAIR_DELAY_WEEKS = 2
ADAPTIVE_RECALC_INTERVAL = 4  # weeks between desired_n recalculations
TARGET_PARTNERS = FIXED_N    # partnership pool target (same for all scenarios)

_INITIAL_PEERS = 50
_MAX_ACTIVE = 2_000    # 2K nodes: enough for statistical validity, fast enough
_ANNUAL_CHURN = 0.25
_N_YEARS = 5
_SNAPSHOT_YEARS = {1, 3, 5}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _weekly_churn_prob() -> float:
    return 1.0 - (1.0 - _ANNUAL_CHURN) ** (1.0 / 52.0)


def _new_nodes_this_week(week: int) -> int:
    """Growth schedule targeting ~2K nodes over 5 years."""
    if week < 52:
        return 8
    elif week < 156:
        return 40
    else:
        return 20


def _build_weekly_pass_probs(n_weeks: int) -> np.ndarray:
    """
    Precompute P(pass weekly check) per archetype per week.
    Returns shape (N_ARCHETYPES, n_weeks).
    """
    week_idx = np.arange(n_weeks)
    week_in_year = week_idx % 52
    probs = np.zeros((N_ARCHETYPES, n_weeks), dtype=np.float64)

    probs[0, :] = 1.0 - (1.0 - 0.99) ** 7                        # Reliable
    p_fail_we = (1.0 - 0.95) ** 3 * (1.0 - 0.30) ** 4
    probs[1, :] = 1.0 - p_fail_we                                 # Weekend
    is_summer = (week_in_year >= 22) & (week_in_year <= 35)
    r_seas = np.where(is_summer, 0.20, 0.95)
    probs[2, :] = 1.0 - (1.0 - r_seas) ** 7                      # Seasonal
    probs[3, :] = 0.50                                             # Nomad
    probs[4, :] = 1.0 - (1.0 - 0.90) ** 7                        # Hoarder
    probs[5, :] = 1.0 - (1.0 - 0.80) ** 7                        # Freeloader

    return probs


def _build_adaptive_n_table() -> np.ndarray:
    """
    Precompute a lookup table: avg_p_bucket -> minimum n.

    avg_p is quantized into 100 buckets [0.01, 1.0] (100 points from 0.1 to 1.0).
    Index i corresponds to avg_p = 0.1 + i * (0.9/99).

    At module import time this runs 100 * K*10 binom.sf calls once.
    During simulation we use _N_TABLE[avg_p_idx] instead of calling scipy.
    """
    n_buckets = 100
    p_values = np.linspace(0.1, 1.0, n_buckets)
    table = np.full(n_buckets, K_SHARDS * 5, dtype=np.int32)
    for i, avg_p in enumerate(p_values):
        for n in range(K_SHARDS, K_SHARDS * 10 + 1):
            if binom.sf(K_SHARDS - 1, n, float(avg_p)) >= TARGET_SURVIVAL:
                table[i] = n
                break
    return table


_ADAPTIVE_N_TABLE = _build_adaptive_n_table()
_TABLE_P_MIN = 0.1
_TABLE_P_MAX = 1.0
_TABLE_N_BUCKETS = len(_ADAPTIVE_N_TABLE)


def compute_adaptive_n(partner_trusts: np.ndarray) -> int:
    """
    Find minimum n s.t. P(Binomial(n, avg_p) >= K_SHARDS) >= TARGET_SURVIVAL.

    Uses precomputed lookup table (_ADAPTIVE_N_TABLE) for O(1) lookup.
    avg_p = mean(clip(trust / MAX_TRUST, 0.1, 1.0))
    """
    if len(partner_trusts) == 0:
        return K_SHARDS * 3

    avg_p = float(np.mean(np.clip(partner_trusts / MAX_TRUST, 0.1, 1.0)))
    # Quantize avg_p to table index
    idx = int(
        (avg_p - _TABLE_P_MIN) / (_TABLE_P_MAX - _TABLE_P_MIN)
        * (_TABLE_N_BUCKETS - 1)
        + 0.5
    )
    idx = max(0, min(idx, _TABLE_N_BUCKETS - 1))
    return int(_ADAPTIVE_N_TABLE[idx])


# ---------------------------------------------------------------------------
# Scenario configuration
# ---------------------------------------------------------------------------

@dataclass
class ScenarioCfg:
    name: str
    adaptive: bool
    acceptance_gate: bool
    gate_threshold: float = 0.3


SCENARIOS: list[ScenarioCfg] = [
    ScenarioCfg("Fixed n=15, gate=ON",  adaptive=False, acceptance_gate=True),
    ScenarioCfg("Fixed n=15, gate=OFF", adaptive=False, acceptance_gate=False),
    ScenarioCfg("Adaptive n, gate=OFF", adaptive=True,  acceptance_gate=False),
    ScenarioCfg("Adaptive n, gate=ON",  adaptive=True,  acceptance_gate=True),
]


# ---------------------------------------------------------------------------
# Core simulation
# ---------------------------------------------------------------------------

def simulate_one(scenario: ScenarioCfg, seed: int) -> dict:
    """
    Run one 5-year simulation under the given scenario.

    Shard matrix design:
      shards[i, j] = partner ID holding shard j (-1 = empty slot)
      shards_n[i]  = number of occupied slots

    The hot path (weekly shard check) is fully vectorized:
      - Extract shards[active_ids, :] into S matrix
      - Check alive[S] and passed[S] with numpy fancy indexing
      - Compact dead holders by row-filtering (only for rows with dead holders)

    The cold path (repair scheduling, initial placement) uses a Python loop
    but only over nodes that actually need action (a small subset each week).
    """
    rng = np.random.default_rng(seed)
    cap = _MAX_ACTIVE + 300
    n_weeks = _N_YEARS * 52
    pw = 4

    # Node state arrays (pre-allocated to cap)
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
    passed_this_week = np.zeros(cap, dtype=bool)

    # Partnership adjacency (used for shard placement weighting)
    partners: list[set[int]] = [set() for _ in range(cap)]

    # Shard matrix (cap x MAX_SHARD_SLOTS)
    shards = np.full((cap, MAX_SHARD_SLOTS), -1, dtype=np.int32)
    shards_n = np.zeros(cap, dtype=np.int32)

    # File / repair state
    file_alive = np.ones(cap, dtype=bool)
    desired_n = np.full(cap, FIXED_N, dtype=np.int32)
    repair_ready = np.full(cap, -1, dtype=np.int32)   # week repair completes
    bootstrap_done = np.full(cap, -1, dtype=np.int32) # week of first >= K live shards

    # Cumulative wasted-shard tracking
    total_shards_placed = np.zeros(cap, dtype=np.int64)
    dead_shards_count = np.zeros(cap, dtype=np.int64)

    weekly_pass_probs = _build_weekly_pass_probs(n_weeks)
    weekly_churn = _weekly_churn_prob()

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

    def _add_node(nid: int, week: int) -> None:
        atype = int(rng.choice(N_ARCHETYPES, p=ARCHETYPE_PROBS))
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
        passed_this_week[nid] = False
        partners[nid] = set()
        shards[nid, :] = -1
        shards_n[nid] = 0
        file_alive[nid] = True
        desired_n[nid] = FIXED_N if not scenario.adaptive else K_SHARDS * 3
        repair_ready[nid] = -1
        bootstrap_done[nid] = -1
        total_shards_placed[nid] = 0
        dead_shards_count[nid] = 0

    def _remove_node(nid: int) -> None:
        alive[nid] = False
        for pid in partners[nid]:
            partners[pid].discard(nid)
        partners[nid].clear()
        free_ids.append(nid)

    for _ in range(_INITIAL_PEERS):
        nid = _alloc()
        if nid is None:
            break
        _add_node(nid, 0)

    snapshots: list[dict] = []

    # ------------------------------------------------------------------
    # Main weekly loop
    # ------------------------------------------------------------------
    for week in range(n_weeks):

        # 1. Growth
        n_active = int(alive.sum())
        if n_active < _MAX_ACTIVE:
            n_new = min(_new_nodes_this_week(week), _MAX_ACTIVE - n_active)
            for _ in range(n_new):
                nid = _alloc()
                if nid is None:
                    break
                _add_node(nid, week)

        # 2. Churn
        active_ids = np.where(alive)[0]
        if active_ids.size > 0:
            churn_mask = rng.random(active_ids.size) < weekly_churn
            for nid in active_ids[churn_mask]:
                _remove_node(int(nid))

        # 3. Weekly check scores (vectorized per archetype)
        active_ids = np.where(alive)[0]
        if active_ids.size == 0:
            continue

        passed_this_week[:] = False
        active_arch = archetype[active_ids]
        week_scores = np.zeros(active_ids.size, dtype=np.float64)

        for atype_idx in range(N_ARCHETYPES):
            grp = np.where(active_arch == atype_idx)[0]
            if grp.size == 0:
                continue
            p_w = float(weekly_pass_probs[atype_idx, week])
            s = (rng.random(grp.size) < p_w).astype(np.float64)
            week_scores[grp] = s
            passed_this_week[active_ids[grp]] = s.astype(bool)

        # 4. Update P circular buffer (vectorized)
        pos = p_buf_pos[active_ids]
        p_buf[active_ids, pos] = week_scores
        p_buf_pos[active_ids] = (pos + 1) % pw
        pf = p_buf_filled[active_ids]
        p_buf_filled[active_ids] = np.minimum(pf + 1, pw)

        # 5. Update I (vectorized)
        i_sum[active_ids] += week_scores
        i_count[active_ids] += 1

        # 6. Recompute P and I values (vectorized)
        pbuf_sum = p_buf[active_ids, :].sum(axis=1)
        pfilled = p_buf_filled[active_ids].astype(np.float64)
        p_val[active_ids] = np.where(pfilled > 0, pbuf_sum / pfilled, 0.0)
        ic = i_count[active_ids].astype(np.float64)
        i_val[active_ids] = np.where(ic > 0, i_sum[active_ids] / ic, 0.0)

        # 7. Partnership formation (batched, trust-weighted, no alive.copy())
        _update_partnerships(
            active_ids, alive, archetype, i_val, p_val,
            partners, scenario, rng,
        )

        # 8. Shard update: vectorized hot path + selective cold path
        _update_shards(
            week, active_ids, alive, archetype,
            i_val, p_val, passed_this_week,
            partners, shards, shards_n,
            file_alive, desired_n, repair_ready, bootstrap_done,
            total_shards_placed, dead_shards_count,
            scenario, rng,
        )

        # 9. Yearly snapshot
        year = (week + 1) // 52
        if year in _SNAPSHOT_YEARS and (week + 1) % 52 == 0:
            snap = _build_snapshot(
                year, active_ids, file_alive, shards_n, desired_n,
                join_week, bootstrap_done, total_shards_placed, dead_shards_count,
            )
            snapshots.append(snap)

    return {"snapshots": snapshots, "seed": seed}


def _update_partnerships(
    active_ids: np.ndarray,
    alive: np.ndarray,
    archetype: np.ndarray,
    i_val: np.ndarray,
    p_val: np.ndarray,
    partners: list[set[int]],
    scenario: ScenarioCfg,
    rng: np.random.Generator,
) -> None:
    """
    Trust-weighted partnership formation for underfull nodes.

    Avoids alive.copy() by working directly with active_ids set for candidate
    filtering. Processes at most 300 underfull nodes per week.
    """
    on_count = np.array([len(partners[int(nid)]) for nid in active_ids], dtype=np.int32)
    underfull_mask = on_count < TARGET_PARTNERS
    underfull = active_ids[underfull_mask]
    if underfull.size == 0:
        return

    if underfull.size > 300:
        underfull = rng.choice(underfull, size=300, replace=False)

    # Pre-build index: active node ID -> index in active_ids
    active_set = set(int(x) for x in active_ids)

    for pid in underfull:
        pid = int(pid)
        n_needed = TARGET_PARTNERS - len(partners[pid])
        if n_needed <= 0:
            continue

        a_pid = int(archetype[pid])
        r_pid = float(STORAGE_RATIOS[a_pid])

        # Candidates: active, not self, not already partner, has room
        existing = partners[pid]
        candidates = [
            c for c in active_set
            if c != pid
            and c not in existing
            and len(partners[c]) < TARGET_PARTNERS
        ]

        # Acceptance gate: newcomer only connects to other newcomers
        if scenario.acceptance_gate and float(i_val[pid]) < scenario.gate_threshold:
            candidates = [c for c in candidates if float(i_val[c]) <= scenario.gate_threshold]

        if not candidates:
            # Relax gate
            candidates = [
                c for c in active_set
                if c != pid
                and c not in existing
                and len(partners[c]) < TARGET_PARTNERS
            ]

        if not candidates:
            continue

        arr = np.array(candidates, dtype=np.int32)
        r_cands = STORAGE_RATIOS[archetype[arr]]
        s_vals = np.clip(r_cands / max(r_pid, 0.01), 0.1, 1.0)
        raw = KP * p_val[arr] + KI * i_val[arr]
        c_trust = np.maximum(raw * s_vals, 0.01)
        probs = c_trust / c_trust.sum()

        n_pick = min(n_needed, len(candidates))
        chosen = rng.choice(arr, size=n_pick, replace=False, p=probs)
        for cid in chosen:
            cid = int(cid)
            partners[pid].add(cid)
            partners[cid].add(pid)


def _update_shards(
    week: int,
    active_ids: np.ndarray,
    alive: np.ndarray,
    archetype: np.ndarray,
    i_val: np.ndarray,
    p_val: np.ndarray,
    passed_this_week: np.ndarray,
    partners: list[set[int]],
    shards: np.ndarray,
    shards_n: np.ndarray,
    file_alive: np.ndarray,
    desired_n: np.ndarray,
    repair_ready: np.ndarray,
    bootstrap_done: np.ndarray,
    total_shards_placed: np.ndarray,
    dead_shards_count: np.ndarray,
    scenario: ScenarioCfg,
    rng: np.random.Generator,
) -> None:
    """
    Combined vectorized + selective per-node shard update.

    Vectorized part (all active nodes):
      - Compute live shard count per node via fancy indexing into shards matrix
      - Detect file loss (live < K_SHARDS)
      - Track bootstrap (first week with >= K live shards)
      - Count dead holders for wasted-shard metric
      - Remove dead holders from shards matrix (compact rows with dead holders)

    Selective per-node part (only nodes needing action):
      - Initial shard placement (shards_n == 0 and enough partners)
      - Completed repair application
      - Repair scheduling (needs shards but degraded)
      - Adaptive desired_n recalculation (every 4 weeks)
    """
    N = active_ids.size
    if N == 0:
        return

    # --- Vectorized: extract shard matrix for active nodes ---
    S = shards[active_ids, :]        # (N, MAX_SHARD_SLOTS) int32
    filled = S != -1                  # (N, MAX_SHARD_SLOTS) bool

    # Safely index into alive and passed arrays (replace -1 with 0)
    S_safe = np.where(filled, S, 0)
    holder_alive = alive[S_safe]     # (N, MAX_SHARD_SLOTS) bool
    holder_passed = passed_this_week[S_safe]

    live_mask = filled & holder_alive & holder_passed
    live_count = live_mask.sum(axis=1).astype(np.int32)   # (N,)

    # Dead holder tracking
    dead_holder_mask = filled & (~holder_alive)
    new_dead = dead_holder_mask.sum(axis=1).astype(np.int64)
    dead_shards_count[active_ids] += new_dead

    # Valid slots: holder still alive (may or may not have passed)
    still_valid = filled & holder_alive
    new_shard_n = still_valid.sum(axis=1).astype(np.int32)
    shards_n[active_ids] = new_shard_n

    # File loss check
    had_shards = filled.any(axis=1)
    lost = had_shards & (live_count < K_SHARDS) & file_alive[active_ids]
    file_alive[active_ids[lost]] = False

    # Bootstrap tracking
    need_bootstrap = bootstrap_done[active_ids] < 0
    just_bootstrapped = need_bootstrap & (live_count >= K_SHARDS)
    bootstrap_done[active_ids[just_bootstrapped]] = week

    # Compact dead holders out of shard matrix (only rows with dead holders)
    has_dead_rows = np.where(new_dead > 0)[0]
    for row_idx in has_dead_rows:
        nid = int(active_ids[row_idx])
        valid = still_valid[row_idx]
        old_row = S[row_idx]
        kept = old_row[valid]
        n_kept = len(kept)
        shards[nid, :n_kept] = kept
        shards[nid, n_kept:] = -1

    # --- Selective per-node: adaptive recalculation ---
    # Use trust of current partners to estimate avg shard survival probability.
    # For efficiency, approximate using the node's own arch-based S expected value:
    # avg_p ≈ mean trust of alive partners / MAX_TRUST
    # We compute this vectorized: for each active node, we use its shards_n as
    # a proxy for partner pool size, then estimate avg_p from the network mean
    # trust weighted by archetype. This avoids per-node Python set iteration.
    if scenario.adaptive and week % ADAPTIVE_RECALC_INTERVAL == 0:
        # For each active node, compute avg partner trust from partner sets.
        # To keep this fast, sample at most 10 partners per node.
        MAX_SAMPLE = 10
        for row_idx in range(N):
            nid = int(active_ids[row_idx])
            part_list = list(partners[nid])
            if not part_list:
                desired_n[nid] = K_SHARDS * 3
                continue
            a_nid = int(archetype[nid])
            r_nid = float(STORAGE_RATIOS[a_nid])
            # Sample partners for speed
            if len(part_list) > MAX_SAMPLE:
                idxs = rng.choice(len(part_list), MAX_SAMPLE, replace=False)
                sample = [part_list[i] for i in idxs]
            else:
                sample = part_list
            arr = np.array(sample, dtype=np.int32)
            arr = arr[alive[arr]]
            if len(arr) == 0:
                desired_n[nid] = K_SHARDS * 3
                continue
            r_cands = STORAGE_RATIOS[archetype[arr]]
            s_vals = np.clip(r_cands / max(r_nid, 0.01), 0.1, 1.0)
            raw = KP * p_val[arr] + KI * i_val[arr]
            pt = np.maximum(raw * s_vals, 0.0)
            desired_n[nid] = compute_adaptive_n(pt)

    # --- Selective per-node: initial placement, repair completion, scheduling ---
    # Only process nodes that actually need attention:
    #   a) Need initial placement: shards_n == 0
    #   b) Have completed repair: repair_ready[i] >= 0 and week >= repair_ready[i]
    #   c) Need repair scheduling: file alive, shards_n < desired_n, no pending repair
    sn_active = shards_n[active_ids]      # (N,)
    dn_active = desired_n[active_ids]     # (N,)
    rr_active = repair_ready[active_ids]  # (N,)
    fa_active = file_alive[active_ids]    # (N,)

    needs_initial = sn_active == 0
    repair_due = (rr_active >= 0) & (week >= rr_active)
    needs_schedule = fa_active & (rr_active < 0) & (sn_active < dn_active)

    action_rows = np.where(needs_initial | repair_due | needs_schedule)[0]

    for row_idx in action_rows:
        nid = int(active_ids[row_idx])
        sn = int(shards_n[nid])
        dn = int(desired_n[nid])

        # Initial placement
        if sn == 0 and len(partners[nid]) >= K_SHARDS:
            _place_shards(nid, alive, archetype, i_val, p_val,
                          partners, shards, shards_n, desired_n,
                          total_shards_placed, rng)
            continue

        # Apply completed repair
        if int(repair_ready[nid]) >= 0 and week >= int(repair_ready[nid]):
            repair_ready[nid] = -1
            _place_shards(nid, alive, archetype, i_val, p_val,
                          partners, shards, shards_n, desired_n,
                          total_shards_placed, rng)

        # Schedule repair if degraded
        if (file_alive[nid] and repair_ready[nid] < 0
                and int(shards_n[nid]) < int(desired_n[nid])):
            repair_ready[nid] = week + REPAIR_DELAY_WEEKS


def _place_shards(
    nid: int,
    alive: np.ndarray,
    archetype: np.ndarray,
    i_val: np.ndarray,
    p_val: np.ndarray,
    partners: list[set[int]],
    shards: np.ndarray,
    shards_n: np.ndarray,
    desired_n: np.ndarray,
    total_shards_placed: np.ndarray,
    rng: np.random.Generator,
) -> None:
    """
    Fill empty shard slots for nid up to desired_n[nid] partners.

    Selects from alive partners not already holding a shard,
    weighted by multiplicative trust score.
    """
    target = int(desired_n[nid])
    current_n = int(shards_n[nid])
    needed = target - current_n
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
        s_vals = np.clip(r_cands / max(r_nid, 0.01), 0.1, 1.0)
        raw = KP * p_val[arr] + KI * i_val[arr]
        trust_vals = np.maximum(raw * s_vals, 0.01)
        probs = trust_vals / trust_vals.sum()
        idxs = rng.choice(len(available), size=n_pick, replace=False, p=probs)
        chosen = [available[int(i)] for i in idxs]

    for h in chosen:
        shards[nid, current_n] = h
        current_n += 1

    shards_n[nid] = current_n
    total_shards_placed[nid] += len(chosen)


def _build_snapshot(
    year: int,
    active_ids: np.ndarray,
    file_alive: np.ndarray,
    shards_n: np.ndarray,
    desired_n: np.ndarray,
    join_week: np.ndarray,
    bootstrap_done: np.ndarray,
    total_shards_placed: np.ndarray,
    dead_shards_count: np.ndarray,
) -> dict:
    """Compute yearly snapshot metrics for active nodes."""
    if active_ids.size == 0:
        return {
            "year": year, "survival_rate": 0.0, "mean_overhead": 0.0,
            "mean_actual_n": 0.0, "mean_desired_n": 0.0,
            "bootstrap_weeks": -1.0, "wasted_frac": 0.0, "n_active": 0,
        }

    survival_rate = float(file_alive[active_ids].mean())
    actual_ns = shards_n[active_ids].astype(np.float64)
    mean_actual_n = float(actual_ns.mean())
    mean_overhead = mean_actual_n / K_SHARDS
    mean_desired_n = float(desired_n[active_ids].astype(np.float64).mean())

    # Bootstrap: nodes that joined post-genesis and completed bootstrap
    jw = join_week[active_ids]
    bd = bootstrap_done[active_ids]
    bootstrap_mask = (jw > 0) & (bd >= 0)
    if bootstrap_mask.any():
        mean_bootstrap = float((bd[bootstrap_mask] - jw[bootstrap_mask]).mean())
    else:
        mean_bootstrap = -1.0

    tot = int(total_shards_placed[active_ids].sum())
    dead = int(dead_shards_count[active_ids].sum())
    wasted_frac = dead / max(tot, 1)

    return {
        "year": year,
        "survival_rate": survival_rate,
        "mean_overhead": mean_overhead,
        "mean_actual_n": mean_actual_n,
        "mean_desired_n": mean_desired_n,
        "bootstrap_weeks": mean_bootstrap,
        "wasted_frac": wasted_frac,
        "n_active": int(active_ids.size),
    }


# ---------------------------------------------------------------------------
# Experiment runner
# ---------------------------------------------------------------------------

def run_scenario(scenario: ScenarioCfg, n_seeds: int, n_jobs: int) -> list[dict]:
    """Run one scenario across n_seeds and return aggregated per-year metrics."""
    seeds = list(range(n_seeds))

    if n_jobs == 1 or n_seeds == 1:
        all_runs = [simulate_one(scenario, s) for s in seeds]
    else:
        all_runs = Parallel(n_jobs=n_jobs)(
            delayed(simulate_one)(scenario, s) for s in seeds
        )

    per_year: dict[int, list[dict]] = {y: [] for y in _SNAPSHOT_YEARS}
    for run in all_runs:
        for snap in run["snapshots"]:
            y = snap["year"]
            if y in per_year:
                per_year[y].append(snap)

    def _avg(snaps: list[dict], key: str) -> float:
        vals = [s[key] for s in snaps if key in s]
        return float(np.mean(vals)) if vals else 0.0

    aggregated: list[dict] = []
    for year in sorted(_SNAPSHOT_YEARS):
        snaps = per_year[year]
        if not snaps:
            continue
        aggregated.append({
            "year": year,
            "survival_rate": _avg(snaps, "survival_rate"),
            "mean_overhead": _avg(snaps, "mean_overhead"),
            "mean_actual_n": _avg(snaps, "mean_actual_n"),
            "mean_desired_n": _avg(snaps, "mean_desired_n"),
            "bootstrap_weeks": _avg(snaps, "bootstrap_weeks"),
            "wasted_frac": _avg(snaps, "wasted_frac"),
            "n_active": int(_avg(snaps, "n_active")),
        })

    return aggregated


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _fmt_bootstrap(bw: float) -> str:
    if bw < 0:
        return "    N/A"
    return f"{bw:.1f} wks"


def print_results(all_results: list[tuple[ScenarioCfg, list[dict]]]) -> None:
    print("=== VIATICUM EXPERIMENT 21: ADAPTIVE SHARD COUNT ===")
    print()

    for sc_idx, (scenario, snaps) in enumerate(all_results, 1):
        print(f"Scenario {sc_idx}: {scenario.name}")
        for snap in snaps:
            y = snap["year"]
            surv = snap["survival_rate"] * 100
            overhead = snap["mean_overhead"]
            actual_n = snap["mean_actual_n"]
            bw = _fmt_bootstrap(snap["bootstrap_weeks"])
            wasted = snap["wasted_frac"] * 100
            n_act = snap["n_active"]
            print(
                f"  Year {y}: survival={surv:.2f}%, overhead={overhead:.2f}x, "
                f"mean_n={actual_n:.1f}, bootstrap={bw}, "
                f"wasted={wasted:.1f}%, nodes={n_act}"
            )
        print()

    # Comparison table at year 5
    print("=== COMPARISON (Year 5) ===")
    hdr = (
        f"{'Scenario':<35} {'Survival%':>9} {'Overhead':>9} "
        f"{'Mean_n':>7} {'Bootstrap':>10} {'Wasted%':>8}"
    )
    print(hdr)
    print("-" * len(hdr))

    for sc_idx, (scenario, snaps) in enumerate(all_results, 1):
        y5 = next((s for s in snaps if s["year"] == 5), None)
        if y5 is None:
            continue
        print(
            f"{sc_idx}. {scenario.name:<33} "
            f"{y5['survival_rate']*100:>8.2f}% "
            f"{y5['mean_overhead']:>9.2f}x "
            f"{y5['mean_actual_n']:>7.1f} "
            f"{_fmt_bootstrap(y5['bootstrap_weeks']):>10} "
            f"{y5['wasted_frac']*100:>7.1f}%"
        )
    print()

    # Key tradeoff: Scenario 1 (fixed + gate) vs Scenario 3 (adaptive + no gate)
    sc1_snaps = next(
        (snaps for sc, snaps in all_results if not sc.adaptive and sc.acceptance_gate), None
    )
    sc3_snaps = next(
        (snaps for sc, snaps in all_results if sc.adaptive and not sc.acceptance_gate), None
    )
    if sc1_snaps and sc3_snaps:
        f5 = next((s for s in sc1_snaps if s["year"] == 5), None)
        a5 = next((s for s in sc3_snaps if s["year"] == 5), None)
        if f5 and a5:
            oh_delta = f5["mean_overhead"] - a5["mean_overhead"]
            surv_delta = (a5["survival_rate"] - f5["survival_rate"]) * 100
            print("Key tradeoff (Sc1 fixed+gate vs Sc3 adaptive+no-gate, year 5):")
            print(
                f"  Overhead: {f5['mean_overhead']:.2f}x -> {a5['mean_overhead']:.2f}x "
                f"(saves {oh_delta:.2f}x = {oh_delta/f5['mean_overhead']*100:.1f}%)"
            )
            print(
                f"  Survival: {f5['survival_rate']*100:.2f}% vs "
                f"{a5['survival_rate']*100:.2f}% ({surv_delta:+.3f} pp)"
            )
            print(
                f"  Wasted:   {f5['wasted_frac']*100:.1f}% vs "
                f"{a5['wasted_frac']*100:.1f}%"
            )


def save_results(results: list[tuple[ScenarioCfg, list[dict]]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    def _convert(obj: object) -> object:
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if isinstance(obj, dict):
            return {k: _convert(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_convert(v) for v in obj]
        return obj

    payload = [
        {
            "scenario": {
                "name": sc.name,
                "adaptive": sc.adaptive,
                "acceptance_gate": sc.acceptance_gate,
                "gate_threshold": sc.gate_threshold,
            },
            "snapshots": snaps,
        }
        for sc, snaps in results
    ]

    out_path = out_dir / "run.json"
    out_path.write_text(json.dumps(_convert(payload), indent=2))
    print(f"Results saved to {out_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Viaticum Experiment 21: Adaptive Shard Count"
    )
    parser.add_argument("--seeds", type=int, default=10,
                        help="Monte Carlo seeds per scenario (default: 10)")
    parser.add_argument("--jobs", type=int, default=1,
                        help="Parallel jobs within each scenario (default: 1)")
    parser.add_argument("--output", type=str, default="results/pis_adaptive_n",
                        help="Output directory for JSON results")
    args = parser.parse_args()

    print("=== VIATICUM EXPERIMENT 21: ADAPTIVE SHARD COUNT ===")
    print(f"Seeds: {args.seeds}, Jobs: {args.jobs}")
    print(
        f"Network: max={_MAX_ACTIVE} nodes, {_N_YEARS} years, "
        f"churn={_ANNUAL_CHURN*100:.0f}%/yr, k={K_SHARDS}, fixed_n={FIXED_N}"
    )
    print(f"Trust: multiplicative S, kp={KP}, ki={KI}")
    print()

    t0 = time.time()
    all_results: list[tuple[ScenarioCfg, list[dict]]] = []

    for sc_idx, scenario in enumerate(SCENARIOS, 1):
        print(f"Running scenario {sc_idx}/4: {scenario.name} ...", flush=True)
        t_sc = time.time()
        snaps = run_scenario(scenario, args.seeds, args.jobs)
        elapsed_sc = time.time() - t_sc
        all_results.append((scenario, snaps))
        print(f"  Done in {elapsed_sc:.1f}s")

    total_elapsed = time.time() - t0
    print(f"\nTotal runtime: {total_elapsed:.1f}s\n")

    print_results(all_results)
    save_results(all_results, Path(args.output))


if __name__ == "__main__":
    main()
