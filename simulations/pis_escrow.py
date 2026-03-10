"""
SyncBack Simulation #24: Escrow as Credit System

Question: Does escrow help when combined with adaptive redundancy? Is it needed?

Four configurations tested:
  A: No escrow, fixed n=15    -- baseline, free-riders can upload/restore/leave
  B: Escrow ON, fixed n=15    -- restore gated by I-score
  C: No escrow, adaptive n    -- n adapts to partner trust
  D: Escrow ON, adaptive n    -- both mechanisms

Trust formula (multiplicative S):
  trust_AB = (0.5 * P_B + 2.0 * I_B) * clamp(S_AB, 0.1, 1.0)
  S_AB = STORAGE_RATIOS[B] / max(STORAGE_RATIOS[A], eps)

Escrow tiers (gating restore by I-score):
  <= 1.0 GB   : free (demo credit)
  <= 5.0 GB   : I >= 0.1  (~1 month)
  <= 50.0 GB  : I >= 0.3  (~3 months)
  > 50.0 GB   : I >= 0.5  (~6 months)

7th archetype -- HitAndRun:
  Joins, uploads a 10GB file, tries to restore every week.
  Leaves on first success or after 4 weeks of blocked attempts.
  Storage contribution: 0.0 (STORAGE_RATIOS = 0.0).
  Online reliability: 80%.

Usage:
    python pis_escrow.py --seeds 10 --jobs 6
    python pis_escrow.py --seeds 3 --jobs 4     # quick smoke test
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


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ARCHETYPE_NAMES = ["Reliable", "Weekend", "Seasonal", "Nomad", "Hoarder", "Freeloader", "HitAndRun"]
N_ARCHETYPES = len(ARCHETYPE_NAMES)

# Fraction of new arrivals per archetype
ARCHETYPE_PROBS = np.array([0.30, 0.20, 0.12, 0.08, 0.10, 0.05, 0.15])

# Storage ratio per archetype: gb_stored_for_others / gb_stored_by_others
# Pairwise S_AB = STORAGE_RATIOS[B] / max(STORAGE_RATIOS[A], _S_EPS)
STORAGE_RATIOS = np.array([1.0, 1.0, 1.0, 1.0, 0.2, 0.1, 0.0], dtype=np.float64)

# File size per archetype: maps to restore tier
# Honest nodes: 2/10/60 GB picked uniformly; HitAndRun: always 10 GB
FILE_SIZES_HONEST = np.array([2.0, 10.0, 60.0])
FILE_SIZE_HIT_AND_RUN = 10.0

# Erasure coding: k = recovery threshold, base_n = nominal shard count
K = 5
BASE_N = 15

# Trust formula weights (multiplicative S)
KP = 0.5
KI = 2.0
S_CLAMP_MIN = 0.1
S_CLAMP_MAX = 1.0
_S_EPS = 0.01

# Adaptive n cap: prevent unbounded shard inflation
ADAPTIVE_N_MAX = 40

# Network
MAX_NODES = 3000
INITIAL_NODES = 100
ANNUAL_CHURN = 0.25
N_YEARS = 3
N_WEEKS = N_YEARS * 52
TARGET_PARTNERS = 15
ACCEPTANCE_GATE_I = 0.3

# HitAndRun behavior: leaves after this many total weeks without a successful restore
HAR_PATIENCE_WEEKS = 4

# Escrow: minimum weeks-in-network per tier (time credit, not I-score)
# Rationale: I = cumulative mean of 0/1 checks approaches reliability immediately
# for well-behaved nodes, so the I-score thresholds in the spec map to time-in-network:
#   I >= 0.1 "~1 month"  -> 4 weeks
#   I >= 0.3 "~3 months" -> 13 weeks
#   I >= 0.5 "~6 months" -> 26 weeks
ESCROW_TIER1_WEEKS = 4    # <= 5 GB
ESCROW_TIER2_WEEKS = 13   # <= 50 GB
ESCROW_TIER3_WEEKS = 26   # > 50 GB


# ---------------------------------------------------------------------------
# Escrow logic
# ---------------------------------------------------------------------------

def can_restore(file_size_gb: float, weeks_in_network: int, escrow_on: bool) -> bool:
    """
    Return True if the node is allowed to restore its file.

    Escrow uses weeks-in-network as the time credit (not raw I-score), because
    a reliable node's I converges to its reliability immediately (from week 1),
    making I-thresholds 0.1/0.3/0.5 trivially satisfied by any uptime > 50%.
    The spec's parentheticals "(~1 month)", "(~3 months)", "(~6 months)" refer
    to time, so we map them directly to week counts.
    """
    if not escrow_on:
        return True
    if file_size_gb <= 1.0:
        return True  # free demo credit
    if file_size_gb <= 5.0:
        return weeks_in_network >= ESCROW_TIER1_WEEKS
    if file_size_gb <= 50.0:
        return weeks_in_network >= ESCROW_TIER2_WEEKS
    return weeks_in_network >= ESCROW_TIER3_WEEKS


def escrow_weeks_needed(file_size_gb: float) -> int:
    """Return the minimum weeks-in-network needed to restore a file of given size."""
    if file_size_gb <= 1.0:
        return 0
    if file_size_gb <= 5.0:
        return ESCROW_TIER1_WEEKS
    if file_size_gb <= 50.0:
        return ESCROW_TIER2_WEEKS
    return ESCROW_TIER3_WEEKS


# ---------------------------------------------------------------------------
# Adaptive n
# ---------------------------------------------------------------------------

def adaptive_n(avg_partner_trust: float, max_trust: float = 2.5) -> int:
    """Compute adaptive shard count n = ceil(K / p), min K+2, max ADAPTIVE_N_MAX."""
    p = max(avg_partner_trust / max_trust, 0.1)
    n = int(np.ceil(K / p))
    return min(max(n, K + 2), ADAPTIVE_N_MAX)


# ---------------------------------------------------------------------------
# Trust formula (multiplicative S, pairwise)
# ---------------------------------------------------------------------------

def compute_trust_mult_s(
    p_val: float | np.ndarray,
    i_val: float | np.ndarray,
    s_val: float | np.ndarray,
) -> float | np.ndarray:
    """trust = (KP*P + KI*I) * clamp(S, S_CLAMP_MIN, S_CLAMP_MAX)"""
    pi = KP * p_val + KI * i_val
    s_c = np.clip(s_val, S_CLAMP_MIN, S_CLAMP_MAX)
    return pi * s_c


def pairwise_s(arch_observer: int | np.ndarray, arch_target: int | np.ndarray) -> float | np.ndarray:
    """S_AB = STORAGE_RATIOS[target] / max(STORAGE_RATIOS[observer], eps)"""
    r_obs = STORAGE_RATIOS[arch_observer]
    r_tgt = STORAGE_RATIOS[arch_target]
    return r_tgt / np.maximum(r_obs, _S_EPS)


# ---------------------------------------------------------------------------
# Weekly pass probabilities per archetype
# ---------------------------------------------------------------------------

def _build_weekly_pass_probs(n_weeks: int) -> np.ndarray:
    """Precompute P(pass weekly check) per archetype per week. Shape: (N_ARCHETYPES, n_weeks)."""
    week_idx = np.arange(n_weeks)
    week_in_year = week_idx % 52

    probs = np.zeros((N_ARCHETYPES, n_weeks), dtype=np.float64)

    # 0: Reliable -- 99% daily
    probs[0, :] = 1.0 - (1.0 - 0.99) ** 7

    # 1: Weekend -- 95% Fri-Sun, 30% Mon-Thu
    p_fail_weekend = (1.0 - 0.95) ** 3 * (1.0 - 0.30) ** 4
    probs[1, :] = 1.0 - p_fail_weekend

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

    # 6: HitAndRun -- 80% daily (motivated to stay online for restore)
    probs[6, :] = 1.0 - (1.0 - 0.80) ** 7

    return probs


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class SimConfig:
    escrow_on: bool = False
    adaptive_n_on: bool = False
    label: str = "A"


# ---------------------------------------------------------------------------
# Core simulation
# ---------------------------------------------------------------------------

def simulate_one(cfg: SimConfig, seed: int) -> dict:
    """
    Simulate a 3-year living network and collect escrow-related metrics.

    Per-node arrays (pre-allocated to MAX_NODES):
      archetype[i]         -- archetype index 0..6, -1=inactive
      alive[i]             -- currently active
      join_week[i]         -- week node joined
      p_buf[i, 0:pw]       -- circular buffer for P (last 4 weeks)
      p_buf_pos[i]         -- next write position
      p_buf_filled[i]      -- how many slots filled (capped at pw)
      i_sum[i]             -- cumulative sum of weekly scores
      i_count[i]           -- weeks counted
      p_val[i]             -- current P (mean of circular buffer)
      i_val[i]             -- current I (cumulative mean)
      file_size[i]         -- file size in GB (set on join)
      shard_holders[i]     -- list of node IDs holding shards of node i's file
      har_blocked_weeks[i] -- for HitAndRun: consecutive weeks blocked from restore
      har_succeeded[i]     -- did this HitAndRun node restore successfully?
      har_gb_weeks[i]      -- GB*weeks spent storing shards for this HitAndRun
      partners[i]          -- set of partner node IDs

    Bootstrap time tracking:
      - For each honest newcomer, record the week they first crossed I >= threshold per tier
      - Record only the first BOOTSTRAP_SAMPLE_LIMIT nodes per tier for efficiency
    """
    rng = np.random.default_rng(seed)
    cap = MAX_NODES
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
    # shard_holders[i]: list of node IDs storing shards of node i's file
    shard_holders: list[list[int]] = [[] for _ in range(cap)]

    har_blocked_weeks = np.zeros(cap, dtype=np.int32)   # weeks blocked by escrow specifically
    har_total_weeks = np.zeros(cap, dtype=np.int32)      # total weeks alive (for giving up)
    har_succeeded = np.zeros(cap, dtype=bool)
    har_gb_weeks = np.zeros(cap, dtype=np.float64)

    partners: list[set[int]] = [set() for _ in range(cap)]

    weekly_pass_probs = _build_weekly_pass_probs(N_WEEKS)

    # ID management
    next_id = [0]
    free_ids: list[int] = []

    def _alloc() -> Optional[int]:
        if free_ids:
            return free_ids.pop()
        if next_id[0] < cap:
            nid = next_id[0]
            next_id[0] += 1
            return nid
        return None

    def _pick_file_size(atype: int, rng: np.random.Generator) -> float:
        if atype == 6:  # HitAndRun
            return FILE_SIZE_HIT_AND_RUN
        return float(rng.choice(FILE_SIZES_HONEST))

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
        file_size[nid] = _pick_file_size(atype, rng)
        shard_holders[nid] = []
        har_blocked_weeks[nid] = 0
        har_total_weeks[nid] = 0
        har_succeeded[nid] = False
        har_gb_weeks[nid] = 0.0
        partners[nid] = set()

    def _remove_node(nid: int) -> None:
        alive[nid] = False
        # Remove nid from partners' adjacency sets
        for pid in partners[nid]:
            partners[pid].discard(nid)
        partners[nid].clear()
        # Remove nid from all shard_holders lists (nid went offline)
        # We don't repair immediately -- handled in weekly repair
        free_ids.append(nid)

    # HitAndRun stats (declared early because bootstrap loop references them)
    har_total = 0
    har_success_count = 0
    har_total_gb_weeks = 0.0

    # Bootstrap
    for _ in range(INITIAL_NODES):
        nid = _alloc()
        if nid is not None:
            _add_node(nid, 0)
            if int(archetype[nid]) == 6:
                har_total += 1

    weekly_churn = 1.0 - (1.0 - ANNUAL_CHURN) ** (1.0 / 52.0)

    # --- Metric tracking ---
    # Bootstrap times: weeks from join until an honest newcomer can first restore.
    # Escrow-off: time until >= K shards are alive (placement latency).
    # Escrow-on: max(escrow_weeks_needed, placement_latency).
    bootstrap_t1: list[float] = []  # tier1: file_size in (1,5]
    bootstrap_t2: list[float] = []  # tier2: file_size in (5,50]
    bootstrap_t3: list[float] = []  # tier3: file_size > 50
    BOOTSTRAP_MAX_SAMPLES = 200

    # Track nodes that are "bootstrap candidates" (honest newcomers joined after week 0)
    bootstrap_candidates_t1: set[int] = set()  # file_size in (1,5]
    bootstrap_candidates_t2: set[int] = set()  # file_size in (5,50]
    bootstrap_candidates_t3: set[int] = set()  # file_size > 50
    bootstrap_done_t1: set[int] = set()
    bootstrap_done_t2: set[int] = set()
    bootstrap_done_t3: set[int] = set()

    # File survival snapshots at end of years 1, 2, 3
    year_survival: dict[int, float] = {}

    # Storage overhead tracking: actual_n / k each week (sampled)
    storage_overhead_samples: list[float] = []

    # Retention: nodes alive at start of year 1 (excluding HitAndRun), still alive after 1yr
    retention_cohort: set[int] = set()
    retention_result: Optional[float] = None

    def _node_n(nid: int) -> int:
        """Target shard count for node nid's file."""
        if not cfg.adaptive_n_on:
            return BASE_N
        part = list(partners[nid])
        if len(part) == 0:
            return BASE_N
        # Compute mean incoming trust from partners toward nid
        a_nid = int(archetype[nid])
        p_nid = float(p_val[nid])
        i_nid = float(i_val[nid])
        s_vals = pairwise_s(np.array([int(archetype[p]) for p in part]), np.full(len(part), a_nid))
        t_vals = compute_trust_mult_s(p_nid, i_nid, s_vals)
        mean_t = float(np.mean(t_vals))
        return adaptive_n(mean_t)

    def _place_shards(nid: int) -> None:
        """Place shards of nid's file among active nodes (prefer by trust, subnet-agnostic here)."""
        n_target = _node_n(nid)
        active_ids = np.where(alive)[0]
        # Exclude self
        candidates = active_ids[active_ids != nid]
        if len(candidates) == 0:
            shard_holders[nid] = []
            return

        # Build trust of nid's perspective toward each candidate
        a_nid = int(archetype[nid])
        a_cands = archetype[candidates]
        s_vals = np.array([STORAGE_RATIOS[a] / max(STORAGE_RATIOS[a_nid], _S_EPS) for a in a_cands])
        t_vals = compute_trust_mult_s(p_val[candidates], i_val[candidates], s_vals)
        t_vals = np.maximum(t_vals, 0.01)

        n_pick = min(n_target, len(candidates))
        probs = t_vals / t_vals.sum()
        chosen = rng.choice(candidates, size=n_pick, replace=False, p=probs)
        shard_holders[nid] = chosen.tolist()

    def _repair_file(nid: int) -> None:
        """
        Repair file of nid: remove dead holders, replace missing shards.
        Only repairs if k or more shards survive (otherwise file is lost).
        """
        n_target = _node_n(nid)
        current_holders = [h for h in shard_holders[nid] if alive[h]]
        n_alive = len(current_holders)

        if n_alive < K:
            # File irrecoverable -- keep what we have (or empty)
            shard_holders[nid] = current_holders
            return

        n_lost = n_target - n_alive
        if n_lost <= 0:
            shard_holders[nid] = current_holders
            return

        # Find replacement holders
        existing_set = set(current_holders)
        existing_set.add(nid)

        active_ids = np.where(alive)[0]
        candidates = active_ids[~np.isin(active_ids, list(existing_set))]
        if len(candidates) == 0:
            shard_holders[nid] = current_holders
            return

        a_nid = int(archetype[nid])
        a_cands = archetype[candidates]
        s_vals = np.array([STORAGE_RATIOS[a] / max(STORAGE_RATIOS[a_nid], _S_EPS) for a in a_cands])
        t_vals = compute_trust_mult_s(p_val[candidates], i_val[candidates], s_vals)
        t_vals = np.maximum(t_vals, 0.01)

        n_pick = min(n_lost, len(candidates))
        probs = t_vals / t_vals.sum()
        new_holders = rng.choice(candidates, size=n_pick, replace=False, p=probs)
        shard_holders[nid] = current_holders + new_holders.tolist()

    def _update_partnerships(active_ids: np.ndarray) -> None:
        """Partnership formation for underfull nodes (batched, max 300/week)."""
        on_count = np.array([len(partners[int(nid)]) for nid in active_ids], dtype=np.int32)
        underfull_mask = on_count < TARGET_PARTNERS
        underfull = active_ids[underfull_mask]
        if underfull.size == 0:
            return
        if underfull.size > 300:
            underfull = rng.choice(underfull, size=300, replace=False)

        for pid in underfull:
            pid = int(pid)
            n_needed = TARGET_PARTNERS - len(partners[pid])
            if n_needed <= 0:
                continue

            a_pid = int(archetype[pid])
            req_i = float(i_val[pid])

            mask = alive.copy()
            mask[pid] = False
            for ex in partners[pid]:
                mask[ex] = False
            # Capacity filter
            for cid in np.where(mask)[0]:
                if len(partners[int(cid)]) >= TARGET_PARTNERS:
                    mask[int(cid)] = False

            # Acceptance gate: newcomers (I < gate) connect only to other newcomers
            if req_i < ACCEPTANCE_GATE_I:
                gate_mask = i_val <= ACCEPTANCE_GATE_I
                mask &= gate_mask

            candidates = np.where(mask)[0]
            if candidates.size == 0:
                # Relax gate
                mask2 = alive.copy()
                mask2[pid] = False
                for ex in partners[pid]:
                    mask2[ex] = False
                for cid in np.where(mask2)[0]:
                    if len(partners[int(cid)]) >= TARGET_PARTNERS:
                        mask2[int(cid)] = False
                candidates = np.where(mask2)[0]
                if candidates.size == 0:
                    continue

            r_pid = STORAGE_RATIOS[a_pid]
            r_cands = STORAGE_RATIOS[archetype[candidates]]
            s_vals = np.minimum(r_cands / max(r_pid, _S_EPS), S_CLAMP_MAX)
            s_vals = np.maximum(s_vals, S_CLAMP_MIN)
            t_vals = compute_trust_mult_s(
                p_val[candidates], i_val[candidates], s_vals
            )
            t_vals = np.maximum(t_vals, 0.01)
            probs = t_vals / t_vals.sum()
            n_pick = min(n_needed, candidates.size)
            chosen = rng.choice(candidates, size=n_pick, replace=False, p=probs)
            for cid in chosen:
                cid = int(cid)
                partners[pid].add(cid)
                partners[cid].add(pid)

    # -----------------------------------------------------------------------
    # Main weekly loop
    # -----------------------------------------------------------------------
    for week in range(N_WEEKS):

        # --- 1. Growth ---
        n_active = int(alive.sum())
        if n_active < MAX_NODES:
            if week < 52:
                n_new_target = 20
            elif week < 104:
                n_new_target = 40
            else:
                n_new_target = 25
            n_new = min(n_new_target, MAX_NODES - n_active)
            for _ in range(n_new):
                nid = _alloc()
                if nid is None:
                    break
                _add_node(nid, week)
                atype = int(archetype[nid])
                # Register new HitAndRun arrivals
                if atype == 6:
                    har_total += 1

                # Register bootstrap candidates (honest, joined after week 0)
                if week > 0 and atype < 6:
                    fsz = float(file_size[nid])
                    if 1.0 < fsz <= 5.0 and len(bootstrap_candidates_t1) < BOOTSTRAP_MAX_SAMPLES:
                        bootstrap_candidates_t1.add(nid)
                    elif 5.0 < fsz <= 50.0 and len(bootstrap_candidates_t2) < BOOTSTRAP_MAX_SAMPLES:
                        bootstrap_candidates_t2.add(nid)
                    elif fsz > 50.0 and len(bootstrap_candidates_t3) < BOOTSTRAP_MAX_SAMPLES:
                        bootstrap_candidates_t3.add(nid)

        # --- 2. Churn (natural) ---
        active_ids = np.where(alive)[0]
        if active_ids.size > 0:
            # Do NOT churn HitAndRun nodes via natural churn -- they self-manage
            har_mask = archetype[active_ids] == 6
            non_har = active_ids[~har_mask]
            if non_har.size > 0:
                churn_mask = rng.random(non_har.size) < weekly_churn
                for nid in non_har[churn_mask]:
                    _remove_node(int(nid))

        # --- 3. Weekly check scores ---
        active_ids = np.where(alive)[0]
        if active_ids.size == 0:
            continue

        active_arch = archetype[active_ids]
        week_scores = np.zeros(active_ids.size, dtype=np.float64)

        for atype_idx in range(N_ARCHETYPES):
            grp = np.where(active_arch == atype_idx)[0]
            if grp.size == 0:
                continue
            p_w = float(weekly_pass_probs[atype_idx, week])
            week_scores[grp] = (rng.random(grp.size) < p_w).astype(np.float64)

        # --- 4. Update P circular buffer ---
        pos = p_buf_pos[active_ids]
        p_buf[active_ids, pos] = week_scores
        p_buf_pos[active_ids] = (pos + 1) % pw
        filled = p_buf_filled[active_ids]
        p_buf_filled[active_ids] = np.minimum(filled + 1, pw)

        # --- 5. Update I ---
        i_sum[active_ids] += week_scores
        i_count[active_ids] += 1

        # --- 6. Recompute P and I arrays ---
        p_buf_sum = p_buf[active_ids, :].sum(axis=1)
        pf = p_buf_filled[active_ids].astype(np.float64)
        p_val[active_ids] = np.where(pf > 0, p_buf_sum / pf, 0.0)

        ic = i_count[active_ids].astype(np.float64)
        i_val[active_ids] = np.where(ic > 0, i_sum[active_ids] / ic, 0.0)

        # --- 7. Partnership formation ---
        _update_partnerships(active_ids)

        # --- 8. Shard placement for nodes that have no shards yet ---
        for nid in active_ids:
            nid = int(nid)
            if len(shard_holders[nid]) == 0 and len(partners[nid]) >= 3:
                _place_shards(nid)

        # --- 9. Weekly repair (sample 10% of active nodes to keep sim fast) ---
        if active_ids.size > 0:
            repair_count = max(1, active_ids.size // 10)
            repair_candidates = rng.choice(active_ids, size=min(repair_count, active_ids.size), replace=False)
            for nid in repair_candidates:
                _repair_file(int(nid))

        # --- 10. Bootstrap time tracking ---
        # Record the first week when a newcomer can restore:
        # escrow_off: shards available (>= K alive holders)
        # escrow_on: max(escrow_gate_weeks, shards_available_week)
        def _shards_ready(nid: int) -> bool:
            if len(shard_holders[nid]) < K:
                return False
            return sum(1 for h in shard_holders[nid] if alive[h]) >= K

        for nid in list(bootstrap_candidates_t1 - bootstrap_done_t1):
            if not alive[nid]:
                bootstrap_done_t1.add(nid)
                continue
            weeks_since_join = week - int(join_week[nid])
            shards_ok = _shards_ready(nid)
            escrow_ok = not cfg.escrow_on or weeks_since_join >= ESCROW_TIER1_WEEKS
            if shards_ok and escrow_ok:
                bootstrap_t1.append(float(weeks_since_join))
                bootstrap_done_t1.add(nid)

        for nid in list(bootstrap_candidates_t2 - bootstrap_done_t2):
            if not alive[nid]:
                bootstrap_done_t2.add(nid)
                continue
            weeks_since_join = week - int(join_week[nid])
            shards_ok = _shards_ready(nid)
            escrow_ok = not cfg.escrow_on or weeks_since_join >= ESCROW_TIER2_WEEKS
            if shards_ok and escrow_ok:
                bootstrap_t2.append(float(weeks_since_join))
                bootstrap_done_t2.add(nid)

        for nid in list(bootstrap_candidates_t3 - bootstrap_done_t3):
            if not alive[nid]:
                bootstrap_done_t3.add(nid)
                continue
            weeks_since_join = week - int(join_week[nid])
            shards_ok = _shards_ready(nid)
            escrow_ok = not cfg.escrow_on or weeks_since_join >= ESCROW_TIER3_WEEKS
            if shards_ok and escrow_ok:
                bootstrap_t3.append(float(weeks_since_join))
                bootstrap_done_t3.add(nid)

        # --- 11. HitAndRun logic ---
        har_ids = active_ids[archetype[active_ids] == 6]
        to_remove_har: list[int] = []
        for nid in har_ids:
            nid = int(nid)
            # Already succeeded last iteration -- should have been removed; skip
            if har_succeeded[nid]:
                to_remove_har.append(nid)
                continue

            # Accumulate GB*weeks cost for each active HitAndRun shard
            fsz = float(file_size[nid])
            shard_size_gb = fsz / K
            n_shards_stored = len(shard_holders[nid])
            har_gb_weeks[nid] += n_shards_stored * shard_size_gb

            # Count this as a "live" week for patience
            har_total_weeks[nid] += 1

            # Attempt restore: need k alive shards, and escrow allows it
            restored = False
            if len(shard_holders[nid]) >= K:
                alive_shards = sum(1 for h in shard_holders[nid] if alive[h])
                if alive_shards >= K:
                    weeks_in_net = int(har_total_weeks[nid])
                    if can_restore(fsz, weeks_in_net, cfg.escrow_on):
                        # Restore succeeded
                        har_succeeded[nid] = True
                        har_success_count += 1
                        har_total_gb_weeks += float(har_gb_weeks[nid])
                        restored = True
                        to_remove_har.append(nid)
                    else:
                        # Blocked specifically by escrow gate
                        har_blocked_weeks[nid] += 1

            if not restored:
                # Give up after HAR_PATIENCE_WEEKS total live weeks without success
                if har_total_weeks[nid] >= HAR_PATIENCE_WEEKS:
                    har_total_gb_weeks += float(har_gb_weeks[nid])
                    to_remove_har.append(nid)

        for nid in to_remove_har:
            if alive[nid]:
                _remove_node(nid)

        # --- 12. Retention cohort setup at week 52 ---
        if week == 52:
            for nid in np.where(alive)[0]:
                if int(archetype[nid]) < 6:  # exclude HitAndRun
                    retention_cohort.add(int(nid))

        # --- 13. Retention measurement at week 104 (year 2) ---
        if week == 104 and retention_cohort:
            still_alive = sum(1 for nid in retention_cohort if alive[nid])
            retention_result = still_alive / len(retention_cohort)

        # --- 14. Storage overhead sample (weekly) ---
        if active_ids.size > 0:
            total_actual = 0
            total_files = 0
            sample = rng.choice(active_ids, size=min(50, active_ids.size), replace=False)
            for nid in sample:
                nid = int(nid)
                n_s = len(shard_holders[nid])
                if n_s > 0:
                    total_actual += n_s
                    total_files += 1
            if total_files > 0:
                storage_overhead_samples.append(total_actual / total_files / K)

        # --- 15. Year-end file survival ---
        year = (week + 1) // 52
        if (week + 1) % 52 == 0 and 1 <= year <= N_YEARS:
            active_ids_snap = np.where(alive)[0]
            honest_ids = active_ids_snap[archetype[active_ids_snap] < 6]
            if honest_ids.size > 0:
                survived = 0
                for nid in honest_ids:
                    nid = int(nid)
                    if len(shard_holders[nid]) >= K:
                        alive_s = sum(1 for h in shard_holders[nid] if alive[h])
                        if alive_s >= K:
                            survived += 1
                year_survival[year] = survived / len(honest_ids)
            else:
                year_survival[year] = 0.0

    # -----------------------------------------------------------------------
    # Final HitAndRun accounting: nodes still alive at end (neither succeeded nor gave up)
    # -----------------------------------------------------------------------
    har_ids_final = np.where((alive) & (archetype == 6))[0]
    for nid in har_ids_final:
        nid = int(nid)
        har_total_gb_weeks += float(har_gb_weeks[nid])

    # -----------------------------------------------------------------------
    # Aggregate metrics
    # -----------------------------------------------------------------------
    har_success_rate = har_success_count / max(har_total, 1)
    har_cost_per_attacker = har_total_gb_weeks / max(har_total, 1)

    # Bootstrap: mean weeks to reach threshold (None if no samples)
    bt1 = float(np.mean(bootstrap_t1)) if bootstrap_t1 else float("nan")
    bt2 = float(np.mean(bootstrap_t2)) if bootstrap_t2 else float("nan")
    bt3 = float(np.mean(bootstrap_t3)) if bootstrap_t3 else float("nan")

    storage_overhead = float(np.mean(storage_overhead_samples)) if storage_overhead_samples else float("nan")

    return {
        "har_success_rate": har_success_rate,
        "har_cost_per_attacker": har_cost_per_attacker,
        "bootstrap_tier1_weeks": bt1,
        "bootstrap_tier2_weeks": bt2,
        "bootstrap_tier3_weeks": bt3,
        "file_survival_y1": year_survival.get(1, float("nan")),
        "file_survival_y2": year_survival.get(2, float("nan")),
        "file_survival_y3": year_survival.get(3, float("nan")),
        "storage_overhead": storage_overhead,
        "retention_y1": retention_result if retention_result is not None else float("nan"),
        "har_total": har_total,
    }


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_config(cfg: SimConfig, n_seeds: int, n_jobs: int) -> dict:
    """Run Monte Carlo for one config, return aggregated metrics."""
    t0 = time.time()
    seeds = list(range(n_seeds))

    if n_jobs == 1 or n_seeds == 1:
        runs = [simulate_one(cfg, s) for s in seeds]
    else:
        runs = Parallel(n_jobs=n_jobs)(
            delayed(simulate_one)(cfg, s) for s in seeds
        )

    elapsed = time.time() - t0

    keys = [
        "har_success_rate", "har_cost_per_attacker",
        "bootstrap_tier1_weeks", "bootstrap_tier2_weeks", "bootstrap_tier3_weeks",
        "file_survival_y1", "file_survival_y2", "file_survival_y3",
        "storage_overhead", "retention_y1",
    ]

    agg: dict[str, float] = {}
    for k in keys:
        vals = [r[k] for r in runs if not np.isnan(r[k])]
        agg[k] = float(np.mean(vals)) if vals else float("nan")
        agg[f"{k}_std"] = float(np.std(vals)) if len(vals) > 1 else float("nan")

    agg["har_total_mean"] = float(np.mean([r["har_total"] for r in runs]))
    agg["elapsed_sec"] = elapsed
    agg["n_seeds"] = n_seeds
    return agg


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def _fmt(v: float, pct: bool = False, decimals: int = 1) -> str:
    if np.isnan(v):
        return "  n/a"
    if pct:
        return f"{v*100:.{decimals}f}%"
    return f"{v:.{decimals}f}"


def print_config_result(label: str, description: str, r: dict) -> None:
    print(f"\nConfig {label}: {description}")
    print(f"  HitAndRun success: {_fmt(r['har_success_rate'], pct=True)}")
    print(f"  HitAndRun network cost: {_fmt(r['har_cost_per_attacker'], decimals=1)} GB*weeks per attacker")
    print(f"  Honest bootstrap (Tier 1, <=5GB,  I>=0.1): {_fmt(r['bootstrap_tier1_weeks'], decimals=1)} weeks")
    print(f"  Honest bootstrap (Tier 2, <=50GB, I>=0.3): {_fmt(r['bootstrap_tier2_weeks'], decimals=1)} weeks")
    print(f"  Honest bootstrap (Tier 3, >50GB,  I>=0.5): {_fmt(r['bootstrap_tier3_weeks'], decimals=1)} weeks")
    print(f"  File survival (year 1): {_fmt(r['file_survival_y1'], pct=True)}")
    print(f"  File survival (year 2): {_fmt(r['file_survival_y2'], pct=True)}")
    print(f"  File survival (year 3): {_fmt(r['file_survival_y3'], pct=True)}")
    print(f"  Storage overhead (actual_n / k): {_fmt(r['storage_overhead'], decimals=2)}")
    print(f"  Retention proxy (non-HAR alive at year 2 / alive at year 1): {_fmt(r['retention_y1'], pct=True)}")


def print_comparison(results: dict[str, dict]) -> None:
    print("\n=== COMPARISON ===")

    # Best for honest users = highest file_survival_y3
    best_survival = max(results.items(), key=lambda kv: kv[1].get("file_survival_y3", 0.0))
    print(f"Best file survival at year 3: Config {best_survival[0]} ({_fmt(best_survival[1]['file_survival_y3'], pct=True)})")

    # Best against hit-and-run = lowest har_success_rate
    best_against_har = min(results.items(), key=lambda kv: kv[1].get("har_success_rate", 1.0))
    print(f"Best against HitAndRun: Config {best_against_har[0]} ({_fmt(best_against_har[1]['har_success_rate'], pct=True)} success rate)")

    # Fastest bootstrap tier 2 (most practically relevant: 10GB photos tier)
    bt2_valid = {k: v for k, v in results.items() if not np.isnan(v.get("bootstrap_tier2_weeks", float("nan")))}
    if bt2_valid:
        best_boot = min(bt2_valid.items(), key=lambda kv: kv[1]["bootstrap_tier2_weeks"])
        print(f"Fastest Tier 2 bootstrap: Config {best_boot[0]} ({_fmt(best_boot[1]['bootstrap_tier2_weeks'], decimals=1)} weeks)")

    # Storage efficiency: lowest overhead
    best_overhead = min(results.items(), key=lambda kv: kv[1].get("storage_overhead", float("inf")))
    print(f"Lowest storage overhead: Config {best_overhead[0]} ({_fmt(best_overhead[1]['storage_overhead'], decimals=2)}x k)")

    # Diagnosis
    print()
    har_A = results["A"].get("har_success_rate", float("nan"))
    har_B = results["B"].get("har_success_rate", float("nan"))
    har_C = results["C"].get("har_success_rate", float("nan"))
    har_D = results["D"].get("har_success_rate", float("nan"))

    if not np.isnan(har_A) and not np.isnan(har_B):
        delta_escrow = har_A - har_B
        print(f"Escrow effect (A->B): HAR success reduced by {delta_escrow*100:.1f} pp")
    if not np.isnan(har_A) and not np.isnan(har_C):
        delta_adap = har_A - har_C
        print(f"Adaptive-n effect (A->C): HAR success changed by {delta_adap*100:.1f} pp")
    if not np.isnan(har_B) and not np.isnan(har_D):
        delta_combo = har_B - har_D
        print(f"Combined vs escrow-only (B->D): HAR success changed by {delta_combo*100:.1f} pp")

    surv_A = results["A"].get("file_survival_y3", float("nan"))
    surv_C = results["C"].get("file_survival_y3", float("nan"))
    if not np.isnan(surv_A) and not np.isnan(surv_C):
        delta_surv = surv_C - surv_A
        print(f"Adaptive-n effect on survival (A->C): {delta_surv*100:+.1f} pp at year 3")


def save_results(all_results: dict, output_dir: Path, n_seeds: int) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "pis_escrow_results.json"

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

    payload = {
        "experiment": 24,
        "n_seeds": n_seeds,
        "n_years": N_YEARS,
        "max_nodes": MAX_NODES,
        "trust_formula": "multiplicative_S: (0.5*P + 2.0*I) * clamp(S, 0.1, 1.0)",
        "configs": _convert(all_results),
    }
    path.write_text(json.dumps(payload, indent=2))
    print(f"\nResults saved to {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SyncBack Experiment 24: Escrow as Credit System"
    )
    parser.add_argument("--seeds", type=int, default=10, help="Monte Carlo seeds per config")
    parser.add_argument("--jobs", type=int, default=1, help="Parallel jobs")
    parser.add_argument(
        "--output", type=str, default="results/pis_escrow",
        help="Output directory for JSON results"
    )
    args = parser.parse_args()

    print("=== SYNCBACK EXPERIMENT 24: ESCROW AS CREDIT SYSTEM ===")
    print(f"Network: {MAX_NODES} nodes, {N_YEARS} years ({N_WEEKS} weeks)")
    print(f"Trust: multiplicative S -- (0.5*P + 2.0*I) * clamp(S, 0.1, 1.0)")
    print(f"7 archetypes including HitAndRun (15% of arrivals, 10GB file, 0% storage)")
    print(f"Seeds: {args.seeds}, Jobs: {args.jobs}")
    print()

    configs = [
        (SimConfig(escrow_on=False, adaptive_n_on=False, label="A"), "No escrow, fixed n=15"),
        (SimConfig(escrow_on=True,  adaptive_n_on=False, label="B"), "Escrow ON, fixed n=15"),
        (SimConfig(escrow_on=False, adaptive_n_on=True,  label="C"), "No escrow, adaptive n"),
        (SimConfig(escrow_on=True,  adaptive_n_on=True,  label="D"), "Escrow ON, adaptive n"),
    ]

    all_results: dict[str, dict] = {}

    for cfg, description in configs:
        print(f"Running Config {cfg.label}: {description} ...", flush=True)
        t0 = time.time()
        result = run_config(cfg, n_seeds=args.seeds, n_jobs=args.jobs)
        elapsed = time.time() - t0
        all_results[cfg.label] = result
        all_results[cfg.label]["description"] = description
        print(f"  Done in {elapsed:.1f}s", flush=True)
        print_config_result(cfg.label, description, result)

    print_comparison(all_results)
    save_results(all_results, Path(args.output), args.seeds)


if __name__ == "__main__":
    main()
