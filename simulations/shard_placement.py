"""
SyncBack Experiment 27 v2: Shard Placement in a Saturated Network

Two scenarios, four hysteresis strategies. The key fix from v1: the network
starts pre-filled (85-95% utilization), so every placement attempt immediately
competes for scarce space and evictions actually happen.

v2 design fixes:
  - Pre-fill creates MULTIPLE entries per holder (one per source-data-chunk),
    not one aggregate entry per owner. This means old and new data compete
    correctly on the same holder.
  - Established nodes place weekly dirty data as NEW entries (new chunk_id),
    not merged into an existing entry. Every week's dirty data is a distinct
    placement event that must displace something.
  - _try_place_on evicts as many lowest-priority entries as needed to free
    enough space for new_gb, not just one. This makes cascades proportional
    to how full the network is.
  - Pre-fill amounts per holder are validated: sum(stored) ≈ 85-95% of
    offered_gb, not a thin slice per partner.

Scenarios:
  1: Saturated steady-state — 200 established nodes, storage ~90% full,
     52 weeks of new dirty data competing for space. Do cascades happen?
     Does coverage degrade for established nodes?

  2: Newcomer burst — same saturated network, a newcomer with 500 GB joins
     every 4 weeks and uploads 30 GB/week (bandwidth-limited). How fast does
     the newcomer reach 50%/80%/100% coverage? How much do established nodes
     lose?

Hysteresis strategies (tested in both scenarios):
  A: No hysteresis (evict if new_priority > min_priority)
  B: Threshold hysteresis (need 20% higher priority to evict)
  C: Time-based hysteresis (age bonus up to +30%)
  D: Combined (B+C)

Offer ratios sweep: [1.0, 1.5, 2.0, 3.0]

Usage:
    python shard_placement.py --scenario all --seeds 5 --jobs 12
    python shard_placement.py --scenario 1 --seeds 3 --jobs 4
    python shard_placement.py --scenario 1,2 --seeds 2 --offer-ratios 1.0,1.5,2.0
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


# ---------------------------------------------------------------------------
# Archetype definitions (6 honest + HitAndRun, same as other sims)
# ---------------------------------------------------------------------------

ARCHETYPE_NAMES = [
    "Reliable",    # 0
    "Weekend",     # 1
    "Seasonal",    # 2
    "Nomad",       # 3
    "Hoarder",     # 4
    "Freeloader",  # 5
    "HitAndRun",   # 6
]
N_ARCHETYPES = len(ARCHETYPE_NAMES)
N_HONEST_ARCHETYPES = 6

# Storage contribution ratio per archetype (affects S score, not physical capacity)
STORAGE_RATIOS = np.array([1.0, 1.0, 1.0, 1.0, 0.2, 0.1, 0.0], dtype=np.float64)

ARCHETYPE_PROBS = np.array([0.30, 0.20, 0.12, 0.08, 0.10, 0.05, 0.15])


# ---------------------------------------------------------------------------
# Trust formula constants (FINAL: confirmed across experiments)
# ---------------------------------------------------------------------------

KP = 0.5
KI = 2.0
S_CLAMP_MIN = 0.1
S_CLAMP_MAX = 1.0
_S_EPS = 0.01
_MAX_TRUST = (KP + KI) * 1.0  # = 2.5


# ---------------------------------------------------------------------------
# Erasure coding parameters
# ---------------------------------------------------------------------------

K = 5                    # minimum shards for recovery
N_HIGH_IMPORTANCE = 15   # n for high-importance data (importance > 0.7)
N_LOW_IMPORTANCE = 5     # n for low-importance data (importance <= 0.3)


# ---------------------------------------------------------------------------
# Network parameters
# ---------------------------------------------------------------------------

N_NODES = 200
N_SIM_WEEKS = 52         # simulate 52 more weeks after bootstrap
TARGET_PARTNERS = 15
NEWCOMER_INTERVAL = 4    # scenario 2: newcomer joins every N weeks
MAX_CASCADE_DEPTH = 10   # hard limit to prevent infinite loops

NEWCOMER_BANDWIDTH_GB = 30.0  # GB/week max upload for new nodes

# Hysteresis parameters
THRESHOLD_H = 0.2        # strategy B: need 20% higher priority to evict
TIME_BONUS_MAX = 0.30    # strategy C: up to +30% bonus for old shards
TIME_BONUS_WEEKS = 26    # strategy C: full bonus after 26 weeks

# Data size distribution
DATA_GB_MEAN = 500.0
DATA_GB_STD = 200.0
DATA_GB_MIN = 50.0

# Weekly new dirty data per node (GB)
DIRTY_GB_MEAN = 5.0
DIRTY_GB_STD = 2.0

# Pre-fill target: fraction of capacity to fill during bootstrap
# Each holder should end up with ~90% utilization
PREFILL_TARGET = 0.90

# Importance distribution: beta(2, 1.5) gives mean ~0.57 with heavy upper tail
IMPORTANCE_DIST_ALPHA = 2.0
IMPORTANCE_DIST_BETA = 1.5

# Offer ratios to sweep (v2: drop 0.5 and 2.5 for speed)
OFFER_RATIOS_DEFAULT = [1.0, 1.5, 2.0, 3.0]

# Pre-fill chunk size: each stored entry represents this many GB of source data.
# Smaller = more fine-grained eviction decisions, more realistic.
# 20 GB per chunk gives ~20-30 entries per holder at 90% fill with 500GB data.
PREFILL_CHUNK_GB = 20.0

# Chunk id counter namespace: use a mutable wrapper so inner functions can modify it
_CHUNK_ID_START = 10_000_000  # distinguish prefill chunks from node ids


# ---------------------------------------------------------------------------
# Weekly pass probabilities per archetype
# ---------------------------------------------------------------------------

def _build_weekly_pass_probs(n_weeks: int) -> np.ndarray:
    """Precompute P(online during week) per archetype per week. Shape: (N_ARCHETYPES, n_weeks)."""
    week_idx = np.arange(n_weeks)
    week_in_year = week_idx % 52
    probs = np.zeros((N_ARCHETYPES, n_weeks), dtype=np.float64)

    probs[0, :] = 1.0 - (1.0 - 0.99) ** 7
    p_fail_we = (1.0 - 0.95) ** 3 * (1.0 - 0.30) ** 4
    probs[1, :] = 1.0 - p_fail_we
    is_summer = (week_in_year >= 22) & (week_in_year <= 35)
    r_seasonal = np.where(is_summer, 0.20, 0.95)
    probs[2, :] = 1.0 - (1.0 - r_seasonal) ** 7
    probs[3, :] = 0.50
    probs[4, :] = 1.0 - (1.0 - 0.90) ** 7
    probs[5, :] = 1.0 - (1.0 - 0.80) ** 7
    probs[6, :] = 1.0 - (1.0 - 0.80) ** 7

    return probs


# ---------------------------------------------------------------------------
# Adaptive n based on importance score
# ---------------------------------------------------------------------------

def importance_to_n(importance: float) -> int:
    """Map importance [0, 1] to n shards via linear interpolation."""
    n_float = N_LOW_IMPORTANCE + importance * (N_HIGH_IMPORTANCE - N_LOW_IMPORTANCE)
    return max(K, int(round(n_float)))


# ---------------------------------------------------------------------------
# Trust helpers
# ---------------------------------------------------------------------------

def _trust_full(
    p_b: float | np.ndarray,
    i_b: float | np.ndarray,
    s_ab: float | np.ndarray,
) -> float | np.ndarray:
    """trust = (KP*P + KI*I) * clamp(S, 0.1, 1.0)"""
    return (KP * p_b + KI * i_b) * np.clip(s_ab, S_CLAMP_MIN, S_CLAMP_MAX)


def _pairwise_s(r_obs: float, r_tgt: float) -> float:
    """S_AB = r_tgt / max(r_obs, eps)"""
    return r_tgt / max(r_obs, _S_EPS)


# ---------------------------------------------------------------------------
# Simulation configuration
# ---------------------------------------------------------------------------

@dataclass
class Config:
    """All parameters for one simulation run."""
    label: str                          # "A", "B", "C", "D", or "E"
    scenario: int                       # 1 or 2
    offer_ratio: float                  # offered_gb = data_gb * offer_ratio
    threshold_hysteresis: bool = False  # strategy B, D, or E
    time_hysteresis: bool = False       # strategy C, D, or E
    budget_aware: bool = False          # strategy E: skip placement if < K partners will accept
    n_nodes: int = N_NODES
    n_sim_weeks: int = N_SIM_WEEKS
    target_partners: int = TARGET_PARTNERS


# ---------------------------------------------------------------------------
# Storage entry key type
# ---------------------------------------------------------------------------
# stored_for[holder_id] maps (owner_id, chunk_id) -> (gb, importance, week_placed)
# chunk_id distinguishes multiple chunks from the same owner.
# For weekly dirty data: chunk_id = week number (0..51).
# For pre-filled data: chunk_id = _CHUNK_ID_START + sequential counter.
# This ensures each weekly placement is a distinct eviction candidate.

StoredKey = tuple[int, int]   # (owner_id, chunk_id)
StoredEntry = tuple[float, float, int]  # (gb, importance, week_placed)


# ---------------------------------------------------------------------------
# Core simulation
# ---------------------------------------------------------------------------

def simulate_one(config: Config, seed: int) -> dict:
    """
    Run one full simulation under the given Config and seed.

    Storage model (GB-level aggregates, multiple chunks per owner per holder):
      stored_for[holder][(owner_id, chunk_id)] = (gb, importance, week_placed)
      week_placed is negative for pre-filled data (weeks -52..0)
      priority = importance * trust_of_owner (from holder's perspective)

    The multi-chunk model is the critical fix from v1: each weekly placement
    is a distinct entry, so old low-priority data genuinely competes with
    new high-priority data. Without this, updates to existing entries bypass
    the eviction logic entirely.

    Returns dict with weekly metrics and aggregate statistics.
    """
    rng = np.random.default_rng(seed)

    n_sim_weeks = config.n_sim_weeks
    # Extra capacity for newcomers in scenario 2
    newcomer_slots = (n_sim_weeks // NEWCOMER_INTERVAL + 10) if config.scenario == 2 else 10
    cap = config.n_nodes + newcomer_slots + 20

    # -----------------------------------------------------------------------
    # Node state arrays
    # -----------------------------------------------------------------------
    alive = np.zeros(cap, dtype=bool)
    archetype = np.full(cap, -1, dtype=np.int8)
    join_week = np.full(cap, -1, dtype=np.int32)

    # Trust components
    pw = 4  # P rolling window (4 weeks)
    p_buf = np.zeros((cap, pw), dtype=np.float64)
    p_buf_pos = np.zeros(cap, dtype=np.int32)
    p_buf_filled = np.zeros(cap, dtype=np.int32)
    i_sum = np.zeros(cap, dtype=np.float64)
    i_count = np.zeros(cap, dtype=np.int32)
    p_val = np.zeros(cap, dtype=np.float64)
    i_val = np.zeros(cap, dtype=np.float64)

    # Per-node backup data
    data_gb = np.zeros(cap, dtype=np.float64)
    offered_gb = np.zeros(cap, dtype=np.float64)
    importance = np.zeros(cap, dtype=np.float64)

    # stored_for[nid][(owner_id, chunk_id)] = (gb, importance, week_placed)
    # Multiple chunks per owner allowed — each is a separate eviction candidate
    stored_for: list[dict[StoredKey, StoredEntry]] = [{} for _ in range(cap)]

    # Performance cache: total GB stored on each holder node.
    # Maintained incrementally so _total_stored(n) = stored_total[n] is O(1).
    stored_total = np.zeros(cap, dtype=np.float64)

    # Performance cache: for each owner, the sum of (shard_gb * K/n) across all
    # holders. This equals "recoverable GB" for coverage calculation.
    # K/n factor makes it independent of the RS fanout: coverage = coverage_gb / data_gb.
    coverage_gb = np.zeros(cap, dtype=np.float64)

    # Partnerships: bidirectional
    partners: list[set[int]] = [set() for _ in range(cap)]

    # Established vs newcomer classification
    established = np.zeros(cap, dtype=bool)

    # Bandwidth remaining this week for newcomers (reset each week)
    bw_remaining = np.zeros(cap, dtype=np.float64)

    # Chunk id counter for pre-fill (each pre-fill entry gets a unique id)
    prefill_chunk_counter: list[int] = [_CHUNK_ID_START]

    # For scenario 2: track coverage milestones per newcomer
    newcomer_milestones: dict[int, dict[str, Optional[int]]] = {}
    newcomer_join_weeks: dict[int, int] = {}

    # Weekly metrics
    weekly_placement_success: list[float] = []
    weekly_eviction_counts: list[int] = []
    weekly_cascade_depths: list[list[int]] = []
    weekly_storage_utilization: list[float] = []
    weekly_coverage_established: list[float] = []
    weekly_coverage_newcomers: list[float] = []
    weekly_data_loss_gb: list[float] = []

    cumulative_data_loss = 0.0

    # All cascade depths for histogram
    all_cascade_depths: list[int] = []

    # Precompute pass probs for bootstrap + sim
    total_weeks_needed = 52 + n_sim_weeks + 10
    weekly_pass_probs = _build_weekly_pass_probs(total_weeks_needed)

    next_id = 0
    free_ids: list[int] = []

    # Current simulation week (negative during bootstrap, 0..n_sim_weeks during sim)
    current_week: list[int] = [-52]

    def _alloc() -> Optional[int]:
        nonlocal next_id
        if free_ids:
            return free_ids.pop()
        if next_id < cap:
            nid = next_id
            next_id += 1
            return nid
        return None

    def _sample_data_gb() -> float:
        val = rng.normal(DATA_GB_MEAN, DATA_GB_STD)
        return max(DATA_GB_MIN, val)

    def _sample_importance() -> float:
        return float(np.clip(rng.beta(IMPORTANCE_DIST_ALPHA, IMPORTANCE_DIST_BETA), 0.01, 1.0))

    def _add_node(nid: int, week: int, atype: Optional[int] = None, is_newcomer: bool = False) -> None:
        if atype is None:
            atype = int(rng.choice(N_ARCHETYPES, p=ARCHETYPE_PROBS))
        archetype[nid] = atype
        alive[nid] = True
        join_week[nid] = week
        established[nid] = not is_newcomer
        p_buf[nid, :] = 0.0
        p_buf_pos[nid] = 0
        p_buf_filled[nid] = 0
        i_sum[nid] = 0.0
        i_count[nid] = 0
        p_val[nid] = 0.0
        i_val[nid] = 0.0
        d = _sample_data_gb()
        data_gb[nid] = d
        offered_gb[nid] = d * config.offer_ratio
        importance[nid] = _sample_importance()
        stored_for[nid] = {}
        stored_total[nid] = 0.0
        # coverage_gb[nid] stays 0 — nothing stored yet
        partners[nid] = set()
        bw_remaining[nid] = NEWCOMER_BANDWIDTH_GB if is_newcomer else float("inf")

    def _remove_node(nid: int) -> None:
        """Remove node. Data stored BY this node for others is lost (churn)."""
        alive[nid] = False
        # Update coverage_gb for owners whose shards were on this node
        n_nid = importance_to_n(float(importance[nid]))  # not used for coverage calc below
        for (owner_id, _cid), (gb, _imp, _wp) in stored_for[nid].items():
            n_owner = importance_to_n(float(importance[owner_id]))
            coverage_gb[owner_id] -= gb * K / n_owner
            if coverage_gb[owner_id] < 0:
                coverage_gb[owner_id] = 0.0
        stored_total[nid] = 0.0
        for pid in list(partners[nid]):
            partners[pid].discard(nid)
        partners[nid].clear()
        stored_for[nid] = {}
        free_ids.append(nid)
        _ = n_nid  # suppress unused

    def _total_stored(nid: int) -> float:
        """O(1) lookup via maintained cache."""
        return float(stored_total[nid])

    def _store_put(holder: int, key: StoredKey, entry: StoredEntry) -> None:
        """Insert/overwrite an entry and update caches."""
        gb, _imp, _wp = entry
        owner_id = key[0]
        n_owner = importance_to_n(float(importance[owner_id]))
        # If key already exists, adjust delta
        if key in stored_for[holder]:
            old_gb = stored_for[holder][key][0]
            stored_total[holder] += gb - old_gb
            coverage_gb[owner_id] += (gb - old_gb) * K / n_owner
        else:
            stored_total[holder] += gb
            coverage_gb[owner_id] += gb * K / n_owner
        stored_for[holder][key] = entry

    def _store_pop(holder: int, key: StoredKey) -> StoredEntry:
        """Remove an entry and update caches. Caller guarantees key exists."""
        entry = stored_for[holder].pop(key)
        gb, _imp, _wp = entry
        owner_id = key[0]
        n_owner = importance_to_n(float(importance[owner_id]))
        stored_total[holder] -= gb
        if stored_total[holder] < 0:
            stored_total[holder] = 0.0
        coverage_gb[owner_id] -= gb * K / n_owner
        if coverage_gb[owner_id] < 0:
            coverage_gb[owner_id] = 0.0
        return entry

    # Per-week trust cache: trust_cache[(observer, target)] = float
    # Valid only within the current simulation week (cleared at start of each week).
    trust_cache: dict[tuple[int, int], float] = {}

    def _node_trust(observer: int, target: int) -> float:
        """Compute trust of 'target' from 'observer' perspective (cached per week)."""
        pair = (observer, target)
        cached = trust_cache.get(pair)
        if cached is not None:
            return cached
        r_obs = float(STORAGE_RATIOS[int(archetype[observer])])
        r_tgt = float(STORAGE_RATIOS[int(archetype[target])])
        s = _pairwise_s(r_obs, r_tgt)
        val = max(float(_trust_full(float(p_val[target]), float(i_val[target]), s)), 0.001)
        trust_cache[pair] = val
        return val

    def _entry_priority(
        holder: int,
        owner: int,
        imp: float,
        week_placed: int,
        current_w: int,
    ) -> float:
        """Priority for a stored entry. Higher = harder to evict."""
        trust = _node_trust(holder, owner)
        base_priority = imp * trust
        if config.time_hysteresis:
            age_weeks = max(0, current_w - week_placed)
            time_bonus = min(age_weeks / TIME_BONUS_WEEKS, 1.0) * TIME_BONUS_MAX
            base_priority *= (1.0 + time_bonus)
        return base_priority

    def _estimate_accepting_partners(
        nid: int,
        shard_gb: float,
        imp: float,
        current_w: int,
    ) -> int:
        """
        Budget Planner: estimate how many partners would accept a shard.
        Checks free space first, then whether eviction would succeed.
        Returns count of partners likely to accept.
        """
        n_accepting = 0
        for p in partners[nid]:
            if not alive[p]:
                continue
            free = float(offered_gb[p]) - _total_stored(p)
            if free >= shard_gb:
                n_accepting += 1
                continue
            # Would need eviction — check if we can beat the worst entry
            if not stored_for[p]:
                continue
            our_prio = imp * _node_trust(p, nid)
            # Time hysteresis makes existing entries harder to evict,
            # so the budget estimate accounts for it automatically via _entry_priority
            min_prio = float("inf")
            evictable_gb = 0.0
            for key_e, entry_e in stored_for[p].items():
                gb_e, imp_e, wp_e = entry_e
                prio_e = _entry_priority(p, key_e[0], imp_e, wp_e, current_w)
                if prio_e < our_prio:
                    if prio_e < min_prio:
                        min_prio = prio_e
                    evictable_gb += gb_e
            threshold_factor = (1.0 + THRESHOLD_H) if config.threshold_hysteresis else 1.0
            need_to_free = shard_gb - max(free, 0.0)
            if (
                min_prio < float("inf")
                and our_prio > min_prio * threshold_factor
                and evictable_gb >= need_to_free
            ):
                n_accepting += 1
        return n_accepting

    def _try_place_on(
        holder: int,
        new_owner: int,
        new_chunk_id: int,
        new_gb: float,
        new_imp: float,
        current_w: int,
        depth: int,
    ) -> tuple[bool, int, int, float]:
        """
        Attempt to place new_gb for new_owner (chunk new_chunk_id) on holder.
        Returns (success, evictions_caused, max_cascade_depth, data_lost_gb).

        Key fix from v1: we evict as many entries as needed to free new_gb,
        not just one. Each evicted chunk tries to re-place on other partners
        (cascade). If the network is truly full, cascades propagate.

        Threshold hysteresis: all candidates for eviction must have priority
        below new_priority / (1 + THRESHOLD_H). If even the worst entry
        has higher priority, placement fails.
        """
        if depth > MAX_CASCADE_DEPTH:
            return False, 0, depth, 0.0

        capacity = float(offered_gb[holder])
        current = _total_stored(holder)
        free_space = capacity - current

        if free_space >= new_gb:
            # Direct fit: no eviction needed
            _store_put(holder, (new_owner, new_chunk_id), (new_gb, new_imp, current_w))
            return True, 0, depth, 0.0

        # Holder is (nearly) full: must evict to make room
        if not stored_for[holder]:
            # Degenerate: no entries to evict but capacity exhausted (shouldn't happen)
            return False, 0, depth, 0.0

        # Compute new data's priority from holder's perspective
        new_trust = _node_trust(holder, new_owner)
        new_priority = new_imp * new_trust

        # Sort all entries by priority (ascending: evict lowest first)
        entries_sorted: list[tuple[float, StoredKey, StoredEntry]] = []
        for key, entry in stored_for[holder].items():
            gb_e, imp_e, wp_e = entry
            owner_e = key[0]
            prio = _entry_priority(holder, owner_e, imp_e, wp_e, current_w)
            entries_sorted.append((prio, key, entry))
        entries_sorted.sort(key=lambda x: x[0])  # ascending: worst first

        # Threshold: the new data must be significantly better than what it evicts
        threshold_factor = (1.0 + THRESHOLD_H) if config.threshold_hysteresis else 1.0

        # Check if the lowest-priority entry can be evicted by new data
        min_prio_existing = entries_sorted[0][0]
        if new_priority <= min_prio_existing * threshold_factor:
            # Even the worst entry has equal or better priority: placement fails
            return False, 0, depth, 0.0

        # Evict entries (lowest priority first) until we have enough space
        # We only evict entries with priority < new_priority / threshold_factor
        eviction_count = 0
        data_lost = 0.0
        max_depth_seen = depth
        freed_so_far = free_space

        # Collect eviction candidates up front (before any mutation).
        # We evict lowest-priority entries until we have freed enough space.
        # Only include entries whose priority is clearly below new_priority.
        to_evict: list[tuple[StoredKey, StoredEntry]] = []
        for prio_e, key_e, entry_e in entries_sorted:
            if freed_so_far >= new_gb:
                break
            if prio_e * threshold_factor >= new_priority:
                # This entry is too valuable to evict — give up
                break
            to_evict.append((key_e, entry_e))
            freed_so_far += entry_e[0]  # gb

        if freed_so_far < new_gb:
            # Cannot free enough space without violating priority constraint
            return False, eviction_count, max_depth_seen, data_lost

        # Now perform evictions.  Re-check key existence: a deep cascade
        # triggered by an earlier eviction in this same loop could have
        # already deleted a key (e.g. a replacement chain landed back here).
        for key_e, entry_e in to_evict:
            if key_e not in stored_for[holder]:
                # Already gone (cascade side-effect); still counts as freed space
                continue
            evicted_entry = _store_pop(holder, key_e)
            gb_e, imp_e, _ = evicted_entry
            owner_e = key_e[0]
            eviction_count += 1

            # Evicted owner tries to re-place elsewhere (cascade)
            if alive[owner_e] and depth < MAX_CASCADE_DEPTH:
                other_partners = [
                    p for p in partners[owner_e]
                    if p != holder and alive[p]
                ]
                rng.shuffle(other_partners)
                re_placed = False
                for alt_holder in other_partners[:6]:
                    ok, sub_ev, sub_d, sub_lost = _try_place_on(
                        alt_holder, owner_e, key_e[1],
                        gb_e, imp_e, current_w, depth + 1,
                    )
                    eviction_count += sub_ev
                    max_depth_seen = max(max_depth_seen, sub_d)
                    data_lost += sub_lost
                    if ok:
                        re_placed = True
                        break
                if not re_placed:
                    data_lost += gb_e
            else:
                data_lost += gb_e

        # Verify we actually have the space (cascade might have added entries back)
        current_after = float(stored_total[holder])
        if float(offered_gb[holder]) - current_after < new_gb:
            # Space was consumed by cascade side-effect; give up placing
            return False, eviction_count, max_depth_seen, data_lost

        # Place new data
        _store_put(holder, (new_owner, new_chunk_id), (new_gb, new_imp, current_w))
        return True, eviction_count, max_depth_seen, data_lost

    def _place_data_for(
        nid: int,
        gb_to_place: float,
        chunk_id: int,
        current_w: int,
        bw_limit: float = float("inf"),
    ) -> tuple[int, int, int, float, float]:
        """
        Distribute gb_to_place of nid's data (as a new chunk) across partners.
        Each partner gets one shard (gb_to_place / n_shards).
        Returns (attempts, successes, total_evictions, data_lost_gb, gb_placed).
        """
        gb_to_place = min(gb_to_place, bw_limit)
        if gb_to_place <= 0:
            return 0, 0, 0, 0.0, 0.0

        available_partners = [p for p in partners[nid] if alive[p]]
        if not available_partners:
            return 1, 0, 0, 0.0, 0.0

        n_shards = importance_to_n(float(importance[nid]))
        gb_per_shard = gb_to_place / n_shards
        imp = float(importance[nid])

        # Sort partners by trust (highest first)
        trust_scores = np.array(
            [_node_trust(nid, p) for p in available_partners], dtype=np.float64
        )
        order = np.argsort(-trust_scores)
        sorted_partners = [available_partners[i] for i in order]

        targets = sorted_partners[:n_shards]
        if len(targets) < K:
            return n_shards, 0, 0, 0.0, 0.0

        attempts = 0
        successes = 0
        total_evictions = 0
        total_lost = 0.0
        total_placed_gb = 0.0

        for holder in targets:
            attempts += 1
            ok, evictions, cascade_d, lost = _try_place_on(
                holder, nid, chunk_id, gb_per_shard, imp, current_w, depth=0
            )
            all_cascade_depths.append(cascade_d)
            if ok:
                successes += 1
                total_placed_gb += gb_per_shard
            total_evictions += evictions
            total_lost += lost

        return attempts, successes, total_evictions, total_lost, total_placed_gb

    def _update_partnerships(active_ids: np.ndarray) -> None:
        """Trust-weighted partnership formation for underfull nodes."""
        on_count = np.array(
            [len(partners[int(nid)]) for nid in active_ids], dtype=np.int32
        )
        underfull_mask = on_count < config.target_partners
        underfull = active_ids[underfull_mask]
        if underfull.size == 0:
            return
        if underfull.size > 300:
            underfull = rng.choice(underfull, size=300, replace=False)

        active_set = set(int(x) for x in active_ids)

        for pid_raw in underfull:
            pid = int(pid_raw)
            n_needed = config.target_partners - len(partners[pid])
            if n_needed <= 0:
                continue
            candidates = [
                c for c in active_set
                if c != pid
                and c not in partners[pid]
                and len(partners[c]) < config.target_partners
            ]
            if not candidates:
                continue
            arr = np.array(candidates, dtype=np.int32)
            r_obs = float(STORAGE_RATIOS[int(archetype[pid])])
            r_cands = STORAGE_RATIOS[archetype[arr]]
            s_vals = np.clip(r_cands / max(r_obs, _S_EPS), S_CLAMP_MIN, S_CLAMP_MAX)
            t_vals = np.maximum(
                (KP * p_val[arr] + KI * i_val[arr]) * s_vals, 0.001
            )
            probs = t_vals / t_vals.sum()
            n_pick = min(n_needed, len(candidates))
            chosen = rng.choice(arr, size=n_pick, replace=False, p=probs)
            for cid_raw in chosen:
                cid = int(cid_raw)
                partners[pid].add(cid)
                partners[cid].add(pid)

    def _compute_coverage(active_arr: np.ndarray) -> tuple[float, float]:
        """
        Compute mean weighted coverage for established and newcomer nodes.
        Uses the maintained coverage_gb cache: O(N) not O(N * chunks_per_node).
        Coverage = coverage_gb[nid] / data_gb[nid], clipped to [0, 1].

        Returns (mean_established_coverage, mean_newcomer_coverage).
        """
        est_ids = active_arr[established[active_arr]]
        new_ids = active_arr[~established[active_arr]]

        def _mean_cov(ids: np.ndarray) -> float:
            if ids.size == 0:
                return float("nan")
            fracs = np.minimum(coverage_gb[ids] / np.maximum(data_gb[ids], 1.0), 1.0)
            return float(fracs.mean())

        return _mean_cov(est_ids), _mean_cov(new_ids)

    # -----------------------------------------------------------------------
    # Bootstrap phase: simulate 52 weeks of trust build-up for established nodes
    # -----------------------------------------------------------------------
    for _ in range(config.n_nodes):
        nid = _alloc()
        if nid is not None:
            _add_node(nid, -52, is_newcomer=False)

    bootstrap_weeks = 52
    for bwk in range(bootstrap_weeks):
        abs_week = -52 + bwk
        current_week[0] = abs_week
        active_ids = np.where(alive)[0]
        if active_ids.size == 0:
            continue
        active_arch = archetype[active_ids]
        week_scores = np.zeros(active_ids.size, dtype=np.float64)
        for atype_idx in range(N_ARCHETYPES):
            grp = np.where(active_arch == atype_idx)[0]
            if grp.size == 0:
                continue
            p_w = float(weekly_pass_probs[atype_idx, bwk])
            week_scores[grp] = (rng.random(grp.size) < p_w).astype(np.float64)
        pos = p_buf_pos[active_ids]
        p_buf[active_ids, pos] = week_scores
        p_buf_pos[active_ids] = (pos + 1) % pw
        filled = p_buf_filled[active_ids]
        p_buf_filled[active_ids] = np.minimum(filled + 1, pw)
        i_sum[active_ids] += week_scores
        i_count[active_ids] += 1
        p_buf_sum = p_buf[active_ids, :].sum(axis=1)
        pf = p_buf_filled[active_ids].astype(np.float64)
        p_val[active_ids] = np.where(pf > 0, p_buf_sum / pf, 0.0)
        ic = i_count[active_ids].astype(np.float64)
        i_val[active_ids] = np.where(ic > 0, i_sum[active_ids] / ic, 0.0)

        if bwk % 4 == 3:
            _update_partnerships(active_ids)

    # -----------------------------------------------------------------------
    # Pre-fill: fill all holders to ~90% capacity with realistic past data
    # -----------------------------------------------------------------------
    # Strategy: for each holder, fill it with chunks from its partners,
    # proportional to trust^2 (same as weighted placement protocol).
    # Each chunk is PREFILL_CHUNK_GB large (not one aggregate per owner).
    # week_placed is uniformly distributed in [-52, -1] for age diversity.
    #
    # This gives realistic per-entry granularity: old chunks from the same
    # owner compete against each other and against new data.

    active_ids = np.where(alive)[0]
    _update_partnerships(active_ids)  # ensure partnerships are formed

    for holder_raw in active_ids:
        holder = int(holder_raw)
        target_fill = float(offered_gb[holder]) * PREFILL_TARGET
        holder_partners = [p for p in partners[holder] if alive[p]]
        if not holder_partners:
            continue

        trust_scores_arr = np.array(
            [_node_trust(holder, p) for p in holder_partners], dtype=np.float64
        )
        weights = trust_scores_arr ** 2
        if weights.sum() < 1e-9:
            weights = np.ones(len(holder_partners))
        weights /= weights.sum()

        # Allocate target_fill proportionally across partners
        allocs = weights * target_fill

        for partner_idx, owner in enumerate(holder_partners):
            total_for_owner = float(allocs[partner_idx])
            if total_for_owner < 0.01:
                continue
            imp_owner = float(importance[owner])

            # Split into PREFILL_CHUNK_GB chunks
            remaining = total_for_owner
            while remaining > 0.01:
                chunk_gb = min(remaining, PREFILL_CHUNK_GB)
                chunk_id = prefill_chunk_counter[0]
                prefill_chunk_counter[0] += 1
                week_placed = int(rng.integers(-52, 0))
                _store_put(holder, (owner, chunk_id), (chunk_gb, imp_owner, week_placed))
                remaining -= chunk_gb

    # -----------------------------------------------------------------------
    # Main weekly simulation loop (weeks 0..n_sim_weeks-1)
    # -----------------------------------------------------------------------

    for week in range(n_sim_weeks):
        current_week[0] = week

        # ----- Scenario 2: newcomer joins every NEWCOMER_INTERVAL weeks -----
        if config.scenario == 2 and week > 0 and week % NEWCOMER_INTERVAL == 0:
            nid = _alloc()
            if nid is not None:
                atype = int(rng.choice(
                    N_HONEST_ARCHETYPES,
                    p=ARCHETYPE_PROBS[:N_HONEST_ARCHETYPES]
                    / ARCHETYPE_PROBS[:N_HONEST_ARCHETYPES].sum(),
                ))
                _add_node(nid, week, atype=atype, is_newcomer=True)
                newcomer_milestones[nid] = {"50": None, "80": None, "100": None}
                newcomer_join_weeks[nid] = week

        # ----- Trust update -----
        active_ids = np.where(alive)[0]
        if active_ids.size == 0:
            continue

        active_arch = archetype[active_ids]
        prob_week = (week + bootstrap_weeks) % total_weeks_needed
        week_scores = np.zeros(active_ids.size, dtype=np.float64)
        for atype_idx in range(N_ARCHETYPES):
            grp = np.where(active_arch == atype_idx)[0]
            if grp.size == 0:
                continue
            p_w = float(weekly_pass_probs[atype_idx, prob_week])
            week_scores[grp] = (rng.random(grp.size) < p_w).astype(np.float64)

        pos = p_buf_pos[active_ids]
        p_buf[active_ids, pos] = week_scores
        p_buf_pos[active_ids] = (pos + 1) % pw
        filled = p_buf_filled[active_ids]
        p_buf_filled[active_ids] = np.minimum(filled + 1, pw)
        i_sum[active_ids] += week_scores
        i_count[active_ids] += 1
        p_buf_sum = p_buf[active_ids, :].sum(axis=1)
        pf = p_buf_filled[active_ids].astype(np.float64)
        p_val[active_ids] = np.where(pf > 0, p_buf_sum / pf, 0.0)
        ic = i_count[active_ids].astype(np.float64)
        i_val[active_ids] = np.where(ic > 0, i_sum[active_ids] / ic, 0.0)

        # Trust values changed: invalidate per-week cache
        trust_cache.clear()

        # ----- Partnership update -----
        _update_partnerships(active_ids)

        # ----- Reset newcomer bandwidth -----
        for nid_nc in newcomer_join_weeks:
            if alive[nid_nc]:
                bw_remaining[nid_nc] = NEWCOMER_BANDWIDTH_GB

        # ----- Weekly data placement -----
        week_attempts = 0
        week_successes = 0
        week_evictions = 0
        week_lost = 0.0

        online_mask = week_scores > 0.5
        online_ids = active_ids[online_mask]

        for nid_raw in online_ids:
            nid = int(nid_raw)
            if len(partners[nid]) < K:
                continue

            if established[nid]:
                # Established nodes: generate new dirty data each week
                # Each week's data is a NEW chunk (chunk_id = week number).
                # This chunk must compete for space against existing entries.
                # RS overhead: dirty data expands to dirty * n/k total shard-GB.
                dirty = max(0.0, rng.normal(DIRTY_GB_MEAN, DIRTY_GB_STD))
                if dirty <= 0:
                    continue
                n_shards = importance_to_n(float(importance[nid]))
                expanded_gb = dirty * n_shards / K

                # Budget Planner: estimate if placement is viable before trying
                if config.budget_aware:
                    shard_gb_est = expanded_gb / n_shards
                    n_accepting = _estimate_accepting_partners(
                        nid, shard_gb_est, float(importance[nid]), week
                    )
                    if n_accepting < K:
                        # Not enough partners will accept — skip, save bandwidth
                        continue

                att, suc, evict, lost, placed = _place_data_for(
                    nid, expanded_gb, week, week
                )
            else:
                # Newcomer: bandwidth-limited upload of their data
                bw = float(bw_remaining[nid])
                if bw <= 0:
                    continue
                n_shards = importance_to_n(float(importance[nid]))
                # coverage_gb[nid] = sum(shard_gb * K/n) across holders
                # Total shard-GB needed = data_gb * n/K.
                # Already placed shard-GB = coverage_gb[nid] * n/K.
                already_placed_shard_gb = float(coverage_gb[nid]) * n_shards / K
                total_shard_gb_needed = float(data_gb[nid]) * n_shards / K
                remaining_to_place = max(0.0, total_shard_gb_needed - already_placed_shard_gb)
                if remaining_to_place <= 0:
                    continue
                gb_this_week = min(bw, remaining_to_place, NEWCOMER_BANDWIDTH_GB)

                # Budget Planner for newcomers too
                if config.budget_aware:
                    shard_gb_est = gb_this_week / n_shards
                    n_accepting = _estimate_accepting_partners(
                        nid, shard_gb_est, float(importance[nid]), week
                    )
                    if n_accepting < K:
                        continue

                # Use week as chunk_id — newcomers upload new chunks each week
                att, suc, evict, lost, placed = _place_data_for(
                    nid, gb_this_week, week, week, bw_limit=bw
                )
                bw_remaining[nid] = max(0.0, bw - placed)

            week_attempts += att
            week_successes += suc
            week_evictions += evict
            week_lost += lost

        cumulative_data_loss += week_lost

        weekly_placement_success.append(week_successes / max(week_attempts, 1))
        weekly_eviction_counts.append(week_evictions)
        weekly_data_loss_gb.append(cumulative_data_loss)

        if week_attempts > 0:
            recent_depths = all_cascade_depths[-week_attempts:]
            weekly_cascade_depths.append(recent_depths)
        else:
            weekly_cascade_depths.append([])

        # ----- Storage utilization -----
        active_arr = np.where(alive)[0]
        if active_arr.size > 0:
            # stored_total cache: O(N) vectorised
            utils = stored_total[active_arr] / np.maximum(offered_gb[active_arr], 1.0)
            weekly_storage_utilization.append(float(np.mean(np.clip(utils, 0.0, 1.0))))
        else:
            weekly_storage_utilization.append(0.0)

        # ----- Coverage: established vs newcomers -----
        cov_est, cov_new = _compute_coverage(active_arr)
        weekly_coverage_established.append(cov_est)
        weekly_coverage_newcomers.append(cov_new)

        # ----- Newcomer milestones (scenario 2) -----
        # Use coverage_gb cache directly — no iteration over stored_for needed
        if config.scenario == 2:
            for nc_id, milestones in newcomer_milestones.items():
                if not alive[nc_id]:
                    continue
                frac = min(float(coverage_gb[nc_id]) / max(float(data_gb[nc_id]), 1.0), 1.0)
                weeks_since_join = week - newcomer_join_weeks[nc_id]
                if milestones["50"] is None and frac >= 0.50:
                    milestones["50"] = weeks_since_join
                if milestones["80"] is None and frac >= 0.80:
                    milestones["80"] = weeks_since_join
                if milestones["100"] is None and frac >= 0.995:
                    milestones["100"] = weeks_since_join

        # ----- Light churn: 0.5%/week departure -----
        if active_arr.size > 4:
            churn_mask = rng.random(active_arr.size) < 0.005
            for churn_nid in active_arr[churn_mask]:
                _remove_node(int(churn_nid))

    # -----------------------------------------------------------------------
    # Post-simulation aggregation
    # -----------------------------------------------------------------------

    cascade_arr = np.array(all_cascade_depths, dtype=np.int32)
    if cascade_arr.size > 0:
        cascade_mean = float(cascade_arr.mean())
        cascade_max = int(cascade_arr.max())
        cascade_nonzero_frac = float((cascade_arr > 0).mean())
        cascade_hist = np.bincount(
            np.clip(cascade_arr, 0, MAX_CASCADE_DEPTH),
            minlength=MAX_CASCADE_DEPTH + 1
        )
        cascade_hist_norm = (cascade_hist / max(cascade_arr.size, 1)).tolist()
    else:
        cascade_mean = 0.0
        cascade_max = 0
        cascade_nonzero_frac = 0.0
        cascade_hist_norm = [1.0] + [0.0] * MAX_CASCADE_DEPTH

    nc_weeks_to_50: list[float] = []
    nc_weeks_to_80: list[float] = []
    nc_weeks_to_100: list[float] = []
    for milestones in newcomer_milestones.values():
        if milestones["50"] is not None:
            nc_weeks_to_50.append(float(milestones["50"]))
        if milestones["80"] is not None:
            nc_weeks_to_80.append(float(milestones["80"]))
        if milestones["100"] is not None:
            nc_weeks_to_100.append(float(milestones["100"]))

    mean_cov_est_final: float
    if weekly_coverage_established:
        vals_est = [x for x in weekly_coverage_established[-4:] if not np.isnan(x)]
        mean_cov_est_final = float(np.mean(vals_est)) if vals_est else float("nan")
    else:
        mean_cov_est_final = float("nan")

    mean_cov_new_final: float
    if weekly_coverage_newcomers:
        vals_new = [x for x in weekly_coverage_newcomers[-4:] if not np.isnan(x)]
        mean_cov_new_final = float(np.mean(vals_new)) if vals_new else float("nan")
    else:
        mean_cov_new_final = float("nan")

    return {
        "seed": seed,
        "strategy": config.label,
        "scenario": config.scenario,
        "offer_ratio": config.offer_ratio,
        "placement_success_rate": float(np.mean(weekly_placement_success)) if weekly_placement_success else 0.0,
        "evictions_per_week": float(np.mean(weekly_eviction_counts)) if weekly_eviction_counts else 0.0,
        "cascade_mean": cascade_mean,
        "cascade_max": cascade_max,
        "cascade_nonzero_frac": cascade_nonzero_frac,
        "cascade_hist_norm": cascade_hist_norm,
        "final_coverage_established": mean_cov_est_final,
        "final_coverage_newcomers": mean_cov_new_final,
        "storage_utilization": float(np.mean(weekly_storage_utilization)) if weekly_storage_utilization else 0.0,
        "total_data_loss_gb": cumulative_data_loss,
        "newcomer_weeks_to_50pct": float(np.mean(nc_weeks_to_50)) if nc_weeks_to_50 else float("nan"),
        "newcomer_weeks_to_80pct": float(np.mean(nc_weeks_to_80)) if nc_weeks_to_80 else float("nan"),
        "newcomer_weeks_to_100pct": float(np.mean(nc_weeks_to_100)) if nc_weeks_to_100 else float("nan"),
        "weekly_coverage_established": weekly_coverage_established,
        "weekly_coverage_newcomers": weekly_coverage_newcomers,
        "weekly_evictions": weekly_eviction_counts,
        "weekly_success_rate": weekly_placement_success,
        "weekly_storage_utilization": weekly_storage_utilization,
        "weekly_data_loss_gb": weekly_data_loss_gb,
    }


# ---------------------------------------------------------------------------
# Multi-seed runner
# ---------------------------------------------------------------------------

def run_condition(config: Config, n_seeds: int, n_jobs: int) -> dict:
    """Run Monte Carlo for one (scenario, strategy, offer_ratio) condition."""
    seeds = list(range(n_seeds))

    if n_jobs == 1 or n_seeds == 1:
        runs = [simulate_one(config, s) for s in seeds]
    else:
        runs = Parallel(n_jobs=n_jobs)(
            delayed(simulate_one)(config, s) for s in seeds
        )

    def _mean(key: str) -> float:
        vals = [r[key] for r in runs if isinstance(r[key], (int, float)) and not np.isnan(r[key])]
        return float(np.mean(vals)) if vals else float("nan")

    def _std(key: str) -> float:
        vals = [r[key] for r in runs if isinstance(r[key], (int, float)) and not np.isnan(r[key])]
        return float(np.std(vals)) if len(vals) > 1 else float("nan")

    all_hists = [r["cascade_hist_norm"] for r in runs]
    mean_hist = np.mean(all_hists, axis=0).tolist()

    n_weeks = config.n_sim_weeks

    def _mean_series(key: str) -> list[float]:
        arrs = []
        for r in runs:
            raw = r.get(key, [])
            if not raw:
                continue
            if len(raw) >= n_weeks:
                arrs.append(raw[:n_weeks])
            else:
                padded = list(raw) + [raw[-1]] * (n_weeks - len(raw))
                arrs.append(padded)
        if not arrs:
            return [float("nan")] * n_weeks
        mat = np.array(arrs, dtype=np.float64)
        result = np.full(n_weeks, float("nan"), dtype=np.float64)
        for col in range(n_weeks):
            col_vals = mat[:, col]
            finite = col_vals[np.isfinite(col_vals)]
            if finite.size > 0:
                result[col] = float(finite.mean())
        return result.tolist()

    return {
        "strategy": config.label,
        "scenario": config.scenario,
        "offer_ratio": config.offer_ratio,
        "n_seeds": n_seeds,
        "placement_success_rate": _mean("placement_success_rate"),
        "placement_success_rate_std": _std("placement_success_rate"),
        "evictions_per_week": _mean("evictions_per_week"),
        "cascade_mean": _mean("cascade_mean"),
        "cascade_max": _mean("cascade_max"),
        "cascade_nonzero_frac": _mean("cascade_nonzero_frac"),
        "cascade_hist_norm": mean_hist,
        "final_coverage_established": _mean("final_coverage_established"),
        "final_coverage_newcomers": _mean("final_coverage_newcomers"),
        "storage_utilization": _mean("storage_utilization"),
        "total_data_loss_gb": _mean("total_data_loss_gb"),
        "newcomer_weeks_to_50pct": _mean("newcomer_weeks_to_50pct"),
        "newcomer_weeks_to_80pct": _mean("newcomer_weeks_to_80pct"),
        "newcomer_weeks_to_100pct": _mean("newcomer_weeks_to_100pct"),
        "mean_coverage_established": _mean_series("weekly_coverage_established"),
        "mean_coverage_newcomers": _mean_series("weekly_coverage_newcomers"),
        "mean_evictions": _mean_series("weekly_evictions"),
        "mean_success_rate": _mean_series("weekly_success_rate"),
        "mean_data_loss_gb": _mean_series("weekly_data_loss_gb"),
    }


# ---------------------------------------------------------------------------
# Strategy and scenario definitions
# ---------------------------------------------------------------------------

STRATEGY_CONFIGS: dict[str, dict[str, bool | str]] = {
    "A": {"label": "A", "threshold_hysteresis": False, "time_hysteresis": False, "budget_aware": False},
    "B": {"label": "B", "threshold_hysteresis": True,  "time_hysteresis": False, "budget_aware": False},
    "C": {"label": "C", "threshold_hysteresis": False, "time_hysteresis": True,  "budget_aware": False},
    "D": {"label": "D", "threshold_hysteresis": True,  "time_hysteresis": True,  "budget_aware": False},
    "E": {"label": "E", "threshold_hysteresis": True,  "time_hysteresis": True,  "budget_aware": True},
}

STRATEGY_LABELS = {
    "A": "No hysteresis",
    "B": "Threshold H=0.2",
    "C": "Time bonus +30%",
    "D": "Combined (B+C)",
    "E": "D + Budget Planner",
}

SCENARIO_LABELS = {
    1: "Saturated steady-state",
    2: "Newcomer into full network",
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


def print_summary_table(
    results: dict[int, dict[str, dict[float, dict]]],
    scenarios: list[int],
    strategies: list[str],
    offer_ratios: list[float],
) -> None:
    """Print scenario x strategy x offer_ratio summary table."""
    print(f"\n{'=' * 110}")
    print("EXPERIMENT 27 v2: Shard Placement in Saturated Network — Results Summary")
    print(f"{'=' * 110}")

    for scenario in scenarios:
        label = SCENARIO_LABELS.get(scenario, f"Scenario {scenario}")
        print(f"\n  Scenario {scenario}: {label}")
        print(f"  {'Strat':>5}  {'Ratio':>5}  {'Success%':>9}  {'Evict/wk':>9}  "
              f"{'Cascade':>8}  {'Util%':>7}  {'CovEst%':>8}  {'CovNew%':>8}  "
              f"{'LossGB':>8}  {'To50wk':>7}  {'To80wk':>7}")
        print("  " + "-" * 102)

        for s in strategies:
            for ratio in offer_ratios:
                r = results.get(scenario, {}).get(s, {}).get(ratio, {})
                print(
                    f"  {s:>5}  {ratio:>5.1f}  "
                    f"{_fmt(r.get('placement_success_rate', float('nan')), pct=True, width=9)}  "
                    f"{_fmt(r.get('evictions_per_week', float('nan')), width=9)}  "
                    f"{_fmt(r.get('cascade_mean', float('nan')), width=8)}  "
                    f"{_fmt(r.get('storage_utilization', float('nan')), pct=True, width=7)}  "
                    f"{_fmt(r.get('final_coverage_established', float('nan')), pct=True, width=8)}  "
                    f"{_fmt(r.get('final_coverage_newcomers', float('nan')), pct=True, width=8)}  "
                    f"{_fmt(r.get('total_data_loss_gb', float('nan')), width=8)}  "
                    f"{_fmt(r.get('newcomer_weeks_to_50pct', float('nan')), width=7)}  "
                    f"{_fmt(r.get('newcomer_weeks_to_80pct', float('nan')), width=7)}"
                )
            print()


# ---------------------------------------------------------------------------
# Save and plot
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
    results: dict[int, dict[str, dict[float, dict]]],
    n_seeds: int,
    scenarios: list[int],
    strategies: list[str],
    offer_ratios: list[float],
    output_dir: Path,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "shard_placement_v2_results.json"
    payload = {
        "experiment": "27v2",
        "description": "Shard placement in saturated network: 2 scenarios x 4 hysteresis strategies",
        "parameters": {
            "n_nodes": N_NODES,
            "n_sim_weeks": N_SIM_WEEKS,
            "bootstrap_weeks": 52,
            "prefill_target": PREFILL_TARGET,
            "prefill_chunk_gb": PREFILL_CHUNK_GB,
            "k": K,
            "n_high_importance": N_HIGH_IMPORTANCE,
            "n_low_importance": N_LOW_IMPORTANCE,
            "target_partners": TARGET_PARTNERS,
            "threshold_h": THRESHOLD_H,
            "time_bonus_max": TIME_BONUS_MAX,
            "time_bonus_weeks": TIME_BONUS_WEEKS,
            "max_cascade_depth": MAX_CASCADE_DEPTH,
            "newcomer_interval_weeks": NEWCOMER_INTERVAL,
            "newcomer_bandwidth_gb_per_week": NEWCOMER_BANDWIDTH_GB,
            "trust_formula": "(0.5*P + 2.0*I) * clamp(S, 0.1, 1.0)",
        },
        "scenarios": {str(k): v for k, v in SCENARIO_LABELS.items()},
        "strategies": STRATEGY_LABELS,
        "offer_ratios": offer_ratios,
        "n_seeds": n_seeds,
        "results": _convert(results),
    }
    path.write_text(json.dumps(payload, indent=2))
    print(f"\nResults saved to {path}", flush=True)


def plot_results(
    results: dict[int, dict[str, dict[float, dict]]],
    scenarios: list[int],
    strategies: list[str],
    offer_ratios: list[float],
    output_dir: Path,
) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not available, skipping plots", flush=True)
        return

    output_dir.mkdir(parents=True, exist_ok=True)
    colors = {"A": "#e74c3c", "B": "#3498db", "C": "#2ecc71", "D": "#9b59b6", "E": "#e67e22"}
    markers = {"A": "o", "B": "s", "C": "^", "D": "D", "E": "P"}

    ref_ratio = 1.5 if 1.5 in offer_ratios else offer_ratios[0]

    # Plot 1: Established node coverage over time — all strategies, for each scenario
    for scenario in scenarios:
        fig, ax = plt.subplots(figsize=(11, 5))
        for s in strategies:
            weekly = results.get(scenario, {}).get(s, {}).get(ref_ratio, {}).get("mean_coverage_established", None)
            if weekly is None or len(weekly) == 0:
                continue
            weeks = np.arange(len(weekly))
            cov_pct = np.array(weekly, dtype=np.float64) * 100
            ax.plot(weeks, cov_pct,
                    label=f"{s}: {STRATEGY_LABELS[s]}",
                    color=colors[s], linewidth=2, alpha=0.9)
        ax.set_xlabel("Week (since simulation start)")
        ax.set_ylabel("Coverage of established nodes (%)")
        ax.set_title(
            f"Exp 27v2 Plot 1: Established Coverage — "
            f"Scenario {scenario}: {SCENARIO_LABELS.get(scenario, '')} (ratio={ref_ratio})"
        )
        ax.legend(fontsize=9)
        ax.set_ylim(0, 105)
        ax.grid(True, alpha=0.3)
        fig.tight_layout()
        p = output_dir / f"exp27v2_plot1_established_coverage_sc{scenario}.png"
        fig.savefig(str(p), dpi=150)
        plt.close(fig)
        print(f"Plot 1 (scenario {scenario}) saved: {p}", flush=True)

    # Plot 2: Newcomer coverage ramp-up over time (scenario 2 only)
    if 2 in scenarios:
        fig, ax = plt.subplots(figsize=(11, 5))
        for s in strategies:
            weekly = results.get(2, {}).get(s, {}).get(ref_ratio, {}).get("mean_coverage_newcomers", None)
            if weekly is None or len(weekly) == 0:
                continue
            weeks = np.arange(len(weekly))
            cov_pct = np.array(weekly, dtype=np.float64) * 100
            ax.plot(weeks, cov_pct,
                    label=f"{s}: {STRATEGY_LABELS[s]}",
                    color=colors[s], linewidth=2)
        ax.axhline(y=50, color="gray", linestyle=":", alpha=0.5, label="50% target")
        ax.axhline(y=80, color="gray", linestyle="--", alpha=0.5, label="80% target")
        ax.set_xlabel("Week (since simulation start)")
        ax.set_ylabel("Newcomer coverage (%)")
        ax.set_title(f"Exp 27v2 Plot 2: Newcomer Coverage Ramp-Up (ratio={ref_ratio})")
        ax.legend(fontsize=9)
        ax.set_ylim(0, 105)
        ax.grid(True, alpha=0.3)
        fig.tight_layout()
        p = output_dir / "exp27v2_plot2_newcomer_coverage.png"
        fig.savefig(str(p), dpi=150)
        plt.close(fig)
        print(f"Plot 2 saved: {p}", flush=True)

    # Plot 3: Cascade depth distribution (at ref_ratio, scenario 1)
    ref_scenario = 1 if 1 in scenarios else scenarios[0]
    fig, ax = plt.subplots(figsize=(9, 5))
    bar_width = 0.2
    n_strats = len(strategies)
    x_depths = np.arange(MAX_CASCADE_DEPTH + 1)
    for i, s in enumerate(strategies):
        hist = results.get(ref_scenario, {}).get(s, {}).get(ref_ratio, {}).get("cascade_hist_norm", None)
        if hist is None:
            continue
        offset = (i - n_strats / 2) * bar_width + bar_width / 2
        ax.bar(x_depths + offset, hist, width=bar_width,
               label=f"{s}: {STRATEGY_LABELS[s]}", color=colors[s], alpha=0.8)
    ax.set_xlabel("Cascade depth")
    ax.set_ylabel("Fraction of placement events")
    ax.set_title(f"Exp 27v2 Plot 3: Cascade Depth Distribution (Scenario {ref_scenario}, ratio={ref_ratio})")
    ax.legend(fontsize=9)
    ax.set_xlim(-0.5, min(6, MAX_CASCADE_DEPTH) + 0.5)
    ax.grid(True, alpha=0.3, axis="y")
    fig.tight_layout()
    p = output_dir / "exp27v2_plot3_cascade_dist.png"
    fig.savefig(str(p), dpi=150)
    plt.close(fig)
    print(f"Plot 3 saved: {p}", flush=True)

    # Plot 4: Evictions per week over time
    for scenario in scenarios:
        fig, ax = plt.subplots(figsize=(11, 5))
        for s in strategies:
            weekly = results.get(scenario, {}).get(s, {}).get(ref_ratio, {}).get("mean_evictions", None)
            if weekly is None or len(weekly) == 0:
                continue
            weeks = np.arange(len(weekly))
            ax.plot(weeks, weekly,
                    label=f"{s}: {STRATEGY_LABELS[s]}",
                    color=colors[s], linewidth=1.5, alpha=0.9)
        ax.set_xlabel("Week")
        ax.set_ylabel("Evictions this week")
        ax.set_title(f"Exp 27v2 Plot 4: Evictions/Week — Scenario {scenario} (ratio={ref_ratio})")
        ax.legend(fontsize=9)
        ax.grid(True, alpha=0.3)
        fig.tight_layout()
        p = output_dir / f"exp27v2_plot4_evictions_sc{scenario}.png"
        fig.savefig(str(p), dpi=150)
        plt.close(fig)
        print(f"Plot 4 (scenario {scenario}) saved: {p}", flush=True)

    # Plot 5: Cumulative data loss over time
    for scenario in scenarios:
        fig, ax = plt.subplots(figsize=(11, 5))
        for s in strategies:
            weekly = results.get(scenario, {}).get(s, {}).get(ref_ratio, {}).get("mean_data_loss_gb", None)
            if weekly is None or len(weekly) == 0:
                continue
            weeks = np.arange(len(weekly))
            ax.plot(weeks, weekly,
                    label=f"{s}: {STRATEGY_LABELS[s]}",
                    color=colors[s], linewidth=2)
        ax.set_xlabel("Week")
        ax.set_ylabel("Cumulative data loss (GB)")
        ax.set_title(f"Exp 27v2 Plot 5: Cumulative Data Loss — Scenario {scenario} (ratio={ref_ratio})")
        ax.legend(fontsize=9)
        ax.grid(True, alpha=0.3)
        fig.tight_layout()
        p = output_dir / f"exp27v2_plot5_dataloss_sc{scenario}.png"
        fig.savefig(str(p), dpi=150)
        plt.close(fig)
        print(f"Plot 5 (scenario {scenario}) saved: {p}", flush=True)

    # Plot 6: Coverage vs offer_ratio (final week, established nodes, scenario 1)
    if 1 in scenarios:
        fig, ax = plt.subplots(figsize=(9, 5))
        for s in strategies:
            ys = [
                results.get(1, {}).get(s, {}).get(r, {}).get("final_coverage_established", float("nan"))
                for r in offer_ratios
            ]
            ys_pct = [y * 100 if not np.isnan(y) else float("nan") for y in ys]
            ax.plot(offer_ratios, ys_pct,
                    label=f"{s}: {STRATEGY_LABELS[s]}",
                    color=colors[s], marker=markers[s], linewidth=2)
        ax.set_xlabel("Offer ratio (offered_gb / data_gb)")
        ax.set_ylabel("Established node coverage (%)")
        ax.set_title("Exp 27v2 Plot 6: Coverage vs Offer Ratio (Scenario 1, established nodes)")
        ax.legend(fontsize=9)
        ax.set_ylim(0, 105)
        ax.grid(True, alpha=0.3)
        fig.tight_layout()
        p = output_dir / "exp27v2_plot6_coverage_vs_ratio.png"
        fig.savefig(str(p), dpi=150)
        plt.close(fig)
        print(f"Plot 6 saved: {p}", flush=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_scenarios(arg: str) -> list[int]:
    if arg.lower() == "all":
        return [1, 2]
    parts = []
    for p in arg.split(","):
        p = p.strip()
        if p not in ("1", "2"):
            raise ValueError(f"Unknown scenario: {p!r}. Valid: 1, 2, all")
        parts.append(int(p))
    return parts


def _parse_strategies(arg: str) -> list[str]:
    if arg.lower() == "all":
        return list(STRATEGY_CONFIGS.keys())
    parts = [p.strip().upper() for p in arg.split(",")]
    unknown = [p for p in parts if p not in STRATEGY_CONFIGS]
    if unknown:
        raise ValueError(f"Unknown strategies: {unknown}. Valid: {list(STRATEGY_CONFIGS)}")
    return parts


def _parse_offer_ratios(arg: str) -> list[float]:
    try:
        return [float(x.strip()) for x in arg.split(",")]
    except ValueError as exc:
        raise ValueError(f"Invalid offer ratios: {arg}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SyncBack Experiment 27 v2: Shard Placement in Saturated Network"
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default="all",
        help="Scenario(s): 1|2|all or comma-separated (default: all)",
    )
    parser.add_argument(
        "--strategy",
        type=str,
        default="all",
        help="Hysteresis strategy(s): A|B|C|D|all (default: all)",
    )
    parser.add_argument(
        "--seeds",
        type=int,
        default=5,
        help="Monte Carlo seeds per condition (default: 5)",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=12,
        help="Parallel jobs (default: 12)",
    )
    parser.add_argument(
        "--offer-ratios",
        type=str,
        default=",".join(str(r) for r in OFFER_RATIOS_DEFAULT),
        help="Comma-separated offer ratios (default: 1.0,1.5,2.0,3.0)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="results/shard_placement",
        help="Output directory for results and plots",
    )
    parser.add_argument(
        "--no-plot",
        action="store_true",
        help="Skip generating plots",
    )
    args = parser.parse_args()

    try:
        scenarios = _parse_scenarios(args.scenario)
        strategies = _parse_strategies(args.strategy)
        offer_ratios = _parse_offer_ratios(args.offer_ratios)
    except ValueError as e:
        print(f"Error: {e}")
        return

    output_dir = Path(args.output)

    print("=== SYNCBACK EXPERIMENT 27 v2: SHARD PLACEMENT IN SATURATED NETWORK ===", flush=True)
    print(f"Scenarios: {scenarios} ({[SCENARIO_LABELS[s] for s in scenarios]})", flush=True)
    print(f"Strategies: {strategies}", flush=True)
    print(f"Offer ratios: {offer_ratios}", flush=True)
    print(f"Network: {N_NODES} nodes, {N_SIM_WEEKS} sim weeks + 52 bootstrap weeks", flush=True)
    print(f"Pre-fill target: {PREFILL_TARGET*100:.0f}% utilization, chunk size: {PREFILL_CHUNK_GB}GB", flush=True)
    print(f"Trust: (0.5*P + 2.0*I) * clamp(S, 0.1, 1.0), partners={TARGET_PARTNERS}", flush=True)
    print(f"RS: k={K}, n_high={N_HIGH_IMPORTANCE}, n_low={N_LOW_IMPORTANCE}", flush=True)
    print(f"Cascade limit: {MAX_CASCADE_DEPTH}, H={THRESHOLD_H}, time_bonus={TIME_BONUS_MAX}", flush=True)
    print(f"Newcomer bandwidth: {NEWCOMER_BANDWIDTH_GB} GB/week", flush=True)
    print(f"Seeds: {args.seeds}, Jobs: {args.jobs}", flush=True)
    print(flush=True)

    all_results: dict[int, dict[str, dict[float, dict]]] = {
        s: {st: {} for st in strategies} for s in scenarios
    }
    t_total = time.time()

    for scenario in scenarios:
        scen_label = SCENARIO_LABELS.get(scenario, f"Scenario {scenario}")
        print(f"\n--- Scenario {scenario}: {scen_label} ---", flush=True)

        for strategy in strategies:
            cfg_params = STRATEGY_CONFIGS[strategy]
            strat_label = STRATEGY_LABELS[strategy]
            print(f"  Strategy {strategy}: {strat_label}", flush=True)

            for ratio in offer_ratios:
                cfg = Config(
                    label=strategy,
                    scenario=scenario,
                    offer_ratio=ratio,
                    threshold_hysteresis=bool(cfg_params["threshold_hysteresis"]),
                    time_hysteresis=bool(cfg_params["time_hysteresis"]),
                    budget_aware=bool(cfg_params.get("budget_aware", False)),
                )
                t0 = time.time()
                result = run_condition(cfg, args.seeds, args.jobs)
                elapsed = time.time() - t0
                all_results[scenario][strategy][ratio] = result

                print(
                    f"    ratio={ratio:.1f} | "
                    f"success={_fmt(result['placement_success_rate'], pct=True).strip()} | "
                    f"evict/wk={_fmt(result['evictions_per_week']).strip()} | "
                    f"cascade={_fmt(result['cascade_mean']).strip()} | "
                    f"util={_fmt(result['storage_utilization'], pct=True).strip()} | "
                    f"cov_est={_fmt(result['final_coverage_established'], pct=True).strip()} | "
                    f"loss={_fmt(result['total_data_loss_gb']).strip()}GB | "
                    f"to50={_fmt(result['newcomer_weeks_to_50pct']).strip()}wk | "
                    f"{elapsed:.1f}s",
                    flush=True,
                )
            print(flush=True)

    print(f"\nTotal runtime: {time.time() - t_total:.1f}s", flush=True)

    print_summary_table(all_results, scenarios, strategies, offer_ratios)
    save_results(all_results, args.seeds, scenarios, strategies, offer_ratios, output_dir)

    if not args.no_plot:
        plot_results(all_results, scenarios, strategies, offer_ratios, output_dir)


if __name__ == "__main__":
    main()
