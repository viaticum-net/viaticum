"""
Viaticum: User Perspective Simulation

Shows Viaticum from a single user's (protagonist's) perspective across
realistic life scenarios. Network has 3000 background nodes; we track
the protagonist in detail each week.

Scenarios:
  1: Новичок (Newcomer)           -- joins fresh, tracks bootstrap time per file
  2: Сдох диск (Disk failure)     -- 2-year normal run, then disk dies at week 104
  3: Потерял ноутбук (Lost device)-- 1 year normal, 26-week offline gap, recovery
  4: Летний отпуск (Vacation)     -- 1 year normal, 8-week offline, comes back
  5: Диск заполнился (Disk full)  -- 1 year normal, then stops storing for others
  6: Ненадёжный интернет (Nomad)  -- full 3 years at 50% availability

Usage:
    python user_perspective.py --scenario all --seeds 5 --jobs 12
    python user_perspective.py --scenario 1 --seeds 1 --jobs 1
    python user_perspective.py --scenario 1,3,5 --seeds 3 --jobs 6
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


# ---------------------------------------------------------------------------
# Archetype definitions (6 honest + HitAndRun, same as pis_weighted_placement)
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
N_ARCHETYPES = 7
_IDX_HAR = 6
_IDX_FREELOADER = 5
_IDX_HOARDER = 4

# Storage offer ratios: gb_stored_for_others / gb_stored_by_others
STORAGE_RATIOS = np.array([1.0, 1.0, 1.0, 1.0, 0.2, 0.1, 0.0], dtype=np.float64)

# Background network archetype distribution (no HitAndRun for simplicity)
# Reliable, Weekend, Seasonal, Nomad, Hoarder, Freeloader
ARCHETYPE_PROBS_BG = np.array([0.35, 0.20, 0.12, 0.08, 0.10, 0.10, 0.05])
assert abs(ARCHETYPE_PROBS_BG.sum() - 1.0) < 1e-9


# ---------------------------------------------------------------------------
# Trust formula
# ---------------------------------------------------------------------------

KP = 0.5
KI = 2.0
S_CLAMP_MIN = 0.1
S_CLAMP_MAX = 1.0
_S_EPS = 0.01
_MAX_TRUST = (KP + KI) * 1.0  # = 2.5


def trust_multiplicative(
    p_b: float | np.ndarray,
    i_b: float | np.ndarray,
    s_ab: float | np.ndarray,
) -> float | np.ndarray:
    """trust = (KP*P + KI*I) * clamp(S, 0.1, 1.0)"""
    pi = KP * p_b + KI * i_b
    s_c = np.clip(s_ab, S_CLAMP_MIN, S_CLAMP_MAX)
    return pi * s_c


def pairwise_s(r_observer: float, r_target: float) -> float:
    """S_AB = storage_ratio[target] / max(storage_ratio[observer], eps)"""
    return float(np.clip(r_target / max(r_observer, _S_EPS), S_CLAMP_MIN, S_CLAMP_MAX))


# ---------------------------------------------------------------------------
# Erasure coding / adaptive n
# ---------------------------------------------------------------------------

K = 5
ADAPTIVE_N_MAX = 50
TARGET_SURVIVAL = 0.9999
_TABLE_N_BUCKETS = 100


def _build_adaptive_n_table() -> np.ndarray:
    p_values = np.linspace(0.1, 1.0, _TABLE_N_BUCKETS)
    table = np.full(_TABLE_N_BUCKETS, K * 5, dtype=np.int32)
    for i, avg_p in enumerate(p_values):
        for n in range(K, K * 10 + 1):
            if binom_dist.sf(K - 1, n, float(avg_p)) >= TARGET_SURVIVAL:
                table[i] = min(n, ADAPTIVE_N_MAX)
                break
    return table


_ADAPTIVE_N_TABLE = _build_adaptive_n_table()


def compute_adaptive_n(partner_trusts: np.ndarray) -> int:
    if len(partner_trusts) == 0:
        return K * 3
    avg_p = float(np.mean(np.clip(partner_trusts / _MAX_TRUST, 0.1, 1.0)))
    idx = int((avg_p - 0.1) / (1.0 - 0.1) * (_TABLE_N_BUCKETS - 1) + 0.5)
    idx = max(0, min(idx, _TABLE_N_BUCKETS - 1))
    return int(_ADAPTIVE_N_TABLE[idx])


# ---------------------------------------------------------------------------
# Escrow
# ---------------------------------------------------------------------------

ESCROW_TIER1_WEEKS = 4    # (1, 5] GB
ESCROW_TIER2_WEEKS = 13   # (5, 50] GB
ESCROW_TIER3_WEEKS = 26   # > 50 GB


def escrow_weeks_required(file_size_gb: float) -> int:
    """Weeks-in-network required before restore is allowed."""
    if file_size_gb <= 1.0:
        return 0
    if file_size_gb <= 5.0:
        return ESCROW_TIER1_WEEKS
    if file_size_gb <= 50.0:
        return ESCROW_TIER2_WEEKS
    return ESCROW_TIER3_WEEKS


def can_restore_escrow(file_size_gb: float, weeks_in_network: int) -> bool:
    return weeks_in_network >= escrow_weeks_required(file_size_gb)


# ---------------------------------------------------------------------------
# Weighted placement
# ---------------------------------------------------------------------------

WEIGHTED_ALPHA = 2.0
MAX_SHARDS_PER_PARTNER = 6
MAX_SHARD_SLOTS = 60  # >= ADAPTIVE_N_MAX


def weighted_alloc(n_total: int, p_arr: np.ndarray) -> np.ndarray:
    """
    Compute shard allocation array, shape (len(p_arr),), summing to n_total.
    p_arr sorted descending. Each partner capped at MAX_SHARDS_PER_PARTNER.
    """
    n = len(p_arr)
    weights = p_arr ** WEIGHTED_ALPHA
    ws = weights.sum()
    if ws == 0.0:
        alloc = np.full(n, n_total // n, dtype=np.int32)
        alloc[: n_total % n] += 1
        return alloc
    raw = n_total * weights / ws
    alloc = np.round(raw).astype(np.int32)
    alloc = np.minimum(alloc, MAX_SHARDS_PER_PARTNER)
    diff = n_total - int(alloc.sum())
    if diff > 0:
        for i in range(n):
            if diff <= 0:
                break
            if alloc[i] < MAX_SHARDS_PER_PARTNER:
                alloc[i] += 1
                diff -= 1
    elif diff < 0:
        for i in range(n - 1, -1, -1):
            if diff >= 0:
                break
            if alloc[i] > 0:
                alloc[i] -= 1
                diff += 1
    return alloc


# ---------------------------------------------------------------------------
# Weekly pass probabilities per archetype
# ---------------------------------------------------------------------------

def _build_weekly_pass_probs(n_weeks: int) -> np.ndarray:
    """Shape: (N_ARCHETYPES, n_weeks). week-level availability probability."""
    week_idx = np.arange(n_weeks)
    week_in_year = week_idx % 52
    probs = np.zeros((N_ARCHETYPES, n_weeks), dtype=np.float64)

    probs[0, :] = 1.0 - (1.0 - 0.99) ** 7       # Reliable
    p_fail_we = (1.0 - 0.95) ** 3 * (1.0 - 0.30) ** 4
    probs[1, :] = 1.0 - p_fail_we                 # Weekend
    is_summer = (week_in_year >= 22) & (week_in_year <= 35)
    r_s = np.where(is_summer, 0.20, 0.95)
    probs[2, :] = 1.0 - (1.0 - r_s) ** 7         # Seasonal
    probs[3, :] = 0.50                             # Nomad
    probs[4, :] = 1.0 - (1.0 - 0.90) ** 7        # Hoarder
    probs[5, :] = 1.0 - (1.0 - 0.80) ** 7        # Freeloader
    probs[6, :] = 1.0 - (1.0 - 0.80) ** 7        # HitAndRun
    return probs


# ---------------------------------------------------------------------------
# Protagonist files
# ---------------------------------------------------------------------------

@dataclass
class FileDef:
    name: str
    size_gb: float          # for escrow tier
    k: int = K


PROTAGONIST_FILES = [
    FileDef("docs",   2.0),
    FileDef("photos", 20.0),
    FileDef("video",  80.0),
]
N_FILES = len(PROTAGONIST_FILES)


# ---------------------------------------------------------------------------
# Per-week snapshot
# ---------------------------------------------------------------------------

@dataclass
class WeekSnapshot:
    week: int
    protagonist_mean_trust: float   # mean trust partners assign to protagonist
    protagonist_p: float            # protagonist's own P value
    protagonist_i: float            # protagonist's own I value
    protagonist_s_mean: float       # mean S_AB (protagonist storage ratio / partner ratio)
    n_partners: int
    n_partners_storing: int         # partners holding ≥1 shard for protagonist
    # per-file: [docs, photos, video]
    live_shards: list[int]
    total_shards: list[int]
    can_restore: list[bool]
    is_online: bool
    storage_for_others_gb: float    # notional GB protagonist stores for others


# ---------------------------------------------------------------------------
# Scenario configuration
# ---------------------------------------------------------------------------

@dataclass
class ScenarioDef:
    id: int
    name: str
    description: str
    n_weeks: int = 156  # 3 years


SCENARIOS = {
    1: ScenarioDef(1, "Newcomer",     "Новичок: joins fresh, tracks bootstrap"),
    2: ScenarioDef(2, "DiskFailure",  "Сдох диск: disk dies at week 104"),
    3: ScenarioDef(3, "LostDevice",   "Потерял ноутбук: 26-week gap at week 52"),
    4: ScenarioDef(4, "Vacation",     "Летний отпуск: 8-week offline at week 52"),
    5: ScenarioDef(5, "DiskFull",     "Диск заполнился: stops storing at week 52"),
    6: ScenarioDef(6, "Nomad",        "Ненадёжный интернет: 50% availability"),
}


# ---------------------------------------------------------------------------
# Simulation parameters
# ---------------------------------------------------------------------------

BG_NODES_TARGET = 3000
BG_NODES_INITIAL = 200
ANNUAL_CHURN = 0.15           # 15% per year
WEEKLY_CHURN = 1.0 - (1.0 - ANNUAL_CHURN) ** (1.0 / 52.0)
TARGET_PARTNERS_BG = 15       # background nodes target partner count
TARGET_PARTNERS_PROT = 50     # protagonist targets more partners


# ---------------------------------------------------------------------------
# Core user-perspective simulation
# ---------------------------------------------------------------------------

def simulate_scenario(scenario_id: int, seed: int) -> list[WeekSnapshot]:
    """
    Run one scenario for the protagonist and return weekly snapshots.

    Architecture:
    - Background nodes: lightweight P/I tracking, partnership formation, churn.
      We do NOT track background files — only their alive status matters.
    - Protagonist: full shard placement, trust computation, file tracking.
    """
    rng = np.random.default_rng(seed)
    sdef = SCENARIOS[scenario_id]
    n_weeks = sdef.n_weeks

    weekly_pass_probs = _build_weekly_pass_probs(n_weeks)
    weekly_churn = WEEKLY_CHURN

    # ------------------------------------------------------------------
    # Background node arrays (size = BG_NODES_TARGET + buffer)
    # ------------------------------------------------------------------
    cap = BG_NODES_TARGET + 300
    bg_alive = np.zeros(cap, dtype=bool)
    bg_archetype = np.full(cap, -1, dtype=np.int8)
    bg_join_week = np.full(cap, -1, dtype=np.int32)

    # P: 4-week rolling average
    PW = 4
    bg_pbuf = np.zeros((cap, PW), dtype=np.float64)
    bg_pbuf_pos = np.zeros(cap, dtype=np.int32)
    bg_pbuf_filled = np.zeros(cap, dtype=np.int32)
    bg_i_sum = np.zeros(cap, dtype=np.float64)
    bg_i_count = np.zeros(cap, dtype=np.int32)
    bg_p_val = np.zeros(cap, dtype=np.float64)
    bg_i_val = np.zeros(cap, dtype=np.float64)

    # Partnerships: list of sets (protagonist is NOT in this list)
    bg_partners: list[set[int]] = [set() for _ in range(cap)]

    next_bg_id = 0
    free_bg_ids: list[int] = []

    def _bg_alloc() -> Optional[int]:
        nonlocal next_bg_id
        if free_bg_ids:
            return free_bg_ids.pop()
        if next_bg_id < cap:
            nid = next_bg_id
            next_bg_id += 1
            return nid
        return None

    def _bg_add(nid: int, week: int) -> None:
        atype = int(rng.choice(N_ARCHETYPES, p=ARCHETYPE_PROBS_BG))
        bg_archetype[nid] = atype
        bg_alive[nid] = True
        bg_join_week[nid] = week
        bg_pbuf[nid, :] = 0.0
        bg_pbuf_pos[nid] = 0
        bg_pbuf_filled[nid] = 0
        bg_i_sum[nid] = 0.0
        bg_i_count[nid] = 0
        bg_p_val[nid] = 0.0
        bg_i_val[nid] = 0.0
        bg_partners[nid] = set()

    def _bg_remove(nid: int) -> None:
        bg_alive[nid] = False
        for pid in bg_partners[nid]:
            bg_partners[pid].discard(nid)
        bg_partners[nid].clear()
        free_bg_ids.append(nid)

    # ------------------------------------------------------------------
    # Protagonist state
    # ------------------------------------------------------------------

    # Protagonist's P/I (as seen by network / as protagonist is evaluated)
    # Protagonists' values used by partners to compute trust toward them.
    prot_join_week = 0
    prot_pbuf = np.zeros(PW, dtype=np.float64)
    prot_pbuf_pos = 0
    prot_pbuf_filled = 0
    prot_i_sum = 0.0
    prot_i_count = 0
    prot_p_val = 0.0
    prot_i_val = 0.0

    # Set of background node IDs that are the protagonist's partners
    prot_partners: set[int] = set()

    # Protagonist's files: one shard list per file
    # shards[f] = list of bg_node_ids holding a shard (with multiplicity for weighted)
    prot_shards: list[list[int]] = [[] for _ in range(N_FILES)]
    prot_desired_n: list[int] = [K * 3] * N_FILES

    # Adaptive n recalc counter
    prot_n_recalc_counter = 0

    # Protagonist's storage ratio (changes in scenario 5)
    prot_storage_ratio = STORAGE_RATIOS[0]  # Reliable = 1.0

    # Scenario-specific protagonist state
    prot_is_online = True
    prot_disk_dead = False        # scenario 2: disk dead flag
    prot_device_lost = False      # scenario 3: device lost, no local state
    prot_offline_start = -1       # week when protagonist went offline

    # Effective join week for escrow: stays as original join week
    # (network remembers identity even after device loss)
    prot_effective_join_week = 0

    # Protagonist's cumulative online weeks (for trust computation by others)
    # This tracks P and I from the network's perspective
    prot_online_weeks_count = 0

    # ------------------------------------------------------------------
    # Bootstrap initial background network
    # ------------------------------------------------------------------
    for _ in range(BG_NODES_INITIAL):
        nid = _bg_alloc()
        if nid is not None:
            _bg_add(nid, 0)

    # Pre-form some initial partnerships among background nodes
    active_bg = np.where(bg_alive)[0]
    for nid in active_bg:
        candidates = [
            c for c in active_bg
            if c != nid and c not in bg_partners[nid]
            and len(bg_partners[c]) < TARGET_PARTNERS_BG
        ]
        n_pick = min(TARGET_PARTNERS_BG - len(bg_partners[nid]), len(candidates))
        if n_pick > 0:
            chosen = rng.choice(candidates, size=n_pick, replace=False)
            for c in chosen:
                c = int(c)
                bg_partners[nid].add(c)
                bg_partners[c].add(nid)

    # ------------------------------------------------------------------
    # Helper: compute trust that bg node `observer` assigns to protagonist
    # ------------------------------------------------------------------
    def _trust_toward_prot(observer_id: int) -> float:
        r_obs = float(STORAGE_RATIOS[int(bg_archetype[observer_id])])
        s = pairwise_s(r_obs, prot_storage_ratio)
        return float(trust_multiplicative(prot_p_val, prot_i_val, s))

    # Helper: compute trust protagonist assigns to bg node `target`
    def _trust_prot_toward(target_id: int) -> float:
        r_obs = prot_storage_ratio
        r_tgt = float(STORAGE_RATIOS[int(bg_archetype[target_id])])
        s = pairwise_s(r_obs, r_tgt)
        p_t = float(bg_p_val[target_id])
        i_t = float(bg_i_val[target_id])
        return float(trust_multiplicative(p_t, i_t, s))

    # ------------------------------------------------------------------
    # Protagonist shard placement helpers
    # ------------------------------------------------------------------

    def _prot_place_shards(file_idx: int) -> None:
        """Initial weighted placement for one file."""
        if prot_disk_dead:
            return
        partners_alive = [p for p in prot_partners if bg_alive[p]]
        if len(partners_alive) < K:
            return
        arr = np.array(partners_alive, dtype=np.int32)
        t_vals = np.array([_trust_prot_toward(int(pid)) for pid in arr])
        order = np.argsort(-t_vals)
        arr = arr[order]
        t_sorted = t_vals[order]
        p_arr = np.clip(t_sorted / _MAX_TRUST, 0.1, 1.0)
        n_total = prot_desired_n[file_idx]
        n_use = min(len(arr), MAX_SHARD_SLOTS)
        arr = arr[:n_use]
        p_arr = p_arr[:n_use]
        alloc = weighted_alloc(n_total, p_arr)
        shards_list: list[int] = []
        for i in range(len(arr)):
            for _ in range(int(alloc[i])):
                if len(shards_list) >= MAX_SHARD_SLOTS:
                    break
                shards_list.append(int(arr[i]))
            if len(shards_list) >= MAX_SHARD_SLOTS:
                break
        prot_shards[file_idx] = shards_list

    def _prot_repair_shards(file_idx: int) -> None:
        """Remove dead holders, add replacement shards if needed."""
        if prot_disk_dead:
            return
        current = prot_shards[file_idx]
        # Count live
        kept = [h for h in current if bg_alive[h]]
        n_alive = len(kept)
        if n_alive < K:
            # Can't repair without enough live shards — leave as is
            prot_shards[file_idx] = kept
            return
        desired = prot_desired_n[file_idx]
        n_lost = desired - n_alive
        if n_lost <= 0:
            prot_shards[file_idx] = kept
            return
        # Weighted repair: recompute allocation over all alive partners
        candidate_set: set[int] = set(p for p in prot_partners if bg_alive[p])
        candidate_set.update(h for h in kept if bg_alive[h])
        if len(candidate_set) < K:
            prot_shards[file_idx] = kept
            return
        arr = np.array(sorted(candidate_set), dtype=np.int32)
        t_vals = np.array([_trust_prot_toward(int(pid)) for pid in arr])
        order = np.argsort(-t_vals)
        arr = arr[order]
        t_sorted = t_vals[order]
        p_arr = np.clip(t_sorted / _MAX_TRUST, 0.1, 1.0)
        n_use = min(len(arr), MAX_SHARD_SLOTS)
        arr = arr[:n_use]
        p_arr = p_arr[:n_use]
        target_alloc = weighted_alloc(desired, p_arr)
        # Count current allocations
        current_count: dict[int, int] = {}
        for h in kept:
            current_count[h] = current_count.get(h, 0) + 1
        # Build new shard list (never remove live shards, only add)
        pos = 0
        new_shards: list[int] = []
        for i in range(len(arr)):
            pid = int(arr[i])
            want = int(target_alloc[i])
            have = current_count.get(pid, 0)
            give = max(want, have)
            give = min(give, MAX_SHARDS_PER_PARTNER, MAX_SHARD_SLOTS - pos)
            for _ in range(give):
                if pos >= MAX_SHARD_SLOTS:
                    break
                new_shards.append(pid)
                pos += 1
            if pos >= MAX_SHARD_SLOTS:
                break
        prot_shards[file_idx] = new_shards

    def _prot_update_desired_n() -> None:
        """Recompute adaptive n for each file based on current partner trusts."""
        partners_alive = [p for p in prot_partners if bg_alive[p]]
        if not partners_alive:
            return
        arr = np.array(partners_alive[:50], dtype=np.int32)  # sample up to 50
        t_vals = np.array([_trust_prot_toward(int(pid)) for pid in arr])
        n = compute_adaptive_n(t_vals)
        for f in range(N_FILES):
            prot_desired_n[f] = n

    # ------------------------------------------------------------------
    # Partner formation for protagonist
    # ------------------------------------------------------------------

    def _prot_form_partnerships(active_bg_ids: np.ndarray) -> None:
        """Protagonist finds new partners from the background network."""
        n_needed = TARGET_PARTNERS_PROT - len(prot_partners)
        if n_needed <= 0:
            return
        candidates = [
            int(c) for c in active_bg_ids
            if c not in prot_partners
            and len(bg_partners[int(c)]) < TARGET_PARTNERS_BG + 10
        ]
        if not candidates:
            return
        arr = np.array(candidates, dtype=np.int32)
        t_vals = np.array([_trust_prot_toward(int(pid)) for pid in arr])
        t_sum = t_vals.sum()
        if t_sum == 0.0:
            probs = np.ones(len(arr)) / len(arr)
        else:
            probs = t_vals / t_sum
        n_pick = min(n_needed, len(candidates))
        chosen = rng.choice(arr, size=n_pick, replace=False, p=probs)
        for cid in chosen:
            cid = int(cid)
            prot_partners.add(cid)
            bg_partners[cid].add(-1)  # -1 = protagonist sentinel in bg partner sets

    def _prot_remove_from_bg(nid: int) -> None:
        """Remove protagonist from bg node's partner set when bg node churns."""
        # bg_partners already cleaned up by _bg_remove; we only need to remove from prot_partners
        prot_partners.discard(nid)
        # Remove associated shards
        for f in range(N_FILES):
            prot_shards[f] = [h for h in prot_shards[f] if h != nid]

    # ------------------------------------------------------------------
    # Snapshot helpers
    # ------------------------------------------------------------------

    def _live_shards(file_idx: int) -> int:
        return sum(1 for h in prot_shards[file_idx] if bg_alive[h])

    def _total_shards(file_idx: int) -> int:
        return len(prot_shards[file_idx])

    def _n_partners_storing() -> int:
        """How many partners hold ≥1 live shard for protagonist."""
        holders: set[int] = set()
        for f in range(N_FILES):
            for h in prot_shards[f]:
                if bg_alive[h]:
                    holders.add(h)
        return len(holders)

    def _mean_trust_toward_prot() -> float:
        """Mean trust that protagonist's partners assign to protagonist."""
        pts = [p for p in prot_partners if bg_alive[p]]
        if not pts:
            return 0.0
        return float(np.mean([_trust_toward_prot(p) for p in pts]))

    def _mean_s() -> float:
        """Mean pairwise S (protagonist ratio / partner ratio)."""
        pts = [p for p in prot_partners if bg_alive[p]]
        if not pts:
            return 0.0
        vals = []
        for p in pts:
            r_p = float(STORAGE_RATIOS[int(bg_archetype[p])])
            vals.append(pairwise_s(r_p, prot_storage_ratio))
        return float(np.mean(vals))

    def _storage_for_others() -> float:
        """Notional GB protagonist stores for others (based on ratio * total file size)."""
        total_file_size = sum(fd.size_gb for fd in PROTAGONIST_FILES)
        return prot_storage_ratio * total_file_size

    def _take_snapshot(week: int) -> WeekSnapshot:
        live = [_live_shards(f) for f in range(N_FILES)]
        total = [_total_shards(f) for f in range(N_FILES)]
        weeks_in_net = week - prot_effective_join_week
        c_restore = [
            (live[f] >= PROTAGONIST_FILES[f].k
             and can_restore_escrow(PROTAGONIST_FILES[f].size_gb, weeks_in_net))
            for f in range(N_FILES)
        ]
        return WeekSnapshot(
            week=week,
            protagonist_mean_trust=_mean_trust_toward_prot(),
            protagonist_p=prot_p_val,
            protagonist_i=prot_i_val,
            protagonist_s_mean=_mean_s(),
            n_partners=len(prot_partners),
            n_partners_storing=_n_partners_storing(),
            live_shards=live,
            total_shards=total,
            can_restore=c_restore,
            is_online=prot_is_online,
            storage_for_others_gb=_storage_for_others(),
        )

    # ------------------------------------------------------------------
    # Per-scenario protagonist online/behavior function
    # ------------------------------------------------------------------

    def _prot_is_online_this_week(week: int) -> bool:
        """Return True if protagonist is online this week (scenario-specific)."""
        nonlocal prot_is_online, prot_offline_start
        if scenario_id == 1:
            return True
        elif scenario_id == 2:
            return week < 104  # disk dies at week 104
        elif scenario_id == 3:
            # offline weeks 52–77 (26 weeks)
            return not (52 <= week < 78)
        elif scenario_id == 4:
            # offline weeks 52–59 (8 weeks)
            return not (52 <= week < 60)
        elif scenario_id == 5:
            return True  # always online, but storage ratio changes
        elif scenario_id == 6:
            # 50% availability (Nomad-like)
            return bool(rng.random() < 0.50)
        return True

    def _prot_storage_ratio_this_week(week: int) -> float:
        """Return protagonist's effective storage ratio (scenario 5 degrades it)."""
        if scenario_id != 5:
            return 1.0
        if week < 52:
            return 1.0
        # After week 52: disk fills up gradually over ~26 weeks
        # Storage ratio linearly decays from 1.0 to 0.05
        elapsed = week - 52
        ratio = max(0.05, 1.0 - elapsed / 26.0)
        return ratio

    # ------------------------------------------------------------------
    # Main weekly loop
    # ------------------------------------------------------------------

    snapshots: list[WeekSnapshot] = []

    for week in range(n_weeks):
        # ---- 0. Determine protagonist state this week ----
        prot_is_online = _prot_is_online_this_week(week)
        prot_storage_ratio = _prot_storage_ratio_this_week(week)

        # Scenario 2: once disk dies, protagonist is permanently offline
        # and loses all shard information (disk is dead)
        if scenario_id == 2 and week == 104:
            prot_disk_dead = True
            # Protagonist can no longer repair shards
            # (we still track what's live for reporting)

        # Scenario 3: device lost at week 52 — protagonist loses P/I history
        # When they return at week 78, trust has decayed (P=0 since offline),
        # but I is preserved by partners (they keep cumulative history).
        # We model: protagonist's local P resets at return; I is NOT reset
        # (partners still have their I record for protagonist from before).
        if scenario_id == 3 and week == 52:
            prot_device_lost = True
        if scenario_id == 3 and week == 78:
            prot_device_lost = False
            # Local P history is lost (new device), but I stays in partner memory
            # Protagonist's own view: P=0 (fresh), I = historical value preserved
            # We keep prot_i_sum/count as-is (partners remember)
            prot_pbuf[:] = 0.0
            prot_pbuf_pos = 0
            prot_pbuf_filled = 0
            prot_p_val = 0.0
            # Note: escrow uses ORIGINAL join week (identity is recovered from seed)
            # prot_effective_join_week stays at 0

        # ---- 1. Background network growth ----
        n_bg_active = int(bg_alive.sum())
        if n_bg_active < BG_NODES_TARGET:
            if week < 26:
                n_new = 40
            else:
                n_new = 15
            n_new = min(n_new, BG_NODES_TARGET - n_bg_active)
            for _ in range(n_new):
                nid = _bg_alloc()
                if nid is None:
                    break
                _bg_add(nid, week)

        # ---- 2. Background churn ----
        active_bg_ids = np.where(bg_alive)[0]
        if active_bg_ids.size > 0:
            churn_mask = rng.random(active_bg_ids.size) < weekly_churn
            for nid in active_bg_ids[churn_mask]:
                nid = int(nid)
                if nid in prot_partners:
                    _prot_remove_from_bg(nid)
                _bg_remove(nid)

        # ---- 3. Background weekly checks & P/I update ----
        active_bg_ids = np.where(bg_alive)[0]
        if active_bg_ids.size > 0:
            active_arch = bg_archetype[active_bg_ids]
            week_scores = np.zeros(active_bg_ids.size, dtype=np.float64)
            for atype_idx in range(N_ARCHETYPES):
                grp = np.where(active_arch == atype_idx)[0]
                if grp.size == 0:
                    continue
                p_w = float(weekly_pass_probs[atype_idx, week % n_weeks])
                week_scores[grp] = (rng.random(grp.size) < p_w).astype(np.float64)

            pos = bg_pbuf_pos[active_bg_ids]
            bg_pbuf[active_bg_ids, pos] = week_scores
            bg_pbuf_pos[active_bg_ids] = (pos + 1) % PW
            filled = bg_pbuf_filled[active_bg_ids]
            bg_pbuf_filled[active_bg_ids] = np.minimum(filled + 1, PW)

            bg_i_sum[active_bg_ids] += week_scores
            bg_i_count[active_bg_ids] += 1

            pbuf_sum = bg_pbuf[active_bg_ids, :].sum(axis=1)
            pf = bg_pbuf_filled[active_bg_ids].astype(np.float64)
            bg_p_val[active_bg_ids] = np.where(pf > 0, pbuf_sum / pf, 0.0)
            ic = bg_i_count[active_bg_ids].astype(np.float64)
            bg_i_val[active_bg_ids] = np.where(ic > 0, bg_i_sum[active_bg_ids] / ic, 0.0)

        # ---- 4. Background partnership formation (lightweight, 100/week) ----
        if active_bg_ids.size > 0:
            underfull_mask = np.array(
                [len(bg_partners[int(nid)]) < TARGET_PARTNERS_BG for nid in active_bg_ids],
                dtype=bool,
            )
            underfull = active_bg_ids[underfull_mask]
            if underfull.size > 100:
                underfull = rng.choice(underfull, size=100, replace=False)
            active_set_bg = set(int(x) for x in active_bg_ids)
            for nid in underfull:
                nid = int(nid)
                n_need = TARGET_PARTNERS_BG - len(bg_partners[nid])
                if n_need <= 0:
                    continue
                cands = [
                    c for c in active_set_bg
                    if c != nid
                    and c not in bg_partners[nid]
                    and len(bg_partners[c]) < TARGET_PARTNERS_BG
                ]
                if not cands:
                    continue
                n_pick = min(n_need, len(cands))
                chosen = rng.choice(cands, size=n_pick, replace=False)
                for c in chosen:
                    c = int(c)
                    bg_partners[nid].add(c)
                    bg_partners[c].add(nid)

        # ---- 5. Protagonist weekly check & P/I update ----
        # Protagonist is Reliable archetype (offline only in specific scenarios)
        if prot_is_online and not prot_device_lost:
            # Reliable: 99% daily = ~0.9321 weekly pass prob
            p_reliable = 1.0 - (1.0 - 0.99) ** 7
            passed = float(rng.random() < p_reliable)

            prot_pbuf[prot_pbuf_pos] = passed
            prot_pbuf_pos = (prot_pbuf_pos + 1) % PW
            prot_pbuf_filled = min(prot_pbuf_filled + 1, PW)
            prot_i_sum += passed
            prot_i_count += 1

            if prot_pbuf_filled > 0:
                prot_p_val = float(prot_pbuf.sum() / prot_pbuf_filled)
            if prot_i_count > 0:
                prot_i_val = float(prot_i_sum / prot_i_count)
        elif not prot_is_online:
            # Offline: P decays (no checks), I stays
            # P buffer gets a 0 each week offline
            prot_pbuf[prot_pbuf_pos] = 0.0
            prot_pbuf_pos = (prot_pbuf_pos + 1) % PW
            prot_pbuf_filled = min(prot_pbuf_filled + 1, PW)
            if prot_pbuf_filled > 0:
                prot_p_val = float(prot_pbuf.sum() / prot_pbuf_filled)
            # I stays (cumulative mean doesn't decay)

        # ---- 6. Protagonist partnership formation (only when online) ----
        if prot_is_online and not prot_device_lost and active_bg_ids.size > 0:
            _prot_form_partnerships(active_bg_ids)

        # ---- 7. Protagonist adaptive n recalc (every 4 weeks) ----
        prot_n_recalc_counter += 1
        if prot_n_recalc_counter >= 4 and prot_is_online and not prot_disk_dead:
            prot_n_recalc_counter = 0
            _prot_update_desired_n()

        # ---- 8. Protagonist initial shard placement ----
        if prot_is_online and not prot_disk_dead and not prot_device_lost:
            for f in range(N_FILES):
                if len(prot_shards[f]) == 0:
                    _prot_place_shards(f)

        # ---- 9. Protagonist shard repair (only when online and disk alive) ----
        if prot_is_online and not prot_disk_dead and not prot_device_lost:
            # Repair all files each week (protagonist is the one we care about)
            for f in range(N_FILES):
                if len(prot_shards[f]) > 0:
                    _prot_repair_shards(f)

        # ---- 10. Scenario 5 cascade: as storage ratio drops, partners'
        #     trust toward protagonist drops too. Partners doing repair may
        #     reallocate protagonist's shards to others (we model this as
        #     random shard loss proportional to trust drop when offline from
        #     partners' perspective). We approximate: when protagonist's
        #     effective S drops, partner-assigned trust drops, so when
        #     partners do repair they may drop some of protagonist's shards.
        #     We simulate this by probabilistically dropping shards based on
        #     how much trust fell below threshold. ----
        if scenario_id == 5 and week >= 52:
            # Mean trust partners assign to protagonist
            mean_t = _mean_trust_toward_prot()
            trust_fraction = min(mean_t / _MAX_TRUST, 1.0)
            # Partners probabilistically evict one shard per week if trust
            # has fallen significantly. Rate: (1 - trust_fraction) * 0.1 per file
            evict_prob = (1.0 - trust_fraction) * 0.10
            if evict_prob > 0.01:
                for f in range(N_FILES):
                    shards_f = prot_shards[f]
                    if not shards_f:
                        continue
                    # Remove one shard with probability evict_prob
                    if rng.random() < evict_prob:
                        idx_remove = int(rng.integers(0, len(shards_f)))
                        prot_shards[f].pop(idx_remove)

        # ---- 11. Snapshot ----
        snapshots.append(_take_snapshot(week))

    return snapshots


# ---------------------------------------------------------------------------
# Multiple seeds + aggregation
# ---------------------------------------------------------------------------

def run_scenario_seeds(
    scenario_id: int,
    n_seeds: int,
    n_jobs: int,
) -> dict:
    """Run scenario with n_seeds seeds, return aggregated results."""
    seeds = list(range(42, 42 + n_seeds))

    if n_jobs == 1 or n_seeds == 1:
        all_snapshots = [simulate_scenario(scenario_id, s) for s in seeds]
    else:
        all_snapshots = Parallel(n_jobs=n_jobs)(
            delayed(simulate_scenario)(scenario_id, s) for s in seeds
        )

    sdef = SCENARIOS[scenario_id]
    n_weeks = sdef.n_weeks

    # Aggregate: for each week, compute median and min/max across seeds
    agg: list[dict] = []
    for week in range(n_weeks):
        week_snaps = [all_snapshots[s][week] for s in range(n_seeds)]

        def _med(key: str) -> float:
            vals = [getattr(ws, key) for ws in week_snaps]
            return float(np.median(vals))

        def _med_list(key: str, idx: int) -> float:
            vals = [getattr(ws, key)[idx] for ws in week_snaps]
            return float(np.median(vals))

        agg.append({
            "week": week,
            "protagonist_mean_trust": _med("protagonist_mean_trust"),
            "protagonist_p": _med("protagonist_p"),
            "protagonist_i": _med("protagonist_i"),
            "protagonist_s_mean": _med("protagonist_s_mean"),
            "n_partners": int(round(_med("n_partners"))),
            "n_partners_storing": int(round(_med("n_partners_storing"))),
            "docs_live": int(round(_med_list("live_shards", 0))),
            "docs_total": int(round(_med_list("total_shards", 0))),
            "docs_can_restore": bool(
                float(np.median([ws.can_restore[0] for ws in week_snaps])) >= 0.5
            ),
            "photos_live": int(round(_med_list("live_shards", 1))),
            "photos_total": int(round(_med_list("total_shards", 1))),
            "photos_can_restore": bool(
                float(np.median([ws.can_restore[1] for ws in week_snaps])) >= 0.5
            ),
            "video_live": int(round(_med_list("live_shards", 2))),
            "video_total": int(round(_med_list("total_shards", 2))),
            "video_can_restore": bool(
                float(np.median([ws.can_restore[2] for ws in week_snaps])) >= 0.5
            ),
            "is_online": bool(
                float(np.median([float(ws.is_online) for ws in week_snaps])) >= 0.5
            ),
            "storage_for_others_gb": _med("storage_for_others_gb"),
        })

    # Raw per-seed snapshots serialized to simple dicts
    raw: list[list[dict]] = []
    for s_snaps in all_snapshots:
        seed_raw = []
        for ws in s_snaps:
            seed_raw.append({
                "week": ws.week,
                "trust": ws.protagonist_mean_trust,
                "p": ws.protagonist_p,
                "i": ws.protagonist_i,
                "s": ws.protagonist_s_mean,
                "partners": ws.n_partners,
                "storing": ws.n_partners_storing,
                "docs_live": ws.live_shards[0],
                "docs_total": ws.total_shards[0],
                "docs_restore": ws.can_restore[0],
                "photos_live": ws.live_shards[1],
                "photos_total": ws.total_shards[1],
                "photos_restore": ws.can_restore[1],
                "video_live": ws.live_shards[2],
                "video_total": ws.total_shards[2],
                "video_restore": ws.can_restore[2],
                "online": ws.is_online,
                "storage_gb": ws.storage_for_others_gb,
            })
        raw.append(seed_raw)

    return {
        "scenario_id": scenario_id,
        "scenario_name": sdef.name,
        "n_seeds": n_seeds,
        "aggregated": agg,
        "per_seed": raw,
    }


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def _restore_str(agg_week: dict) -> str:
    parts = []
    if agg_week["docs_can_restore"]:
        parts.append("docs")
    if agg_week["photos_can_restore"]:
        parts.append("photos")
    if agg_week["video_can_restore"]:
        parts.append("video")
    return ",".join(parts) if parts else "---"


def _online_str(agg_week: dict) -> str:
    return "yes" if agg_week["is_online"] else "NO "


def _trust_norm(trust: float) -> float:
    return min(trust / _MAX_TRUST, 1.0)


def print_scenario_results(result: dict) -> None:
    sdef = SCENARIOS[result["scenario_id"]]
    print(f"\n{'=' * 80}")
    print(f"Scenario {sdef.id}: {sdef.name}")
    print(f"  {sdef.description}")
    print(f"  Seeds: {result['n_seeds']}  |  n_weeks: {len(result['aggregated'])}")
    print(f"{'=' * 80}")

    escrow_req = [escrow_weeks_required(fd.size_gb) for fd in PROTAGONIST_FILES]
    print(
        f"  Escrow required: "
        f"docs(2GB)={escrow_req[0]}wk  "
        f"photos(20GB)={escrow_req[1]}wk  "
        f"video(80GB)={escrow_req[2]}wk"
    )
    print()
    print(
        f"  {'Month':>5}  {'Online':>6}  {'Partners':>12}  {'Trust':>7}  "
        f"{'Docs(k=5)':>11}  {'Photos(k=5)':>13}  {'Video(k=5)':>12}  {'Restore?'}"
    )
    print(f"  {'-' * 5}  {'-' * 6}  {'-' * 12}  {'-' * 7}  "
          f"{'-' * 11}  {'-' * 13}  {'-' * 12}  {'-' * 20}")

    agg = result["aggregated"]
    # Print every 4 weeks (monthly)
    for week in range(0, len(agg), 4):
        w = agg[week]
        month = week // 4
        online = _online_str(w)
        partners = f"{w['n_partners']}/{w['n_partners_storing']}"
        trust = f"{_trust_norm(w['protagonist_mean_trust']):.3f}"
        docs = f"{w['docs_live']}/{w['docs_total']}"
        photos = f"{w['photos_live']}/{w['photos_total']}"
        video = f"{w['video_live']}/{w['video_total']}"
        restore = _restore_str(w)
        print(
            f"  {month:>5}  {online:>6}  {partners:>12}  {trust:>7}  "
            f"{docs:>11}  {photos:>13}  {video:>12}  {restore}"
        )

    # Key events summary
    print()
    _print_key_events(result)


def _print_key_events(result: dict) -> None:
    """Print scenario-specific key event observations."""
    agg = result["aggregated"]
    scenario_id = result["scenario_id"]
    print("  --- Key events ---")

    # First restore availability per file
    for f_idx, fname in enumerate(["docs", "photos", "video"]):
        key = f"{fname}_can_restore"
        for w in agg:
            if w[key]:
                wk = w["week"]
                print(f"  First restore possible ({fname}): week {wk} (month {wk // 4})")
                break
        else:
            print(f"  {fname}: never restorable within simulation window")

    if scenario_id == 2:
        # Trust at disk failure (week 104)
        w104 = agg[104] if len(agg) > 104 else agg[-1]
        print(f"  Trust at disk failure (week 104): "
              f"{_trust_norm(w104['protagonist_mean_trust']):.3f} "
              f"(P={w104['protagonist_p']:.3f}, I={w104['protagonist_i']:.3f})")
        print(f"  Shards alive at crash: "
              f"docs={w104['docs_live']}/{w104['docs_total']}  "
              f"photos={w104['photos_live']}/{w104['photos_total']}  "
              f"video={w104['video_live']}/{w104['video_total']}")

    elif scenario_id == 3:
        # State at loss (week 52), state at return (week 78)
        w52 = agg[52] if len(agg) > 52 else agg[-1]
        w78 = agg[78] if len(agg) > 78 else agg[-1]
        print(f"  At device loss (week 52): trust={_trust_norm(w52['protagonist_mean_trust']):.3f} "
              f"docs={w52['docs_live']}  photos={w52['photos_live']}  video={w52['video_live']}")
        print(f"  At return (week 78): trust={_trust_norm(w78['protagonist_mean_trust']):.3f} "
              f"docs={w78['docs_live']}  photos={w78['photos_live']}  video={w78['video_live']}")
        # Shard survival during gap
        shards_at_loss = [w52['docs_live'], w52['photos_live'], w52['video_live']]
        shards_at_return = [w78['docs_live'], w78['photos_live'], w78['video_live']]
        for fname, s_loss, s_return in zip(
            ["docs", "photos", "video"], shards_at_loss, shards_at_return
        ):
            if s_loss > 0:
                pct = 100.0 * s_return / s_loss
                print(f"  Shard survival during 26-week gap ({fname}): "
                      f"{s_return}/{s_loss} = {pct:.0f}%")

    elif scenario_id == 4:
        # Trust drop/recovery around vacation
        w52 = agg[52] if len(agg) > 52 else agg[-1]
        w60 = agg[60] if len(agg) > 60 else agg[-1]
        w68 = agg[68] if len(agg) > 68 else agg[-1]
        print(f"  Before vacation (week 52): trust={_trust_norm(w52['protagonist_mean_trust']):.3f}")
        print(f"  After vacation (week 60):  trust={_trust_norm(w60['protagonist_mean_trust']):.3f}")
        print(f"  Recovery at week 68:       trust={_trust_norm(w68['protagonist_mean_trust']):.3f}")

    elif scenario_id == 5:
        # Trust degradation over time
        w52 = agg[52] if len(agg) > 52 else agg[-1]
        w78 = agg[78] if len(agg) > 78 else agg[-1]
        w104 = agg[104] if len(agg) > 104 else agg[-1]
        print(f"  Before disk full (week 52): trust={_trust_norm(w52['protagonist_mean_trust']):.3f} "
              f"storage_for_others={w52['storage_for_others_gb']:.1f}GB")
        print(f"  At week 78: trust={_trust_norm(w78['protagonist_mean_trust']):.3f} "
              f"storage={w78['storage_for_others_gb']:.1f}GB  "
              f"docs_shards={w78['docs_live']}/{w78['docs_total']}")
        print(f"  At week 104: trust={_trust_norm(w104['protagonist_mean_trust']):.3f} "
              f"storage={w104['storage_for_others_gb']:.1f}GB  "
              f"docs_shards={w104['docs_live']}/{w104['docs_total']}")

    elif scenario_id == 6:
        # Average shard survival and trust with nomad availability
        mid = agg[78]
        end = agg[-1]
        print(f"  Mid-point (week 78): trust={_trust_norm(mid['protagonist_mean_trust']):.3f} "
              f"docs={mid['docs_live']}/{mid['docs_total']}  "
              f"photos={mid['photos_live']}/{mid['photos_total']}")
        print(f"  End (week {end['week']}): trust={_trust_norm(end['protagonist_mean_trust']):.3f} "
              f"docs={end['docs_live']}/{end['docs_total']}  "
              f"video={end['video_live']}/{end['video_total']}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_scenario_list(s: str) -> list[int]:
    if s == "all":
        return list(SCENARIOS.keys())
    parts = s.split(",")
    result = []
    for p in parts:
        p = p.strip()
        if p.isdigit():
            v = int(p)
            if v not in SCENARIOS:
                raise ValueError(f"Unknown scenario: {v}")
            result.append(v)
        else:
            raise ValueError(f"Cannot parse scenario: {p!r}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Viaticum user perspective simulation"
    )
    parser.add_argument(
        "--scenario",
        default="all",
        help="Scenario(s) to run: 'all', a number (1-6), or comma-separated list",
    )
    parser.add_argument(
        "--seeds",
        type=int,
        default=5,
        help="Number of seeds per scenario (default: 5)",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=6,
        help="Parallel jobs (default: 6)",
    )
    args = parser.parse_args()

    try:
        scenario_ids = _parse_scenario_list(args.scenario)
    except ValueError as e:
        print(f"Error: {e}")
        raise SystemExit(1)

    out_dir = Path("results/user_perspective")
    out_dir.mkdir(parents=True, exist_ok=True)

    all_results: dict[int, dict] = {}
    total_start = time.time()

    for sid in scenario_ids:
        sdef = SCENARIOS[sid]
        print(f"\nRunning scenario {sid}: {sdef.name} ({sdef.description})")
        print(f"  {args.seeds} seeds x {sdef.n_weeks} weeks = "
              f"{args.seeds * sdef.n_weeks} week-runs")

        t0 = time.time()
        result = run_scenario_seeds(sid, args.seeds, args.jobs)
        elapsed = time.time() - t0
        print(f"  Done in {elapsed:.1f}s")

        all_results[sid] = result
        print_scenario_results(result)

        # Save JSON
        out_path = out_dir / f"scenario_{sid}_{sdef.name.lower()}.json"
        # Convert to JSON-serializable (booleans already fine, floats may be nan)
        def _clean(obj: object) -> object:
            if isinstance(obj, dict):
                return {k: _clean(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_clean(x) for x in obj]
            if isinstance(obj, float) and (obj != obj):  # nan check
                return None
            return obj

        with open(out_path, "w") as fh:
            json.dump(_clean(result), fh, indent=2)
        print(f"  Saved: {out_path}")

    total_elapsed = time.time() - total_start
    print(f"\nTotal time: {total_elapsed:.1f}s")

    # Cross-scenario summary
    if len(scenario_ids) > 1:
        print(f"\n{'=' * 80}")
        print("CROSS-SCENARIO SUMMARY (end state, week 155)")
        print(f"{'=' * 80}")
        print(
            f"  {'Scenario':<30} {'Trust':>7}  "
            f"{'Docs':>10}  {'Photos':>13}  {'Video':>12}  {'All restorable?'}"
        )
        print(f"  {'-' * 30}  {'-' * 7}  {'-' * 10}  {'-' * 13}  {'-' * 12}  {'-' * 16}")
        for sid, result in all_results.items():
            sdef = SCENARIOS[sid]
            agg = result["aggregated"]
            end = agg[-1]
            trust_s = f"{_trust_norm(end['protagonist_mean_trust']):.3f}"
            docs_s = f"{end['docs_live']}/{end['docs_total']}"
            photos_s = f"{end['photos_live']}/{end['photos_total']}"
            video_s = f"{end['video_live']}/{end['video_total']}"
            all_ok = all([end["docs_can_restore"], end["photos_can_restore"], end["video_can_restore"]])
            all_s = "yes" if all_ok else "NO"
            print(
                f"  {sid}. {sdef.name:<27} {trust_s:>7}  "
                f"{docs_s:>10}  {photos_s:>13}  {video_s:>12}  {all_s}"
            )


if __name__ == "__main__":
    main()
