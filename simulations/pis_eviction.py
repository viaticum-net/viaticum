"""
Viaticum Simulation #23: Eviction Strategies

Question: Does active partner eviction improve network quality, and what kind of
eviction (economic/disk-pressure vs. threshold-based) works best?

In the baseline (Strategy A), partnerships only dissolve when a node churns.
We test two active eviction strategies:

  B: Soft eviction (economic) -- drop the lowest-trust partner when over capacity.
     Simulates natural disk pressure: replace a bad partner with a better one.

  C: Hard eviction (threshold) -- drop any partner whose trust falls below a
     fixed threshold (tested at 0.5, 1.0, 1.5).

Trust formula (multiplicative S, as specified):
    trust_AB = (kp * P_B + ki * I_B) * max(min(S_AB, 1.0), 0.1)
    kp=0.5, ki=2.0
    S_AB = STORAGE_RATIOS[arch_B] / max(STORAGE_RATIOS[arch_A], 0.01)

Metrics collected at years 1, 3, 5:
  - Kendall's tau: trust ranking vs. actual archetype usefulness
  - Partner turnover rate: (churn_breaks + eviction_breaks) / node / year
  - Archetype segregation: per-archetype fraction of same-archetype partners
  - Newcomer integration time: median weeks until new node has target_partners
  - "Honest trapped" rate: honest nodes (arch 0-3) with >50% bad partners (arch 4-5)
  - Trust distribution by archetype

Design decisions:
  - Eviction runs every 4 weeks, after trust is updated (step 6).
  - Eviction is mutual: when A drops B, B loses A too.
  - For hard eviction, both directions are checked independently, so A can
    drop B even if B trusts A above threshold.
  - Partnership turnover counts each severed bond once (from the initiating side
    for eviction, or once on churn removal).
  - Newcomer integration: tracked only for nodes that join after week 0
    (not bootstrap nodes). We record the first week they reach target_partners.
  - With multiplicative S, Freeloaders (r=0.1) get clamped to S_eff = 0.1 when
    evaluated by Reliable peers, making their trust roughly 0.1x a Reliable peer
    with same P+I. This creates stronger isolation pressure than additive S.

Usage:
    python pis_eviction.py                    # 1 seed, all strategies
    python pis_eviction.py --seeds 10 --jobs 6
    python pis_eviction.py --output results/pis_eviction
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

import numpy as np
from joblib import Parallel, delayed
from scipy.stats import kendalltau


# ---------------------------------------------------------------------------
# Archetype definitions
# ---------------------------------------------------------------------------

ARCHETYPE_NAMES = [
    "Reliable",
    "Weekend",
    "Seasonal",
    "Nomad",
    "Hoarder",
    "Freeloader",
]

# Lower rank = more useful to the network.
ACTUAL_USEFULNESS_RANK = [1, 2, 3, 4, 5, 6]

ARCHETYPE_PROBS = np.array([0.35, 0.25, 0.15, 0.10, 0.10, 0.05])

# Storage offer ratio per archetype.
STORAGE_RATIOS = np.array([1.0, 1.0, 1.0, 1.0, 0.2, 0.1], dtype=np.float64)

N_ARCHETYPES = len(ARCHETYPE_NAMES)

# Archetypes 0-3 are "honest"; 4-5 are "bad" (Hoarder, Freeloader).
BAD_ARCHETYPES = {4, 5}

_S_EPS = 0.01


# ---------------------------------------------------------------------------
# Trust formula
# ---------------------------------------------------------------------------

def _compute_trust_multiplicative(
    p_b: float,
    i_b: float,
    arch_a: int,
    arch_b: int,
    kp: float,
    ki: float,
) -> float:
    """
    Multiplicative PI+S trust: A evaluates B.

    trust_AB = (kp * P_B + ki * I_B) * max(min(S_AB, 1.0), 0.1)
    S_AB = STORAGE_RATIOS[arch_B] / max(STORAGE_RATIOS[arch_A], _S_EPS)

    The S term acts as a multiplier in [0.1, 1.0].  Nodes that store less than
    the observer contribute at most 1.0x; those that store more are not rewarded
    above 1.0x (excess storage doesn't inflate trust beyond proportional).
    """
    r_a = float(STORAGE_RATIOS[arch_a])
    r_b = float(STORAGE_RATIOS[arch_b])
    s_ab = r_b / max(r_a, _S_EPS)
    s_eff = max(min(s_ab, 1.0), 0.1)
    return (kp * p_b + ki * i_b) * s_eff


def _trust_vec_from_a(
    a_arch: int,
    candidates: np.ndarray,
    archetype: np.ndarray,
    p_val: np.ndarray,
    i_val: np.ndarray,
    kp: float,
    ki: float,
) -> np.ndarray:
    """Vectorised trust: node a evaluates array of candidate nodes."""
    r_a = float(STORAGE_RATIOS[a_arch])
    r_cands = STORAGE_RATIOS[archetype[candidates]]
    s_ab = r_cands / max(r_a, _S_EPS)
    s_eff = np.clip(s_ab, 0.1, 1.0)
    return (kp * p_val[candidates] + ki * i_val[candidates]) * s_eff


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class EvictionStrategy:
    NONE = "none"
    SOFT = "soft"
    HARD = "hard"


@dataclass
class Config:
    kp: float = 0.5
    ki: float = 2.0
    p_window_weeks: int = 4
    initial_peers: int = 50
    max_active_peers: int = 5_000
    annual_churn: float = 0.25
    target_partners: int = 15
    acceptance_gate: float = 0.3
    n_years: int = 5
    n_seeds: int = 1
    eviction_strategy: str = EvictionStrategy.NONE
    # Used only for hard eviction:
    eviction_threshold: float = 1.0
    # Run eviction every N weeks:
    eviction_period_weeks: int = 4


def _weekly_churn_prob(cfg: Config) -> float:
    return 1.0 - (1.0 - cfg.annual_churn) ** (1.0 / 52.0)


def _new_nodes_this_week(week: int) -> int:
    """Growth schedule: year 1 +25/wk, years 2-3 +100/wk, years 4-5 +50/wk."""
    if week < 52:
        return 25
    elif week < 156:
        return 100
    else:
        return 50


# ---------------------------------------------------------------------------
# Weekly pass probabilities (precomputed per archetype)
# ---------------------------------------------------------------------------

def _build_weekly_pass_probs(n_weeks: int) -> np.ndarray:
    """Shape (N_ARCHETYPES, n_weeks). P(at least 1 of 7 daily checks passes)."""
    week_idx = np.arange(n_weeks)
    week_in_year = week_idx % 52
    probs = np.zeros((N_ARCHETYPES, n_weeks), dtype=np.float64)

    # Reliable: 99% daily
    probs[0, :] = 1.0 - (1.0 - 0.99) ** 7

    # Weekend: Fri/Sat/Sun 95%, Mon-Thu 30%
    p_fail_wknd = (1.0 - 0.95) ** 3 * (1.0 - 0.30) ** 4
    probs[1, :] = 1.0 - p_fail_wknd

    # Seasonal: 95% semester, 20% summer (weeks 22-35 in year)
    is_summer = (week_in_year >= 22) & (week_in_year <= 35)
    r_seasonal = np.where(is_summer, 0.20, 0.95)
    probs[2, :] = 1.0 - (1.0 - r_seasonal) ** 7

    # Nomad: 50% chance online this week, 100% when online
    probs[3, :] = 0.50

    # Hoarder: 90% daily
    probs[4, :] = 1.0 - (1.0 - 0.90) ** 7

    # Freeloader: 80% daily
    probs[5, :] = 1.0 - (1.0 - 0.80) ** 7

    return probs


# ---------------------------------------------------------------------------
# Eviction logic
# ---------------------------------------------------------------------------

def _soft_eviction(
    nid: int,
    partners: list[set[int]],
    archetype: np.ndarray,
    p_val: np.ndarray,
    i_val: np.ndarray,
    cfg: Config,
) -> int:
    """
    Soft (economic) eviction: if node nid has more partners than target,
    drop the lowest-trust ones until back at target.
    Returns number of partnerships broken.
    """
    excess = len(partners[nid]) - cfg.target_partners
    if excess <= 0:
        return 0

    a_arch = int(archetype[nid])
    partner_list = list(partners[nid])
    trust_vals = [
        _compute_trust_multiplicative(
            float(p_val[pid]), float(i_val[pid]),
            a_arch, int(archetype[pid]),
            cfg.kp, cfg.ki,
        )
        for pid in partner_list
    ]
    # Sort ascending: lowest trust first
    sorted_pairs = sorted(zip(trust_vals, partner_list), key=lambda x: x[0])
    n_broken = 0
    for _, pid in sorted_pairs[:excess]:
        partners[nid].discard(pid)
        partners[pid].discard(nid)
        n_broken += 1
    return n_broken


def _hard_eviction(
    nid: int,
    partners: list[set[int]],
    archetype: np.ndarray,
    p_val: np.ndarray,
    i_val: np.ndarray,
    cfg: Config,
) -> int:
    """
    Hard (threshold) eviction: drop all partners below eviction_threshold.
    Each severed bond counted once (from nid's perspective).
    Returns number of partnerships broken.
    """
    a_arch = int(archetype[nid])
    to_drop = []
    for pid in list(partners[nid]):
        t = _compute_trust_multiplicative(
            float(p_val[pid]), float(i_val[pid]),
            a_arch, int(archetype[pid]),
            cfg.kp, cfg.ki,
        )
        if t < cfg.eviction_threshold:
            to_drop.append(pid)
    for pid in to_drop:
        partners[nid].discard(pid)
        partners[pid].discard(nid)
    return len(to_drop)


# ---------------------------------------------------------------------------
# Core simulation
# ---------------------------------------------------------------------------

@dataclass
class YearlySnapshot:
    year: int
    kendall_tau: float
    turnover_rate: float          # partnerships broken per node per year
    same_arch_frac: dict[str, float]  # per archetype, fraction of same-arch partners
    newcomer_integ_weeks: float   # median weeks until target_partners (0 = none joined)
    honest_trapped_frac: float    # fraction of honest nodes with >50% bad partners
    arch_trust: dict[str, float]  # mean incoming trust by archetype
    n_active: int
    mean_partners: float


def simulate_one(cfg: Config, seed: int) -> list[YearlySnapshot]:
    """
    Simulate one 5-year run with the given eviction strategy.
    Returns a YearlySnapshot per year (years 1..n_years).
    """
    rng = np.random.default_rng(seed)
    cap = cfg.max_active_peers
    n_weeks = cfg.n_years * 52
    pw = cfg.p_window_weeks

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

    partners: list[set[int]] = [set() for _ in range(cap)]

    # Integration tracking: for nodes that join after bootstrap, record
    # the first week they reach target_partners.  -1 = not yet reached.
    integ_week: np.ndarray = np.full(cap, -1, dtype=np.int32)
    is_bootstrap: np.ndarray = np.zeros(cap, dtype=bool)

    # Turnover counters (reset each year)
    churn_breaks_year = 0
    eviction_breaks_year = 0
    node_weeks_year = 0  # sum of active-node-weeks (for per-node-per-year rate)

    weekly_pass_probs = _build_weekly_pass_probs(n_weeks)
    weekly_churn = _weekly_churn_prob(cfg)

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

    def _add(nid: int, week: int, bootstrap: bool = False) -> None:
        atype = int(rng.choice(N_ARCHETYPES, p=ARCHETYPE_PROBS.tolist()))
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
        partners[nid] = set()
        integ_week[nid] = -1
        is_bootstrap[nid] = bootstrap

    def _remove(nid: int) -> int:
        """Remove node, return number of broken partnerships."""
        alive[nid] = False
        n_broken = len(partners[nid])
        for pid in partners[nid]:
            partners[pid].discard(nid)
        partners[nid].clear()
        free_ids.append(nid)
        return n_broken

    # Bootstrap
    for _ in range(cfg.initial_peers):
        nid = _alloc()
        if nid is None:
            break
        _add(nid, 0, bootstrap=True)

    snapshot_weeks = {y * 52 for y in range(1, cfg.n_years + 1)}
    yearly_snapshots: list[YearlySnapshot] = []

    for week in range(n_weeks):
        nonlocal_churn_breaks = 0
        nonlocal_eviction_breaks = 0

        # --- 1. Growth ---
        n_active = int(alive.sum())
        if n_active < cfg.max_active_peers:
            n_new = min(_new_nodes_this_week(week), cfg.max_active_peers - n_active)
            for _ in range(n_new):
                nid = _alloc()
                if nid is None:
                    break
                _add(nid, week, bootstrap=False)

        # --- 2. Churn ---
        active_ids = np.where(alive)[0]
        if active_ids.size > 0:
            churn_mask = rng.random(active_ids.size) < weekly_churn
            for nid_idx in active_ids[churn_mask]:
                nonlocal_churn_breaks += _remove(int(nid_idx))

        # --- 3. Weekly check scores ---
        active_ids = np.where(alive)[0]
        if active_ids.size == 0:
            churn_breaks_year += nonlocal_churn_breaks
            node_weeks_year += 0
            continue

        node_weeks_year += int(active_ids.size)

        active_arch = archetype[active_ids]
        week_scores = np.zeros(active_ids.size, dtype=np.float64)
        for atype_idx in range(N_ARCHETYPES):
            grp = np.where(active_arch == atype_idx)[0]
            if grp.size == 0:
                continue
            p_w = float(weekly_pass_probs[atype_idx, week])
            week_scores[grp] = (rng.random(grp.size) < p_w).astype(np.float64)

        # --- 4. Update circular P buffer ---
        pos = p_buf_pos[active_ids]
        p_buf[active_ids, pos] = week_scores
        p_buf_pos[active_ids] = (pos + 1) % pw
        filled = p_buf_filled[active_ids]
        p_buf_filled[active_ids] = np.minimum(filled + 1, pw)

        # --- 5. Update I ---
        i_sum[active_ids] += week_scores
        i_count[active_ids] += 1

        # --- 6. Recompute P and I arrays ---
        p_buf_sums = p_buf[active_ids, :].sum(axis=1)
        pf = p_buf_filled[active_ids].astype(np.float64)
        p_val[active_ids] = np.where(pf > 0, p_buf_sums / pf, 0.0)
        ic = i_count[active_ids].astype(np.float64)
        i_val[active_ids] = np.where(ic > 0, i_sum[active_ids] / ic, 0.0)

        # --- 7. Eviction (every eviction_period_weeks weeks) ---
        if (week + 1) % cfg.eviction_period_weeks == 0:
            if cfg.eviction_strategy == EvictionStrategy.SOFT:
                for nid in active_ids:
                    nonlocal_eviction_breaks += _soft_eviction(
                        int(nid), partners, archetype, p_val, i_val, cfg
                    )
            elif cfg.eviction_strategy == EvictionStrategy.HARD:
                # Process each node; discard already counts mutually so we
                # track from initiating side only to avoid double-counting.
                # But since we remove partner[nid].discard(pid) and partner[pid].discard(nid),
                # pid may later also try to "evict" nid which is already gone —
                # that iteration finds empty set, so count stays accurate.
                evicted_this_round: set[tuple[int, int]] = set()
                for nid in active_ids:
                    nid = int(nid)
                    a_arch = int(archetype[nid])
                    to_drop = []
                    for pid in list(partners[nid]):
                        pair = (min(nid, pid), max(nid, pid))
                        if pair in evicted_this_round:
                            continue
                        t = _compute_trust_multiplicative(
                            float(p_val[pid]), float(i_val[pid]),
                            a_arch, int(archetype[pid]),
                            cfg.kp, cfg.ki,
                        )
                        if t < cfg.eviction_threshold:
                            to_drop.append(pid)
                            evicted_this_round.add(pair)
                    for pid in to_drop:
                        partners[nid].discard(pid)
                        partners[pid].discard(nid)
                    nonlocal_eviction_breaks += len(to_drop)

        churn_breaks_year += nonlocal_churn_breaks
        eviction_breaks_year += nonlocal_eviction_breaks

        # --- 8. Partnership formation ---
        _update_partnerships(
            np.where(alive)[0], alive, archetype, i_val, p_val, partners, cfg, rng
        )

        # --- 9. Newcomer integration check ---
        active_ids_post = np.where(alive)[0]
        for nid in active_ids_post:
            nid = int(nid)
            if is_bootstrap[nid]:
                continue
            if integ_week[nid] >= 0:
                continue
            if len(partners[nid]) >= cfg.target_partners:
                integ_week[nid] = week - int(join_week[nid])

        # --- 10. Yearly snapshot ---
        if (week + 1) in snapshot_weeks:
            year = (week + 1) // 52
            snap = _build_snapshot(
                year=year,
                active_ids=np.where(alive)[0],
                archetype=archetype,
                i_val=i_val,
                p_val=p_val,
                partners=partners,
                integ_week=integ_week,
                is_bootstrap=is_bootstrap,
                churn_breaks=churn_breaks_year,
                eviction_breaks=eviction_breaks_year,
                node_weeks=node_weeks_year,
                cfg=cfg,
            )
            yearly_snapshots.append(snap)
            # Reset yearly counters
            churn_breaks_year = 0
            eviction_breaks_year = 0
            node_weeks_year = 0

    return yearly_snapshots


def _update_partnerships(
    active_ids: np.ndarray,
    alive: np.ndarray,
    archetype: np.ndarray,
    i_val: np.ndarray,
    p_val: np.ndarray,
    partners: list[set[int]],
    cfg: Config,
    rng: np.random.Generator,
) -> None:
    """
    Form new partnerships for underfull nodes (up to 500 per week).
    Uses multiplicative S for candidate ranking.
    Acceptance gate: newcomers (I < gate) only connect to other newcomers.
    """
    on_count = np.array([len(partners[int(nid)]) for nid in active_ids], dtype=np.int32)
    underfull_mask = on_count < cfg.target_partners
    underfull = active_ids[underfull_mask]
    if underfull.size == 0:
        return
    if underfull.size > 500:
        underfull = rng.choice(underfull, size=500, replace=False)

    for pid in underfull:
        pid = int(pid)
        n_needed = cfg.target_partners - len(partners[pid])
        if n_needed <= 0:
            continue

        a_pid = int(archetype[pid])
        req_i = float(i_val[pid])

        # Build candidate mask
        mask = alive.copy()
        mask[pid] = False
        for existing in partners[pid]:
            if existing < len(mask):
                mask[existing] = False
        # Capacity check
        for cid_idx in np.where(mask)[0]:
            if len(partners[int(cid_idx)]) >= cfg.target_partners:
                mask[int(cid_idx)] = False

        # Acceptance gate
        if req_i < cfg.acceptance_gate:
            gate_mask = i_val <= cfg.acceptance_gate
            mask &= gate_mask

        candidates = np.where(mask)[0]
        if candidates.size == 0:
            # Relax gate as last resort
            mask2 = alive.copy()
            mask2[pid] = False
            for existing in partners[pid]:
                if existing < len(mask2):
                    mask2[existing] = False
            for cid_idx in np.where(mask2)[0]:
                if len(partners[int(cid_idx)]) >= cfg.target_partners:
                    mask2[int(cid_idx)] = False
            candidates = np.where(mask2)[0]
            if candidates.size == 0:
                continue

        c_trust = _trust_vec_from_a(
            a_pid, candidates, archetype, p_val, i_val, cfg.kp, cfg.ki
        )
        c_trust = np.maximum(c_trust, 1e-6)
        probs = c_trust / c_trust.sum()
        n_pick = min(n_needed, candidates.size)
        chosen = rng.choice(candidates, size=n_pick, replace=False, p=probs)
        for cid in chosen:
            cid = int(cid)
            partners[pid].add(cid)
            partners[cid].add(pid)


def _build_snapshot(
    year: int,
    active_ids: np.ndarray,
    archetype: np.ndarray,
    i_val: np.ndarray,
    p_val: np.ndarray,
    partners: list[set[int]],
    integ_week: np.ndarray,
    is_bootstrap: np.ndarray,
    churn_breaks: int,
    eviction_breaks: int,
    node_weeks: int,
    cfg: Config,
) -> YearlySnapshot:
    if active_ids.size == 0:
        return YearlySnapshot(
            year=year,
            kendall_tau=0.0,
            turnover_rate=0.0,
            same_arch_frac={n: 0.0 for n in ARCHETYPE_NAMES},
            newcomer_integ_weeks=0.0,
            honest_trapped_frac=0.0,
            arch_trust={n: 0.0 for n in ARCHETYPE_NAMES},
            n_active=0,
            mean_partners=0.0,
        )

    active_set = set(int(x) for x in active_ids)

    # --- Kendall's tau ---
    arch_trust_vals: dict[str, float] = {}
    for target_arch_idx, name in enumerate(ARCHETYPE_NAMES):
        target_mask = archetype[active_ids] == target_arch_idx
        target_nodes = active_ids[target_mask]
        if target_nodes.size == 0:
            arch_trust_vals[name] = 0.0
            continue
        r_b = float(STORAGE_RATIOS[target_arch_idx])
        t_sum = 0.0
        obs_cnt = 0
        for b in target_nodes:
            b = int(b)
            p_b = float(p_val[b])
            i_b = float(i_val[b])
            for a in partners[b]:
                if a not in active_set:
                    continue
                a_arch = int(archetype[a])
                t = _compute_trust_multiplicative(p_b, i_b, a_arch, target_arch_idx, cfg.kp, cfg.ki)
                t_sum += t
                obs_cnt += 1
        arch_trust_vals[name] = t_sum / max(obs_cnt, 1)

    trust_vec = np.array([arch_trust_vals[n] for n in ARCHETYPE_NAMES])
    tau_val, _ = kendalltau(trust_vec, -np.array(ACTUAL_USEFULNESS_RANK))

    # --- Turnover rate ---
    total_breaks = churn_breaks + eviction_breaks
    # node_weeks / 52 = node-years; divide breaks by that
    node_years = node_weeks / 52.0
    turnover_rate = (total_breaks / max(node_years, 1.0))

    # --- Archetype segregation ---
    same_arch_frac: dict[str, float] = {}
    for atype_idx, name in enumerate(ARCHETYPE_NAMES):
        nodes_of_arch = [
            int(nid) for nid in active_ids
            if int(archetype[nid]) == atype_idx
        ]
        if not nodes_of_arch:
            same_arch_frac[name] = 0.0
            continue
        same_total = 0
        all_total = 0
        for nid in nodes_of_arch:
            for pid in partners[nid]:
                if pid not in active_set:
                    continue
                all_total += 1
                if int(archetype[pid]) == atype_idx:
                    same_total += 1
        same_arch_frac[name] = same_total / max(all_total, 1)

    # --- Newcomer integration time ---
    # Only non-bootstrap nodes that have been in the network
    integrated_times: list[int] = []
    for nid in active_ids:
        nid = int(nid)
        if is_bootstrap[nid]:
            continue
        if integ_week[nid] >= 0:
            integrated_times.append(int(integ_week[nid]))
    newcomer_integ = float(np.median(integrated_times)) if integrated_times else 0.0

    # --- Honest trapped ---
    honest_nodes = [
        int(nid) for nid in active_ids
        if int(archetype[nid]) not in BAD_ARCHETYPES
    ]
    trapped_count = 0
    for nid in honest_nodes:
        active_partners = [pid for pid in partners[nid] if pid in active_set]
        if not active_partners:
            continue
        bad_count = sum(1 for pid in active_partners if int(archetype[pid]) in BAD_ARCHETYPES)
        if bad_count / len(active_partners) > 0.5:
            trapped_count += 1
    honest_trapped = trapped_count / max(len(honest_nodes), 1)

    # --- Mean partners ---
    n_partners_arr = np.array([len(partners[int(nid)]) for nid in active_ids], dtype=np.float64)
    mean_partners = float(n_partners_arr.mean())

    return YearlySnapshot(
        year=year,
        kendall_tau=float(tau_val),
        turnover_rate=turnover_rate,
        same_arch_frac=same_arch_frac,
        newcomer_integ_weeks=newcomer_integ,
        honest_trapped_frac=honest_trapped,
        arch_trust=arch_trust_vals,
        n_active=int(active_ids.size),
        mean_partners=mean_partners,
    )


# ---------------------------------------------------------------------------
# Monte Carlo runner for one strategy
# ---------------------------------------------------------------------------

def run_strategy(cfg: Config, n_jobs: int = 1) -> list[YearlySnapshot]:
    """
    Run Monte Carlo over n_seeds, aggregate YearlySnapshots by year.
    Returns one averaged YearlySnapshot per year.
    """
    seeds = list(range(cfg.n_seeds))

    if n_jobs == 1 or cfg.n_seeds == 1:
        all_runs: list[list[YearlySnapshot]] = [simulate_one(cfg, s) for s in seeds]
    else:
        all_runs = Parallel(n_jobs=n_jobs)(
            delayed(simulate_one)(cfg, s) for s in seeds
        )

    # Group by year index
    n_years = cfg.n_years
    per_year: dict[int, list[YearlySnapshot]] = {y: [] for y in range(1, n_years + 1)}
    for run in all_runs:
        for snap in run:
            if snap.year in per_year:
                per_year[snap.year].append(snap)

    def _avg_dict(snaps: list[YearlySnapshot], field_name: str) -> dict[str, float]:
        result: dict[str, float] = {}
        for name in ARCHETYPE_NAMES:
            vals = [getattr(s, field_name)[name] for s in snaps]
            result[name] = float(np.mean(vals))
        return result

    aggregated: list[YearlySnapshot] = []
    for year in range(1, n_years + 1):
        snaps = per_year[year]
        if not snaps:
            continue
        aggregated.append(YearlySnapshot(
            year=year,
            kendall_tau=float(np.mean([s.kendall_tau for s in snaps])),
            turnover_rate=float(np.mean([s.turnover_rate for s in snaps])),
            same_arch_frac=_avg_dict(snaps, "same_arch_frac"),
            newcomer_integ_weeks=float(np.mean([s.newcomer_integ_weeks for s in snaps])),
            honest_trapped_frac=float(np.mean([s.honest_trapped_frac for s in snaps])),
            arch_trust=_avg_dict(snaps, "arch_trust"),
            n_active=int(np.mean([s.n_active for s in snaps])),
            mean_partners=float(np.mean([s.mean_partners for s in snaps])),
        ))
    return aggregated


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def _strategy_label(cfg: Config) -> str:
    if cfg.eviction_strategy == EvictionStrategy.NONE:
        return "Strategy A: No eviction"
    if cfg.eviction_strategy == EvictionStrategy.SOFT:
        return "Strategy B: Soft eviction (economic, at disk pressure)"
    return f"Strategy C: Hard eviction (threshold={cfg.eviction_threshold})"


def print_strategy_results(cfg: Config, snapshots: list[YearlySnapshot]) -> None:
    label = _strategy_label(cfg)
    print(f"\n{label}")
    header = (
        f"  {'Year':>5}  {'Tau':>6}  {'Turnover':>10}  "
        f"{'NewcomerInteg':>14}  {'HonestTrapped':>14}  "
        f"{'HoarderPartners':>16}"
    )
    print(header)
    print("  " + "-" * (len(header) - 2))

    snap_years = {1, 3, 5}
    for s in snapshots:
        if s.year not in snap_years:
            continue
        hoarder_same = s.same_arch_frac.get("Hoarder", 0.0)
        print(
            f"  {s.year:>5}  {s.kendall_tau:>6.3f}  "
            f"{s.turnover_rate:>9.2f}/yr  "
            f"{s.newcomer_integ_weeks:>12.1f} wks  "
            f"{s.honest_trapped_frac*100:>12.1f}%  "
            f"{hoarder_same*100:>13.0f}% same-arch"
        )


def print_arch_trust_section(
    strategy_results: list[tuple[Config, list[YearlySnapshot]]],
) -> None:
    print("\n=== ARCHETYPE TRUST (year 5, each strategy) ===")
    header = f"  {'Archetype':<14}"
    for cfg, _ in strategy_results:
        label = _strategy_label(cfg)
        short = label.replace("Strategy ", "").replace(": ", ":").split(" ")[0]
        header += f"  {short:>10}"
    print(header)
    print("  " + "-" * (14 + 12 * len(strategy_results)))

    for arch_name in ARCHETYPE_NAMES:
        row = f"  {arch_name:<14}"
        for cfg, snaps in strategy_results:
            year5 = next((s for s in snaps if s.year == 5), None)
            val = year5.arch_trust.get(arch_name, 0.0) if year5 else 0.0
            row += f"  {val:>10.3f}"
        print(row)


def print_segregation_section(
    strategy_results: list[tuple[Config, list[YearlySnapshot]]],
) -> None:
    print("\n=== ARCHETYPE SEGREGATION AT YEAR 5 (fraction of same-arch partners) ===")
    header = f"  {'Archetype':<14}"
    for cfg, _ in strategy_results:
        label = _strategy_label(cfg)
        short = label.replace("Strategy ", "").replace(": ", ":").split(" ")[0]
        header += f"  {short:>10}"
    print(header)
    print("  " + "-" * (14 + 12 * len(strategy_results)))

    for arch_name in ARCHETYPE_NAMES:
        row = f"  {arch_name:<14}"
        for cfg, snaps in strategy_results:
            year5 = next((s for s in snaps if s.year == 5), None)
            val = year5.same_arch_frac.get(arch_name, 0.0) if year5 else 0.0
            row += f"  {val*100:>9.1f}%"
        print(row)


# ---------------------------------------------------------------------------
# JSON serialisation
# ---------------------------------------------------------------------------

def _snapshots_to_dict(snaps: list[YearlySnapshot]) -> list[dict]:
    return [asdict(s) for s in snaps]


def save_results(
    strategy_results: list[tuple[Config, list[YearlySnapshot]]],
    output_dir: Path,
    elapsed: float,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

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
        "experiment": "23: Eviction Strategies",
        "elapsed_sec": elapsed,
        "strategies": [
            {
                "config": _convert(asdict(cfg)),
                "label": _strategy_label(cfg),
                "snapshots": _convert(_snapshots_to_dict(snaps)),
            }
            for cfg, snaps in strategy_results
        ],
    }

    path = output_dir / "run.json"
    path.write_text(json.dumps(payload, indent=2))
    print(f"\nResults saved to {path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Viaticum Experiment 23: Eviction Strategies"
    )
    parser.add_argument("--seeds", type=int, default=1,
                        help="Monte Carlo seeds per strategy (default: 1)")
    parser.add_argument("--jobs", type=int, default=1,
                        help="Parallel jobs (default: 1)")
    parser.add_argument("--output", type=str, default="results/pis_eviction",
                        help="Output directory (default: results/pis_eviction)")
    parser.add_argument("--years", type=int, default=5,
                        help="Simulation years (default: 5)")
    parser.add_argument("--max-peers", type=int, default=5_000,
                        help="Max active peers (default: 5000)")
    args = parser.parse_args()

    print("=== VIATICUM EXPERIMENT 23: EVICTION STRATEGIES ===\n")
    print(
        f"Network: max={args.max_peers} nodes, {args.years} years, "
        f"25% annual churn, 6 archetypes"
    )
    print(
        "Trust formula (multiplicative S): "
        "trust_AB = (kp*P_B + ki*I_B) * max(min(S_AB, 1.0), 0.1)"
    )
    print(f"  kp=0.5, ki=2.0, S_AB = STORAGE_RATIOS[B] / STORAGE_RATIOS[A]")
    print(f"Seeds: {args.seeds}, jobs: {args.jobs}\n")

    base_cfg = dict(
        kp=0.5,
        ki=2.0,
        p_window_weeks=4,
        initial_peers=50,
        max_active_peers=args.max_peers,
        annual_churn=0.25,
        target_partners=15,
        acceptance_gate=0.3,
        n_years=args.years,
        n_seeds=args.seeds,
        eviction_period_weeks=4,
    )

    # Define all strategies to run
    strategy_configs: list[Config] = [
        Config(**base_cfg, eviction_strategy=EvictionStrategy.NONE),
        Config(**base_cfg, eviction_strategy=EvictionStrategy.SOFT),
        Config(**base_cfg, eviction_strategy=EvictionStrategy.HARD, eviction_threshold=0.5),
        Config(**base_cfg, eviction_strategy=EvictionStrategy.HARD, eviction_threshold=1.0),
        Config(**base_cfg, eviction_strategy=EvictionStrategy.HARD, eviction_threshold=1.5),
    ]

    t0 = time.time()
    strategy_results: list[tuple[Config, list[YearlySnapshot]]] = []

    for cfg in strategy_configs:
        label = _strategy_label(cfg)
        print(f"Running: {label} ...", flush=True)
        t_start = time.time()
        snaps = run_strategy(cfg, n_jobs=args.jobs)
        t_end = time.time()
        strategy_results.append((cfg, snaps))
        print(f"  done in {t_end - t_start:.1f}s")

    elapsed = time.time() - t0

    # Print main results table
    for cfg, snaps in strategy_results:
        print_strategy_results(cfg, snaps)

    # Archetype trust and segregation tables
    print_arch_trust_section(strategy_results)
    print_segregation_section(strategy_results)

    print(f"\nTotal runtime: {elapsed:.1f}s")

    save_results(strategy_results, Path(args.output), elapsed)


if __name__ == "__main__":
    main()
