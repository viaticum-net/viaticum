"""
SyncBack Simulation #17: Long-term Mixed Network with PI+S Formula (pairwise S)

Question: Does the corrected trust formula trust = kp*P + ki*I + ks*S correctly
rank diverse behavioral archetypes over a 10-year network lifetime with realistic
churn, growth, and partnership dynamics?

Key differences from Experiment 13 (behavior_models.py):
  - Weekly time steps (520 weeks) instead of daily
  - P = mean of last 4 weekly scores (not 30-day rolling)
  - I = cumulative mean of all weekly scores (non-decaying)
  - S = PAIRWISE storage balance: S_AB = r_B / max(r_A, eps), clamped [0, 2.0]
    where r_X = STORAGE_RATIOS[archetype_X].
    This means when node A evaluates node B, S depends on BOTH archetypes:
      Reliable (r=1.0) evaluating Hoarder (r=0.2): S = 0.2/1.0 = 0.2 (low trust)
      Hoarder evaluating Reliable: S = 1.0/0.2 = 5.0 -> clamped 2.0 (high trust)
      Hoarder evaluating Hoarder: S = 0.2/0.2 = 1.0 (symmetric peers)
  - trust = kp*P + ki*I + ks*S  (P and I are per-node; S is pairwise)
  - Living network: growth + 25% annual churn, max 10K nodes
  - Partnership model with acceptance gate (I > 0.3 rejects newcomers)

Design decisions:
  - Weekly pass probability = P(at least 1 of 7 daily checks passes) is
    precomputed per archetype and week, then sampled as Bernoulli(p_weekly).
    This is mathematically equivalent to 7 daily Bernoulli draws but O(1)
    per peer per week instead of O(7).
  - P and I are computed as per-node arrays updated vectorized each week.
    They represent the same value regardless of who is observing, because
    availability/reliability is node-intrinsic.
  - S is pairwise: trust_AB = kp*P_B + ki*I_B + ks*S_AB. S_AB depends on
    both the observer's archetype (r_A) and the target's archetype (r_B).
  - Partnership formation is batched (500 nodes/week) to keep O(N^2) bounded.
  - partners[i] is a set of partner node IDs (actual adjacency), enabling:
      * correct pairwise S during partnership selection
      * accurate community detection via igraph/leidenalg
      * correct incoming-trust aggregation per archetype in snapshots

Expected: With pairwise S, Hoarders see each other as S=1.0 (balanced) but
Reliable nodes penalize Hoarders (S=0.2). Freeloaders are penalized even more.
The pairwise model creates realistic segregation: Hoarders form their own
clusters, Reliables prefer each other.

Usage:
    python pis_longterm.py                          # default 10-year run
    python pis_longterm.py --seeds 5 --jobs 4       # Monte Carlo parallel
    python pis_longterm.py --kp 0.5 --ki 2.0 --ks 1.0  # custom weights
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass, asdict, field
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

# Actual usefulness ranking (lower = more useful, 1-indexed).
# With the S term, Hoarder and Freeloader are no longer tied.
ACTUAL_USEFULNESS_RANK = [1, 2, 3, 4, 5, 6]

# Archetype probabilities for new nodes
ARCHETYPE_PROBS = np.array([0.35, 0.25, 0.15, 0.10, 0.10, 0.05])

# Storage offer ratio per archetype.
# Pairwise S_AB = STORAGE_RATIOS[B] / max(STORAGE_RATIOS[A], eps), clamped [0, 2].
STORAGE_RATIOS = np.array([1.0, 1.0, 1.0, 1.0, 0.2, 0.1], dtype=np.float64)

N_ARCHETYPES = len(ARCHETYPE_NAMES)

# Small epsilon to avoid division by zero in pairwise S
_S_EPS = 0.01


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class Config:
    # Trust formula weights
    kp: float = 0.5
    ki: float = 2.0
    ks: float = 1.0
    # P window: number of recent weekly scores used for P component
    p_window_weeks: int = 4
    # Network parameters
    initial_peers: int = 50
    max_active_peers: int = 10_000
    annual_churn: float = 0.25
    target_partners: int = 15
    # Acceptance gate: established nodes (I > gate) reject newcomers (I < gate)
    acceptance_gate: float = 0.3
    n_years: int = 10
    # Monte Carlo
    n_seeds: int = 1
    # Archetype distribution (tuple for dataclass hashability)
    archetype_probs: tuple[float, ...] = field(
        default_factory=lambda: tuple(ARCHETYPE_PROBS.tolist())
    )


def _weekly_churn_prob(cfg: Config) -> float:
    """Convert annual churn rate to per-week probability."""
    return 1.0 - (1.0 - cfg.annual_churn) ** (1.0 / 52.0)


def _new_nodes_this_week(week: int) -> int:
    """Growth schedule per spec: year 1 = +25/week, years 2-5 = +250/week,
    years 6-10 = +125/week."""
    if week < 52:
        return 25
    elif week < 260:
        return 250
    else:
        return 125


# ---------------------------------------------------------------------------
# Precomputed weekly pass probabilities
# ---------------------------------------------------------------------------

def _build_weekly_pass_probs(n_weeks: int) -> np.ndarray:
    """
    Precompute P(at least 1 of 7 daily checks passes) per archetype per week.

    This is mathematically equivalent to running 7 Bernoulli(r_daily) draws
    and checking if any succeeded:  p_weekly = 1 - (1 - r_daily)^7

    Returns shape (N_ARCHETYPES, n_weeks).
    """
    week_idx = np.arange(n_weeks)
    week_in_year = week_idx % 52

    probs = np.zeros((N_ARCHETYPES, n_weeks), dtype=np.float64)

    # 0: Reliable — 99% daily
    probs[0, :] = 1.0 - (1.0 - 0.99) ** 7

    # 1: Weekend — Fri/Sat/Sun at 0.95, Mon-Thu at 0.30
    # Week modeled as 3 "weekend" days and 4 "weekday" days
    # P(fail all) = (1-0.95)^3 * (1-0.30)^4
    p_fail_weekend = (1.0 - 0.95) ** 3 * (1.0 - 0.30) ** 4
    probs[1, :] = 1.0 - p_fail_weekend

    # 2: Seasonal — 0.95 during semester, 0.20 during summer
    # Summer = weeks 22-35 within each year (roughly Jun-Aug)
    is_summer = (week_in_year >= 22) & (week_in_year <= 35)
    r_seasonal = np.where(is_summer, 0.20, 0.95)
    probs[2, :] = 1.0 - (1.0 - r_seasonal) ** 7

    # 3: Nomad — 50% chance the node is online this week (geometric block model)
    # When online, 100% daily reliability. P(any pass) = 0.5 * 1.0 = 0.5
    probs[3, :] = 0.50

    # 4: Hoarder — 90% daily reliability
    probs[4, :] = 1.0 - (1.0 - 0.90) ** 7

    # 5: Freeloader — 80% daily reliability
    probs[5, :] = 1.0 - (1.0 - 0.80) ** 7

    return probs


# ---------------------------------------------------------------------------
# Core simulation
# ---------------------------------------------------------------------------

def simulate_one(cfg: Config, seed: int) -> dict:
    """
    Simulate one 10-year run with the PI+S trust formula (pairwise S).

    Per-peer arrays (pre-allocated to max_active_peers):
      archetype[i]    -- archetype index 0..5 (-1 = inactive)
      alive[i]        -- currently active
      join_week[i]    -- week when node joined
      p_buf[i, 0:pw]  -- circular buffer of last pw weekly scores
      p_buf_pos[i]    -- next write position in circular buffer
      p_buf_filled[i] -- number of entries filled so far (0..pw)
      i_sum[i]        -- cumulative sum of all weekly scores
      i_count[i]      -- total weeks scored (denominator for I)
      p_val_arr[i]    -- current P value (mean of p_buf window)
      i_val_arr[i]    -- current I value (cumulative mean)
      partners[i]     -- set of current partner node IDs (actual adjacency)

    S is NOT stored per-node. It is computed pairwise on demand:
      S_AB = STORAGE_RATIOS[archetype[B]] / max(STORAGE_RATIOS[archetype[A]], eps)
      clamped to [0, 2.0].
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
    p_val_arr = np.zeros(cap, dtype=np.float64)
    i_val_arr = np.zeros(cap, dtype=np.float64)

    # partners[i] = set of partner node IDs; enables pairwise S and community detection
    partners: list[set[int]] = [set() for _ in range(cap)]

    arch_probs = list(cfg.archetype_probs)
    weekly_pass_probs = _build_weekly_pass_probs(n_weeks)

    # ID management: recycled IDs first, then fresh
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

    def _add(nid: int, week: int) -> None:
        atype = int(rng.choice(N_ARCHETYPES, p=arch_probs))
        archetype[nid] = atype
        alive[nid] = True
        join_week[nid] = week
        p_buf[nid, :] = 0.0
        p_buf_pos[nid] = 0
        p_buf_filled[nid] = 0
        i_sum[nid] = 0.0
        i_count[nid] = 0
        p_val_arr[nid] = 0.0
        i_val_arr[nid] = 0.0
        partners[nid] = set()

    def _remove(nid: int) -> None:
        alive[nid] = False
        # Remove nid from all its partners' adjacency sets
        for pid in partners[nid]:
            partners[pid].discard(nid)
        partners[nid].clear()
        free_ids.append(nid)

    # Bootstrap
    for _ in range(cfg.initial_peers):
        nid = _alloc()
        if nid is None:
            break
        _add(nid, 0)

    weekly_churn = _weekly_churn_prob(cfg)
    snapshot_weeks = set(range(52, n_weeks + 1, 52))
    yearly_snapshots: list[dict] = []

    # -----------------------------------------------------------------------
    # Main weekly loop
    # -----------------------------------------------------------------------
    for week in range(n_weeks):

        # --- 1. Growth ---
        n_active = int(alive.sum())
        if n_active < cfg.max_active_peers:
            n_new = min(_new_nodes_this_week(week), cfg.max_active_peers - n_active)
            for _ in range(n_new):
                nid = _alloc()
                if nid is None:
                    break
                _add(nid, week)

        # --- 2. Churn ---
        active_ids = np.where(alive)[0]
        if active_ids.size > 0:
            churn_mask = rng.random(active_ids.size) < weekly_churn
            for nid in active_ids[churn_mask]:
                _remove(int(nid))

        # --- 3. Weekly check scores (vectorized per archetype group) ---
        active_ids = np.where(alive)[0]
        if active_ids.size == 0:
            continue

        active_arch = archetype[active_ids]   # shape (n_active,)
        week_scores = np.zeros(active_ids.size, dtype=np.float64)

        for atype_idx in range(N_ARCHETYPES):
            grp = np.where(active_arch == atype_idx)[0]
            if grp.size == 0:
                continue
            p_w = float(weekly_pass_probs[atype_idx, week])
            week_scores[grp] = (rng.random(grp.size) < p_w).astype(np.float64)

        # --- 4. Update circular P buffer (vectorized) ---
        pos = p_buf_pos[active_ids]                    # shape (n_active,)
        p_buf[active_ids, pos] = week_scores
        p_buf_pos[active_ids] = (pos + 1) % pw
        filled = p_buf_filled[active_ids]
        p_buf_filled[active_ids] = np.minimum(filled + 1, pw)

        # --- 5. Update I ---
        i_sum[active_ids] += week_scores
        i_count[active_ids] += 1

        # --- 6. Update per-node P and I arrays (vectorized) ---
        # P = mean of filled entries in circular buffer.
        # Since unfilled slots are 0 and p_buf was zeroed on join,
        # sum(p_buf[i,:]) / p_buf_filled[i] gives the correct mean.
        p_buf_sum = p_buf[active_ids, :].sum(axis=1)    # shape (n_active,)
        pf = p_buf_filled[active_ids].astype(np.float64)
        p_val_arr[active_ids] = np.where(pf > 0, p_buf_sum / pf, 0.0)

        ic = i_count[active_ids].astype(np.float64)
        i_val_arr[active_ids] = np.where(ic > 0, i_sum[active_ids] / ic, 0.0)

        # NOTE: no global trust array. Trust is pairwise (depends on observer's
        # archetype via S_AB) and computed on demand in _update_partnerships
        # and _build_snapshot.

        # --- 7. Partnership formation (batched) ---
        _update_partnerships(
            active_ids, alive, archetype, i_val_arr,
            p_val_arr, partners, cfg, rng,
        )

        # --- 8. Yearly snapshot ---
        if (week + 1) in snapshot_weeks:
            year = (week + 1) // 52
            snap = _build_snapshot(
                year, active_ids, archetype, i_val_arr,
                p_val_arr, partners, alive, cfg,
            )
            yearly_snapshots.append(snap)

    return {"snapshots": yearly_snapshots, "seed": seed}


def _update_partnerships(
    active_ids: np.ndarray,
    alive: np.ndarray,
    archetype: np.ndarray,
    i_val_arr: np.ndarray,
    p_val_arr: np.ndarray,
    partners: list[set[int]],
    cfg: Config,
    rng: np.random.Generator,
) -> None:
    """
    Simplified partnership formation for underfull nodes.

    Acceptance gate: established nodes (I > gate) reject newcomers (I < gate).
    We process at most 500 underfull nodes per week to keep simulation fast.

    Partnership selection uses pairwise S: when pid (archetype a_pid) evaluates
    candidate cid (archetype a_cid), S = r_cid / max(r_pid, eps).
    This means nodes preferentially partner with those who offer more storage
    relative to their own offer.
    """
    # Derive on_count from actual partner sets (O(1) per node via len)
    on_count_active = np.array([len(partners[int(nid)]) for nid in active_ids],
                                dtype=np.int32)

    underfull_mask = on_count_active < cfg.target_partners
    underfull = active_ids[underfull_mask]
    if underfull.size == 0:
        return

    if underfull.size > 500:
        underfull = rng.choice(underfull, size=500, replace=False)

    for pid in underfull:
        pid = int(pid)
        n_partners_pid = len(partners[pid])
        n_needed = cfg.target_partners - n_partners_pid
        if n_needed <= 0:
            continue

        req_i = float(i_val_arr[pid])
        a_pid = int(archetype[pid])
        r_pid = float(STORAGE_RATIOS[a_pid])

        # Candidate mask: alive, not self, not already a partner, has capacity
        mask = alive.copy()
        mask[pid] = False
        # Exclude existing partners
        for existing in partners[pid]:
            if existing < len(mask):
                mask[existing] = False
        # Capacity check: only accept partners that still have room
        for cid_idx in np.where(mask)[0]:
            if len(partners[int(cid_idx)]) >= cfg.target_partners:
                mask[int(cid_idx)] = False

        # Acceptance gate: newcomers (low I) can only connect to other newcomers
        if req_i < cfg.acceptance_gate:
            gate_mask = i_val_arr <= cfg.acceptance_gate
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

        # Pairwise S for all candidates (vectorized)
        r_cands = STORAGE_RATIOS[archetype[candidates]]
        s_vals = np.minimum(r_cands / max(r_pid, _S_EPS), 2.0)
        c_trust = np.maximum(
            cfg.kp * p_val_arr[candidates]
            + cfg.ki * i_val_arr[candidates]
            + cfg.ks * s_vals,
            0.01,
        )
        probs = c_trust / c_trust.sum()
        n_pick = min(n_needed, candidates.size)
        chosen = rng.choice(candidates, size=n_pick, replace=False, p=probs)

        for cid in chosen:
            cid = int(cid)
            # Mutual partnership
            partners[pid].add(cid)
            partners[cid].add(pid)


def _build_snapshot(
    year: int,
    active_ids: np.ndarray,
    archetype: np.ndarray,
    i_val_arr: np.ndarray,
    p_val_arr: np.ndarray,
    partners: list[set[int]],
    alive: np.ndarray,
    cfg: Config,
) -> dict:
    """
    Compute yearly snapshot metrics from current network state.

    Archetype trust is computed as the average incoming trust received by
    nodes of that archetype from their actual partners:
      trust_AB = kp*P_B + ki*I_B + ks*S_AB
    where S_AB = r_B / max(r_A, eps), r_X = STORAGE_RATIOS[archetype_X].
    This reflects how peers actually perceive each archetype.
    """
    if active_ids.size == 0:
        return {"year": year, "n_active": 0}

    arch = archetype[active_ids]

    # Per-archetype aggregates using pairwise incoming trust
    arch_trust: dict[str, float] = {}
    arch_count: dict[str, int] = {}
    arch_frac: dict[str, float] = {}

    active_set = set(int(x) for x in active_ids)

    for target_arch_idx, name in enumerate(ARCHETYPE_NAMES):
        target_mask = arch == target_arch_idx
        target_nodes = active_ids[target_mask]
        cnt = int(target_nodes.size)
        arch_count[name] = cnt
        arch_frac[name] = float(cnt / active_ids.size)

        if cnt == 0:
            arch_trust[name] = 0.0
            continue

        r_b = float(STORAGE_RATIOS[target_arch_idx])
        trust_sum = 0.0
        obs_count = 0
        for b in target_nodes:
            b = int(b)
            for a in partners[b]:
                if a not in active_set:
                    continue
                r_a = float(STORAGE_RATIOS[int(archetype[a])])
                s_ab = min(r_b / max(r_a, _S_EPS), 2.0)
                t = cfg.kp * float(p_val_arr[b]) + cfg.ki * float(i_val_arr[b]) + cfg.ks * s_ab
                trust_sum += t
                obs_count += 1
        arch_trust[name] = trust_sum / max(obs_count, 1)

    # Overall trust distribution: for each active node, compute its mean
    # incoming trust across its partners (or its self-trust if no partners)
    node_trust = np.zeros(active_ids.size, dtype=np.float64)
    for idx, b in enumerate(active_ids):
        b = int(b)
        r_b = float(STORAGE_RATIOS[int(archetype[b])])
        p_b = float(p_val_arr[b])
        i_b = float(i_val_arr[b])
        b_partners = [a for a in partners[b] if a in active_set]
        if b_partners:
            t_sum = 0.0
            for a in b_partners:
                r_a = float(STORAGE_RATIOS[int(archetype[a])])
                s_ab = min(r_b / max(r_a, _S_EPS), 2.0)
                t_sum += cfg.kp * p_b + cfg.ki * i_b + cfg.ks * s_ab
            node_trust[idx] = t_sum / len(b_partners)
        else:
            # No partners yet: compute with S=1.0 as a neutral baseline
            node_trust[idx] = cfg.kp * p_b + cfg.ki * i_b + cfg.ks * 1.0

    t = node_trust

    # Kendall's tau: PI+S ranking vs actual usefulness
    trust_by_arch = np.array([arch_trust[n] for n in ARCHETYPE_NAMES])
    tau_val, _ = kendalltau(trust_by_arch, -np.array(ACTUAL_USEFULNESS_RANK))

    # Partnership quality
    n_partners_arr = np.array([len(partners[int(nid)]) for nid in active_ids],
                               dtype=np.float64)
    good_mask = t > 0.5    # "good" = trust above threshold
    established_frac = float((i_val_arr[active_ids] > cfg.acceptance_gate).mean())

    # Community detection (optional)
    comm = _detect_communities(active_ids, partners, alive)

    snap: dict = {
        "year": year,
        "n_active": int(active_ids.size),
        "trust_mean": float(t.mean()),
        "trust_std": float(t.std()),
        "trust_p5": float(np.percentile(t, 5)),
        "trust_p95": float(np.percentile(t, 95)),
        "archetype_trust": arch_trust,
        "archetype_count": arch_count,
        "archetype_fraction": arch_frac,
        "kendall_tau": float(tau_val),
        "mean_partners": float(n_partners_arr.mean()),
        "good_partner_frac": float(good_mask.mean()),
        "established_frac": established_frac,
    }
    if comm is not None:
        snap["community"] = comm
    return snap


# ---------------------------------------------------------------------------
# Community detection (optional, graceful degradation)
# ---------------------------------------------------------------------------

def _detect_communities(
    active_ids: np.ndarray,
    partners: list[set[int]],
    alive: np.ndarray,
) -> Optional[dict]:
    """
    Attempt community detection via Leiden/igraph if available.
    Returns None if libraries are not installed or edge count is too small.

    Uses the actual partnership adjacency (partners[i]) to build a real
    undirected graph, enabling meaningful modularity computation.
    """
    try:
        import igraph as ig
        import leidenalg
    except ImportError:
        return None

    # Build edge list from partnerships (undirected, deduplicated)
    id_map = {int(nid): i for i, nid in enumerate(active_ids)}
    edges: list[tuple[int, int]] = []
    for nid in active_ids:
        nid = int(nid)
        for pid in partners[nid]:
            if pid in id_map and nid < pid:  # undirected: emit each edge once
                edges.append((id_map[nid], id_map[pid]))

    if len(edges) < 10:
        return None

    g = ig.Graph(n=len(active_ids), edges=edges)
    partition = leidenalg.find_partition(g, leidenalg.ModularityVertexPartition)

    modularity = partition.modularity
    n_communities = len(partition)

    # Cross-cluster edge ratio
    membership = np.array(partition.membership)
    cross = sum(1 for u, v in edges if membership[u] != membership[v])
    cross_ratio = cross / max(len(edges), 1)

    # Bridge nodes: have partners in more than one community
    bridge_count = 0
    for i, nid in enumerate(active_ids):
        partner_communities: set[int] = set()
        for pid in partners[int(nid)]:
            if pid in id_map:
                partner_communities.add(int(membership[id_map[pid]]))
        if len(partner_communities) > 1:
            bridge_count += 1
    bridge_ratio = bridge_count / max(len(active_ids), 1)

    # Isolated communities: those with zero cross-cluster edges
    community_has_cross: set[int] = set()
    for u, v in edges:
        if membership[u] != membership[v]:
            community_has_cross.add(int(membership[u]))
            community_has_cross.add(int(membership[v]))
    isolated = n_communities - len(community_has_cross)

    return {
        "modularity": float(modularity),
        "n_communities": int(n_communities),
        "cross_cluster_edge_ratio": float(cross_ratio),
        "bridge_node_ratio": float(bridge_ratio),
        "isolated_communities": int(isolated),
    }


# ---------------------------------------------------------------------------
# Experiment runner
# ---------------------------------------------------------------------------

def run_experiment(cfg: Config, n_jobs: int = 1) -> dict:
    """Run Monte Carlo experiment and aggregate yearly snapshots."""
    t0 = time.time()
    seeds = list(range(cfg.n_seeds))

    if n_jobs == 1 or cfg.n_seeds == 1:
        all_runs = [simulate_one(cfg, s) for s in seeds]
    else:
        all_runs = Parallel(n_jobs=n_jobs)(
            delayed(simulate_one)(cfg, s) for s in seeds
        )

    elapsed = time.time() - t0

    # Aggregate across seeds per year
    per_year: dict[int, list[dict]] = {y: [] for y in range(1, cfg.n_years + 1)}
    for run in all_runs:
        for snap in run["snapshots"]:
            y = snap["year"]
            if y in per_year:
                per_year[y].append(snap)

    def _avg(snaps: list[dict], key: str) -> float:
        return float(np.mean([s[key] for s in snaps]))

    def _avg_arch(snaps: list[dict], sub: str) -> dict[str, float]:
        result: dict[str, float] = {}
        for name in ARCHETYPE_NAMES:
            vals = [s[sub][name] for s in snaps if name in s.get(sub, {})]
            result[name] = float(np.mean(vals)) if vals else 0.0
        return result

    def _avg_community(snaps: list[dict]) -> Optional[dict]:
        comm_snaps = [s["community"] for s in snaps if "community" in s]
        if not comm_snaps:
            return None
        keys = ["modularity", "n_communities", "cross_cluster_edge_ratio",
                "bridge_node_ratio", "isolated_communities"]
        return {k: float(np.mean([c[k] for c in comm_snaps])) for k in keys}

    aggregated: list[dict] = []
    for year in range(1, cfg.n_years + 1):
        snaps = per_year[year]
        if not snaps:
            continue
        agg: dict = {
            "year": year,
            "n_active": int(np.mean([s["n_active"] for s in snaps])),
            "trust_mean": _avg(snaps, "trust_mean"),
            "trust_std": _avg(snaps, "trust_std"),
            "trust_p5": _avg(snaps, "trust_p5"),
            "trust_p95": _avg(snaps, "trust_p95"),
            "kendall_tau": _avg(snaps, "kendall_tau"),
            "mean_partners": _avg(snaps, "mean_partners"),
            "good_partner_frac": _avg(snaps, "good_partner_frac"),
            "established_frac": _avg(snaps, "established_frac"),
            "archetype_trust": _avg_arch(snaps, "archetype_trust"),
            "archetype_fraction": _avg_arch(snaps, "archetype_fraction"),
        }
        comm = _avg_community(snaps)
        if comm is not None:
            agg["community"] = comm
        aggregated.append(agg)

    return {
        "config": asdict(cfg),
        "elapsed_sec": elapsed,
        "snapshots": aggregated,
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_summary(result: dict) -> None:
    """Print yearly summary table and final archetype trust breakdown."""
    cfg = result["config"]
    snaps = result["snapshots"]

    print(
        f"Config: kp={cfg['kp']}, ki={cfg['ki']}, ks={cfg['ks']}, "
        f"P-window={cfg['p_window_weeks']} weeks  [pairwise S]"
    )
    print(
        f"Network: initial={cfg['initial_peers']}, "
        f"max={cfg['max_active_peers']}, "
        f"churn={cfg['annual_churn']*100:.0f}%/yr, "
        f"target_partners={cfg['target_partners']}"
    )
    print(f"Seeds: {cfg['n_seeds']}, runtime: {result['elapsed_sec']:.1f}s")
    print()

    header = (
        f"{'Year':>5} {'Active':>7}  "
        f"{'Reliable%':>9} {'Hoarder%':>8} {'Freeloader%':>11}  "
        f"{'MeanTrust':>9} {'Tau':>6}  "
        f"{'GoodPart%':>9}"
    )
    sep = "-" * len(header)
    print(header)
    print(sep)

    for s in snaps:
        af = s["archetype_fraction"]
        print(
            f"{s['year']:>5} {s['n_active']:>7}  "
            f"{af.get('Reliable', 0)*100:>8.1f}% "
            f"{af.get('Hoarder', 0)*100:>7.1f}% "
            f"{af.get('Freeloader', 0)*100:>10.1f}%  "
            f"{s['trust_mean']:>9.3f} "
            f"{s['kendall_tau']:>6.3f}  "
            f"{s['good_partner_frac']*100:>8.1f}%"
        )

    if not snaps:
        return

    # Final archetype trust table
    final = snaps[-1]
    print(f"\n=== ARCHETYPE TRUST AT YEAR {final['year']} (pairwise S) ===")
    arch_trust = final["archetype_trust"]
    arch_frac = final["archetype_fraction"]

    trust_vals = np.array([arch_trust.get(n, 0.0) for n in ARCHETYPE_NAMES])
    pi_ranks = np.empty(len(ARCHETYPE_NAMES), dtype=int)
    for rank, idx in enumerate(np.argsort(-trust_vals), 1):
        pi_ranks[idx] = rank

    print(
        f"{'Archetype':<16} {'Trust':>8} {'Frac%':>7}  "
        f"{'PI_rank':>7} {'Expected':>8}"
    )
    print("-" * 52)
    for i, name in enumerate(ARCHETYPE_NAMES):
        print(
            f"{name:<16} {arch_trust.get(name, 0.0):>8.3f} "
            f"{arch_frac.get(name, 0.0)*100:>6.1f}%  "
            f"{pi_ranks[i]:>7d} {ACTUAL_USEFULNESS_RANK[i]:>8d}"
        )

    tau = final["kendall_tau"]
    print(f"\nKendall's tau (final year): {tau:.3f}")
    print(
        "  (tau=1.0 = PI+S perfectly ranks archetypes, "
        "tau=0 = random, tau<0 = inverted)"
    )

    # Nomad/Hoarder inversion analysis
    hoarder_trust = arch_trust.get("Hoarder", 0.0)
    nomad_trust = arch_trust.get("Nomad", 0.0)
    if hoarder_trust > nomad_trust:
        print(
            "\n  Note: Hoarder > Nomad in PI+S despite lower expected rank."
        )
        print(
            "  With pairwise S, Hoarders prefer each other (S_HH = 1.0) and"
        )
        print(
            "  form dense clusters. Hoarder's 90% check reliability still"
        )
        print(
            "  produces high P+I. Increase ks to flip the ranking."
        )

    # Trust distribution
    print(f"\n=== TRUST DISTRIBUTION (year {final['year']}) ===")
    print(
        f"  mean={final['trust_mean']:.3f}  "
        f"std={final['trust_std']:.3f}  "
        f"p5={final['trust_p5']:.3f}  "
        f"p95={final['trust_p95']:.3f}"
    )

    # Community metrics (if available)
    if "community" in final:
        c = final["community"]
        print(f"\n=== COMMUNITY STRUCTURE (year {final['year']}) ===")
        print(f"  communities={c['n_communities']:.0f}  "
              f"modularity={c['modularity']:.3f}  "
              f"cross_edges={c['cross_cluster_edge_ratio']*100:.1f}%  "
              f"bridges={c['bridge_node_ratio']*100:.1f}%  "
              f"isolated={c['isolated_communities']:.0f}")


def save_results(result: dict, path: Path) -> None:
    """Save full results to JSON (handles numpy types)."""
    path.parent.mkdir(parents=True, exist_ok=True)

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

    path.write_text(json.dumps(_convert(result), indent=2))
    print(f"\nResults saved to {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SyncBack Experiment 17: Long-term Mixed Network with PI+S (pairwise S)"
    )
    parser.add_argument("--kp", type=float, default=0.5)
    parser.add_argument("--ki", type=float, default=2.0)
    parser.add_argument("--ks", type=float, default=1.0)
    parser.add_argument("--p-window", type=int, default=4,
                        help="P rolling window in weeks")
    parser.add_argument("--initial-peers", type=int, default=50)
    parser.add_argument("--max-peers", type=int, default=10_000)
    parser.add_argument("--churn", type=float, default=0.25,
                        help="Annual churn rate (0.25 = 25%%)")
    parser.add_argument("--target-partners", type=int, default=15)
    parser.add_argument("--acceptance-gate", type=float, default=0.3,
                        help="I threshold for acceptance gate")
    parser.add_argument("--years", type=int, default=10)
    parser.add_argument("--seeds", type=int, default=1,
                        help="Number of Monte Carlo seeds")
    parser.add_argument("--jobs", type=int, default=1,
                        help="Parallel jobs for Monte Carlo")
    parser.add_argument("--output", type=str, default="results/pis_longterm",
                        help="Output directory for JSON")
    args = parser.parse_args()

    cfg = Config(
        kp=args.kp,
        ki=args.ki,
        ks=args.ks,
        p_window_weeks=args.p_window,
        initial_peers=args.initial_peers,
        max_active_peers=args.max_peers,
        annual_churn=args.churn,
        target_partners=args.target_partners,
        acceptance_gate=args.acceptance_gate,
        n_years=args.years,
        n_seeds=args.seeds,
    )

    print("=== SYNCBACK EXPERIMENT 17: LONG-TERM MIXED NETWORK (PI+S, pairwise S) ===\n")

    result = run_experiment(cfg, n_jobs=args.jobs)
    print_summary(result)
    save_results(result, Path(args.output) / "run.json")


if __name__ == "__main__":
    main()
