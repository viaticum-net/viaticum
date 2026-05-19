"""
Viaticum Simulation #12: "Prison" Scenario — Captive / Small Network

Question: What happens when a small group of users is trapped with only each other?
What is the minimum viable network size? How does one malicious node in a small
network affect everyone?

Scenario A — Minimum Viable Network
    Small isolated networks of N nodes (N = 3, 5, 7, 10, 15, 20, 30, 50).
    All nodes honest (reliability 0.95), no external peers.
    Erasure coding adapts to the available pool:
      if N < n_shards_desired: actual_n = N - 1, actual_k = ceil(actual_n * 0.6)
      else: actual_n = n_shards_desired, actual_k = k_desired
    Simulates 24 months of operation with configurable annual churn.
    Tracks file survival and effective redundancy.

Scenario B — One Bad Apple
    Same small networks, but 1 node is malicious:
      freerider  — reliability 0; stores nothing from day 0
      liar       — reliability 0.95 for 30 days, then deletes all held shards
      spite      — stores normally, but at restore time refuses shards for one
                   specific "target" node
    Reports survival impact and amplification factor vs all-honest baseline.

Scenario C — Capacity Saturation
    Each node wants to back up X GB but can only offer Y GB storage (X > Y).
    Trust-weighted allocation determines who gets storage.
    Reports per-node effective backup ratio (actual / desired).

Usage:
    python prison_network.py                    # default run (all 3 scenarios)
    python prison_network.py --scenario A       # single scenario
    python prison_network.py --sweep --jobs 8   # full parameter sweep
    python prison_network.py --sweep-b --jobs 8 # Scenario B sweep only
"""

import argparse
import json
import math
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path

import numpy as np
from joblib import Parallel, delayed


# ---------------------------------------------------------------------------
# Shared trust mechanics
# ---------------------------------------------------------------------------

def _compute_trust(
    p_buffer: np.ndarray,
    i_sum: np.ndarray,
    total_checks: int,
    kp: float,
    ki: float,
    p_window: int,
) -> np.ndarray:
    """Compute PI trust from circular P buffer and cumulative I sum.

    p_buffer: shape (p_window, n_peers) — circular buffer of daily checks
    i_sum: shape (n_peers,) — cumulative sum of check results
    total_checks: number of days elapsed
    Returns trust array of shape (n_peers,).
    """
    filled = min(total_checks, p_window)
    if filled == 0:
        return np.full(p_buffer.shape[1], 0.5)
    p_score = p_buffer[:filled].mean(axis=0)
    i_score = i_sum / total_checks
    return kp * p_score + ki * i_score


# ---------------------------------------------------------------------------
# Erasure coding helpers
# ---------------------------------------------------------------------------

def adapt_erasure(n_nodes: int, k_desired: int, n_shards_desired: int) -> tuple[int, int]:
    """Adapt erasure coding parameters to available pool size.

    Returns (actual_k, actual_n) such that:
      - actual_n <= n_nodes - 1  (leave at least 1 node shard-free for repair)
      - actual_k / actual_n ~ 0.6  (60% reconstruction threshold)
    """
    if n_nodes <= 1:
        return 1, 1
    actual_n = min(n_shards_desired, n_nodes - 1)
    actual_n = max(actual_n, 1)
    if actual_n >= n_shards_desired:
        actual_k = k_desired
    else:
        actual_k = max(1, math.ceil(actual_n * 0.6))
    return actual_k, actual_n


def annual_churn_to_daily(annual_churn: float) -> float:
    """Convert annual churn rate to per-day leave probability."""
    if annual_churn <= 0.0:
        return 0.0
    return 1.0 - (1.0 - annual_churn) ** (1.0 / 365.0)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class Config:
    # Core network
    n_nodes: int = 10
    n_files_per_node: int = 100
    n_months: int = 24
    n_seeds: int = 30

    # Erasure coding (desired; may be adapted down for small networks)
    k_desired: int = 5
    n_shards_desired: int = 15

    # Node reliability (honest)
    honest_reliability: float = 0.95

    # Churn
    annual_churn: float = 0.10
    rejoin_prob: float = 0.6
    rejoin_delay_days: int = 30

    # Repair parameters
    repair_interval_days: int = 7
    repair_delay_days: int = 7

    # PI trust parameters
    kp: float = 0.5
    ki: float = 2.0
    p_window: int = 30
    trust_threshold: float = 0.3

    # Scenario B: bad apple
    bad_apple_type: str = "none"   # "none" | "freerider" | "liar" | "spite"
    liar_delay_days: int = 30      # days before liar deletes shards
    spite_target_id: int = 0       # node index that spite refuses to serve

    # Scenario C: capacity saturation
    want_gb_per_node: float = 100.0
    offer_gb_per_node: float = 60.0

    # Which scenarios to run (comma-separated: "A", "B", "C", or "all")
    scenarios: str = "all"


# ---------------------------------------------------------------------------
# Scenario A: Minimum Viable Network
# ---------------------------------------------------------------------------

def simulate_scenario_a(config: Config, seed: int) -> dict:
    """Simulate small isolated honest network for 24 months.

    Returns metrics: file_survival_rate, effective_redundancy, actual_k, actual_n.
    """
    rng = np.random.default_rng(seed)

    n = config.n_nodes
    actual_k, actual_n = adapt_erasure(n, config.k_desired, config.n_shards_desired)

    n_files_total = n * config.n_files_per_node
    n_days = config.n_months * 30

    # Peer state
    peer_online = np.ones(n, dtype=bool)
    peer_rejoin_day = np.full(n, -1, dtype=np.int64)
    p_leave = annual_churn_to_daily(config.annual_churn)

    # File shard placement: file_shards[f] = list of peer IDs holding shards
    file_shards: list[list[int]] = []
    for _ in range(n_files_total):
        online_peers = np.where(peer_online)[0]
        n_place = min(actual_n, len(online_peers))
        if n_place < actual_k:
            # Impossible to meet k with available peers — file is immediately lost
            file_shards.append([])
        else:
            holders = rng.choice(online_peers, size=n_place, replace=False).tolist()
            file_shards.append(holders)

    file_alive = np.array([len(s) >= actual_k for s in file_shards])

    # PI trust tracking
    p_buffer = np.zeros((config.p_window, n))
    i_sum = np.zeros(n)
    total_checks = 0

    pending_repairs: list[tuple[int, int, list[int]]] = []

    for day in range(n_days):
        # --- Churn ---
        for pid in range(n):
            if peer_online[pid] and p_leave > 0 and rng.random() < p_leave:
                peer_online[pid] = False
                if rng.random() < config.rejoin_prob:
                    delay = rng.geometric(1.0 / max(1, config.rejoin_delay_days))
                    peer_rejoin_day[pid] = day + int(delay)

        # --- Rejoin ---
        for pid in range(n):
            if not peer_online[pid] and peer_rejoin_day[pid] == day:
                peer_online[pid] = True
                peer_rejoin_day[pid] = -1

        # --- Daily proof-of-storage check ---
        checks = (rng.random(n) < config.honest_reliability).astype(np.float64)
        # Offline peers fail check
        checks[~peer_online] = 0.0

        p_buffer[day % config.p_window] = checks
        i_sum += checks
        total_checks += 1

        # --- Complete pending repairs ---
        still_pending: list[tuple[int, int, list[int]]] = []
        for fidx, comp_day, new_holders in pending_repairs:
            if day >= comp_day:
                if file_alive[fidx]:
                    for pid in new_holders:
                        if peer_online[pid] and pid not in file_shards[fidx]:
                            file_shards[fidx].append(pid)
            else:
                still_pending.append((fidx, comp_day, new_holders))
        pending_repairs = still_pending

        # --- Weekly repair cycle ---
        if (day + 1) % config.repair_interval_days == 0:
            online_set = set(np.where(peer_online)[0])
            trust = _compute_trust(p_buffer, i_sum, total_checks,
                                   config.kp, config.ki, config.p_window)

            for fidx in range(n_files_total):
                if not file_alive[fidx]:
                    continue

                live = [p for p in file_shards[fidx] if p in online_set]
                if len(live) < actual_k:
                    file_alive[fidx] = False
                    file_shards[fidx] = []
                    continue

                file_shards[fidx] = live
                missing = actual_n - len(live)
                if missing <= 0:
                    continue

                current_holders = set(live)
                # Trust-gated candidates
                candidates = [
                    p for p in online_set
                    if p not in current_holders and trust[p] >= config.trust_threshold
                ]
                if not candidates:
                    # Fall back to any online peer not already holding
                    candidates = [
                        p for p in online_set if p not in current_holders
                    ]
                if not candidates:
                    continue

                n_place = min(missing, len(candidates))
                weights = np.array([max(trust[p], 0.01) for p in candidates])
                weights /= weights.sum()
                chosen = rng.choice(candidates, size=n_place, replace=False, p=weights)
                pending_repairs.append((fidx, day + config.repair_delay_days,
                                        chosen.tolist()))

    # Effective redundancy: mean shard count / desired n, for surviving files
    surviving_shard_counts = [
        len(file_shards[f]) for f in range(n_files_total) if file_alive[f]
    ]
    if surviving_shard_counts:
        eff_red = float(np.mean(surviving_shard_counts)) / actual_n
    else:
        eff_red = 0.0

    return {
        "file_survival_rate": float(file_alive.sum()) / n_files_total,
        "effective_redundancy": eff_red,
        "actual_k": actual_k,
        "actual_n": actual_n,
        "n_files_total": n_files_total,
        "files_lost": int((~file_alive).sum()),
    }


def run_scenario_a(config: Config, n_jobs: int = 1) -> dict:
    """Monte Carlo for Scenario A."""
    t0 = time.time()
    seeds = range(config.n_seeds)

    if n_jobs == 1:
        results = [simulate_scenario_a(config, s) for s in seeds]
    else:
        results = Parallel(n_jobs=n_jobs)(
            delayed(simulate_scenario_a)(config, s) for s in seeds
        )

    surv = np.array([r["file_survival_rate"] for r in results])
    red = np.array([r["effective_redundancy"] for r in results])

    return {
        "config": asdict(config),
        "elapsed_sec": time.time() - t0,
        "actual_k": results[0]["actual_k"],
        "actual_n": results[0]["actual_n"],
        "file_survival_mean": float(surv.mean()),
        "file_survival_std": float(surv.std()),
        "file_survival_p5": float(np.percentile(surv, 5)),
        "file_survival_p95": float(np.percentile(surv, 95)),
        "effective_redundancy_mean": float(red.mean()),
        "effective_redundancy_p5": float(np.percentile(red, 5)),
    }


# ---------------------------------------------------------------------------
# Scenario B: One Bad Apple
# ---------------------------------------------------------------------------

def simulate_scenario_b(config: Config, seed: int) -> dict:
    """Simulate small network with one malicious node.

    bad_apple_type options:
      "none"      — all honest (baseline)
      "freerider" — node 0 stores nothing (reliability=0) from day 0
      "liar"      — node 0 honest for liar_delay_days, then deletes all its shards
      "spite"     — node 0 stores normally, but refuses restore for target node
    """
    rng = np.random.default_rng(seed)

    n = config.n_nodes
    actual_k, actual_n = adapt_erasure(n, config.k_desired, config.n_shards_desired)

    bad_type = config.bad_apple_type
    bad_id = 0  # the bad apple is always node 0
    target_id = max(1, config.spite_target_id % n)  # ensure target != bad_id

    n_days = config.n_months * 30

    # Reliability per peer (affects daily checks)
    reliability = np.full(n, config.honest_reliability)
    if bad_type == "freerider":
        reliability[bad_id] = 0.0

    # Peer state
    peer_online = np.ones(n, dtype=bool)
    peer_rejoin_day = np.full(n, -1, dtype=np.int64)
    p_leave = annual_churn_to_daily(config.annual_churn)

    # Files owned by each node; we track shards per file
    # files 0..n_files_per_node-1 = owned by node 0,
    # files n_files_per_node..2*n_files_per_node-1 = owned by node 1, etc.
    n_files_total = n * config.n_files_per_node
    file_owner = np.repeat(np.arange(n), config.n_files_per_node)

    # Initial shard placement
    file_shards: list[list[int]] = []
    for _ in range(n_files_total):
        online_peers = np.where(peer_online)[0]
        n_place = min(actual_n, len(online_peers))
        if n_place < actual_k:
            file_shards.append([])
        else:
            holders = rng.choice(online_peers, size=n_place, replace=False).tolist()
            file_shards.append(holders)

    file_alive = np.array([len(s) >= actual_k for s in file_shards])

    # Liar state: tracks shards the liar accepted (pid -> fidx -> delete_day)
    liar_deletes: dict[int, int] = {}  # fidx -> deletion day
    if bad_type == "liar":
        for fidx, holders in enumerate(file_shards):
            if bad_id in holders:
                liar_deletes[fidx] = config.liar_delay_days

    # PI trust tracking
    p_buffer = np.zeros((config.p_window, n))
    i_sum = np.zeros(n)
    total_checks = 0

    pending_repairs: list[tuple[int, int, list[int]]] = []

    for day in range(n_days):
        # --- Churn (bad apple does not churn — it is persistent) ---
        for pid in range(n):
            if pid == bad_id:
                continue
            if peer_online[pid] and p_leave > 0 and rng.random() < p_leave:
                peer_online[pid] = False
                if rng.random() < config.rejoin_prob:
                    delay = rng.geometric(1.0 / max(1, config.rejoin_delay_days))
                    peer_rejoin_day[pid] = day + int(delay)

        for pid in range(n):
            if not peer_online[pid] and peer_rejoin_day[pid] == day:
                peer_online[pid] = True
                peer_rejoin_day[pid] = -1

        # --- Liar: delete shards on schedule ---
        if bad_type == "liar":
            newly_deleted = [f for f, d in liar_deletes.items() if d <= day]
            for fidx in newly_deleted:
                if bad_id in file_shards[fidx]:
                    file_shards[fidx].remove(bad_id)
                del liar_deletes[fidx]

        # --- Daily proof-of-storage check ---
        # For liar: after deletions, the liar fails checks for deleted files.
        # We model liar reliability as: fraction of shards still held.
        if bad_type == "liar":
            # liar still passes for undeleted files; already-deleted shards
            # are gone from file_shards, so the check reflects remaining capacity.
            # Overall: if liar still has some shards, pass rate = held/total accepted.
            held = sum(1 for fidx, holders in enumerate(file_shards)
                       if bad_id in holders)
            total_assigned = held + len(newly_deleted) if day == 0 else held
            liar_rel = config.honest_reliability if held > 0 else 0.0
            reliability[bad_id] = liar_rel

        checks = np.array([
            1.0 if rng.random() < reliability[p] else 0.0
            for p in range(n)
        ])
        checks[~peer_online] = 0.0

        p_buffer[day % config.p_window] = checks
        i_sum += checks
        total_checks += 1

        # --- Complete pending repairs ---
        still_pending: list[tuple[int, int, list[int]]] = []
        for fidx, comp_day, new_holders in pending_repairs:
            if day >= comp_day:
                if file_alive[fidx]:
                    for pid in new_holders:
                        if peer_online[pid] and pid not in file_shards[fidx]:
                            file_shards[fidx].append(pid)
            else:
                still_pending.append((fidx, comp_day, new_holders))
        pending_repairs = still_pending

        # --- Weekly repair cycle ---
        if (day + 1) % config.repair_interval_days == 0:
            online_set = set(np.where(peer_online)[0])
            trust = _compute_trust(p_buffer, i_sum, total_checks,
                                   config.kp, config.ki, config.p_window)

            for fidx in range(n_files_total):
                if not file_alive[fidx]:
                    continue

                # For freerider: count live shards, exclude bad node
                live = [p for p in file_shards[fidx] if p in online_set]

                if bad_type == "freerider":
                    # freerider holds no real data — shard is lost
                    live = [p for p in live if p != bad_id]
                    file_shards[fidx] = live

                if len(live) < actual_k:
                    file_alive[fidx] = False
                    file_shards[fidx] = []
                    continue

                file_shards[fidx] = live
                missing = actual_n - len(live)
                if missing <= 0:
                    continue

                current_holders = set(live)
                # freerider is below trust threshold after enough checks
                candidates = [
                    p for p in online_set
                    if p not in current_holders and trust[p] >= config.trust_threshold
                ]
                if not candidates:
                    candidates = [
                        p for p in online_set if p not in current_holders
                    ]
                if not candidates:
                    continue

                n_place = min(missing, len(candidates))
                weights = np.array([max(trust[p], 0.01) for p in candidates])
                weights /= weights.sum()
                chosen = rng.choice(candidates, size=n_place, replace=False, p=weights)
                pending_repairs.append((fidx, day + config.repair_delay_days,
                                        chosen.tolist()))

    # --- Evaluate survival ---
    # For spite: at restore time, bad apple refuses shards for target node's files.
    # File survives if (live_shards - spite_shards) >= actual_k.
    if bad_type == "spite":
        for fidx in range(n_files_total):
            if not file_alive[fidx]:
                continue
            owner = int(file_owner[fidx])
            if owner == target_id:
                # spite refuses shards it holds for this file
                non_spite = [p for p in file_shards[fidx] if p != bad_id]
                if len(non_spite) < actual_k:
                    file_alive[fidx] = False

    surv_rate = float(file_alive.sum()) / n_files_total

    # Per-owner survival breakdown
    target_files = [f for f in range(n_files_total) if file_owner[f] == target_id]
    target_surv = (
        float(sum(1 for f in target_files if file_alive[f])) / len(target_files)
        if target_files else 1.0
    )

    bad_owned_files = [f for f in range(n_files_total) if file_owner[f] == bad_id]
    bad_owner_surv = (
        float(sum(1 for f in bad_owned_files if file_alive[f])) / len(bad_owned_files)
        if bad_owned_files else 1.0
    )

    return {
        "file_survival_rate": surv_rate,
        "target_file_survival": target_surv,
        "bad_owner_file_survival": bad_owner_surv,
        "actual_k": actual_k,
        "actual_n": actual_n,
    }


def run_scenario_b(config: Config, n_jobs: int = 1) -> dict:
    """Monte Carlo for Scenario B."""
    t0 = time.time()
    seeds = range(config.n_seeds)

    if n_jobs == 1:
        results = [simulate_scenario_b(config, s) for s in seeds]
    else:
        results = Parallel(n_jobs=n_jobs)(
            delayed(simulate_scenario_b)(config, s) for s in seeds
        )

    surv = np.array([r["file_survival_rate"] for r in results])
    target_surv = np.array([r["target_file_survival"] for r in results])
    bad_surv = np.array([r["bad_owner_file_survival"] for r in results])

    return {
        "config": asdict(config),
        "elapsed_sec": time.time() - t0,
        "actual_k": results[0]["actual_k"],
        "actual_n": results[0]["actual_n"],
        "file_survival_mean": float(surv.mean()),
        "file_survival_std": float(surv.std()),
        "file_survival_p5": float(np.percentile(surv, 5)),
        "target_file_survival_mean": float(target_surv.mean()),
        "target_file_survival_p5": float(np.percentile(target_surv, 5)),
        "bad_owner_survival_mean": float(bad_surv.mean()),
    }


# ---------------------------------------------------------------------------
# Scenario C: Capacity Saturation
# ---------------------------------------------------------------------------

def simulate_scenario_c(config: Config, seed: int) -> dict:
    """Simulate capacity-constrained small network.

    Each node wants to back up want_gb_per_node but can only offer
    offer_gb_per_node. Trust-weighted allocation determines who gets space.
    Returns per-node effective backup ratio.
    """
    rng = np.random.default_rng(seed)

    n = config.n_nodes
    actual_k, actual_n = adapt_erasure(n, config.k_desired, config.n_shards_desired)

    n_days = config.n_months * 30

    # Storage accounting (in normalized units; 1 file = 1 GB for simplicity)
    # Each node can store: offer_gb for others' data
    # Each node wants: want_gb placed across the network
    capacity = np.full(n, config.offer_gb_per_node)
    used = np.zeros(n)   # storage used on each node (holding others' shards)

    # Files per node, sized proportionally to want_gb
    # Each file occupies (shard_size * n_shards) total storage on the network.
    # We normalize: file_size = 1.0, shard_size = file_size / actual_n
    shard_size = 1.0 / actual_n if actual_n > 0 else 1.0

    # How many files can node i back up given network capacity?
    # Simplified: total offered capacity = n * offer_gb
    # Total desired storage = n * want_gb (each file costs actual_n shard_size)
    total_offered = float(n * config.offer_gb_per_node)
    total_desired = float(n * config.want_gb_per_node)
    saturation_ratio = total_desired / max(total_offered, 1e-9)

    # Compute how many files per node actually get placed (capacity-limited)
    files_wanted_per_node = config.n_files_per_node
    # Each file needs actual_n shard slots across the network
    # Total slots available = total_offered / shard_size
    total_slots = total_offered / shard_size
    total_files_possible = int(total_slots / actual_n)
    total_files_wanted = n * files_wanted_per_node
    files_actually_placed = min(total_files_wanted, total_files_possible)

    # Trust-based allocation: nodes with higher trust get priority
    # PI trust accumulated from initial checks
    p_buffer = np.zeros((config.p_window, n))
    i_sum = np.zeros(n)
    total_checks = 0
    reliability = np.full(n, config.honest_reliability)

    # Simulate initial trust buildup (30 days before placement)
    for day in range(30):
        checks = (rng.random(n) < reliability).astype(np.float64)
        p_buffer[day % config.p_window] = checks
        i_sum += checks
        total_checks += 1

    trust = _compute_trust(p_buffer, i_sum, total_checks,
                           config.kp, config.ki, config.p_window)

    # Assign files using trust-weighted allocation
    # Files are created in round-robin order by owner; earlier files get priority
    # if capacity is saturated.
    file_owner_list: list[int] = []
    for _ in range(files_wanted_per_node):
        for owner in range(n):
            file_owner_list.append(owner)
    file_owner_arr = np.array(file_owner_list[:total_files_wanted])

    files_placed = np.zeros(total_files_wanted, dtype=bool)
    node_usage = np.zeros(n)
    node_files_placed = np.zeros(n, dtype=np.int64)

    # Trust-weighted order: owners with higher trust get files placed first
    # when capacity is tight
    owner_trust = trust[file_owner_arr]
    placement_order = np.argsort(-owner_trust)  # descending trust

    for idx in placement_order:
        owner = file_owner_arr[idx]
        # Try to place actual_n shards across n-1 other nodes
        available = [
            p for p in range(n)
            if p != owner and (node_usage[p] + shard_size) <= capacity[p]
        ]
        if len(available) < actual_k:
            # Not enough capacity — file cannot be backed up
            continue
        n_place = min(actual_n, len(available))
        if n_place < actual_k:
            continue
        # Place shards (greedy: fill lowest-usage nodes first)
        available_sorted = sorted(available, key=lambda p: node_usage[p])
        for p in available_sorted[:n_place]:
            node_usage[p] += shard_size
        files_placed[idx] = True
        node_files_placed[owner] += 1

    # Per-node effective backup ratio
    node_backup_ratio = node_files_placed / max(files_wanted_per_node, 1)

    return {
        "saturation_ratio": saturation_ratio,
        "files_placed_frac": float(files_placed.sum()) / total_files_wanted,
        "mean_backup_ratio": float(node_backup_ratio.mean()),
        "min_backup_ratio": float(node_backup_ratio.min()),
        "std_backup_ratio": float(node_backup_ratio.std()),
        "gini_backup_ratio": float(_gini(node_backup_ratio)),
        "actual_k": actual_k,
        "actual_n": actual_n,
    }


def _gini(arr: np.ndarray) -> float:
    """Gini coefficient of array (0=equal, 1=maximally unequal)."""
    if arr.sum() == 0:
        return 0.0
    arr = np.sort(arr)
    n = len(arr)
    index = np.arange(1, n + 1)
    return float((2 * (index * arr).sum()) / (n * arr.sum()) - (n + 1) / n)


def run_scenario_c(config: Config, n_jobs: int = 1) -> dict:
    """Monte Carlo for Scenario C."""
    t0 = time.time()
    seeds = range(config.n_seeds)

    if n_jobs == 1:
        results = [simulate_scenario_c(config, s) for s in seeds]
    else:
        results = Parallel(n_jobs=n_jobs)(
            delayed(simulate_scenario_c)(config, s) for s in seeds
        )

    ratio = np.array([r["mean_backup_ratio"] for r in results])
    min_ratio = np.array([r["min_backup_ratio"] for r in results])
    gini = np.array([r["gini_backup_ratio"] for r in results])
    placed = np.array([r["files_placed_frac"] for r in results])

    return {
        "config": asdict(config),
        "elapsed_sec": time.time() - t0,
        "saturation_ratio": results[0]["saturation_ratio"],
        "actual_k": results[0]["actual_k"],
        "actual_n": results[0]["actual_n"],
        "files_placed_frac_mean": float(placed.mean()),
        "mean_backup_ratio_mean": float(ratio.mean()),
        "mean_backup_ratio_p5": float(np.percentile(ratio, 5)),
        "min_backup_ratio_mean": float(min_ratio.mean()),
        "gini_mean": float(gini.mean()),
    }


# ---------------------------------------------------------------------------
# Sweep helpers
# ---------------------------------------------------------------------------

def _sweep_a_task(
    n_nodes: int,
    annual_churn: float,
    n_files_per_node: int,
    n_months: int,
    k_desired: int,
    n_shards_desired: int,
    honest_reliability: float,
    kp: float,
    ki: float,
    p_window: int,
    trust_threshold: float,
    repair_interval_days: int,
    repair_delay_days: int,
    rejoin_prob: float,
    rejoin_delay_days: int,
    n_seeds: int,
) -> dict:
    cfg = Config(
        n_nodes=n_nodes,
        annual_churn=annual_churn,
        n_files_per_node=n_files_per_node,
        n_months=n_months,
        k_desired=k_desired,
        n_shards_desired=n_shards_desired,
        honest_reliability=honest_reliability,
        kp=kp,
        ki=ki,
        p_window=p_window,
        trust_threshold=trust_threshold,
        repair_interval_days=repair_interval_days,
        repair_delay_days=repair_delay_days,
        rejoin_prob=rejoin_prob,
        rejoin_delay_days=rejoin_delay_days,
        n_seeds=n_seeds,
        bad_apple_type="none",
    )
    res = run_scenario_a(cfg, n_jobs=1)
    return {
        "n_nodes": n_nodes,
        "annual_churn": annual_churn,
        "actual_k": res["actual_k"],
        "actual_n": res["actual_n"],
        "file_survival_mean": res["file_survival_mean"],
        "file_survival_p5": res["file_survival_p5"],
        "effective_redundancy_mean": res["effective_redundancy_mean"],
        "effective_redundancy_p5": res["effective_redundancy_p5"],
    }


def _sweep_b_task(
    n_nodes: int,
    bad_apple_type: str,
    n_files_per_node: int,
    n_months: int,
    k_desired: int,
    n_shards_desired: int,
    honest_reliability: float,
    annual_churn: float,
    kp: float,
    ki: float,
    p_window: int,
    trust_threshold: float,
    repair_interval_days: int,
    repair_delay_days: int,
    rejoin_prob: float,
    rejoin_delay_days: int,
    liar_delay_days: int,
    n_seeds: int,
) -> dict:
    cfg = Config(
        n_nodes=n_nodes,
        bad_apple_type=bad_apple_type,
        n_files_per_node=n_files_per_node,
        n_months=n_months,
        k_desired=k_desired,
        n_shards_desired=n_shards_desired,
        honest_reliability=honest_reliability,
        annual_churn=annual_churn,
        kp=kp,
        ki=ki,
        p_window=p_window,
        trust_threshold=trust_threshold,
        repair_interval_days=repair_interval_days,
        repair_delay_days=repair_delay_days,
        rejoin_prob=rejoin_prob,
        rejoin_delay_days=rejoin_delay_days,
        liar_delay_days=liar_delay_days,
        n_seeds=n_seeds,
    )
    res = run_scenario_b(cfg, n_jobs=1)
    return {
        "n_nodes": n_nodes,
        "bad_apple_type": bad_apple_type,
        "actual_k": res["actual_k"],
        "actual_n": res["actual_n"],
        "file_survival_mean": res["file_survival_mean"],
        "file_survival_p5": res["file_survival_p5"],
        "target_file_survival_mean": res["target_file_survival_mean"],
    }


def run_sweep_a(base_config: Config, output_dir: Path, n_jobs: int = 1) -> list[dict]:
    """Sweep Scenario A: network_size x annual_churn."""
    sizes = [3, 5, 7, 10, 15, 20, 30, 50]
    churns = [0.0, 0.10, 0.25]

    tasks = []
    for n_nodes in sizes:
        for churn in churns:
            tasks.append((
                n_nodes, churn,
                base_config.n_files_per_node,
                base_config.n_months,
                base_config.k_desired,
                base_config.n_shards_desired,
                base_config.honest_reliability,
                base_config.kp,
                base_config.ki,
                base_config.p_window,
                base_config.trust_threshold,
                base_config.repair_interval_days,
                base_config.repair_delay_days,
                base_config.rejoin_prob,
                base_config.rejoin_delay_days,
                30,  # seeds per config in sweep
            ))

    total = len(tasks)
    print(f"Scenario A sweep: {total} configs ({len(sizes)} sizes x "
          f"{len(churns)} churn rates), {n_jobs} jobs")

    if n_jobs == 1:
        results: list[dict] = []
        for i, t in enumerate(tasks, 1):
            r = _sweep_a_task(*t)
            results.append(r)
            print(f"  [{i:>2}/{total}] N={r['n_nodes']:>2} "
                  f"churn={r['annual_churn']*100:.0f}% "
                  f"k-of-n={r['actual_k']}-of-{r['actual_n']} "
                  f"surv={r['file_survival_mean']*100:.1f}% "
                  f"(p5={r['file_survival_p5']*100:.1f}%) "
                  f"red={r['effective_redundancy_mean']:.2f}")
    else:
        t0 = time.time()
        results = list(Parallel(n_jobs=n_jobs, verbose=5)(
            delayed(_sweep_a_task)(*t) for t in tasks
        ))
        print(f"  Done in {time.time()-t0:.1f}s")

    out = output_dir / "sweep_a.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(f"  Saved to {out}")
    return results


def run_sweep_b(base_config: Config, output_dir: Path, n_jobs: int = 1) -> list[dict]:
    """Sweep Scenario B: network_size x bad_apple_type."""
    sizes = [5, 10, 20, 50]
    bad_types = ["none", "freerider", "liar", "spite"]

    tasks = []
    for n_nodes in sizes:
        for bad_type in bad_types:
            tasks.append((
                n_nodes, bad_type,
                base_config.n_files_per_node,
                base_config.n_months,
                base_config.k_desired,
                base_config.n_shards_desired,
                base_config.honest_reliability,
                base_config.annual_churn,
                base_config.kp,
                base_config.ki,
                base_config.p_window,
                base_config.trust_threshold,
                base_config.repair_interval_days,
                base_config.repair_delay_days,
                base_config.rejoin_prob,
                base_config.rejoin_delay_days,
                base_config.liar_delay_days,
                30,  # seeds per config
            ))

    total = len(tasks)
    print(f"Scenario B sweep: {total} configs ({len(sizes)} sizes x "
          f"{len(bad_types)} bad-apple types), {n_jobs} jobs")

    if n_jobs == 1:
        results: list[dict] = []
        for i, t in enumerate(tasks, 1):
            r = _sweep_b_task(*t)
            results.append(r)
            print(f"  [{i:>2}/{total}] N={r['n_nodes']:>2} "
                  f"type={r['bad_apple_type']:<10} "
                  f"k-of-n={r['actual_k']}-of-{r['actual_n']} "
                  f"surv={r['file_survival_mean']*100:.1f}% "
                  f"target={r['target_file_survival_mean']*100:.1f}%")
    else:
        t0 = time.time()
        results = list(Parallel(n_jobs=n_jobs, verbose=5)(
            delayed(_sweep_b_task)(*t) for t in tasks
        ))
        print(f"  Done in {time.time()-t0:.1f}s")

    out = output_dir / "sweep_b.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(f"  Saved to {out}")
    return results


# ---------------------------------------------------------------------------
# Print summaries
# ---------------------------------------------------------------------------

def print_summary_a(result: dict) -> None:
    cfg = result["config"]
    print(f"Config: {cfg['n_nodes']} nodes, {cfg['n_files_per_node']} files/node, "
          f"{cfg['n_months']} months")
    print(f"Erasure (adapted): {result['actual_k']}-of-{result['actual_n']} "
          f"(desired: {cfg['k_desired']}-of-{cfg['n_shards_desired']})")
    print(f"Churn: {cfg['annual_churn']*100:.0f}%/year, "
          f"rejoin_prob={cfg['rejoin_prob']:.1f}")
    print(f"Seeds: {cfg['n_seeds']}, runtime: {result['elapsed_sec']:.1f}s")
    print()
    print(f"File survival: {result['file_survival_mean']*100:.2f}% "
          f"(p5={result['file_survival_p5']*100:.1f}%, "
          f"p95={result['file_survival_p95']*100:.1f}%)")
    print(f"Effective redundancy: {result['effective_redundancy_mean']:.3f} "
          f"(p5={result['effective_redundancy_p5']:.3f})")


def print_summary_b(result: dict) -> None:
    cfg = result["config"]
    print(f"Config: {cfg['n_nodes']} nodes, bad_apple={cfg['bad_apple_type']}, "
          f"{cfg['n_months']} months")
    print(f"Erasure (adapted): {result['actual_k']}-of-{result['actual_n']}")
    print(f"Seeds: {cfg['n_seeds']}, runtime: {result['elapsed_sec']:.1f}s")
    print()
    print(f"Overall file survival: {result['file_survival_mean']*100:.2f}% "
          f"(p5={result['file_survival_p5']*100:.1f}%)")
    print(f"Target file survival:  {result['target_file_survival_mean']*100:.2f}% "
          f"(p5={result['target_file_survival_p5']*100:.1f}%)")
    print(f"Bad-apple owner files: {result['bad_owner_survival_mean']*100:.2f}%")


def print_summary_c(result: dict) -> None:
    cfg = result["config"]
    print(f"Config: {cfg['n_nodes']} nodes, "
          f"want={cfg['want_gb_per_node']:.0f}GB, "
          f"offer={cfg['offer_gb_per_node']:.0f}GB, "
          f"{cfg['n_months']} months")
    print(f"Saturation ratio: {result['saturation_ratio']:.2f}x "
          f"(want/offer = {cfg['want_gb_per_node']:.0f}/{cfg['offer_gb_per_node']:.0f})")
    print(f"Erasure (adapted): {result['actual_k']}-of-{result['actual_n']}")
    print(f"Seeds: {cfg['n_seeds']}, runtime: {result['elapsed_sec']:.1f}s")
    print()
    print(f"Files placed:      {result['files_placed_frac_mean']*100:.1f}%")
    print(f"Backup ratio mean: {result['mean_backup_ratio_mean']*100:.1f}% "
          f"(p5={result['mean_backup_ratio_p5']*100:.1f}%)")
    print(f"Min backup ratio:  {result['min_backup_ratio_mean']*100:.1f}%")
    print(f"Gini coefficient:  {result['gini_mean']:.3f} "
          f"(0=equal, 1=one node gets everything)")


def print_sweep_a_table(rows: list[dict]) -> None:
    print("\n=== MINIMUM VIABLE NETWORK (Scenario A) ===")
    print(f"  {'Size':>4}  {'Churn':>5}  {'k-of-n':>6}  "
          f"{'Survival%':>9}  {'p5%':>5}  {'Redundancy':>10}")
    for r in sorted(rows, key=lambda x: (x["annual_churn"], x["n_nodes"])):
        print(f"  {r['n_nodes']:>4}  {r['annual_churn']*100:>4.0f}%  "
              f"{r['actual_k']}-of-{r['actual_n']:<3}  "
              f"{r['file_survival_mean']*100:>8.1f}%  "
              f"{r['file_survival_p5']*100:>4.1f}%  "
              f"{r['effective_redundancy_mean']:>10.2f}")

    # Find minimum viable size (first N where survival >= 95%) per churn level
    print()
    print("Minimum viable size (survival >= 95%):")
    from itertools import groupby
    rows_sorted = sorted(rows, key=lambda x: x["annual_churn"])
    for churn_val, group in groupby(rows_sorted, key=lambda x: x["annual_churn"]):
        viable = [r for r in group if r["file_survival_mean"] >= 0.95]
        if viable:
            min_n = min(r["n_nodes"] for r in viable)
            print(f"  Churn {churn_val*100:.0f}%: N >= {min_n}")
        else:
            print(f"  Churn {churn_val*100:.0f}%: no viable size found in sweep")


def print_sweep_b_table(rows: list[dict]) -> None:
    print("\n=== BAD APPLE IMPACT (Scenario B) ===")

    # Build lookup for "none" baseline per network size
    baseline: dict[int, float] = {
        r["n_nodes"]: r["file_survival_mean"]
        for r in rows if r["bad_apple_type"] == "none"
    }

    print(f"  {'Size':>4}  {'BadApple':>10}  {'Survival%':>9}  "
          f"{'vs_Honest':>9}  {'Amplification':>13}")

    for r in sorted(rows, key=lambda x: (x["n_nodes"], x["bad_apple_type"])):
        base = baseline.get(r["n_nodes"], None)
        bad_type = r["bad_apple_type"]

        if bad_type == "none" or base is None:
            vs_str = "     -"
            amp_str = "           -"
        else:
            delta = r["file_survival_mean"] - base
            # Amplification: how much worse than random 1/N fraction would predict
            # If 1 bad node = 1/N of network, "naive" impact = 1/N
            # Amplification = actual_impact / (1/N)
            n = r["n_nodes"]
            naive_impact = 1.0 / n
            actual_impact = abs(delta)
            amp = actual_impact / naive_impact if naive_impact > 0 else 0.0
            vs_str = f"{delta*100:>+6.1f}%"
            amp_str = f"{amp:>10.1f}x"

        print(f"  {r['n_nodes']:>4}  {bad_type:>10}  "
              f"{r['file_survival_mean']*100:>8.1f}%  "
              f"{vs_str:>9}  {amp_str:>13}")


def save_results(result: dict, path: Path) -> None:
    """Save results to JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2))
    print(f"Results saved to {path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Prison Network Simulation (Experiment #12)'
    )
    parser.add_argument("--nodes", type=int, default=10,
                        help="Number of nodes in the network")
    parser.add_argument("--files", type=int, default=100,
                        help="Files per node")
    parser.add_argument("--months", type=int, default=24,
                        help="Simulation duration in months")
    parser.add_argument("--seeds", type=int, default=30,
                        help="Monte Carlo seeds")
    parser.add_argument("--k", type=int, default=5,
                        help="Desired reconstruction threshold")
    parser.add_argument("--n-shards", type=int, default=15,
                        help="Desired total shards per file")
    parser.add_argument("--churn", type=float, default=0.10,
                        help="Annual churn rate (0.0 = none, 0.1 = 10%%)")
    parser.add_argument("--reliability", type=float, default=0.95,
                        help="Honest peer reliability")
    parser.add_argument("--scenario", choices=["A", "B", "C", "all"], default="all",
                        help="Which scenario to run (default: all)")
    parser.add_argument("--bad-apple", choices=["none", "freerider", "liar", "spite"],
                        default="freerider",
                        help="Bad apple type for Scenario B")
    parser.add_argument("--want-gb", type=float, default=100.0,
                        help="GB each node wants to back up (Scenario C)")
    parser.add_argument("--offer-gb", type=float, default=60.0,
                        help="GB each node offers for storage (Scenario C)")
    parser.add_argument("--kp", type=float, default=0.5,
                        help="PI controller P weight")
    parser.add_argument("--ki", type=float, default=2.0,
                        help="PI controller I weight")
    parser.add_argument("--window", type=int, default=30,
                        help="P rolling window in days")
    parser.add_argument("--trust-threshold", type=float, default=0.3,
                        help="Min trust to be eligible as shard holder")
    parser.add_argument("--repair-interval", type=int, default=7,
                        help="Days between repair cycles")
    parser.add_argument("--repair-delay", type=int, default=7,
                        help="Days from detection to repair completion")
    parser.add_argument("--liar-delay", type=int, default=30,
                        help="Days before liar deletes shards (Scenario B)")
    parser.add_argument("--sweep", action="store_true",
                        help="Run full parameter sweep (all scenarios)")
    parser.add_argument("--sweep-a", action="store_true",
                        help="Run Scenario A sweep only")
    parser.add_argument("--sweep-b", action="store_true",
                        help="Run Scenario B sweep only")
    parser.add_argument("--jobs", type=int, default=1,
                        help="Parallel jobs (joblib)")
    parser.add_argument("--output", type=str, default="results/prison_network",
                        help="Output directory for results")
    args = parser.parse_args()

    output_dir = Path(args.output)
    if args.sweep or args.sweep_a or args.sweep_b:
        output_dir = Path("results/prison_sweep")

    base_config = Config(
        n_nodes=args.nodes,
        n_files_per_node=args.files,
        n_months=args.months,
        n_seeds=args.seeds,
        k_desired=args.k,
        n_shards_desired=args.n_shards,
        honest_reliability=args.reliability,
        annual_churn=args.churn,
        kp=args.kp,
        ki=args.ki,
        p_window=args.window,
        trust_threshold=args.trust_threshold,
        repair_interval_days=args.repair_interval,
        repair_delay_days=args.repair_delay,
        bad_apple_type=args.bad_apple,
        want_gb_per_node=args.want_gb,
        offer_gb_per_node=args.offer_gb,
        liar_delay_days=args.liar_delay,
    )

    if args.sweep or args.sweep_a:
        print("=== PRISON NETWORK: SCENARIO A SWEEP ===\n")
        rows_a = run_sweep_a(base_config, output_dir, n_jobs=args.jobs)
        print_sweep_a_table(rows_a)

    if args.sweep or args.sweep_b:
        print("\n=== PRISON NETWORK: SCENARIO B SWEEP ===\n")
        rows_b = run_sweep_b(base_config, output_dir, n_jobs=args.jobs)
        print_sweep_b_table(rows_b)

    if not (args.sweep or args.sweep_a or args.sweep_b):
        scenario = args.scenario

        if scenario in ("A", "all"):
            print("=== SCENARIO A: MINIMUM VIABLE NETWORK ===\n")
            result_a = run_scenario_a(base_config, n_jobs=args.jobs)
            print_summary_a(result_a)
            save_results(result_a, output_dir / "scenario_a.json")
            print()

        if scenario in ("B", "all"):
            print("=== SCENARIO B: ONE BAD APPLE ===\n")
            result_b = run_scenario_b(base_config, n_jobs=args.jobs)
            print_summary_b(result_b)
            save_results(result_b, output_dir / "scenario_b.json")
            print()

        if scenario in ("C", "all"):
            print("=== SCENARIO C: CAPACITY SATURATION ===\n")
            result_c = run_scenario_c(base_config, n_jobs=args.jobs)
            print_summary_c(result_c)
            save_results(result_c, output_dir / "scenario_c.json")


if __name__ == "__main__":
    main()
