"""
SyncBack Simulation #10: Emergent Cluster Formation in a Living P2P Network

Question: Does a trust graph with reciprocity and churn naturally partition into
stable, evolving communities over a 10-year network lifetime?

Model:
- Network grows gradually: +100 nodes/month year 1, +1000/month after (cap 10K)
- Annual churn of 20-30%: nodes leave, their shard-holding relationships break
- Remaining nodes repair by finding new partners
- Partner selection uses: reciprocity > I-score trust > newcomer-to-newcomer pairing
- Acceptance gate: high-trust nodes REJECT low-trust requestors (push newcomers together)
- This gate is the core mechanism driving cohort cluster formation

Key dynamics captured:
- Cohort effect: nodes that joined together form bonds (both newcomers simultaneously)
- Churn breaks old partnerships, creating openings for new relationships
- Some nodes become bridge nodes (high trust in multiple clusters)
- Clusters are STABLE but not FROZEN: members change slowly

Metrics at each snapshot:
- Modularity (Leiden via leidenalg/igraph)
- Number and sizes of communities
- Mutual edge ratio (I store for you AND you store for me)
- Clustering coefficient
- Cross-cohort edges (edges between nodes from different cohort years)
- Bridge nodes: participation coefficient > threshold

Usage:
    python cluster_formation.py                          # default 10-year run
    python cluster_formation.py --years 5 --seeds 10     # shorter run
    python cluster_formation.py --sweep --jobs 24        # sweep trust_threshold x reciprocity
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path

import numpy as np
from joblib import Parallel, delayed


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class Config:
    max_active_peers: int = 10000
    initial_peers: int = 50
    growth_rate_y1: int = 100      # new peers/month during year 1
    growth_rate_after: int = 1000  # new peers/month after year 1
    annual_churn: float = 0.25     # fraction of active nodes that leave per year
    max_partners: int = 50         # max nodes that store OUR shards
    n_shards: int = 15             # target number of storage partners per node
    n_years: int = 10
    reciprocity_weight: float = 2.0   # score bonus if partner already stores our shards
    trust_threshold: float = 0.3      # acceptance gate: established nodes reject low-trust
    n_seeds: int = 5
    snapshot_interval_months: int = 6


# ---------------------------------------------------------------------------
# Network state helpers
# ---------------------------------------------------------------------------

def _months_total(config: Config) -> int:
    return config.n_years * 12


def _monthly_churn_rate(config: Config) -> float:
    """Convert annual churn rate to monthly probability."""
    return 1.0 - (1.0 - config.annual_churn) ** (1.0 / 12.0)


def _new_arrivals_this_month(month: int, config: Config) -> int:
    """Number of new peers joining in a given month (0-indexed)."""
    if month < 12:
        return config.growth_rate_y1
    return config.growth_rate_after


# ---------------------------------------------------------------------------
# Core simulation
# ---------------------------------------------------------------------------

def simulate_one(config: Config, seed: int) -> dict:
    """
    Simulate trust graph formation over n_years with gradual growth and churn.

    Data structures (numpy for speed):
      stores_on[i, :]  -- indices of nodes that hold node i's shards (-1 = empty slot)
      stores_for[j, :] -- indices of nodes whose shards are stored by node j (-1 = empty)
      i_score[i]       -- cumulative trust score (months of reliable storage / N)
      cohort[i]        -- year index (0-9) when node i joined

    Partner selection is vectorized: we score all active candidates for a
    requesting node using numpy operations, then pick the best ones.
    Only nodes that LOST a partner due to churn are required to seek repair.
    """
    rng = np.random.default_rng(seed)
    cfg = config
    months = _months_total(cfg)
    monthly_churn = _monthly_churn_rate(cfg)
    snapshot_months = set(
        m for m in range(1, months + 1)
        if m % cfg.snapshot_interval_months == 0
    )

    # Pre-allocate arrays for maximum possible active peers
    cap = cfg.max_active_peers
    MP = cfg.max_partners

    # stores_on[i, :] = who stores node i's shards (node i's *uploaders*)
    # stores_for[j, :] = whose shards node j is storing (j's *downloads*)
    # Using -1 as sentinel for empty slot.
    stores_on = np.full((cap, MP), -1, dtype=np.int32)
    stores_for = np.full((cap, MP), -1, dtype=np.int32)

    i_score = np.zeros(cap, dtype=np.float64)
    cohort = np.full(cap, -1, dtype=np.int32)  # which year-cohort (0..9)
    join_month = np.full(cap, -1, dtype=np.int32)
    alive = np.zeros(cap, dtype=bool)           # currently active

    # How many slots used per node (counts non-(-1) entries)
    on_count = np.zeros(cap, dtype=np.int32)    # len of stores_on[i]
    for_count = np.zeros(cap, dtype=np.int32)   # len of stores_for[j]

    next_id = 0       # next fresh ID to assign (grows up to cap, never beyond)
    free_ids: list[int] = []  # recycled IDs from churned nodes

    def _add_node(node_id: int, month: int) -> None:
        """Activate a new node."""
        year = min(month // 12, cfg.n_years - 1)
        alive[node_id] = True
        join_month[node_id] = month
        cohort[node_id] = year
        i_score[node_id] = 0.0
        stores_on[node_id, :] = -1
        stores_for[node_id, :] = -1
        on_count[node_id] = 0
        for_count[node_id] = 0

    def _add_edge(a: int, b: int) -> None:
        """
        Add the edge where a places shards ON b (b stores FOR a).
        No-op if already present or either node is full.
        """
        if on_count[a] >= MP or for_count[b] >= MP:
            return
        # Check not already present
        if b in stores_on[a, :on_count[a]]:
            return
        stores_on[a, on_count[a]] = b
        on_count[a] += 1
        stores_for[b, for_count[b]] = a
        for_count[b] += 1

    def _churn_node(node_id: int) -> list[int]:
        """
        Remove node from network. Break all its edges.
        Returns list of nodes that lost a partner (need repair).
        """
        need_repair: list[int] = []

        # node_id stored shards ON these nodes → those nodes lose a "for" entry
        for b in stores_on[node_id, :on_count[node_id]].copy():
            if b < 0:
                continue
            row_b = stores_for[b, :for_count[b]]
            pos = np.where(row_b == node_id)[0]
            if pos.size > 0:
                idx = int(pos[0])
                cnt = for_count[b] - 1
                stores_for[b, idx] = stores_for[b, cnt]
                stores_for[b, cnt] = -1
                for_count[b] = cnt

        # These nodes stored shards FOR node_id → they lose an "on" entry,
        # and node_id loses its shard holders → need repair
        for a in stores_for[node_id, :for_count[node_id]].copy():
            if a < 0:
                continue
            row_a = stores_on[a, :on_count[a]]
            pos = np.where(row_a == node_id)[0]
            if pos.size > 0:
                idx = int(pos[0])
                cnt = on_count[a] - 1
                stores_on[a, idx] = stores_on[a, cnt]
                stores_on[a, cnt] = -1
                on_count[a] = cnt
            need_repair.append(a)

        # Clear node's own arrays and return ID to the free pool
        stores_on[node_id, :] = -1
        stores_for[node_id, :] = -1
        on_count[node_id] = 0
        for_count[node_id] = 0
        alive[node_id] = False
        free_ids.append(node_id)
        return need_repair

    def _select_partners(
        requestor: int,
        active_ids: np.ndarray,
        n_needed: int,
        already_on: np.ndarray,
    ) -> list[int]:
        """
        Vectorized partner selection for requestor.

        Scoring (higher = preferred):
          base     = i_score[candidate]
          +reciprocity_weight  if requestor already in stores_for[candidate]
                               (i.e., candidate stores FOR requestor already)
          +newcomer_bonus      if both requestor and candidate are below trust_threshold

        Acceptance gate: if candidate i_score > trust_threshold AND
                         requestor i_score < trust_threshold → candidate rejects.

        already_on: current stores_on[requestor, :on_count[requestor]]
        """
        r_score = i_score[requestor]

        # Mask: exclude self, already partners, full nodes
        mask = alive.copy()
        mask[requestor] = False
        if already_on.size > 0:
            mask[already_on[already_on >= 0]] = False
        # Exclude nodes that can't accept more (for_count at capacity)
        mask &= for_count < MP

        # Acceptance gate: established nodes reject low-trust requestors
        if r_score < cfg.trust_threshold:
            # Candidates with i_score > trust_threshold will reject us
            # → exclude them from candidates
            mask &= i_score <= cfg.trust_threshold

        candidates = np.where(mask)[0]
        if candidates.size == 0:
            # Relax the acceptance gate as last resort: try anyone with capacity
            mask2 = alive.copy()
            mask2[requestor] = False
            if already_on.size > 0:
                mask2[already_on[already_on >= 0]] = False
            mask2 &= for_count < MP
            candidates = np.where(mask2)[0]
            if candidates.size == 0:
                return []

        c_scores = i_score[candidates].copy()

        # Reciprocity bonus: candidate already stores FOR requestor
        # (requestor is in stores_for[candidate])
        # Check vectorized: requestor in stores_for[c, :for_count[c]]
        # This is the main O(n_candidates) loop — unavoidable but numpy-fast
        reciprocal = np.zeros(candidates.size, dtype=bool)
        for k, cid in enumerate(candidates):
            fc = int(for_count[cid])
            if fc > 0 and requestor in stores_for[cid, :fc]:
                reciprocal[k] = True
        c_scores[reciprocal] += cfg.reciprocity_weight

        # Newcomer bonus: both sides are low-trust
        if r_score <= cfg.trust_threshold:
            newcomer_mask = i_score[candidates] <= cfg.trust_threshold
            c_scores[newcomer_mask] += 0.5

        # Weighted random selection from top candidates (top 3x needed)
        top_n = min(n_needed * 3, candidates.size)
        if top_n < candidates.size:
            top_idx = np.argpartition(c_scores, -top_n)[-top_n:]
        else:
            top_idx = np.arange(candidates.size)

        top_scores = np.maximum(c_scores[top_idx], 0.01)
        probs = top_scores / top_scores.sum()
        n_pick = min(n_needed, top_idx.size)
        chosen = rng.choice(top_idx, size=n_pick, replace=False, p=probs)
        return [int(candidates[k]) for k in chosen]

    # -----------------------------------------------------------------------
    # Main simulation loop
    # -----------------------------------------------------------------------
    snapshots: dict[int, dict] = {}

    # Nodes that specifically need partner repair this month
    # (either just joined or lost a partner to churn)
    need_placement: set[int] = set()

    # Bootstrap: seed the network with initial_peers at month 0 before main loop
    for _ in range(min(cfg.initial_peers, cap)):
        nid = next_id
        next_id += 1
        _add_node(nid, 0)
        need_placement.add(nid)

    for month in range(months):
        # --- 1. New arrivals ---
        n_active = int(alive.sum())
        arrivals = _new_arrivals_this_month(month, cfg)
        if n_active < cfg.max_active_peers:
            # Available slots = cap − currently alive.
            # IDs come from the recycled free pool first, then fresh pool up to cap.
            n_slots = cfg.max_active_peers - n_active
            batch = min(arrivals, n_slots)
            for _ in range(batch):
                # Prefer recycled IDs; fall back to fresh IDs
                if free_ids:
                    nid = free_ids.pop()
                elif next_id < cap:
                    nid = next_id
                    next_id += 1
                else:
                    # Array space exhausted (shouldn't happen under normal params)
                    break
                _add_node(nid, month)
                need_placement.add(nid)

        # --- 2. Churn: remove nodes ---
        active_ids = np.where(alive)[0]
        if active_ids.size > 0:
            churn_mask = rng.random(active_ids.size) < monthly_churn
            churning = active_ids[churn_mask]
            for node_id in churning:
                orphaned = _churn_node(int(node_id))
                need_placement.update(o for o in orphaned if alive[o])

        # --- 3. Update I-scores for all active nodes ---
        # Each month a node stores shards for others, its I-score grows.
        # Normalise by cap (not current N) so scores are comparable over time.
        active_ids = np.where(alive)[0]
        if active_ids.size > 0:
            i_score[active_ids] += for_count[active_ids].astype(np.float64) / cap

        # --- 4. Partner placement (only for nodes that need it) ---
        # Also: active nodes that are underfull may opportunistically seek partners.
        # We limit opportunistic repair to avoid O(N^2) every month.
        underfull = active_ids[on_count[active_ids] < cfg.n_shards]
        # Add newly underfull to the placement queue (sample up to 200 to bound cost)
        if underfull.size > 200:
            sample = rng.choice(underfull, size=200, replace=False)
            need_placement.update(int(x) for x in sample)
        else:
            need_placement.update(int(x) for x in underfull)

        if need_placement:
            active_ids_current = np.where(alive)[0]
            # Shuffle placement order to avoid systematic bias
            placement_list = list(need_placement)
            rng.shuffle(placement_list)

            for pid in placement_list:
                if not alive[pid]:
                    continue
                current_count = int(on_count[pid])
                n_needed = cfg.n_shards - current_count
                if n_needed <= 0:
                    continue
                already_on = stores_on[pid, :current_count]
                chosen = _select_partners(
                    pid, active_ids_current, n_needed, already_on
                )
                for cid in chosen:
                    _add_edge(pid, cid)

            need_placement.clear()

        # --- 5. Snapshot ---
        if (month + 1) in snapshot_months:
            active_ids_snap = np.where(alive)[0]
            snap = _analyze_graph(
                active_ids_snap, stores_on, on_count,
                cohort, i_score, cfg
            )
            snap["month"] = month + 1
            snap["n_active"] = int(active_ids_snap.size)
            snapshots[month + 1] = snap

    return snapshots


# ---------------------------------------------------------------------------
# Graph analysis
# ---------------------------------------------------------------------------

def _analyze_graph(
    active_ids: np.ndarray,
    stores_on: np.ndarray,
    on_count: np.ndarray,
    cohort: np.ndarray,
    i_score: np.ndarray,
    config: Config,
) -> dict:
    """
    Build undirected storage graph and compute community metrics.

    Edge weight: 1 = one-directional storage, 2 = mutual (both store for each other).
    Bridge node: participation coefficient >= 0.5 (stores for multiple communities).
    Cross-cohort edge: endpoints joined in different year-cohorts.
    """
    try:
        import igraph as ig
    except ImportError:
        return {"error": "igraph not installed"}

    n = active_ids.size
    if n < 2:
        return {"error": "too few nodes"}

    # Map global node IDs to 0..n-1
    id_map = {int(gid): local for local, gid in enumerate(active_ids)}

    # Build edge dictionary: (u, v) → weight (1 or 2 for mutual)
    edge_dict: dict[tuple[int, int], int] = {}
    for gid in active_ids:
        pid = int(gid)
        local_p = id_map[pid]
        for slot in range(int(on_count[pid])):
            cid = int(stores_on[pid, slot])
            if cid < 0 or cid not in id_map:
                continue
            local_c = id_map[cid]
            key = (min(local_p, local_c), max(local_p, local_c))
            edge_dict[key] = edge_dict.get(key, 0) + 1

    if not edge_dict:
        return {"modularity": 0.0, "n_communities": 0, "error": "no edges"}

    edge_list = list(edge_dict.keys())
    weights = [float(w) for w in edge_dict.values()]

    g = ig.Graph(n=n, edges=edge_list, directed=False)
    g.es["weight"] = weights

    # Community detection (Leiden preferred, fallback to Louvain)
    try:
        import leidenalg
        partition = leidenalg.find_partition(
            g, leidenalg.ModularityVertexPartition, weights="weight",
            seed=42,
        )
        modularity = float(partition.modularity)
        membership = list(partition.membership)
    except ImportError:
        part = g.community_multilevel(weights="weight")
        modularity = float(part.modularity)
        membership = list(part.membership)

    membership_arr = np.array(membership, dtype=np.int32)
    n_communities = int(membership_arr.max()) + 1
    comm_sizes = np.bincount(membership_arr)

    # Mutual edge ratio
    n_mutual = sum(1 for w in weights if w >= 2)
    total_edges = len(weights)
    mutual_ratio = float(n_mutual / total_edges) if total_edges > 0 else 0.0

    # Clustering coefficient
    clustering = float(g.transitivity_undirected())

    # Cross-cohort edge ratio
    cohort_local = cohort[active_ids]  # shape (n,)
    cross_cohort = 0
    for (u, v) in edge_list:
        if cohort_local[u] != cohort_local[v]:
            cross_cohort += 1
    cross_cohort_ratio = float(cross_cohort / total_edges) if total_edges > 0 else 0.0

    # Bridge nodes: participation coefficient
    # PC_i = 1 - sum_c (k_{ic}/k_i)^2  where k_{ic} = edges from i to community c
    # PC >= 0.5 → bridge node
    degrees = np.array(g.degree(), dtype=np.float64)
    adj_list = [[] for _ in range(n)]
    for (u, v) in edge_list:
        adj_list[u].append(v)
        adj_list[v].append(u)

    n_bridges = 0
    pc_values = np.zeros(n, dtype=np.float64)
    for node in range(n):
        ki = degrees[node]
        if ki == 0:
            pc_values[node] = 0.0
            continue
        neighbors = adj_list[node]
        comm_counts: dict[int, int] = {}
        for nb in neighbors:
            c = int(membership_arr[nb])
            comm_counts[c] = comm_counts.get(c, 0) + 1
        pc = 1.0 - sum((cnt / ki) ** 2 for cnt in comm_counts.values())
        pc_values[node] = pc
        if pc >= 0.5:
            n_bridges += 1

    degree_arr = degrees
    return {
        "modularity": modularity,
        "n_communities": n_communities,
        "community_sizes": {
            "mean": float(comm_sizes.mean()),
            "std": float(comm_sizes.std()),
            "min": int(comm_sizes.min()),
            "max": int(comm_sizes.max()),
            "median": float(np.median(comm_sizes)),
        },
        "mutual_edge_ratio": mutual_ratio,
        "total_edges": total_edges,
        "degree_mean": float(degree_arr.mean()),
        "degree_std": float(degree_arr.std()),
        "clustering_coeff": clustering,
        "cross_cohort_ratio": cross_cohort_ratio,
        "n_bridge_nodes": n_bridges,
        "bridge_ratio": float(n_bridges / n) if n > 0 else 0.0,
        "pc_mean": float(pc_values.mean()),
    }


# ---------------------------------------------------------------------------
# Experiment runner (Monte Carlo)
# ---------------------------------------------------------------------------

def run_experiment(config: Config, n_jobs: int = 1) -> dict:
    """Run Monte Carlo experiment across seeds and aggregate snapshots."""
    t0 = time.time()

    if n_jobs == 1:
        all_snapshots = [
            simulate_one(config, seed) for seed in range(config.n_seeds)
        ]
    else:
        all_snapshots = Parallel(n_jobs=n_jobs)(
            delayed(simulate_one)(config, seed)
            for seed in range(config.n_seeds)
        )

    elapsed = time.time() - t0

    # Collect all snapshot months across seeds
    all_months: set[int] = set()
    for snaps in all_snapshots:
        all_months.update(snaps.keys())

    aggregated: dict[int, dict] = {}
    for month in sorted(all_months):
        valid = [
            s[month] for s in all_snapshots
            if month in s and "error" not in s[month]
        ]
        if not valid:
            continue

        def _mean(key: str) -> float:
            return float(np.mean([s[key] for s in valid]))

        aggregated[int(month)] = {
            "n_active": valid[0]["n_active"],
            "modularity_mean": _mean("modularity"),
            "modularity_std": float(np.std([s["modularity"] for s in valid])),
            "n_communities_mean": _mean("n_communities"),
            "community_size_mean": float(np.mean([
                s["community_sizes"]["mean"] for s in valid
            ])),
            "community_size_max": float(np.mean([
                s["community_sizes"]["max"] for s in valid
            ])),
            "mutual_ratio_mean": _mean("mutual_edge_ratio"),
            "clustering_mean": _mean("clustering_coeff"),
            "cross_cohort_ratio_mean": _mean("cross_cohort_ratio"),
            "bridge_ratio_mean": _mean("bridge_ratio"),
            "degree_mean": _mean("degree_mean"),
            "total_edges_mean": _mean("total_edges"),
        }

    return {
        "config": asdict(config),
        "elapsed_sec": elapsed,
        "snapshots": aggregated,
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_summary(result: dict) -> None:
    """Print per-snapshot metrics table."""
    cfg = result["config"]
    print(
        f"Config: max_active={cfg['max_active_peers']}, "
        f"initial={cfg['initial_peers']}, "
        f"y1_growth={cfg['growth_rate_y1']}/mo, "
        f"after_growth={cfg['growth_rate_after']}/mo"
    )
    print(
        f"Churn: {cfg['annual_churn']*100:.0f}%/yr, "
        f"partners={cfg['max_partners']}, "
        f"shards={cfg['n_shards']}, "
        f"years={cfg['n_years']}"
    )
    print(
        f"reciprocity_weight={cfg['reciprocity_weight']}, "
        f"trust_threshold={cfg['trust_threshold']}"
    )
    print(f"Seeds: {cfg['n_seeds']}, runtime: {result['elapsed_sec']:.1f}s")
    print()

    header = (
        f"{'Mo':>4} {'Active':>7} {'Q':>6} {'Comms':>6} "
        f"{'AvgSz':>6} {'MaxSz':>6} "
        f"{'Mutual%':>8} {'Clust':>6} "
        f"{'XCohort%':>9} {'Bridge%':>8} {'Deg':>5}"
    )
    print(header)
    print("-" * len(header))

    for month, s in sorted(result["snapshots"].items()):
        csm = s.get("community_size_mean", 0.0)
        print(
            f"{month:>4} "
            f"{s['n_active']:>7} "
            f"{s['modularity_mean']:>6.3f} "
            f"{s['n_communities_mean']:>6.1f} "
            f"{csm:>6.1f} "
            f"{s['community_size_max']:>6.0f} "
            f"{s['mutual_ratio_mean']*100:>7.1f}% "
            f"{s['clustering_mean']:>6.3f} "
            f"{s['cross_cohort_ratio_mean']*100:>8.1f}% "
            f"{s['bridge_ratio_mean']*100:>7.1f}% "
            f"{s['degree_mean']:>5.1f}"
        )


def save_results(result: dict, path: Path) -> None:
    """Save full results to JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2))
    print(f"\nResults saved to {path}")


# ---------------------------------------------------------------------------
# Parameter sweep
# ---------------------------------------------------------------------------

def _evaluate_sweep_config(cfg: Config) -> dict:
    """Evaluate one config for the sweep (single-seed run)."""
    res = run_experiment(cfg, n_jobs=1)
    snaps = res["snapshots"]
    if not snaps:
        return {
            "trust_threshold": cfg.trust_threshold,
            "reciprocity_weight": cfg.reciprocity_weight,
            "modularity": 0.0,
            "n_communities": 0.0,
            "mutual_ratio": 0.0,
            "cross_cohort_ratio": 0.0,
            "bridge_ratio": 0.0,
            "clustering": 0.0,
        }
    # Use the last snapshot as the "final state"
    final = snaps[max(snaps.keys())]
    return {
        "trust_threshold": cfg.trust_threshold,
        "reciprocity_weight": cfg.reciprocity_weight,
        "modularity": round(final["modularity_mean"], 4),
        "n_communities": round(final["n_communities_mean"], 1),
        "mutual_ratio": round(final["mutual_ratio_mean"], 4),
        "cross_cohort_ratio": round(final["cross_cohort_ratio_mean"], 4),
        "bridge_ratio": round(final["bridge_ratio_mean"], 4),
        "clustering": round(final["clustering_mean"], 4),
    }


def run_sweep(base_config: Config, output_dir: Path, n_jobs: int = 1) -> None:
    """
    Sweep trust_threshold x reciprocity_weight.
    20 configs x 3 seeds each.
    """
    trust_values = [0.0, 0.1, 0.2, 0.3, 0.5]
    reciprocity_values = [0.0, 1.0, 2.0, 5.0]
    sweep_seeds = 3

    configs = []
    for thr in trust_values:
        for rec in reciprocity_values:
            configs.append(Config(
                max_active_peers=base_config.max_active_peers,
                initial_peers=base_config.initial_peers,
                growth_rate_y1=base_config.growth_rate_y1,
                growth_rate_after=base_config.growth_rate_after,
                annual_churn=base_config.annual_churn,
                max_partners=base_config.max_partners,
                n_shards=base_config.n_shards,
                n_years=base_config.n_years,
                trust_threshold=thr,
                reciprocity_weight=rec,
                n_seeds=sweep_seeds,
                snapshot_interval_months=base_config.snapshot_interval_months,
            ))

    total = len(configs)
    print(f"Sweep: {total} configs x {sweep_seeds} seeds, {n_jobs} jobs\n")

    if n_jobs == 1:
        results_table = []
        for i, cfg in enumerate(configs, 1):
            r = _evaluate_sweep_config(cfg)
            results_table.append(r)
            print(
                f"  [{i:>2}/{total}] thr={r['trust_threshold']:.1f} "
                f"rec={r['reciprocity_weight']:.1f} "
                f"→ Q={r['modularity']:.3f} "
                f"comms={r['n_communities']:.0f} "
                f"mutual={r['mutual_ratio']*100:.1f}% "
                f"xcohort={r['cross_cohort_ratio']*100:.1f}%"
            )
    else:
        t0 = time.time()
        results_table = Parallel(n_jobs=n_jobs, verbose=5)(
            delayed(_evaluate_sweep_config)(cfg) for cfg in configs
        )
        elapsed = time.time() - t0
        print(f"\nSweep completed in {elapsed:.1f}s")
        for r in results_table:
            print(
                f"  thr={r['trust_threshold']:.1f} "
                f"rec={r['reciprocity_weight']:.1f} "
                f"→ Q={r['modularity']:.3f} "
                f"comms={r['n_communities']:.0f} "
                f"mutual={r['mutual_ratio']*100:.1f}% "
                f"xcohort={r['cross_cohort_ratio']*100:.1f}%"
            )

    results_table.sort(key=lambda r: -r["modularity"])

    print("\n=== SWEEP RESULTS (sorted by modularity) ===")
    print(
        f"{'thr':>5} {'rec':>5} {'Q':>7} {'comms':>6} "
        f"{'mutual%':>8} {'xcohort%':>9} {'bridge%':>8} {'clust':>7}"
    )
    for r in results_table:
        print(
            f"{r['trust_threshold']:>5.2f} "
            f"{r['reciprocity_weight']:>5.1f} "
            f"{r['modularity']:>7.3f} "
            f"{r['n_communities']:>6.0f} "
            f"{r['mutual_ratio']*100:>7.1f}% "
            f"{r['cross_cohort_ratio']*100:>8.1f}% "
            f"{r['bridge_ratio']*100:>7.1f}% "
            f"{r['clustering']:>7.3f}"
        )

    sweep_path = output_dir / "sweep_results.json"
    sweep_path.parent.mkdir(parents=True, exist_ok=True)
    sweep_path.write_text(json.dumps(results_table, indent=2))
    print(f"\nFull sweep saved to {sweep_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Emergent Cluster Formation in a Living P2P Network"
    )
    parser.add_argument("--years", type=int, default=10,
                        help="Simulation duration in years")
    parser.add_argument("--max-peers", type=int, default=10000,
                        help="Maximum active peers (cap)")
    parser.add_argument("--initial-peers", type=int, default=50,
                        help="Peers present at month 0")
    parser.add_argument("--growth-y1", type=int, default=100,
                        help="New peers per month during year 1")
    parser.add_argument("--growth-after", type=int, default=1000,
                        help="New peers per month after year 1")
    parser.add_argument("--churn", type=float, default=0.25,
                        help="Annual churn rate (0.25 = 25%%)")
    parser.add_argument("--max-partners", type=int, default=50,
                        help="Max storage partners per node")
    parser.add_argument("--shards", type=int, default=15,
                        help="Target number of shard holders per node")
    parser.add_argument("--reciprocity", type=float, default=2.0,
                        help="Score bonus for mutual storage partners")
    parser.add_argument("--trust-threshold", type=float, default=0.3,
                        help="I-score gate: established nodes reject low-trust requestors")
    parser.add_argument("--seeds", type=int, default=5,
                        help="Number of Monte Carlo seeds")
    parser.add_argument("--snapshot-interval", type=int, default=6,
                        help="Months between snapshots")
    parser.add_argument("--sweep", action="store_true",
                        help="Run parameter sweep (trust_threshold x reciprocity)")
    parser.add_argument("--jobs", type=int, default=1,
                        help="Parallel jobs (cores)")
    parser.add_argument("--output", type=str,
                        default="results/cluster_formation",
                        help="Output directory for JSON results")
    args = parser.parse_args()

    config = Config(
        max_active_peers=args.max_peers,
        initial_peers=args.initial_peers,
        growth_rate_y1=args.growth_y1,
        growth_rate_after=args.growth_after,
        annual_churn=args.churn,
        max_partners=args.max_partners,
        n_shards=args.shards,
        n_years=args.years,
        reciprocity_weight=args.reciprocity,
        trust_threshold=args.trust_threshold,
        n_seeds=args.seeds,
        snapshot_interval_months=args.snapshot_interval,
    )
    output_dir = Path(args.output)

    if args.sweep:
        print("=== CLUSTER FORMATION PARAMETER SWEEP ===\n")
        run_sweep(config, output_dir, n_jobs=args.jobs)
    else:
        print("=== CLUSTER FORMATION — LIVING NETWORK ===\n")
        result = run_experiment(config, n_jobs=args.jobs)
        print_summary(result)
        save_results(result, output_dir / "run.json")


if __name__ == "__main__":
    main()
