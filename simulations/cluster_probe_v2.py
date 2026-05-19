"""
cluster_probe_v2.py — Cluster / federation analysis of the FINAL trust model.

Runs a lightweight 10-year network simulation (no file/shard tracking) then
analyses the partnership graph with Leiden community detection.

Sections
--------
1. Community detection (Leiden, ModularityVertexPartition)
2. Per-community archetype composition
3. Isolation analysis (cross-cluster edge fractions)
4. Federation summary
5. Trust distribution by archetype (+ Kendall tau)
6. Partner diversity (sampled honest nodes)

Usage
-----
    python cluster_probe_v2.py
    python cluster_probe_v2.py --seed 42 --years 10
    python cluster_probe_v2.py --partners 100 --nodes 5000
"""

from __future__ import annotations

import argparse
import time
from typing import Optional

import numpy as np
from scipy.stats import kendalltau

try:
    import igraph as ig
    import leidenalg
except ImportError:
    print(
        "ERROR: igraph and leidenalg are required.\n"
        "Install with:  pip install igraph leidenalg"
    )
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# Archetype definitions  (copied from pis_weighted_placement.py)
# ---------------------------------------------------------------------------

ARCHETYPE_NAMES = [
    "Reliable",    # 0 — most useful
    "Weekend",     # 1
    "Seasonal",    # 2
    "Nomad",       # 3
    "Hoarder",     # 4
    "Freeloader",  # 5
    "HitAndRun",   # 6 — adversarial
]
N_ARCHETYPES = len(ARCHETYPE_NAMES)
N_HONEST_ARCHETYPES = 6  # indices 0..5

# Expected usefulness rank (1 = best), excluding HitAndRun
USEFULNESS_RANK = [1, 2, 3, 4, 5, 6]

# Storage offer ratio: gb_stored_for_others / gb_stored_by_others
STORAGE_RATIOS = np.array([1.0, 1.0, 1.0, 1.0, 0.2, 0.1, 0.0], dtype=np.float64)

# Default archetype probabilities (baseline from Exp 25/26)
ARCHETYPE_PROBS_DEFAULT = np.array([0.30, 0.20, 0.12, 0.08, 0.10, 0.05, 0.15])

# P-window (weeks used for rolling average)
P_WINDOW = 4


# ---------------------------------------------------------------------------
# Trust formula  (FINAL model — multiplicative S)
# ---------------------------------------------------------------------------

KP: float = 0.5
KI: float = 2.0
S_CLAMP_MIN: float = 0.1
S_CLAMP_MAX: float = 1.0
_S_EPS: float = 0.01
_MAX_TRUST: float = (KP + KI) * 1.0  # at P=1, I=1, S_clamp=1


def _trust(
    p_b: np.ndarray,
    i_b: np.ndarray,
    s_ab: np.ndarray,
) -> np.ndarray:
    """trust = (KP*P + KI*I) * clamp(S, 0.1, 1.0)"""
    pi = KP * p_b + KI * i_b
    s_c = np.clip(s_ab, S_CLAMP_MIN, S_CLAMP_MAX)
    return pi * s_c


def _pairwise_s(arch_observer: int, arch_targets: np.ndarray) -> np.ndarray:
    """S_AB = STORAGE_RATIOS[B] / max(STORAGE_RATIOS[A], eps)"""
    r_obs = float(STORAGE_RATIOS[arch_observer])
    r_tgt = STORAGE_RATIOS[arch_targets]
    return r_tgt / max(r_obs, _S_EPS)


# ---------------------------------------------------------------------------
# Weekly pass probabilities per archetype
# ---------------------------------------------------------------------------

def _build_weekly_pass_probs(n_weeks: int) -> np.ndarray:
    """Return shape (N_ARCHETYPES, n_weeks) array of P(pass weekly check)."""
    week_idx = np.arange(n_weeks)
    week_in_year = week_idx % 52
    probs = np.zeros((N_ARCHETYPES, n_weeks), dtype=np.float64)

    # 0: Reliable — 99% daily uptime
    probs[0, :] = 1.0 - (1.0 - 0.99) ** 7

    # 1: Weekend — 95% Fri-Sun, 30% Mon-Thu
    p_fail_we = (1.0 - 0.95) ** 3 * (1.0 - 0.30) ** 4
    probs[1, :] = 1.0 - p_fail_we

    # 2: Seasonal — 95% non-summer, 20% summer (weeks 22-35)
    is_summer = (week_in_year >= 22) & (week_in_year <= 35)
    r_seasonal = np.where(is_summer, 0.20, 0.95)
    probs[2, :] = 1.0 - (1.0 - r_seasonal) ** 7

    # 3: Nomad — 50% weekly availability
    probs[3, :] = 0.50

    # 4: Hoarder — 90% daily uptime
    probs[4, :] = 1.0 - (1.0 - 0.90) ** 7

    # 5: Freeloader — 80% daily uptime
    probs[5, :] = 1.0 - (1.0 - 0.80) ** 7

    # 6: HitAndRun — 80% daily (motivated while active)
    probs[6, :] = 1.0 - (1.0 - 0.80) ** 7

    return probs


# ---------------------------------------------------------------------------
# Partnership update (simplified: no gate, no eviction)
# ---------------------------------------------------------------------------

_PARTNER_BATCH = 300  # max underfull nodes processed per week


def _update_partnerships(
    active_ids: np.ndarray,
    alive: np.ndarray,
    archetype: np.ndarray,
    p_val: np.ndarray,
    i_val: np.ndarray,
    partners: list[set[int]],
    target_partners: int,
    rng: np.random.Generator,
) -> None:
    """Trust-weighted partnership formation, no gate, no eviction."""
    on_count = np.array([len(partners[int(n)]) for n in active_ids], dtype=np.int32)
    underfull_mask = on_count < target_partners
    underfull = active_ids[underfull_mask]
    if underfull.size == 0:
        return
    if underfull.size > _PARTNER_BATCH:
        underfull = rng.choice(underfull, size=_PARTNER_BATCH, replace=False)

    active_set = set(int(x) for x in active_ids)

    for pid_raw in underfull:
        pid = int(pid_raw)
        n_needed = target_partners - len(partners[pid])
        if n_needed <= 0:
            continue

        existing = partners[pid]
        candidates = [
            c for c in active_set
            if c != pid
            and c not in existing
            and len(partners[c]) < target_partners
        ]
        if not candidates:
            continue

        arr = np.array(candidates, dtype=np.int32)
        r_pid = float(STORAGE_RATIOS[int(archetype[pid])])
        r_cands = STORAGE_RATIOS[archetype[arr]]
        s_vals = np.clip(r_cands / max(r_pid, _S_EPS), S_CLAMP_MIN, S_CLAMP_MAX)
        t_vals = np.maximum(
            _trust(p_val[arr], i_val[arr], s_vals),
            0.01,
        )
        probs = t_vals / t_vals.sum()

        n_pick = min(n_needed, len(candidates))
        chosen = rng.choice(arr, size=n_pick, replace=False, p=probs)
        for cid in chosen:
            cid = int(cid)
            partners[pid].add(cid)
            partners[cid].add(pid)


# ---------------------------------------------------------------------------
# Core simulation (lightweight — no files, no shards, no escrow)
# ---------------------------------------------------------------------------

def run_simulation(
    seed: int,
    n_years: int,
    max_nodes: int,
    target_partners: int,
    annual_churn: float,
    archetype_probs: np.ndarray,
) -> tuple[
    np.ndarray,      # active_ids
    np.ndarray,      # archetype array (cap,)
    np.ndarray,      # join_week array (cap,)
    np.ndarray,      # p_val array (cap,)
    np.ndarray,      # i_val array (cap,)
    list[set[int]],  # partners
]:
    """
    Run lightweight trust simulation.  Returns state at simulation end.
    Only tracks: node identity, P/I values, and partnership graph.
    """
    rng = np.random.default_rng(seed)
    n_weeks = n_years * 52
    pw = P_WINDOW

    cap = max_nodes + 1000  # headroom for transient spikes
    weekly_churn = 1.0 - (1.0 - annual_churn) ** (1.0 / 52.0)

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

    weekly_pass_probs = _build_weekly_pass_probs(n_weeks)

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
        atype = int(rng.choice(N_ARCHETYPES, p=archetype_probs))
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

    def _remove_node(nid: int) -> None:
        alive[nid] = False
        for pid in partners[nid]:
            partners[pid].discard(nid)
        partners[nid].clear()
        free_ids.append(nid)

    # --- Bootstrap: seed the network with some initial nodes ---
    initial_nodes = min(200, max_nodes)
    for _ in range(initial_nodes):
        nid = _alloc()
        if nid is not None:
            _add_node(nid, 0)

    print(f"  Simulating {n_years} years ({n_weeks} weeks), "
          f"max_nodes={max_nodes}, partners={target_partners} ...")

    t0 = time.time()

    for week in range(n_weeks):
        # --- Growth ---
        n_active = int(alive.sum())
        if n_active < max_nodes:
            if week < 52:
                n_new_target = 30
            elif week < 2 * 52:
                n_new_target = 80
            else:
                n_new_target = 50
            n_new = min(n_new_target, max_nodes - n_active)
            for _ in range(n_new):
                nid = _alloc()
                if nid is None:
                    break
                _add_node(nid, week)

        # --- Churn ---
        active_ids = np.where(alive)[0]
        if active_ids.size > 0:
            churn_mask = rng.random(active_ids.size) < weekly_churn
            for nid in active_ids[churn_mask]:
                _remove_node(int(nid))

        # --- Weekly checks ---
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

        # --- Update P circular buffer ---
        pos = p_buf_pos[active_ids]
        p_buf[active_ids, pos] = week_scores
        p_buf_pos[active_ids] = (pos + 1) % pw
        filled = p_buf_filled[active_ids]
        p_buf_filled[active_ids] = np.minimum(filled + 1, pw)

        # --- Update I ---
        i_sum[active_ids] += week_scores
        i_count[active_ids] += 1

        # --- Recompute P and I ---
        p_buf_sum = p_buf[active_ids, :].sum(axis=1)
        pf = p_buf_filled[active_ids].astype(np.float64)
        p_val[active_ids] = np.where(pf > 0, p_buf_sum / pf, 0.0)
        ic = i_count[active_ids].astype(np.float64)
        i_val[active_ids] = np.where(ic > 0, i_sum[active_ids] / ic, 0.0)

        # --- Partnership formation ---
        _update_partnerships(
            active_ids, alive, archetype,
            p_val, i_val, partners,
            target_partners, rng,
        )

        if week % (52 * 2) == 0:
            elapsed = time.time() - t0
            print(f"  week {week:4d}/{n_weeks}  active={int(alive.sum()):5d}  "
                  f"elapsed={elapsed:.1f}s")

    active_ids = np.where(alive)[0]
    return active_ids, archetype, join_week, p_val, i_val, partners


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def _build_graph(
    active_ids: np.ndarray,
    partners: list[set[int]],
) -> tuple[ig.Graph, dict[int, int], np.ndarray]:
    """
    Build undirected igraph from partnership sets.
    Returns (graph, node_id -> vertex_index map, vertex_index -> node_id array).
    """
    id_map = {int(nid): i for i, nid in enumerate(active_ids)}
    edges = []
    for nid in active_ids:
        nid_int = int(nid)
        for pid in partners[nid_int]:
            if pid in id_map and nid_int < pid:
                edges.append((id_map[nid_int], id_map[pid]))
    g = ig.Graph(n=len(active_ids), edges=edges)
    return g, id_map, active_ids


def _community_stats(
    membership: np.ndarray,
    active_ids: np.ndarray,
    archetype: np.ndarray,
    partners: list[set[int]],
    id_map: dict[int, int],
) -> list[dict]:
    """
    Compute per-community statistics.
    Returns list of dicts sorted by size descending.
    """
    n_comm = int(membership.max()) + 1
    stats = []
    for c in range(n_comm):
        members = np.where(membership == c)[0]
        size = len(members)
        member_nids = active_ids[members]
        arch_of_members = archetype[member_nids]

        arch_counts = {i: int((arch_of_members == i).sum()) for i in range(N_ARCHETYPES)}

        # Cross-cluster edges
        cross_edges = 0
        total_edges = 0
        for m_idx in members:
            nid = int(active_ids[m_idx])
            for pid in partners[nid]:
                if pid in id_map:
                    total_edges += 1
                    if membership[id_map[pid]] != c:
                        cross_edges += 1

        # Each edge counted from both endpoints so halve
        cross_edges //= 2
        total_edges //= 2

        cross_frac = cross_edges / max(total_edges, 1)
        har_frac = arch_counts[6] / max(size, 1)
        hoard_frac = (arch_counts[4] + arch_counts[5]) / max(size, 1)
        max_arch_frac = max(arch_counts[i] / max(size, 1) for i in range(N_ARCHETYPES))

        stats.append({
            "comm": c,
            "size": size,
            "arch_counts": arch_counts,
            "cross_edges": cross_edges,
            "total_edges": total_edges,
            "cross_frac": cross_frac,
            "har_frac": har_frac,
            "hoard_frac": hoard_frac,
            "max_arch_frac": max_arch_frac,
            "isolated": cross_edges == 0,
            "pure": max_arch_frac > 0.80,
        })

    stats.sort(key=lambda d: -d["size"])
    return stats


def _bridge_fraction(
    membership: np.ndarray,
    active_ids: np.ndarray,
    partners: list[set[int]],
    id_map: dict[int, int],
) -> float:
    """
    Fraction of nodes that have at least one partner in a different community.
    """
    n = len(active_ids)
    bridge_count = 0
    for i, nid in enumerate(active_ids):
        nid_int = int(nid)
        my_comm = membership[i]
        for pid in partners[nid_int]:
            if pid in id_map and membership[id_map[pid]] != my_comm:
                bridge_count += 1
                break
    return bridge_count / max(n, 1)


# ---------------------------------------------------------------------------
# Section printers
# ---------------------------------------------------------------------------

SECTION_SEP = "=" * 72


def _print_community_table(
    comm_stats: list[dict],
    top_n: int = 20,
) -> None:
    header = (
        f"{'Comm':>5} {'Size':>6}  "
        f"{'Reliable':>9} {'Weekend':>9} {'Seasonal':>9} "
        f"{'Nomad':>7} {'Hoarder':>8} {'Freeload':>9} {'HAR':>6}  "
        f"{'HoardFrac':>10} {'Cross%':>7} {'Isolated':>9}"
    )
    print(header)
    print("-" * len(header))

    for row in comm_stats[:top_n]:
        if row["size"] < 5:
            continue
        ac = row["arch_counts"]
        sz = row["size"]
        fracs = [ac[i] / sz * 100 for i in range(N_ARCHETYPES)]
        cross_pct = row["cross_frac"] * 100
        hf = row["hoard_frac"] * 100
        iso = "YES" if row["isolated"] else "no"
        print(
            f"{row['comm']:>5} {sz:>6}  "
            f"{fracs[0]:>8.1f}% {fracs[1]:>8.1f}% {fracs[2]:>8.1f}% "
            f"{fracs[3]:>6.1f}% {fracs[4]:>7.1f}% {fracs[5]:>8.1f}% {fracs[6]:>5.1f}%  "
            f"{hf:>9.1f}% {cross_pct:>6.1f}% {iso:>9}"
        )


def _print_federation_summary(
    active_ids: np.ndarray,
    comm_stats: list[dict],
    modularity: float,
    bridge_frac: float,
) -> None:
    large = [s for s in comm_stats if s["size"] >= 5]
    sizes = np.array([s["size"] for s in large], dtype=np.float64)
    mean_sz = float(sizes.mean()) if len(sizes) else 0.0
    std_sz = float(sizes.std()) if len(sizes) else 0.0

    # Overall cross-cluster edge fraction
    total_cross = sum(s["cross_edges"] for s in large)
    total_edges = sum(s["total_edges"] for s in comm_stats)
    cross_overall = total_cross / max(total_edges, 1)

    isolated_count = sum(1 for s in large if s["isolated"])
    pure_count = sum(1 for s in large if s["pure"])

    print(f"Total active nodes:              {len(active_ids):>8,}")
    print(f"Communities (size >= 5):         {len(large):>8,}")
    print(f"Modularity Q:                    {modularity:>8.4f}")
    print(f"Mean community size:             {mean_sz:>8.1f} +/- {std_sz:.1f}")
    print(f"Cross-cluster edge fraction:     {cross_overall*100:>7.2f}%")
    print(f"Bridge nodes (>= 1 cross edge):  {bridge_frac*100:>7.2f}%")
    print(f"Isolated communities:            {isolated_count:>8,}")
    print(f"Pure (>80% one archetype):       {pure_count:>8,}")


def _print_trust_distribution(
    active_ids: np.ndarray,
    archetype: np.ndarray,
    p_val: np.ndarray,
    i_val: np.ndarray,
    partners: list[set[int]],
    alive: np.ndarray,
) -> None:
    # Build alive set for quick lookup
    alive_set = set(int(x) for x in active_ids)

    mean_trusts: list[float] = []
    for target_arch in range(N_HONEST_ARCHETYPES):
        target_nodes = active_ids[archetype[active_ids] == target_arch]
        t_sum = 0.0
        count = 0
        for b_raw in target_nodes:
            b = int(b_raw)
            for a in partners[b]:
                if a not in alive_set:
                    continue
                s_ab = float(np.clip(
                    STORAGE_RATIOS[target_arch] / max(float(STORAGE_RATIOS[archetype[a]]), _S_EPS),
                    S_CLAMP_MIN, S_CLAMP_MAX,
                ))
                t = float(_trust(
                    np.array([p_val[b]]),
                    np.array([i_val[b]]),
                    np.array([s_ab]),
                )[0])
                t_sum += t
                count += 1
        mean_trusts.append(t_sum / max(count, 1))

    sorted_idx = np.argsort(-np.array(mean_trusts))
    ranks = np.empty(N_HONEST_ARCHETYPES, dtype=int)
    for rank, idx in enumerate(sorted_idx):
        ranks[idx] = rank + 1

    print(f"{'Archetype':<14} {'MeanTrust':>10} {'Rank':>5} {'Expected':>9}")
    print("-" * 45)
    for i in range(N_HONEST_ARCHETYPES):
        print(
            f"{ARCHETYPE_NAMES[i]:<14} {mean_trusts[i]:>10.4f} "
            f"{ranks[i]:>5} {USEFULNESS_RANK[i]:>9}"
        )

    tau_val, p_val_tau = kendalltau(mean_trusts, [-r for r in USEFULNESS_RANK])
    print(f"\nKendall tau (observed vs expected rank): {tau_val:.4f}  (p={p_val_tau:.4f})")


def _print_partner_diversity(
    active_ids: np.ndarray,
    archetype: np.ndarray,
    join_week: np.ndarray,
    partners: list[set[int]],
    membership: np.ndarray,
    id_map: dict[int, int],
    rng: np.random.Generator,
    sample_size: int = 200,
) -> None:
    # Restrict to honest nodes with enough partners
    honest_mask = archetype[active_ids] < N_HONEST_ARCHETYPES
    honest_ids = active_ids[honest_mask]
    honest_ids = honest_ids[[len(partners[int(n)]) >= 2 for n in honest_ids]]

    if len(honest_ids) == 0:
        print("No honest nodes with partners found.")
        return

    n_sample = min(sample_size, len(honest_ids))
    sampled = rng.choice(honest_ids, size=n_sample, replace=False)

    unique_types_list: list[int] = []
    same_arch_fracs: list[float] = []
    cross_comm_fracs: list[float] = []
    cohort_spreads: list[float] = []

    for nid_raw in sampled:
        nid = int(nid_raw)
        my_arch = int(archetype[nid])
        my_comm = membership[id_map[nid]]
        my_cohort = int(join_week[nid])

        part_list = [p for p in partners[nid] if p in id_map]
        if not part_list:
            continue

        part_arr = np.array(part_list, dtype=np.int32)
        part_archs = archetype[part_arr]
        unique_types_list.append(int(np.unique(part_archs).size))

        same_arch = float((part_archs == my_arch).sum()) / len(part_arr)
        same_arch_fracs.append(same_arch)

        cross_comm = float(
            sum(1 for p in part_list if membership[id_map[p]] != my_comm)
        ) / len(part_arr)
        cross_comm_fracs.append(cross_comm)

        cohort_diffs = np.abs(join_week[part_arr] - my_cohort)
        cohort_spreads.append(float(cohort_diffs.mean()))

    if not unique_types_list:
        print("Insufficient data for diversity analysis.")
        return

    ut = np.array(unique_types_list)
    sa = np.array(same_arch_fracs)
    cc = np.array(cross_comm_fracs)
    cs = np.array(cohort_spreads)

    print(f"Sampled {len(ut)} honest nodes")
    print(
        f"  Unique archetype types among partners: "
        f"mean={ut.mean():.2f}, min={ut.min()}, max={ut.max()}"
    )
    print(f"  Same-archetype partner fraction:       mean={sa.mean():.3f}, std={sa.std():.3f}")
    print(f"  Cross-community partner fraction:      mean={cc.mean():.3f}, std={cc.std():.3f}")
    print(f"  Cohort spread (mean |join_week diff|): mean={cs.mean():.1f} weeks")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cluster/federation analysis of the FINAL Viaticum trust model."
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--years", type=int, default=10)
    parser.add_argument("--nodes", type=int, default=5000)
    parser.add_argument("--partners", type=int, default=50)
    parser.add_argument("--churn", type=float, default=0.20)
    args = parser.parse_args()

    print(SECTION_SEP)
    print("cluster_probe_v2 — FINAL model cluster analysis")
    print(SECTION_SEP)
    print(f"seed={args.seed}  years={args.years}  nodes={args.nodes}  "
          f"partners={args.partners}  annual_churn={args.churn:.0%}")
    print()

    t_start = time.time()

    active_ids, archetype, join_week, p_val, i_val, partners = run_simulation(
        seed=args.seed,
        n_years=args.years,
        max_nodes=args.nodes,
        target_partners=args.partners,
        annual_churn=args.churn,
        archetype_probs=ARCHETYPE_PROBS_DEFAULT,
    )

    print(f"\nSimulation done in {time.time() - t_start:.1f}s")
    print(f"Active nodes at end: {len(active_ids):,}")

    # Alive array for trust distribution analysis
    alive = np.zeros(archetype.shape[0], dtype=bool)
    alive[active_ids] = True

    # --- Build graph ---
    print("\nBuilding partnership graph...")
    g, id_map, _ = _build_graph(active_ids, partners)
    print(f"Vertices: {g.vcount():,}   Edges: {g.ecount():,}")

    # --- Community detection ---
    print("Running Leiden community detection...")
    t_leiden = time.time()
    partition = leidenalg.find_partition(g, leidenalg.ModularityVertexPartition)
    membership = np.array(partition.membership, dtype=np.int32)
    print(f"Leiden done in {time.time() - t_leiden:.2f}s")

    all_sizes = np.bincount(membership)
    large_comms = int((all_sizes >= 5).sum())
    tiny_comms = int((all_sizes < 5).sum())

    print()
    print(SECTION_SEP)
    print("SECTION 1 — Community detection")
    print(SECTION_SEP)
    print(f"Total communities:              {len(partition):>8,}")
    print(f"Communities (size >= 5):        {large_comms:>8,}")
    print(f"Singleton/tiny (size < 5):      {tiny_comms:>8,}")
    print(f"Modularity Q:                   {partition.modularity:>8.4f}")

    # --- Per-community archetype composition ---
    comm_stats = _community_stats(membership, active_ids, archetype, partners, id_map)

    print()
    print(SECTION_SEP)
    print("SECTION 2 — Per-community archetype composition (top 20 by size)")
    print(SECTION_SEP)
    _print_community_table(comm_stats, top_n=20)

    # --- Isolation analysis ---
    print()
    print(SECTION_SEP)
    print("SECTION 3 — Isolation analysis")
    print(SECTION_SEP)
    large = [s for s in comm_stats if s["size"] >= 5]
    isolated = [s for s in large if s["isolated"]]
    pure = [s for s in large if s["pure"]]

    if isolated:
        print(f"ISOLATED communities ({len(isolated)} total — 0% cross-cluster edges):")
        for s in isolated:
            ac = s["arch_counts"]
            sz = s["size"]
            top_arch = max(range(N_ARCHETYPES), key=lambda i: ac[i])
            print(
                f"  comm={s['comm']:>4}  size={sz:>5}  "
                f"dominant={ARCHETYPE_NAMES[top_arch]} ({ac[top_arch]/sz*100:.1f}%)"
            )
    else:
        print("No isolated communities (all have >= 1 cross-cluster edge).")

    if pure:
        print(f"\nPURE communities >80% one archetype ({len(pure)} total):")
        for s in pure:
            ac = s["arch_counts"]
            sz = s["size"]
            top_arch = max(range(N_ARCHETYPES), key=lambda i: ac[i])
            print(
                f"  comm={s['comm']:>4}  size={sz:>5}  "
                f"dominant={ARCHETYPE_NAMES[top_arch]} ({ac[top_arch]/sz*100:.1f}%)"
            )
    else:
        print("\nNo pure communities (none exceed 80% one archetype).")

    # Cross-cluster edge fractions for large communities
    print()
    print(f"Cross-cluster edge fraction per community (top 10 by size):")
    print(f"{'Comm':>5} {'Size':>6} {'CrossEdges':>11} {'TotalEdges':>11} {'CrossFrac':>10}")
    print("-" * 50)
    for s in large[:10]:
        print(
            f"{s['comm']:>5} {s['size']:>6} {s['cross_edges']:>11,} "
            f"{s['total_edges']:>11,} {s['cross_frac']*100:>9.2f}%"
        )

    # --- Federation summary ---
    bridge_frac = _bridge_fraction(membership, active_ids, partners, id_map)

    print()
    print(SECTION_SEP)
    print("SECTION 4 — Federation summary")
    print(SECTION_SEP)
    _print_federation_summary(active_ids, comm_stats, partition.modularity, bridge_frac)

    # --- Trust distribution by archetype ---
    print()
    print(SECTION_SEP)
    print("SECTION 5 — Trust distribution by archetype (incoming, honest nodes only)")
    print(SECTION_SEP)
    _print_trust_distribution(active_ids, archetype, p_val, i_val, partners, alive)

    # --- Partner diversity ---
    diversity_rng = np.random.default_rng(args.seed + 9999)
    print()
    print(SECTION_SEP)
    print("SECTION 6 — Partner diversity (200 sampled honest nodes)")
    print(SECTION_SEP)
    _print_partner_diversity(
        active_ids, archetype, join_week,
        partners, membership, id_map,
        diversity_rng, sample_size=200,
    )

    print()
    print(SECTION_SEP)
    print(f"Total runtime: {time.time() - t_start:.1f}s")
    print(SECTION_SEP)


if __name__ == "__main__":
    main()
