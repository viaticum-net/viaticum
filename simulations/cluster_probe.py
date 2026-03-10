"""
Quick probe: run Exp 17 once and print per-community archetype composition.
Goal: understand if isolated clusters are pure hoarder/freeloader or trap honest nodes.
"""
from __future__ import annotations
import numpy as np
from pis_longterm import (
    Config, ARCHETYPE_NAMES, ARCHETYPE_PROBS, STORAGE_RATIOS,
    N_ARCHETYPES, _weekly_churn_prob, _new_nodes_this_week,
    _build_weekly_pass_probs, _update_partnerships, _S_EPS,
)

try:
    import igraph as ig
    import leidenalg
except ImportError:
    print("ERROR: igraph and leidenalg required")
    exit(1)


def run_probe(seed: int = 42, n_years: int = 10) -> None:
    cfg = Config(kp=0.5, ki=2.0, ks=1.0, n_years=n_years)
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
    partners: list[set[int]] = [set() for _ in range(cap)]

    arch_probs = list(cfg.archetype_probs)
    weekly_pass_probs = _build_weekly_pass_probs(n_weeks)

    next_id = [0]
    free_ids: list[int] = []

    def _alloc():
        if free_ids:
            return free_ids.pop()
        if next_id[0] < cap:
            nid = next_id[0]
            next_id[0] += 1
            return nid
        return None

    def _add(nid, week):
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

    def _remove(nid):
        alive[nid] = False
        for pid in partners[nid]:
            partners[pid].discard(nid)
        partners[nid].clear()
        free_ids.append(nid)

    # Bootstrap
    for _ in range(cfg.initial_peers):
        nid = _alloc()
        if nid is not None:
            _add(nid, 0)

    weekly_churn = _weekly_churn_prob(cfg)

    print(f"Running {n_years} years ({n_weeks} weeks)...")

    for week in range(n_weeks):
        # Growth
        n_active = int(alive.sum())
        if n_active < cfg.max_active_peers:
            n_new = min(_new_nodes_this_week(week), cfg.max_active_peers - n_active)
            for _ in range(n_new):
                nid = _alloc()
                if nid is None:
                    break
                _add(nid, week)

        # Churn
        active_ids = np.where(alive)[0]
        if active_ids.size > 0:
            churn_mask = rng.random(active_ids.size) < weekly_churn
            for nid in active_ids[churn_mask]:
                _remove(int(nid))

        # Weekly checks
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

        # Update P buffer
        pos = p_buf_pos[active_ids]
        p_buf[active_ids, pos] = week_scores
        p_buf_pos[active_ids] = (pos + 1) % pw
        filled = p_buf_filled[active_ids]
        p_buf_filled[active_ids] = np.minimum(filled + 1, pw)

        # Update I
        i_sum[active_ids] += week_scores
        i_count[active_ids] += 1

        # Compute P and I arrays
        p_buf_sum = p_buf[active_ids, :].sum(axis=1)
        pf = p_buf_filled[active_ids].astype(np.float64)
        p_val_arr[active_ids] = np.where(pf > 0, p_buf_sum / pf, 0.0)
        ic = i_count[active_ids].astype(np.float64)
        i_val_arr[active_ids] = np.where(ic > 0, i_sum[active_ids] / ic, 0.0)

        # Partnerships
        _update_partnerships(
            active_ids, alive, archetype,
            i_val_arr, p_val_arr, partners, cfg, rng,
        )

    # --- Analysis ---
    active_ids = np.where(alive)[0]
    print(f"\nActive nodes: {active_ids.size}")

    # Build graph
    id_map = {int(nid): i for i, nid in enumerate(active_ids)}
    edges = []
    for nid in active_ids:
        for pid in partners[int(nid)]:
            if pid in id_map and int(nid) < pid:
                edges.append((id_map[int(nid)], id_map[pid]))

    print(f"Edges: {len(edges)}")

    g = ig.Graph(n=len(active_ids), edges=edges)
    partition = leidenalg.find_partition(g, leidenalg.ModularityVertexPartition)
    membership = np.array(partition.membership)

    print(f"Communities: {len(partition)}, Modularity: {partition.modularity:.3f}")

    # Per-community archetype composition
    n_comm = len(partition)
    print(f"\n{'Comm':>5} {'Size':>6}  ", end="")
    for name in ARCHETYPE_NAMES:
        print(f"{name[:8]:>9}", end="")
    print(f"  {'HoardFrac':>9} {'Isolated':>8}")
    print("-" * 95)

    community_sizes = []
    for c in range(n_comm):
        members = np.where(membership == c)[0]
        size = len(members)
        if size < 5:
            continue
        community_sizes.append((c, size))

    # Sort by size descending
    community_sizes.sort(key=lambda x: -x[1])

    for c, size in community_sizes:
        members = np.where(membership == c)[0]
        member_nids = active_ids[members]
        arch_of_members = archetype[member_nids]

        counts = {}
        for idx, name in enumerate(ARCHETYPE_NAMES):
            counts[name] = int((arch_of_members == idx).sum())

        # Check if isolated (no cross-cluster edges)
        has_cross = False
        for m in members:
            nid = int(active_ids[m])
            for pid in partners[nid]:
                if pid in id_map and membership[id_map[pid]] != c:
                    has_cross = True
                    break
            if has_cross:
                break

        hoard_free_frac = (counts.get("Hoarder", 0) + counts.get("Freeloader", 0)) / size

        print(f"{c:>5} {size:>6}  ", end="")
        for name in ARCHETYPE_NAMES:
            frac = counts[name] / size * 100
            print(f"{frac:>8.1f}%", end="")
        print(f"  {hoard_free_frac*100:>8.1f}% {'YES' if not has_cross else 'no':>8}")

    # Summary: trust from honest nodes only
    print("\n=== TRUST FROM HONEST NODES ONLY ===")
    print(f"{'Archetype':<16} {'AllPartners':>12} {'HonestOnly':>12} {'Rank_all':>9} {'Rank_hon':>9}")
    print("-" * 62)

    for target_arch in range(N_ARCHETYPES):
        target_nodes = active_ids[archetype[active_ids] == target_arch]
        trust_all_sum, count_all = 0.0, 0
        trust_hon_sum, count_hon = 0.0, 0

        for b in target_nodes:
            b = int(b)
            for a in partners[b]:
                if not alive[a]:
                    continue
                r_a = STORAGE_RATIOS[archetype[a]]
                r_b = STORAGE_RATIOS[target_arch]
                s_ab = min(r_b / max(r_a, _S_EPS), 2.0)
                t = cfg.kp * p_val_arr[b] + cfg.ki * i_val_arr[b] + cfg.ks * s_ab
                trust_all_sum += t
                count_all += 1
                # Honest = archetype 0-3 (Reliable, Weekend, Seasonal, Nomad)
                if archetype[a] < 4:
                    trust_hon_sum += t
                    count_hon += 1

        t_all = trust_all_sum / max(count_all, 1)
        t_hon = trust_hon_sum / max(count_hon, 1)
        print(f"{ARCHETYPE_NAMES[target_arch]:<16} {t_all:>12.3f} {t_hon:>12.3f}")

    # Compute ranks
    all_trusts = []
    hon_trusts = []
    for target_arch in range(N_ARCHETYPES):
        target_nodes = active_ids[archetype[active_ids] == target_arch]
        t_a_sum, c_a = 0.0, 0
        t_h_sum, c_h = 0.0, 0
        for b in target_nodes:
            b = int(b)
            for a in partners[b]:
                if not alive[a]:
                    continue
                r_a = STORAGE_RATIOS[archetype[a]]
                r_b = STORAGE_RATIOS[target_arch]
                s_ab = min(r_b / max(r_a, _S_EPS), 2.0)
                t = cfg.kp * p_val_arr[b] + cfg.ki * i_val_arr[b] + cfg.ks * s_ab
                t_a_sum += t
                c_a += 1
                if archetype[a] < 4:
                    t_h_sum += t
                    c_h += 1
        all_trusts.append(t_a_sum / max(c_a, 1))
        hon_trusts.append(t_h_sum / max(c_h, 1))

    all_ranks = np.argsort(-np.array(all_trusts)) + 1
    hon_ranks = np.argsort(-np.array(hon_trusts)) + 1

    print(f"\n{'Archetype':<16} {'Expected':>8} {'Rank_all':>9} {'Rank_hon':>9}")
    print("-" * 46)
    expected = [1, 2, 3, 4, 5, 6]
    for i, name in enumerate(ARCHETYPE_NAMES):
        # rank = position in sorted order
        rank_all = int(np.where(np.argsort(-np.array(all_trusts)) == i)[0][0]) + 1
        rank_hon = int(np.where(np.argsort(-np.array(hon_trusts)) == i)[0][0]) + 1
        print(f"{name:<16} {expected[i]:>8} {rank_all:>9} {rank_hon:>9}")

    from scipy.stats import kendalltau
    tau_all, _ = kendalltau(all_trusts, [-r for r in expected])
    tau_hon, _ = kendalltau(hon_trusts, [-r for r in expected])
    print(f"\nKendall tau (all partners):    {tau_all:.3f}")
    print(f"Kendall tau (honest partners): {tau_hon:.3f}")


if __name__ == "__main__":
    run_probe()
