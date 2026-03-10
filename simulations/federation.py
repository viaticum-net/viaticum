"""
SyncBack Simulation #9: Automatic Federation Emergence in P2P Backup

Hypothesis: "nobody trusts us, let's be friends" — new peers are forced to partner
with other newcomers because established peers reject low-trust partners. This
creates natural geographic diversity: newcomer clusters form across many regions,
and over time these clusters graduate into established, trusted groups.

Model:
- Peers join over time from one of n_regions geographic clusters
- Seed peers start from 2-3 regions (concentrated bootstrap)
- Trust score follows PI formula from experiment 01:
    trust = 0.5 * P_30d + 2.0 * I_cumulative
  where P_30d is the 30-day rolling proof-of-storage pass rate and
  I_cumulative is the all-time average pass rate for a given (requester, host) pair
- When a peer places shards it sorts candidates by trust descending; established
  peers gate on trust_acceptance_threshold and reject low-trust requesters
- New peers fall back to whichever peers actually accept them — which are other
  newcomers, spread across many regions

Key metrics:
- Geographic diversity: distinct regions holding shards per peer (want high)
- Cross-region edges: fraction of (peer, host) relationships crossing regions
- Cluster coefficient: local clustering in the trust graph
- Average path length: small-world property of trust graph
- Timeline: how diversity and topology evolve month by month

Usage:
    python federation.py                    # default run
    python federation.py --sweep --jobs 24  # sweep acceptance thresholds
"""

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
    n_regions: int = 10
    seed_peers: int = 20             # peers present at day 0
    seed_regions: int = 3            # seed peers come from this many regions
    new_peers_per_month: int = 20    # peers joining each month
    n_months: int = 24               # simulation length
    n_shards: int = 15               # shards placed per file, per peer
    # PI trust formula weights (from experiment 01 optimal: Kp=0.5, Ki=2.0)
    kp: float = 0.5
    ki: float = 2.0
    p_window: int = 30               # days for rolling P score
    # Peer reliability (proof-of-storage pass probability)
    peer_reliability: float = 0.95
    # Acceptance gate: a host rejects a requester whose trust score is below this
    trust_acceptance_threshold: float = 0.3
    # Monte Carlo
    n_seeds: int = 50


# ---------------------------------------------------------------------------
# Trust helpers
# ---------------------------------------------------------------------------

def _compute_trust(p30: float, i_cum: float, kp: float, ki: float) -> float:
    """PI trust formula: kp * P_30d + ki * I_cumulative."""
    return kp * p30 + ki * i_cum


def _build_initial_trust(
    n_peers: int,
    join_ages_days: np.ndarray,
    config: Config,
    rng: np.random.Generator,
) -> np.ndarray:
    """Simulate proof-of-storage checks for each peer over its lifetime to date.

    Returns trust[i] = trust score of peer i as seen by the network average.
    Peers are independent here (no pairwise tracking — we use a single network-
    wide score per peer to keep complexity tractable for the placement step).
    """
    trust = np.zeros(n_peers)

    for i in range(n_peers):
        age = int(join_ages_days[i])
        if age == 0:
            # Brand new — zero track record
            trust[i] = 0.0
            continue

        # Simulate age days of daily checks with peer_reliability
        checks = (rng.random(age) < config.peer_reliability).astype(np.float64)

        # I: cumulative average
        i_cum = checks.mean()

        # P: rolling 30-day window (or all days if younger)
        window = min(age, config.p_window)
        p30 = checks[-window:].mean()

        trust[i] = _compute_trust(p30, i_cum, config.kp, config.ki)

    return trust


# ---------------------------------------------------------------------------
# Core simulation
# ---------------------------------------------------------------------------

def simulate_one(config: Config, seed: int) -> dict:
    """Run one federation emergence simulation.

    Returns a dict of scalar metrics and per-month trajectories.
    """
    rng = np.random.default_rng(seed)

    days_per_month = 30
    total_peers_max = (
        config.seed_peers
        + config.new_peers_per_month * config.n_months
    )

    # --- Peer registry ---
    # peer_region[i]: region id in [0, n_regions)
    # peer_join_day[i]: day peer joined the simulation
    peer_region = np.empty(total_peers_max, dtype=np.int32)
    peer_join_day = np.empty(total_peers_max, dtype=np.int32)

    # Seed peers: distributed across seed_regions (2-3 concentrated regions)
    seed_region_ids = rng.choice(config.n_regions, size=config.seed_regions, replace=False)
    peer_region[:config.seed_peers] = rng.choice(seed_region_ids, size=config.seed_peers)
    peer_join_day[:config.seed_peers] = 0

    n_peers = config.seed_peers  # grows as new peers join

    # shard_holders[i] = list of peer ids that hold shards for peer i's file
    # We model each peer as having exactly one file.
    shard_holders: list[list[int]] = [[] for _ in range(total_peers_max)]

    # Pairwise observation counts: used to compute per-pair PI trust.
    # For scalability we track trust from the perspective of the requester:
    # obs_checks[requester][host] tracks successful checks requester has seen
    # from host. We represent this as two dicts of arrays updated monthly.
    #
    # Implementation choice: because we simulate monthly and the network grows
    # to ~500 peers, we maintain a dense n_peers x n_peers matrix for P and I
    # scores. We resize lazily. At each month we update checks for existing
    # shard-holding relationships only (sparse update), then recompute scores.
    #
    # For the acceptance gate we use a simpler approximation: a peer's trust
    # score from the requester's POV equals the network-wide trust score for
    # that host (all requesters see the same global score). This is realistic
    # for a public proof-of-storage ledger.

    # Global trust score per peer (updated monthly)
    peer_trust = np.zeros(total_peers_max)

    # Rolling window buffer for P: shape (p_window, total_peers_max)
    window_buf = np.zeros((config.p_window, total_peers_max))
    # Cumulative I score
    i_score = np.zeros(total_peers_max)
    # Day counter per peer (for weighted cumulative average)
    peer_days_observed = np.zeros(total_peers_max, dtype=np.int64)

    # --- Monthly trajectory metrics ---
    traj_month: list[int] = []
    traj_n_peers: list[int] = []
    traj_geo_diversity_mean: list[float] = []    # mean distinct regions per peer
    traj_geo_diversity_p25: list[float] = []
    traj_cross_region_frac: list[float] = []    # fraction of edges crossing regions
    traj_cluster_coeff: list[float] = []        # clustering coefficient of trust graph
    traj_avg_path_len: list[float] = []         # avg shortest path (sampled)

    # --- Main simulation loop (monthly ticks) ---
    for month in range(config.n_months):
        current_day = month * days_per_month

        # 1. New peers join this month (except month 0 where seeds are already in)
        if month > 0:
            for _ in range(config.new_peers_per_month):
                if n_peers >= total_peers_max:
                    break
                pid = n_peers
                peer_region[pid] = rng.integers(0, config.n_regions)
                peer_join_day[pid] = current_day
                n_peers += 1

        # 2. Simulate daily proof-of-storage checks for this month
        #    for all peers that have been active (joined before this month)
        for day_offset in range(days_per_month):
            day = current_day + day_offset
            active_mask = peer_join_day[:n_peers] <= current_day

            # Draw checks for all active peers
            checks = np.where(
                active_mask,
                (rng.random(n_peers) < config.peer_reliability).astype(np.float64),
                0.0,
            )

            # Update rolling P window
            slot = day % config.p_window
            window_buf[slot, :n_peers] = checks

            # Update cumulative I (weighted average with day count)
            t = peer_days_observed[:n_peers]
            i_score[:n_peers] = (i_score[:n_peers] * t + checks) / np.maximum(t + 1, 1)
            peer_days_observed[:n_peers] += active_mask.astype(np.int64)

        # Recompute P30 from window buffer
        # For each peer, average across filled slots
        for i in range(n_peers):
            age_days = int(peer_days_observed[i])
            if age_days == 0:
                peer_trust[i] = 0.0
                continue
            filled = min(age_days, config.p_window)
            # Most recent `filled` slots
            p30 = window_buf[:filled, i].mean()
            peer_trust[i] = _compute_trust(p30, i_score[i], config.kp, config.ki)

        # 3. Each peer tries to (re-)place shards for its file.
        #    Peers with already-placed shards skip (cold backup: files are stable).
        #    New joiners this month attempt placement.
        new_this_month_start = max(0, n_peers - config.new_peers_per_month) if month > 0 else 0
        placers = list(range(new_this_month_start if month > 0 else 0, n_peers))

        for requester in placers:
            if shard_holders[requester]:
                # Already placed — skip
                continue

            req_trust = peer_trust[requester]

            # Build candidate list: all other active peers except self
            candidates = [
                pid for pid in range(n_peers)
                if pid != requester
            ]

            if not candidates:
                continue

            # Sort candidates by trust descending (prefer most trusted hosts)
            candidates.sort(key=lambda pid: -peer_trust[pid])

            # Each candidate accepts iff requester trust >= threshold.
            # Established peers (high trust) prefer high-trust requesters;
            # newer peers have lower thresholds effectively (their own trust is
            # low, so they are more willing to accept peers of similar standing).
            #
            # Implementation: a host accepts if req_trust >= threshold OR
            # host's own trust is also low (both newcomers).
            accepted: list[int] = []
            for host in candidates:
                host_trust = peer_trust[host]
                # Newcomer hosts (trust < threshold) accept anyone
                if host_trust < config.trust_acceptance_threshold:
                    accepted.append(host)
                # Established hosts gate on requester trust
                elif req_trust >= config.trust_acceptance_threshold:
                    accepted.append(host)
                # else: established host rejects low-trust requester
                if len(accepted) >= config.n_shards:
                    break

            # Place shards on accepted peers (up to n_shards)
            shard_holders[requester] = accepted[:config.n_shards]

        # 4. Compute monthly metrics for peers that have placed shards
        placed_peers = [i for i in range(n_peers) if shard_holders[i]]

        if placed_peers:
            # Geographic diversity: distinct regions among shard holders
            diversities = []
            cross_edges = 0
            total_edges = 0
            for p in placed_peers:
                holders = shard_holders[p]
                if not holders:
                    continue
                holder_regions = peer_region[holders]
                n_distinct = len(set(holder_regions.tolist()))
                diversities.append(n_distinct)
                # Cross-region edges
                req_region = int(peer_region[p])
                for hr in holder_regions:
                    total_edges += 1
                    if int(hr) != req_region:
                        cross_edges += 1

            geo_div_mean = float(np.mean(diversities)) if diversities else 0.0
            geo_div_p25 = float(np.percentile(diversities, 25)) if diversities else 0.0
            cross_frac = cross_edges / total_edges if total_edges > 0 else 0.0

            # Trust graph topology: nodes are placed_peers, edges exist when
            # peer A holds shards for peer B (directed → symmetric adjacency
            # for clustering). We use the mutual relationship for undirected
            # clustering coefficient computation.
            cc, apl = _compute_graph_metrics(
                placed_peers, shard_holders, n_peers, rng
            )
        else:
            geo_div_mean = 0.0
            geo_div_p25 = 0.0
            cross_frac = 0.0
            cc = 0.0
            apl = 0.0

        traj_month.append(month + 1)
        traj_n_peers.append(n_peers)
        traj_geo_diversity_mean.append(geo_div_mean)
        traj_geo_diversity_p25.append(geo_div_p25)
        traj_cross_region_frac.append(cross_frac)
        traj_cluster_coeff.append(cc)
        traj_avg_path_len.append(apl)

    # --- Final scalar summaries ---
    final_placed = [i for i in range(n_peers) if shard_holders[i]]
    final_diversities = []
    for p in final_placed:
        holders = shard_holders[p]
        if holders:
            holder_regions = peer_region[holders]
            final_diversities.append(len(set(holder_regions.tolist())))

    return {
        # Scalar summaries
        "final_n_peers": n_peers,
        "final_geo_diversity_mean": float(np.mean(final_diversities)) if final_diversities else 0.0,
        "final_geo_diversity_p25": float(np.percentile(final_diversities, 25)) if final_diversities else 0.0,
        "final_cross_region_frac": traj_cross_region_frac[-1] if traj_cross_region_frac else 0.0,
        "final_cluster_coeff": traj_cluster_coeff[-1] if traj_cluster_coeff else 0.0,
        "final_avg_path_len": traj_avg_path_len[-1] if traj_avg_path_len else 0.0,
        # Monthly trajectories
        "traj_month": traj_month,
        "traj_n_peers": traj_n_peers,
        "traj_geo_diversity_mean": traj_geo_diversity_mean,
        "traj_geo_diversity_p25": traj_geo_diversity_p25,
        "traj_cross_region_frac": traj_cross_region_frac,
        "traj_cluster_coeff": traj_cluster_coeff,
        "traj_avg_path_len": traj_avg_path_len,
    }


def _compute_graph_metrics(
    active_nodes: list[int],
    shard_holders: list[list[int]],
    n_peers: int,
    rng: np.random.Generator,
) -> tuple[float, float]:
    """Compute clustering coefficient and average path length of the trust graph.

    Nodes: active_nodes (peers with placed shards).
    Edges: undirected — edge (u, v) exists if u holds shards for v OR v holds
    shards for u (mutual exposure creates trust relationship).

    Returns (clustering_coefficient, avg_path_length).
    Avg path length is estimated from a sample of 50 source nodes for speed.
    """
    if len(active_nodes) < 3:
        return 0.0, 0.0

    # Map global peer ids to local indices for matrix ops
    node_set = set(active_nodes)
    local_idx = {pid: i for i, pid in enumerate(active_nodes)}
    n = len(active_nodes)

    # Build adjacency as a set of edges
    adj: list[set[int]] = [set() for _ in range(n)]
    for pid in active_nodes:
        for host in shard_holders[pid]:
            if host in node_set:
                u = local_idx[pid]
                v = local_idx[host]
                adj[u].add(v)
                adj[v].add(u)

    # Clustering coefficient: for each node count triangles / possible triangles
    cc_values = []
    for i in range(n):
        neighbors = list(adj[i])
        k = len(neighbors)
        if k < 2:
            cc_values.append(0.0)
            continue
        # Count edges among neighbors
        edges_among = 0
        for a in range(len(neighbors)):
            for b in range(a + 1, len(neighbors)):
                if neighbors[b] in adj[neighbors[a]]:
                    edges_among += 1
        possible = k * (k - 1) / 2
        cc_values.append(edges_among / possible)
    cc = float(np.mean(cc_values))

    # Average path length: BFS from a sample of source nodes
    sample_size = min(50, n)
    sample_nodes = rng.choice(n, size=sample_size, replace=False)
    path_lengths: list[int] = []

    for src in sample_nodes:
        dist = [-1] * n
        dist[src] = 0
        queue = [src]
        head = 0
        while head < len(queue):
            cur = queue[head]
            head += 1
            for nb in adj[cur]:
                if dist[nb] == -1:
                    dist[nb] = dist[cur] + 1
                    queue.append(nb)
        # Collect distances to reachable nodes (exclude self and unreachable)
        for d in dist:
            if d > 0:
                path_lengths.append(d)

    apl = float(np.mean(path_lengths)) if path_lengths else 0.0
    return cc, apl


# ---------------------------------------------------------------------------
# Monte Carlo aggregation
# ---------------------------------------------------------------------------

def run_experiment(config: Config, n_jobs: int = 1) -> dict:
    """Run Monte Carlo experiment across seeds."""
    t0 = time.time()

    if n_jobs == 1:
        results = [
            simulate_one(config, seed) for seed in range(config.n_seeds)
        ]
    else:
        results = Parallel(n_jobs=n_jobs)(
            delayed(simulate_one)(config, seed)
            for seed in range(config.n_seeds)
        )

    elapsed = time.time() - t0

    # Aggregate scalar finals
    geo_divs = [r["final_geo_diversity_mean"] for r in results]
    cross_fracs = [r["final_cross_region_frac"] for r in results]
    ccs = [r["final_cluster_coeff"] for r in results]
    apls = [r["final_avg_path_len"] for r in results]

    # Aggregate monthly trajectories (element-wise across seeds)
    n_months = len(results[0]["traj_month"])
    traj_keys = [
        "traj_geo_diversity_mean",
        "traj_geo_diversity_p25",
        "traj_cross_region_frac",
        "traj_cluster_coeff",
        "traj_avg_path_len",
        "traj_n_peers",
    ]
    traj_agg: dict[str, dict] = {}
    for key in traj_keys:
        matrix = np.array([r[key] for r in results])  # shape: (n_seeds, n_months)
        traj_agg[key] = {
            "mean": matrix.mean(axis=0).tolist(),
            "std": matrix.std(axis=0).tolist(),
            "p5": np.percentile(matrix, 5, axis=0).tolist(),
            "p95": np.percentile(matrix, 95, axis=0).tolist(),
        }

    return {
        "config": asdict(config),
        "elapsed_sec": elapsed,
        "months": results[0]["traj_month"],
        # Final distribution
        "final_geo_diversity_mean": float(np.mean(geo_divs)),
        "final_geo_diversity_std": float(np.std(geo_divs)),
        "final_geo_diversity_p5": float(np.percentile(geo_divs, 5)),
        "final_geo_diversity_p95": float(np.percentile(geo_divs, 95)),
        "final_cross_region_frac_mean": float(np.mean(cross_fracs)),
        "final_cross_region_frac_p5": float(np.percentile(cross_fracs, 5)),
        "final_cluster_coeff_mean": float(np.mean(ccs)),
        "final_avg_path_len_mean": float(np.mean([a for a in apls if a > 0])) if any(a > 0 for a in apls) else 0.0,
        # Per-month trajectories
        "trajectories": traj_agg,
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_summary(result: dict) -> None:
    """Print key federation metrics in a human-readable format."""
    cfg = result["config"]
    print(
        f"Config: {cfg['seed_peers']} seeds ({cfg['seed_regions']} regions), "
        f"+{cfg['new_peers_per_month']}/month, {cfg['n_months']} months"
    )
    print(
        f"Trust: Kp={cfg['kp']} Ki={cfg['ki']} P_window={cfg['p_window']}d, "
        f"accept_threshold={cfg['trust_acceptance_threshold']}"
    )
    print(
        f"Shards: {cfg['n_shards']} per peer, {cfg['n_regions']} regions, "
        f"{cfg['n_seeds']} Monte Carlo seeds"
    )
    print(f"Runtime: {result['elapsed_sec']:.1f}s")
    print()

    # Monthly snapshots at months 1, 6, 12, 24 (or last)
    months = result["months"]
    geo_mean = result["trajectories"]["traj_geo_diversity_mean"]["mean"]
    cross_mean = result["trajectories"]["traj_cross_region_frac"]["mean"]
    cc_mean = result["trajectories"]["traj_cluster_coeff"]["mean"]
    n_peers_mean = result["trajectories"]["traj_n_peers"]["mean"]

    checkpoints = [1, 6, 12, 18, 24]
    print(f"{'Month':>6} {'Peers':>6} {'GeoDiv':>7} {'CrossReg%':>10} {'ClustCoef':>10}")
    for cp in checkpoints:
        if cp > len(months):
            break
        idx = cp - 1
        print(
            f"{months[idx]:>6} {n_peers_mean[idx]:>6.0f} "
            f"{geo_mean[idx]:>7.2f} {cross_mean[idx]*100:>9.1f}% "
            f"{cc_mean[idx]:>10.3f}"
        )

    print()
    print(f"Final state (month {months[-1]}, mean over {cfg['n_seeds']} seeds):")
    print(
        f"  Geographic diversity: {result['final_geo_diversity_mean']:.2f} regions/peer "
        f"(p5={result['final_geo_diversity_p5']:.1f}, "
        f"p95={result['final_geo_diversity_p95']:.1f}, "
        f"max possible={cfg['n_regions']})"
    )
    print(
        f"  Cross-region shard edges: {result['final_cross_region_frac_mean']*100:.1f}% "
        f"(p5={result['final_cross_region_frac_p5']*100:.1f}%)"
    )
    print(f"  Trust graph clustering coeff: {result['final_cluster_coeff_mean']:.3f}")
    apl = result["final_avg_path_len_mean"]
    print(f"  Trust graph avg path length: {apl:.2f}" if apl > 0 else "  Trust graph avg path length: n/a (disconnected)")


def save_results(result: dict, path: Path) -> None:
    """Save results to JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2))
    print(f"\nResults saved to {path}")


# ---------------------------------------------------------------------------
# Parameter sweep
# ---------------------------------------------------------------------------

def _evaluate_config(threshold: float, seed_regions: int, n_seeds: int, base: Config) -> dict:
    """Evaluate one config point for the sweep."""
    cfg = Config(
        n_regions=base.n_regions,
        seed_peers=base.seed_peers,
        seed_regions=seed_regions,
        new_peers_per_month=base.new_peers_per_month,
        n_months=base.n_months,
        n_shards=base.n_shards,
        kp=base.kp,
        ki=base.ki,
        p_window=base.p_window,
        peer_reliability=base.peer_reliability,
        trust_acceptance_threshold=threshold,
        n_seeds=n_seeds,
    )
    res = run_experiment(cfg, n_jobs=1)
    return {
        "threshold": threshold,
        "seed_regions": seed_regions,
        "final_geo_diversity_mean": res["final_geo_diversity_mean"],
        "final_geo_diversity_p5": res["final_geo_diversity_p5"],
        "final_cross_region_frac_mean": res["final_cross_region_frac_mean"],
        "final_cluster_coeff_mean": res["final_cluster_coeff_mean"],
        "final_avg_path_len_mean": res["final_avg_path_len_mean"],
    }


def run_sweep(base_config: Config, output_dir: Path, n_jobs: int = 1) -> None:
    """Sweep trust_acceptance_threshold and seed_regions."""
    thresholds = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6]
    seed_regions_values = [1, 2, 3, 5]
    sweep_seeds = 20  # fewer seeds for speed

    tasks = []
    for threshold in thresholds:
        for sr in seed_regions_values:
            tasks.append((threshold, sr, sweep_seeds, base_config))

    total = len(tasks)
    print(f"Sweep: {total} configs, {n_jobs} jobs\n")

    if n_jobs == 1:
        results_table = []
        for i, t in enumerate(tasks, 1):
            r = _evaluate_config(*t)
            results_table.append(r)
            print(
                f"  [{i}/{total}] threshold={r['threshold']:.1f} "
                f"seed_regions={r['seed_regions']} "
                f"-> geo_div={r['final_geo_diversity_mean']:.2f} "
                f"cross={r['final_cross_region_frac_mean']*100:.1f}% "
                f"cc={r['final_cluster_coeff_mean']:.3f}"
            )
    else:
        t0 = time.time()
        results_table = Parallel(n_jobs=n_jobs, verbose=10)(
            delayed(_evaluate_config)(*t) for t in tasks
        )
        elapsed = time.time() - t0
        print(f"\nSweep completed in {elapsed:.1f}s")
        for r in results_table:
            print(
                f"  threshold={r['threshold']:.1f} "
                f"seed_regions={r['seed_regions']} "
                f"-> geo_div={r['final_geo_diversity_mean']:.2f} "
                f"cross={r['final_cross_region_frac_mean']*100:.1f}% "
                f"cc={r['final_cluster_coeff_mean']:.3f}"
            )

    # Sort by geographic diversity descending
    results_table.sort(key=lambda r: -r["final_geo_diversity_mean"])

    print("\n=== RESULTS (sorted by geographic diversity) ===")
    print(
        f"{'threshold':>10} {'seed_reg':>9} {'geo_div':>8} "
        f"{'geo_p5':>7} {'cross%':>7} {'cc':>7} {'apl':>6}"
    )
    for r in results_table:
        print(
            f"{r['threshold']:>10.2f} {r['seed_regions']:>9} "
            f"{r['final_geo_diversity_mean']:>8.2f} "
            f"{r['final_geo_diversity_p5']:>7.2f} "
            f"{r['final_cross_region_frac_mean']*100:>6.1f}% "
            f"{r['final_cluster_coeff_mean']:>7.3f} "
            f"{r['final_avg_path_len_mean']:>6.2f}"
        )

    sweep_path = output_dir / "sweep_results.json"
    sweep_path.parent.mkdir(parents=True, exist_ok=True)
    sweep_path.write_text(json.dumps(results_table, indent=2))
    print(f"\nFull sweep saved to {sweep_path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Federation Emergence in P2P Backup Network"
    )
    parser.add_argument("--regions", type=int, default=10, help="Number of geographic regions")
    parser.add_argument("--seed-peers", type=int, default=20, help="Peers at day 0")
    parser.add_argument("--seed-regions", type=int, default=3, help="Regions seed peers come from")
    parser.add_argument("--new-peers-per-month", type=int, default=20)
    parser.add_argument("--months", type=int, default=24, help="Simulation length in months")
    parser.add_argument("--shards", type=int, default=15, help="Shards per peer's file")
    parser.add_argument("--kp", type=float, default=0.5, help="P weight in trust formula")
    parser.add_argument("--ki", type=float, default=2.0, help="I weight in trust formula")
    parser.add_argument("--p-window", type=int, default=30, help="P rolling window in days")
    parser.add_argument("--threshold", type=float, default=0.3,
                        help="Trust acceptance threshold")
    parser.add_argument("--seeds", type=int, default=50, help="Monte Carlo seeds")
    parser.add_argument("--sweep", action="store_true", help="Sweep acceptance thresholds")
    parser.add_argument("--jobs", type=int, default=1, help="Parallel jobs (cores)")
    parser.add_argument("--output", type=str, default="results/federation")
    args = parser.parse_args()

    output_dir = Path(args.output)

    config = Config(
        n_regions=args.regions,
        seed_peers=args.seed_peers,
        seed_regions=args.seed_regions,
        new_peers_per_month=args.new_peers_per_month,
        n_months=args.months,
        n_shards=args.shards,
        kp=args.kp,
        ki=args.ki,
        p_window=args.p_window,
        trust_acceptance_threshold=args.threshold,
        n_seeds=args.seeds,
    )

    if args.sweep:
        print("=== FEDERATION EMERGENCE PARAMETER SWEEP ===\n")
        run_sweep(config, output_dir, n_jobs=args.jobs)
    else:
        print("=== FEDERATION EMERGENCE SIMULATION ===\n")
        result = run_experiment(config, n_jobs=args.jobs)
        print_summary(result)
        save_results(result, output_dir / "run.json")


if __name__ == "__main__":
    main()
