"""
SyncBack Simulation #16: PI+S Under Threats

Question: Does adding the storage-balance term S to the trust formula
break existing defenses against Sybil, free-rider, and spite attacks?
Or does S improve detection of fake-storage adversaries?

New trust formula:
    trust = kp * P_weekly + ki * I + ks * S

    P_weekly = rolling 4-week window; each week a peer either passes the
               weekly storage check (1) or fails (0). P = mean of last 4 weeks.
    I        = cumulative mean of weekly pass/fail scores (0..1).
    S        = storage_ratio = gb_stored_for_others / max(gb_stored_by_others, 0.01)
               clamped to [0.0, 2.0]. Represents reciprocity in storage exchange.

Three scenarios (--scenario a/b/c or --all):

    A  Sybil attack — sybils with real vs. fake storage, subnet limit
    B  Free-rider attack — does S gate out peers who store little?
    C  Spite attack — attackers build S+PI trust before turning hostile

Usage:
    python pis_threats.py --scenario a                  # scenario A only
    python pis_threats.py --all --jobs 8                # all, 8 cores
    python pis_threats.py --scenario b --seeds 50       # fewer seeds
    python pis_threats.py --scenario c --ks 0.5         # override ks
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
# Trust computation (PI+S, weekly resolution)
# ---------------------------------------------------------------------------

CLAMP_S_MAX: float = 2.0


def compute_pis_trust(
    weekly_scores: np.ndarray,  # shape (n_weeks, n_peers), values 0.0 or 1.0
    storage_ratios: np.ndarray,  # shape (n_peers,), clamped externally
    kp: float,
    ki: float,
    ks: float,
    p_weeks: int = 4,
) -> np.ndarray:
    """Compute PI+S trust from weekly check history and storage ratios.

    Returns trust array of shape (n_peers,).
    """
    n_weeks, n_peers = weekly_scores.shape

    if n_weeks == 0:
        baseline = np.full(n_peers, kp * 0.5 + ki * 0.5)
        return baseline + ks * np.clip(storage_ratios, 0.0, CLAMP_S_MAX)

    # P_weekly: rolling 4-week window
    window_start = max(0, n_weeks - p_weeks)
    p_score = weekly_scores[window_start:].mean(axis=0)

    # I: cumulative mean over all weeks
    i_score = weekly_scores.mean(axis=0)

    # S: clamped storage ratio
    s_score = np.clip(storage_ratios, 0.0, CLAMP_S_MAX)

    return kp * p_score + ki * i_score + ks * s_score


def _build_pis_trust_from_params(
    n_total: int,
    reliability: np.ndarray,  # per-peer pass probability for weekly check
    storage_ratios: np.ndarray,
    n_months: int,
    kp: float,
    ki: float,
    ks: float,
    rng: np.random.Generator,
    p_weeks: int = 4,
) -> np.ndarray:
    """Simulate n_months of weekly checks, return final PI+S trust array."""
    n_weeks = n_months * 4  # ~4 weeks per month
    weekly_scores = np.zeros((n_weeks, n_total))

    for w in range(n_weeks):
        # One weekly check per peer
        passed = (rng.random(n_total) < reliability).astype(np.float64)
        weekly_scores[w] = passed

    return compute_pis_trust(weekly_scores, storage_ratios, kp, ki, ks, p_weeks)


# ---------------------------------------------------------------------------
# Shared placement helpers (identical logic to sybil_attack.py / spite_attack.py)
# ---------------------------------------------------------------------------

def _assign_subnets_two_groups(
    n_honest: int,
    n_adversary: int,
    adversary_subnets: int,
) -> np.ndarray:
    """Honest peers each get their own /24. Adversaries share adversary_subnets blocks."""
    n_total = n_honest + n_adversary
    subnets = np.empty(n_total, dtype=np.int32)
    subnets[:n_honest] = np.arange(n_honest)
    adv_ids = n_honest + (np.arange(n_adversary) % adversary_subnets)
    subnets[n_honest:] = adv_ids
    return subnets


def _place_shards(
    n_shards: int,
    subnet_limit: int,
    trust: np.ndarray,
    subnets: np.ndarray,
    excluded: set[int],
    rng: np.random.Generator,
) -> list[int]:
    """Place n_shards shards using trust-weighted sampling with subnet rate limit.

    Matches the implementation in sybil_attack.py and spite_attack.py exactly.
    """
    selected: list[int] = []
    subnet_counts: dict[int, int] = {}

    remaining: list[int] = [
        i for i in range(len(trust))
        if i not in excluded and trust[i] > 0
    ]

    while len(selected) < n_shards and remaining:
        weights = np.array([trust[i] for i in remaining], dtype=np.float64)
        total_w = weights.sum()
        if total_w <= 0:
            break
        probs = weights / total_w
        idx = int(rng.choice(len(remaining), p=probs))
        peer = remaining[idx]
        subnet = subnets[peer]

        if subnet_counts.get(subnet, 0) < subnet_limit:
            selected.append(peer)
            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1

        remaining.pop(idx)
        # Remove all peers in a now-full subnet
        if subnet_counts.get(subnet, 0) >= subnet_limit:
            remaining = [p for p in remaining if subnets[p] != subnet]

    return selected


def _repair_cycle(
    file_shards: list[list[int]],
    trust: np.ndarray,
    subnets: np.ndarray,
    n_shards: int,
    k: int,
    subnet_limit: int,
    shard_failure_prob: float,
    rng: np.random.Generator,
) -> None:
    """Run one weekly repair cycle in-place: drop failed shards, replace with trust-weighted peers."""
    for fidx in range(len(file_shards)):
        holders = file_shards[fidx]
        survived = [p for p in holders if rng.random() > shard_failure_prob]
        n_lost = n_shards - len(survived)
        if n_lost > 0 and len(survived) >= k:
            new_shards = _place_shards(
                n_lost, subnet_limit, trust, subnets, set(survived), rng
            )
            file_shards[fidx] = survived + new_shards
        else:
            file_shards[fidx] = survived


def _count_file_denials(
    file_shards: list[list[int]],
    is_adversary: np.ndarray,
    k: int,
) -> tuple[int, list[int]]:
    """Count files that cannot be restored because adversaries withhold shards.

    Returns (files_denied, per_file_adversary_shard_counts).
    """
    denied = 0
    adv_counts: list[int] = []
    for holders in file_shards:
        n_adv = sum(1 for p in holders if is_adversary[p])
        n_hon = len(holders) - n_adv
        adv_counts.append(n_adv)
        if n_hon < k:
            denied += 1
    return denied, adv_counts


# ---------------------------------------------------------------------------
# Scenario A: Sybil with PI+S
# ---------------------------------------------------------------------------

@dataclass
class SybilConfig:
    n_honest_peers: int = 500
    n_sybils: int = 100
    sybil_subnets: int = 3
    subnet_limit: int = 1
    n_files: int = 1000
    n_seeds: int = 30
    k: int = 5
    n_shards: int = 15
    buildup_months: int = 12
    shard_failure_prob: float = 0.02
    repair_interval_weeks: int = 1
    honest_reliability: float = 0.95
    sybil_reliability: float = 1.0
    honest_storage_ratio: float = 1.0
    sybil_storage_ratio: float = 1.0   # 1.0=real storage, 0.1=fake
    kp: float = 0.5
    ki: float = 2.0
    ks: float = 1.0
    p_weeks: int = 4


def _sybil_simulate_one(cfg: SybilConfig, seed: int) -> dict[str, float]:
    rng = np.random.default_rng(seed)

    n_total = cfg.n_honest_peers + cfg.n_sybils
    is_sybil = np.zeros(n_total, dtype=bool)
    is_sybil[cfg.n_honest_peers:] = True

    subnets = _assign_subnets_two_groups(
        cfg.n_honest_peers, cfg.n_sybils, cfg.sybil_subnets
    )

    reliability = np.where(is_sybil, cfg.sybil_reliability, cfg.honest_reliability)
    storage_ratios = np.where(
        is_sybil, cfg.sybil_storage_ratio, cfg.honest_storage_ratio
    )

    # Phase 0: initial flat-trust placement (sybils have no reputation yet)
    initial_trust = np.ones(n_total, dtype=np.float64)
    file_shards: list[list[int]] = []
    for _ in range(cfg.n_files):
        holders = _place_shards(
            cfg.n_shards, cfg.subnet_limit, initial_trust, subnets, set(), rng
        )
        file_shards.append(holders)

    # Phase 1: buildup — weekly repair cycles with progressively built trust
    n_weeks_total = cfg.buildup_months * 4
    # Accumulate weekly scores incrementally
    weekly_scores = np.zeros((n_weeks_total, n_total))
    for w in range(n_weeks_total):
        passed = (rng.random(n_total) < reliability).astype(np.float64)
        weekly_scores[w] = passed

        # Every repair_interval_weeks weeks, run repair with current trust
        if (w + 1) % cfg.repair_interval_weeks == 0:
            current_trust = compute_pis_trust(
                weekly_scores[: w + 1],
                storage_ratios,
                cfg.kp,
                cfg.ki,
                cfg.ks,
                cfg.p_weeks,
            )
            _repair_cycle(
                file_shards,
                current_trust,
                subnets,
                cfg.n_shards,
                cfg.k,
                cfg.subnet_limit,
                cfg.shard_failure_prob,
                rng,
            )

    final_trust = compute_pis_trust(
        weekly_scores, storage_ratios, cfg.kp, cfg.ki, cfg.ks, cfg.p_weeks
    )

    # Phase 2: attack — sybils refuse to serve
    files_denied, adv_counts = _count_file_denials(file_shards, is_sybil, cfg.k)
    adv_arr = np.array(adv_counts, dtype=np.float64)

    return {
        "denial_rate": files_denied / cfg.n_files,
        "sybil_trust_mean": float(final_trust[is_sybil].mean()),
        "honest_trust_mean": float(final_trust[~is_sybil].mean()),
        "mean_sybil_shards": float(adv_arr.mean()),
    }


def _sybil_run_config(cfg: SybilConfig, n_jobs: int) -> dict[str, float]:
    """Monte Carlo average for one SybilConfig."""
    results = Parallel(n_jobs=n_jobs)(
        delayed(_sybil_simulate_one)(cfg, seed) for seed in range(cfg.n_seeds)
    )
    denial_rates = [r["denial_rate"] for r in results]
    sybil_trust = [r["sybil_trust_mean"] for r in results]
    honest_trust = [r["honest_trust_mean"] for r in results]
    mean_shards = [r["mean_sybil_shards"] for r in results]
    return {
        "denial_mean": float(np.mean(denial_rates)),
        "denial_p95": float(np.percentile(denial_rates, 95)),
        "sybil_trust": float(np.mean(sybil_trust)),
        "honest_trust": float(np.mean(honest_trust)),
        "mean_sybil_shards": float(np.mean(mean_shards)),
    }


def run_scenario_a(
    kp: float,
    ki: float,
    ks: float,
    n_seeds: int,
    n_jobs: int,
    output_dir: Path,
) -> list[dict]:
    """Scenario A: Sybil attack with PI+S vs PI-only."""
    print("\n=== SCENARIO A: SYBIL WITH PI+S ===")
    print(f"kp={kp}, ki={ki}, ks={ks} | seeds={n_seeds} | 5-of-15, subnet_limit=1")
    print()

    n_sybils_list = [50, 100, 200, 500]
    subnets_list = [1, 5, 10]
    sybil_ratios = [1.0, 0.1]  # real storage vs fake storage

    base = SybilConfig(
        n_honest_peers=500,
        n_files=1000,
        n_seeds=n_seeds,
        k=5,
        n_shards=15,
        buildup_months=12,
        shard_failure_prob=0.02,
        subnet_limit=1,
        honest_reliability=0.95,
        sybil_reliability=1.0,
        honest_storage_ratio=1.0,
        kp=kp,
        ki=ki,
        ks=ks,
        p_weeks=4,
    )

    rows: list[dict] = []
    header = (
        f"{'Sybils':>7} {'Subnets':>8} {'S_ratio':>8} "
        f"{'Denial%(PI+S)':>14} {'Denial%(PI)':>12} {'Delta':>6} "
        f"{'SybilTrust':>11} {'HonTrust':>9}"
    )
    print(header)
    print("-" * len(header))

    t0 = time.time()
    for n_sybils in n_sybils_list:
        for n_subnets in subnets_list:
            for s_ratio in sybil_ratios:
                cfg_pis = SybilConfig(
                    **{**asdict(base),
                       "n_sybils": n_sybils,
                       "sybil_subnets": n_subnets,
                       "sybil_storage_ratio": s_ratio,
                       "ks": ks}
                )
                cfg_pi = SybilConfig(
                    **{**asdict(base),
                       "n_sybils": n_sybils,
                       "sybil_subnets": n_subnets,
                       "sybil_storage_ratio": s_ratio,
                       "ks": 0.0}
                )
                res_pis = _sybil_run_config(cfg_pis, n_jobs)
                res_pi = _sybil_run_config(cfg_pi, n_jobs)

                d_pis = res_pis["denial_mean"] * 100
                d_pi = res_pi["denial_mean"] * 100
                delta = d_pis - d_pi  # positive = PI+S is worse (more denial)

                row = {
                    "n_sybils": n_sybils,
                    "sybil_subnets": n_subnets,
                    "sybil_storage_ratio": s_ratio,
                    "denial_pis": res_pis["denial_mean"],
                    "denial_pi": res_pi["denial_mean"],
                    "denial_pis_p95": res_pis["denial_p95"],
                    "denial_pi_p95": res_pi["denial_p95"],
                    "sybil_trust_pis": res_pis["sybil_trust"],
                    "honest_trust_pis": res_pis["honest_trust"],
                    "sybil_trust_pi": res_pi["sybil_trust"],
                    "honest_trust_pi": res_pi["honest_trust"],
                    "mean_sybil_shards_pis": res_pis["mean_sybil_shards"],
                    "mean_sybil_shards_pi": res_pi["mean_sybil_shards"],
                }
                rows.append(row)

                delta_str = f"{delta:+.2f}"
                print(
                    f"{n_sybils:>7} {n_subnets:>8} {s_ratio:>8.1f} "
                    f"{d_pis:>13.2f}% {d_pi:>11.2f}% {delta_str:>7} "
                    f"{res_pis['sybil_trust']:>11.3f} {res_pis['honest_trust']:>9.3f}"
                )

    elapsed = time.time() - t0
    print(f"\nScenario A completed in {elapsed:.1f}s")
    print()
    print("Note: Delta = Denial%(PI+S) - Denial%(PI).")
    print("Negative delta means PI+S reduces denial (better defense).")
    print("S_ratio=1.0 = sybils have real storage; S_ratio=0.1 = fake storage.")

    out_path = output_dir / "scenario_a_sybil.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({
        "scenario": "A",
        "kp": kp, "ki": ki, "ks": ks, "n_seeds": n_seeds,
        "rows": rows,
    }, indent=2))
    print(f"\nResults saved to {out_path}")
    return rows


# ---------------------------------------------------------------------------
# Scenario B: Free-rider with PI+S
# ---------------------------------------------------------------------------

@dataclass
class FreeRiderConfig:
    n_honest_peers: int = 160
    n_freeriders: int = 40
    n_files_per_honest: int = 100
    n_seeds: int = 30
    k: int = 5
    n_shards: int = 15
    n_months: int = 12
    shard_failure_prob: float = 0.02
    repair_interval_weeks: int = 1
    honest_reliability: float = 0.95
    freerider_reliability: float = 0.25
    honest_storage_ratio: float = 1.0
    freerider_storage_ratio: float = 0.1
    trust_threshold: float = 0.3
    kp: float = 0.5
    ki: float = 2.0
    ks: float = 1.0
    p_weeks: int = 4


def _freerider_simulate_one(cfg: FreeRiderConfig, seed: int) -> dict[str, float]:
    rng = np.random.default_rng(seed)

    n_honest = cfg.n_honest_peers
    n_free = cfg.n_freeriders
    n_total = n_honest + n_free

    is_freerider = np.zeros(n_total, dtype=bool)
    is_freerider[n_honest:] = True

    reliability = np.where(is_freerider, cfg.freerider_reliability, cfg.honest_reliability)
    storage_ratios = np.where(
        is_freerider, cfg.freerider_storage_ratio, cfg.honest_storage_ratio
    )

    # Files: only honest peers back up data (n_files_per_honest each).
    # Free-riders also try to back up (same count). They can only get shards
    # placed if their trust is above the threshold.
    n_honest_files = n_honest * cfg.n_files_per_honest
    n_fr_files = n_free * cfg.n_files_per_honest
    n_files_total = n_honest_files + n_fr_files

    all_peers = np.arange(n_total)

    # Initial placement: uniform random (no trust yet)
    file_shards: list[list[int]] = []
    for _ in range(n_files_total):
        holders = rng.choice(
            all_peers, size=min(cfg.n_shards, n_total), replace=False
        ).tolist()
        file_shards.append(holders)

    n_weeks_total = cfg.n_months * 4
    weekly_scores = np.zeros((n_weeks_total, n_total))

    for w in range(n_weeks_total):
        passed = (rng.random(n_total) < reliability).astype(np.float64)
        weekly_scores[w] = passed

        if (w + 1) % cfg.repair_interval_weeks == 0:
            current_trust = compute_pis_trust(
                weekly_scores[: w + 1],
                storage_ratios,
                cfg.kp,
                cfg.ki,
                cfg.ks,
                cfg.p_weeks,
            )

            for fidx in range(n_files_total):
                holders = file_shards[fidx]
                survived = [p for p in holders if rng.random() > cfg.shard_failure_prob]
                n_lost = cfg.n_shards - len(survived)

                if n_lost <= 0 or len(survived) < cfg.k:
                    file_shards[fidx] = survived
                    continue

                # For free-rider files: honest peers check the owner group's mean trust.
                # If below threshold, honest peers decline to store.
                is_fr_file = fidx >= n_honest_files
                if is_fr_file:
                    owner_trust = current_trust[n_honest:].mean()
                    if owner_trust < cfg.trust_threshold:
                        file_shards[fidx] = survived
                        continue

                existing = set(survived)
                # Only peers above threshold can receive new shards
                candidate_mask = (
                    (current_trust >= cfg.trust_threshold)
                    & ~np.isin(all_peers, list(existing))
                )
                candidates = all_peers[candidate_mask]

                if len(candidates) == 0:
                    file_shards[fidx] = survived
                    continue

                weights = current_trust[candidates]
                total_w = float(weights.sum())
                if total_w <= 0:
                    file_shards[fidx] = survived
                    continue

                n_place = min(n_lost, len(candidates))
                probs = weights / total_w
                chosen = rng.choice(candidates, size=n_place, replace=False, p=probs)
                file_shards[fidx] = survived + chosen.tolist()

    final_trust = compute_pis_trust(
        weekly_scores, storage_ratios, cfg.kp, cfg.ki, cfg.ks, cfg.p_weeks
    )

    # Assess survival
    honest_alive = sum(
        1 for fidx in range(n_honest_files) if len(file_shards[fidx]) >= cfg.k
    )
    fr_alive = sum(
        1 for fidx in range(n_honest_files, n_files_total)
        if len(file_shards[fidx]) >= cfg.k
    )

    honest_survival = honest_alive / n_honest_files if n_honest_files > 0 else 1.0
    fr_survival = fr_alive / n_fr_files if n_fr_files > 0 else 0.0

    fr_above_threshold = float(
        (final_trust[n_honest:] >= cfg.trust_threshold).mean()
    )
    fr_trust_mean = float(final_trust[n_honest:].mean())
    honest_trust_mean = float(final_trust[:n_honest].mean())

    return {
        "honest_survival": honest_survival,
        "fr_survival": fr_survival,
        "fr_above_threshold": fr_above_threshold,
        "fr_trust_mean": fr_trust_mean,
        "honest_trust_mean": honest_trust_mean,
    }


def _freerider_run_config(cfg: FreeRiderConfig, n_jobs: int) -> dict[str, float]:
    results = Parallel(n_jobs=n_jobs)(
        delayed(_freerider_simulate_one)(cfg, seed) for seed in range(cfg.n_seeds)
    )
    def _mean(key: str) -> float:
        return float(np.mean([r[key] for r in results]))

    return {
        "honest_survival": _mean("honest_survival"),
        "fr_survival": _mean("fr_survival"),
        "fr_above_threshold": _mean("fr_above_threshold"),
        "fr_trust_mean": _mean("fr_trust_mean"),
        "honest_trust_mean": _mean("honest_trust_mean"),
    }


def run_scenario_b(
    kp: float,
    ki: float,
    ks: float,
    n_seeds: int,
    n_jobs: int,
    output_dir: Path,
) -> list[dict]:
    """Scenario B: Free-rider detection with PI+S vs PI-only."""
    print("\n=== SCENARIO B: FREE-RIDER WITH PI+S ===")
    print(f"kp={kp}, ki={ki}, ks={ks} | seeds={n_seeds} | 5-of-15, 12 months")
    print()

    total_peers = 200
    fr_proportions = [0.10, 0.25, 0.40]
    fr_reliabilities = [0.25, 0.50, 0.80]
    fr_storage_ratios = [0.1, 0.3, 0.5]
    trust_thresholds = [0.3, 0.5]

    rows: list[dict] = []
    header = (
        f"{'FR%':>5} {'Rel%':>5} {'S_fr':>5} {'Thr':>5} "
        f"{'H_surv%':>8} {'FR_surv%(PI+S)':>15} {'FR_surv%(PI)':>13} "
        f"{'Delta':>7} {'FR_above_thr%':>14}"
    )
    print(header)
    print("-" * len(header))

    t0 = time.time()
    for fr_prop in fr_proportions:
        n_fr = max(1, int(total_peers * fr_prop))
        n_hon = total_peers - n_fr
        for fr_rel in fr_reliabilities:
            for fr_s in fr_storage_ratios:
                for thr in trust_thresholds:
                    base_args = dict(
                        n_honest_peers=n_hon,
                        n_freeriders=n_fr,
                        n_files_per_honest=100,
                        n_seeds=n_seeds,
                        k=5,
                        n_shards=15,
                        n_months=12,
                        shard_failure_prob=0.02,
                        repair_interval_weeks=1,
                        honest_reliability=0.95,
                        freerider_reliability=fr_rel,
                        honest_storage_ratio=1.0,
                        freerider_storage_ratio=fr_s,
                        trust_threshold=thr,
                        kp=kp,
                        ki=ki,
                        p_weeks=4,
                    )
                    cfg_pis = FreeRiderConfig(**base_args, ks=ks)
                    cfg_pi = FreeRiderConfig(**base_args, ks=0.0)

                    res_pis = _freerider_run_config(cfg_pis, n_jobs)
                    res_pi = _freerider_run_config(cfg_pi, n_jobs)

                    h_surv = res_pis["honest_survival"] * 100
                    fr_surv_pis = res_pis["fr_survival"] * 100
                    fr_surv_pi = res_pi["fr_survival"] * 100
                    delta = fr_surv_pis - fr_surv_pi
                    above_thr = res_pis["fr_above_threshold"] * 100

                    row = {
                        "fr_proportion": fr_prop,
                        "n_freeriders": n_fr,
                        "fr_reliability": fr_rel,
                        "fr_storage_ratio": fr_s,
                        "trust_threshold": thr,
                        "honest_survival_pis": res_pis["honest_survival"],
                        "fr_survival_pis": res_pis["fr_survival"],
                        "fr_survival_pi": res_pi["fr_survival"],
                        "fr_above_threshold_pis": res_pis["fr_above_threshold"],
                        "fr_above_threshold_pi": res_pi["fr_above_threshold"],
                        "fr_trust_pis": res_pis["fr_trust_mean"],
                        "fr_trust_pi": res_pi["fr_trust_mean"],
                        "honest_trust_pis": res_pis["honest_trust_mean"],
                        "honest_trust_pi": res_pi["honest_trust_mean"],
                    }
                    rows.append(row)

                    delta_str = f"{delta:+.1f}"
                    print(
                        f"{fr_prop*100:>4.0f}% {fr_rel*100:>4.0f}% {fr_s:>5.1f} {thr:>5.1f} "
                        f"{h_surv:>7.1f}% {fr_surv_pis:>14.1f}% {fr_surv_pi:>12.1f}% "
                        f"{delta_str:>8} {above_thr:>13.1f}%"
                    )

    elapsed = time.time() - t0
    print(f"\nScenario B completed in {elapsed:.1f}s")
    print()
    print("Note: Delta = FR_surv%(PI+S) - FR_surv%(PI).")
    print("Negative delta means PI+S better excludes free-riders.")
    print("FR_above_thr% = fraction of free-riders still above trust threshold (PI+S).")

    out_path = output_dir / "scenario_b_freerider.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({
        "scenario": "B",
        "kp": kp, "ki": ki, "ks": ks, "n_seeds": n_seeds,
        "rows": rows,
    }, indent=2))
    print(f"\nResults saved to {out_path}")
    return rows


# ---------------------------------------------------------------------------
# Scenario C: Spite attack with PI+S
# ---------------------------------------------------------------------------

@dataclass
class SpiteConfig:
    n_honest_peers: int = 500
    n_attackers: int = 20
    attacker_subnets: int = 3
    subnet_limit: int = 1
    n_files: int = 1000
    n_seeds: int = 30
    k: int = 5
    n_shards: int = 15
    initial_reputation_months: int = 6
    wait_years: float = 1.0
    shard_failure_prob: float = 0.02
    honest_reliability: float = 0.95
    honest_storage_ratio: float = 1.0
    attacker_storage_ratio: float = 1.0  # attackers DO store (real nodes)
    kp: float = 0.5
    ki: float = 2.0
    ks: float = 1.0
    p_weeks: int = 4


def _spite_simulate_one(cfg: SpiteConfig, seed: int) -> dict[str, float]:
    rng = np.random.default_rng(seed)

    n_total = cfg.n_honest_peers + cfg.n_attackers
    is_attacker = np.zeros(n_total, dtype=bool)
    is_attacker[cfg.n_honest_peers:] = True

    subnets = _assign_subnets_two_groups(
        cfg.n_honest_peers, cfg.n_attackers, cfg.attacker_subnets
    )

    # All nodes behave honestly (attackers are real nodes, just refusing target at restore)
    reliability = np.full(n_total, cfg.honest_reliability)
    storage_ratios = np.where(
        is_attacker, cfg.attacker_storage_ratio, cfg.honest_storage_ratio
    )

    # Phase 0: initial reputation buildup
    initial_weeks = cfg.initial_reputation_months * 4
    weekly_scores_init = np.zeros((initial_weeks, n_total))
    for w in range(initial_weeks):
        passed = (rng.random(n_total) < reliability).astype(np.float64)
        weekly_scores_init[w] = passed

    trust = compute_pis_trust(
        weekly_scores_init, storage_ratios, cfg.kp, cfg.ki, cfg.ks, cfg.p_weeks
    )

    # Place target's files after initial reputation buildup
    file_shards: list[list[int]] = []
    for _ in range(cfg.n_files):
        holders = _place_shards(
            cfg.n_shards, cfg.subnet_limit, trust, subnets, set(), rng
        )
        file_shards.append(holders)

    # Phase 1: wait phase — attacker keeps behaving honestly, accumulating shards
    n_wait_weeks = int(cfg.wait_years * 52)  # 52 weeks per year
    total_weeks = initial_weeks + n_wait_weeks
    # We extend the weekly_scores array and update trust periodically
    all_weekly_scores = np.zeros((total_weeks, n_total))
    all_weekly_scores[:initial_weeks] = weekly_scores_init

    # Rebuild trust quarterly (~every 13 weeks) to avoid recomputing every week
    snapshot_interval = max(1, n_wait_weeks // 8)

    for w_offset in range(n_wait_weeks):
        w_abs = initial_weeks + w_offset
        passed = (rng.random(n_total) < reliability).astype(np.float64)
        all_weekly_scores[w_abs] = passed

        if w_offset % snapshot_interval == 0 or w_offset == n_wait_weeks - 1:
            trust = compute_pis_trust(
                all_weekly_scores[: w_abs + 1],
                storage_ratios,
                cfg.kp,
                cfg.ki,
                cfg.ks,
                cfg.p_weeks,
            )

        # Weekly repair cycle
        _repair_cycle(
            file_shards, trust, subnets,
            cfg.n_shards, cfg.k, cfg.subnet_limit,
            cfg.shard_failure_prob, rng,
        )

    # Phase 2: target's disk fails, attackers refuse
    files_denied, adv_counts = _count_file_denials(file_shards, is_attacker, cfg.k)
    adv_arr = np.array(adv_counts, dtype=np.float64)

    final_trust = compute_pis_trust(
        all_weekly_scores, storage_ratios, cfg.kp, cfg.ki, cfg.ks, cfg.p_weeks
    )

    return {
        "denial_rate": files_denied / cfg.n_files,
        "attacker_trust_mean": float(final_trust[is_attacker].mean()),
        "honest_trust_mean": float(final_trust[~is_attacker].mean()),
        "mean_attacker_shards": float(adv_arr.mean()),
        "p_file_with_any_attacker": float((adv_arr > 0).mean()),
    }


def _spite_run_config(cfg: SpiteConfig, n_jobs: int) -> dict[str, float]:
    results = Parallel(n_jobs=n_jobs)(
        delayed(_spite_simulate_one)(cfg, seed) for seed in range(cfg.n_seeds)
    )
    denial_rates = [r["denial_rate"] for r in results]
    atk_trust = [r["attacker_trust_mean"] for r in results]
    hon_trust = [r["honest_trust_mean"] for r in results]
    atk_shards = [r["mean_attacker_shards"] for r in results]
    p_any = [r["p_file_with_any_attacker"] for r in results]
    return {
        "denial_mean": float(np.mean(denial_rates)),
        "denial_p95": float(np.percentile(denial_rates, 95)),
        "attacker_trust": float(np.mean(atk_trust)),
        "honest_trust": float(np.mean(hon_trust)),
        "mean_attacker_shards": float(np.mean(atk_shards)),
        "p_file_with_any_attacker": float(np.mean(p_any)),
    }


def run_scenario_c(
    kp: float,
    ki: float,
    ks: float,
    n_seeds: int,
    n_jobs: int,
    output_dir: Path,
) -> list[dict]:
    """Scenario C: Spite attack dynamics with PI+S vs PI-only."""
    print("\n=== SCENARIO C: SPITE ATTACK WITH PI+S ===")
    print(f"kp={kp}, ki={ki}, ks={ks} | seeds={n_seeds} | 5-of-15, attacker_storage=1.0")
    print()

    n_attackers_list = [20, 50, 100]
    wait_years_list = [1, 3, 5]

    rows: list[dict] = []
    header = (
        f"{'Attackers':>10} {'Wait_yr':>8} "
        f"{'Denial%(PI+S)':>14} {'Denial%(PI)':>12} {'Delta':>7} "
        f"{'AtkTrust(PI+S)':>15} {'AtkShards':>10}"
    )
    print(header)
    print("-" * len(header))

    t0 = time.time()
    for n_atk in n_attackers_list:
        for wait_yr in wait_years_list:
            base_args = dict(
                n_honest_peers=500,
                n_attackers=n_atk,
                attacker_subnets=3,
                subnet_limit=1,
                n_files=1000,
                n_seeds=n_seeds,
                k=5,
                n_shards=15,
                initial_reputation_months=6,
                wait_years=float(wait_yr),
                shard_failure_prob=0.02,
                honest_reliability=0.95,
                honest_storage_ratio=1.0,
                attacker_storage_ratio=1.0,
                kp=kp,
                ki=ki,
                p_weeks=4,
            )
            cfg_pis = SpiteConfig(**base_args, ks=ks)
            cfg_pi = SpiteConfig(**base_args, ks=0.0)

            res_pis = _spite_run_config(cfg_pis, n_jobs)
            res_pi = _spite_run_config(cfg_pi, n_jobs)

            d_pis = res_pis["denial_mean"] * 100
            d_pi = res_pi["denial_mean"] * 100
            delta = d_pis - d_pi

            row = {
                "n_attackers": n_atk,
                "wait_years": wait_yr,
                "denial_pis": res_pis["denial_mean"],
                "denial_pi": res_pi["denial_mean"],
                "denial_pis_p95": res_pis["denial_p95"],
                "denial_pi_p95": res_pi["denial_p95"],
                "attacker_trust_pis": res_pis["attacker_trust"],
                "attacker_trust_pi": res_pi["attacker_trust"],
                "honest_trust_pis": res_pis["honest_trust"],
                "honest_trust_pi": res_pi["honest_trust"],
                "mean_attacker_shards_pis": res_pis["mean_attacker_shards"],
                "mean_attacker_shards_pi": res_pi["mean_attacker_shards"],
                "p_file_with_any_attacker_pis": res_pis["p_file_with_any_attacker"],
                "p_file_with_any_attacker_pi": res_pi["p_file_with_any_attacker"],
            }
            rows.append(row)

            delta_str = f"{delta:+.2f}"
            print(
                f"{n_atk:>10} {wait_yr:>8} "
                f"{d_pis:>13.2f}% {d_pi:>11.2f}% {delta_str:>8} "
                f"{res_pis['attacker_trust']:>15.3f} {res_pis['mean_attacker_shards']:>10.2f}"
            )

    elapsed = time.time() - t0
    print(f"\nScenario C completed in {elapsed:.1f}s")
    print()
    print("Note: Attackers have storage_ratio=1.0 (real nodes storing real data).")
    print("S term cannot distinguish them from honest peers until attack time.")
    print("Delta = Denial%(PI+S) - Denial%(PI).")

    out_path = output_dir / "scenario_c_spite.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({
        "scenario": "C",
        "kp": kp, "ki": ki, "ks": ks, "n_seeds": n_seeds,
        "rows": rows,
    }, indent=2))
    print(f"\nResults saved to {out_path}")
    return rows


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SyncBack Experiment 16: PI+S Trust Under Threat Scenarios"
    )
    parser.add_argument(
        "--scenario", choices=["a", "b", "c"],
        help="Run a specific scenario (a=sybil, b=freerider, c=spite)"
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Run all three scenarios"
    )
    parser.add_argument("--kp", type=float, default=0.5, help="PI+S kp weight")
    parser.add_argument("--ki", type=float, default=2.0, help="PI+S ki weight")
    parser.add_argument("--ks", type=float, default=1.0, help="PI+S ks weight (S term)")
    parser.add_argument("--seeds", type=int, default=30, help="Monte Carlo seeds per config")
    parser.add_argument("--jobs", type=int, default=1, help="Parallel jobs (cores)")
    parser.add_argument(
        "--output", type=str, default="results/pis_threats",
        help="Output directory for JSON results"
    )
    args = parser.parse_args()

    if not args.all and not args.scenario:
        parser.error("Specify --scenario a/b/c or --all")

    output_dir = Path(args.output)

    print("=== SYNCBACK EXPERIMENT 16: PI+S UNDER THREATS ===")
    print(f"Trust formula: trust = {args.kp}*P_weekly + {args.ki}*I + {args.ks}*S")
    print(f"  P_weekly: rolling 4-week window of weekly checks")
    print(f"  I: cumulative mean of weekly scores")
    print(f"  S: storage_ratio = gb_stored_for_others / max(gb_stored_by_others, 0.01)")
    print(f"     clamped to [0.0, {CLAMP_S_MAX}]")
    print(f"Comparison: each config run twice — with ks={args.ks} and ks=0.0 (PI-only)")
    print()

    run_a = args.all or args.scenario == "a"
    run_b = args.all or args.scenario == "b"
    run_c = args.all or args.scenario == "c"

    if run_a:
        run_scenario_a(args.kp, args.ki, args.ks, args.seeds, args.jobs, output_dir)

    if run_b:
        run_scenario_b(args.kp, args.ki, args.ks, args.seeds, args.jobs, output_dir)

    if run_c:
        run_scenario_c(args.kp, args.ki, args.ks, args.seeds, args.jobs, output_dir)

    print("\n=== EXPERIMENT 16 COMPLETE ===")


if __name__ == "__main__":
    main()
