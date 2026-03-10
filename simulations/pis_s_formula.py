"""
SyncBack Simulation #22: Multiplicative vs Additive S

Question: Does a multiplicative or hybrid S formulation correctly rank archetypes
(specifically fixing Hoarder > Nomad inversion) compared to the additive baseline?

Exp 17 finding: additive S gives tau=0.667 because Hoarder (90% uptime, S=0.2)
outranks Nomad (50% uptime, S=1.0). The PI terms outweigh the S penalty.

Three variants tested:
  A: Additive (baseline from Exp 17)
       trust_AB = kp*P_B + ki*I_B + ks*S_AB

  B: Multiplicative
       trust_AB = (kp*P_B + ki*I_B) * clamp(S_AB, 0.1, 1.0)
       S is a multiplier; if S<1.0 trust is proportionally reduced. Floor=0.1
       prevents complete rejection during bootstrap.

  C: Hybrid
       trust_AB = (kp*P_B + ki*I_B) * clamp(S_AB, 0.1, 1.0) + ks_bonus * max(S_AB-1, 0)
       Multiplicative penalty for S<1.0, small additive bonus for S>1.0.

Network model (simplified from Exp 17):
  - 5000 max nodes, 5 years, 25% annual churn
  - Weekly time steps, P=4-week window, I=cumulative mean
  - Partnership formation batched at 300/week
  - 10 seeds per config, parallelized

Usage:
    python pis_s_formula.py --seeds 10 --jobs 6
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

import numpy as np
from joblib import Parallel, delayed
from scipy.stats import kendalltau


# ---------------------------------------------------------------------------
# Archetype definitions
# ---------------------------------------------------------------------------

ARCHETYPE_NAMES = [
    "Reliable",    # rank 1 (most useful)
    "Weekend",     # rank 2
    "Seasonal",    # rank 3
    "Nomad",       # rank 4
    "Hoarder",     # rank 5
    "Freeloader",  # rank 6 (least useful)
]

# Expected usefulness rank (lower = more useful, 1-indexed).
# This is the ground truth we want the trust formula to reproduce.
ACTUAL_USEFULNESS_RANK = [1, 2, 3, 4, 5, 6]

# Archetype probabilities for new nodes
ARCHETYPE_PROBS = np.array([0.35, 0.25, 0.15, 0.10, 0.10, 0.05])

# Storage offer ratio per archetype.
# Pairwise S_AB = STORAGE_RATIOS[B] / max(STORAGE_RATIOS[A], eps), clamped [0, 2].
STORAGE_RATIOS = np.array([1.0, 1.0, 1.0, 1.0, 0.2, 0.1], dtype=np.float64)

N_ARCHETYPES = len(ARCHETYPE_NAMES)

# Hoarder and Freeloader archetypes (for "honest-only tau")
_HOARDER_IDX = 4
_FREELOADER_IDX = 5

# Small epsilon to avoid division by zero in pairwise S
_S_EPS = 0.01

# S floor for multiplicative formulas (bootstrap protection)
_S_FLOOR = 0.1


# ---------------------------------------------------------------------------
# Formula variants
# ---------------------------------------------------------------------------

class FormulaKind(Enum):
    ADDITIVE = "A"
    MULTIPLICATIVE = "B"
    HYBRID = "C"


@dataclass(frozen=True)
class FormulaConfig:
    """Parameters for one trust formula configuration."""
    kind: FormulaKind
    kp: float
    ki: float
    # For A: additive S weight
    ks: float = 0.0
    # For C: bonus weight for S > 1
    ks_bonus: float = 0.0

    def label(self) -> str:
        if self.kind == FormulaKind.ADDITIVE:
            return f"kp={self.kp} ki={self.ki} ks={self.ks}"
        elif self.kind == FormulaKind.MULTIPLICATIVE:
            return f"kp={self.kp} ki={self.ki}"
        else:
            return f"kp={self.kp} ki={self.ki} ks_bonus={self.ks_bonus}"

    def compute_trust(
        self,
        p_b: float | np.ndarray,
        i_b: float | np.ndarray,
        s_ab: float | np.ndarray,
    ) -> float | np.ndarray:
        """Compute trust from observer A toward target B."""
        pi = self.kp * p_b + self.ki * i_b
        if self.kind == FormulaKind.ADDITIVE:
            return pi + self.ks * s_ab
        elif self.kind == FormulaKind.MULTIPLICATIVE:
            clamp_s = np.clip(s_ab, _S_FLOOR, 1.0)
            return pi * clamp_s
        else:  # HYBRID
            clamp_s = np.clip(s_ab, _S_FLOOR, 1.0)
            bonus = np.maximum(s_ab - 1.0, 0.0)
            return pi * clamp_s + self.ks_bonus * bonus


def _build_formula_grid() -> list[FormulaConfig]:
    """Build the full parameter sweep grid for all three formula variants."""
    configs: list[FormulaConfig] = []

    # Formula A: additive
    for kp in [0.3, 0.5]:
        for ki in [1.5, 2.0]:
            for ks in [0.3, 0.5, 1.0, 2.0]:
                configs.append(FormulaConfig(
                    kind=FormulaKind.ADDITIVE, kp=kp, ki=ki, ks=ks,
                ))

    # Formula B: multiplicative (no ks parameter)
    for kp in [0.3, 0.5]:
        for ki in [1.5, 2.0]:
            configs.append(FormulaConfig(
                kind=FormulaKind.MULTIPLICATIVE, kp=kp, ki=ki,
            ))

    # Formula C: hybrid
    for kp in [0.3, 0.5]:
        for ki in [1.5, 2.0]:
            for ks_bonus in [0.1, 0.3]:
                configs.append(FormulaConfig(
                    kind=FormulaKind.HYBRID, kp=kp, ki=ki, ks_bonus=ks_bonus,
                ))

    return configs


# ---------------------------------------------------------------------------
# Network simulation parameters
# ---------------------------------------------------------------------------

@dataclass
class SimConfig:
    """Fixed simulation parameters (not swept)."""
    initial_peers: int = 50
    max_active_peers: int = 5_000
    annual_churn: float = 0.25
    target_partners: int = 15
    acceptance_gate: float = 0.3
    n_years: int = 5
    p_window_weeks: int = 4
    # Batched partnership formation limit per week
    partnership_batch: int = 300


def _weekly_churn_prob(cfg: SimConfig) -> float:
    return 1.0 - (1.0 - cfg.annual_churn) ** (1.0 / 52.0)


def _new_nodes_this_week(week: int) -> int:
    """Growth schedule matching Exp 17 but scaled for 5K max."""
    if week < 52:
        return 15
    elif week < 156:
        return 150
    else:
        return 75


# ---------------------------------------------------------------------------
# Precomputed weekly pass probabilities
# ---------------------------------------------------------------------------

def _build_weekly_pass_probs(n_weeks: int) -> np.ndarray:
    """
    Precompute P(at least 1 of 7 daily checks passes) per archetype per week.
    Returns shape (N_ARCHETYPES, n_weeks).
    """
    week_idx = np.arange(n_weeks)
    week_in_year = week_idx % 52
    probs = np.zeros((N_ARCHETYPES, n_weeks), dtype=np.float64)

    # 0: Reliable — 99% daily
    probs[0, :] = 1.0 - (1.0 - 0.99) ** 7

    # 1: Weekend — 3 weekend days at 0.95, 4 weekdays at 0.30
    p_fail = (1.0 - 0.95) ** 3 * (1.0 - 0.30) ** 4
    probs[1, :] = 1.0 - p_fail

    # 2: Seasonal — 0.95 during semester, 0.20 during summer (weeks 22-35)
    is_summer = (week_in_year >= 22) & (week_in_year <= 35)
    r_seasonal = np.where(is_summer, 0.20, 0.95)
    probs[2, :] = 1.0 - (1.0 - r_seasonal) ** 7

    # 3: Nomad — 50% weekly availability, 100% when online
    probs[3, :] = 0.50

    # 4: Hoarder — 90% daily
    probs[4, :] = 1.0 - (1.0 - 0.90) ** 7

    # 5: Freeloader — 80% daily
    probs[5, :] = 1.0 - (1.0 - 0.80) ** 7

    return probs


# ---------------------------------------------------------------------------
# Core simulation (single seed)
# ---------------------------------------------------------------------------

def simulate_one(
    formula: FormulaConfig,
    sim_cfg: SimConfig,
    seed: int,
) -> dict:
    """
    Simulate one 5-year run with the given trust formula.

    Returns yearly snapshots at years 1, 3, 5 with Kendall's tau
    and honest-only tau.
    """
    rng = np.random.default_rng(seed)
    cap = sim_cfg.max_active_peers
    n_weeks = sim_cfg.n_years * 52
    pw = sim_cfg.p_window_weeks

    # Per-node state arrays (pre-allocated to cap)
    archetype = np.full(cap, -1, dtype=np.int8)
    alive = np.zeros(cap, dtype=bool)
    p_buf = np.zeros((cap, pw), dtype=np.float64)
    p_buf_pos = np.zeros(cap, dtype=np.int32)
    p_buf_filled = np.zeros(cap, dtype=np.int32)
    i_sum = np.zeros(cap, dtype=np.float64)
    i_count = np.zeros(cap, dtype=np.int32)
    p_val_arr = np.zeros(cap, dtype=np.float64)
    i_val_arr = np.zeros(cap, dtype=np.float64)

    # partners[i] = set of partner node IDs
    partners: list[set[int]] = [set() for _ in range(cap)]

    weekly_pass_probs = _build_weekly_pass_probs(n_weeks)
    weekly_churn = _weekly_churn_prob(sim_cfg)

    # ID management
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

    def _add(nid: int) -> None:
        atype = int(rng.choice(N_ARCHETYPES, p=ARCHETYPE_PROBS))
        archetype[nid] = atype
        alive[nid] = True
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
        for pid in partners[nid]:
            partners[pid].discard(nid)
        partners[nid].clear()
        free_ids.append(nid)

    # Bootstrap
    for _ in range(sim_cfg.initial_peers):
        nid = _alloc()
        if nid is None:
            break
        _add(nid)

    # Snapshot at years 1, 3, 5
    snapshot_weeks = {52, 156, 260}
    yearly_snapshots: list[dict] = []

    # -----------------------------------------------------------------------
    # Main weekly loop
    # -----------------------------------------------------------------------
    for week in range(n_weeks):

        # --- 1. Growth ---
        n_active = int(alive.sum())
        if n_active < sim_cfg.max_active_peers:
            n_new = min(_new_nodes_this_week(week), sim_cfg.max_active_peers - n_active)
            for _ in range(n_new):
                nid = _alloc()
                if nid is None:
                    break
                _add(nid)

        # --- 2. Churn ---
        active_ids = np.where(alive)[0]
        if active_ids.size > 0:
            churn_mask = rng.random(active_ids.size) < weekly_churn
            for nid in active_ids[churn_mask]:
                _remove(int(nid))

        # --- 3. Weekly scores (vectorized per archetype) ---
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
        p_buf_sum = p_buf[active_ids, :].sum(axis=1)
        pf = p_buf_filled[active_ids].astype(np.float64)
        p_val_arr[active_ids] = np.where(pf > 0, p_buf_sum / pf, 0.0)

        ic = i_count[active_ids].astype(np.float64)
        i_val_arr[active_ids] = np.where(ic > 0, i_sum[active_ids] / ic, 0.0)

        # --- 7. Partnership formation (batched) ---
        _update_partnerships(
            active_ids, alive, archetype, i_val_arr,
            p_val_arr, partners, sim_cfg, formula, rng,
        )

        # --- 8. Snapshot ---
        if (week + 1) in snapshot_weeks:
            year = (week + 1) // 52
            snap = _build_snapshot(
                year, active_ids, archetype, i_val_arr,
                p_val_arr, partners, formula,
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
    sim_cfg: SimConfig,
    formula: FormulaConfig,
    rng: np.random.Generator,
) -> None:
    """
    Batched partnership formation with trust-weighted selection.

    Acceptance gate: newcomers (I < gate) can only connect to other newcomers.
    Partnership selection uses pairwise S from the observer's perspective.
    Batch size limited to partnership_batch per week for speed.
    """
    on_count = np.array([len(partners[int(nid)]) for nid in active_ids], dtype=np.int32)
    underfull_mask = on_count < sim_cfg.target_partners
    underfull = active_ids[underfull_mask]
    if underfull.size == 0:
        return

    if underfull.size > sim_cfg.partnership_batch:
        underfull = rng.choice(underfull, size=sim_cfg.partnership_batch, replace=False)

    for pid in underfull:
        pid = int(pid)
        n_partners_pid = len(partners[pid])
        n_needed = sim_cfg.target_partners - n_partners_pid
        if n_needed <= 0:
            continue

        req_i = float(i_val_arr[pid])
        a_pid = int(archetype[pid])
        r_pid = float(STORAGE_RATIOS[a_pid])

        # Build candidate mask
        mask = alive.copy()
        mask[pid] = False
        for existing in partners[pid]:
            if existing < len(mask):
                mask[existing] = False
        for cid_idx in np.where(mask)[0]:
            if len(partners[int(cid_idx)]) >= sim_cfg.target_partners:
                mask[int(cid_idx)] = False

        # Acceptance gate
        if req_i < sim_cfg.acceptance_gate:
            gate_mask = i_val_arr <= sim_cfg.acceptance_gate
            mask &= gate_mask

        candidates = np.where(mask)[0]
        if candidates.size == 0:
            # Relax gate as fallback
            mask2 = alive.copy()
            mask2[pid] = False
            for existing in partners[pid]:
                if existing < len(mask2):
                    mask2[existing] = False
            for cid_idx in np.where(mask2)[0]:
                if len(partners[int(cid_idx)]) >= sim_cfg.target_partners:
                    mask2[int(cid_idx)] = False
            candidates = np.where(mask2)[0]
            if candidates.size == 0:
                continue

        # Pairwise S from pid's perspective toward each candidate
        r_cands = STORAGE_RATIOS[archetype[candidates]]
        s_vals = np.minimum(r_cands / max(r_pid, _S_EPS), 2.0)

        c_trust = np.maximum(
            formula.compute_trust(p_val_arr[candidates], i_val_arr[candidates], s_vals),
            0.01,
        )
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
    i_val_arr: np.ndarray,
    p_val_arr: np.ndarray,
    partners: list[set[int]],
    formula: FormulaConfig,
) -> dict:
    """
    Compute snapshot metrics for one year.

    Archetype trust = mean incoming trust received by nodes of that archetype
    from their actual partners. Reflects how peers actually perceive each type.

    Also computes "honest-only tau": Kendall's tau computed only from trust
    as seen by non-Hoarder, non-Freeloader observers (honest nodes).
    """
    if active_ids.size == 0:
        return {"year": year, "n_active": 0, "kendall_tau": 0.0, "kendall_tau_honest": 0.0}

    arch = archetype[active_ids]
    active_set = set(int(x) for x in active_ids)

    # Per-archetype mean incoming trust (from all observers)
    arch_trust_all: dict[str, float] = {}
    # Per-archetype mean incoming trust (from honest observers only)
    arch_trust_honest: dict[str, float] = {}
    arch_count: dict[str, int] = {}
    arch_frac: dict[str, float] = {}

    for target_arch_idx, name in enumerate(ARCHETYPE_NAMES):
        target_mask = arch == target_arch_idx
        target_nodes = active_ids[target_mask]
        cnt = int(target_nodes.size)
        arch_count[name] = cnt
        arch_frac[name] = float(cnt / active_ids.size) if active_ids.size > 0 else 0.0

        if cnt == 0:
            arch_trust_all[name] = 0.0
            arch_trust_honest[name] = 0.0
            continue

        r_b = float(STORAGE_RATIOS[target_arch_idx])
        trust_sum_all = 0.0
        trust_sum_honest = 0.0
        obs_count_all = 0
        obs_count_honest = 0

        for b in target_nodes:
            b = int(b)
            p_b = float(p_val_arr[b])
            i_b = float(i_val_arr[b])
            for a in partners[b]:
                if a not in active_set:
                    continue
                r_a = float(STORAGE_RATIOS[int(archetype[a])])
                s_ab = min(r_b / max(r_a, _S_EPS), 2.0)
                t = float(formula.compute_trust(p_b, i_b, s_ab))
                trust_sum_all += t
                obs_count_all += 1
                # Honest observer: not Hoarder and not Freeloader
                a_arch = int(archetype[a])
                if a_arch != _HOARDER_IDX and a_arch != _FREELOADER_IDX:
                    trust_sum_honest += t
                    obs_count_honest += 1

        arch_trust_all[name] = trust_sum_all / max(obs_count_all, 1)
        arch_trust_honest[name] = trust_sum_honest / max(obs_count_honest, 1)

    # Kendall's tau: trust ranking vs expected usefulness ranking
    trust_vals = np.array([arch_trust_all[n] for n in ARCHETYPE_NAMES])
    trust_vals_honest = np.array([arch_trust_honest[n] for n in ARCHETYPE_NAMES])
    expected = -np.array(ACTUAL_USEFULNESS_RANK, dtype=float)

    tau_all, _ = kendalltau(trust_vals, expected)
    tau_honest, _ = kendalltau(trust_vals_honest, expected)

    return {
        "year": year,
        "n_active": int(active_ids.size),
        "kendall_tau": float(tau_all),
        "kendall_tau_honest": float(tau_honest),
        "archetype_trust": arch_trust_all,
        "archetype_trust_honest": arch_trust_honest,
        "archetype_count": arch_count,
        "archetype_fraction": arch_frac,
    }


# ---------------------------------------------------------------------------
# Multi-seed aggregation
# ---------------------------------------------------------------------------

def run_formula_config(
    formula: FormulaConfig,
    sim_cfg: SimConfig,
    n_seeds: int,
    n_jobs: int,
) -> dict:
    """Run n_seeds simulations for one formula config and aggregate results."""
    seeds = list(range(n_seeds))

    if n_jobs == 1 or n_seeds == 1:
        all_runs = [simulate_one(formula, sim_cfg, s) for s in seeds]
    else:
        all_runs = Parallel(n_jobs=n_jobs)(
            delayed(simulate_one)(formula, sim_cfg, s) for s in seeds
        )

    # Collect snapshots per year
    per_year: dict[int, list[dict]] = {}
    for run in all_runs:
        for snap in run["snapshots"]:
            y = snap["year"]
            per_year.setdefault(y, []).append(snap)

    def _mean(snaps: list[dict], key: str) -> float:
        vals = [s[key] for s in snaps if key in s]
        return float(np.mean(vals)) if vals else 0.0

    aggregated: dict[int, dict] = {}
    for year, snaps in per_year.items():
        aggregated[year] = {
            "year": year,
            "n_active": int(np.mean([s["n_active"] for s in snaps])),
            "kendall_tau": _mean(snaps, "kendall_tau"),
            "kendall_tau_honest": _mean(snaps, "kendall_tau_honest"),
            "archetype_trust": _mean_arch(snaps, "archetype_trust"),
            "archetype_trust_honest": _mean_arch(snaps, "archetype_trust_honest"),
        }

    return aggregated


def _mean_arch(snaps: list[dict], key: str) -> dict[str, float]:
    result: dict[str, float] = {}
    for name in ARCHETYPE_NAMES:
        vals = [s[key][name] for s in snaps if key in s and name in s[key]]
        result[name] = float(np.mean(vals)) if vals else 0.0
    return result


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def _tau_str(tau: float) -> str:
    """Format tau with a quality indicator."""
    if tau >= 0.99:
        return f"{tau:.3f} [perfect]"
    elif tau >= 0.8:
        return f"{tau:.3f} [good]"
    elif tau >= 0.6:
        return f"{tau:.3f} [weak]"
    else:
        return f"{tau:.3f} [fail]"


def print_results(
    all_results: list[tuple[FormulaConfig, dict]],
    sim_cfg: SimConfig,
    n_seeds: int,
    elapsed: float,
) -> None:
    """Print formatted results grouped by formula variant."""
    print(f"\nRuntime: {elapsed:.1f}s  Seeds: {n_seeds}  "
          f"Max nodes: {sim_cfg.max_active_peers}  Years: {sim_cfg.n_years}")
    print()

    # Snapshot years present
    snap_years = [1, 3, 5]

    def _header_for_years() -> str:
        parts = []
        for y in snap_years:
            parts.append(f"tau_y{y}")
            parts.append(f"tau_hon_y{y}")
        return "  ".join(parts)

    def _row_for_years(agg: dict) -> str:
        parts = []
        for y in snap_years:
            if y in agg:
                tau = agg[y]["kendall_tau"]
                tau_h = agg[y]["kendall_tau_honest"]
                parts.append(f"{tau:+.3f}")
                parts.append(f"{tau_h:+.3f}")
            else:
                parts.append("  n/a ")
                parts.append("  n/a ")
        return "  ".join(parts)

    # Group by formula kind
    for kind in [FormulaKind.ADDITIVE, FormulaKind.MULTIPLICATIVE, FormulaKind.HYBRID]:
        kind_results = [(f, agg) for f, agg in all_results if f.kind == kind]
        if not kind_results:
            continue

        if kind == FormulaKind.ADDITIVE:
            print("Formula A (additive): trust = kp*P + ki*I + ks*S")
        elif kind == FormulaKind.MULTIPLICATIVE:
            print("Formula B (multiplicative): trust = (kp*P + ki*I) * clamp(S, 0.1, 1.0)")
        else:
            print("Formula C (hybrid): trust = (kp*P + ki*I) * clamp(S, 0.1, 1.0) + ks_bonus * max(S-1, 0)")

        print(f"  {'Config':<36}  {_header_for_years()}")
        print("  " + "-" * 80)

        for formula, agg in kind_results:
            y5 = agg.get(5, {})
            tau_y5 = y5.get("kendall_tau", float("nan"))
            tau_hon = y5.get("kendall_tau_honest", float("nan"))
            row = _row_for_years(agg)
            print(f"  {formula.label():<36}  {row}")

        print()

    # Best config by tau_y5
    best_formula, best_agg = max(
        all_results,
        key=lambda x: x[1].get(5, {}).get("kendall_tau", -2.0),
    )
    best_y5 = best_agg.get(5, {})

    print("=" * 60)
    print("=== BEST CONFIG ===")
    print(f"Formula {best_formula.kind.value}: {best_formula.label()}")
    print(f"  tau_y5={best_y5.get('kendall_tau', float('nan')):.3f}  "
          f"tau_hon_y5={best_y5.get('kendall_tau_honest', float('nan')):.3f}")
    print()

    # Archetype ranking for best config
    print("=== ARCHETYPE RANKING (best config, year 5) ===")
    arch_trust = best_y5.get("archetype_trust", {})
    arch_trust_h = best_y5.get("archetype_trust_honest", {})

    if arch_trust:
        trust_vals = [arch_trust.get(n, 0.0) for n in ARCHETYPE_NAMES]
        sorted_idx = np.argsort(-np.array(trust_vals))
        formula_ranks = np.empty(N_ARCHETYPES, dtype=int)
        for rank, idx in enumerate(sorted_idx, 1):
            formula_ranks[idx] = rank

        print(f"{'Archetype':<16} {'Trust':>8} {'TrustHon':>9} {'FormulaRank':>12} {'Expected':>8}  Match")
        print("-" * 64)
        for i, name in enumerate(ARCHETYPE_NAMES):
            t_val = arch_trust.get(name, 0.0)
            t_hon = arch_trust_h.get(name, 0.0)
            f_rank = formula_ranks[i]
            e_rank = ACTUAL_USEFULNESS_RANK[i]
            match = "OK" if f_rank == e_rank else f"!= {e_rank}"
            print(f"{name:<16} {t_val:>8.3f} {t_hon:>9.3f} {f_rank:>12d} {e_rank:>8d}  {match}")

    print()

    # Also print best for honest-only tau
    best_hon_formula, best_hon_agg = max(
        all_results,
        key=lambda x: x[1].get(5, {}).get("kendall_tau_honest", -2.0),
    )
    best_hon_y5 = best_hon_agg.get(5, {})
    if best_hon_formula is not best_formula:
        print("=== BEST CONFIG (honest-only tau) ===")
        print(f"Formula {best_hon_formula.kind.value}: {best_hon_formula.label()}")
        print(f"  tau_y5={best_hon_y5.get('kendall_tau', float('nan')):.3f}  "
              f"tau_hon_y5={best_hon_y5.get('kendall_tau_honest', float('nan')):.3f}")
        print()

    # Summary: any config that achieves tau >= 0.9?
    good_configs = [
        (f, agg) for f, agg in all_results
        if agg.get(5, {}).get("kendall_tau", 0.0) >= 0.9
    ]
    if good_configs:
        print(f"=== CONFIGS WITH tau_y5 >= 0.9 ({len(good_configs)} found) ===")
        for f, agg in good_configs:
            y5 = agg.get(5, {})
            print(f"  Formula {f.kind.value}: {f.label()}"
                  f"  tau={y5['kendall_tau']:.3f}  tau_hon={y5['kendall_tau_honest']:.3f}")
    else:
        print("No config achieved tau_y5 >= 0.9.")
        # Show top 5
        top5 = sorted(
            all_results,
            key=lambda x: x[1].get(5, {}).get("kendall_tau", -2.0),
            reverse=True,
        )[:5]
        print("Top 5 by tau_y5:")
        for f, agg in top5:
            y5 = agg.get(5, {})
            print(f"  Formula {f.kind.value}: {f.label()}"
                  f"  tau={y5.get('kendall_tau', float('nan')):.3f}"
                  f"  tau_hon={y5.get('kendall_tau_honest', float('nan')):.3f}")


def save_results(
    all_results: list[tuple[FormulaConfig, dict]],
    sim_cfg: SimConfig,
    n_seeds: int,
    elapsed: float,
    out_dir: Path,
) -> None:
    """Save full results to JSON."""
    out_dir.mkdir(parents=True, exist_ok=True)

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
        "experiment": 22,
        "description": "Multiplicative vs Additive S formula comparison",
        "sim_config": {
            "max_active_peers": sim_cfg.max_active_peers,
            "n_years": sim_cfg.n_years,
            "annual_churn": sim_cfg.annual_churn,
            "target_partners": sim_cfg.target_partners,
            "acceptance_gate": sim_cfg.acceptance_gate,
            "partnership_batch": sim_cfg.partnership_batch,
        },
        "n_seeds": n_seeds,
        "elapsed_sec": elapsed,
        "results": [
            {
                "formula": {
                    "kind": f.kind.value,
                    "kp": f.kp,
                    "ki": f.ki,
                    "ks": f.ks,
                    "ks_bonus": f.ks_bonus,
                    "label": f.label(),
                },
                "aggregated": {str(k): v for k, v in agg.items()},
            }
            for f, agg in all_results
        ],
    }

    out_path = out_dir / "results.json"
    out_path.write_text(json.dumps(_convert(payload), indent=2))
    print(f"\nResults saved to {out_path}", flush=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SyncBack Experiment 22: Multiplicative vs Additive S formula"
    )
    parser.add_argument("--seeds", type=int, default=10,
                        help="Monte Carlo seeds per config")
    parser.add_argument("--jobs", type=int, default=6,
                        help="Parallel jobs")
    parser.add_argument("--max-peers", type=int, default=5_000,
                        help="Max active peers")
    parser.add_argument("--years", type=int, default=5,
                        help="Simulation years")
    parser.add_argument("--output", type=str, default="results/pis_s_formula",
                        help="Output directory")
    args = parser.parse_args()

    print("=== SYNCBACK EXPERIMENT 22: MULTIPLICATIVE vs ADDITIVE S ===", flush=True)
    print(f"Seeds per config: {args.seeds}  Jobs: {args.jobs}  "
          f"Max peers: {args.max_peers}  Years: {args.years}", flush=True)

    sim_cfg = SimConfig(
        max_active_peers=args.max_peers,
        n_years=args.years,
    )

    formula_grid = _build_formula_grid()
    n_configs = len(formula_grid)
    print(f"Total configs: {n_configs}", flush=True)
    print(f"Total simulations: {n_configs * args.seeds}", flush=True)
    print()

    t0 = time.time()
    all_results: list[tuple[FormulaConfig, dict]] = []

    for i, formula in enumerate(formula_grid):
        t_cfg = time.time()
        print(
            f"[{i+1}/{n_configs}] Formula {formula.kind.value}: {formula.label()} ...",
            end=" ",
            flush=True,
        )
        agg = run_formula_config(formula, sim_cfg, args.seeds, args.jobs)
        elapsed_cfg = time.time() - t_cfg

        # Quick inline result
        y5 = agg.get(5, {})
        tau_y5 = y5.get("kendall_tau", float("nan"))
        tau_hon = y5.get("kendall_tau_honest", float("nan"))
        print(f"tau_y5={tau_y5:+.3f}  tau_hon={tau_hon:+.3f}  [{elapsed_cfg:.1f}s]",
              flush=True)

        all_results.append((formula, agg))

    elapsed = time.time() - t0

    print_results(all_results, sim_cfg, args.seeds, elapsed)
    save_results(all_results, sim_cfg, args.seeds, elapsed, Path(args.output))


if __name__ == "__main__":
    main()
