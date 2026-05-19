"""
Viaticum Simulation #6: Mass Departure (Shock Event)

Question: What happens when 30-50% of network leaves simultaneously?
How does instant shock compare to gradual churn of the same magnitude?

Model:
- Network of N peers with established trust (6 months of honest operation)
- At time T_shock, a fraction of peers leaves (no prior warning)
- Departure modes:
    instant      — all selected peers vanish at T_shock
    gradual_3mo  — selected peers depart uniformly over 13 weeks post-shock
    gradual_6mo  — selected peers depart uniformly over 26 weeks post-shock
    death_scream — instant departure but departing peers notify; repair starts
                   immediately (no repair delay for affected shards)
- After shock: remaining peers discover missing shards in next repair cycle,
  begin rebuilding under capacity and trust constraints
- D-component monitors partner trend, triggers early repair when D < d_threshold
- Key dynamic: after 50% shock, each surviving peer must absorb ~2x storage.
  Capacity constraint: max_shards_per_peer limits successful repair.

Key metrics:
- file_survival_rate        fraction of files alive at end of simulation
- file_survival_at_shock    fraction immediately after shock (before repair)
- recovery_time_weeks       weeks until survival rate stabilizes (within 0.5%)
- repair_traffic_shards     total shards replaced during recovery phase
- files_permanently_lost    files that drop below k shards at shock and can't recover

Usage:
    python mass_departure.py                          # default run
    python mass_departure.py --shock-fraction 0.5     # 50% departure
    python mass_departure.py --mode gradual_3mo       # gradual churn
    python mass_departure.py --sweep --jobs 8         # parameter sweep
"""

import argparse
import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path

import numpy as np
from joblib import Parallel, delayed


@dataclass
class Config:
    n_peers: int = 500
    n_files: int = 1000
    n_seeds: int = 100
    # Erasure coding
    k: int = 5
    n_shards: int = 15
    # Simulation timeline (in weeks)
    buildup_weeks: int = 26         # 6 months of trust accumulation
    total_weeks: int = 52           # 12 months total (shock at week 26)
    # Shock parameters
    shock_fraction: float = 0.3     # fraction of peers that depart
    departure_mode: str = "instant" # instant | gradual_3mo | gradual_6mo | death_scream
    # PID parameters (Kp=0.5, Ki=2.0 from experiment 1)
    kp: float = 0.5
    ki: float = 2.0
    p_window: int = 4               # rolling window in weeks (approx 30 days)
    d_threshold: float = -0.01      # D-trigger: repair when D < this
    # Peer reliability
    peer_reliability: float = 0.95  # honest peer weekly check-in probability
    # Repair
    repair_delay_weeks: int = 1     # repair takes 1 cycle (cold backup = weekly)
    # Capacity: max shards a single peer can hold
    max_shards_per_peer: int = 100
    # Shard size for traffic estimation (GB per shard)
    shard_size_gb: float = 0.1


def _compute_trust(
    checks_history: np.ndarray,   # shape (n_weeks_filled, n_peers)
    cumulative_i: np.ndarray,      # shape (n_peers,)
    n_total_weeks: int,
    config: Config,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Return (trust, p_score, d_score) for all peers.

    trust = kp * P + ki * I
    P = rolling window mean of recent checks (last p_window weeks)
    I = cumulative average (all history)
    D = p_score_current - p_score_previous (trend signal)
    """
    n_peers = checks_history.shape[1]
    filled = checks_history.shape[0]

    # P: rolling window
    window = min(config.p_window, filled)
    if window > 0:
        p_score = checks_history[-window:].mean(axis=0)
    else:
        p_score = np.full(n_peers, 0.5)

    # D: change relative to previous window
    if filled >= 2:
        prev_window = min(config.p_window, filled - 1)
        p_prev = checks_history[-(prev_window + 1):-1].mean(axis=0)
        d_score = p_score - p_prev
    else:
        d_score = np.zeros(n_peers)

    trust = config.kp * p_score + config.ki * cumulative_i
    return trust, p_score, d_score


def simulate_one(config: Config, seed: int) -> dict:
    """Run one mass departure simulation. Returns per-run metrics."""
    rng = np.random.default_rng(seed)

    n_peers = config.n_peers
    n_files = config.n_files
    shock_week = config.buildup_weeks

    # --- Peer state ---
    # peer_online[i] = True means peer i is available
    peer_online = np.ones(n_peers, dtype=bool)

    # Peer capacity: how many shards each peer currently holds
    peer_load = np.zeros(n_peers, dtype=np.int32)

    # --- PID trust state ---
    # checks_buf: circular buffer of weekly check results, shape (p_window+2, n_peers)
    buf_size = config.p_window + 4
    checks_buf = np.zeros((buf_size, n_peers))
    buf_idx = 0
    buf_filled = 0
    cumulative_i = np.full(n_peers, 0.5)  # start with neutral trust

    # --- Place files at start (flat trust, all peers online) ---
    # Each file: list of peer_id holding a shard; len == n_shards
    file_shards: list[list[int]] = []
    for _ in range(n_files):
        holders = list(rng.choice(n_peers, size=config.n_shards, replace=False))
        file_shards.append(holders)
        for pid in holders:
            peer_load[pid] += 1

    file_alive = np.ones(n_files, dtype=bool)

    # --- Departure schedule ---
    # For gradual modes: departed_at[i] = week peer i departs (-1 = never departs)
    departure_week = np.full(n_peers, -1, dtype=np.int32)

    # Select which peers will depart
    n_departing = max(1, int(round(config.shock_fraction * n_peers)))
    departing_peers = rng.choice(n_peers, size=n_departing, replace=False)

    if config.departure_mode == "instant" or config.departure_mode == "death_scream":
        departure_week[departing_peers] = shock_week
    elif config.departure_mode == "gradual_3mo":
        # Spread over 13 weeks starting at shock_week
        weeks = rng.integers(shock_week, shock_week + 13, size=n_departing)
        departure_week[departing_peers] = weeks
    elif config.departure_mode == "gradual_6mo":
        # Spread over 26 weeks starting at shock_week
        weeks = rng.integers(shock_week, shock_week + 26, size=n_departing)
        departure_week[departing_peers] = weeks
    else:
        raise ValueError(f"Unknown departure_mode: {config.departure_mode!r}")

    # --- Metrics ---
    weekly_survival: list[float] = []
    repair_traffic_shards = 0
    file_survival_at_shock: float = 0.0
    files_permanently_lost = 0
    shock_recorded = False

    # Pending repairs: list of (file_idx, completion_week, new_holders)
    # For death_scream: completion_week = shock_week (immediate)
    pending_repairs: list[tuple[int, int, list[int]]] = []

    # --- Main simulation loop ---
    for week in range(config.total_weeks):

        # === 1. Update peer departures ===
        departing_now = np.where(departure_week == week)[0]
        for pid in departing_now:
            peer_online[pid] = False
            # Release capacity (shards will be detected missing on next repair cycle)
            # We don't update peer_load here — the load will be adjusted when
            # shards are pruned during repair cycle detection.

        # === 2. Run weekly proof-of-storage checks (for trust tracking) ===
        # Departed peers always fail; online peers pass with peer_reliability
        checks = np.where(
            peer_online,
            (rng.random(n_peers) < config.peer_reliability).astype(np.float64),
            0.0,
        )

        # Update circular buffer
        checks_buf[buf_idx % buf_size] = checks
        buf_idx += 1
        buf_filled = min(buf_filled + 1, buf_size)

        # Compute trust and D-component
        # Build ordered slice for the history (last buf_filled entries)
        start = (buf_idx - buf_filled) % buf_size
        if start + buf_filled <= buf_size:
            history_slice = checks_buf[start:start + buf_filled]
        else:
            # Wrapped: concatenate
            history_slice = np.concatenate([
                checks_buf[start:],
                checks_buf[:buf_idx % buf_size],
            ], axis=0)

        trust, p_score, d_score = _compute_trust(
            history_slice, cumulative_i, week, config
        )

        # Update cumulative I
        cumulative_i = (cumulative_i * week + checks) / (week + 1)

        # === 3. Complete pending repairs ===
        still_pending: list[tuple[int, int, list[int]]] = []
        for fidx, comp_week, new_holders in pending_repairs:
            if week >= comp_week and file_alive[fidx]:
                for pid in new_holders:
                    if peer_online[pid] and peer_load[pid] < config.max_shards_per_peer:
                        if len(file_shards[fidx]) < config.n_shards:
                            file_shards[fidx].append(pid)
                            peer_load[pid] += 1
                            repair_traffic_shards += 1
            elif week < comp_week:
                still_pending.append((fidx, comp_week, new_holders))
        pending_repairs = still_pending

        # === 4. Detect missing shards and trigger repairs (weekly cycle) ===
        online_set: set[int] = set(int(pid) for pid in np.where(peer_online)[0])

        # Build eligible peers for repair (online, not over capacity)
        eligible_for_repair = [
            pid for pid in online_set
            if peer_load[pid] < config.max_shards_per_peer
        ]

        # Trust-weighted selection pool (for repair target selection)
        if eligible_for_repair:
            eligible_arr = np.array(eligible_for_repair, dtype=np.int32)
            eligible_trust = trust[eligible_arr]
            eligible_trust = np.maximum(eligible_trust, 0.0)
            trust_total = eligible_trust.sum()
        else:
            eligible_arr = np.array([], dtype=np.int32)
            trust_total = 0.0

        for fidx in range(n_files):
            if not file_alive[fidx]:
                continue

            # Find live shards
            live = [pid for pid in file_shards[fidx] if pid in online_set]
            n_live = len(live)

            if n_live < config.k:
                # File is permanently lost — can't reconstruct
                file_alive[fidx] = False
                # Release load for shards that are on surviving peers
                for pid in live:
                    peer_load[pid] = max(0, peer_load[pid] - 1)
                continue

            # Update shard list to only live shards, adjust load for departed
            old_holders = set(file_shards[fidx])
            departed_holders = old_holders - online_set
            for pid in departed_holders:
                # peer_load for departed peers is no longer meaningful, but
                # we zero it out to avoid stale counts
                pass  # load already meaningless for offline peers
            file_shards[fidx] = live

            # Determine how many shards need repair
            missing = config.n_shards - n_live

            # D-trigger: preemptively replace shards from declining peers
            # (replicate before they go fully offline)
            if week >= shock_week:
                d_suspect = [
                    pid for pid in live
                    if d_score[pid] < config.d_threshold
                ]
                # Preemptive replacement count (don't double-count truly missing)
                preemptive = len(d_suspect)
                missing = min(config.n_shards - n_live + preemptive, config.n_shards)

            if missing <= 0 or trust_total <= 0.0 or len(eligible_arr) == 0:
                continue

            # Select new shard holders (trust-weighted, not already holding)
            current_set = set(file_shards[fidx])
            candidates_mask = np.array([
                pid for pid in eligible_for_repair if pid not in current_set
            ], dtype=np.int32)

            if len(candidates_mask) == 0:
                continue

            cand_trust = trust[candidates_mask]
            cand_trust = np.maximum(cand_trust, 0.0)
            cand_total = cand_trust.sum()
            if cand_total <= 0.0:
                continue

            n_new = min(missing, len(candidates_mask))
            probs = cand_trust / cand_total
            chosen = rng.choice(
                candidates_mask, size=n_new, replace=False, p=probs
            )

            # Completion: death_scream = immediate, else +repair_delay
            if config.departure_mode == "death_scream" and week == shock_week:
                comp_week = week  # immediate (same week)
            else:
                comp_week = week + config.repair_delay_weeks

            # Reserve capacity now (optimistic reservation)
            chosen_list: list[int] = []
            for pid in chosen:
                if peer_load[pid] < config.max_shards_per_peer:
                    peer_load[pid] += 1
                    chosen_list.append(int(pid))

            if chosen_list:
                pending_repairs.append((fidx, comp_week, chosen_list))

        # === 5. Record metrics ===
        alive_count = int(file_alive.sum())
        survival_frac = alive_count / n_files
        weekly_survival.append(survival_frac)

        # Record survival immediately after shock (before any repair completes)
        if week == shock_week and not shock_recorded:
            file_survival_at_shock = survival_frac
            # Count files permanently lost at shock moment
            files_permanently_lost = n_files - alive_count
            shock_recorded = True

    # --- Compute recovery time ---
    # Weeks until weekly survival stabilizes (change < 0.5% for 3 consecutive weeks)
    recovery_time_weeks: int = -1
    if len(weekly_survival) > shock_week + 3:
        post_shock = weekly_survival[shock_week:]
        final_val = post_shock[-1]
        stabilized_since = 0
        for i, val in enumerate(post_shock):
            if abs(val - final_val) < 0.005:
                stabilized_since += 1
                if stabilized_since >= 3 and recovery_time_weeks < 0:
                    recovery_time_weeks = i - 2  # first of the 3 stable weeks
            else:
                stabilized_since = 0

    final_survival = weekly_survival[-1] if weekly_survival else 0.0

    return {
        "file_survival_rate": final_survival,
        "file_survival_at_shock": file_survival_at_shock,
        "recovery_time_weeks": recovery_time_weeks,
        "repair_traffic_shards": repair_traffic_shards,
        "repair_traffic_gb": repair_traffic_shards * config.shard_size_gb,
        "files_permanently_lost": files_permanently_lost,
        "weekly_survival": weekly_survival,
    }


def run_experiment(config: Config, n_jobs: int = 1) -> dict:
    """Run Monte Carlo experiment across seeds."""
    t0 = time.time()

    if n_jobs == 1:
        results = [simulate_one(config, seed) for seed in range(config.n_seeds)]
    else:
        results = Parallel(n_jobs=n_jobs)(
            delayed(simulate_one)(config, seed)
            for seed in range(config.n_seeds)
        )

    elapsed = time.time() - t0

    survival_rates = [r["file_survival_rate"] for r in results]
    at_shock = [r["file_survival_at_shock"] for r in results]
    rec_times = [r["recovery_time_weeks"] for r in results]
    traffic = [r["repair_traffic_gb"] for r in results]
    perm_lost = [r["files_permanently_lost"] for r in results]

    # Valid recovery times (exclude -1 = never stabilized)
    valid_rec = [t for t in rec_times if t >= 0]

    # Weekly survival curve: mean across seeds
    n_weeks = len(results[0]["weekly_survival"]) if results else 0
    weekly_mean: list[float] = []
    weekly_p5: list[float] = []
    weekly_p95: list[float] = []
    for w in range(n_weeks):
        vals = [r["weekly_survival"][w] for r in results if w < len(r["weekly_survival"])]
        weekly_mean.append(float(np.mean(vals)))
        weekly_p5.append(float(np.percentile(vals, 5)))
        weekly_p95.append(float(np.percentile(vals, 95)))

    return {
        "config": asdict(config),
        "elapsed_sec": elapsed,
        # Survival at end of simulation
        "survival_rate_mean": float(np.mean(survival_rates)),
        "survival_rate_std": float(np.std(survival_rates)),
        "survival_rate_p5": float(np.percentile(survival_rates, 5)),
        "survival_rate_p95": float(np.percentile(survival_rates, 95)),
        "survival_rate_min": float(np.min(survival_rates)),
        # Survival immediately after shock (before repair)
        "survival_at_shock_mean": float(np.mean(at_shock)),
        "survival_at_shock_p5": float(np.percentile(at_shock, 5)),
        # Recovery time
        "recovery_time_mean": float(np.mean(valid_rec)) if valid_rec else -1.0,
        "recovery_time_p95": float(np.percentile(valid_rec, 95)) if valid_rec else -1.0,
        "fraction_never_stabilized": float(sum(1 for t in rec_times if t < 0)) / len(rec_times),
        # Repair traffic
        "repair_traffic_gb_mean": float(np.mean(traffic)),
        "repair_traffic_gb_p95": float(np.percentile(traffic, 95)),
        # Files permanently lost
        "files_perm_lost_mean": float(np.mean(perm_lost)),
        "files_perm_lost_p95": float(np.percentile(perm_lost, 95)),
        # Time series
        "weekly_survival_mean": weekly_mean,
        "weekly_survival_p5": weekly_p5,
        "weekly_survival_p95": weekly_p95,
    }


def print_summary(result: dict) -> None:
    """Print key shock event metrics."""
    cfg = result["config"]
    mode = cfg["departure_mode"]
    shock_pct = cfg["shock_fraction"] * 100

    print(f"Config: {cfg['n_peers']} peers, {cfg['n_files']} files, "
          f"{cfg['k']}-of-{cfg['n_shards']} erasure")
    print(f"Shock: {shock_pct:.0f}% departure ({mode}), "
          f"at month {cfg['buildup_weeks'] // 4}, "
          f"total {cfg['total_weeks'] // 4} months")
    print(f"Capacity: {cfg['max_shards_per_peer']} shards/peer, "
          f"repair delay: {cfg['repair_delay_weeks']}w")
    print(f"Seeds: {cfg['n_seeds']}, runtime: {result['elapsed_sec']:.1f}s")
    print()

    print(f"Survival at shock (before repair): "
          f"{result['survival_at_shock_mean']*100:.2f}% "
          f"(p5={result['survival_at_shock_p5']*100:.1f}%)")
    print(f"Files permanently lost at shock:   "
          f"{result['files_perm_lost_mean']:.1f} "
          f"(p95={result['files_perm_lost_p95']:.0f})")
    print()

    surv = result["survival_rate_mean"]
    print(f"Final survival rate:  {surv*100:.2f}% "
          f"(p5={result['survival_rate_p5']*100:.1f}%, "
          f"min={result['survival_rate_min']*100:.1f}%)")

    if result["recovery_time_mean"] >= 0:
        rec = result["recovery_time_mean"]
        print(f"Recovery time:       {rec:.1f} weeks "
              f"(p95={result['recovery_time_p95']:.0f}w, "
              f"never={result['fraction_never_stabilized']*100:.1f}%)")
    else:
        print(f"Recovery time:       never stabilized "
              f"({result['fraction_never_stabilized']*100:.1f}% of runs)")

    print(f"Repair traffic:      {result['repair_traffic_gb_mean']:.1f} GB "
          f"(p95={result['repair_traffic_gb_p95']:.1f} GB)")

    print()
    print("Weekly survival (shock month highlighted):")
    mean_w = result["weekly_survival_mean"]
    shock_wk = cfg["buildup_weeks"]
    for w in range(0, len(mean_w), 4):
        marker = " <-- SHOCK" if w == shock_wk else ""
        print(f"  Week {w:>3} (mo {w//4}): {mean_w[w]*100:.1f}%{marker}")


def save_results(result: dict, path: Path) -> None:
    """Save results to JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2))
    print(f"\nResults saved to {path}")


def _evaluate_sweep(
    n_peers: int,
    n_files: int,
    k: int,
    n_shards: int,
    shock_fraction: float,
    departure_mode: str,
    n_seeds: int,
    buildup_weeks: int,
    total_weeks: int,
    max_shards_per_peer: int,
    kp: float,
    ki: float,
) -> dict:
    """Evaluate one config for sweep (runs in its own process)."""
    cfg = Config(
        n_peers=n_peers,
        n_files=n_files,
        k=k,
        n_shards=n_shards,
        shock_fraction=shock_fraction,
        departure_mode=departure_mode,
        n_seeds=n_seeds,
        buildup_weeks=buildup_weeks,
        total_weeks=total_weeks,
        max_shards_per_peer=max_shards_per_peer,
        kp=kp,
        ki=ki,
    )
    res = run_experiment(cfg, n_jobs=1)
    return {
        "shock_fraction": shock_fraction,
        "departure_mode": departure_mode,
        "k": k,
        "n_shards": n_shards,
        "survival_rate": res["survival_rate_mean"],
        "survival_at_shock": res["survival_at_shock_mean"],
        "files_perm_lost": res["files_perm_lost_mean"],
        "recovery_time": res["recovery_time_mean"],
        "fraction_never_stabilized": res["fraction_never_stabilized"],
        "repair_traffic_gb": res["repair_traffic_gb_mean"],
        "survival_rate_p5": res["survival_rate_p5"],
        "survival_rate_min": res["survival_rate_min"],
    }


def run_sweep(base_config: Config, output_dir: Path, n_jobs: int = 1) -> None:
    """Sweep shock_fraction x departure_mode x erasure profile."""
    shock_fractions = [0.1, 0.2, 0.3, 0.5, 0.7]
    departure_modes = ["instant", "gradual_3mo", "gradual_6mo", "death_scream"]
    erasure_profiles = [(5, 15), (7, 10)]

    tasks: list[tuple] = []
    for k, n_shards in erasure_profiles:
        for shock_fraction in shock_fractions:
            for mode in departure_modes:
                tasks.append((
                    base_config.n_peers,
                    base_config.n_files,
                    k,
                    n_shards,
                    shock_fraction,
                    mode,
                    30,  # fewer seeds for sweep
                    base_config.buildup_weeks,
                    base_config.total_weeks,
                    base_config.max_shards_per_peer,
                    base_config.kp,
                    base_config.ki,
                ))

    total = len(tasks)
    print(f"Sweep: {total} configs ({len(erasure_profiles)} erasure x "
          f"{len(shock_fractions)} fractions x {len(departure_modes)} modes), "
          f"{n_jobs} jobs\n")

    if n_jobs == 1:
        results_table: list[dict] = []
        for i, t in enumerate(tasks, 1):
            r = _evaluate_sweep(*t)
            results_table.append(r)
            rec_str = (f"{r['recovery_time']:.0f}w"
                       if r["recovery_time"] >= 0 else "never")
            print(f"  [{i:>3}/{total}] "
                  f"{r['k']}-of-{r['n_shards']:>2} "
                  f"shock={r['shock_fraction']*100:>2.0f}% "
                  f"{r['departure_mode']:<14} "
                  f"surv={r['survival_rate']*100:>6.2f}% "
                  f"(p5={r['survival_rate_p5']*100:>5.1f}%) "
                  f"lost={r['files_perm_lost']:>6.1f} "
                  f"rec={rec_str}")
    else:
        t0 = time.time()
        results_table = Parallel(n_jobs=n_jobs, verbose=10)(
            delayed(_evaluate_sweep)(*t) for t in tasks
        )
        elapsed = time.time() - t0
        print(f"\nSweep completed in {elapsed:.1f}s")
        for r in results_table:
            rec_str = (f"{r['recovery_time']:.0f}w"
                       if r["recovery_time"] >= 0 else "never")
            print(f"  {r['k']}-of-{r['n_shards']:>2} "
                  f"shock={r['shock_fraction']*100:>2.0f}% "
                  f"{r['departure_mode']:<14} "
                  f"surv={r['survival_rate']*100:>6.2f}% "
                  f"lost={r['files_perm_lost']:>6.1f} "
                  f"rec={rec_str}")

    # Sort by survival rate (worst first for analysis)
    results_table_sorted = sorted(results_table, key=lambda r: r["survival_rate"])

    print("\n=== WORST CONFIGURATIONS (lowest survival) ===")
    print(f"{'k-n':>5} {'shock%':>7} {'mode':<14} "
          f"{'surv%':>7} {'p5%':>6} {'lost':>6} "
          f"{'rec_w':>6} {'traffic_gb':>10}")
    for r in results_table_sorted[:15]:
        rec_str = f"{r['recovery_time']:>5.0f}" if r["recovery_time"] >= 0 else "never "
        print(f"{r['k']}-{r['n_shards']:>2} "
              f"{r['shock_fraction']*100:>6.0f}% "
              f"{r['departure_mode']:<14} "
              f"{r['survival_rate']*100:>6.2f}% "
              f"{r['survival_rate_p5']*100:>5.1f}% "
              f"{r['files_perm_lost']:>5.1f} "
              f"{rec_str} "
              f"{r['repair_traffic_gb']:>9.1f}")

    # Compare instant vs death_scream for the same shock_fraction
    print("\n=== INSTANT vs DEATH_SCREAM COMPARISON ===")
    print(f"{'k-n':>5} {'shock%':>7} {'mode':<14} "
          f"{'surv%':>7} {'lost':>6} {'rec_w':>6}")
    for k, n_shards in erasure_profiles:
        for sf in shock_fractions:
            for mode in ["instant", "death_scream"]:
                matching = [
                    r for r in results_table
                    if r["k"] == k and r["n_shards"] == n_shards
                    and abs(r["shock_fraction"] - sf) < 1e-9
                    and r["departure_mode"] == mode
                ]
                if matching:
                    r = matching[0]
                    rec_str = (f"{r['recovery_time']:>5.0f}"
                               if r["recovery_time"] >= 0 else "never ")
                    print(f"{r['k']}-{r['n_shards']:>2} "
                          f"{r['shock_fraction']*100:>6.0f}% "
                          f"{r['departure_mode']:<14} "
                          f"{r['survival_rate']*100:>6.2f}% "
                          f"{r['files_perm_lost']:>5.1f} "
                          f"{rec_str}")

    # Compare instant vs gradual for same magnitude
    print("\n=== INSTANT vs GRADUAL COMPARISON ===")
    print(f"{'k-n':>5} {'shock%':>7} {'mode':<14} "
          f"{'surv%':>7} {'lost':>6} {'rec_w':>6}")
    for k, n_shards in erasure_profiles:
        for sf in shock_fractions:
            for mode in ["instant", "gradual_3mo", "gradual_6mo"]:
                matching = [
                    r for r in results_table
                    if r["k"] == k and r["n_shards"] == n_shards
                    and abs(r["shock_fraction"] - sf) < 1e-9
                    and r["departure_mode"] == mode
                ]
                if matching:
                    r = matching[0]
                    rec_str = (f"{r['recovery_time']:>5.0f}"
                               if r["recovery_time"] >= 0 else "never ")
                    print(f"{r['k']}-{r['n_shards']:>2} "
                          f"{r['shock_fraction']*100:>6.0f}% "
                          f"{r['departure_mode']:<14} "
                          f"{r['survival_rate']*100:>6.2f}% "
                          f"{r['files_perm_lost']:>5.1f} "
                          f"{rec_str}")

    sweep_path = output_dir / "sweep_results.json"
    sweep_path.parent.mkdir(parents=True, exist_ok=True)
    sweep_path.write_text(json.dumps(results_table, indent=2))
    print(f"\nFull sweep saved to {sweep_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mass Departure Shock Event Simulation"
    )
    parser.add_argument("--peers", type=int, default=500)
    parser.add_argument("--files", type=int, default=1000)
    parser.add_argument("--seeds", type=int, default=100)
    parser.add_argument("--k", type=int, default=5)
    parser.add_argument("--n-shards", type=int, default=15)
    parser.add_argument(
        "--shock-fraction", type=float, default=0.3,
        help="Fraction of peers that depart (0.0-1.0)"
    )
    parser.add_argument(
        "--mode", type=str, default="instant",
        choices=["instant", "gradual_3mo", "gradual_6mo", "death_scream"],
        help="Departure mode"
    )
    parser.add_argument(
        "--buildup-weeks", type=int, default=26,
        help="Weeks of trust buildup before shock (default: 26 = 6 months)"
    )
    parser.add_argument(
        "--total-weeks", type=int, default=52,
        help="Total simulation weeks (default: 52 = 12 months)"
    )
    parser.add_argument(
        "--max-shards-per-peer", type=int, default=100,
        help="Storage capacity per peer in shards"
    )
    parser.add_argument("--kp", type=float, default=0.5)
    parser.add_argument("--ki", type=float, default=2.0)
    parser.add_argument("--d-threshold", type=float, default=-0.01,
                        help="D-trigger threshold for early repair")
    parser.add_argument("--sweep", action="store_true",
                        help="Run parameter sweep")
    parser.add_argument("--jobs", type=int, default=1,
                        help="Parallel jobs (cores)")
    parser.add_argument("--output", type=str, default="results/mass_departure",
                        help="Output directory for results")
    args = parser.parse_args()

    output_dir = Path(args.output)

    config = Config(
        n_peers=args.peers,
        n_files=args.files,
        n_seeds=args.seeds,
        k=args.k,
        n_shards=args.n_shards,
        shock_fraction=args.shock_fraction,
        departure_mode=args.mode,
        buildup_weeks=args.buildup_weeks,
        total_weeks=args.total_weeks,
        max_shards_per_peer=args.max_shards_per_peer,
        kp=args.kp,
        ki=args.ki,
        d_threshold=args.d_threshold,
    )

    if args.sweep:
        sweep_out = Path(args.output + "_sweep") if args.output == "results/mass_departure" \
            else Path(args.output)
        print("=== MASS DEPARTURE PARAMETER SWEEP ===\n")
        run_sweep(config, sweep_out, n_jobs=args.jobs)
    else:
        print("=== MASS DEPARTURE SIMULATION ===\n")
        result = run_experiment(config, n_jobs=args.jobs)
        print_summary(result)
        save_results(result, output_dir / "run.json")


if __name__ == "__main__":
    main()
