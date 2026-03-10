"""
SyncBack Simulation #8: Storage Lie + Proof-of-Storage

Question: How quickly does proof-of-storage detect liars, and does repair
outpace the lie?

Model:
- Network of N honest peers + L liars
- Honest peers: store shards, pass proof-of-storage checks (reliability 0.95)
- Liars: accept shards, wait T_lie_delay days, then delete the shard to free
  space. Continue passing availability pings. Fail proof-of-storage challenges
  after deletion. May accept new shards and repeat the lie.
- Proof-of-storage runs at configurable intervals (7/14/30 days)
- Two repair strategies compared:
  A) PI-only: repair when trust drops below pi_threshold (lagging indicator)
  B) PID-trigger: repair when D < d_threshold (leading indicator — catches the
     P drop from passing to failing before trust fully decays)
- Erasure coding: 5-of-15 shards per file

Key race: liar deletes shard -> undetected gap -> check fires -> detection ->
repair. File is lost if >= (n - k + 1) shards are simultaneously lost and
the protocol has not yet repaired them.

Usage:
    python storage_lie.py                      # default single run
    python storage_lie.py --sweep --jobs 8    # parameter sweep
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
    # Network
    n_honest: int = 450
    n_liars: int = 50
    n_files: int = 500
    n_days: int = 365       # 12-month simulation
    n_seeds: int = 100
    # Erasure coding (5-of-15 profile)
    k: int = 5
    n_shards: int = 15
    # Honest peer reliability (proof-of-storage pass rate)
    honest_reliability: float = 0.95
    # Liar behaviour
    lie_delay_days: int = 30    # days after accepting shard before deletion
    # Detection
    check_interval_days: int = 7   # how often proof-of-storage runs
    # Repair
    repair_delay_days: int = 7     # days from detection to repair completion
    # Trust / PID parameters
    kp: float = 0.5
    ki: float = 2.0
    p_window: int = 30            # rolling window for P component (days)
    pi_threshold: float = 0.6     # PI: repair when trust < this
    d_threshold: float = -0.01    # PID: repair when D < this (negative = dropping)
    # Repair strategy: "pi_only" or "pid_trigger"
    repair_strategy: str = "pid_trigger"
    # Setup phase (days): honest initial period so liars can accumulate trust
    setup_days: int = 30


# ---------------------------------------------------------------------------
# Per-strategy file state — holds shard assignment independently
# ---------------------------------------------------------------------------

class FileState:
    """Tracks shard holders for one repair strategy, for all files."""

    def __init__(self, initial: list[list[int]]) -> None:
        # Deep copy so strategies are fully independent
        self.shards: list[list[int]] = [list(h) for h in initial]

    def remove_peer(self, fidx: int, pid: int) -> None:
        try:
            self.shards[fidx].remove(pid)
        except ValueError:
            pass

    def add_peer(self, fidx: int, pid: int) -> None:
        if pid not in self.shards[fidx]:
            self.shards[fidx].append(pid)

    def holders(self, fidx: int) -> list[int]:
        return self.shards[fidx]


# ---------------------------------------------------------------------------
# Core simulation
# ---------------------------------------------------------------------------

def simulate_one(config: Config, seed: int) -> dict:
    """Run one storage-lie simulation. Returns per-run metrics."""
    rng = np.random.default_rng(seed)

    n_total = config.n_honest + config.n_liars
    is_liar = np.zeros(n_total, dtype=bool)
    is_liar[config.n_honest:] = True
    honest_set = set(range(config.n_honest))

    # -----------------------------------------------------------------------
    # Trust tracking (per peer, observer's perspective)
    # trust(p) = kp * P + ki * I, D = change in P per step
    # -----------------------------------------------------------------------
    p_score = np.full(n_total, config.honest_reliability)
    i_score = np.full(n_total, config.honest_reliability)
    d_score = np.zeros(n_total)
    prev_p = np.full(n_total, config.honest_reliability)
    window_buf = np.ones((config.p_window, n_total)) * config.honest_reliability

    # -----------------------------------------------------------------------
    # File placement: each file has n_shards holders chosen uniformly.
    # During setup_days, liars behave honestly, building initial trust.
    # -----------------------------------------------------------------------
    all_peers = np.arange(n_total)
    initial_shards: list[list[int]] = []
    for _ in range(config.n_files):
        holders = list(
            rng.choice(all_peers, size=config.n_shards, replace=False)
        )
        initial_shards.append(holders)

    # Each strategy gets its own independent copy of file->shard assignments
    state_pi = FileState(initial_shards)
    state_pid = FileState(initial_shards)

    file_alive_pi = np.ones(config.n_files, dtype=bool)
    file_alive_pid = np.ones(config.n_files, dtype=bool)

    # -----------------------------------------------------------------------
    # Liar shard state: shard_delete_day[pid][fidx] = day liar deletes shard
    # Deletion is scheduled at (accept_day + lie_delay_days).
    # -----------------------------------------------------------------------
    shard_delete_day: dict[int, dict[int, int]] = {
        pid: {} for pid in range(config.n_honest, n_total)
    }

    def schedule_deletion(pid: int, fidx: int, accept_day: int) -> None:
        shard_delete_day[pid][fidx] = accept_day + config.lie_delay_days

    def liar_has_shard(pid: int, fidx: int, day: int) -> bool:
        if fidx not in shard_delete_day[pid]:
            return True   # not yet accepted or already evicted
        return day < shard_delete_day[pid][fidx]

    # Schedule initial deletions: shards given at placement, liar deletes
    # after setup_days + lie_delay_days
    for fidx, holders in enumerate(initial_shards):
        for pid in holders:
            if is_liar[pid]:
                schedule_deletion(pid, fidx, accept_day=config.setup_days)

    # -----------------------------------------------------------------------
    # Pending repairs: (file_idx, completion_day, new_peer_id)
    # -----------------------------------------------------------------------
    pending_pi: list[tuple[int, int, int]] = []
    pending_pid: list[tuple[int, int, int]] = []

    # -----------------------------------------------------------------------
    # Metrics
    # -----------------------------------------------------------------------
    detection_delays: list[float] = []
    recorded_delays: set[tuple[int, int]] = set()   # prevent double-counting
    repairs_pi = 0
    repairs_pid = 0
    # Track actual deletion day for detection-delay measurement
    actual_deletion: dict[tuple[int, int], int] = {}

    # -----------------------------------------------------------------------
    # Main simulation loop — steps of check_interval_days
    # -----------------------------------------------------------------------
    step = config.check_interval_days

    for day in range(0, config.n_days, step):
        day_end = min(day + step, config.n_days)

        # -------------------------------------------------------------------
        # Simulate daily trust checks for the full step window.
        # Liar reliability = fraction of their assigned shards still held.
        # This models the proof-of-storage challenge: challenge a random shard;
        # liar can only pass if that shard hasn't been deleted yet.
        # -------------------------------------------------------------------
        for t in range(day, day_end):
            # Vectorised: honest peers use honest_reliability
            checks = (rng.random(n_total) < config.honest_reliability).astype(
                np.float64
            )

            # Override for liars past setup phase
            if t >= config.setup_days:
                for pid in range(config.n_honest, n_total):
                    assigned = list(shard_delete_day[pid].keys())
                    if assigned:
                        held = sum(
                            1 for fidx in assigned if liar_has_shard(pid, fidx, t)
                        )
                        liar_rel = held / len(assigned)
                    else:
                        liar_rel = 1.0
                    checks[pid] = 1.0 if rng.random() < liar_rel else 0.0

            # Update rolling window P
            slot = t % config.p_window
            window_buf[slot] = checks
            filled = min(t + 1, config.p_window)
            p_score[:] = window_buf[:filled].mean(axis=0)

            # Update cumulative I (incremental average)
            i_score[:] = (i_score * t + checks) / (t + 1)

        # D = change in P from previous check cycle
        d_score[:] = p_score - prev_p
        prev_p[:] = p_score.copy()

        # -------------------------------------------------------------------
        # Record actual deletion events that occurred in this window
        # (before day_end) — needed for detection-delay measurement
        # -------------------------------------------------------------------
        for pid in range(config.n_honest, n_total):
            for fidx, del_day in shard_delete_day[pid].items():
                if day <= del_day < day_end:
                    actual_deletion[(pid, fidx)] = del_day

        # -------------------------------------------------------------------
        # Complete pending repairs
        # -------------------------------------------------------------------
        next_pi: list[tuple[int, int, int]] = []
        for (fidx, comp_day, new_pid) in pending_pi:
            if day_end >= comp_day:
                if file_alive_pi[fidx] and new_pid in honest_set:
                    state_pi.add_peer(fidx, new_pid)
                    repairs_pi += 1
            else:
                next_pi.append((fidx, comp_day, new_pid))
        pending_pi = next_pi

        next_pid: list[tuple[int, int, int]] = []
        for (fidx, comp_day, new_pid) in pending_pid:
            if day_end >= comp_day:
                if file_alive_pid[fidx] and new_pid in honest_set:
                    state_pid.add_peer(fidx, new_pid)
                    repairs_pid += 1
            else:
                next_pid.append((fidx, comp_day, new_pid))
        pending_pid = next_pid

        # -------------------------------------------------------------------
        # Proof-of-storage challenge cycle at end of step.
        # Detect liars whose deletion day is before day_end (shard is gone).
        # -------------------------------------------------------------------
        # detected_global: set of liar peer IDs that have deleted >= 1 shard
        # and whose deletion is now past — they will fail the PoS challenge.
        # We record detection delay only once, the first time it is detected.
        detected_global: set[int] = set()
        for pid in range(config.n_honest, n_total):
            for f_del, del_day in shard_delete_day[pid].items():
                if del_day < day_end:
                    detected_global.add(pid)
                    key = (pid, f_del)
                    # Record detection delay on first detection only
                    if key in actual_deletion and key not in recorded_delays:
                        delay = float(day_end - actual_deletion[key])
                        detection_delays.append(delay)
                        recorded_delays.add(key)

        # Honest peers available to accept repairs
        honest_available = list(honest_set)

        trust_arr = config.kp * p_score + config.ki * i_score

        def count_truly_available(holders: list[int], f: int) -> int:
            """Count holders that truly have the shard on day_end."""
            count = 0
            for pid in holders:
                if pid in honest_set:
                    count += 1
                elif liar_has_shard(pid, f, day_end):
                    count += 1
            return count

        # -------------------------------------------------------------------
        # Evaluate each file under both strategies
        # -------------------------------------------------------------------
        for fidx in range(config.n_files):

            # --- Strategy A: PI-only ---
            if file_alive_pi[fidx]:
                holders_pi = state_pi.holders(fidx)
                if count_truly_available(holders_pi, fidx) < config.k:
                    file_alive_pi[fidx] = False
                else:
                    # Suspects: failed PoS challenge OR trust decayed below thr
                    suspects = [
                        pid for pid in holders_pi
                        if pid in detected_global
                        or trust_arr[pid] < config.pi_threshold
                    ]
                    for bad_pid in suspects:
                        state_pi.remove_peer(fidx, bad_pid)
                        # NOTE: do NOT touch shard_delete_day — it is ground
                        # truth shared between strategies. Eviction is tracked
                        # via FileState only.
                        current = set(state_pi.holders(fidx))
                        cands = [p for p in honest_available if p not in current]
                        if cands:
                            new_pid = int(rng.choice(cands))
                            comp = day_end + config.repair_delay_days
                            pending_pi.append((fidx, comp, new_pid))

            # --- Strategy B: PID-trigger ---
            if file_alive_pid[fidx]:
                holders_pid = state_pid.holders(fidx)
                if count_truly_available(holders_pid, fidx) < config.k:
                    file_alive_pid[fidx] = False
                else:
                    # Suspects: failed PoS challenge OR PI fallback OR D drop.
                    # D < d_threshold indicates a sudden drop in P (liar going
                    # from passing to failing). Applied only when D is negative
                    # AND trust is still above pi_threshold (early warning before
                    # PI would fire). This may produce false positives on honest
                    # peers that had a bad check interval — a real cost of D-trigger.
                    suspects = [
                        pid for pid in holders_pid
                        if pid in detected_global
                        or trust_arr[pid] < config.pi_threshold
                        or d_score[pid] < config.d_threshold
                    ]
                    for bad_pid in suspects:
                        state_pid.remove_peer(fidx, bad_pid)
                        # Do NOT mutate shard_delete_day here.
                        current = set(state_pid.holders(fidx))
                        cands = [p for p in honest_available if p not in current]
                        if cands:
                            new_pid = int(rng.choice(cands))
                            comp = day_end + config.repair_delay_days
                            pending_pid.append((fidx, comp, new_pid))

        # -------------------------------------------------------------------
        # Persistent liar re-infiltration: detected liars may accept new shards
        # on other files and repeat the lie. Models the worst-case attacker
        # that actively seeks to re-infiltrate after eviction.
        # -------------------------------------------------------------------
        for pid in detected_global:
            if rng.random() < 0.2:   # 20% chance per check cycle
                target = int(rng.integers(0, config.n_files))
                # Re-infiltrate whichever strategy still tracks them as absent
                if (file_alive_pi[target]
                        and pid not in state_pi.holders(target)
                        and pid not in honest_set):
                    state_pi.add_peer(target, pid)
                    schedule_deletion(pid, target, accept_day=int(day_end))
                if (file_alive_pid[target]
                        and pid not in state_pid.holders(target)
                        and pid not in honest_set):
                    state_pid.add_peer(target, pid)
                    schedule_deletion(pid, target, accept_day=int(day_end))

    # -----------------------------------------------------------------------
    # Aggregate results
    # -----------------------------------------------------------------------
    pi_survival = float(file_alive_pi.sum()) / config.n_files
    pid_survival = float(file_alive_pid.sum()) / config.n_files

    detection_time = (
        float(np.mean(detection_delays)) if detection_delays else float("nan")
    )

    # Repair success rate: approximate — completed repairs vs (completed + lost files)
    repairs_used = repairs_pi if config.repair_strategy == "pi_only" else repairs_pid
    lost_count = int((~file_alive_pi).sum()) if config.repair_strategy == "pi_only" \
        else int((~file_alive_pid).sum())
    repair_success = (
        float(repairs_used) / (repairs_used + lost_count)
        if (repairs_used + lost_count) > 0
        else 1.0
    )

    liar_trust = float(
        np.mean(
            config.kp * p_score[config.n_honest:]
            + config.ki * i_score[config.n_honest:]
        )
    )

    return {
        "pi_survival": pi_survival,
        "pid_survival": pid_survival,
        "file_survival_rate": pid_survival
        if config.repair_strategy == "pid_trigger"
        else pi_survival,
        "detection_time_days": detection_time,
        "repair_success_rate": repair_success,
        "liar_trust_mean": liar_trust,
        "d_trigger_advantage": pid_survival - pi_survival,
        "repairs_pi": repairs_pi,
        "repairs_pid": repairs_pid,
    }


# ---------------------------------------------------------------------------
# Monte Carlo runner
# ---------------------------------------------------------------------------

def run_experiment(config: Config, n_jobs: int = 1) -> dict:
    """Run Monte Carlo across seeds and aggregate results."""
    t0 = time.time()

    if n_jobs == 1:
        results = [simulate_one(config, seed) for seed in range(config.n_seeds)]
    else:
        results = Parallel(n_jobs=n_jobs)(
            delayed(simulate_one)(config, seed)
            for seed in range(config.n_seeds)
        )

    elapsed = time.time() - t0

    def agg(key: str) -> tuple[float, float, float, float]:
        vals = [r[key] for r in results if not np.isnan(r[key])]
        if not vals:
            return float("nan"), float("nan"), float("nan"), float("nan")
        return (
            float(np.mean(vals)),
            float(np.std(vals)),
            float(np.percentile(vals, 5)),
            float(np.percentile(vals, 95)),
        )

    surv_m, surv_s, surv_p5, surv_p95 = agg("file_survival_rate")
    det_m, det_s, det_p5, det_p95 = agg("detection_time_days")
    rep_m, rep_s, rep_p5, _ = agg("repair_success_rate")

    pi_m = float(np.mean([r["pi_survival"] for r in results]))
    pid_m = float(np.mean([r["pid_survival"] for r in results]))
    adv_m = float(np.mean([r["d_trigger_advantage"] for r in results]))
    liar_m = float(np.mean([r["liar_trust_mean"] for r in results]))

    return {
        "config": asdict(config),
        "elapsed_sec": elapsed,
        "file_survival_mean": surv_m,
        "file_survival_std": surv_s,
        "file_survival_p5": surv_p5,
        "file_survival_p95": surv_p95,
        "pi_survival_mean": pi_m,
        "pid_survival_mean": pid_m,
        "detection_time_mean": det_m,
        "detection_time_std": det_s,
        "detection_time_p5": det_p5,
        "detection_time_p95": det_p95,
        "repair_success_mean": rep_m,
        "repair_success_p5": rep_p5,
        "liar_trust_mean": liar_m,
        "d_trigger_advantage_mean": adv_m,
    }


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def print_summary(result: dict) -> None:
    cfg = result["config"]
    n_total = cfg["n_honest"] + cfg["n_liars"]
    liar_pct = cfg["n_liars"] / n_total * 100
    honest_baseline = (cfg["kp"] + cfg["ki"]) * cfg["honest_reliability"]
    print(
        f"Config: {cfg['n_honest']} honest + {cfg['n_liars']} liars "
        f"({liar_pct:.0f}% liars), {cfg['n_files']} files, "
        f"{cfg['n_days']}d simulation"
    )
    print(
        f"Erasure: {cfg['k']}-of-{cfg['n_shards']}, "
        f"lie_delay={cfg['lie_delay_days']}d, "
        f"check_interval={cfg['check_interval_days']}d, "
        f"repair_delay={cfg['repair_delay_days']}d"
    )
    print(
        f"Strategy: {cfg['repair_strategy']}, "
        f"PI_thr={cfg['pi_threshold']}, D_thr={cfg['d_threshold']}"
    )
    print(f"Seeds: {cfg['n_seeds']}, runtime: {result['elapsed_sec']:.1f}s")
    print()

    print(
        f"File survival:    {result['file_survival_mean']*100:.2f}%  "
        f"(p5={result['file_survival_p5']*100:.1f}%, "
        f"p95={result['file_survival_p95']*100:.1f}%)"
    )
    print(f"  PI-only:        {result['pi_survival_mean']*100:.2f}%")
    print(f"  PID-trigger:    {result['pid_survival_mean']*100:.2f}%")
    adv = result["d_trigger_advantage_mean"]
    print(f"  D-advantage:    {adv*100:+.2f}%")
    print()

    det = result["detection_time_mean"]
    det_str = f"{det:.1f}d" if not np.isnan(det) else "n/a"
    p5_str = f"{result['detection_time_p5']:.1f}d" \
        if not np.isnan(result["detection_time_p5"]) else "n/a"
    p95_str = f"{result['detection_time_p95']:.1f}d" \
        if not np.isnan(result["detection_time_p95"]) else "n/a"
    print(f"Detection time:   {det_str} mean  (p5={p5_str}, p95={p95_str})")

    print(
        f"Repair success:   {result['repair_success_mean']*100:.1f}%  "
        f"(p5={result['repair_success_p5']*100:.1f}%)"
    )
    print(
        f"Liar trust (end): {result['liar_trust_mean']:.3f}  "
        f"(honest baseline ~{honest_baseline:.3f})"
    )


def save_results(result: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2))
    print(f"\nResults saved to {path}")


# ---------------------------------------------------------------------------
# Sweep
# ---------------------------------------------------------------------------

def _evaluate_sweep(
    n_honest: int,
    n_liars: int,
    n_files: int,
    k: int,
    n_shards: int,
    lie_delay_days: int,
    check_interval_days: int,
    repair_strategy: str,
    n_seeds: int,
    kp: float,
    ki: float,
    p_window: int,
    pi_threshold: float,
    d_threshold: float,
    repair_delay_days: int,
    n_days: int,
) -> dict:
    cfg = Config(
        n_honest=n_honest,
        n_liars=n_liars,
        n_files=n_files,
        k=k,
        n_shards=n_shards,
        lie_delay_days=lie_delay_days,
        check_interval_days=check_interval_days,
        repair_strategy=repair_strategy,
        n_seeds=n_seeds,
        kp=kp,
        ki=ki,
        p_window=p_window,
        pi_threshold=pi_threshold,
        d_threshold=d_threshold,
        repair_delay_days=repair_delay_days,
        n_days=n_days,
    )
    res = run_experiment(cfg, n_jobs=1)
    return {
        "n_liars": n_liars,
        "lie_delay_days": lie_delay_days,
        "check_interval_days": check_interval_days,
        "repair_strategy": repair_strategy,
        "k": k,
        "n_shards": n_shards,
        "file_survival": res["file_survival_mean"],
        "file_survival_p5": res["file_survival_p5"],
        "pi_survival": res["pi_survival_mean"],
        "pid_survival": res["pid_survival_mean"],
        "d_trigger_advantage": res["d_trigger_advantage_mean"],
        "detection_time": res["detection_time_mean"],
        "repair_success": res["repair_success_mean"],
        "liar_trust": res["liar_trust_mean"],
    }


def run_sweep(base_config: Config, output_dir: Path, n_jobs: int = 1) -> None:
    """Sweep n_liars, lie_delay_days, check_interval_days, repair_strategy."""
    n_liars_values = [10, 25, 50, 100]
    lie_delay_values = [7, 30, 90]
    check_interval_values = [7, 14, 30]
    repair_strategies = ["pi_only", "pid_trigger"]

    tasks: list[tuple] = []
    for n_liars in n_liars_values:
        n_honest = 500 - n_liars
        for lie_delay in lie_delay_values:
            for check_interval in check_interval_values:
                for strategy in repair_strategies:
                    tasks.append((
                        n_honest,
                        n_liars,
                        base_config.n_files,
                        base_config.k,
                        base_config.n_shards,
                        lie_delay,
                        check_interval,
                        strategy,
                        30,   # 30 seeds for sweep
                        base_config.kp,
                        base_config.ki,
                        base_config.p_window,
                        base_config.pi_threshold,
                        base_config.d_threshold,
                        base_config.repair_delay_days,
                        base_config.n_days,
                    ))

    total = len(tasks)
    print(f"Sweep: {total} configs, {n_jobs} jobs\n")

    results_table: list[dict]
    if n_jobs == 1:
        results_table = []
        for i, t in enumerate(tasks, 1):
            r = _evaluate_sweep(*t)
            results_table.append(r)
            det_val = r["detection_time"]
            det_str = f"{det_val:.1f}d" if not np.isnan(det_val) else "  n/a"
            print(
                f"  [{i:>3}/{total}] "
                f"liars={r['n_liars']:>3} "
                f"delay={r['lie_delay_days']:>2}d "
                f"check={r['check_interval_days']:>2}d "
                f"strat={r['repair_strategy']:<11} "
                f"surv={r['file_survival']*100:>5.1f}% "
                f"det={det_str} "
                f"D-adv={r['d_trigger_advantage']*100:+.2f}%"
            )
    else:
        t0 = time.time()
        results_table = list(
            Parallel(n_jobs=n_jobs, verbose=10)(
                delayed(_evaluate_sweep)(*t) for t in tasks
            )
        )
        elapsed = time.time() - t0
        print(f"\nSweep completed in {elapsed:.1f}s")

    # Sort by file_survival ascending (worst cases first)
    results_table.sort(key=lambda r: r["file_survival"])

    print("\n=== WORST SURVIVAL CONFIGURATIONS ===")
    print(
        f"{'liars':>6} {'delay':>6} {'check':>6} {'strategy':<12} "
        f"{'surv%':>6} {'p5%':>6} {'det(d)':>7} "
        f"{'repair%':>8} {'D-adv%':>7}"
    )
    for r in results_table[:15]:
        det_val = r["detection_time"]
        det_str = f"{det_val:>6.1f}d" if not np.isnan(det_val) else "   n/ad"
        print(
            f"{r['n_liars']:>6} {r['lie_delay_days']:>5}d "
            f"{r['check_interval_days']:>5}d "
            f"{r['repair_strategy']:<12} "
            f"{r['file_survival']*100:>5.1f}% "
            f"{r['file_survival_p5']*100:>5.1f}% "
            f"{det_str} "
            f"{r['repair_success']*100:>7.1f}% "
            f"{r['d_trigger_advantage']*100:>+6.2f}%"
        )

    # D-trigger advantage: configs where PID beats PI most
    print("\n=== D-TRIGGER ADVANTAGE (PID survival - PI survival) ===")
    adv_rows = sorted(results_table, key=lambda r: -r["d_trigger_advantage"])
    print(
        f"{'liars':>6} {'delay':>6} {'check':>6} "
        f"{'PI%':>7} {'PID%':>7} {'D-adv%':>8}"
    )
    for r in adv_rows[:10]:
        print(
            f"{r['n_liars']:>6} {r['lie_delay_days']:>5}d "
            f"{r['check_interval_days']:>5}d "
            f"{r['pi_survival']*100:>6.1f}% "
            f"{r['pid_survival']*100:>6.1f}% "
            f"{r['d_trigger_advantage']*100:>+7.2f}%"
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
        description="Storage Lie + Proof-of-Storage Detection (Experiment #8)"
    )
    parser.add_argument("--honest", type=int, default=450,
                        help="Number of honest peers")
    parser.add_argument("--liars", type=int, default=50,
                        help="Number of liar peers")
    parser.add_argument("--files", type=int, default=500,
                        help="Number of files")
    parser.add_argument("--days", type=int, default=365,
                        help="Simulation duration in days")
    parser.add_argument("--seeds", type=int, default=100,
                        help="Monte Carlo seeds")
    parser.add_argument("--k", type=int, default=5,
                        help="Reconstruction threshold (k-of-n)")
    parser.add_argument("--n-shards", type=int, default=15,
                        help="Total shards per file")
    parser.add_argument("--lie-delay", type=int, default=30,
                        help="Days before liar deletes shard after accepting")
    parser.add_argument("--check-interval", type=int, default=7,
                        help="Proof-of-storage challenge interval (days)")
    parser.add_argument("--repair-delay", type=int, default=7,
                        help="Days from detection to repair completion")
    parser.add_argument("--strategy", choices=["pi_only", "pid_trigger"],
                        default="pid_trigger",
                        help="Repair trigger strategy")
    parser.add_argument("--kp", type=float, default=0.5,
                        help="P-component weight in trust formula")
    parser.add_argument("--ki", type=float, default=2.0,
                        help="I-component weight in trust formula")
    parser.add_argument("--window", type=int, default=30,
                        help="P rolling window in days")
    parser.add_argument("--pi-threshold", type=float, default=0.6,
                        help="PI strategy: repair when trust < this")
    parser.add_argument("--d-threshold", type=float, default=-0.01,
                        help="PID strategy: repair when D < this")
    parser.add_argument("--sweep", action="store_true",
                        help="Run parameter sweep over key variables")
    parser.add_argument("--jobs", type=int, default=1,
                        help="Parallel jobs for sweep (joblib)")
    parser.add_argument("--output", type=str, default="results/storage_lie",
                        help="Output directory for results")
    args = parser.parse_args()

    config = Config(
        n_honest=args.honest,
        n_liars=args.liars,
        n_files=args.files,
        n_days=args.days,
        n_seeds=args.seeds,
        k=args.k,
        n_shards=args.n_shards,
        lie_delay_days=args.lie_delay,
        check_interval_days=args.check_interval,
        repair_delay_days=args.repair_delay,
        repair_strategy=args.strategy,
        kp=args.kp,
        ki=args.ki,
        p_window=args.window,
        pi_threshold=args.pi_threshold,
        d_threshold=args.d_threshold,
    )

    if args.sweep:
        output_dir = Path(args.output + "_sweep")
        print("=== STORAGE LIE PARAMETER SWEEP ===\n")
        run_sweep(config, output_dir, n_jobs=args.jobs)
    else:
        output_dir = Path(args.output)
        print("=== STORAGE LIE + PROOF-OF-STORAGE ===\n")
        result = run_experiment(config, n_jobs=args.jobs)
        print_summary(result)
        save_results(result, output_dir / "run.json")


if __name__ == "__main__":
    main()
