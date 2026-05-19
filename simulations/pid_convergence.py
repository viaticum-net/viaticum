"""
Viaticum Simulation #1: PID Reputation Convergence

Question: Does PID-style reputation correctly rank peers by reliability?
Metric: Kendall's tau (PID-perceived rank vs true reliability rank)

Model:
- N peers with true reliability from 3 classes (reliable/normal/lazy)
- Each timestep: proof-of-storage check (Bernoulli with true_reliability)
- PID controller per peer:
    P = exponential moving average of recent checks
    I = cumulative success rate (GB·days analog)
    D = rate of change of P (early warning)
- Trust = Kp*P + Ki*I + Kd*D

Usage:
    python pid_convergence.py                    # default run
    python pid_convergence.py --peers 5000       # more peers
    python pid_convergence.py --sweep            # parameter sweep
    python pid_convergence.py --jobs 4           # use 4 cores
"""

import argparse
import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path

import numpy as np
from joblib import Parallel, delayed
from scipy.stats import kendalltau


@dataclass
class Config:
    n_peers: int = 1000
    n_steps: int = 365       # 1 year of daily checks
    n_seeds: int = 100       # Monte Carlo runs
    kp: float = 1.0          # P weight
    ki: float = 1.0          # I weight
    kd: float = 0.5          # D weight
    p_window: int = 7        # P: rolling window in days (0 = EMA mode)
    ema_alpha: float = 0.1   # P: EMA smoothing (only if p_window=0)
    # Peer class distribution: [reliable, normal, lazy]
    class_fractions: tuple = (0.2, 0.6, 0.2)
    # Reliability ranges per class
    reliable_range: tuple = (0.90, 0.99)
    normal_range: tuple = (0.50, 0.80)
    lazy_range: tuple = (0.10, 0.40)


def create_peers(n: int, config: Config, rng: np.random.Generator):
    """Create peers with true reliability from 3 classes."""
    classes = rng.choice(3, size=n, p=config.class_fractions)
    reliability = np.empty(n)

    ranges = [config.reliable_range, config.normal_range, config.lazy_range]
    for cls_id, (lo, hi) in enumerate(ranges):
        mask = classes == cls_id
        reliability[mask] = rng.uniform(lo, hi, size=mask.sum())

    return reliability, classes


def simulate_one(config: Config, seed: int):
    """Run one simulation. Returns tau at each timestep."""
    rng = np.random.default_rng(seed)
    reliability, _classes = create_peers(config.n_peers, config, rng)

    # PID state
    p_score = np.full(config.n_peers, 0.5)
    i_score = np.zeros(config.n_peers)
    prev_p = np.full(config.n_peers, 0.5)

    # Rolling window buffer for P (circular buffer)
    use_window = config.p_window > 0
    if use_window:
        window = np.zeros((config.p_window, config.n_peers))

    taus = np.empty(config.n_steps)

    for t in range(config.n_steps):
        # Proof-of-storage check
        checks = (rng.random(config.n_peers) < reliability).astype(np.float64)

        if use_window:
            # P: rolling average over last p_window days
            window[t % config.p_window] = checks
            filled = min(t + 1, config.p_window)
            p_score = window[:filled].mean(axis=0)
        else:
            # P: exponential moving average (legacy mode)
            p_score = config.ema_alpha * checks + (1.0 - config.ema_alpha) * p_score

        # I: cumulative average (bounded, won't overflow)
        i_score = (i_score * t + checks) / (t + 1)

        # D: rate of change of P
        d_score = p_score - prev_p
        prev_p = p_score.copy()

        # Combined trust score
        trust = config.kp * p_score + config.ki * i_score + config.kd * d_score

        # Kendall's tau: correlation between trust ranking and true reliability
        tau, _ = kendalltau(trust, reliability)
        taus[t] = tau

    return taus


def run_experiment(config: Config, n_jobs: int = 1):
    """Run Monte Carlo experiment across seeds."""
    t0 = time.time()

    if n_jobs == 1:
        all_taus = np.array([
            simulate_one(config, seed) for seed in range(config.n_seeds)
        ])
    else:
        all_taus = np.array(
            Parallel(n_jobs=n_jobs)(
                delayed(simulate_one)(config, seed)
                for seed in range(config.n_seeds)
            )
        )

    elapsed = time.time() - t0

    return {
        "mean": all_taus.mean(axis=0),
        "std": all_taus.std(axis=0),
        "p5": np.percentile(all_taus, 5, axis=0),
        "p95": np.percentile(all_taus, 95, axis=0),
        "elapsed_sec": elapsed,
    }


def print_summary(config: Config, results: dict):
    """Print key convergence metrics."""
    mean = results["mean"]
    steps_to_80 = np.argmax(mean >= 0.8) if np.any(mean >= 0.8) else -1
    steps_to_90 = np.argmax(mean >= 0.9) if np.any(mean >= 0.9) else -1

    print(f"Config: {config.n_peers} peers, {config.n_steps} steps, "
          f"{config.n_seeds} seeds")
    p_mode = f"window={config.p_window}d" if config.p_window > 0 else f"EMA alpha={config.ema_alpha}"
    print(f"PID weights: Kp={config.kp}, Ki={config.ki}, Kd={config.kd}, P: {p_mode}")
    print(f"Runtime: {results['elapsed_sec']:.1f}s")
    print()
    print(f"Kendall's tau (mean over {config.n_seeds} seeds):")
    print(f"  Day 1:   {mean[0]:.3f}")
    print(f"  Day 7:   {mean[min(6, len(mean)-1)]:.3f}")
    print(f"  Day 30:  {mean[min(29, len(mean)-1)]:.3f}")
    print(f"  Day 90:  {mean[min(89, len(mean)-1)]:.3f}")
    print(f"  Day 365: {mean[-1]:.3f}")
    print()
    if steps_to_80 >= 0:
        print(f"  tau >= 0.8 at day {steps_to_80 + 1}")
    else:
        print(f"  tau >= 0.8: NOT REACHED")
    if steps_to_90 >= 0:
        print(f"  tau >= 0.9 at day {steps_to_90 + 1}")
    else:
        print(f"  tau >= 0.9: NOT REACHED")


def save_results(config: Config, results: dict, path: Path):
    """Save results to JSON for later analysis."""
    output = {
        "config": asdict(config),
        "summary": {
            "tau_day1": float(results["mean"][0]),
            "tau_day7": float(results["mean"][min(6, len(results["mean"])-1)]),
            "tau_day30": float(results["mean"][min(29, len(results["mean"])-1)]),
            "tau_day90": float(results["mean"][min(89, len(results["mean"])-1)]),
            "tau_day365": float(results["mean"][-1]),
            "elapsed_sec": results["elapsed_sec"],
        },
        # Full trajectories as lists for plotting
        "tau_mean": results["mean"].tolist(),
        "tau_std": results["std"].tolist(),
        "tau_p5": results["p5"].tolist(),
        "tau_p95": results["p95"].tolist(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(output, indent=2))
    print(f"\nResults saved to {path}")


def plot_convergence(results: dict, config: Config, path: Path):
    """Plot tau convergence with confidence band."""
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed, skipping plot")
        return

    days = np.arange(1, config.n_steps + 1)
    mean = results["mean"]
    p5 = results["p5"]
    p95 = results["p95"]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(days, mean, "b-", linewidth=1.5, label="Mean tau")
    ax.fill_between(days, p5, p95, alpha=0.2, color="blue", label="5-95 percentile")
    ax.axhline(0.8, color="green", linestyle="--", alpha=0.5, label="tau = 0.8")
    ax.axhline(0.9, color="orange", linestyle="--", alpha=0.5, label="tau = 0.9")
    ax.set_xlabel("Day")
    ax.set_ylabel("Kendall's tau")
    ax.set_title(f"PID Reputation Convergence "
                 f"(N={config.n_peers}, Kp={config.kp}, Ki={config.ki}, "
                 f"Kd={config.kd})")
    ax.legend()
    ax.set_ylim(0, 1.05)
    ax.grid(True, alpha=0.3)

    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Plot saved to {path}")


def _evaluate_config(cfg: Config):
    """Evaluate a single config (for parallel sweep)."""
    res = run_experiment(cfg, n_jobs=1)  # inner loop sequential
    mean = res["mean"]
    t80 = int(np.argmax(mean >= 0.8) + 1) if np.any(mean >= 0.8) else -1
    t90 = int(np.argmax(mean >= 0.9) + 1) if np.any(mean >= 0.9) else -1
    final = float(mean[-1])
    return {
        "kp": cfg.kp, "ki": cfg.ki, "kd": cfg.kd, "window": cfg.p_window,
        "tau_final": round(final, 4),
        "days_to_80": t80,
        "days_to_90": t90,
    }


def run_sweep(base_config: Config, output_dir: Path, n_jobs: int = 1):
    """Sweep PID weights to find optimal combination."""
    kp_values = [0.5, 1.0, 2.0]
    ki_values = [0.5, 1.0, 2.0]
    kd_values = [0.0, 0.5, 1.0]
    window_values = [3, 7, 14, 30]

    configs = []
    for kp in kp_values:
        for ki in ki_values:
            for kd in kd_values:
                for win in window_values:
                    configs.append(Config(
                        n_peers=base_config.n_peers,
                        n_steps=base_config.n_steps,
                        n_seeds=30,
                        kp=kp, ki=ki, kd=kd, p_window=win,
                    ))

    total = len(configs)
    print(f"Sweep: {total} configs, {n_jobs} jobs\n")

    if n_jobs == 1:
        results_table = []
        for i, cfg in enumerate(configs, 1):
            r = _evaluate_config(cfg)
            results_table.append(r)
            print(f"  [{i}/{total}] Kp={r['kp']} Ki={r['ki']} Kd={r['kd']} "
                  f"w={r['window']} → tau={r['tau_final']:.3f} "
                  f"t80={r['days_to_80']} t90={r['days_to_90']}")
    else:
        t0 = time.time()
        results_table = Parallel(n_jobs=n_jobs, verbose=10)(
            delayed(_evaluate_config)(cfg) for cfg in configs
        )
        elapsed = time.time() - t0
        print(f"\nSweep completed in {elapsed:.1f}s")
        for r in results_table:
            print(f"  Kp={r['kp']} Ki={r['ki']} Kd={r['kd']} "
                  f"w={r['window']} → tau={r['tau_final']:.3f} "
                  f"t80={r['days_to_80']} t90={r['days_to_90']}")

    # Sort by final tau, then by convergence speed
    results_table.sort(key=lambda r: (-r["tau_final"], r["days_to_90"]))

    print("\n=== TOP 10 CONFIGURATIONS ===")
    print(f"{'Kp':>4} {'Ki':>4} {'Kd':>4} {'win':>4} "
          f"{'tau_final':>10} {'days→0.8':>8} {'days→0.9':>8}")
    for r in results_table[:10]:
        print(f"{r['kp']:>4} {r['ki']:>4} {r['kd']:>4} {r['window']:>4} "
              f"{r['tau_final']:>10.4f} {r['days_to_80']:>8} "
              f"{r['days_to_90']:>8}")

    # Save full sweep
    sweep_path = output_dir / "sweep_results.json"
    sweep_path.parent.mkdir(parents=True, exist_ok=True)
    sweep_path.write_text(json.dumps(results_table, indent=2))
    print(f"\nFull sweep saved to {sweep_path}")


def main():
    parser = argparse.ArgumentParser(description="PID Reputation Convergence")
    parser.add_argument("--peers", type=int, default=1000)
    parser.add_argument("--steps", type=int, default=365)
    parser.add_argument("--seeds", type=int, default=100)
    parser.add_argument("--kp", type=float, default=1.0)
    parser.add_argument("--ki", type=float, default=1.0)
    parser.add_argument("--kd", type=float, default=0.5)
    parser.add_argument("--alpha", type=float, default=0.1)
    parser.add_argument("--window", type=int, default=7, help="P rolling window in days (0=EMA)")
    parser.add_argument("--sweep", action="store_true", help="Run parameter sweep")
    parser.add_argument("--jobs", type=int, default=1, help="Parallel jobs (cores)")
    parser.add_argument("--output", type=str, default="results/pid_convergence")
    args = parser.parse_args()

    output_dir = Path(args.output)

    config = Config(
        n_peers=args.peers,
        n_steps=args.steps,
        n_seeds=args.seeds,
        kp=args.kp, ki=args.ki, kd=args.kd,
        p_window=args.window, ema_alpha=args.alpha,
    )

    if args.sweep:
        print("=== PID PARAMETER SWEEP ===\n")
        run_sweep(config, output_dir, n_jobs=args.jobs)
    else:
        print("=== PID REPUTATION CONVERGENCE ===\n")
        results = run_experiment(config, n_jobs=args.jobs)
        print_summary(config, results)
        save_results(config, results, output_dir / "run.json")
        plot_convergence(results, config, output_dir / "convergence.png")


if __name__ == "__main__":
    main()
