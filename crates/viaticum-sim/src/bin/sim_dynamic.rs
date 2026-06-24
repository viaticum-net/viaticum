//! `sim_dynamic` runnable: the full honest-convergence Experiment-1 on the dynamic
//! 4R harness (~200 nodes, weekly ticks, ~2-3y). Prints the structured report:
//! metric (a) earned-G gap + Spearman ρ, metric (b) reciprocity balance + Freeloader
//! decay, metric (c) DR median, and the newcomer `T_boot`.
//!
//! Deterministic in the seed (optional first arg). Exit code 0 if the load-bearing
//! structural sign holds (honest holders out-earn exploiters), 1 otherwise — so it
//! can gate a script.
//!
//! Usage: `cargo run -p viaticum-sim --bin sim_dynamic [seed] [n_nodes]`

use std::process::ExitCode;

use viaticum_sim::sim_dynamic::{Experiment1Config, print_experiment_1, run_experiment_1};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let seed: u64 = args
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x00E1_5EED);
    let n_nodes: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(200);

    let cfg = Experiment1Config {
        n_nodes,
        seed,
        ..Experiment1Config::default()
    };
    let report = run_experiment_1(cfg);
    print_experiment_1(&report);

    if report.rank.gap > 0.0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
