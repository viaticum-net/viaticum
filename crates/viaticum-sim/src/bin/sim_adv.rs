//! `sim_adv` — the World-v3 adversarial-polygon runner (phase 0, sub-tranche 0.1).
//!
//! Usage:
//!
//! ```text
//! sim_adv <scenario> [--seeds N] [--sweep dial=a,b,c] [--csv <file>] [--fast]
//! ```
//!
//! * `<scenario>` — a registry name (0.1: `honest_v2`).
//! * `--seeds N` — run N seeds `base, base+1, ...` (base = the scenario's first default
//!   seed); default = the scenario's seed list.
//! * `--sweep dial=a,b,c` — run the scenario once per dial value and print a sweep table
//!   (an A/B toggle is the two-value case). Known dials: `block_volume`, `c_recip_days`,
//!   `depth_w_d`, `preempt_theta`, `v_free_symbols`, `burn_b_ann`, `burn_b_max`.
//! * `--csv <file>` — also write the per-seed machine CSV to `<file>` (default: none).
//! * `--fast` — advisory fast-mode flag (the fast/full split lands with more scenarios).
//!
//! The text report shows mean±σ over seeds + the invariant board; single-seed numbers
//! never headline. Runs are deterministic (seeded), so two identical invocations produce
//! byte-identical output.

use std::process::ExitCode;

use viaticum_sim::sim_adv::cli::resolve_seeds;
use viaticum_sim::sim_adv::{
    Cli, SimAdvError, evaluate_board, find_scenario, format_report, format_sweep, parse_cli,
    restore_csv, run, run_result_csv, run_sweep, sweep_csv,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run_cli(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sim_adv: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_cli(args: &[String]) -> Result<(), SimAdvError> {
    let cli: Cli = parse_cli(args)?;
    let scenario = find_scenario(&cli.scenario)?;
    let seeds = resolve_seeds(&scenario.seeds, cli.seeds);

    if let Some(sweep) = &cli.sweep {
        // `run_sweep` validates the dial on the first value and returns a graceful
        // `SimAdvError::UnknownDial` (never a panic) before doing work.
        let rows = run_sweep(&scenario, &sweep.dial, &sweep.values, &seeds)?;
        print!("{}", format_sweep(&scenario, &sweep.dial, &rows));
        if let Some(path) = &cli.csv {
            write_csv(path, &sweep_csv(&sweep.dial, &rows))?;
        }
        return Ok(());
    }

    let result = run(&scenario, &seeds);
    let verdicts = evaluate_board(&scenario, &result);
    print!("{}", format_report(&scenario, &result, &verdicts));

    if let Some(path) = &cli.csv {
        write_csv(path, &run_result_csv(&result))?;
        // Restore-truth has its own schema (metric №1); write it to a sibling `.restore`
        // file when the scenario produced any (a DR scenario like `dr_baseline`).
        if result.per_seed_restore.iter().any(|r| r.is_some()) {
            write_csv(&restore_csv_path(path), &restore_csv(&result))?;
        }
    }
    Ok(())
}

/// Derive the restore-CSV sibling path: `x.csv` → `x.restore.csv`, else `x` → `x.restore.csv`.
fn restore_csv_path(path: &str) -> String {
    match path.strip_suffix(".csv") {
        Some(stem) => format!("{stem}.restore.csv"),
        None => format!("{path}.restore.csv"),
    }
}

fn write_csv(path: &str, contents: &str) -> Result<(), SimAdvError> {
    std::fs::write(path, contents)
        .map_err(|e| SimAdvError::CsvWrite(path.to_string(), e.to_string()))
}
