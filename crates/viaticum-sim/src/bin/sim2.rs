//! SIM-2 runnable: drive `φ` back and forth across `s_hard`, assert no chatter
//! with the two-gap hysteresis, demonstrate the limit cycle reappears at Δ=0,
//! and print PASS/FAIL plus the measured Δ_min vs the analytic value.
//!
//! Exit code 0 on PASS, 1 on FAIL — so it can gate a script.

use std::process::ExitCode;

use viaticum_sim::sim2;

fn main() -> ExitCode {
    // Deterministic default population; override via args: `sim2 <n_owners> <seed>`.
    let mut args = std::env::args().skip(1);
    let n_owners: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(40);
    let seed: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(42);

    let report = sim2::run(n_owners, seed);
    sim2::print_report(&report);

    if report.pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
