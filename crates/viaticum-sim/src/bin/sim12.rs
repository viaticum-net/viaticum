//! SIM-12 runnable: discover the surface form on honest data with the
//! nonparametric estimator (blind to the generator's true form), assert it
//! DISTINGUISHES exponential / bathtub / volume-dependent, and confirm the kernel
//! estimate stays conservative off-sample. Prints PASS/FAIL.
//!
//! Exit code 0 on PASS, 1 on FAIL — so it can gate a script.

use std::process::ExitCode;

use viaticum_sim::sim12;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let n_holders: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(5000);
    let seed: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(42);

    let report = sim12::run(n_holders, seed);
    sim12::print_report(&report);

    if report.pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
