//! SIM-12b runnable: graceful degradation under mis-specification. Generate
//! OUT-OF-FAMILY hazard data the Weibull backbone cannot represent, fit the best
//! in-family prior, and assert the kernel's off-sample `r_hat ≤ true_r`
//! (under-estimate — the safe side) EVEN THOUGH the form is wrong. Any
//! over-estimate is reported honestly. Prints PASS/FAIL.
//!
//! Exit code 0 on PASS, 1 on FAIL — so it can gate a script.

use std::process::ExitCode;

use viaticum_sim::sim12b;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let n_holders: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(20000);
    let seed: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(42);

    let report = sim12b::run(n_holders, seed);
    sim12b::print_report(&report);

    if report.pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
