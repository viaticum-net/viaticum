//! SIM-R1 runnable: forecast per-symbol block survival with the K3 kernel and
//! compare against the god-view evaluator across a dial sweep. Asserts the three
//! STRUCTURAL signs — (1) the forecast is conservative (≤ actual), (2) high-ι
//! symbols actually survive more, (3) the per-symbol forecast beats the
//! aggregate-per-holder-average it replaces — printing PASS/FAIL.
//!
//! Exit code 0 on PASS, 1 on FAIL — so it can gate a script.

use std::process::ExitCode;

use viaticum_sim::sim_r1;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let seed: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(42);

    let report = sim_r1::run(seed);
    sim_r1::print_report(&report);

    if report.pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
