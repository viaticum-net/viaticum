//! SIM-6 runnable: probe the addr-correlate diversity-cap across a dial sweep and
//! assert the STRUCTURAL sign — under the addr-correlate cap (policy B) the farm
//! needs strictly more distinct subnets to deny the block than under the
//! master-id-only cap (policy A) — plus the one-subnet survive/fall witness.
//! Prints PASS/FAIL and the dial-dependent cost-ratio range.
//!
//! Exit code 0 on PASS, 1 on FAIL — so it can gate a script.

use std::process::ExitCode;

use viaticum_sim::sim6;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let seed: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(42);

    let report = sim6::run(seed);
    sim6::print_report(&report);

    if report.pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
