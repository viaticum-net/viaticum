//! SIM-R1 — per-symbol block-survival forecast vs god-view, + calibration. See
//! `sim_refinement_plan.md` SIM-R1 and `sim_plan.md` §5.1.
//!
//! ## What it measures (that the formula does not give)
//!
//! The kernel's [`estimate_block_survival_per_symbol`] gives the Poisson-binomial
//! MECHANICS over heterogeneous per-symbol keep-probs `p_i = surface × s(r;φ_O)`.
//! It does NOT, by itself, tell us whether the ι-rank → `p_i` mapping yields a
//! forecast that MATCHES reality under simulated hardware-death + eviction, nor
//! whether the aggregate-per-holder-average forecast it replaces is systematically
//! off. SIM-R1 answers both against a god-view evaluator.
//!
//! ## Three STRUCTURAL claims (signs, robust to dials — sim_plan.md §5.1)
//!
//! 1. **Conservative calibration.** The kernel's forecast block-R̂ is ≤ the ACTUAL
//!    survival fraction (the safe side — never optimistic), across swept dials.
//! 2. **Per-symbol ordering correct.** A block of HIGH-ι symbols actually survives
//!    MORE than the same block of LOW-ι symbols — the ranking the per-symbol
//!    forecast predicts holds in god-view.
//! 3. **Per-symbol beats aggregate.** The per-symbol forecast is BETTER-CALIBRATED
//!    (lower total |forecast − actual| over both the bottom- and top-rung block,
//!    while staying conservative) than the aggregate-per-holder-average forecast it
//!    replaces. The aggregate is RUNG-BLIND — it averages the ladder, producing one
//!    number for a block whose actual survival differs wildly by rung — so it must
//!    mis-fit at least one rung; the per-symbol forecast tracks both.
//!
//! ## ANTI-ORACLE
//!
//! The kernel forecasts from `FirstHandObs` + the owner's OWN ι-ladder only — it
//! never sees `true_surface` / `true_keep_depth` / `archetype` (no field exists for
//! them, and the sim's `GroundTruth` is not in `viaticum-core`'s graph). The
//! god-view lives ONLY in [`crate::sim_r1::evaluator`], which scores outcomes and
//! never feeds back into a forecast. Litmus: the forecast's arguments are ⊆
//! {`surface r_hat` (from `estimate_surface`), own `G(h←O)`, own observed drops,
//! own ι-ranks} + the owner-private `req`/`prior`/`retention`/`policy`. ✓

#[cfg(test)]
mod tests;

pub mod evaluator;
pub mod generator;
pub mod observer;

use viaticum_core::four_r::{
    BlockReq, HolderPlacement, PlacementPolicy, RetentionPrior, SurfacePrior,
    estimate_block_survival_per_symbol, eviction_retention, retained_depth,
};

use self::generator::{Dial, SimR1Pop};

/// Monte-Carlo trial count for the god-view evaluator (hardware-death is random).
const TRIALS: usize = 4000;

/// One dial's result: the per-symbol forecast vs actual at the bottom and top
/// rungs, plus the aggregate baseline's calibration error, used to verify the
/// three structural claims.
#[derive(Debug, Clone, Copy)]
pub struct DialResult {
    pub dial: Dial,
    /// Forecast block-R̂ for the BOTTOM-rung block (per-symbol kernel).
    pub forecast_low: f64,
    /// Actual survival fraction for the BOTTOM-rung block (god-view).
    pub actual_low: f64,
    /// Forecast block-R̂ for the TOP-rung block (per-symbol kernel).
    pub forecast_high: f64,
    /// Actual survival fraction for the TOP-rung block (god-view).
    pub actual_high: f64,
    /// Aggregate-per-holder-average forecast — RUNG-BLIND (one number used for
    /// both the bottom- and top-rung block, because it averages the ladder).
    pub aggregate: f64,
    /// Total per-symbol calibration error over both rungs (|fc−act| summed).
    pub per_symbol_err: f64,
    /// Total aggregate calibration error over both rungs (|agg−act| summed).
    pub aggregate_err: f64,
    /// (1) forecast ≤ actual at BOTH rungs (conservative, never optimistic).
    pub conservative: bool,
    /// (2) actual_high > actual_low (high-ι symbols survive more in god-view).
    pub ordering_correct: bool,
    /// (3) the per-symbol forecast is strictly better-calibrated (lower total error
    /// over both rungs) than the rung-blind aggregate, AND stays conservative —
    /// the aggregate's single rung-blind number cannot fit both rungs at once.
    pub per_symbol_beats_aggregate: bool,
}

/// Full SIM-R1 report over a battery of dials.
#[derive(Debug, Clone)]
pub struct SimR1Report {
    pub rows: Vec<DialResult>,
    /// Claim 1 held for EVERY dial.
    pub claim_conservative: bool,
    /// Claim 2 held for EVERY dial.
    pub claim_ordering: bool,
    /// Claim 3 held for EVERY dial.
    pub claim_per_symbol_beats_aggregate: bool,
    pub pass: bool,
}

/// Aggregate-per-holder-average forecast — the K2-style estimate the per-symbol
/// model REPLACES. For each holder it computes the AVERAGE keep-prob over the
/// holder's WHOLE ι-ladder (`surface × mean_rung s`) and uses that single average
/// for the block's symbol — so it CANNOT distinguish a bottom-rung from a top-rung
/// block (the very thing the per-symbol model fixes). The Poisson-binomial is then
/// taken over those per-holder averages (one per §7 bucket).
///
/// This is intentionally NOT a kernel function: it is the BASELINE we are showing
/// the per-symbol kernel beats, so it lives in the sim, not in `viaticum-core`.
fn aggregate_forecast(
    placements: &[HolderPlacement],
    prior: &SurfacePrior,
    retention: &RetentionPrior,
    req: &BlockReq,
    policy: &PlacementPolicy,
) -> f64 {
    use viaticum_core::four_r::estimate_surface;
    // Build a synthetic placement set where each holder's symbol carries the
    // per-holder AVERAGE eviction-retention (averaged over the ladder), then reuse
    // the same §7 spread + Poisson-binomial via a tiny local re-implementation that
    // mirrors the kernel's bucketing (we cannot ask the kernel for an average, by
    // design). To stay faithful we compute the per-bucket best of the averaged prob.
    if req.k_eff == 0 {
        return 1.0;
    }
    let v_per_symbol = req.volume_per_symbol();
    let tau = req.tau.max(0.0);

    // Bucket by the kernel's spread key (subnet/master) using the cluster_count
    // helper indirectly: here every holder is on a distinct subnet by construction,
    // so one symbol per holder. We still de-dup defensively by (subnet|master).
    let mut bucket_probs: Vec<(u64, f64)> = Vec::new();
    for hp in placements {
        let surface = estimate_surface(&hp.obs, prior, v_per_symbol, tau)
            .r_hat
            .clamp(0.0, 1.0);
        let phi_o = retained_depth(&hp.obs, retention);
        // Average the eviction-retention over the WHOLE ladder (the aggregate's
        // blindness: it cannot see which rung the block's symbol is at).
        let m = hp.ladder_iotas.len().max(1);
        let mut s_sum = 0.0;
        for rung in 0..m {
            let rank = if m <= 1 {
                0.0
            } else {
                // rank of `rung` in a distinct-ι ladder = rung/(m-1) when sorted,
                // but the ladder may be unsorted; recompute by counting lowers.
                let my = hp.ladder_iotas[rung];
                let lower = hp.ladder_iotas.iter().filter(|&&i| i < my).count();
                lower as f64 / (m - 1) as f64
            };
            s_sum += eviction_retention(rank, phi_o, retention);
        }
        let s_avg = s_sum / m as f64;
        let p = (surface * s_avg).clamp(0.0, 1.0);

        // Spread key matching the kernel's default (subnet); distinct here.
        let key = match policy.cap_mode {
            viaticum_core::four_r::CapMode::MasterIdOnly => hp.obs.master_id.0[0] as u64,
            viaticum_core::four_r::CapMode::AddrCorrelate => hp.obs.addr_subnet as u64,
        };
        match bucket_probs.iter_mut().find(|(k, _)| *k == key) {
            Some((_, best)) => *best = best.max(p),
            None => bucket_probs.push((key, p)),
        }
    }
    if bucket_probs.len() < req.k_eff {
        return 0.0;
    }
    let probs: Vec<f64> = bucket_probs.iter().map(|(_, p)| *p).collect();
    poisson_binomial_at_least(&probs, req.k_eff)
}

/// Local copy of the kernel's Poisson-binomial (the kernel's is private). Used ONLY
/// by the aggregate BASELINE above so the comparison is apples-to-apples.
fn poisson_binomial_at_least(probs: &[f64], k: usize) -> f64 {
    if k == 0 {
        return 1.0;
    }
    let m = probs.len();
    if k > m {
        return 0.0;
    }
    let mut dp = vec![0.0f64; m + 1];
    dp[0] = 1.0;
    let mut filled = 0usize;
    for &p in probs {
        let p = p.clamp(0.0, 1.0);
        let upper = filled + 1;
        for c in (0..=upper).rev() {
            let stay = dp[c] * (1.0 - p);
            let gain = if c > 0 { dp[c - 1] * p } else { 0.0 };
            dp[c] = stay + gain;
        }
        filled = upper;
    }
    dp[k..=m].iter().sum::<f64>().clamp(0.0, 1.0)
}

/// Probe ONE dial: forecast and measure the bottom- and top-rung blocks, and
/// compute the aggregate baseline's calibration. The block uses ALL holders (one
/// symbol per holder; distinct subnets ⇒ §7 spread is the identity here).
fn probe_dial(dial: Dial, seed: u64) -> DialResult {
    let prior = SurfacePrior::default();
    let retention = RetentionPrior::default();
    let policy = PlacementPolicy::default();

    let pop = SimR1Pop::build(dial, seed);
    let n = pop.holders.len();
    let k_eff = (n / 2).max(1); // ask half the holders to survive — a real threshold

    let req = BlockReq {
        volume: 10.0 * n as f64, // per-symbol volume = 10 = observed v0 (in-sample)
        n_symbols: n,
        k_eff,
        tau: 30.0, // = observed τ0 (in-sample ⇒ surface route non-degenerate)
        r_target: 0.99,
    };

    let bottom = 0usize; // lowest-ι rung
    let top = dial.ladder_len.saturating_sub(1); // highest-ι rung

    // --- Per-symbol kernel forecasts (first-hand only) ---
    let plc_low = observer::observe_all(&pop, bottom);
    let plc_high = observer::observe_all(&pop, top);
    let forecast_low =
        estimate_block_survival_per_symbol(&plc_low, &prior, &retention, &req, &policy);
    let forecast_high =
        estimate_block_survival_per_symbol(&plc_high, &prior, &retention, &req, &policy);

    // --- God-view actuals (hardware-death + eviction) ---
    let chosen_low: Vec<(usize, usize)> = (0..n)
        .map(|i| {
            (
                i,
                bottom.min(pop.holders[i].ladder_iotas.len().saturating_sub(1)),
            )
        })
        .collect();
    let chosen_high: Vec<(usize, usize)> = (0..n)
        .map(|i| {
            (
                i,
                top.min(pop.holders[i].ladder_iotas.len().saturating_sub(1)),
            )
        })
        .collect();
    let actual_low =
        evaluator::actual_block_survival(&pop, &chosen_low, k_eff, TRIALS, seed ^ 0x11);
    let actual_high =
        evaluator::actual_block_survival(&pop, &chosen_high, k_eff, TRIALS, seed ^ 0x22);

    // --- Aggregate-per-holder-average baseline (RUNG-BLIND: it averages the whole
    //     ladder, so it produces the SAME number for the bottom- and top-rung block).
    let aggregate = aggregate_forecast(&plc_low, &prior, &retention, &req, &policy);

    // Claim 1: conservative at BOTH rungs (forecast ≤ actual + a tiny MC slack).
    let mc_slack = 0.02; // Monte-Carlo noise tolerance on the actual fraction
    let conservative =
        forecast_low <= actual_low + mc_slack && forecast_high <= actual_high + mc_slack;

    // Claim 2: high-ι actually survives more than low-ι (god-view). Require a clear
    // margin above MC noise so the sign is unambiguous.
    let ordering_correct = actual_high > actual_low + mc_slack;

    // Claim 3: the per-symbol forecast is STRICTLY better-calibrated than the
    // rung-blind aggregate, measured as total |forecast − actual| over BOTH rungs.
    // The aggregate uses ONE ladder-average number for a block whose actual survival
    // differs wildly by rung (bottom ≈ 0, top ≈ 1), so it MUST mis-fit at least one
    // rung; the per-symbol forecast tracks both. This is a structural sign (the
    // aggregate's rung-blindness), robust to the dialed contention level — unlike a
    // "the aggregate is optimistic on the bottom rung" test, which only fires at
    // moderate contention. We additionally require the per-symbol to stay
    // conservative (it does not buy calibration by going optimistic).
    let per_symbol_err = (forecast_low - actual_low).abs() + (forecast_high - actual_high).abs();
    let aggregate_err = (aggregate - actual_low).abs() + (aggregate - actual_high).abs();
    let per_symbol_beats_aggregate = per_symbol_err + 1e-9 < aggregate_err && conservative;

    DialResult {
        dial,
        forecast_low,
        actual_low,
        forecast_high,
        actual_high,
        aggregate,
        per_symbol_err,
        aggregate_err,
        conservative,
        ordering_correct,
        per_symbol_beats_aggregate,
    }
}

/// Run SIM-R1 over a battery of dials and return the structural verdict.
pub fn run(seed: u64) -> SimR1Report {
    // A battery spanning a RANGE of dials (sim_plan.md §5.1: the sign must hold for
    // ALL plausible settings, not one tuned point). Vary holder count, ladder
    // length, surface strength, and contention severity (mean keep-depth).
    let dials = [
        Dial {
            n_holders: 8,
            ladder_len: 4,
            mean_surface: 0.9,
            mean_keep_depth: 0.5,
        },
        Dial {
            n_holders: 10,
            ladder_len: 5,
            mean_surface: 0.85,
            mean_keep_depth: 0.4,
        },
        Dial {
            n_holders: 12,
            ladder_len: 6,
            mean_surface: 0.95,
            mean_keep_depth: 0.6,
        },
        Dial {
            n_holders: 6,
            ladder_len: 3,
            mean_surface: 0.8,
            mean_keep_depth: 0.45,
        },
        Dial {
            n_holders: 14,
            ladder_len: 5,
            mean_surface: 0.9,
            mean_keep_depth: 0.35,
        },
        Dial {
            n_holders: 9,
            ladder_len: 4,
            mean_surface: 0.88,
            mean_keep_depth: 0.55,
        },
    ];

    let mut rows = Vec::new();
    let mut claim_conservative = true;
    let mut claim_ordering = true;
    let mut claim_per_symbol_beats_aggregate = true;

    for (i, dial) in dials.iter().enumerate() {
        let s = seed.wrapping_add(i as u64 * 7919);
        let row = probe_dial(*dial, s);
        claim_conservative &= row.conservative;
        claim_ordering &= row.ordering_correct;
        claim_per_symbol_beats_aggregate &= row.per_symbol_beats_aggregate;
        rows.push(row);
    }

    let pass = claim_conservative && claim_ordering && claim_per_symbol_beats_aggregate;

    SimR1Report {
        rows,
        claim_conservative,
        claim_ordering,
        claim_per_symbol_beats_aggregate,
        pass,
    }
}

/// Pretty-print the SIM-R1 report.
pub fn print_report(report: &SimR1Report) {
    println!("=== SIM-R1: per-symbol block-survival forecast vs god-view (structural) ===");
    println!();
    println!("THREE STRUCTURAL CLAIMS (signs, robust to dials — sim_plan.md §5.1):");
    println!("  (1) conservative  : per-symbol forecast R̂ ≤ actual survival (never optimistic)");
    println!("  (2) ordering      : high-ι symbols actually survive MORE than low-ι (god-view)");
    println!("  (3) beats-aggregate: per-symbol total error (both rungs) < rung-blind aggregate,");
    println!("                       while staying conservative (the aggregate cannot fit both)");
    println!();
    println!(
        "{:<26} {:>8} {:>8} {:>8} {:>8} {:>8} {:>7} {:>7}",
        "dial (n,ladder,surf,keep)",
        "fc_low",
        "act_low",
        "fc_high",
        "act_hi",
        "agg",
        "ps_err",
        "agg_err"
    );
    for r in &report.rows {
        println!(
            "n={:>2} L={:>2} s={:.2} d={:.2}    {:>8.4} {:>8.4} {:>8.4} {:>8.4} {:>8.4} {:>7.4} {:>7.4}  [{}{}{}]",
            r.dial.n_holders,
            r.dial.ladder_len,
            r.dial.mean_surface,
            r.dial.mean_keep_depth,
            r.forecast_low,
            r.actual_low,
            r.forecast_high,
            r.actual_high,
            r.aggregate,
            r.per_symbol_err,
            r.aggregate_err,
            if r.conservative { "C" } else { "." },
            if r.ordering_correct { "O" } else { "." },
            if r.per_symbol_beats_aggregate {
                "A"
            } else {
                "."
            },
        );
    }
    println!();
    println!(
        "  (1) conservative for EVERY dial               : {}",
        report.claim_conservative
    );
    println!(
        "  (2) ι-ordering correct for EVERY dial         : {}",
        report.claim_ordering
    );
    println!(
        "  (3) per-symbol beats aggregate for EVERY dial : {}",
        report.claim_per_symbol_beats_aggregate
    );
    println!();
    println!("RESULT: {}", if report.pass { "PASS" } else { "FAIL" });
    println!();
    println!("HONEST FRAME (sim_plan.md §5.1):");
    println!("  • The PASS criteria are SIGNS (conservative, ordering, beats-aggregate),");
    println!("    asserted robust across the dial sweep — NOT measured magnitudes.");
    println!("  • god-view (true_surface / true_keep_depth) lives ONLY in the evaluator;");
    println!("    the kernel forecasts from FirstHandObs + the owner's own ι-ladder.");
}
