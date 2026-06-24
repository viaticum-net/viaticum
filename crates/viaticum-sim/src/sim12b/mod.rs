//! SIM-12b — graceful degradation under MIS-SPECIFICATION (the ⭐#2 deliverable).
//!
//! See `meaning_scenarios_sim.md` SIM-12b and `sim_plan.md` §5. The generator uses
//! an OUT-OF-FAMILY true hazard the parametric backbone CANNOT represent
//! (multimodal; long-plateau-then-cliff). We fit the best in-family
//! [`SurfacePrior`] to that data, feed it into [`estimate_surface`], and check over
//! a DENSE `(v, τ)` grid that the estimate stays CONSERVATIVE: `r_hat ≤ true_r` (it
//! UNDER-estimates reliability) EVEN THOUGH the form is wrong.
//!
//! The deliverable is **"when we are wrong about the form, the inflated-uncertainty
//! guardrail still keeps the estimate on the safe (under-estimate) side"**, NOT "we
//! found the form". The PASS rests on the DENSE grid (every `(v, τ)`), not on lucky
//! probe points: the worst `r_hat − true_r` over the whole grid — and where it
//! occurs — is computed and REPORTED. An earlier 4-point probe (all at high volume,
//! `v 40–100`) was a RIGGED green: at high volume the `(v/v_dem)^p` hazard
//! multiplier crushes `r_hat ≈ 0` and dodges the real failure region. The dense
//! grid INCLUDES `v ≤ v_dem` and the long-τ interior, where the off-sample
//! conservatism has to come from the TIME axis alone (no volume multiplier to
//! rescue it) — exactly where the old `ln(τ/τ0)` distance was too weak.
//!
//! ## The coupled counter-check (CRITICAL — not "make it green")
//!
//! Strengthening the off-sample inflation could trivially pass by crushing EVERY
//! estimate to zero — which would make long-horizon backup impossible. So we ALSO
//! run an IN-FAMILY-CORRECT check: with the prior form CORRECT (the data really are
//! the Weibull the prior assumes), at long τ and a reasonable observation window the
//! kernel's `r_hat` must stay a USEFUL (non-vacuous) fraction of the true survival.
//! The report carries BOTH: (i) out-of-family stays conservative, (ii)
//! in-family-correct stays useful. This is the real architecture from
//! `formula_phase.md` §3 — learn the form offline AND be conservative when wrong;
//! the two are coupled, and the boundary is empirical, not universal.
//!
//! Deferred (recorded honestly): the downstream "over-place → blocks survive"
//! consequence needs `place`/`R̂` (Phase 2b). Here we test the estimate-level
//! conservatism directly — `r_hat ≤ true_r` at the surface — which is the
//! load-bearing precondition for that downstream safety.

#[cfg(test)]
mod tests;

use viaticum_core::four_r::{SurfacePrior, estimate_surface};

use crate::failure_gen::{self, OutOfFamily};
use crate::observer;
use crate::surface_fit;

/// Reliability floor below which a survival claim is operationally zero: no block
/// is ever placed expecting `r ≤ R_NEGLIGIBLE`, so a claim at or below it cannot
/// cause over-placement and is not a DANGEROUS over-estimate. Used to tolerate the
/// harmless residual of the backbone's exponential tail (e.g. `r_hat ≈ 2e-8` where
/// the true survival is exactly 0) when judging off-sample conservatism.
const R_NEGLIGIBLE: f64 = 1e-6;

/// Maximum tolerated OPERATIONAL over-estimate: the dense grid PASSES only if the
/// worst `r_hat − true_r` over the whole grid stays at or below this. A 2%
/// over-claim in reliability is the chosen ε — small enough that it cannot move a
/// placement decision materially (redundancy is sized in whole symbols), defensible
/// as "operationally on the safe side". The `R_NEGLIGIBLE` floor above is a
/// SEPARATE, stricter tolerance reserved for points whose true survival is
/// genuinely ~0 (a tiny residual there is not a meaningful over-claim).
const MAX_OPERATIONAL_OVERAGE: f64 = 0.02;

/// Long-τ point at which the in-family-CORRECT counter-check must remain useful,
/// and the observation window the node is assumed to have. `τ0 = 365` days models
/// a node that watched the holder for about a year (realistic for cold backup,
/// where relationships are long); `τ = 730` days is a two-year horizon. The
/// strengthened inflation must NOT crush a correctly-specified prior to zero here.
const COUNTER_OBS_TAU0: f64 = 365.0;
const COUNTER_LONG_TAU: f64 = 730.0;
/// The in-family `r_hat` at the long-τ counter-point must be at least this fraction
/// of the true Weibull survival there — i.e. the estimate is conservative but NOT
/// vacuous (long-horizon backup stays possible when the form is right).
const COUNTER_MIN_USEFUL_FRACTION: f64 = 0.25;

/// One off-sample grid point and the conservatism verdict there.
#[derive(Debug, Clone, Copy)]
pub struct ProbePoint {
    pub v: f64,
    pub tau: f64,
    /// Kernel conservative estimate at `(v, τ)`.
    pub r_hat: f64,
    /// God-view TRUE survival at `(v, τ)` for the out-of-family form.
    pub true_r: f64,
    /// `r_hat − true_r` (positive = over-estimate, the unsafe direction).
    pub overage: f64,
    /// True iff this point is NOT a dangerous over-estimate.
    pub conservative: bool,
}

/// One out-of-family form's result over the DENSE grid.
#[derive(Debug, Clone)]
pub struct OofRow {
    pub label: &'static str,
    /// The in-family scale we fitted (`λ_W`) — the form (k) is the offline default.
    pub fitted_lambda: f64,
    /// Total dense-grid points evaluated.
    pub grid_points: usize,
    /// Number of grid points whose over-estimate exceeds `MAX_OPERATIONAL_OVERAGE`.
    pub n_over: usize,
    /// The worst (largest) `r_hat − true_r` over the WHOLE dense grid.
    pub worst_overage: f64,
    /// The grid point where the worst overage occurs (for the report).
    pub worst_at: ProbePoint,
    /// A few illustrative low-`v`, long-`τ` probe points (the region the old
    /// 4-point probe never visited) for the human-readable report.
    pub sample_probes: Vec<ProbePoint>,
    /// True iff no grid point is a dangerous over-estimate.
    pub all_conservative: bool,
}

/// The in-family-CORRECT usefulness counter-check (anti-"crush everything to 0").
#[derive(Debug, Clone, Copy)]
pub struct InFamilyUsefulness {
    /// Observation window assumed (days).
    pub obs_tau0: f64,
    /// Long horizon queried (days).
    pub long_tau: f64,
    /// True Weibull survival at the long horizon (form == prior, so this is exact).
    pub true_r: f64,
    /// Kernel conservative `r_hat` there with the CORRECT prior.
    pub r_hat: f64,
    /// `r_hat / true_r` — must stay above `COUNTER_MIN_USEFUL_FRACTION`.
    pub useful_fraction: f64,
    /// True iff the estimate is conservative (`r_hat ≤ true_r`) yet still useful.
    pub useful: bool,
}

/// The SIM-12b report.
#[derive(Debug, Clone)]
pub struct Sim12bReport {
    pub rows: Vec<OofRow>,
    /// True iff every out-of-family form stays conservative across the whole grid.
    pub all_conservative: bool,
    /// The coupled counter-check: a correctly-specified prior stays useful at long τ.
    pub in_family_useful: InFamilyUsefulness,
    /// Overall PASS = out-of-family conservative AND in-family-correct still useful.
    pub pass: bool,
}

/// Fit the best in-family scale `λ_W` from out-of-family data while KEEPING the
/// offline form (`k`, volume exponent). This is the "best in-family fit": the
/// production machinery learns the SCALE online (formula_phase.md §3 "λ_W online,
/// k offline"); the FORM is the offline prior and is deliberately mis-specified
/// here (the data are out-of-family). We match the median: choose `λ_W` so the
/// Weibull median `λ·(ln 2)^{1/k}` equals the empirical median failure time.
fn fit_in_family_lambda(data: &surface_fit::FailureDataset, form_k: f64) -> f64 {
    // Empirical median of the OBSERVED FAILURE times (uncensored), a robust scale.
    let mut fails: Vec<f64> = data
        .obs
        .iter()
        .filter(|o| !o.censored)
        .map(|o| o.time)
        .collect();
    if fails.is_empty() {
        // No failures observed → fall back to the overall median time.
        fails = data.obs.iter().map(|o| o.time).collect();
    }
    fails.sort_by(|a, b| a.total_cmp(b));
    let median = if fails.is_empty() {
        365.0
    } else {
        fails[fails.len() / 2]
    };
    // Weibull median = λ·(ln 2)^{1/k}  ⇒  λ = median / (ln 2)^{1/k}.
    let k = form_k.max(1e-9);
    median / (std::f64::consts::LN_2).powf(1.0 / k).max(1e-9)
}

/// Evaluate one grid point: kernel `r_hat` vs god-view `true_r`, conservatism
/// verdict (no dangerous over-estimate). `true_r` is a large-MC truth.
fn eval_point(
    obs: &viaticum_core::four_r::FirstHandObs,
    prior: &SurfacePrior,
    form: OutOfFamily,
    v: f64,
    tau: f64,
    true_r_seed: u64,
) -> ProbePoint {
    let r_hat = estimate_surface(obs, prior, v, tau).r_hat;
    // The OOF forms are time-only by construction (volume does not enter their
    // hidden time process), so the true survival depends on τ alone.
    let true_r = failure_gen::true_survival_oof(form, tau, 200_000, true_r_seed);
    let overage = r_hat - true_r;
    // "Conservative" = NO DANGEROUS over-estimate. Two tolerances, both honest:
    // (a) where the truth is genuinely ~0, a residual below `R_NEGLIGIBLE` is not a
    //     meaningful over-claim (no block is placed expecting it);
    // (b) elsewhere, an over-claim up to `MAX_OPERATIONAL_OVERAGE` (2% reliability)
    //     is below what could move a whole-symbol placement decision.
    let conservative = r_hat <= true_r.max(R_NEGLIGIBLE) || overage <= MAX_OPERATIONAL_OVERAGE;
    ProbePoint {
        v,
        tau,
        r_hat,
        true_r,
        overage,
        conservative,
    }
}

/// Run SIM-12b end-to-end.
pub fn run(n_holders: usize, seed: u64) -> Sim12bReport {
    let horizon = 3000.0;
    // OUT-OF-FAMILY battery (Weibull × power-volume cannot represent these).
    let battery: Vec<(&'static str, OutOfFamily)> = vec![
        (
            "multimodal (early burst + late burst)",
            OutOfFamily::Multimodal {
                early_frac: 0.4,
                early_center: 200.0,
                early_spread: 60.0,
                late_center: 1600.0,
                late_spread: 150.0,
            },
        ),
        (
            "plateau-then-cliff (deadline / heavy tail)",
            OutOfFamily::PlateauCliff {
                plateau: 1000.0,
                cliff_width: 200.0,
                plateau_rate: 1.0 / 20000.0,
            },
        ),
    ];

    let base_prior = SurfacePrior::default();
    // The node's one observed slice (production view) with a clean PoS history at
    // `(V0=10, τ0=30)`. `v_dem = 10`.
    let obs = observer::observe_failure_point(10.0, 30.0, 50, 0);
    let v_dem = obs.v_dem; // 10.0

    // DENSE `(v, τ)` grid. CRUCIALLY it INCLUDES `v ≤ v_dem` (where the
    // `(v/v_dem)^p` volume multiplier is absent and conservatism must come from the
    // TIME axis alone) and the LONG-τ interior (where a wrong slowly-decaying
    // backbone tail would over-estimate). The old 4-point probe sat only at
    // `v 40–100` and dodged exactly this region — a rigged green.
    //   v: 1 .. 2·v_dem (covers v < v_dem, v ≈ v_dem, v > v_dem)
    //   τ: τ0 .. ~horizon (the whole interior, not just a couple of points)
    let n_v = 50usize;
    let n_tau = 100usize;
    let v_max = 2.0 * v_dem; // = 20: spans below, at, and above demonstrated scale.
    let tau0 = obs.observed_tau; // 30
    let tau_max = 2900.0;

    let mut rows = Vec::new();
    let mut all_conservative = true;

    for (i, (label, form)) in battery.iter().enumerate() {
        let data = failure_gen::generate_oof(
            *form,
            n_holders,
            horizon,
            1.0,
            100.0,
            seed.wrapping_add(i as u64 * 104729),
        );
        // Fit the in-family SCALE; KEEP the offline FORM (mis-specified on purpose).
        let lambda = fit_in_family_lambda(&data, base_prior.weibull_k);
        let prior = SurfacePrior {
            weibull_lambda_default: lambda,
            ..base_prior.clone()
        };
        let true_r_seed = seed.wrapping_add(0xBEEF).wrapping_add(i as u64);

        let mut grid_points = 0usize;
        let mut n_over = 0usize;
        let mut worst_overage = f64::NEG_INFINITY;
        let mut worst_at = ProbePoint {
            v: 0.0,
            tau: 0.0,
            r_hat: 0.0,
            true_r: 0.0,
            overage: f64::NEG_INFINITY,
            conservative: true,
        };
        let mut row_conservative = true;

        for vi in 0..n_v {
            // v in (0, v_max], including the sub-`v_dem` band.
            let v = v_max * (vi as f64 + 1.0) / n_v as f64;
            for ti in 0..n_tau {
                let tau = tau0 + (tau_max - tau0) * (ti as f64) / (n_tau as f64 - 1.0);
                let p = eval_point(&obs, &prior, *form, v, tau, true_r_seed);
                grid_points += 1;
                if p.overage > worst_overage {
                    worst_overage = p.overage;
                    worst_at = p;
                }
                if !p.conservative {
                    n_over += 1;
                    row_conservative = false;
                }
            }
        }

        // A few illustrative low-v, long-τ probes (the region the old probe missed).
        let sample_probes: Vec<ProbePoint> = [(1.0, 1830.0), (5.0, 1830.0), (1.0, 1200.0)]
            .iter()
            .map(|&(v, tau)| eval_point(&obs, &prior, *form, v, tau, true_r_seed))
            .collect();

        all_conservative &= row_conservative;
        rows.push(OofRow {
            label,
            fitted_lambda: lambda,
            grid_points,
            n_over,
            worst_overage,
            worst_at,
            sample_probes,
            all_conservative: row_conservative,
        });
    }

    // ---- Coupled counter-check: in-family-CORRECT prior stays USEFUL at long τ. ----
    // With the prior form CORRECT, the data really are the default Weibull; the true
    // survival is the analytic Weibull tail. A node that observed the holder for a
    // realistic window (`τ0 = 365`) and asks about a two-year horizon must still get
    // a non-vacuous `r_hat`. This is the proof that the strengthened inflation did
    // NOT pass by crushing everything to zero.
    let correct_prior = base_prior.clone();
    let counter_obs = observer::observe_failure_point(10.0, COUNTER_OBS_TAU0, 50, 0);
    let counter_r_hat =
        estimate_surface(&counter_obs, &correct_prior, 10.0, COUNTER_LONG_TAU).r_hat;
    let counter_true = failure_gen::true_survival_weibull(
        correct_prior.weibull_k,
        correct_prior.weibull_lambda_default,
        COUNTER_LONG_TAU,
    );
    let useful_fraction = if counter_true > 0.0 {
        counter_r_hat / counter_true
    } else {
        0.0
    };
    let in_family_useful = InFamilyUsefulness {
        obs_tau0: COUNTER_OBS_TAU0,
        long_tau: COUNTER_LONG_TAU,
        true_r: counter_true,
        r_hat: counter_r_hat,
        useful_fraction,
        // Conservative (r_hat ≤ true_r) AND non-vacuous (≥ min useful fraction).
        useful: counter_r_hat <= counter_true + 1e-12
            && useful_fraction >= COUNTER_MIN_USEFUL_FRACTION,
    };

    let pass = all_conservative && in_family_useful.useful;
    Sim12bReport {
        rows,
        all_conservative,
        in_family_useful,
        pass,
    }
}

/// Pretty-print the SIM-12b report.
pub fn print_report(report: &Sim12bReport) {
    println!("=== SIM-12b: graceful degradation under MIS-SPECIFICATION (out-of-family) ===");
    println!();
    for row in &report.rows {
        println!(
            "-- {} (fitted λ_W = {:.1}, offline form k kept) --",
            row.label, row.fitted_lambda
        );
        println!(
            "    dense grid: {} points  |  over {:.0}% threshold: {}  |  worst overage = {:.4}",
            row.grid_points,
            MAX_OPERATIONAL_OVERAGE * 100.0,
            row.n_over,
            row.worst_overage
        );
        let w = &row.worst_at;
        println!(
            "    worst at v={:>5.1} τ={:>6.0}:  r_hat={:.4}  true_r={:.4}  [{}]",
            w.v,
            w.tau,
            w.r_hat,
            w.true_r,
            if w.conservative {
                "conservative ✓"
            } else {
                "OVER-ESTIMATE ✗"
            }
        );
        for p in &row.sample_probes {
            println!(
                "      probe v={:>4.0} τ={:>6.0}:  r_hat={:.4}  true_r={:.4}  (low-v long-τ region)",
                p.v, p.tau, p.r_hat, p.true_r
            );
        }
        if !row.all_conservative {
            println!(
                "    !! {} grid points over the {:.0}% operational threshold (HONEST finding: \
                 guardrail needs more inflation here)",
                row.n_over,
                MAX_OPERATIONAL_OVERAGE * 100.0
            );
        }
        println!();
    }
    println!(
        "  (i)  out-of-family stays conservative over the DENSE grid : {}",
        report.all_conservative
    );
    let u = &report.in_family_useful;
    println!(
        "  (ii) in-family-CORRECT stays USEFUL at long τ (τ0={:.0}, τ={:.0}): r_hat={:.4} \
         true_r={:.4} fraction={:.2} → {}",
        u.obs_tau0,
        u.long_tau,
        u.r_hat,
        u.true_r,
        u.useful_fraction,
        if u.useful {
            "useful ✓"
        } else {
            "VACUOUS ✗"
        }
    );
    println!();
    println!("RESULT: {}", if report.pass { "PASS" } else { "FAIL" });
    println!();
    println!("DELIVERABLE: \"when we are WRONG about the form, the inflated-uncertainty guardrail");
    println!(
        "still keeps the estimate on the safe (under-estimate) side\" — NOT \"we found the form\"."
    );
    println!("COUPLED: the guardrail is strengthened in BOTH axes (volume linear, time √) AND a");
    println!("correctly-specified prior stays useful at long τ — mis-spec safety ⇄ usefulness.");
    println!("DEFERRED (Phase 2b): the downstream over-place → blocks-survive consequence needs");
    println!("place/R̂; here the estimate-level conservatism r_hat ≤ true_r is tested directly.");
}
