//! SIM-12 — discover the surface FORM on honest data (nonparametric).
//!
//! See `meaning_scenarios_sim.md` SIM-12 and `sim_plan.md` §5. The hypothesis: the
//! reliability surface `r̂(V,τ)` is a FUNCTION whose time/volume shape is a shared
//! OFFLINE prior. The job of this scenario is to OPEN that form nonparametrically
//! on rich HONEST failure data — to recognise which hidden hazard law the
//! generator used (exponential / bathtub / volume-dependent) — WITHOUT being told
//! it. PASS = the nonparametric estimator DISTINGUISHES the forms across a battery
//! of true forms, not "confirms one hardwired form".
//!
//! ## ANTI-ORACLE (the meta-level one, critical)
//!
//! The estimator ([`crate::surface_fit::classify_form`]) sees only the emitted
//! failure OUTCOMES (a [`crate::surface_fit::FailureDataset`] of `time, censored,
//! volume`). The generator's true [`HazardForm`] is hidden in
//! [`crate::failure_gen`] and is NEVER passed into `classify_form`. If the
//! classifier returned a fixed answer regardless of the data, that would be a
//! form-oracle — exactly what the whole 4R redesign fights. The litmus: the only
//! argument to the classifier is `data`. ✓
//!
//! ## Honest scope (record in the output)
//!
//! Green SIM-12 ≠ "the surface form is closed". It = "the discovery apparatus +
//! the off-sample conservatism hold across a battery of plausible forms". The
//! real-world form stays OPEN until there is a deployed fleet to calibrate on.
//!
//! The classifier reliably recovers STRONG-signal forms (clean bathtub, strong
//! volume-dependence, flat exponential); NEAR-THRESHOLD / weak-signal forms (milder
//! bathtub, weak volume-coupling, monotone IFR/DFR with no interior trough) DEFAULT
//! to the conservative exponential form. The boundary is EMPIRICAL, not universal.
//! The interior-trough requirement (a bathtub needs a genuine interior minimum,
//! with the hazard rising above it on BOTH sides) is load-bearing: a pure-IFR
//! (monotone wear-out, `k ≥ 1` — the seniority-KILLING case, the OPPOSITE of the
//! `k < 1` infant-mortality bathtub) is therefore NEVER classified as a bathtub.
//!
//! ## Coupling to SIM-12b (the form-error backstop) — and its honest limit
//!
//! The SIM-12b conservatism guardrail — genuinely holding in BOTH the volume AND time
//! axes for OUT-OF-FAMILY forms (dense-grid worst `r_hat − true_r` ≲ 0.004, verified) —
//! is the backstop for classifier form-error: where the recovered form is wrong, the
//! off-sample inflation keeps `r_hat` on the under-estimate side. The two scenarios are
//! COUPLED: learn the form offline AND be conservative when wrong.
//!
//! ONE honest exception, accepted BY DESIGN (NOT bounded by a number): a holder truly
//! WEARING OUT (pure IFR, k>1) classified as exponential OVER-estimates at long τ. Its
//! magnitude is DIAL-DEPENDENT (grows with k and the fitted λ — a dense sweep measured
//! up to ~0.27 at k=3.0 and higher for larger λ, so it is NOT a ceiling); we deliberately
//! do NOT pin a number (`sim_plan.md §5.1`, structural-vs-measurement: a dial-dependent
//! quantity is not a bound). This is acceptable because wear-out is handled REACTIVELY,
//! not predictively: degradation surfaces as PoS failures → P/G decay → repair within
//! sensor bandwidth (TR-9), redundancy (W12) absorbs the rest, and steeper wear-out is
//! detected FASTER — so the reactive mechanism holds at any magnitude. The surface is NOT
//! relied on to predict wear-out (§1: a cliff is unpredictable anyway). See `foundation
//! §9.12` (wear-out reactive-not-predictive). The only residual cost is possible extra
//! repair churn from over-placing on a degrader — a block-level efficiency question
//! deferred to Phase 2b (placement/R̂), not a safety issue here.

#[cfg(test)]
mod tests;

use viaticum_core::four_r::{SurfacePrior, estimate_surface};

use crate::failure_gen::{self, HazardForm};
use crate::observer;
use crate::surface_fit::{self, RecoveredForm};

/// One row of the SIM-12 battery: a hidden true form, the recovered form, and
/// whether they agree.
#[derive(Debug, Clone)]
pub struct FormRow {
    /// Human label of the hidden true form (for the report).
    pub true_label: &'static str,
    /// What the nonparametric estimator recovered (blind to the truth).
    pub recovered: RecoveredForm,
    /// Whether the recovered form matches the (god-view) expected category.
    pub matched: bool,
}

/// One row of the PERTURBED-form battery: a form whose params sit near the
/// classifier thresholds (milder bathtub, weaker volume-dependence, pure-IFR
/// wear-out). The point is NOT that every one is recovered exactly — near-threshold
/// forms default conservatively — but to DOCUMENT what each becomes and that the
/// misclassification DIRECTION is SAFE.
#[derive(Debug, Clone)]
pub struct PerturbedRow {
    pub label: &'static str,
    /// What the classifier recovered for this perturbed form.
    pub recovered: RecoveredForm,
    /// The qualitative true shape (god-view, for the safe-direction note).
    pub true_shape: &'static str,
    /// A one-line safe-direction verdict: does the SIM-12b conservatism guardrail
    /// catch the resulting form-error?
    pub safe_direction_note: &'static str,
    /// True iff this is a pure-IFR (monotone wear-out) form that the classifier must
    /// NOT call a bathtub (the load-bearing WARN fix). `None` for non-IFR rows.
    pub is_pure_ifr: bool,
}

/// The SIM-12 report: the form-distinction battery, the perturbed-form battery, and
/// the off-sample conservatism check.
#[derive(Debug, Clone)]
pub struct Sim12Report {
    /// One row per baseline true form tried.
    pub rows: Vec<FormRow>,
    /// One row per perturbed (near-threshold) form (the WARN battery).
    pub perturbed: Vec<PerturbedRow>,
    /// True iff every baseline form in the battery was recovered correctly.
    pub all_forms_distinguished: bool,
    /// True iff NO pure-IFR (monotone wear-out) form is classified as a bathtub —
    /// the interior-trough fix for the SIM-12 WARN (a monotone-rising hazard is the
    /// seniority-KILLING `k≥1` case, the opposite of the `k<1` infant-mortality
    /// bathtub, and must never be recovered as bathtub).
    pub no_ifr_classed_bathtub: bool,
    /// True iff a prior calibrated from honest data keeps the kernel estimate
    /// conservative off-sample (lower r_hat far from the observed point).
    pub off_sample_conservative: bool,
    /// Overall PASS.
    pub pass: bool,
}

/// The expected recovered category for a hidden true form (god-view mapping used
/// ONLY to score the result — never fed into the classifier).
///
/// For a plain [`HazardForm::Weibull`] (no infant-mortality mixture, no wear-out
/// offset) the hazard is MONOTONE — there is no interior trough — so the
/// interior-trough detector must NOT call it a bathtub. A monotone-rising pure-IFR
/// (`k ≥ 1`) or monotone-falling DFR (`k < 1`) recovers as the conservative
/// `Exponential` default (the classifier reliably recovers only STRONG-signal
/// forms; a monotone shape with no U is the weak-signal case that defaults
/// conservative — see the honest-scope note). The KEY property tested in the
/// perturbed battery is that pure-IFR is NEVER `Bathtub`.
fn expected(form: HazardForm) -> RecoveredForm {
    match form {
        HazardForm::Exponential { .. } => RecoveredForm::Exponential,
        HazardForm::Bathtub { .. } => RecoveredForm::Bathtub,
        HazardForm::VolumeDependent { .. } => RecoveredForm::VolumeDependent,
        HazardForm::Weibull { .. } => RecoveredForm::Exponential,
    }
}

/// Run SIM-12 end-to-end.
///
/// `n_holders` per form, `seed` the deterministic seed. The horizon is long
/// enough that a meaningful fraction of holders fail (so the curves are rich) yet
/// some survive (so there is censoring to exercise Kaplan-Meier).
pub fn run(n_holders: usize, seed: u64) -> Sim12Report {
    // The battery of HIDDEN true forms (the estimator never sees these).
    let battery: Vec<(&'static str, HazardForm)> = vec![
        (
            "exponential (memoryless)",
            HazardForm::Exponential { rate: 1.0 / 400.0 },
        ),
        (
            "bathtub (infant-mortality + wear-out)",
            HazardForm::Bathtub {
                early_k: 0.5,
                early_lambda: 300.0,
                wearout_onset: 1200.0,
                wearout_rate: 1.0 / 200.0,
            },
        ),
        (
            "volume-dependent hazard",
            HazardForm::VolumeDependent {
                base_rate: 1.0 / 1500.0,
                v_ref: 10.0,
                exponent: 2.0,
            },
        ),
    ];

    let horizon = 2000.0;
    // Classifier knobs (the CONFIDENCE we report the distinction within): a
    // high-volume hazard ≥ 2.5× the low-volume hazard reads as volume-dependent; an
    // INTERIOR trough with the peak BEFORE it AND the peak AFTER it both ≥ 2.0× the
    // trough reads as a bathtub. The interior requirement is load-bearing — a
    // monotone-rising pure-IFR hazard troughs at the start (no interior trough) so
    // it is NOT a bathtub no matter how large its late peak. These are classifier
    // tuning, NOT the generator's parameters. The 2.0 sits in a wide gap: honest
    // exponential data shows early/late-peak/trough ≈ 1.2–1.5 (pure bin noise) while
    // the bathtub shows ≈ 5–10 — a clean, seed-robust split.
    let vol_ratio_thresh = 2.5;
    let bathtub_rel = 2.0;

    let mut rows = Vec::new();
    let mut all_matched = true;
    for (i, (label, form)) in battery.iter().enumerate() {
        let data = failure_gen::generate(
            *form,
            n_holders,
            horizon,
            1.0,
            100.0,
            seed.wrapping_add(i as u64 * 7919),
        );
        // BLIND classification: only `data` goes in. The true `form` is NOT passed.
        let recovered = surface_fit::classify_form(&data, vol_ratio_thresh, bathtub_rel);
        let matched = recovered == expected(*form);
        all_matched &= matched;
        rows.push(FormRow {
            true_label: label,
            recovered,
            matched,
        });
    }

    // ---- PERTURBED-form battery (the SIM-12 WARN: near-threshold robustness). ----
    // The baseline thresholds separate the THREE clean baseline instances; under
    // perturbed params the classifier may default conservatively. The load-bearing
    // property is that a PURE-IFR (monotone wear-out, k≥1, no infant mortality) is
    // NEVER called a bathtub — the interior-trough detector rejects it because its
    // hazard minimum is at the START (no interior trough). pure-IFR is the
    // seniority-KILLING case (formula_phase §3), the OPPOSITE of the k<1 bathtub.
    let perturbed_battery: Vec<(&'static str, HazardForm, &'static str, &'static str, bool)> = vec![
        (
            "milder bathtub (early_k=0.8)",
            HazardForm::Bathtub {
                early_k: 0.8,
                early_lambda: 300.0,
                wearout_onset: 1200.0,
                wearout_rate: 1.0 / 200.0,
            },
            "U-shaped (weaker infant-mortality)",
            "near-threshold: the weak early spike may default to the conservative \
             exponential form rather than bathtub — a conservative miss, and SIM-12b \
             backstops any long-τ error",
            false,
        ),
        (
            "weaker volume-dep (exponent=0.5)",
            HazardForm::VolumeDependent {
                base_rate: 1.0 / 1500.0,
                v_ref: 10.0,
                exponent: 0.5,
            },
            "mild volume-coupling",
            "defaults to exponential (volume signal below threshold) → conservative \
             form; SIM-12b guardrail keeps r_hat ≤ true off-sample",
            false,
        ),
        (
            "pure IFR wear-out (k=1.5)",
            HazardForm::Weibull {
                k: 1.5,
                lambda: 800.0,
            },
            "monotone-rising (NO infant mortality)",
            "NOT bathtub (no interior trough) → exponential default. OVER-estimates at \
             long τ (exponential decays slower than IFR); magnitude DIAL-DEPENDENT, not a \
             fixed bound (sim_plan.md §5.1). Accepted by design: wear-out is caught \
             REACTIVELY (PoS→repair), not surface-predicted (foundation §9.12)",
            true,
        ),
        (
            "pure IFR wear-out (k=3.0)",
            HazardForm::Weibull {
                k: 3.0,
                lambda: 800.0,
            },
            "sharply monotone-rising (NO infant mortality)",
            "NOT bathtub (no interior trough) → exponential default. Over-claim is LARGER \
             than k=1.5 (steeper wear-out; dense sweep ~0.27, λ-dependent) — same REACTIVE \
             handling, and steeper wear-out is detected faster by PoS",
            true,
        ),
    ];

    let mut perturbed = Vec::new();
    let mut no_ifr_classed_bathtub = true;
    for (j, (label, form, shape, note, is_ifr)) in perturbed_battery.iter().enumerate() {
        let data = failure_gen::generate(
            *form,
            n_holders,
            horizon,
            1.0,
            100.0,
            seed.wrapping_add(0x5F3A).wrapping_add(j as u64 * 7919),
        );
        let recovered = surface_fit::classify_form(&data, vol_ratio_thresh, bathtub_rel);
        if *is_ifr && recovered == RecoveredForm::Bathtub {
            no_ifr_classed_bathtub = false;
        }
        perturbed.push(PerturbedRow {
            label,
            recovered,
            true_shape: shape,
            safe_direction_note: note,
            is_pure_ifr: *is_ifr,
        });
    }

    // Cheap in-family smoke check (NOT the load-bearing backstop — that is SIM-12b's
    // dense grid): with a calibrated in-family prior, confirm r_hat is more conservative
    // and its CI wider far off-sample than at the observed point. A 2-point sanity, not
    // evidence of mis-spec safety (which lives in viaticum-sim::sim12b's dense grid).
    let prior = SurfacePrior::default();
    let obs = observer::observe_failure_point(10.0, 30.0, 50, 0);
    let at_obs = estimate_surface(&obs, &prior, 10.0, 30.0);
    let off = estimate_surface(&obs, &prior, 80.0, 600.0);
    let off_sample_conservative =
        off.r_hat < at_obs.r_hat && (off.ci_high - off.ci_low) > (at_obs.ci_high - at_obs.ci_low);

    let all_forms_distinguished = all_matched;
    // PASS now ALSO requires the WARN fix: no pure-IFR is ever called a bathtub.
    let pass = all_forms_distinguished && no_ifr_classed_bathtub && off_sample_conservative;

    Sim12Report {
        rows,
        perturbed,
        all_forms_distinguished,
        no_ifr_classed_bathtub,
        off_sample_conservative,
        pass,
    }
}

/// Pretty-print the SIM-12 report.
pub fn print_report(report: &Sim12Report) {
    println!("=== SIM-12: discover the surface form on honest data (nonparametric) ===");
    println!();
    println!("-- Form-distinction battery (estimator BLIND to the true form) --");
    for row in &report.rows {
        println!(
            "  true: {:<40} recovered: {:?}  [{}]",
            row.true_label,
            row.recovered,
            if row.matched { "MATCH" } else { "MISS" }
        );
    }
    println!();
    println!("-- Perturbed-form battery (near-threshold robustness; the SIM-12 WARN) --");
    for row in &report.perturbed {
        println!(
            "  {:<34} true: {:<34} recovered: {:?}{}",
            row.label,
            row.true_shape,
            row.recovered,
            if row.is_pure_ifr {
                if row.recovered == RecoveredForm::Bathtub {
                    "  [!! pure-IFR called BATHTUB — WARN regression]"
                } else {
                    "  [pure-IFR NOT bathtub ✓]"
                }
            } else {
                ""
            }
        );
        println!("      safe-direction: {}", row.safe_direction_note);
    }
    println!();
    println!(
        "  all baseline forms distinguished (not one hardwired form) : {}",
        report.all_forms_distinguished
    );
    println!(
        "  no pure-IFR classed as bathtub (interior-trough fix)      : {}",
        report.no_ifr_classed_bathtub
    );
    println!(
        "  off-sample estimate stays conservative (B1)               : {}",
        report.off_sample_conservative
    );
    println!();
    println!("RESULT: {}", if report.pass { "PASS" } else { "FAIL" });
    println!();
    println!("HONEST SCOPE (boundary is EMPIRICAL, not universal):");
    println!("  • The classifier reliably recovers STRONG-signal forms (clean bathtub,");
    println!("    strong volume-dependence, flat exponential). NEAR-THRESHOLD / weak-signal");
    println!("    forms (milder bathtub, weak volume-coupling, monotone IFR/DFR with no");
    println!("    interior trough) DEFAULT to the conservative exponential form rather than");
    println!("    over-claiming a structure that is not clearly present.");
    println!("  • The interior-trough requirement makes a pure-IFR (monotone wear-out, k≥1 —");
    println!("    the seniority-KILLING case, the OPPOSITE of the k<1 bathtub) classify as");
    println!("    wear-out/exponential default, NEVER bathtub.");
    println!("  • The SIM-12b guardrail (dense-grid, BOTH axes) is the BACKSTOP for");
    println!("    OUT-OF-FAMILY form-error: r_hat stays on the under-estimate side. ONE");
    println!("    honest exception — a truly-wearing-out (IFR) holder classed as exponential");
    println!("    OVER-claims at long τ; magnitude dial-dependent (not pinned), accepted");
    println!("    because wear-out is handled REACTIVELY (PoS→repair), not predicted.");
    println!("  • Green SIM-12 ≠ \"surface form closed\". The real-world form stays OPEN until");
    println!("    there is a deployed fleet to calibrate on.");
}
