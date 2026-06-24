use super::*;

#[test]
fn sim12b_dense_grid_stays_conservative_under_mis_spec() {
    // The #2 deliverable: with an OUT-OF-FAMILY true form (the backbone cannot
    // represent it), the kernel's r_hat must NOT dangerously exceed the true
    // survival ANYWHERE on a dense (v, τ) grid that INCLUDES v ≤ v_dem and the
    // long-τ interior — it under-estimates reliability (the safe side), EVEN THOUGH
    // the form is wrong. The inflated-uncertainty guardrail carries the safety in
    // BOTH axes, not just where a lucky high-volume probe crushes r_hat to 0.
    let report = run(20000, 42);
    assert!(
        report.all_conservative,
        "every out-of-family dense-grid point must be conservative; rows: {:?}",
        report.rows
    );
    // The worst overage over the WHOLE grid must sit at or below the operational
    // threshold for every form (this is the honest, dense-grid-based PASS, not a
    // hand-picked point).
    for row in &report.rows {
        assert!(
            row.worst_overage <= MAX_OPERATIONAL_OVERAGE + 1e-9,
            "form {} worst overage {:.4} must be ≤ {:.4} (at v={:.1} τ={:.0}, r_hat={:.4} \
             true_r={:.4})",
            row.label,
            row.worst_overage,
            MAX_OPERATIONAL_OVERAGE,
            row.worst_at.v,
            row.worst_at.tau,
            row.worst_at.r_hat,
            row.worst_at.true_r,
        );
        assert_eq!(row.n_over, 0, "no grid point may exceed the threshold");
    }
    assert!(report.pass, "SIM-12b must PASS overall");
}

#[test]
fn sim12b_grid_actually_covers_the_dodged_region() {
    // Guard the test's own validity: the dense grid must REACH the region the old
    // 4-point probe never visited — low volume (v < v_dem = 10) AND long τ. If the
    // grid only sat at high volume / short τ, "conservative" would be the same
    // rigged green the review caught.
    let report = run(10000, 42);
    for row in &report.rows {
        assert!(
            row.grid_points >= 1000,
            "grid must be dense (got {})",
            row.grid_points
        );
        // The illustrative probes are explicitly in the low-v, long-τ region.
        assert!(
            row.sample_probes
                .iter()
                .any(|p| p.v < 10.0 && p.tau > 1000.0),
            "sample probes must include the low-v long-τ region the old probe dodged"
        );
    }
    // The worst overage is found somewhere — recorded with its location — so a
    // future regression that re-introduces the over-estimate is visible, not hidden.
    assert!(report.rows.iter().all(|r| r.worst_overage.is_finite()));
}

#[test]
fn sim12b_in_family_correct_prior_stays_useful_at_long_tau() {
    // The CRITICAL counter-check: the strengthened off-sample inflation must NOT
    // pass by crushing every estimate to zero. With the prior form CORRECT (the
    // data really are the assumed Weibull) and a realistic observation window, the
    // long-τ r_hat must stay a USEFUL (non-vacuous) fraction of the true survival —
    // long-horizon backup is still possible when the form is right.
    let report = run(20000, 42);
    let u = report.in_family_useful;
    assert!(
        u.r_hat <= u.true_r + 1e-12,
        "in-family estimate must still be conservative (r_hat {:.4} ≤ true_r {:.4})",
        u.r_hat,
        u.true_r
    );
    assert!(
        u.useful_fraction >= COUNTER_MIN_USEFUL_FRACTION,
        "in-family-correct r_hat must stay useful at long τ: r_hat={:.4} true_r={:.4} \
         fraction={:.2} (min {:.2}) — if this fails the inflation crushed a correct prior \
         to zero (a real mis-spec-safety vs usefulness tension, not a tuning nit)",
        u.r_hat,
        u.true_r,
        u.useful_fraction,
        COUNTER_MIN_USEFUL_FRACTION
    );
    assert!(u.useful, "in-family usefulness check must pass");
}

#[test]
fn sim12b_is_deterministic() {
    let a = run(10000, 5);
    let b = run(10000, 5);
    assert_eq!(a.pass, b.pass);
    for (x, y) in a.rows.iter().zip(b.rows.iter()) {
        assert!((x.fitted_lambda - y.fitted_lambda).abs() < 1e-9);
        assert_eq!(x.all_conservative, y.all_conservative);
        assert!((x.worst_overage - y.worst_overage).abs() < 1e-9);
        assert_eq!(x.n_over, y.n_over);
    }
    assert!((a.in_family_useful.r_hat - b.in_family_useful.r_hat).abs() < 1e-12);
}

#[test]
fn sim12b_holds_across_several_seeds() {
    // Conservatism over the dense grid AND in-family usefulness must hold across the
    // out-of-family battery for several seeds — a guardrail, not a lucky single run.
    for seed in [1u64, 2, 3, 77, 54321] {
        let report = run(15000, seed);
        assert!(
            report.all_conservative,
            "out-of-family dense-grid conservatism must hold for seed {seed}; rows: {:?}",
            report.rows
        );
        assert!(
            report.in_family_useful.useful,
            "in-family usefulness must hold for seed {seed}: {:?}",
            report.in_family_useful
        );
    }
}

#[test]
fn sim12b_conservatism_is_not_vacuous() {
    // The conservatism claim must bite somewhere real: at least one grid point per
    // form must have a MEANINGFULLY POSITIVE true survival where the kernel still
    // under-estimates (r_hat < true_r). Otherwise "r_hat ≤ true_r" could hold only
    // because the truth collapsed to zero everywhere (a vacuous pass). The worst
    // overage is recorded at the WORST point; here we re-derive that the grid spans
    // points where the holder is genuinely reliable yet the estimate is on the safe
    // side. We probe the multimodal plateau (τ around 1000–1200, before the late
    // burst) where true survival is high.
    let report = run(20000, 42);
    // multimodal: at τ=1000 (between the early burst ~200 and late burst ~1600) the
    // true survival is high (~0.6); the kernel must under-estimate it there.
    use crate::failure_gen::{self, OutOfFamily};
    let form = OutOfFamily::Multimodal {
        early_frac: 0.4,
        early_center: 200.0,
        early_spread: 60.0,
        late_center: 1600.0,
        late_spread: 150.0,
    };
    let lambda = report.rows[0].fitted_lambda;
    let prior = SurfacePrior {
        weibull_lambda_default: lambda,
        ..SurfacePrior::default()
    };
    let obs = observer::observe_failure_point(10.0, 30.0, 50, 0);
    let r_hat = estimate_surface(&obs, &prior, 5.0, 1000.0).r_hat;
    let true_r = failure_gen::true_survival_oof(form, 1000.0, 200_000, 42u64.wrapping_add(0xBEEF));
    assert!(
        true_r > 0.3,
        "the plateau between the two bursts must have high true survival: {true_r}"
    );
    assert!(
        r_hat < true_r,
        "the kernel must UNDER-estimate a genuinely-reliable holder (not vacuously 0): \
         r_hat={r_hat} true_r={true_r}"
    );
}
