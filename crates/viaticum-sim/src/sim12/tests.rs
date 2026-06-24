use super::*;

#[test]
fn sim12_distinguishes_all_forms_and_passes() {
    // The whole scenario: the nonparametric estimator, BLIND to the generator's
    // true form, recovers the distinct category for every baseline form, no pure-IFR
    // is ever called a bathtub (the WARN fix), and the kernel estimate stays
    // conservative off-sample.
    let report = run(5000, 42);
    assert!(
        report.all_forms_distinguished,
        "every hidden baseline form must be distinguished: {:?}",
        report.rows
    );
    assert!(
        report.no_ifr_classed_bathtub,
        "no pure-IFR form may be classified as a bathtub: {:?}",
        report.perturbed
    );
    assert!(
        report.off_sample_conservative,
        "kernel estimate must stay conservative off-sample"
    );
    assert!(report.pass, "SIM-12 must PASS overall");
}

#[test]
fn sim12_pure_ifr_is_never_bathtub() {
    // The load-bearing WARN fix: a pure-IFR (monotone wear-out, k≥1, NO infant
    // mortality) must NOT classify as bathtub — it has no interior trough. This is
    // the seniority-KILLING case (formula_phase §3), semantically the OPPOSITE of
    // the k<1 infant-mortality bathtub; the old global-min detector accepted it.
    for seed in [1u64, 2, 3, 42, 12345] {
        let report = run(5000, seed);
        for row in report.perturbed.iter().filter(|r| r.is_pure_ifr) {
            assert_ne!(
                row.recovered,
                RecoveredForm::Bathtub,
                "pure-IFR '{}' must not be bathtub (seed {seed}); recovered {:?}",
                row.label,
                row.recovered
            );
        }
        assert!(report.no_ifr_classed_bathtub, "seed {seed}");
    }
}

#[test]
fn sim12_perturbed_battery_is_documented() {
    // The perturbed (near-threshold) battery must run and record a safe-direction
    // note for every row — the documentation the WARN asks for, not a silent pass.
    let report = run(5000, 42);
    assert!(
        report.perturbed.len() >= 4,
        "the perturbed battery must cover milder bathtub, weak vol-dep, and pure-IFR"
    );
    assert!(
        report.perturbed.iter().filter(|r| r.is_pure_ifr).count() >= 2,
        "at least two pure-IFR rows (k=1.5 and k=3.0)"
    );
    for row in &report.perturbed {
        assert!(
            !row.safe_direction_note.is_empty(),
            "every perturbed row must carry a safe-direction note: {}",
            row.label
        );
    }
}

#[test]
fn sim12_is_deterministic() {
    let a = run(3000, 7);
    let b = run(3000, 7);
    assert_eq!(a.pass, b.pass);
    for (x, y) in a.rows.iter().zip(b.rows.iter()) {
        assert_eq!(x.recovered, y.recovered);
        assert_eq!(x.matched, y.matched);
    }
    for (x, y) in a.perturbed.iter().zip(b.perturbed.iter()) {
        assert_eq!(x.recovered, y.recovered);
    }
}

#[test]
fn sim12_distinguishes_across_several_seeds() {
    // PASS = distinguishes a battery, not "confirms one hardwired form": the
    // distinction must hold for several independent seeds, not a lucky one.
    for seed in [1u64, 2, 3, 99, 12345] {
        let report = run(5000, seed);
        assert!(
            report.all_forms_distinguished,
            "forms must be distinguished for seed {seed}: {:?}",
            report.rows
        );
    }
}
