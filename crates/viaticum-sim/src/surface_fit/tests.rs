use super::*;
use crate::failure_gen::{self, HazardForm};

// ---- Kaplan-Meier ----

#[test]
fn kaplan_meier_steps_down_at_each_failure() {
    // Three uncensored failures at distinct times: S steps 1 → 2/3 → 1/3 → 0.
    let mut data = FailureDataset::new();
    for &t in &[10.0, 20.0, 30.0] {
        data.push(FailureObs {
            time: t,
            censored: false,
            volume: 1.0,
        });
    }
    let km = kaplan_meier(&data);
    assert_eq!(km.times, vec![10.0, 20.0, 30.0]);
    assert!((km.at(5.0) - 1.0).abs() < 1e-12);
    assert!((km.at(10.0) - 2.0 / 3.0).abs() < 1e-12);
    assert!((km.at(25.0) - 1.0 / 3.0).abs() < 1e-12);
    assert!((km.at(35.0) - 0.0).abs() < 1e-12);
}

#[test]
fn kaplan_meier_survival_is_non_increasing() {
    let data = failure_gen::generate(
        HazardForm::Exponential { rate: 1.0 / 100.0 },
        2000,
        500.0,
        1.0,
        10.0,
        7,
    );
    let km = kaplan_meier(&data);
    for w in km.survival.windows(2) {
        assert!(w[1] <= w[0] + 1e-12, "KM survival must be non-increasing");
    }
}

#[test]
fn kaplan_meier_handles_censoring_without_dropping_to_zero() {
    // A censored observation does NOT step S down; with only censoring, S stays 1.
    let mut data = FailureDataset::new();
    for &t in &[10.0, 20.0, 30.0] {
        data.push(FailureObs {
            time: t,
            censored: true,
            volume: 1.0,
        });
    }
    let km = kaplan_meier(&data);
    assert!(km.times.is_empty(), "no events ⇒ no steps");
    assert!((km.at(100.0) - 1.0).abs() < 1e-12);
}

// ---- binned hazard ----

#[test]
fn binned_hazard_recovers_constant_rate_for_exponential() {
    // For an exponential with rate r, the binned hazard should be ≈ r in every bin
    // that has appreciable person-time (the discovery of "flat ⇒ exponential").
    let rate = 1.0 / 100.0;
    let data = failure_gen::generate(
        HazardForm::Exponential { rate },
        50_000,
        300.0,
        1.0,
        10.0,
        11,
    );
    let bh = binned_hazard(&data, 6);
    // Check the first few bins (the ones with most person-time) are near `rate`.
    for &h in &bh.hazard[0..3] {
        assert!(
            (h - rate).abs() < 0.4 * rate,
            "binned hazard {h} should be near exponential rate {rate}"
        );
    }
}

// ---- form classification (the discovery) ----

#[test]
fn classify_distinguishes_exponential_from_bathtub_and_volume() {
    // The estimator is BLIND to the form — only the dataset goes in. It must
    // recover the DISTINCT category for each. This is the anti-oracle PASS: it
    // distinguishes, it does not confirm one hardwired answer.
    let exp = failure_gen::generate(
        HazardForm::Exponential { rate: 1.0 / 400.0 },
        8000,
        2000.0,
        1.0,
        100.0,
        1,
    );
    let bath = failure_gen::generate(
        HazardForm::Bathtub {
            early_k: 0.5,
            early_lambda: 300.0,
            wearout_onset: 1200.0,
            wearout_rate: 1.0 / 200.0,
        },
        8000,
        2000.0,
        1.0,
        100.0,
        2,
    );
    let vol = failure_gen::generate(
        HazardForm::VolumeDependent {
            base_rate: 1.0 / 1500.0,
            v_ref: 10.0,
            exponent: 2.0,
        },
        8000,
        2000.0,
        1.0,
        100.0,
        3,
    );

    assert_eq!(
        classify_form(&exp, 2.5, 2.0),
        RecoveredForm::Exponential,
        "memoryless data must classify as exponential"
    );
    assert_eq!(
        classify_form(&bath, 2.5, 2.0),
        RecoveredForm::Bathtub,
        "infant-mortality+wear-out data must classify as bathtub"
    );
    assert_eq!(
        classify_form(&vol, 2.5, 2.0),
        RecoveredForm::VolumeDependent,
        "volume-coupled data must classify as volume-dependent"
    );
}

#[test]
fn classify_pure_ifr_wearout_is_not_bathtub() {
    // The SIM-12 WARN fix: a PURE wear-out IFR (monotone-rising hazard, Weibull
    // k≥1.5, NO infant-mortality) must NOT classify as bathtub. Its hazard MINIMUM
    // is at the START (no interior trough), so even though its late peak towers over
    // the global min, the interior-trough requirement rejects it. Semantically this
    // is the seniority-KILLING case (formula_phase §3) — the opposite of the k<1
    // infant-mortality bathtub — so calling it bathtub would be wrong.
    for k in [1.5_f64, 2.0, 3.0] {
        let ifr = failure_gen::generate(
            HazardForm::Weibull { k, lambda: 800.0 },
            8000,
            2000.0,
            1.0,
            100.0,
            (k * 100.0) as u64 + 1,
        );
        let s = shape_summary(&ifr, 12);
        assert!(
            !s.trough_interior,
            "monotone-rising IFR (k={k}) must trough at the START, not interior \
             (early_peak={}, trough={}, late_peak={})",
            s.early_peak, s.trough_hazard, s.late_peak
        );
        assert_ne!(
            classify_form(&ifr, 2.5, 2.0),
            RecoveredForm::Bathtub,
            "pure-IFR wear-out (k={k}) must not classify as bathtub"
        );
    }
}

#[test]
fn classify_pure_dfr_is_not_bathtub() {
    // A pure DFR (monotone-FALLING hazard, Weibull k<1, no wear-out rise) troughs at
    // the END — no late segment above an interior trough — so it is not a bathtub
    // either (it is the infant-mortality LEFT edge only, recovered as the
    // conservative default, not a full U).
    let dfr = failure_gen::generate(
        HazardForm::Weibull {
            k: 0.5,
            lambda: 400.0,
        },
        8000,
        2000.0,
        1.0,
        100.0,
        99,
    );
    assert_ne!(
        classify_form(&dfr, 2.5, 2.0),
        RecoveredForm::Bathtub,
        "pure-DFR (k<1, no wear-out) must not classify as bathtub"
    );
}

#[test]
fn classify_is_not_a_fixed_answer() {
    // Sanity that the classifier's output actually DEPENDS on the data (not a
    // constant) — the litmus against a form-oracle. The three datasets above give
    // three different answers, so the classifier is data-driven, not hardwired.
    let exp = failure_gen::generate(
        HazardForm::Exponential { rate: 1.0 / 400.0 },
        6000,
        2000.0,
        1.0,
        100.0,
        4,
    );
    let vol = failure_gen::generate(
        HazardForm::VolumeDependent {
            base_rate: 1.0 / 1500.0,
            v_ref: 10.0,
            exponent: 2.0,
        },
        6000,
        2000.0,
        1.0,
        100.0,
        5,
    );
    assert_ne!(
        classify_form(&exp, 2.5, 2.0),
        classify_form(&vol, 2.5, 2.0),
        "classifier output must vary with the data (not a hardwired form)"
    );
}

// ---- overall hazard ----

#[test]
fn overall_hazard_is_deaths_over_person_time() {
    let mut data = FailureDataset::new();
    // 2 deaths, person-time = 10+20+30 = 60 → hazard = 2/60.
    data.push(FailureObs {
        time: 10.0,
        censored: false,
        volume: 1.0,
    });
    data.push(FailureObs {
        time: 20.0,
        censored: false,
        volume: 1.0,
    });
    data.push(FailureObs {
        time: 30.0,
        censored: true,
        volume: 1.0,
    });
    assert!((overall_hazard(&data) - 2.0 / 60.0).abs() < 1e-12);
}
