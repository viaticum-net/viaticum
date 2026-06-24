use super::*;

#[test]
fn generate_is_deterministic_for_a_seed() {
    let form = HazardForm::Exponential { rate: 1.0 / 100.0 };
    let a = generate(form, 1000, 500.0, 1.0, 10.0, 42);
    let b = generate(form, 1000, 500.0, 1.0, 10.0, 42);
    assert_eq!(a.len(), b.len());
    for (x, y) in a.obs.iter().zip(b.obs.iter()) {
        assert_eq!(x.time, y.time);
        assert_eq!(x.censored, y.censored);
        assert_eq!(x.volume, y.volume);
    }
}

#[test]
fn generate_censors_survivors_at_horizon() {
    // With a tiny rate and short horizon, most holders survive ⇒ are censored at
    // exactly the horizon. No failure time may exceed the horizon.
    let form = HazardForm::Exponential {
        rate: 1.0 / 100000.0,
    };
    let horizon = 100.0;
    let data = generate(form, 2000, horizon, 1.0, 10.0, 7);
    let censored = data.obs.iter().filter(|o| o.censored).count();
    assert!(censored > 1500, "most low-rate holders should be censored");
    for o in &data.obs {
        assert!(
            o.time <= horizon + 1e-9,
            "no observed time beyond the horizon"
        );
        if o.censored {
            assert!((o.time - horizon).abs() < 1e-9, "censored at horizon");
        }
    }
}

#[test]
fn volume_dependent_form_kills_high_volume_holders_faster() {
    // The hidden volume-dependent hazard must make high-volume holders fail sooner
    // on average — the structure the estimator later recovers. (God-view check.)
    let form = HazardForm::VolumeDependent {
        base_rate: 1.0 / 1000.0,
        v_ref: 10.0,
        exponent: 2.0,
    };
    let data = generate(form, 20000, 5000.0, 1.0, 100.0, 9);
    let med_v = {
        let mut v: Vec<f64> = data.obs.iter().map(|o| o.volume).collect();
        v.sort_by(|a, b| a.total_cmp(b));
        v[v.len() / 2]
    };
    let mean_time = |hi: bool| -> f64 {
        let xs: Vec<f64> = data
            .obs
            .iter()
            .filter(|o| (o.volume > med_v) == hi && !o.censored)
            .map(|o| o.time)
            .collect();
        xs.iter().sum::<f64>() / xs.len().max(1) as f64
    };
    assert!(
        mean_time(true) < mean_time(false),
        "high-volume holders must fail sooner under the volume-dependent form"
    );
}

#[test]
fn out_of_family_multimodal_has_two_failure_clusters() {
    // A bimodal failure-time distribution: failures cluster near both centres,
    // with a quiet gap between — what a unimodal Weibull cannot represent.
    let form = OutOfFamily::Multimodal {
        early_frac: 0.4,
        early_center: 200.0,
        early_spread: 50.0,
        late_center: 1600.0,
        late_spread: 120.0,
    };
    let data = generate_oof(form, 20000, 5000.0, 1.0, 10.0, 3);
    let near = |c: f64, w: f64| -> usize {
        data.obs
            .iter()
            .filter(|o| !o.censored && (o.time - c).abs() < w)
            .count()
    };
    let gap = data
        .obs
        .iter()
        .filter(|o| !o.censored && o.time > 600.0 && o.time < 1200.0)
        .count();
    assert!(near(200.0, 150.0) > 1000, "early failure cluster present");
    assert!(near(1600.0, 360.0) > 1000, "late failure cluster present");
    assert!(
        gap * 3 < near(200.0, 150.0),
        "a quiet gap separates the two clusters (multimodal, not Weibull)"
    );
}

#[test]
fn true_survival_weibull_matches_closed_form_and_is_monotone() {
    // S(τ) = exp(−(τ/λ)^k): 1 at τ=0, λ·(ln2)^{1/k} is the median (S = 0.5), and it
    // is strictly decreasing. The analytic in-family truth for the counter-check.
    let (k, lambda) = (0.8, 365.0);
    assert!((true_survival_weibull(k, lambda, 0.0) - 1.0).abs() < 1e-12);
    let median = lambda * (std::f64::consts::LN_2).powf(1.0 / k);
    assert!(
        (true_survival_weibull(k, lambda, median) - 0.5).abs() < 1e-9,
        "survival at the Weibull median must be 0.5"
    );
    let mut prev = 1.01;
    for &t in &[0.0, 100.0, 365.0, 730.0, 1825.0] {
        let s = true_survival_weibull(k, lambda, t);
        assert!(s <= prev + 1e-12, "Weibull survival must be non-increasing");
        prev = s;
    }
}

#[test]
fn true_survival_oof_is_monotone_non_increasing() {
    let form = OutOfFamily::PlateauCliff {
        plateau: 1000.0,
        cliff_width: 200.0,
        plateau_rate: 1.0 / 20000.0,
    };
    let mut prev = 1.01;
    for &t in &[0.0, 500.0, 999.0, 1100.0, 1300.0, 3000.0] {
        let s = true_survival_oof(form, t, 50000, 1);
        assert!(s <= prev + 1e-3, "survival must be non-increasing in t");
        prev = s;
    }
    // The plateau really is a plateau: survival barely drops before the cliff.
    let before = true_survival_oof(form, 900.0, 50000, 1);
    let after = true_survival_oof(form, 1300.0, 50000, 1);
    assert!(before > 0.9, "plateau keeps most holders alive: {before}");
    assert!(after < 0.2, "the cliff kills most holders: {after}");
}
