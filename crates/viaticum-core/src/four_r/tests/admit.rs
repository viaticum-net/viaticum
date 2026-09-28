// K-3..K-11 (В-0b): `admit_offer` — the kernel transcription of the sim's accept/preemption
// gate, with the daemon's deviations (see the function's doc).

use super::*;

const LAMBDA: f64 = 1.0 / 60.0;

fn params(v_free: f64, c_recip: f64) -> AdmitParams {
    AdmitParams {
        hyst: Hysteresis {
            s_hard: 0.05,
            s_target: 0.15,
            s_soft: 0.20,
        },
        cap: RetentionCap { v_free, c_recip },
        theta_p: 0.2,
        v_min: 0.002,
        lambda: LAMBDA,
    }
}

fn newcomer(kappa: f64) -> AdmitOfferer {
    AdmitOfferer {
        index: None,
        kappa,
        v_parked: 0.0,
    }
}

/// W (κ 0, two symbols) and P (κ 0.5, one symbol).
fn w_and_p() -> (Vec<OwnerEvictionView>, Vec<f64>) {
    (
        vec![
            owner_view_vols(0.0, 0.0, 0.0, &[(0, 0.5, 0.01), (1, 0.1, 0.01)]),
            owner_view_vols(0.0, 0.0, 0.0, &[(2, 0.3, 0.01)]),
        ],
        vec![0.0, 0.5],
    )
}

/// K-3: above s_soft with room and not latched → Free; latched or without room → not Free.
#[test]
fn admit_offer_accepts_freely_above_s_soft_with_room() {
    let (owners, kappa) = w_and_p();
    let p = params(0.0, 3.0);
    let free = EvictPhase::default();
    let latched = EvictPhase { evicting: true };
    let d = admit_offer(&owners, &kappa, &newcomer(0.0), 0.005, 0.5, 0.1, free, &p);
    assert_eq!(d, AdmitDecision::Free);
    let d = admit_offer(
        &owners,
        &kappa,
        &newcomer(0.0),
        0.005,
        0.5,
        0.1,
        latched,
        &p,
    );
    assert_ne!(d, AdmitDecision::Free);
    let d = admit_offer(&owners, &kappa, &newcomer(0.0), 0.005, 0.5, 0.001, free, &p);
    assert_ne!(d, AdmitDecision::Free);
    // Exactly at s_soft is not above it.
    let d = admit_offer(&owners, &kappa, &newcomer(0.0), 0.005, 0.20, 0.1, free, &p);
    assert_ne!(d, AdmitDecision::Free);
}

/// K-4: contended — a serving newcomer displaces the LEAST reciprocal other owner, lowest ι.
#[test]
fn admit_offer_preempts_the_least_reciprocal_other_owner() {
    let (owners, kappa) = w_and_p();
    let d = admit_offer(
        &owners,
        &kappa,
        &newcomer(1.0),
        0.005,
        0.1,
        0.01,
        EvictPhase::default(),
        &params(0.0, 3.0),
    );
    assert_eq!(
        d,
        AdmitDecision::Preempt {
            victim_owner: 0,
            victim_symbols: vec![1],
        }
    );
}

/// K-5: a zero-service offerer never clears the margin (cap off, so the guard lets it reach
/// the margin); a margin of 0 would admit κ_victim + margin/2 (the mutation this pins).
#[test]
fn a_zero_service_offerer_never_clears_the_margin() {
    let owners = vec![owner_view_vols(0.0, 0.0, 0.0, &[(0, 0.1, 0.01)])];
    let p = params(0.0, 0.0); // cap disabled
    let v = 0.005;
    let margin = preemption_margin(p.theta_p, v, p.v_min, p.lambda);
    assert!(margin > 0.0);
    let run = |k_new: f64, k_victim: f64| {
        admit_offer(
            &owners,
            &[k_victim],
            &newcomer(k_new),
            v,
            0.1,
            0.01,
            EvictPhase::default(),
            &p,
        )
    };
    assert_eq!(run(0.0, 0.0), AdmitDecision::Reject(AdmitReject::Margin));
    assert_eq!(
        run(0.1 + margin / 2.0, 0.1),
        AdmitDecision::Reject(AdmitReject::Margin)
    );
    assert!(matches!(
        run(0.1 + 2.0 * margin, 0.1),
        AdmitDecision::Preempt { .. }
    ));
}

/// K-5b (B-1): with V_free = 0 a zero-service offerer that already parks data here is stopped
/// by the accept-guard, before the margin.
#[test]
fn with_v_free_zero_a_zero_service_offerer_with_parked_data_is_refused_by_the_guard() {
    let (mut owners, mut kappa) = w_and_p();
    owners.push(owner_view_vols(0.0, 0.0, 0.0, &[(9, 0.5, 0.02)]));
    kappa.push(0.0);
    let offerer = AdmitOfferer {
        index: Some(2),
        kappa: 0.0,
        v_parked: 0.02,
    };
    let d = admit_offer(
        &owners,
        &kappa,
        &offerer,
        0.005,
        0.1,
        0.01,
        EvictPhase::default(),
        &params(0.0, 3.0),
    );
    assert_eq!(d, AdmitDecision::Reject(AdmitReject::Guard));
}

/// K-6: margin = θ_p · max(V_offer, V_min) / λ.
#[test]
fn the_margin_is_theta_times_the_steady_capital_of_max_offer_vmin() {
    assert!((preemption_margin(0.2, 0.5, 1.0, LAMBDA) - 12.0).abs() < 1e-12);
    assert!((preemption_margin(0.2, 3.0, 1.0, LAMBDA) - 36.0).abs() < 1e-12);
    assert!((preemption_margin(0.2, 0.0001, 0.002, LAMBDA) - 0.024).abs() < 1e-12);
    assert_eq!(preemption_margin(0.2, 3.0, 1.0, 0.0), 0.0);
}

/// K-7 (З-2): the offerer is never its own victim.
#[test]
fn the_offerer_is_never_its_own_victim() {
    let owners = vec![owner_view_vols(0.0, 0.0, 0.0, &[(0, 0.1, 0.05)])];
    let me = AdmitOfferer {
        index: Some(0),
        kappa: 5.0,
        v_parked: 0.05,
    };
    let d = admit_offer(
        &owners,
        &[5.0],
        &me,
        0.005,
        0.1,
        0.01,
        EvictPhase::default(),
        &params(0.0, 0.0),
    );
    assert_eq!(d, AdmitDecision::Reject(AdmitReject::NoVictim));
    // With another owner, the lowest-κ OTHER owner is the victim even though the offerer
    // has the lower κ.
    let (mut owners, mut kappa) = w_and_p();
    owners.push(owner_view_vols(0.0, 0.0, 0.0, &[(7, 0.1, 0.05)]));
    kappa.push(0.0);
    kappa[0] = 0.3; // W now more reciprocal than… the offerer at index 2 (κ 0) is excluded
    let me = AdmitOfferer {
        index: Some(2),
        kappa: 10.0,
        v_parked: 0.05,
    };
    let d = admit_offer(
        &owners,
        &kappa,
        &me,
        0.005,
        0.1,
        0.01,
        EvictPhase::default(),
        &params(0.0, 0.0),
    );
    assert!(
        matches!(
            d,
            AdmitDecision::Preempt {
                victim_owner: 0,
                ..
            }
        ),
        "{d:?}"
    );
}

/// K-8: the accept-guard refuses an offer the offerer's own V_ret cannot hold; a disabled cap
/// never guards.
#[test]
fn the_accept_guard_rejects_an_offer_the_offerer_vret_cannot_hold() {
    let (owners, kappa) = w_and_p();
    let offerer = AdmitOfferer {
        index: None,
        kappa: 1.0, // V_ret = 1/3 gb at c_recip 3
        v_parked: 0.3,
    };
    let run = |p: &AdmitParams, v: f64| {
        admit_offer(
            &owners,
            &kappa,
            &offerer,
            v,
            0.1,
            0.5,
            EvictPhase::default(),
            p,
        )
    };
    assert_eq!(
        run(&params(0.0, 3.0), 0.1),
        AdmitDecision::Reject(AdmitReject::Guard)
    );
    assert_ne!(
        run(&params(0.0, 3.0), 0.02),
        AdmitDecision::Reject(AdmitReject::Guard)
    );
    assert_ne!(
        run(&params(0.0, 0.0), 0.1),
        AdmitDecision::Reject(AdmitReject::Guard)
    );
    // V_free lifts the tariff.
    assert_ne!(
        run(&params(0.2, 3.0), 0.1),
        AdmitDecision::Reject(AdmitReject::Guard)
    );
}

/// K-9 (З-3): the victim's symbols accumulate lowest-ι first until they cover the offer; a
/// victim smaller than the offer is refused.
#[test]
fn victim_symbols_accumulate_lowest_iota_until_the_offer_volume() {
    let owners = vec![owner_view_vols(
        0.0,
        0.0,
        0.0,
        &[(0, 3.0, 0.01), (1, 1.0, 0.01), (2, 2.0, 0.01)],
    )];
    let run = |v: f64| {
        admit_offer(
            &owners,
            &[0.0],
            &newcomer(1.0),
            v,
            0.1,
            1.0,
            EvictPhase::default(),
            &params(0.0, 0.0),
        )
    };
    assert_eq!(
        run(0.015),
        AdmitDecision::Preempt {
            victim_owner: 0,
            victim_symbols: vec![1, 2],
        }
    );
    assert_eq!(
        run(0.05),
        AdmitDecision::Reject(AdmitReject::VictimTooSmall)
    );
}

/// K-10 (Р-15): the victim leaves through its window — without room NOW, no preemption.
#[test]
fn preemption_waits_for_physical_room() {
    let (owners, kappa) = w_and_p();
    let d = admit_offer(
        &owners,
        &kappa,
        &newcomer(1.0),
        0.005,
        0.01,
        0.004,
        EvictPhase { evicting: true },
        &params(0.0, 3.0),
    );
    assert_eq!(d, AdmitDecision::Reject(AdmitReject::NoRoomNow));
}

/// K-11: a negative, NaN or infinite θ_p disables preemption (the free path still works).
#[test]
fn a_negative_or_nan_theta_disables_preemption() {
    let (owners, kappa) = w_and_p();
    for theta in [-1.0, f64::NAN, f64::INFINITY] {
        let p = AdmitParams {
            theta_p: theta,
            ..params(0.0, 3.0)
        };
        let contended = admit_offer(
            &owners,
            &kappa,
            &newcomer(9.0),
            0.005,
            0.1,
            0.01,
            EvictPhase::default(),
            &p,
        );
        assert_eq!(
            contended,
            AdmitDecision::Reject(AdmitReject::PreemptDisabled),
            "θ = {theta}"
        );
        let abundant = admit_offer(
            &owners,
            &kappa,
            &newcomer(9.0),
            0.005,
            0.9,
            0.5,
            EvictPhase::default(),
            &p,
        );
        assert_eq!(abundant, AdmitDecision::Free, "θ = {theta}");
    }
}
