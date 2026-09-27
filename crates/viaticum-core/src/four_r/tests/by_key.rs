// K-0..K-2 (В-0a): `eviction_order` → `owner_order_by_key` / `eviction_order_by_key`.
//
// K-0 pins the FULL decisions of `eviction_order` on six fixtures. The expected values were
// captured from the code BEFORE the key refactor (N-1: without a pre-refactor golden, K-1 —
// "the wrapper equals the by-key function" — would compare the new code with itself).

use super::*;

/// One K-0 fixture: the full input of one `eviction_order` call.
struct K0Fixture {
    name: &'static str,
    owners: Vec<OwnerEvictionView>,
    phi: f64,
    prev: EvictPhase,
    cap: RetentionCap,
}

/// Non-trivial depth params (the depth floor moves κ): κ = g + 5·min(D/100, 1).
fn k0_depth() -> DepthParams {
    DepthParams {
        w_d: 0.5,
        d_ref: 100.0,
        g_star: 10.0,
    }
}

fn k0_band() -> Hysteresis {
    Hysteresis {
        s_hard: 0.1,
        s_target: 0.2,
        s_soft: 0.3,
    }
}

/// The six fixtures of K-0: abundance, latch (deadband hold), cap active, cap disabled,
/// κ ties, empty view.
fn k0_fixtures() -> Vec<K0Fixture> {
    let capped_owners = || {
        vec![
            // κ = 2 + 5·0.5 = 4.5; V_ret = 0.5 + 0.45 = 0.95; parked 1.2.
            owner_view_vols(
                2.0,
                50.0,
                1.0,
                &[(0, 3.0, 0.4), (1, 1.0, 0.3), (2, 2.0, 0.5)],
            ),
            // κ = 0; V_ret = 0.5; parked 0.7; ι tie on ids 10/11.
            owner_view_vols(
                0.0,
                0.0,
                0.0,
                &[(10, 1.0, 0.2), (11, 1.0, 0.2), (12, 5.0, 0.3)],
            ),
            // κ = 10 + 5 = 15; V_ret = 2.0; parked 0.6 (no trim).
            owner_view_vols(10.0, 200.0, 4.0, &[(20, 1.0, 0.3), (21, 2.0, 0.3)]),
            // κ = 0.5; V_ret = 0.55; parked 1.0.
            owner_view_vols(0.5, 0.0, 3.0, &[(30, 0.5, 1.0)]),
        ]
    };
    vec![
        K0Fixture {
            name: "abundance",
            owners: capped_owners(),
            phi: 0.9,
            prev: EvictPhase::default(),
            cap: RetentionCap {
                v_free: 0.5,
                c_recip: 10.0,
            },
        },
        K0Fixture {
            name: "latch_hold_in_deadband",
            owners: vec![
                owner_view_vols(1.0, 20.0, 0.0, &[(0, 2.0, 1.0), (1, 1.0, 1.0)]),
                owner_view_vols(0.0, 100.0, 0.0, &[(5, 1.0, 1.0)]),
                owner_view_vols(3.0, 0.0, 0.0, &[(9, 0.1, 1.0)]),
            ],
            phi: 0.15,
            prev: EvictPhase { evicting: true },
            cap: RetentionCap::disabled(),
        },
        K0Fixture {
            name: "cap_active",
            owners: capped_owners(),
            phi: 0.0,
            prev: EvictPhase::default(),
            cap: RetentionCap {
                v_free: 0.5,
                c_recip: 10.0,
            },
        },
        K0Fixture {
            name: "cap_disabled",
            owners: capped_owners(),
            phi: 0.0,
            prev: EvictPhase::default(),
            cap: RetentionCap::disabled(),
        },
        K0Fixture {
            name: "kappa_ties",
            owners: vec![
                owner_view_vols(1.0, 0.0, 2.0, &[(0, 1.0, 0.5), (1, 2.0, 0.5)]),
                owner_view_vols(1.0, 0.0, 1.0, &[(2, 1.0, 0.5)]),
                owner_view_vols(1.0, 0.0, 1.0, &[(3, 1.0, 0.5), (4, 1.0, 0.5)]),
                owner_view_vols(0.5, 10.0, 1.0, &[(5, 3.0, 0.9), (6, 1.0, 0.9)]),
            ],
            phi: 0.05,
            prev: EvictPhase::default(),
            cap: RetentionCap {
                v_free: 1.0,
                c_recip: 5.0,
            },
        },
        K0Fixture {
            name: "empty_view",
            owners: vec![],
            phi: 0.0,
            prev: EvictPhase::default(),
            cap: RetentionCap {
                v_free: 0.5,
                c_recip: 10.0,
            },
        },
    ]
}

fn slots(s: &[SymbolSlot]) -> Vec<(usize, usize)> {
    s.iter().map(|x| (x.owner_idx, x.symbol_idx)).collect()
}

/// Golden decisions, captured from `eviction_order` BEFORE the key refactor (N-1):
/// `(name, cap_drops, drop_order, accept_ok, evicting)` as `(owner_idx, symbol_idx)` slots.
#[allow(clippy::type_complexity)]
fn k0_golden() -> Vec<(
    &'static str,
    Vec<(usize, usize)>,
    Vec<(usize, usize)>,
    bool,
    bool,
)> {
    vec![
        ("abundance", vec![], vec![], true, false),
        (
            "latch_hold_in_deadband",
            vec![],
            vec![(0, 1), (0, 0), (2, 0), (1, 0)],
            false,
            true,
        ),
        (
            "cap_active",
            vec![(1, 0), (3, 0), (0, 1)],
            vec![(1, 1), (1, 2), (0, 2), (0, 0), (2, 0), (2, 1)],
            false,
            true,
        ),
        (
            "cap_disabled",
            vec![],
            vec![
                (1, 0),
                (1, 1),
                (1, 2),
                (3, 0),
                (0, 1),
                (0, 2),
                (0, 0),
                (2, 0),
                (2, 1),
            ],
            false,
            true,
        ),
        (
            "kappa_ties",
            vec![(3, 1)],
            vec![(1, 0), (2, 0), (2, 1), (3, 0), (0, 0), (0, 1)],
            false,
            true,
        ),
        ("empty_view", vec![], vec![], false, true),
    ]
}

/// K-0: the refactored `eviction_order` still returns the decisions frozen before the refactor.
#[test]
fn eviction_order_matches_decisions_frozen_before_the_key_refactor() {
    let golden = k0_golden();
    let fixtures = k0_fixtures();
    assert_eq!(golden.len(), fixtures.len());
    for (f, (name, cap, drop, accept_ok, evicting)) in fixtures.iter().zip(golden) {
        assert_eq!(f.name, name);
        let d = eviction_order(&f.owners, f.phi, k0_band(), f.prev, &k0_depth(), &f.cap);
        assert_eq!(slots(&d.cap_drops), cap, "{name}: cap_drops");
        assert_eq!(slots(&d.drop_order), drop, "{name}: drop_order");
        assert_eq!(d.accept_ok, accept_ok, "{name}: accept_ok");
        assert_eq!(d.phase.evicting, evicting, "{name}: phase");
    }
}

/// K-1: `eviction_order` = `eviction_order_by_key` with κ from `kappa_key` (the wrapper adds
/// nothing and drops nothing).
#[test]
fn eviction_order_equals_eviction_order_by_key_with_kernel_kappa() {
    for f in k0_fixtures() {
        let kappa: Vec<f64> = f
            .owners
            .iter()
            .map(|v| kappa_key(v.obs.g_holder_from_owner, v.depth, &k0_depth()))
            .collect();
        let a = eviction_order(&f.owners, f.phi, k0_band(), f.prev, &k0_depth(), &f.cap);
        let b = eviction_order_by_key(&f.owners, &kappa, f.phi, k0_band(), f.prev, &f.cap);
        assert_eq!(a, b, "{}", f.name);
    }
}

/// K-1b (`4r-i66`): `eviction_order_by_key` is exactly `relay_latch` then
/// `eviction_order_in_phase`; given a phase, `eviction_order_in_phase` keeps it whatever φ says
/// (the holder bridge freezes the latch on an invalid tick through it).
#[test]
fn eviction_order_in_phase_keeps_the_given_phase_and_by_key_is_latch_then_order() {
    for f in k0_fixtures() {
        let kappa: Vec<f64> = f
            .owners
            .iter()
            .map(|v| kappa_key(v.obs.g_holder_from_owner, v.depth, &k0_depth()))
            .collect();
        let latched = relay_latch(f.phi, k0_band(), f.prev);
        assert_eq!(
            eviction_order_by_key(&f.owners, &kappa, f.phi, k0_band(), f.prev, &f.cap),
            eviction_order_in_phase(&f.owners, &kappa, f.phi, k0_band(), latched, &f.cap),
            "{}",
            f.name
        );
        for evicting in [false, true] {
            let d = eviction_order_in_phase(
                &f.owners,
                &kappa,
                f.phi,
                k0_band(),
                EvictPhase { evicting },
                &f.cap,
            );
            assert_eq!(d.phase.evicting, evicting, "{}", f.name);
            if !evicting {
                assert!(d.cap_drops.is_empty() && d.drop_order.is_empty());
            } else {
                assert!(!d.accept_ok, "{}: never accept while evicting", f.name);
            }
        }
    }
    // The latch rule itself: ON below s_hard, OFF at s_target, hold in the deadband and on NaN.
    let on = EvictPhase { evicting: true };
    let off = EvictPhase { evicting: false };
    assert_eq!(relay_latch(0.05, k0_band(), off), on);
    assert_eq!(relay_latch(0.2, k0_band(), on), off);
    assert_eq!(relay_latch(0.15, k0_band(), on), on);
    assert_eq!(relay_latch(0.15, k0_band(), off), off);
    assert_eq!(relay_latch(f64::NAN, k0_band(), on), on);
}

/// K-2: the inter-owner order is ascending κ, then ascending `observed_tau`, then input order.
#[test]
fn owner_order_by_key_breaks_ties_by_observed_tau_then_input_order() {
    let owners = vec![
        owner_view_vols(0.0, 0.0, 5.0, &[(0, 1.0, 1.0)]), // κ 2, τ 5
        owner_view_vols(0.0, 0.0, 1.0, &[(1, 1.0, 1.0)]), // κ 2, τ 1
        owner_view_vols(0.0, 0.0, 1.0, &[(2, 1.0, 1.0)]), // κ 2, τ 1 (input after #1)
        owner_view_vols(0.0, 0.0, 9.0, &[(3, 1.0, 1.0)]), // κ 0.5, τ 9
        owner_view_vols(0.0, 0.0, 0.0, &[]),              // κ 3, no symbols
    ];
    // κ supplied from outside: the by-key order must NOT read obs.g_holder_from_owner.
    let kappa = [2.0, 2.0, 2.0, 0.5, 3.0];
    assert_eq!(owner_order_by_key(&owners, &kappa), vec![3, 1, 2, 0, 4]);
    // The same views with a different κ vector reorder — the key really is the argument.
    let kappa2 = [0.0, 1.0, 1.0, 5.0, 3.0];
    assert_eq!(owner_order_by_key(&owners, &kappa2), vec![0, 1, 2, 4, 3]);
}

/// A κ vector of the wrong length is a caller bug, not data: the by-key functions panic.
#[test]
#[should_panic(expected = "kappa")]
fn owner_order_by_key_panics_when_kappa_length_differs() {
    let owners = vec![owner_view_vols(0.0, 0.0, 0.0, &[(0, 1.0, 1.0)])];
    let _ = owner_order_by_key(&owners, &[]);
}
