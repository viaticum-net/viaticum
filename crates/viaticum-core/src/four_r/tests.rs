use super::*;
use crate::types::{DeviceId, IdentityPub};

/// Build a minimal FirstHandObs with a given `g_holder_from_owner` and `tau`.
/// All other fields are first-hand defaults (zeros / reachable). This helper
/// only sets the fields the eviction kernel reads — it cannot set any
/// ground-truth field because none exists on the struct.
fn obs_with(g_holder_from_owner: f64, tau: f64) -> FirstHandObs {
    FirstHandObs {
        g_owner_from_holder: 0.0,
        g_holder_from_owner,
        v_dem: 0.0,
        recent_rate_p: 0.0,
        trend_d: 0.0,
        pos_pass: 0,
        pos_fail: 0,
        pos_timeout: 0,
        observed_volume: 0.0,
        observed_tau: tau,
        addr_subnet: 0,
        addr_geo: 0,
        latency_ms: 0.0,
        reachable: true,
        scrutiny: 0.0,
        master_id: IdentityPub([0u8; 32]),
        device_id: DeviceId([0u8; 32]),
    }
}

/// Build an [`OwnerEvictionView`] for one owner with pairwise capital
/// `g_holder_from_owner` and `tau`, holding a SINGLE symbol of the given
/// importance (id derived from a counter the caller supplies for determinism).
/// This is the common one-symbol-per-owner case the inter-owner level exercises.
fn owner_view(
    g_holder_from_owner: f64,
    tau: f64,
    importance: f64,
    sym_id: u64,
) -> OwnerEvictionView {
    OwnerEvictionView {
        obs: obs_with(g_holder_from_owner, tau),
        depth: 0.0,
        symbols: vec![SymbolDecl {
            id: SymbolId(sym_id),
            importance,
            // Unit volume: the legacy eviction tests pass RetentionCap::disabled(), so
            // the Р-7 cap never reads `volume` (it is inert here).
            volume: 1.0,
        }],
    }
}

/// Like [`owner_view`] but with an explicit loyalty depth `D` (A.4). Used by the
/// κ_O eviction tests where the W10 floor must move an owner up the drop order.
fn owner_view_depth(
    g_holder_from_owner: f64,
    depth: f64,
    tau: f64,
    importance: f64,
    sym_id: u64,
) -> OwnerEvictionView {
    OwnerEvictionView {
        obs: obs_with(g_holder_from_owner, tau),
        depth,
        symbols: vec![SymbolDecl {
            id: SymbolId(sym_id),
            importance,
            volume: 1.0, // inert under RetentionCap::disabled() (see owner_view).
        }],
    }
}

/// DepthParams for the legacy (pre-3a) eviction tests: every such view has `depth =
/// 0`, so κ_O collapses to bare `g_ho` and the ordering is exactly the pre-3a one.
/// These field values are inert whenever the view depths are 0.
fn dp_zero() -> DepthParams {
    DepthParams {
        w_d: 0.5,
        d_ref: 100.0,
        g_star: 10.0,
    }
}

/// Build an [`OwnerEvictionView`] for one owner holding MANY symbols, each with
/// its own importance. Symbol ids are assigned `base, base+1, …` in input order.
fn owner_view_multi(
    g_holder_from_owner: f64,
    tau: f64,
    importances: &[f64],
    base: u64,
) -> OwnerEvictionView {
    OwnerEvictionView {
        obs: obs_with(g_holder_from_owner, tau),
        depth: 0.0,
        symbols: importances
            .iter()
            .enumerate()
            .map(|(i, &importance)| SymbolDecl {
                id: SymbolId(base + i as u64),
                importance,
                volume: 1.0, // inert under RetentionCap::disabled() (see owner_view).
            })
            .collect(),
    }
}

// ============================================================
// update_capital — leaky integrator relaxes to V_conf/λ.
// ============================================================

#[test]
fn capital_relaxes_toward_steady_state_when_input_constant() {
    let v_conf = 2.0;
    let lambda = 0.5;
    let dt = 0.01; // λΔt = 0.005 ≪ 1 → stable, monotone relaxation.
    let target = capital_steady_state(v_conf, lambda); // = 4.0

    let mut g = 0.0;
    for _ in 0..5000 {
        g = update_capital(g, v_conf, lambda, dt);
    }
    assert!(
        (g - target).abs() < 1e-3,
        "capital should relax to V_conf/λ = {target}, got {g}"
    );
}

#[test]
fn capital_at_steady_state_does_not_move() {
    let v_conf = 3.0;
    let lambda = 0.75;
    let g_star = capital_steady_state(v_conf, lambda); // 4.0
    let next = update_capital(g_star, v_conf, lambda, 0.1);
    assert!(
        (next - g_star).abs() < 1e-12,
        "at steady state dG/dt = 0, expected {g_star}, got {next}"
    );
}

#[test]
fn capital_relaxation_is_monotone_when_lambda_dt_below_one() {
    // λΔt = 0.9 < 1 ⇒ multiplier (1−λΔt) = 0.1 > 0 ⇒ no oscillation, monotone
    // approach from below toward steady state.
    let v_conf = 1.0;
    let lambda = 0.9;
    let dt = 1.0;
    let target = capital_steady_state(v_conf, lambda);
    let mut g = 0.0;
    for _ in 0..200 {
        let next = update_capital(g, v_conf, lambda, dt);
        assert!(
            next >= g - 1e-12,
            "approach from below must be non-decreasing"
        );
        assert!(next <= target + 1e-9, "must not overshoot steady state");
        g = next;
    }
    assert!((g - target).abs() < 1e-3);
}

#[test]
fn capital_steady_state_is_zero_when_no_leak() {
    assert_eq!(capital_steady_state(5.0, 0.0), 0.0);
    assert_eq!(capital_steady_state(5.0, -1.0), 0.0);
}

#[test]
fn update_capital_clamps_negative_lambda_and_dt() {
    // Negative lambda/dt must not produce explosive/NaN behaviour.
    let g = update_capital(1.0, 2.0, -1.0, -1.0);
    assert_eq!(g, 1.0, "negative dt clamps to 0 → no change");
}

// ============================================================
// eviction_order — two-level: ascending G across owners, ascending ι within.
// ============================================================

/// Convenience: the owner index of each slot in drop order (for one-symbol-per-
/// owner tests where the owner order is what matters).
fn owner_seq(dec: &EvictionDecision) -> Vec<usize> {
    dec.drop_order.iter().map(|s| s.owner_idx).collect()
}

#[test]
fn eviction_orders_net_debtors_before_net_creditors() {
    // One symbol per owner: owner 0 a deep creditor, owner 2 a freeloader
    // (near-zero G), owner 1 in between. ι is identical so only G decides.
    let owners = vec![
        owner_view(10.0, 0.0, 1.0, 0), // creditor — evict LAST
        owner_view(3.0, 0.0, 1.0, 1),  // middle
        owner_view(0.1, 0.0, 1.0, 2),  // net-debtor / freeloader — evict FIRST
    ];
    // φ below s_hard ⇒ evicting.
    let hyst = Hysteresis {
        s_hard: 0.1,
        s_target: 0.2,
        s_soft: 0.3,
    };
    let dec = eviction_order(
        &owners,
        0.05,
        hyst,
        EvictPhase::default(),
        &dp_zero(),
        &RetentionCap::disabled(),
    );
    assert_eq!(
        owner_seq(&dec),
        vec![2, 1, 0],
        "drop order must be ascending g_holder_from_owner (debtors first)"
    );
    assert!(dec.phase.evicting);
    assert!(!dec.accept_ok, "cannot accept while evicting");
}

#[test]
fn eviction_returns_empty_drop_order_when_not_under_pressure() {
    let owners = vec![owner_view(1.0, 0.0, 1.0, 0), owner_view(2.0, 0.0, 1.0, 1)];
    let hyst = Hysteresis {
        s_hard: 0.1,
        s_target: 0.2,
        s_soft: 0.3,
    };
    // φ well above s_soft, not previously evicting ⇒ nothing dropped, accept ok.
    let dec = eviction_order(
        &owners,
        0.9,
        hyst,
        EvictPhase::default(),
        &dp_zero(),
        &RetentionCap::disabled(),
    );
    assert!(dec.drop_order.is_empty());
    assert!(!dec.phase.evicting);
    assert!(dec.accept_ok);
}

#[test]
fn eviction_retention_tiebreak_drops_shorter_held_first_among_equal_capital() {
    // Equal G ⇒ the longer-held owner-pair (larger tau) is dropped LAST.
    let owners = vec![
        owner_view(5.0, 100.0, 1.0, 0), // long-held → drop last among equals
        owner_view(5.0, 1.0, 1.0, 1),   // short-held → drop first among equals
    ];
    let hyst = Hysteresis {
        s_hard: 0.1,
        s_target: 0.2,
        s_soft: 0.3,
    };
    let dec = eviction_order(
        &owners,
        0.0,
        hyst,
        EvictPhase::default(),
        &dp_zero(),
        &RetentionCap::disabled(),
    );
    assert_eq!(
        owner_seq(&dec),
        vec![1, 0],
        "among equal G, ascending tau → shorter-held dropped first"
    );
}

#[test]
fn eviction_orders_symbols_within_an_owner_by_ascending_importance() {
    // INTRA-owner level: a single owner with three symbols of differing ι. The
    // lowest-ι symbol must drop first, highest-ι last — purely the owner's ladder.
    let owners = vec![owner_view_multi(5.0, 10.0, &[0.9, 0.1, 0.5], 100)];
    let hyst = Hysteresis {
        s_hard: 0.1,
        s_target: 0.2,
        s_soft: 0.3,
    };
    let dec = eviction_order(
        &owners,
        0.0,
        hyst,
        EvictPhase::default(),
        &dp_zero(),
        &RetentionCap::disabled(),
    );
    // symbol_idx order: index 1 (ι=0.1) first, index 2 (ι=0.5), index 0 (ι=0.9) last.
    let sym_seq: Vec<usize> = dec.drop_order.iter().map(|s| s.symbol_idx).collect();
    assert!(
        dec.drop_order.iter().all(|s| s.owner_idx == 0),
        "all slots belong to the single owner"
    );
    assert_eq!(
        sym_seq,
        vec![1, 2, 0],
        "within one owner, symbols drop ascending by ι (lowest-ι first)"
    );
}

#[test]
fn eviction_is_two_level_g_dominates_importance_across_owners() {
    // Owner A (LOW G) has a MAXIMALLY important symbol; owner B (HIGH G) has a
    // worthless symbol. The cross-owner ×ι ban means A's high-ι symbol STILL
    // drops before B's low-ι symbol — G sets the share, ι never jumps owners.
    let low_g_high_iota = owner_view(0.5, 10.0, 1_000.0, 0); // owner 0
    let high_g_low_iota = owner_view(50.0, 10.0, 0.001, 1); // owner 1
    let owners = vec![low_g_high_iota, high_g_low_iota];
    let hyst = Hysteresis {
        s_hard: 0.1,
        s_target: 0.2,
        s_soft: 0.3,
    };
    let dec = eviction_order(
        &owners,
        0.0,
        hyst,
        EvictPhase::default(),
        &dp_zero(),
        &RetentionCap::disabled(),
    );
    assert_eq!(
        owner_seq(&dec),
        vec![0, 1],
        "the low-G owner's symbol drops first even though its ι is far higher \
         (no cross-owner G×ι product)"
    );
}

#[test]
fn eviction_latch_holds_state_inside_the_deadband() {
    let owners = vec![owner_view(1.0, 0.0, 1.0, 0)];
    let hyst = Hysteresis {
        s_hard: 0.1,
        s_target: 0.2,
        s_soft: 0.3,
    };
    // Enter evicting below s_hard.
    let d1 = eviction_order(
        &owners,
        0.05,
        hyst,
        EvictPhase::default(),
        &dp_zero(),
        &RetentionCap::disabled(),
    );
    assert!(d1.phase.evicting);
    // φ rises into the deadband (s_hard ≤ φ < s_target): latch HOLDS → still evicting.
    let d2 = eviction_order(
        &owners,
        0.15,
        hyst,
        d1.phase,
        &dp_zero(),
        &RetentionCap::disabled(),
    );
    assert!(d2.phase.evicting, "deadband must hold the evicting latch");
    assert!(!d2.drop_order.is_empty());
    // φ reaches s_target: latch releases.
    let d3 = eviction_order(
        &owners,
        0.2,
        hyst,
        d2.phase,
        &dp_zero(),
        &RetentionCap::disabled(),
    );
    assert!(!d3.phase.evicting, "reaching s_target releases the latch");
}

// ============================================================
// eviction_order — incentive-compatibility of intra-owner ι (the safety property).
// ============================================================

#[test]
fn inflating_own_importance_does_not_steal_share_from_other_owner() {
    // Scenario: owner A (lower G) with symbols at mixed ι, owner B (higher G) with
    // its own symbols. A then LIES, inflating ALL its ι to the max. Prove:
    //   (1) A's disk SHARE is unchanged — the set of A's symbols evicted in the
    //       first `cap` drops (under any disk-pressure budget) is the SAME size,
    //       because the share is set by G(h←O), which the lie cannot touch;
    //   (2) A's lie NEVER evicts one of B's symbols earlier (B's slots keep their
    //       positions) — A can only REORDER its own symbols, not jump B's;
    //   (3) the only change is the internal permutation of A's own symbols.
    let hyst = Hysteresis {
        s_hard: 0.1,
        s_target: 0.2,
        s_soft: 0.3,
    };

    // Owner A: G = 2.0, three symbols ι = [0.2, 0.8, 0.5] (ids 10,11,12).
    // Owner B: G = 9.0 (higher creditor), two symbols ι = [0.3, 0.6] (ids 20,21).
    let a_honest = owner_view_multi(2.0, 10.0, &[0.2, 0.8, 0.5], 10);
    let b = owner_view_multi(9.0, 10.0, &[0.3, 0.6], 20);
    let honest = vec![a_honest, b.clone()];

    // A inflates every ι to the maximum (claims everything is precious).
    let a_liar = owner_view_multi(2.0, 10.0, &[1.0, 1.0, 1.0], 10);
    let lying = vec![a_liar, b];

    let dec_honest = eviction_order(
        &honest,
        0.0,
        hyst,
        EvictPhase::default(),
        &dp_zero(),
        &RetentionCap::disabled(),
    );
    let dec_lying = eviction_order(
        &lying,
        0.0,
        hyst,
        EvictPhase::default(),
        &dp_zero(),
        &RetentionCap::disabled(),
    );

    // Owner A is index 0 in both. Helper: which owner each drop slot belongs to.
    let owners_honest = owner_seq(&dec_honest);
    let owners_lying = owner_seq(&dec_lying);

    // (1) + (2): the OWNER sequence of the drop order is byte-identical. A's lie
    // does not move a single B-symbol earlier or later, and A keeps exactly the
    // same number of slots in every prefix → identical disk share at every
    // pressure budget. (A is the low-G owner, so all of A's 3 symbols come first,
    // then both of B's — and that does not change.)
    assert_eq!(
        owners_honest, owners_lying,
        "inflating ι must not change WHICH owner's symbols are dropped at any \
         position — share is set by G, not ι: honest={owners_honest:?} lying={owners_lying:?}"
    );
    assert_eq!(
        owners_honest,
        vec![0, 0, 0, 1, 1],
        "A (low G) loses all its share before any of B's symbols, regardless of ι"
    );

    // (3) The ONLY effect of the lie is a permutation of A's OWN symbol ids. Honest
    // A drops its symbols ascending by ι: id 10 (0.2), 12 (0.5), 11 (0.8). Lying A
    // (all ι equal) falls back to the id tie-breaker: 10, 11, 12.
    let a_ids = |dec: &EvictionDecision, src: &[OwnerEvictionView]| -> Vec<u64> {
        dec.drop_order
            .iter()
            .filter(|s| s.owner_idx == 0)
            .map(|s| src[0].symbols[s.symbol_idx].id.0)
            .collect()
    };
    assert_eq!(
        a_ids(&dec_honest, &honest),
        vec![10, 12, 11],
        "honest A drops its own symbols ascending by ι"
    );
    assert_eq!(
        a_ids(&dec_lying, &lying),
        vec![10, 11, 12],
        "lying A only permutes its OWN symbols (ι all equal → id order)"
    );

    // And B's internal symbol order is untouched by A's lie (ascending ι: 20,21).
    let b_ids = |dec: &EvictionDecision, src: &[OwnerEvictionView]| -> Vec<u64> {
        dec.drop_order
            .iter()
            .filter(|s| s.owner_idx == 1)
            .map(|s| src[1].symbols[s.symbol_idx].id.0)
            .collect()
    };
    assert_eq!(b_ids(&dec_honest, &honest), vec![20, 21]);
    assert_eq!(
        b_ids(&dec_lying, &lying),
        vec![20, 21],
        "A's lie cannot reorder B's symbols"
    );
}

// ============================================================
// update_depth — slow-leaky loyalty carrier D (A.4).
// ============================================================

#[test]
fn depth_grows_to_steady_state_and_fades_with_tau_slow() {
    // λ_slow = 1/180 ⇒ τ_slow = 180 days; V_conf = 2 gb ⇒ D* = V_conf·τ_slow = 360.
    let lambda_slow = 1.0 / 180.0;
    let v_conf = 2.0;
    let dt = 1.0; // λ_slow·dt ≈ 0.0056 < 1.
    let d_star = v_conf / lambda_slow; // 360

    // Grow from cold under constant confirmed service → relaxes to D*.
    let mut d = 0.0;
    for _ in 0..3600 {
        d = update_depth(d, v_conf, dt, lambda_slow);
    }
    let d_grown = d;
    assert!(
        (d_grown - d_star).abs() < 0.5,
        "depth should relax to D* = V_conf·τ_slow = {d_star}, got {d_grown}"
    );

    // Then 4·τ_slow of SILENCE (V_conf = 0) → an e-fold per τ_slow ⇒ ≈ e⁻⁴.
    for _ in 0..720 {
        d = update_depth(d, 0.0, dt, lambda_slow);
    }
    let ratio = d / d_grown;
    assert!(
        (ratio - (-4.0f64).exp()).abs() < 1e-3,
        "after 4·τ_slow of silence depth must fade to ≈ e⁻⁴ ({}), got ratio {ratio}",
        (-4.0f64).exp()
    );
}

#[test]
fn depth_is_not_erased_by_silence_within_months() {
    // The whole point of the SLOW time constant: a couple of months of silence must
    // NOT wipe the loyalty depth (that is the fast capital's job). Slow keeps > 70%
    // over 2 months where the fast capital (λ = 1/60) is already down to ~37%.
    let d0 = 100.0;
    let dt = 1.0;
    let two_months = 60;

    let mut d_slow = d0;
    for _ in 0..two_months {
        d_slow = update_depth(d_slow, 0.0, dt, 1.0 / 180.0);
    }
    assert!(
        d_slow > 0.70 * d0,
        "2 months of silence should leave > 70% of the depth, got {}%",
        100.0 * d_slow / d0
    );

    // Same 2 months through the FAST capital law → nearly gone (slow ≠ fast).
    let mut g_fast = d0;
    for _ in 0..two_months {
        g_fast = update_capital(g_fast, 0.0, 1.0 / 60.0, dt);
    }
    assert!(
        g_fast < 0.40 * d0,
        "the fast capital should have decayed below 40% over the same window, got {}%",
        100.0 * g_fast / d0
    );
}

// ============================================================
// kappa_key — the single holder-side reciprocity key κ_O (A.14).
// ============================================================

/// §13 default depth params for a 10 gb symbol at λ = 1/60 (g* = 600, d_ref = 3650).
fn dp_canon() -> DepthParams {
    let v_sym = 10.0;
    let lambda = 1.0 / 60.0;
    DepthParams {
        w_d: 0.5,
        d_ref: 365.0 * v_sym,
        g_star: capital_steady_state(v_sym, lambda),
    }
}

#[test]
fn kappa_key_ranks_silent_deep_above_stranger_below_active() {
    let p = dp_canon();
    let g_star = p.g_star;

    // active: strong fast capital, no depth needed.
    let k_active = kappa_key(g_star, 0.0, &p);
    // silent-deep: fast capital gone, but depth fully saturated (D ≥ d_ref).
    let k_deep = kappa_key(0.0, p.d_ref, &p);
    // stranger: nothing.
    let k_stranger = kappa_key(0.0, 0.0, &p);

    assert!(
        k_active > k_deep && k_deep > k_stranger,
        "κ order must be active ({k_active}) > silent-deep ({k_deep}) > stranger ({k_stranger})"
    );
    // The floor is exactly w_d·g* at full saturation, and the stranger is bare 0.
    assert!((k_deep - 0.5 * g_star).abs() < 1e-9);
    assert_eq!(k_stranger, 0.0);
}

// ============================================================
// eviction_order — the κ_O inter-owner key (A.14, transaction 3a).
// ============================================================

#[test]
fn eviction_drops_stranger_before_silent_deep_partner() {
    // Two owners, both with g_ho = 0. One is a stranger (D = 0), the other a
    // silent-but-DEEP loyal partner (D = d_ref). Under pressure the stranger drops
    // first — the W10 depth floor keeps the deep partner's disk share.
    let p = dp_canon();
    let deep = owner_view_depth(0.0, p.d_ref, 5.0, 1.0, 0); // owner 0
    let stranger = owner_view_depth(0.0, 0.0, 5.0, 1.0, 1); // owner 1
    let owners = vec![deep, stranger];
    let hyst = Hysteresis {
        s_hard: 0.1,
        s_target: 0.2,
        s_soft: 0.3,
    };
    let dec = eviction_order(
        &owners,
        0.0,
        hyst,
        EvictPhase::default(),
        &p,
        &RetentionCap::disabled(),
    );
    assert_eq!(
        owner_seq(&dec),
        vec![1, 0],
        "the stranger (κ=0) drops before the silent-deep partner (κ = w_d·g*)"
    );
}

#[test]
fn eviction_deep_floor_fades_after_years_of_silence() {
    // The D-farm is CLOSED: a once-deep partner that goes silent for ~4·τ_slow sees
    // its floor decay to ≈ e⁻⁴ of saturation, so it ranks essentially with a
    // stranger — and drops BEFORE a partner still at full depth. Depth is evolved
    // with the real update_depth law (ties the fade mechanism to eviction).
    let p = dp_canon();
    let lambda_slow = 1.0 / 180.0;
    let mut d_faded = p.d_ref; // start fully saturated
    for _ in 0..720 {
        // 4·τ_slow of silence
        d_faded = update_depth(d_faded, 0.0, 1.0, lambda_slow);
    }

    // The faded floor is a small fraction of the fresh floor (farm closed).
    let k_faded = kappa_key(0.0, d_faded, &p);
    let k_fresh = kappa_key(0.0, p.d_ref, &p);
    assert!(
        k_faded < 0.05 * k_fresh,
        "after ~4·τ_slow of silence the floor must have collapsed: faded {k_faded} vs fresh {k_fresh}"
    );

    // In eviction: stranger, faded-deep, fresh-deep — fresh drops LAST, faded drops
    // before fresh (its loyalty protection is gone).
    let stranger = owner_view_depth(0.0, 0.0, 5.0, 1.0, 0); // owner 0
    let faded = owner_view_depth(0.0, d_faded, 5.0, 1.0, 1); // owner 1
    let fresh = owner_view_depth(0.0, p.d_ref, 5.0, 1.0, 2); // owner 2
    let owners = vec![stranger, faded, fresh];
    let hyst = Hysteresis {
        s_hard: 0.1,
        s_target: 0.2,
        s_soft: 0.3,
    };
    let dec = eviction_order(
        &owners,
        0.0,
        hyst,
        EvictPhase::default(),
        &p,
        &RetentionCap::disabled(),
    );
    let seq = owner_seq(&dec);
    assert_eq!(seq.last(), Some(&2), "the still-deep partner drops LAST");
    let pos = |o: usize| seq.iter().position(|&x| x == o).unwrap();
    assert!(
        pos(1) < pos(2),
        "the faded once-deep partner now drops before the still-deep one: {seq:?}"
    );
}

#[test]
fn eviction_cross_owner_iota_ban_still_holds() {
    // Existing H2 invariant under the κ_O key: an owner with LOW κ (even with real
    // depth) whose symbol is MAXIMALLY important still loses its whole share before
    // any symbol of a higher-κ owner — ι never jumps owners.
    let p = dp_canon();
    // Owner 0: g_ho = 0.5, depth = d_ref ⇒ κ ≈ 0.5 + 0.5·g* = 300.5; symbol ι = 1000.
    let poor_kappa_high_iota = owner_view_depth(0.5, p.d_ref, 10.0, 1_000.0, 0);
    // Owner 1: g_ho = 350, depth = 0 ⇒ κ = 350; symbol ι = 0.001.
    let rich_kappa_low_iota = owner_view_depth(350.0, 0.0, 10.0, 0.001, 1);
    let owners = vec![poor_kappa_high_iota, rich_kappa_low_iota];
    let hyst = Hysteresis {
        s_hard: 0.1,
        s_target: 0.2,
        s_soft: 0.3,
    };
    let dec = eviction_order(
        &owners,
        0.0,
        hyst,
        EvictPhase::default(),
        &p,
        &RetentionCap::disabled(),
    );
    assert_eq!(
        owner_seq(&dec),
        vec![0, 1],
        "the low-κ owner's symbol drops first even with far-higher ι and real depth \
         (no cross-owner κ×ι product)"
    );
}

#[test]
fn eviction_kappa_reads_only_first_hand_no_archetype_channel() {
    // Anti-oracle: the κ_O rank is a pure function of first-hand scalars (g_ho, D,
    // tau, ι) — there is NOWHERE on OwnerEvictionView / DepthParams to encode a hidden
    // archetype, so two owners identical in every κ/tie-break input are
    // INTERCHANGEABLE: the drop order is decided only by those inputs and the input
    // order (stable tie-break), never by any concealed discriminator.
    let p = dp_canon();
    let a = owner_view_depth(3.0, 100.0, 10.0, 0.5, 7);
    let b = owner_view_depth(3.0, 100.0, 10.0, 0.5, 8);
    let hyst = Hysteresis {
        s_hard: 0.1,
        s_target: 0.2,
        s_soft: 0.3,
    };
    // Identical κ and tau ⇒ stable order preserves input order in both arrangements.
    let dec_ab = eviction_order(
        &[a.clone(), b.clone()],
        0.0,
        hyst,
        EvictPhase::default(),
        &p,
        &RetentionCap::disabled(),
    );
    let dec_ba = eviction_order(
        &[b, a],
        0.0,
        hyst,
        EvictPhase::default(),
        &p,
        &RetentionCap::disabled(),
    );
    assert_eq!(
        owner_seq(&dec_ab),
        vec![0, 1],
        "equal-κ owners keep input order (no hidden discriminator)"
    );
    assert_eq!(
        owner_seq(&dec_ba),
        vec![0, 1],
        "swapping the two equal-κ owners swaps their drop positions symmetrically"
    );
}

// ============================================================
// eviction_order — Р-7 holder-side volume cap V_ret (A.14 ⭐, transaction 3b).
// ============================================================

/// An [`OwnerEvictionView`] with explicit per-symbol `(id, importance, volume)` tuples,
/// a loyalty depth `D`, and pairwise capital `g_ho` — the shape the Р-7 cap tests need
/// (they must set real volumes, unlike the legacy unit-volume helpers).
fn owner_view_vols(g_ho: f64, depth: f64, tau: f64, syms: &[(u64, f64, f64)]) -> OwnerEvictionView {
    OwnerEvictionView {
        obs: obs_with(g_ho, tau),
        depth,
        symbols: syms
            .iter()
            .map(|&(id, importance, volume)| SymbolDecl {
                id: SymbolId(id),
                importance,
                volume,
            })
            .collect(),
    }
}

/// A `n` unit-volume symbols list with ascending ι and ids `base..base+n`.
fn unit_syms(base: u64, n: u64) -> Vec<(u64, f64, f64)> {
    (0..n).map(|i| (base + i, (i + 1) as f64, 1.0)).collect()
}

/// The standard evicting band; a φ of 0 is well below `s_hard` (the cap only bites
/// while the relay is in the evicting state).
fn evicting_band() -> Hysteresis {
    Hysteresis {
        s_hard: 0.1,
        s_target: 0.2,
        s_soft: 0.3,
    }
}

/// True iff every owner-0 slot precedes every owner-1 slot in a flat slot sequence
/// (the H2 property: ι orders only WITHIN an owner, never across owners).
fn owner0_before_owner1(seq: &[usize]) -> bool {
    match seq.iter().position(|&x| x == 1) {
        None => true,
        Some(p) => seq[p..].iter().all(|&x| x == 1),
    }
}

#[test]
fn retention_cap_trims_excess_lowest_iota_first_within_owner() {
    // One owner, κ_O = 0 (g_ho = 0, depth = 0) ⇒ V_ret = v_free = 2. It parks 5
    // unit-volume symbols (V_parked = 5) ⇒ the excess 3 gb is trimmed, LOWEST-ι first.
    let p = dp_canon();
    let cap = RetentionCap {
        v_free: 2.0,
        c_recip: 30.0,
    };
    // (id, ι, volume): ι deliberately out of id order to prove the sort is on ι.
    let owner = owner_view_vols(
        0.0,
        0.0,
        5.0,
        &[
            (10, 5.0, 1.0),
            (11, 1.0, 1.0),
            (12, 4.0, 1.0),
            (13, 2.0, 1.0),
            (14, 3.0, 1.0),
        ],
    );
    let owners = vec![owner];
    let dec = eviction_order(
        &owners,
        0.0,
        evicting_band(),
        EvictPhase::default(),
        &p,
        &cap,
    );

    // Trimmed the three lowest-ι symbols, ascending ι: ι=1 (id11), ι=2 (id13), ι=3 (id14).
    let cap_ids: Vec<u64> = dec
        .cap_drops
        .iter()
        .map(|s| owners[s.owner_idx].symbols[s.symbol_idx].id.0)
        .collect();
    assert_eq!(
        cap_ids,
        vec![11, 13, 14],
        "lowest-ι symbols are trimmed first"
    );

    // The remaining parked volume is ≤ V_ret (= 2.0): the two HIGH-ι symbols survive.
    let capped: Vec<usize> = dec.cap_drops.iter().map(|s| s.symbol_idx).collect();
    let remaining: f64 = owners[0]
        .symbols
        .iter()
        .enumerate()
        .filter(|(i, _)| !capped.contains(i))
        .map(|(_, s)| s.volume)
        .sum();
    assert!(
        remaining <= 2.0 + 1e-9,
        "remaining parked {remaining} must be ≤ V_ret"
    );
    assert_eq!(
        remaining, 2.0,
        "exactly the top-2 ι symbols (ι=4,5) are kept"
    );
}

#[test]
fn retention_cap_epsilon_whale_parks_at_most_v_free_plus_margin() {
    // P1b: an ε-GIVE whale (κ_O ≈ ε > 0, NOT zero-give) that piles 10 symbols on a
    // holder is capped near V_free — its parked volume is BOUNDED, not unbounded.
    let p = dp_canon();
    let cap = RetentionCap {
        v_free: 2.0,
        c_recip: 30.0,
    };
    let eps = 0.03; // κ_O = g_ho = ε ⇒ V_ret = 2 + 0.03/30 = 2.001 (barely above V_free).
    let owner = owner_view_vols(eps, 0.0, 5.0, &unit_syms(100, 10));
    let owners = vec![owner];
    let dec = eviction_order(
        &owners,
        0.0,
        evicting_band(),
        EvictPhase::default(),
        &p,
        &cap,
    );

    let v_ret = cap.v_ret(kappa_key(eps, 0.0, &p));
    assert!(
        (v_ret - 2.001).abs() < 1e-9,
        "ε-give lifts V_ret only by ε/c_recip"
    );
    let remaining: f64 = (0..10usize)
        .filter(|i| !dec.cap_drops.iter().any(|s| s.symbol_idx == *i))
        .map(|i| owners[0].symbols[i].volume)
        .sum();
    // Parked ≤ V_ret ≈ V_free, and FAR below the 10 gb it tried to park (P1b bound).
    assert!(
        remaining <= v_ret + 1e-9,
        "ε-whale parks ≤ V_ret ≈ V_free, got {remaining}"
    );
    assert_eq!(
        remaining, 2.0,
        "keeps 2 unit symbols (2.0 ≤ 2.001); the other 8 are trimmed"
    );
    assert_eq!(
        dec.cap_drops.len(),
        8,
        "8 of the whale's 10 symbols are cap-trimmed"
    );
}

#[test]
fn retention_cap_deep_silent_partner_keeps_depth_floor_volume() {
    // P5: a silent-but-DEEP partner (g_ho ≈ 0, D ≥ d_ref) gets a ROOMIER V_ret than a
    // stranger — the W10 depth floor (κ_O = w_d·g*) buys retention capacity.
    let p = dp_canon(); // g_star = 600, d_ref = 3650, w_d = 0.5.
    let cap = RetentionCap {
        v_free: 2.0,
        c_recip: 30.0,
    };
    // Deep: κ_O = 0 + 0.5·1·600 = 300 ⇒ V_ret = 2 + 300/30 = 12.
    let v_ret_deep = cap.v_ret(kappa_key(0.0, p.d_ref, &p));
    assert!(
        (v_ret_deep - 12.0).abs() < 1e-9,
        "deep V_ret = V_free + w_d·g*/c_recip = 12"
    );
    // Stranger: κ_O = 0 ⇒ V_ret = 2.
    let v_ret_str = cap.v_ret(kappa_key(0.0, 0.0, &p));
    assert!((v_ret_str - 2.0).abs() < 1e-9);

    // Each parks 20 unit symbols; measure how much each KEEPS after the cap.
    let deep = owner_view_vols(0.0, p.d_ref, 5.0, &unit_syms(200, 20));
    let stranger = owner_view_vols(0.0, 0.0, 5.0, &unit_syms(300, 20));
    let kept = |ov: OwnerEvictionView| -> usize {
        let owners = vec![ov];
        let dec = eviction_order(
            &owners,
            0.0,
            evicting_band(),
            EvictPhase::default(),
            &p,
            &cap,
        );
        owners[0].symbols.len() - dec.cap_drops.len()
    };
    let kept_deep = kept(deep);
    let kept_str = kept(stranger);
    assert_eq!(
        kept_deep, 12,
        "deep partner keeps its 12 gb depth-floor envelope"
    );
    assert_eq!(kept_str, 2, "stranger keeps only V_free = 2 gb");
    assert!(
        kept_deep > kept_str,
        "the depth floor makes the deep partner's V_ret roomier"
    );
}

#[test]
fn retention_cap_disabled_when_c_recip_nonpositive() {
    // WARN-1 guard: c_recip ≤ 0 DISABLES the cap (no /0, no evict-all). Behaviour then
    // reduces to the pre-3b pressure list (regress-equivalence).
    let p = dp_canon();
    // Two HUGE-volume symbols; an active cap would trim them, a disabled one must not.
    let owner = owner_view_vols(0.0, 0.0, 5.0, &[(1, 1.0, 100.0), (2, 2.0, 100.0)]);
    let owners = vec![owner];

    let dec0 = eviction_order(
        &owners,
        0.0,
        evicting_band(),
        EvictPhase::default(),
        &p,
        &RetentionCap::disabled(),
    );
    assert!(dec0.cap_drops.is_empty(), "c_recip = 0 ⇒ no cap_drops");
    let seq0: Vec<usize> = dec0.drop_order.iter().map(|s| s.symbol_idx).collect();
    assert_eq!(
        seq0,
        vec![0, 1],
        "drop_order is the full pre-3b ascending-ι list"
    );

    // Negative price must ALSO disable (not merely weaken) the cap.
    let neg = RetentionCap {
        v_free: 2.0,
        c_recip: -5.0,
    };
    let dec_neg = eviction_order(
        &owners,
        0.0,
        evicting_band(),
        EvictPhase::default(),
        &p,
        &neg,
    );
    assert!(
        dec_neg.cap_drops.is_empty(),
        "c_recip < 0 also disables the cap (no evict-all)"
    );
    assert_eq!(dec_neg.drop_order.len(), 2);
}

#[test]
fn retention_cap_active_iff_c_recip_positive() {
    // Direct contract of the WARN-1 guard predicate (reviewer 3b NOTE-3).
    assert!(!RetentionCap::disabled().active());
    assert!(
        !RetentionCap {
            v_free: 2.0,
            c_recip: -5.0
        }
        .active()
    );
    assert!(
        RetentionCap {
            v_free: 0.0,
            c_recip: 30.0
        }
        .active()
    );
}

#[test]
fn cap_drops_and_pressure_drops_do_not_overlap() {
    // The two lists partition the owner's symbols: every symbol appears in EXACTLY one
    // (no double-drop). κ_O = 0 ⇒ V_ret = 2 ⇒ 3 of 5 symbols are cap-trimmed.
    let p = dp_canon();
    let cap = RetentionCap {
        v_free: 2.0,
        c_recip: 30.0,
    };
    let owner = owner_view_vols(0.0, 0.0, 5.0, &unit_syms(1, 5));
    let owners = vec![owner];
    let dec = eviction_order(
        &owners,
        0.0,
        evicting_band(),
        EvictPhase::default(),
        &p,
        &cap,
    );

    let cap_set: Vec<(usize, usize)> = dec
        .cap_drops
        .iter()
        .map(|s| (s.owner_idx, s.symbol_idx))
        .collect();
    let pres_set: Vec<(usize, usize)> = dec
        .drop_order
        .iter()
        .map(|s| (s.owner_idx, s.symbol_idx))
        .collect();
    for c in &cap_set {
        assert!(
            !pres_set.contains(c),
            "cap_drops and drop_order must be disjoint: {c:?}"
        );
    }
    assert_eq!(dec.cap_drops.len(), 3, "3 excess symbols trimmed");
    assert_eq!(
        dec.drop_order.len(),
        2,
        "the other 2 stay in the pressure list"
    );
    assert_eq!(
        cap_set.len() + pres_set.len(),
        5,
        "every symbol appears exactly once"
    );
}

#[test]
fn cap_drops_empty_when_not_evicting() {
    // In abundance (φ above s_target ⇒ not evicting) the cap does NOT bite, even though
    // V_parked (100) massively exceeds V_ret (1) — W9 greed: the disk parks freely, the
    // excess only leaves at the NEXT contention.
    let p = dp_canon();
    let cap = RetentionCap {
        v_free: 1.0,
        c_recip: 30.0,
    };
    let owner = owner_view_vols(0.0, 0.0, 5.0, &[(1, 1.0, 100.0)]);
    let owners = vec![owner];
    let dec = eviction_order(
        &owners,
        0.9,
        evicting_band(),
        EvictPhase::default(),
        &p,
        &cap,
    );
    assert!(!dec.phase.evicting, "φ above s_target ⇒ relay not evicting");
    assert!(
        dec.cap_drops.is_empty(),
        "the cap does not trim in abundance"
    );
    assert!(dec.drop_order.is_empty());
}

#[test]
fn eviction_cross_owner_iota_ban_still_holds_with_cap() {
    // H2 in BOTH lists: a LOW-κ owner's symbols (even with MAXIMAL ι) all precede a
    // HIGH-κ owner's symbols (even with minimal ι) — ι never jumps owners, in cap_drops
    // AND in drop_order.
    let p = dp_canon();
    let cap = RetentionCap {
        v_free: 2.0,
        c_recip: 30.0,
    };
    // Owner 0: κ_O = 0 (V_ret = 2), 5 unit symbols all ι = 1000 (very important).
    let low_kappa_high_iota = owner_view_vols(
        0.0,
        0.0,
        5.0,
        &(0..5).map(|i| (i, 1000.0, 1.0)).collect::<Vec<_>>(),
    );
    // Owner 1: κ_O = 600 (V_ret = 22), 30 unit symbols all ι = 0.001 (worthless).
    let high_kappa_low_iota = owner_view_vols(
        600.0,
        0.0,
        5.0,
        &(0..30).map(|i| (100 + i, 0.001, 1.0)).collect::<Vec<_>>(),
    );
    let owners = vec![low_kappa_high_iota, high_kappa_low_iota];
    let dec = eviction_order(
        &owners,
        0.0,
        evicting_band(),
        EvictPhase::default(),
        &p,
        &cap,
    );

    // Both owners are trimmed (owner 0: 5−2 = 3; owner 1: 30−22 = 8).
    assert_eq!(dec.cap_drops.iter().filter(|s| s.owner_idx == 0).count(), 3);
    assert_eq!(dec.cap_drops.iter().filter(|s| s.owner_idx == 1).count(), 8);

    // H2 in cap_drops: all of owner 0's trims precede owner 1's (low-κ owner first),
    // even though owner 0's ι (1000) dwarfs owner 1's (0.001).
    let cap_owners: Vec<usize> = dec.cap_drops.iter().map(|s| s.owner_idx).collect();
    assert!(
        owner0_before_owner1(&cap_owners),
        "cap_drops: ι does not jump owners (H2)"
    );

    // H2 in drop_order: same — owner 0's surviving symbols precede owner 1's.
    let pres_owners: Vec<usize> = dec.drop_order.iter().map(|s| s.owner_idx).collect();
    assert!(
        owner0_before_owner1(&pres_owners),
        "drop_order: ι does not jump owners (H2)"
    );
}

#[test]
fn disabled_cap_leaves_full_two_level_drop_order() {
    // Explicit regress: with the cap disabled the full two-level order (κ_O across
    // owners, ι within) is exactly the pre-3b result, and cap_drops is empty — legacy
    // callers pass RetentionCap::disabled() and see no behavioural change.
    let p = dp_zero();
    let owners = vec![
        owner_view_multi(0.1, 1.0, &[0.9, 0.1], 100), // owner 0: lowest g_ho (drops first)
        owner_view_multi(9.0, 1.0, &[0.5], 200),      // owner 1: highest g_ho (drops last)
        owner_view_multi(3.0, 1.0, &[0.2, 0.8], 300), // owner 2: middle
    ];
    let dec = eviction_order(
        &owners,
        0.0,
        evicting_band(),
        EvictPhase::default(),
        &p,
        &RetentionCap::disabled(),
    );
    assert!(dec.cap_drops.is_empty(), "disabled cap ⇒ no cap_drops");
    // Owner order ascending g_ho: 0, 2, 1. Within: ascending ι.
    let seq: Vec<(usize, usize)> = dec
        .drop_order
        .iter()
        .map(|s| (s.owner_idx, s.symbol_idx))
        .collect();
    assert_eq!(
        seq,
        vec![(0, 1), (0, 0), (2, 0), (2, 1), (1, 0)],
        "two-level order intact: owner 0 (ι 0.1,0.9) → owner 2 (ι 0.2,0.8) → owner 1"
    );
}

// ============================================================
// Hysteresis gaps.
// ============================================================

#[test]
fn hysteresis_gaps_compute_evict_and_accept_deltas() {
    let h = Hysteresis {
        s_hard: 0.10,
        s_target: 0.25,
        s_soft: 0.40,
    };
    assert!((h.delta_evict() - 0.15).abs() < 1e-12);
    assert!((h.delta_accept() - 0.15).abs() < 1e-12);
}

#[test]
fn min_hysteresis_gap_scales_with_max_rate_and_tick() {
    // Δ_min = κ·max(a,b)·tick. a<b ⇒ uses b.
    let dmin = min_hysteresis_gap(0.01, 0.03, 2.0, 1.5);
    assert!((dmin - 1.5 * 0.03 * 2.0).abs() < 1e-12);
}

#[test]
fn min_hysteresis_gap_clamps_negative_inputs_to_zero() {
    assert_eq!(min_hysteresis_gap(-1.0, -1.0, -1.0, -1.0), 0.0);
}

// ============================================================
// credit_limit — never below V_dem, ratchets only by capital.
// ============================================================

#[test]
fn credit_limit_never_below_v_dem() {
    let policy = CreditPolicy::default();
    // Zero capital ⇒ confidence 0 ⇒ L = V_dem exactly.
    assert!((credit_limit(0.0, 7.0, &policy) - 7.0).abs() < 1e-12);
    // Negative capital clamps to 0 ⇒ still exactly V_dem.
    assert!((credit_limit(-5.0, 7.0, &policy) - 7.0).abs() < 1e-12);
    // Huge capital ⇒ approaches V_dem·(1+margin) but is always ≥ V_dem.
    let l = credit_limit(1e9, 7.0, &policy);
    assert!(l >= 7.0);
    assert!(l <= 7.0 * (1.0 + policy.margin) + 1e-6);
}

#[test]
fn credit_limit_ratchets_up_monotonically_with_capital() {
    let policy = CreditPolicy::default();
    let v_dem = 4.0;
    let mut prev = credit_limit(0.0, v_dem, &policy);
    for step in 1..100 {
        let g = step as f64 * 0.5;
        let l = credit_limit(g, v_dem, &policy);
        assert!(
            l >= prev - 1e-12,
            "credit limit must be non-decreasing in capital: g={g} l={l} prev={prev}"
        );
        assert!(l >= v_dem, "L must never drop below V_dem");
        prev = l;
    }
}

#[test]
fn credit_limit_grants_more_headroom_to_proven_partner() {
    let policy = CreditPolicy::default();
    let v_dem = 10.0;
    let low_capital = credit_limit(0.1, v_dem, &policy);
    let high_capital = credit_limit(100.0, v_dem, &policy);
    assert!(
        high_capital > low_capital,
        "a partner with more proven service gets more credit headroom"
    );
}

#[test]
fn credit_limit_saturates_margin_when_g_ref_nonpositive() {
    let policy = CreditPolicy {
        margin: 0.5,
        g_ref: 0.0,
    };
    // g_ref ≤ 0 ⇒ confidence factor = 1 ⇒ full margin granted.
    let l = credit_limit(0.0, 8.0, &policy);
    assert!((l - 8.0 * 1.5).abs() < 1e-12);
}

// ============================================================
// estimate_surface — reliability surface with off-sample inflation.
// ============================================================

/// Build a FirstHandObs that has observed ONE point `(v0, τ0)` with `pass`
/// successful and `fail` failed PoS rounds. Demonstrated scale is the observed
/// volume (the holder has proven exactly what we placed). All other fields are
/// first-hand defaults — there is no ground-truth field to set.
fn obs_observed_at(v0: f64, tau0: f64, pass: u32, fail: u32) -> FirstHandObs {
    FirstHandObs {
        g_owner_from_holder: 0.0,
        g_holder_from_owner: 0.0,
        v_dem: v0,
        recent_rate_p: 0.0,
        trend_d: 0.0,
        pos_pass: pass,
        pos_fail: fail,
        pos_timeout: 0,
        observed_volume: v0,
        observed_tau: tau0,
        addr_subnet: 0,
        addr_geo: 0,
        latency_ms: 0.0,
        reachable: true,
        scrutiny: 0.0,
        master_id: IdentityPub([0u8; 32]),
        device_id: DeviceId([0u8; 32]),
    }
}

#[test]
fn surface_estimate_is_in_unit_interval_and_ordered() {
    let prior = SurfacePrior::default();
    let obs = obs_observed_at(10.0, 30.0, 20, 0);
    // Probe a grid spanning in-sample and far off-sample.
    for &v in &[1.0, 10.0, 50.0, 500.0] {
        for &tau in &[1.0, 30.0, 200.0, 2000.0] {
            let e = estimate_surface(&obs, &prior, v, tau);
            assert!(
                (0.0..=1.0).contains(&e.r_hat),
                "r_hat in [0,1]: {} at v={v} tau={tau}",
                e.r_hat
            );
            assert!(
                e.ci_low <= e.r_hat + 1e-12,
                "ci_low ≤ r_hat at v={v} tau={tau}"
            );
            assert!(
                e.r_hat <= e.ci_high + 1e-12,
                "r_hat ≤ ci_high at v={v} tau={tau}"
            );
            assert!(
                e.ci_low <= e.ci_high + 1e-12,
                "ci_low ≤ ci_high at v={v} tau={tau}"
            );
        }
    }
}

#[test]
fn surface_ci_is_narrow_in_sample() {
    let prior = SurfacePrior::default();
    let obs = obs_observed_at(10.0, 30.0, 50, 0);
    // At the observed point with ample PoS samples the CI is tight: the only
    // width comes from σ0 and the tiny small-sample term, NOT off-sample inflation.
    let e = estimate_surface(&obs, &prior, 10.0, 30.0);
    let width = e.ci_high - e.ci_low;
    assert!(
        width < 0.15,
        "in-sample CI must be narrow (width={width}, ci=[{},{}])",
        e.ci_low,
        e.ci_high
    );
}

#[test]
fn surface_ci_widens_and_r_hat_drops_off_sample() {
    let prior = SurfacePrior::default();
    let obs = obs_observed_at(10.0, 30.0, 50, 0);
    let at_obs = estimate_surface(&obs, &prior, 10.0, 30.0);
    // Move off-sample in volume (3x proven) and time (2x observed). Both the CI
    // widens AND the conservative point estimate drops vs the observed point.
    let off_v = estimate_surface(&obs, &prior, 30.0, 30.0);
    let off_tau = estimate_surface(&obs, &prior, 10.0, 60.0);
    let in_width = at_obs.ci_high - at_obs.ci_low;
    assert!(
        (off_v.ci_high - off_v.ci_low) > in_width,
        "CI must widen off-sample in volume"
    );
    assert!(
        (off_tau.ci_high - off_tau.ci_low) > in_width,
        "CI must widen off-sample in time"
    );
    assert!(
        off_v.r_hat < at_obs.r_hat,
        "r_hat must drop trusting more volume"
    );
    assert!(
        off_tau.r_hat < at_obs.r_hat,
        "r_hat must drop trusting longer time"
    );
}

#[test]
fn surface_r_hat_monotone_decreasing_in_tau() {
    let prior = SurfacePrior::default();
    let obs = obs_observed_at(10.0, 30.0, 20, 0);
    let mut prev = f64::INFINITY;
    let mut tau = 0.1;
    while tau < 2000.0 {
        let e = estimate_surface(&obs, &prior, 10.0, tau);
        assert!(
            e.r_hat <= prev + 1e-9,
            "r_hat must be non-increasing in τ: tau={tau} r_hat={} prev={prev}",
            e.r_hat
        );
        prev = e.r_hat;
        tau += 0.7;
    }
}

#[test]
fn surface_r_hat_monotone_decreasing_in_volume() {
    let prior = SurfacePrior::default();
    let obs = obs_observed_at(10.0, 30.0, 20, 0);
    let mut prev = f64::INFINITY;
    let mut v = 0.1;
    while v < 1000.0 {
        let e = estimate_surface(&obs, &prior, v, 30.0);
        assert!(
            e.r_hat <= prev + 1e-9,
            "r_hat must be non-increasing in V: v={v} r_hat={} prev={prev}",
            e.r_hat
        );
        prev = e.r_hat;
        v += 0.5;
    }
}

#[test]
fn surface_r_hat_never_exceeds_backbone_and_off_sample_uses_lower_edge() {
    let prior = SurfacePrior::default();
    let obs = obs_observed_at(10.0, 30.0, 50, 0);
    // The conservative side is the LOWER bound: off-sample r_hat must sit at or
    // below the backbone value (computed via the same form, no inflation) — the
    // estimate is never more optimistic than the parametric skeleton.
    for &(v, tau) in &[(10.0, 30.0), (40.0, 90.0), (100.0, 365.0)] {
        let e = estimate_surface(&obs, &prior, v, tau);
        let v_dem = obs.v_dem.max(obs.observed_volume).max(1e-9);
        let r_back = backbone_survival(&prior, v, v_dem, tau);
        assert!(
            e.r_hat <= r_back + 1e-12,
            "r_hat ({}) must not exceed backbone ({r_back}) at v={v} tau={tau}",
            e.r_hat
        );
        // And the off-sample point estimate is pulled toward (never below) ci_low.
        assert!(e.r_hat >= e.ci_low - 1e-12);
    }
}

#[test]
fn surface_shape_comes_from_prior_not_observations() {
    // Two priors with DIFFERENT Weibull shape `k` but the SAME observation produce
    // DIFFERENT off-sample curves — proving the form is read from the prior, not
    // fit from `obs` (B1 / CONV-8: k is the offline form, never learned online).
    let obs = obs_observed_at(10.0, 30.0, 20, 0);
    let infant_mortality = SurfacePrior {
        weibull_k: 0.5,
        ..SurfacePrior::default()
    };
    let wear_out = SurfacePrior {
        weibull_k: 2.0,
        ..SurfacePrior::default()
    };
    // Far in time (off-sample): a wear-out form (k>1) collapses faster than an
    // infant-mortality form (k<1). Same obs, different prior ⇒ different surface.
    let r_dfr = estimate_surface(&obs, &infant_mortality, 10.0, 400.0).r_hat;
    let r_ifr = estimate_surface(&obs, &wear_out, 10.0, 400.0).r_hat;
    assert!(
        r_ifr < r_dfr,
        "wear-out prior (k>1) must give lower long-τ survival than infant-mortality (k<1): \
         r_ifr={r_ifr} r_dfr={r_dfr}"
    );
}

#[test]
fn surface_bad_pos_record_drops_estimate_below_clean_record() {
    let prior = SurfacePrior::default();
    let clean = obs_observed_at(10.0, 30.0, 50, 0);
    let mut spotty = obs_observed_at(10.0, 30.0, 25, 25);
    spotty.v_dem = 10.0;
    // At the observed point, a holder with a 50% PoS failure record is estimated
    // strictly LOWER than one with a clean record (the empirical anchor can only
    // drop the estimate, never raise it above the form).
    let r_clean = estimate_surface(&clean, &prior, 10.0, 30.0).r_hat;
    let r_spotty = estimate_surface(&spotty, &prior, 10.0, 30.0).r_hat;
    assert!(
        r_spotty < r_clean,
        "a failing PoS record must lower r_hat: spotty={r_spotty} clean={r_clean}"
    );
}

// ============================================================
// Phase 2b-1 — block survival R̂ + placement diversity-cap.
// ============================================================

/// Build a holder observed at `(v0, τ0)` with a clean PoS record, on a given
/// `master_id` and `addr_subnet`. Used to construct independent vs correlated
/// holder sets. Address fields are first-hand observables (§1-legal); there is no
/// "is-one-farm" field to set, by construction.
fn holder(master: u8, subnet: u32, v0: f64, tau0: f64) -> FirstHandObs {
    let mut m = [0u8; 32];
    m[0] = master;
    FirstHandObs {
        g_owner_from_holder: 0.0,
        g_holder_from_owner: 0.0,
        v_dem: v0,
        recent_rate_p: 0.0,
        trend_d: 0.0,
        pos_pass: 50,
        pos_fail: 0,
        pos_timeout: 0,
        observed_volume: v0,
        observed_tau: tau0,
        addr_subnet: subnet,
        addr_geo: 0,
        latency_ms: 10.0,
        reachable: true,
        scrutiny: 0.0,
        master_id: IdentityPub(m),
        device_id: DeviceId([0u8; 32]),
    }
}

/// A block request: erasure (n, k_eff), volume, horizon close to the observed
/// window (so per-holder r_hat is high), and a reliability target. `r_min = 0.5` is
/// a per-holder floor comfortably BELOW the ≈0.87 in-sample surface of the standard
/// `holder(...)` (v0=10, τ0=30, clean PoS), so the Р-5 credit cap does NOT bite an
/// in-sample holder asked to keep its demonstrated volume; it only bites a holder
/// asked to keep far MORE than it has proven (see the credit-cap test).
fn req(n: usize, k_eff: usize, r_target: f64) -> BlockReq {
    BlockReq {
        volume: 10.0 * n as f64, // per-symbol volume = 10.0 (= observed v0)
        n_symbols: n,
        k_eff,
        tau: 30.0, // = observed τ0 (in-sample ⇒ high, non-degenerate r_hat)
        r_target,
        r_min: 0.5,
    }
}

#[test]
fn block_survival_rises_when_independent_holders_are_added() {
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    let r = req(6, 3, 0.99);
    // Each holder is on a DISTINCT master and DISTINCT subnet → all independent.
    let two: Vec<FirstHandObs> = (0..2).map(|i| holder(i as u8, i, 10.0, 30.0)).collect();
    let four: Vec<FirstHandObs> = (0..4).map(|i| holder(i as u8, i, 10.0, 30.0)).collect();
    let r2 = estimate_block_survival(&two, &prior, &r, &policy);
    let r4 = estimate_block_survival(&four, &prior, &r, &policy);
    assert!(
        r4 > r2,
        "more independent holders must raise R̂ (k_eff=3): r2={r2} r4={r4}"
    );
}

#[test]
fn block_survival_wc_discounts_same_correlate_additions_vs_independent() {
    // A.9 (Р-4): the estimator no longer COLLAPSES same-subnet holders to one best
    // position — it carries every symbol and treats a shared correlate as WORST-CASE
    // coupled (comonotone) inside the group, independent between. So adding
    // same-subnet holders is worth STRICTLY LESS than adding independent ones (the §7
    // discrimination survives), though — unlike the old hard collapse — it is not
    // exactly zero: a comonotone group that crosses k_eff can meet the threshold
    // together, a small honest benefit. The hard §7 spread (≤1 symbol/bucket) is
    // enforced by `place`, not by this estimate.
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default(); // spread by addr_subnet
    let r = req(6, 2, 0.99);
    // Baseline: 3 INDEPENDENT holders (distinct master + subnet).
    let base: Vec<FirstHandObs> = (0..3).map(|i| holder(i as u8, i, 10.0, 30.0)).collect();
    let r_base = estimate_block_survival(&base, &prior, &r, &policy);

    // Add 2 MORE holders that share subnet 0 with holder 0 (a farm minting fresh
    // keys on one subnet) → they join holder 0's comonotone group.
    let mut correlated = base.clone();
    correlated.push(holder(50, 0, 10.0, 30.0)); // subnet 0 (== holder 0)
    correlated.push(holder(51, 0, 10.0, 30.0)); // subnet 0 (== holder 0)
    let r_corr = estimate_block_survival(&correlated, &prior, &r, &policy);

    // For contrast: adding 2 INDEPENDENT holders (distinct subnets) raises it much more.
    let mut independent = base.clone();
    independent.push(holder(60, 60, 10.0, 30.0));
    independent.push(holder(61, 61, 10.0, 30.0));
    let r_indep = estimate_block_survival(&independent, &prior, &r, &policy);

    assert!(
        r_corr >= r_base - 1e-12,
        "comonotone within a group never LOWERS R̂ below the no-addition baseline: \
         base={r_base} corr={r_corr}"
    );
    assert!(
        r_corr < r_indep - 1e-6,
        "same-correlate additions must be worth STRICTLY LESS than independent ones: \
         corr={r_corr} indep={r_indep}"
    );
    assert!(
        r_indep > r_base + 1e-6,
        "adding independent holders MUST raise R̂: base={r_base} indep={r_indep}"
    );
}

#[test]
fn block_survival_takes_best_holder_in_a_shared_bucket() {
    // Two holders share subnet 0: one with a CLEAN PoS record (high r_hat), one
    // with a spotty record (low r_hat). The §7 spread keeps ONE position for that
    // bucket and uses the BEST holder's prob — so adding the strong same-subnet
    // holder must RAISE R̂ over a baseline that has only the weak one there.
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    let r = req(6, 1, 0.99); // k_eff=1: R̂ is driven by the single shared bucket
    let mut weak = holder(0, 0, 10.0, 30.0);
    weak.pos_pass = 5;
    weak.pos_fail = 45; // mostly-failing record → low r_hat
    let strong = holder(1, 0, 10.0, 30.0); // clean record (pass:50) on SAME subnet 0

    let only_weak = vec![weak.clone()];
    let weak_plus_strong = vec![weak, strong];
    let r_weak = estimate_block_survival(&only_weak, &prior, &r, &policy);
    let r_both = estimate_block_survival(&weak_plus_strong, &prior, &r, &policy);
    assert!(
        r_both > r_weak + 1e-6,
        "a shared bucket must use the BEST holder's prob, not the worst: \
         weak={r_weak} both={r_both}"
    );
}

#[test]
fn block_survival_is_monotone_in_per_holder_reliability() {
    let policy = PlacementPolicy::default();
    let r = req(6, 3, 0.99);
    // Two priors: a more-reliable one (longer characteristic time) and a
    // less-reliable one (shorter). Same independent holder set.
    let strong = SurfacePrior {
        weibull_lambda_default: 3650.0,
        ..SurfacePrior::default()
    };
    let weak = SurfacePrior {
        weibull_lambda_default: 60.0,
        ..SurfacePrior::default()
    };
    let holders: Vec<FirstHandObs> = (0..5).map(|i| holder(i as u8, i, 10.0, 30.0)).collect();
    let r_strong = estimate_block_survival(&holders, &strong, &r, &policy);
    let r_weak = estimate_block_survival(&holders, &weak, &r, &policy);
    assert!(
        r_strong > r_weak,
        "R̂ must rise with per-holder reliability: strong={r_strong} weak={r_weak}"
    );
}

#[test]
fn block_survival_is_zero_when_fewer_buckets_than_k_eff() {
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    let r = req(6, 3, 0.99);
    // Two holders only, both on the SAME subnet → ONE address bucket < k_eff=3.
    let holders = vec![holder(0, 7, 10.0, 30.0), holder(1, 7, 10.0, 30.0)];
    let r_hat = estimate_block_survival(&holders, &prior, &r, &policy);
    assert_eq!(
        r_hat, 0.0,
        "fewer address buckets than k_eff ⇒ R̂ = 0 (structurally undeliverable)"
    );
}

#[test]
fn block_survival_collapse_is_master_blind_under_master_only_cap() {
    // Under MasterIdOnly the SAME farm (distinct masters, one subnet) spreads into
    // a SEPARATE bucket per master-id — so R̂ rises with farm size. This is the weak
    // policy: spreading by master-id does not see the shared subnet.
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy {
        cap_mode: CapMode::MasterIdOnly,
    };
    let r = req(6, 2, 0.99);
    let base: Vec<FirstHandObs> = (0..3).map(|i| holder(i as u8, i, 10.0, 30.0)).collect();
    let r_base = estimate_block_survival(&base, &prior, &r, &policy);
    let mut farmed = base.clone();
    farmed.push(holder(50, 0, 10.0, 30.0)); // same subnet 0 but a NEW master
    farmed.push(holder(51, 0, 10.0, 30.0));
    let r_farm = estimate_block_survival(&farmed, &prior, &r, &policy);
    assert!(
        r_farm > r_base + 1e-6,
        "MasterIdOnly does NOT collapse a same-subnet farm ⇒ R̂ rises (the weak policy): \
         base={r_base} farm={r_farm}"
    );
}

// ============================================================
// A.9 (Р-4) — correlation-aware worst-case block survival R̂_wc =
//   min(comonotone-within-groups, independent-over-all-symbols).
// These key the private `group_min_survival` / `comonotone_within_groups_at_least`
// helpers directly (accessible via `use super::*`) with hand-picked probs so the
// exact A.9 arithmetic is asserted, not the surface-derived probs.
// ============================================================

#[test]
fn block_survival_wc_is_not_always_below_independent_pb() {
    // B-2 counterexample. 3 symbols in ONE group, p=0.9, k_eff=3. Comonotone (A) =
    // P(N≥3) = p₍₃₎ = 0.9; independent (B) = 0.9³ = 0.729. Since A (0.9) > B (0.729),
    // a naïve "comonotone is the worst-case" bound would OVER-estimate at 0.9 — so
    // "R̂_wc ≤ independent-PB always" is only rescued by the min, which binds to B.
    let pos = vec![(BucketKey::Subnet(0), 0.9); 3];
    let a = comonotone_within_groups_at_least(&pos, 3);
    let b = poisson_binomial_at_least(&[0.9, 0.9, 0.9], 3);
    let wc = group_min_survival(&pos, 3);
    assert!((a - 0.9).abs() < 1e-12, "comonotone A must be 0.9, got {a}");
    assert!(
        (b - 0.729).abs() < 1e-12,
        "independent B must be 0.9³=0.729, got {b}"
    );
    assert!(
        a > b,
        "here comonotone {a} > independent {b} (min must take indep)"
    );
    assert!((wc - 0.729).abs() < 1e-12, "R̂_wc = min = 0.729, got {wc}");
}

#[test]
fn block_survival_wc_comonotone_binds_when_k_is_one() {
    // 3 symbols in one group, p=0.9, k_eff=1. Comonotone (A) = P(N≥1) = p₍₁₎ = 0.9
    // (the max p — they survive together); independent (B) = 1−0.1³ = 0.999. Here
    // comonotone is the CONSERVATIVE one, so the min binds to A = 0.9.
    let pos = vec![(BucketKey::Subnet(0), 0.9); 3];
    let a = comonotone_within_groups_at_least(&pos, 1);
    let b = poisson_binomial_at_least(&[0.9, 0.9, 0.9], 1);
    let wc = group_min_survival(&pos, 1);
    assert!((a - 0.9).abs() < 1e-12, "comonotone A must be 0.9, got {a}");
    assert!(
        (b - 0.999).abs() < 1e-12,
        "independent B must be 0.999, got {b}"
    );
    assert!(
        a < b,
        "here comonotone {a} < independent {b} (min must take comonotone)"
    );
    assert!((wc - 0.9).abs() < 1e-12, "R̂_wc = min = 0.9, got {wc}");
}

#[test]
fn block_survival_wc_degenerates_to_independent_when_one_per_group() {
    // ≤1 symbol per group ⇒ comonotone-within is a single Bernoulli ⇒ construction A
    // is analytically identical to B ⇒ R̂_wc equals the plain independent
    // Poisson-binomial. This is the guarantee that A.9 does not shift `place` / the
    // sim, which always spread ≤1 symbol per bucket.
    let probs = [0.9, 0.8, 0.7, 0.95];
    let pos: Vec<(BucketKey, f64)> = probs
        .iter()
        .enumerate()
        .map(|(i, &p)| (BucketKey::Subnet(i as u32), p))
        .collect();
    for k in 1..=probs.len() {
        let wc = group_min_survival(&pos, k);
        let pb = poisson_binomial_at_least(&probs, k);
        assert!(
            (wc - pb).abs() < 1e-9,
            "≤1/group must equal the independent PB at k={k}: wc={wc} pb={pb}"
        );
    }
}

#[test]
fn block_survival_wc_zero_only_when_fewer_symbols_than_k_eff() {
    // Structural-zero semantics under A.9 (decision_model §5): R̂_wc = 0 iff the
    // SYMBOL count < k_eff (max Σ N_c = symbol count) — NOT "distinct GROUPS < k_eff".
    // (a) 1 group of 3 symbols, k_eff=2 (< group size): NOT zero. Comonotone lets the
    //     group deliver ≥2 survivors together: A = p₍₂₎ = 0.9; independent
    //     PB(≥2 of 3) = 0.972; min = 0.9.
    let one_group = vec![(BucketKey::Subnet(0), 0.9); 3];
    let wc_a = group_min_survival(&one_group, 2);
    assert!(
        (wc_a - 0.9).abs() < 1e-12,
        "1 group, k_eff (2) < group size (3) is NOT structural zero: {wc_a}"
    );
    // (b) 2 symbols in TWO groups, k_eff=3: fewer symbols than k_eff ⇒ 0.
    let too_few = vec![(BucketKey::Subnet(0), 0.9), (BucketKey::Subnet(1), 0.9)];
    assert_eq!(
        group_min_survival(&too_few, 3),
        0.0,
        "fewer symbols than k_eff ⇒ structural zero"
    );
    // (c) 2 symbols in ONE group, k_eff=3: still 0 — same SYMBOL-count trigger, not
    //     a group-count trigger.
    let too_few_one_group = vec![(BucketKey::Subnet(0), 0.9), (BucketKey::Subnet(0), 0.9)];
    assert_eq!(group_min_survival(&too_few_one_group, 3), 0.0);
}

#[test]
fn block_survival_wc_two_groups_are_independent() {
    // Sanity of the BETWEEN-group independence: two groups of one symbol each are two
    // independent Bernoullis. k_eff=2 ⇒ both must survive ⇒ 0.9·0.8 = 0.72; k_eff=1 ⇒
    // at least one ⇒ 1 − 0.1·0.2 = 0.98.
    let pos = vec![(BucketKey::Subnet(0), 0.9), (BucketKey::Subnet(1), 0.8)];
    let wc2 = group_min_survival(&pos, 2);
    assert!(
        (wc2 - 0.72).abs() < 1e-12,
        "k=2 ⇒ 0.9·0.8 = 0.72, got {wc2}"
    );
    let wc1 = group_min_survival(&pos, 1);
    assert!(
        (wc1 - 0.98).abs() < 1e-12,
        "k=1 ⇒ 1−(1−0.9)(1−0.8) = 0.98, got {wc1}"
    );
}

#[test]
fn place_selects_enough_holders_to_reach_target() {
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    // n=8, k_eff=3, plenty of INDEPENDENT high-surface candidates.
    let r = req(8, 3, 0.95);
    let cands: Vec<FirstHandObs> = (0..8).map(|i| holder(i as u8, i, 10.0, 30.0)).collect();
    match place(&r, &cands, &prior, &policy) {
        PlacementResult::Placed {
            holders,
            r_hat_block,
        } => {
            assert!(
                r_hat_block >= r.r_target,
                "placed R̂ must reach the target: {r_hat_block} < {}",
                r.r_target
            );
            assert!(!holders.is_empty(), "must choose at least one holder");
        }
        other => panic!("expected Placed, got {other:?}"),
    }
}

#[test]
fn place_spreads_at_most_one_symbol_per_address_bucket() {
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default(); // spread by addr_subnet
    // n=5, k_eff=2. §7 spread ⇒ at most ONE symbol per subnet bucket.
    let r = req(5, 2, 0.999_999); // unreachably high so place keeps adding
    // Candidates: a big farm on subnet 0 (6 holders, distinct masters) + a few
    // independents on distinct subnets. The spread must take at most one of the
    // farm holders (one subnet bucket → one symbol).
    let mut cands: Vec<FirstHandObs> = (0..6).map(|i| holder(i as u8, 0, 10.0, 30.0)).collect();
    cands.push(holder(100, 100, 10.0, 30.0));
    cands.push(holder(101, 101, 10.0, 30.0));
    let result = place(&r, &cands, &prior, &policy);
    let holders = match &result {
        PlacementResult::Placed { holders, .. } => holders.clone(),
        PlacementResult::Insufficient { holders, .. } => holders.clone(),
    };
    // Rebuild the chosen observation set and verify no subnet bucket holds >1 symbol.
    let chosen_obs: Vec<FirstHandObs> = holders.iter().map(|&i| cands[i].clone()).collect();
    // Number of chosen symbols must equal the number of distinct buckets spanned
    // (≤1 per bucket), and the same-subnet farm contributes exactly one bucket.
    assert_eq!(
        chosen_obs.len(),
        cluster_count(&chosen_obs, &policy),
        "no two chosen symbols may share an address bucket (≤1 per subnet)"
    );
    let mut subnets: Vec<u32> = chosen_obs.iter().map(|o| o.addr_subnet).collect();
    subnets.sort_unstable();
    let distinct = {
        subnets.dedup();
        subnets.len()
    };
    assert_eq!(
        distinct,
        chosen_obs.len(),
        "every chosen holder is on a distinct subnet (one symbol per bucket)"
    );
}

#[test]
fn place_is_insufficient_when_candidates_too_correlated() {
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default(); // spread by addr_subnet
    // n=6, k_eff=3. ALL candidates on one subnet ⇒ one bucket ⇒ at most ONE symbol
    // placeable ⇒ buckets (1) < k_eff (3) ⇒ R̂ = 0 ⇒ Insufficient.
    let r = req(6, 3, 0.90);
    let cands: Vec<FirstHandObs> = (0..10).map(|i| holder(i as u8, 0, 10.0, 30.0)).collect();
    match place(&r, &cands, &prior, &policy) {
        PlacementResult::Insufficient {
            best_r_hat_block, ..
        } => {
            assert!(
                best_r_hat_block < r.r_target,
                "Insufficient must carry a best R̂ below target: {best_r_hat_block}"
            );
        }
        other => panic!("expected Insufficient for one-subnet candidates, got {other:?}"),
    }
}

#[test]
fn place_under_master_only_cap_lets_a_one_subnet_farm_fill_the_block() {
    // The SAME one-subnet farm that is Insufficient under AddrCorrelate (subnet
    // spread → one position) becomes a full placement under MasterIdOnly — spreading
    // by master-id gives each of the N farm keys its own bucket. This is the core
    // SIM-6 sign at the kernel level: subnet-spread (B) beats master-spread (A).
    let prior = SurfacePrior::default();
    let r = req(6, 3, 0.90);
    let cands: Vec<FirstHandObs> = (0..10).map(|i| holder(i as u8, 0, 10.0, 30.0)).collect();

    let strong = PlacementPolicy {
        cap_mode: CapMode::AddrCorrelate,
    };
    let weak = PlacementPolicy {
        cap_mode: CapMode::MasterIdOnly,
    };
    let under_strong = place(&r, &cands, &prior, &strong);
    let under_weak = place(&r, &cands, &prior, &weak);

    assert!(
        matches!(under_strong, PlacementResult::Insufficient { .. }),
        "subnet-spread must refuse a one-subnet farm: {under_strong:?}"
    );
    assert!(
        matches!(under_weak, PlacementResult::Placed { .. }),
        "master-spread lets the same farm fill the block (bypassed): {under_weak:?}"
    );
}

// ============================================================
// A.10 (place = argmax marginal ΔR̂_wc) + Р-5 (per-holder credit cap).
// ============================================================

#[test]
fn place_reaches_r_target_by_argmax_marginal() {
    // A.10: place must add each symbol to the candidate that maximises the marginal
    // ΔR̂_wc — i.e. argmax R̂_wc(chosen ∪ {cand}) at every step. We give candidates
    // with DIFFERENT surfaces (varying PoS records) so argmax genuinely discriminates
    // (with equal surfaces it degenerates to input order), then verify the chosen
    // sequence against a hand brute-force: at each prefix, no admissible candidate
    // would have produced a strictly higher R̂ than the one place picked.
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    let r = req(4, 1, 0.9); // k_eff=1, per-symbol volume 10 = observed scale

    // Three independent (distinct-subnet) holders with strong / medium / weak PoS.
    let strong = holder_with_standing(0, 0, 0.0, 50, 0, 0);
    let medium = holder_with_standing(1, 1, 0.0, 40, 10, 0);
    let weak = holder_with_standing(2, 2, 0.0, 20, 30, 0);
    let cands = vec![strong, medium, weak];

    let result = place(&r, &cands, &prior, &policy);
    let holders = match &result {
        PlacementResult::Placed {
            holders,
            r_hat_block,
        } => {
            assert!(
                *r_hat_block >= r.r_target,
                "placed R̂ must reach the target: {r_hat_block} < {}",
                r.r_target
            );
            holders.clone()
        }
        other => panic!("expected Placed, got {other:?}"),
    };
    assert!(!holders.is_empty(), "must choose at least one holder");

    // Brute-force argmax check: replay the selection and assert each pick was the
    // marginal-maximiser among the candidates admissible at that step.
    let v_per = r.volume_per_symbol();
    let cvmax = v_per * 4.0;
    let mut prefix: Vec<FirstHandObs> = Vec::new();
    let mut used_subnets: Vec<u32> = Vec::new();
    for (step, &ch) in holders.iter().enumerate() {
        // R̂ with the actually-chosen candidate at this step.
        let mut with_ch = prefix.clone();
        with_ch.push(cands[ch].clone());
        let r_ch = estimate_block_survival(&with_ch, &prior, &r, &policy);

        // No admissible OTHER candidate may beat r_ch (argmax property).
        for (c, cand_c) in cands.iter().enumerate() {
            if holders[..step].contains(&c) {
                continue; // already chosen before this step
            }
            if used_subnets.contains(&cand_c.addr_subnet) {
                continue; // §7 spread: bucket taken
            }
            let l = credit_limit_from_surface(cand_c, &prior, r.r_min, r.tau, cvmax);
            if l < v_per {
                continue; // Р-5 credit-capped
            }
            let mut with_c = prefix.clone();
            with_c.push(cand_c.clone());
            let r_c = estimate_block_survival(&with_c, &prior, &r, &policy);
            assert!(
                r_ch >= r_c - 1e-9,
                "step {step}: chosen holder {ch} (R̂={r_ch}) is NOT the marginal argmax — \
                 candidate {c} would give R̂={r_c}"
            );
        }
        prefix.push(cands[ch].clone());
        used_subnets.push(cands[ch].addr_subnet);
    }

    // With k_eff=1 the marginal argmax is the highest per-holder prob → the strong
    // holder (index 0) must be picked FIRST.
    assert_eq!(holders[0], 0, "argmax must pick the strongest holder first");
}

#[test]
fn place_never_puts_two_symbols_in_one_bucket() {
    // NOTE-1: the ≤1-symbol-per-bucket spread stays HARD under argmax. Candidates
    // with DUPLICATE addr_subnet must never both be chosen — every chosen holder
    // sits in a distinct bucket.
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default(); // spread by addr_subnet
    // Unreachably high target ⇒ place keeps adding every admissible candidate.
    let r = req(6, 2, 0.999_999);
    // Two crowded subnets (0 and 1, three holders each) + two lone subnets.
    let mut cands: Vec<FirstHandObs> = Vec::new();
    for m in 0..3 {
        cands.push(holder(m, 0, 10.0, 30.0)); // subnet 0
    }
    for m in 3..6 {
        cands.push(holder(m, 1, 10.0, 30.0)); // subnet 1
    }
    cands.push(holder(100, 100, 10.0, 30.0));
    cands.push(holder(101, 101, 10.0, 30.0));

    let holders = match place(&r, &cands, &prior, &policy) {
        PlacementResult::Placed { holders, .. } => holders,
        PlacementResult::Insufficient { holders, .. } => holders,
    };
    let chosen_subnets: Vec<u32> = holders.iter().map(|&i| cands[i].addr_subnet).collect();
    let mut sorted = chosen_subnets.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        chosen_subnets.len(),
        "no two chosen symbols may share a subnet bucket: {chosen_subnets:?}"
    );
    // Exactly four distinct buckets exist (subnets 0,1,100,101) ⇒ at most four picks.
    assert!(
        holders.len() <= 4,
        "cannot place more symbols than distinct buckets: {}",
        holders.len()
    );
}

#[test]
fn place_skips_holder_whose_credit_below_symbol_volume() {
    // Р-5: a holder that is highly RELIABLE at its own demonstrated scale but has a
    // SMALL demonstrated volume must be skipped when asked to keep a per-symbol volume
    // far above its credit limit L(O→h) < v_per_symbol — even though it would improve
    // R̂. An adequately-scaled holder on another bucket is still selected.
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    // per-symbol volume = 10; low target so a single adequate holder can be Placed.
    let r = req(3, 1, 0.5);
    let v_per = r.volume_per_symbol();
    let cvmax = v_per * 4.0;

    // small: proven only at v0=1 (clean PoS) → high surface AT its point, tiny credit.
    let small = holder(0, 5, 1.0, 30.0);
    // ok: proven at the full per-symbol volume v0=10 → credit ≥ v_per_symbol.
    let ok = holder(1, 6, 10.0, 30.0);

    // Precondition (1): small IS highly reliable at its demonstrated point (high surface).
    assert!(
        estimate_surface(&small, &prior, 1.0, 30.0).r_hat > 0.8,
        "small holder must be high-surface at its own proven scale"
    );
    // Precondition (2): but its credit at the per-symbol ask is below v_per_symbol.
    let l_small = credit_limit_from_surface(&small, &prior, r.r_min, r.tau, cvmax);
    assert!(
        l_small < v_per,
        "small holder's credit L={l_small} must be below v_per_symbol={v_per}"
    );
    // And the adequate holder's credit clears the bar.
    let l_ok = credit_limit_from_surface(&ok, &prior, r.r_min, r.tau, cvmax);
    assert!(
        l_ok >= v_per,
        "adequate holder's credit L={l_ok} must clear v_per_symbol={v_per}"
    );

    // place must SKIP small (index 0) and keep ok (index 1).
    let cands = vec![small, ok];
    let holders = match place(&r, &cands, &prior, &policy) {
        PlacementResult::Placed { holders, .. } => holders,
        PlacementResult::Insufficient { holders, .. } => holders,
    };
    assert!(
        !holders.contains(&0),
        "credit-capped small holder must NOT be chosen: {holders:?}"
    );
    assert!(
        holders.contains(&1),
        "adequate holder must be chosen: {holders:?}"
    );
}

#[test]
fn credit_limit_from_surface_is_monotone_and_matches_closed_form_approx() {
    // A.13: L falls as the required per-holder floor r_min rises (a stricter floor
    // admits less volume). And under the default prior the surface read sits in the
    // same order of magnitude as the closed-form approximation credit_limit(...).
    let prior = SurfacePrior::default();
    let holder = obs_observed_at(10.0, 30.0, 50, 0); // v_dem=10, clean PoS, τ0=30
    let t_horizon = 30.0;
    let v_max = 200.0;

    // Monotone non-increasing in r_min.
    let mut prev = f64::INFINITY;
    for &r_min in &[0.1, 0.3, 0.5, 0.7, 0.85] {
        let l = credit_limit_from_surface(&holder, &prior, r_min, t_horizon, v_max);
        assert!(
            l <= prev + 1e-9,
            "L must be non-increasing in r_min: r_min={r_min} L={l} prev={prev}"
        );
        assert!((0.0..=v_max).contains(&l), "L in [0, v_max]: {l}");
        prev = l;
    }

    // Order-of-magnitude match to the closed form at a floor just under the in-sample
    // surface (where the closed form is anchored ≈ V_dem). r̂(10,30) ≈ 0.87.
    let r_min = 0.85;
    let l_surface = credit_limit_from_surface(&holder, &prior, r_min, t_horizon, v_max);
    let l_closed = credit_limit(1.0, 10.0, &CreditPolicy::default()); // ≈ 11.25
    let ratio = l_surface / l_closed;
    assert!(
        (0.3..=3.0).contains(&ratio),
        "surface read L={l_surface} must be within an order of magnitude of the closed \
         form L={l_closed} (ratio={ratio})"
    );
}

#[test]
fn credit_limit_from_surface_binary_search_is_deterministic() {
    // Determinism (hard frame): the fixed-iteration bisection has no clock/rng and no
    // data-dependent loop bound, so two calls are BIT-identical.
    let prior = SurfacePrior::default();
    let holder = obs_observed_at(10.0, 30.0, 37, 3);
    let a = credit_limit_from_surface(&holder, &prior, 0.6, 45.0, 128.0);
    let b = credit_limit_from_surface(&holder, &prior, 0.6, 45.0, 128.0);
    assert_eq!(
        a.to_bits(),
        b.to_bits(),
        "credit surface read must be bit-deterministic: {a} vs {b}"
    );
}

// ============================================================
// K3 — per-symbol survival: retained-depth φ_O, eviction-retention s(r;φ_O),
//      and the heterogeneous per-symbol block-R̂.
// ============================================================

/// Build a `FirstHandObs` with a chosen `g_holder_from_owner` (standing signal),
/// PoS counters (pressure signal), and an in-sample observed point so the surface
/// route is high and clean. Address fields are first-hand; there is no
/// ground-truth field to set.
fn holder_with_standing(
    master: u8,
    subnet: u32,
    g_holder_from_owner: f64,
    pass: u32,
    fail: u32,
    timeout: u32,
) -> FirstHandObs {
    let mut m = [0u8; 32];
    m[0] = master;
    FirstHandObs {
        g_owner_from_holder: 0.0,
        g_holder_from_owner,
        v_dem: 10.0,
        recent_rate_p: 0.0,
        trend_d: 0.0,
        pos_pass: pass,
        pos_fail: fail,
        pos_timeout: timeout,
        observed_volume: 10.0,
        observed_tau: 30.0,
        addr_subnet: subnet,
        addr_geo: 0,
        latency_ms: 10.0,
        reachable: true,
        scrutiny: 0.0,
        master_id: IdentityPub(m),
        device_id: DeviceId([0u8; 32]),
    }
}

/// One holder's placement carrying an ι-ladder and the symbol's rung in it.
fn placement_on(obs: FirstHandObs, ladder: &[f64], symbol_in_ladder: usize) -> HolderPlacement {
    HolderPlacement {
        obs,
        ladder_iotas: ladder.to_vec(),
        symbol_in_ladder,
    }
}

#[test]
fn retained_depth_rises_with_standing_and_falls_with_observed_drops() {
    let r = RetentionPrior::default();
    // Deep partner, clean record → highest φ_O of the three (proven service earns
    // the most retained depth, even over the conservative floor).
    let deep = holder_with_standing(0, 0, 20.0, 50, 0, 0);
    let phi_deep = retained_depth(&deep, &r);
    // Unproven pair, clean record → low φ_O: with no proven standing the
    // conservative floor (depth_conservatism) keeps the modeled depth shallow.
    let unproven = holder_with_standing(0, 0, 0.0, 50, 0, 0);
    let phi_unproven = retained_depth(&unproven, &r);
    // Same standing as deep but a record full of drops/timeouts → pressure pulls
    // φ_O down hard.
    let squeezed = holder_with_standing(0, 0, 20.0, 10, 20, 20);
    let phi_squeezed = retained_depth(&squeezed, &r);

    assert!(
        phi_deep > phi_unproven,
        "higher G(h←O) must raise retained depth: deep={phi_deep} unproven={phi_unproven}"
    );
    assert!(
        phi_squeezed < phi_deep,
        "observed drops/timeouts must lower retained depth: squeezed={phi_squeezed} deep={phi_deep}"
    );
    // The conservative floor: an unproven pair is modeled SHALLOW (φ_O < 0.5) —
    // over-estimating retention is the dangerous direction, so we under-estimate.
    assert!(
        phi_unproven < 0.5,
        "unproven pair must be modeled shallow (conservative floor): {phi_unproven}"
    );
    for &p in &[phi_deep, phi_unproven, phi_squeezed] {
        assert!((0.0..=1.0).contains(&p), "φ_O in [0,1]: {p}");
    }
}

#[test]
fn retained_depth_curve_is_low_at_stranger_and_rises_with_standing() {
    // CALIBRATION SHAPE (the architect's intent — sign/threshold, not a pinned
    // curve): φ_O is (a) LOW at the stranger floor (weak-by-default, variant A), and
    // (b) rises MONOTONICALLY with accrued standing G(h←O) — more proven service ⇒
    // the holder is modeled as keeping more of the ladder.
    // All checks are first-hand: G(h←O) with a clean PoS record (no observed drops).
    let r = RetentionPrior::default();
    let phi = |g: f64| retained_depth(&holder_with_standing(0, 0, g, 50, 0, 0), &r);

    let stranger = phi(0.0);
    let modest = phi(4.0); // a few units of proven service
    let deep = phi(40.0); // a long-served reciprocal partner

    // (a) Stranger floor is weak-by-default (variant A): φ_O ≈ sigmoid(−1.5) ≈ 0.18.
    assert!(
        stranger < 0.25,
        "stranger must be weakly trusted by default (low floor): {stranger}"
    );

    // (b) Standing raises φ_O above the stranger floor — proven service is rewarded.
    assert!(
        deep > stranger,
        "accrued standing must raise retained depth above the floor: deep={deep} floor={stranger}"
    );
    // Monotone strictly increasing across the three probe points.
    assert!(
        stranger < modest && modest < deep,
        "φ_O must rise monotonically with standing: {stranger} < {modest} < {deep}"
    );
}

#[test]
fn retained_depth_is_more_conservative_with_a_larger_conservatism_offset() {
    // The depth_conservatism prior leans φ_O DOWN: a larger offset gives a shallower
    // modeled depth at the same standing/pressure — the safe (under-estimate) side.
    let obs = holder_with_standing(0, 0, 4.0, 50, 0, 0);
    let mild = RetentionPrior {
        depth_conservatism: 0.0,
        ..RetentionPrior::default()
    };
    let strong = RetentionPrior {
        depth_conservatism: 3.0,
        ..RetentionPrior::default()
    };
    let phi_mild = retained_depth(&obs, &mild);
    let phi_strong = retained_depth(&obs, &strong);
    assert!(
        phi_strong < phi_mild,
        "a larger conservatism offset must lower modeled depth: strong={phi_strong} mild={phi_mild}"
    );
}

#[test]
fn eviction_retention_is_monotone_increasing_in_iota_rank() {
    let r = RetentionPrior::default();
    let phi_o = 0.5; // edge at rank 0.5
    let mut last = -1.0;
    for &rank in &[0.0, 0.25, 0.5, 0.75, 1.0] {
        let s = eviction_retention(rank, phi_o, &r);
        assert!((0.0..=1.0).contains(&s), "s in [0,1]: {s} at rank={rank}");
        assert!(
            s > last - 1e-12,
            "s must be non-decreasing in ι-rank: {s} at rank={rank} (prev {last})"
        );
        last = s;
    }
    // Above the retained edge survives strongly; below it is small.
    assert!(
        eviction_retention(1.0, phi_o, &r) > eviction_retention(0.0, phi_o, &r) + 0.3,
        "top of the ladder must clearly out-survive the bottom"
    );
}

#[test]
fn eviction_retention_keeps_more_when_retained_depth_is_larger() {
    let r = RetentionPrior::default();
    // At a fixed mid ι-rank, a deeper φ_O (more of my ladder kept) must give a
    // higher keep-probability — the edge `1−φ_O` shifts below the symbol.
    let rank = 0.5;
    let s_shallow = eviction_retention(rank, 0.2, &r);
    let s_deep = eviction_retention(rank, 0.9, &r);
    assert!(
        s_deep > s_shallow,
        "larger φ_O must raise retention at a fixed rank: deep={s_deep} shallow={s_shallow}"
    );
    // The retained band's bottom edge is at rank `1−φ_O`. A symbol exactly ON the
    // edge sits at the sigmoid midpoint (0.5) by construction — neither clearly
    // kept nor clearly dropped. φ_O=1 puts the edge at rank 0, so the BOTTOM rung
    // (rank 0) is exactly at the edge (0.5) and every rung above it is kept;
    // φ_O=0 puts the edge at rank 1, so only the very TOP rung is at the edge and
    // everything below it is dropped. This is the faithful `sigmoid(β·(r−(1−φ_O)))`
    // semantics — a symbol must be ABOVE the retained depth to survive strongly.
    assert!(
        (eviction_retention(0.0, 1.0, &r) - 0.5).abs() < 1e-9,
        "φ_O=1 ⇒ edge at rank 0 ⇒ the bottom rung sits exactly on the edge (0.5)"
    );
    assert!(
        eviction_retention(0.5, 1.0, &r) > 0.9,
        "φ_O=1 keeps every rung ABOVE the bottom edge (mid rung clearly kept)"
    );
    assert!(
        eviction_retention(0.0, 0.0, &r) < 0.1,
        "φ_O=0 ⇒ edge at rank 1 ⇒ the bottom rung is far below the edge (dropped)"
    );
}

#[test]
fn iota_rank_is_midpoint_for_singleton_and_orders_by_importance() {
    // Р-3 midpoint: a single-symbol ladder is the MIDPOINT 0.5 (not 0) — the earlier
    // singleton→0 degeneracy collapsed the K3 per-symbol keep to ≤0.05 even for an
    // ideal partner (A.8).
    let single = placement_on(holder_with_standing(0, 0, 0.0, 50, 0, 0), &[0.7], 0);
    assert!((single.iota_rank() - 0.5).abs() < 1e-12);

    // Р-3 midpoint: a three-rung ladder ⇒ rank (i+0.5)/3: lowest-ι ⇒ 0.5/3 ≈ 0.1667,
    // middle ⇒ 1.5/3 = 0.5, highest ⇒ 2.5/3 ≈ 0.8333.
    let ladder = [0.1, 0.5, 0.9];
    let obs = holder_with_standing(0, 0, 0.0, 50, 0, 0);
    assert!((placement_on(obs.clone(), &ladder, 0).iota_rank() - 0.5 / 3.0).abs() < 1e-12);
    assert!((placement_on(obs.clone(), &ladder, 1).iota_rank() - 0.5).abs() < 1e-12);
    assert!((placement_on(obs, &ladder, 2).iota_rank() - 2.5 / 3.0).abs() < 1e-12);
}

#[test]
fn retention_ceiling_is_about_0_9_for_deep_partner_on_default_prior() {
    // Р-2 / A.7: a deeply-served partner (large G(h←O), clean PoS record) on the
    // recalibrated default prior reaches φ_O ≈ 0.90 — the ceiling sigmoid(c_s − c_0)
    // = sigmoid(3.7 − 1.5) = sigmoid(2.2) ≈ 0.900 (was 0.622 under c_s=2.0).
    let r = RetentionPrior::default();
    let deep = holder_with_standing(0, 0, 1000.0, 50, 0, 0);
    let phi = retained_depth(&deep, &r);
    assert!(
        (0.88..=0.91).contains(&phi),
        "deep partner must reach the ≈0.9 ceiling on the default prior: {phi}"
    );
}

#[test]
fn retention_discriminates_deep_from_stranger_on_default_prior() {
    // Р-2 / A.7: with the raised ceiling, a deep reciprocal partner is clearly
    // distinguishable from a stranger (the 0.622 ceiling made deep ≈ "a bit above
    // average"). φ_O(deep) must dominate φ_O(stranger) by a wide margin.
    let r = RetentionPrior::default();
    let deep = retained_depth(&holder_with_standing(0, 0, 1000.0, 50, 0, 0), &r);
    let stranger = retained_depth(&holder_with_standing(0, 0, 0.0, 50, 0, 0), &r);
    assert!(
        deep > stranger,
        "deep partner must outrank a stranger: deep={deep} stranger={stranger}"
    );
    assert!(
        deep / stranger > 3.0,
        "discrimination must be wide (>3×): deep={deep} stranger={stranger}"
    );
}

#[test]
fn iota_rank_is_midpoint_half_for_singleton() {
    // Р-3 / A.8: a one-rung ladder maps to the midpoint 0.5, never the degenerate 0.
    let single = placement_on(holder_with_standing(0, 0, 0.0, 50, 0, 0), &[0.42], 0);
    assert!((single.iota_rank() - 0.5).abs() < 1e-12);
}

#[test]
fn iota_rank_midpoint_is_monotone_and_bounded() {
    // Р-3 / A.8: for an m-rung ladder the midpoint ranks (i+0.5)/m strictly increase
    // with ι, all lie in (0,1), the bottom sits at 0.5/m and the top at (m−0.5)/m.
    let ladder = [0.1, 0.2, 0.3, 0.4, 0.5];
    let m = ladder.len();
    let obs = holder_with_standing(0, 0, 0.0, 50, 0, 0);
    let ranks: Vec<f64> = (0..m)
        .map(|i| placement_on(obs.clone(), &ladder, i).iota_rank())
        .collect();
    for &rk in &ranks {
        assert!(rk > 0.0 && rk < 1.0, "rank must lie in (0,1): {rk}");
    }
    for w in ranks.windows(2) {
        assert!(
            w[1] > w[0],
            "ranks must strictly increase with ι: {} !> {}",
            w[1],
            w[0]
        );
    }
    assert!(
        (ranks[0] - 0.5 / m as f64).abs() < 1e-12,
        "bottom rung must sit at 0.5/m: {}",
        ranks[0]
    );
    assert!(
        (ranks[m - 1] - (m as f64 - 0.5) / m as f64).abs() < 1e-12,
        "top rung must sit at (m−0.5)/m: {}",
        ranks[m - 1]
    );
}

#[test]
fn per_symbol_block_survival_ranks_high_iota_symbols_safer() {
    // On the SAME (shared) holder, a high-ι symbol must have a higher keep-prob
    // than a low-ι one — so a block whose symbol sits at the TOP of my ladder gets
    // a higher R̂ than the otherwise-identical block whose symbol sits at the
    // BOTTOM. We use k_eff=1 so R̂ is driven by the single chosen holder's symbol.
    let prior = SurfacePrior::default();
    let retention = RetentionPrior::default();
    let policy = PlacementPolicy::default();
    let r = req(3, 1, 0.99);
    // Middling standing so φ_O is partway and the ι-rank genuinely bites.
    let obs = holder_with_standing(0, 0, 0.5, 50, 0, 0);
    let ladder = [0.1, 0.5, 0.9];

    let low = [placement_on(obs.clone(), &ladder, 0)]; // bottom rung
    let high = [placement_on(obs, &ladder, 2)]; // top rung
    let r_low = estimate_block_survival_per_symbol(&low, &prior, &retention, &r, &policy);
    let r_high = estimate_block_survival_per_symbol(&high, &prior, &retention, &r, &policy);

    assert!(
        r_high > r_low,
        "high-ι symbol must forecast safer than low-ι on the same holder: low={r_low} high={r_high}"
    );
}

#[test]
fn per_symbol_block_survival_is_at_most_the_surface_only_estimate() {
    // The eviction route s ∈ [0,1] can only LOWER the per-symbol prob below the
    // surface-only value (the K2 estimate). So the per-symbol block-R̂ must never
    // exceed the surface-only block-R̂ over the same holder set — the per-symbol
    // refinement is conservative w.r.t. the aggregate it replaces.
    let prior = SurfacePrior::default();
    let retention = RetentionPrior::default();
    let policy = PlacementPolicy::default();
    let r = req(6, 3, 0.99);

    // Five independent holders, each holding a 2-rung ladder; forecast the BOTTOM
    // rung (worst eviction case) on each.
    let ladder = [0.2, 0.8];
    let placements: Vec<HolderPlacement> = (0..5)
        .map(|i| {
            placement_on(
                holder_with_standing(i as u8, i, 0.5, 50, 0, 0),
                &ladder,
                0, // bottom rung
            )
        })
        .collect();
    let surface_only: Vec<FirstHandObs> = placements.iter().map(|hp| hp.obs.clone()).collect();

    let r_per_symbol =
        estimate_block_survival_per_symbol(&placements, &prior, &retention, &r, &policy);
    let r_surface = estimate_block_survival(&surface_only, &prior, &r, &policy);

    assert!(
        r_per_symbol <= r_surface + 1e-12,
        "per-symbol R̂ must not exceed surface-only R̂: per_symbol={r_per_symbol} surface={r_surface}"
    );
}

#[test]
fn per_symbol_block_survival_is_zero_when_fewer_symbols_than_k_eff() {
    // A.9 (Р-4): the structural zero is now on the SYMBOL count, not the
    // distinct-GROUP count. Fewer symbols than k_eff ⇒ even all-survive cannot reach
    // the threshold (max Σ N_c = the symbol count) ⇒ R̂ = 0. Here 2 placements
    // (one subnet) with k_eff=3: 2 < 3 ⇒ 0, inherited by the K3 path.
    let prior = SurfacePrior::default();
    let retention = RetentionPrior::default();
    let policy = PlacementPolicy::default(); // spread by subnet
    let r = req(6, 3, 0.99);
    let ladder = [0.5];
    let placements: Vec<HolderPlacement> = (0..2)
        .map(|i| placement_on(holder_with_standing(i as u8, 0, 1.0, 50, 0, 0), &ladder, 0))
        .collect();
    let r_hat = estimate_block_survival_per_symbol(&placements, &prior, &retention, &r, &policy);
    assert_eq!(r_hat, 0.0, "fewer symbols than k_eff ⇒ R̂ = 0");
}

#[test]
fn per_symbol_block_survival_is_not_structurally_zero_when_group_meets_k_eff() {
    // A.9 (Р-4) contrast to the old collapse model: 6 placements on ONE subnet with
    // k_eff=3 is NO LONGER structurally zero. The estimator keeps all 6 symbols, and
    // a single correlate group CAN deliver ≥ k_eff survivors together (comonotone),
    // so R̂ > 0 (the min(comonotone, independent) worst-case bound, not the old
    // "distinct buckets (1) < k_eff (3) ⇒ 0"). Only the symbol count gates the
    // structural zero — see the sibling test above.
    let prior = SurfacePrior::default();
    let retention = RetentionPrior::default();
    let policy = PlacementPolicy::default();
    let r = req(6, 3, 0.99);
    let ladder = [0.5];
    let placements: Vec<HolderPlacement> = (0..6)
        .map(|i| placement_on(holder_with_standing(i as u8, 0, 1.0, 50, 0, 0), &ladder, 0))
        .collect();
    let r_hat = estimate_block_survival_per_symbol(&placements, &prior, &retention, &r, &policy);
    assert!(
        r_hat > 0.0,
        "6 symbols in one group with k_eff=3 (≤ group size) is NOT structurally zero \
         under A.9: R̂={r_hat}"
    );
}

#[test]
fn per_symbol_block_survival_takes_best_symbol_in_a_shared_bucket() {
    // Two placements share subnet 0: one is the BOTTOM rung of a deep partner's
    // ladder (low keep-prob), the other the TOP rung (high keep-prob). The §7
    // spread keeps ONE position for the bucket and uses the BEST per-symbol prob —
    // so the bucket's contribution is the high-ι symbol's.
    let prior = SurfacePrior::default();
    let retention = RetentionPrior::default();
    let policy = PlacementPolicy::default();
    let r = req(6, 1, 0.99); // k_eff=1 ⇒ R̂ driven by the single shared bucket
    let obs = holder_with_standing(0, 0, 0.5, 50, 0, 0);
    let ladder = [0.1, 0.9];

    let weak_only = [placement_on(obs.clone(), &ladder, 0)]; // bottom rung
    let with_strong = [
        placement_on(obs.clone(), &ladder, 0),
        placement_on(holder_with_standing(1, 0, 0.5, 50, 0, 0), &ladder, 1), // top, same subnet
    ];
    let r_weak = estimate_block_survival_per_symbol(&weak_only, &prior, &retention, &r, &policy);
    let r_best = estimate_block_survival_per_symbol(&with_strong, &prior, &retention, &r, &policy);

    assert!(
        r_best > r_weak,
        "the shared bucket must use the BEST per-symbol prob: weak={r_weak} best={r_best}"
    );
}

#[test]
fn per_symbol_forecast_is_bit_identical_for_owners_differing_only_in_hidden_archetype() {
    // ANTI-ORACLE GUARD (extended to the K3 per-symbol path). Two owners whose
    // ONLY difference is a hidden archetype — which is NOT a field on any kernel
    // input — must produce a bit-for-bit identical forecast. The "archetype" is
    // expressed here as god-view metadata the test holds OUTSIDE the kernel call;
    // it cannot reach `estimate_block_survival_per_symbol` because `HolderPlacement`
    // / `FirstHandObs` have no field for it (the crate boundary keeps the sim's
    // GroundTruth out entirely). The two forecasts being byte-equal proves the
    // hidden axis is structurally unreachable.
    let prior = SurfacePrior::default();
    let retention = RetentionPrior::default();
    let policy = PlacementPolicy::default();
    let r = req(6, 3, 0.99);
    let ladder = [0.2, 0.5, 0.8];

    // Build identical first-hand placements for BOTH owners (same observables:
    // standing, PoS record, addresses, ι-ladder, symbol rung). The hidden archetype
    // (Generous vs Freeloader, modeled by the local enum below) differs but is
    // NEVER passed to the kernel.
    #[derive(Clone, Copy)]
    enum HiddenArchetype {
        Generous,
        Freeloader,
    }
    let build = |_hidden: HiddenArchetype| -> Vec<HolderPlacement> {
        (0..5usize)
            .map(|i| {
                placement_on(
                    holder_with_standing(i as u8, i as u32, 0.7, 50, 0, 0),
                    &ladder,
                    i % ladder.len(),
                )
            })
            .collect()
    };
    let generous = build(HiddenArchetype::Generous);
    let freeloader = build(HiddenArchetype::Freeloader);

    let r_generous = estimate_block_survival_per_symbol(&generous, &prior, &retention, &r, &policy);
    let r_freeloader =
        estimate_block_survival_per_symbol(&freeloader, &prior, &retention, &r, &policy);

    // Bit-identical: same exact f64 bits, not merely close.
    assert_eq!(
        r_generous.to_bits(),
        r_freeloader.to_bits(),
        "forecast must be bit-identical when only a HIDDEN archetype differs: \
         generous={r_generous} freeloader={r_freeloader}"
    );
}

#[test]
fn place_below_k_eff_first_pick_is_index_tiebreak_not_surface() {
    // Reviewer NOTE-1 (транш 2b): while `chosen.len() < k_eff` for k_eff > 1, the block
    // survival is a STRUCTURAL ZERO for every candidate — fewer than k_eff symbols can
    // never meet the threshold — so all marginal ΔR̂ are identically 0 and the first
    // k_eff−1 picks fall to the index tie-break, NOT surface. This test DOCUMENTS (does
    // not endorse) that behaviour: it is SAFE (r_target still reached) but index-ordered
    // below k_eff. See the `place` doc-comment caveat.
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    let r = req(4, 2, 0.5); // k_eff = 2 ⇒ the first pick sits in the structural-zero region

    // Mechanism: a SINGLE strong holder gives R̂ = 0 at k_eff = 2 (one symbol can never
    // reach a 2-of threshold) ⇒ the first marginal is 0 regardless of its surface.
    let strong_solo = vec![holder_with_standing(1, 1, 0.0, 60, 0, 0)];
    assert_eq!(
        estimate_block_survival(&strong_solo, &prior, &r, &policy),
        0.0,
        "one holder is a structural zero at k_eff=2 ⇒ zero marginal below k_eff"
    );

    // idx 0 = MEDIUM surface (40/10), idx 1 = STRONG surface (60/0), distinct buckets,
    // both credit-uncapped. A surface-driven first pick would take STRONG (idx 1); the
    // zero-marginal region falls to the index tie-break and takes idx 0 (medium).
    let cands = vec![
        holder_with_standing(0, 0, 0.0, 40, 10, 0),
        holder_with_standing(1, 1, 0.0, 60, 0, 0),
    ];
    match place(&r, &cands, &prior, &policy) {
        PlacementResult::Placed {
            holders,
            r_hat_block,
        } => {
            assert_eq!(
                holders[0], 0,
                "below k_eff the first pick is the index tie-break (medium, idx 0), \
                 NOT the higher-surface strong holder at idx 1"
            );
            assert!(
                r_hat_block >= r.r_target,
                "safety: r_target floor still reached ({r_hat_block} ≥ {})",
                r.r_target
            );
        }
        other => panic!("expected Placed, got {other:?}"),
    }
}
