use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use viaticum_core::four_r::{FirstHandObs, SymbolDecl, SymbolId};
use viaticum_core::types::{DeviceId, IdentityPub};

/// An owner eviction view with a given pairwise service and tau, holding ONE
/// symbol (SIM-2 shape). Other fields are first-hand defaults; the symbol id is a
/// per-call counter so distinct owners get distinct ids. Mirrors the kernel test
/// helper but at the new input shape.
fn obs(g_holder_from_owner: f64, tau: f64) -> OwnerEvictionView {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    let fho = FirstHandObs {
        g_owner_from_holder: 0.0,
        g_holder_from_owner,
        v_dem: 0.0,
        recent_rate_p: 0.0,
        trend_d: 0.0,
        pos_pass: 0,
        pos_fail: 0,
        pos_timeout: 0,
        drop_ann: 0.0,
        drop_silent: 0.0,
        observed_volume: 0.0,
        observed_tau: tau,
        addr_subnet: 0,
        addr_geo: 0,
        latency_ms: 0.0,
        reachable: true,
        scrutiny: 0.0,
        master_id: IdentityPub([0u8; 32]),
        device_id: DeviceId([0u8; 32]),
    };
    OwnerEvictionView {
        obs: fho,
        // SIM-2 predates the A.4 loyalty depth (κ_O collapses to bare g_ho here).
        depth: 0.0,
        symbols: vec![SymbolDecl {
            id: SymbolId(NEXT_ID.fetch_add(1, Ordering::Relaxed)),
            importance: 1.0,
            // SIM-2 predates the Р-7 volume cap (RetentionCap::disabled()); volume inert.
            volume: 1.0,
        }],
    }
}

fn band(s_hard: f64, gap: f64) -> Hysteresis {
    Hysteresis {
        s_hard,
        s_target: s_hard + gap,
        s_soft: s_hard + 2.0 * gap,
    }
}

#[test]
fn run_with_empty_holdings_tracks_no_symbol_and_records_no_cycles() {
    // tracked_idx = None path: no holding to track, so no drop/reaccept ever
    // recorded, and the run must not panic on the empty slice.
    let trace = run(&[], band(0.30, 0.12), EngineParams::default());
    assert_eq!(trace.tracked.chatter_cycles, 0);
    assert_eq!(trace.tracked.all_cycles, 0);
    assert_eq!(trace.tracked.evict_count, 0);
    // With no holdings the drop_order is always empty even while evicting.
    assert!(trace.last_drop_order.is_empty());
    // φ was still logged every tick.
    assert_eq!(trace.phi.len(), EngineParams::default().ticks);
    // The tracked symbol is reported held (the default) since it never existed.
    assert!(trace.tracked.final_held);
}

#[test]
fn run_accept_leg_is_live_in_the_damped_band() {
    // With the default (retuned) load the φ envelope spans the whole band, so the
    // accept leg (φ > s_soft) fires repeatedly — the WARN-1 property at the engine
    // level, independent of the sim2 wiring.
    let holdings = vec![obs(0.2, 5.0), obs(4.0, 50.0), obs(8.0, 90.0)];
    let params = EngineParams {
        chatter_period_ticks: 6,
        ..EngineParams::default()
    };
    let trace = run(&holdings, band(0.30, 0.12), params);
    assert!(
        trace.tracked.accept_fire_count > 0,
        "accept leg must be reachable in the damped band"
    );
    assert!(
        trace.tracked.all_cycles > 0,
        "a full drop→reaccept→drop cycle must occur (both legs live)"
    );
    assert_eq!(
        trace.tracked.chatter_cycles, 0,
        "the slow load cycle is not short-period chatter"
    );
}

#[test]
fn run_zero_gap_band_chatters_at_tick_frequency() {
    // Δ = 0 collapses the band to a single threshold → the relay dithers across it
    // and produces many short-period chatter cycles (the load-bearing comparison).
    let holdings = vec![obs(0.2, 5.0), obs(4.0, 50.0)];
    let params = EngineParams {
        chatter_period_ticks: 6,
        ..EngineParams::default()
    };
    let zero = Hysteresis {
        s_hard: 0.30,
        s_target: 0.30,
        s_soft: 0.30,
    };
    let trace = run(&holdings, zero, params);
    assert!(
        trace.tracked.chatter_cycles > 0,
        "zero-gap relay must chatter at the tick frequency"
    );
}

#[test]
fn run_is_deterministic_for_same_inputs() {
    let holdings = vec![obs(0.2, 5.0), obs(4.0, 50.0), obs(8.0, 90.0)];
    let p = EngineParams::default();
    let a = run(&holdings, band(0.30, 0.12), p);
    let b = run(&holdings, band(0.30, 0.12), p);
    assert_eq!(a.phi, b.phi);
    assert_eq!(a.tracked.chatter_cycles, b.tracked.chatter_cycles);
    assert_eq!(a.tracked.accept_fire_count, b.tracked.accept_fire_count);
}

// ---- count_cycles unit tests (the period-aware chatter metric). ----

#[test]
fn count_cycles_pairs_drop_reaccept_drop_and_splits_by_period() {
    // drops at 0, 2, 100; reaccepts at 1, 50.
    // cycle from drop@0: reaccept@1, next drop@2 → period 2 (chatter at thresh 5).
    // cycle from drop@2: reaccept@50, next drop@100 → period 98 (not chatter).
    let drops = [0usize, 2, 100];
    let reaccepts = [1usize, 50];
    let (chatter, all) = count_cycles(&drops, &reaccepts, 5);
    assert_eq!(all, 2, "two full drop→reaccept→drop cycles");
    assert_eq!(
        chatter, 1,
        "only the period-2 cycle is short-period chatter"
    );
}

#[test]
fn count_cycles_zero_when_no_reaccept_between_drops() {
    // Drops with no reaccept after the first → no completed cycle.
    let drops = [0usize, 1, 2];
    let reaccepts: [usize; 0] = [];
    let (chatter, all) = count_cycles(&drops, &reaccepts, 5);
    assert_eq!(chatter, 0);
    assert_eq!(all, 0);
}

#[test]
fn count_cycles_all_short_period_are_chatter_when_threshold_large() {
    let drops = [0usize, 3, 6, 9];
    let reaccepts = [1usize, 4, 7];
    let (chatter, all) = count_cycles(&drops, &reaccepts, 100);
    assert_eq!(
        all, chatter,
        "with a huge threshold every cycle counts as chatter"
    );
    assert!(all >= 1);
}
