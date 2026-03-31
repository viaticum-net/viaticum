use super::{
    compute_combined, compute_effective_trust, recompute_master_trust, DeviceTrustRecord,
    MasterTrustRecord, PosOutcome, TrustEngine,
};
use crate::constants::{INITIAL_TRUST_P, KI, KP, MAX_COMBINED_TRUST};
use crate::types::{DeviceId, IdentityPub, Timestamp};

fn peer(byte: u8) -> DeviceId {
    let mut key = [0u8; 32];
    key[0] = byte;
    DeviceId(key)
}

fn master(byte: u8) -> IdentityPub {
    let mut key = [0u8; 32];
    key[0] = byte;
    IdentityPub(key)
}

fn ts(secs: u64) -> Timestamp {
    Timestamp(secs)
}

#[test]
fn compute_combined_basic() {
    let result = compute_combined(0.8, 0.5, 0.7);
    let expected = (KP * 0.8 + KI * 0.5) * 0.7;
    assert!((result - expected).abs() < 1e-10, "got {result}, expected {expected}");
    assert!((result - 0.8365).abs() < 1e-4);
}

#[test]
fn compute_combined_s_clamp_min() {
    let result = compute_combined(0.8, 0.5, 0.0);
    let expected = (KP * 0.8 + KI * 0.5) * 0.1;
    assert!((result - expected).abs() < 1e-10);
    assert!((result - 0.1195).abs() < 1e-4);
}

#[test]
fn compute_combined_s_clamp_max() {
    let result = compute_combined(0.8, 0.5, 2.5);
    let expected = (KP * 0.8 + KI * 0.5) * 1.0;
    assert!((result - expected).abs() < 1e-10);
    assert!((result - 1.195).abs() < 1e-4);
}

#[test]
fn upsert_peer_new_gets_initial_trust() {
    let mut engine = TrustEngine::new();
    let peer_a = peer(1);
    let now = ts(1_000_000);

    engine.upsert_peer_device(peer_a, master(0), now);
    let score = engine.score(&peer_a).unwrap();

    assert_eq!(score.p, INITIAL_TRUST_P);
    assert_eq!(score.i, 0.0);
    assert_eq!(score.s_raw, 1.0);

    let expected_combined = (KP * INITIAL_TRUST_P + KI * 0.0) * 1.0;
    assert!((score.combined - expected_combined).abs() < 1e-10);
    assert!((score.combined - 0.04).abs() < 1e-4);
}

#[test]
fn upsert_peer_reconnect_preserves_state() {
    let mut engine = TrustEngine::new();
    let peer_a = peer(1);
    let t0 = ts(1_000_000);
    let t1 = ts(2_000_000);

    engine.upsert_peer(peer_a, t0);
    engine
        .record_pos_result(
            peer_a,
            PosOutcome {
                week_number: 1,
                challenged: 10,
                passed: 9,
            },
        )
        .unwrap();
    engine.recalculate(&peer_a, t0, 1).unwrap();

    let score_before = engine.score(&peer_a).unwrap();

    engine.upsert_peer(peer_a, t1);

    let score_after = engine.score(&peer_a).unwrap();
    assert_eq!(score_before.p, score_after.p);
    assert_eq!(score_before.i, score_after.i);

    let record = engine.get_peer(&peer_a).unwrap();
    assert_eq!(record.last_seen, t1);
}

#[test]
fn recalculate_p_rolling_window() {
    let mut engine = TrustEngine::new();
    let peer_a = peer(1);
    let now = ts(1_000_000);

    engine.upsert_peer_device(peer_a, master(0), now);

    let records = vec![
        (6u32, 5u32, 5u32),
        (7u32, 5u32, 3u32),
        (10u32, 2u32, 2u32),
    ];
    for (week, challenged, passed) in records {
        engine
            .record_pos_result(
                peer_a,
                PosOutcome {
                    week_number: week,
                    challenged,
                    passed,
                },
            )
            .unwrap();
    }

    let current_week = 10;
    let score = engine.recalculate(&peer_a, now, current_week).unwrap();

    // Window [7, 10]: weeks 7 and 10 are in range; week 6 is excluded.
    // P = (3 + 2) / (5 + 2) = 5/7
    let expected_p = 5.0 / 7.0;
    assert!((score.p - expected_p).abs() < 1e-10, "p={} expected={}", score.p, expected_p);

    // I = mean of all active weeks: week6=1.0, week7=0.6, week10=1.0 → (1.0+0.6+1.0)/3
    let expected_i = (1.0 + 0.6 + 1.0) / 3.0;
    assert!((score.i - expected_i).abs() < 1e-10, "i={} expected={}", score.i, expected_i);
}

#[test]
fn recalculate_p_is_initial_when_no_pos_data_in_window() {
    let mut engine = TrustEngine::new();
    let peer_a = peer(1);
    let now = ts(1_000_000);

    engine.upsert_peer_device(peer_a, master(0), now);
    engine
        .record_pos_result(
            peer_a,
            PosOutcome {
                week_number: 3,
                challenged: 5,
                passed: 5,
            },
        )
        .unwrap();

    // current_week=10, window=[7,10] — week 3 is outside.
    let score = engine.recalculate(&peer_a, now, 10).unwrap();

    assert_eq!(score.p, INITIAL_TRUST_P, "P should be INITIAL_TRUST_P when no data in window");
    // I is still computed from all active weeks (week 3 passes 5/5 = 1.0)
    assert!((score.i - 1.0).abs() < 1e-10, "I should be 1.0");
}

#[test]
fn update_storage_bytes_s_neutral_when_we_store_nothing() {
    let mut engine = TrustEngine::new();
    let peer_a = peer(1);
    let now = ts(1_000_000);

    engine.upsert_peer_device(peer_a, master(0), now);
    engine
        .update_storage_bytes(peer_a, 0, 500_000)
        .unwrap();

    let record = engine.get_peer(&peer_a).unwrap();
    assert_eq!(record.trust_s, 1.0, "S should be 1.0 (neutral) when we store nothing");
}

#[test]
fn update_storage_bytes_s_below_one_when_peer_stores_less() {
    let mut engine = TrustEngine::new();
    let peer_a = peer(1);
    let now = ts(1_000_000);

    engine.upsert_peer_device(peer_a, master(0), now);
    engine
        .update_storage_bytes(peer_a, 1_000_000_000, 500_000_000)
        .unwrap();

    let record = engine.get_peer(&peer_a).unwrap();
    let expected_s = 0.5;
    assert!(
        (record.trust_s - expected_s).abs() < 1e-10,
        "s={} expected={}",
        record.trust_s,
        expected_s
    );
}

#[test]
fn zero_trust_resets_p_and_i() {
    let mut engine = TrustEngine::new();
    let peer_a = peer(1);
    let now = ts(1_000_000);

    engine.upsert_peer_device(peer_a, master(0), now);
    for week in 1..=5u32 {
        engine
            .record_pos_result(
                peer_a,
                PosOutcome {
                    week_number: week,
                    challenged: 10,
                    passed: 10,
                },
            )
            .unwrap();
    }
    engine.recalculate(&peer_a, now, 5).unwrap();

    let score_before = engine.score(&peer_a).unwrap();
    assert!(score_before.p > 0.0);
    assert!(score_before.i > 0.0);

    engine
        .update_storage_bytes(peer_a, 0, 1_000_000)
        .unwrap();
    let s_before = engine.get_peer(&peer_a).unwrap().trust_s;

    engine.zero_trust(&peer_a).unwrap();

    let score_after = engine.score(&peer_a).unwrap();
    assert_eq!(score_after.p, 0.0, "P should be 0.0 after zero_trust");
    assert_eq!(score_after.i, 0.0, "I should be 0.0 after zero_trust");

    let record = engine.get_peer(&peer_a).unwrap();
    assert_eq!(record.trust_s, s_before, "S should be unchanged by zero_trust");
}

#[test]
fn load_round_trips_state() {
    let mut engine1 = TrustEngine::new();
    let peer_a = peer(1);
    let peer_b = peer(2);
    let now = ts(1_000_000);

    engine1.upsert_peer_device(peer_a, master(0), now);
    engine1.upsert_peer_device(peer_b, master(0), now);

    engine1
        .record_pos_result(
            peer_a,
            PosOutcome {
                week_number: 1,
                challenged: 10,
                passed: 8,
            },
        )
        .unwrap();
    engine1
        .record_pos_result(
            peer_b,
            PosOutcome {
                week_number: 2,
                challenged: 5,
                passed: 5,
            },
        )
        .unwrap();

    engine1.update_storage_bytes(peer_a, 1_000, 500).unwrap();

    engine1.recalculate(&peer_a, now, 5).unwrap();
    engine1.recalculate(&peer_b, now, 5).unwrap();

    let score_a1 = engine1.score(&peer_a).unwrap();
    let score_b1 = engine1.score(&peer_b).unwrap();

    let peers = engine1.export_peers();
    let pos = engine1.export_pos_history();

    let mut engine2 = TrustEngine::load(peers, pos);

    let score_a2 = engine2.score(&peer_a).unwrap();
    let score_b2 = engine2.score(&peer_b).unwrap();

    assert_eq!(score_a1, score_a2, "peer_a scores should match after round-trip");
    assert_eq!(score_b1, score_b2, "peer_b scores should match after round-trip");

    // Verify recalculate produces same results after load
    engine2.recalculate(&peer_a, now, 5).unwrap();
    let score_a2_recalc = engine2.score(&peer_a).unwrap();
    assert_eq!(score_a1, score_a2_recalc);
}

#[test]
fn recalculate_all_returns_count() {
    let mut engine = TrustEngine::new();
    let now = ts(1_000_000);

    engine.upsert_peer_device(peer(1), master(0), now);
    engine.upsert_peer_device(peer(2), master(0), now);
    engine.upsert_peer_device(peer(3), master(0), now);

    let count = engine.recalculate_all(now, 5);
    assert_eq!(count, 3);
}

#[test]
fn peers_by_trust_sorted_descending() {
    let mut engine = TrustEngine::new();
    let peer_a = peer(1);
    let peer_b = peer(2);
    let peer_c = peer(3);
    let now = ts(1_000_000);

    engine.upsert_peer_device(peer_a, master(0), now);
    engine.upsert_peer_device(peer_b, master(0), now);
    engine.upsert_peer_device(peer_c, master(0), now);

    // Give peer_a lots of PoS
    for week in 1..=4u32 {
        engine
            .record_pos_result(
                peer_a,
                PosOutcome {
                    week_number: week,
                    challenged: 10,
                    passed: 10,
                },
            )
            .unwrap();
    }
    // Give peer_b some PoS
    engine
        .record_pos_result(
            peer_b,
            PosOutcome {
                week_number: 1,
                challenged: 10,
                passed: 5,
            },
        )
        .unwrap();
    // peer_c has no PoS

    engine.recalculate_all(now, 4);

    let ranked = engine.peers_by_trust();
    assert_eq!(ranked.len(), 3);

    let scores: Vec<f64> = ranked.iter().map(|(_, s)| s.combined).collect();
    for i in 0..scores.len() - 1 {
        assert!(
            scores[i] >= scores[i + 1],
            "scores not sorted descending: {scores:?}"
        );
    }

    // peer_a should be first (best trust)
    assert_eq!(ranked[0].0.device_id, peer_a);
}

#[test]
fn combined_score_returns_zero_for_unknown_peer() {
    let engine = TrustEngine::new();
    let unknown = peer(99);
    assert_eq!(engine.combined_score(&unknown), 0.0);
}

#[test]
fn score_returns_error_for_unknown_peer() {
    let engine = TrustEngine::new();
    let unknown = peer(99);
    assert!(engine.score(&unknown).is_err());
}

#[test]
fn record_pos_result_returns_error_for_unknown_peer() {
    let mut engine = TrustEngine::new();
    let unknown = peer(99);
    let result = engine.record_pos_result(
        unknown,
        PosOutcome {
            week_number: 1,
            challenged: 1,
            passed: 1,
        },
    );
    assert!(result.is_err());
}

#[test]
fn update_storage_bytes_returns_error_for_unknown_peer() {
    let mut engine = TrustEngine::new();
    let unknown = peer(99);
    let result = engine.update_storage_bytes(unknown, 100, 100);
    assert!(result.is_err());
}

#[test]
fn pos_accumulates_within_same_week() {
    let mut engine = TrustEngine::new();
    let peer_a = peer(1);
    let now = ts(1_000_000);

    engine.upsert_peer_device(peer_a, master(0), now);
    engine
        .record_pos_result(
            peer_a,
            PosOutcome {
                week_number: 1,
                challenged: 5,
                passed: 4,
            },
        )
        .unwrap();
    engine
        .record_pos_result(
            peer_a,
            PosOutcome {
                week_number: 1,
                challenged: 5,
                passed: 5,
            },
        )
        .unwrap();

    let score = engine.recalculate(&peer_a, now, 1).unwrap();
    // P = (4+5)/(5+5) = 9/10
    assert!((score.p - 0.9).abs() < 1e-10, "p={}", score.p);
}

#[test]
fn recent_pos_stats_no_data_returns_zeros() {
    let engine = TrustEngine::new();
    let p = peer(1);
    let (challenged, passed) = engine.recent_pos_stats(&p, 10, 4);
    assert_eq!(challenged, 0);
    assert_eq!(passed, 0);
}

#[test]
fn recent_pos_stats_single_week_in_window() {
    let mut engine = TrustEngine::new();
    let p = peer(1);
    engine.upsert_peer_device(p, master(0), ts(1_000_000));
    engine
        .record_pos_result(p, PosOutcome { week_number: 10, challenged: 5, passed: 4 })
        .unwrap();
    let (challenged, passed) = engine.recent_pos_stats(&p, 10, 4);
    assert_eq!(challenged, 5);
    assert_eq!(passed, 4);
}

#[test]
fn recent_pos_stats_multiple_weeks_summed() {
    let mut engine = TrustEngine::new();
    let p = peer(1);
    engine.upsert_peer_device(p, master(0), ts(1_000_000));
    engine
        .record_pos_result(p, PosOutcome { week_number: 8, challenged: 3, passed: 2 })
        .unwrap();
    engine
        .record_pos_result(p, PosOutcome { week_number: 9, challenged: 5, passed: 5 })
        .unwrap();
    engine
        .record_pos_result(p, PosOutcome { week_number: 10, challenged: 4, passed: 3 })
        .unwrap();
    let (challenged, passed) = engine.recent_pos_stats(&p, 10, 4);
    assert_eq!(challenged, 12);
    assert_eq!(passed, 10);
}

#[test]
fn recent_pos_stats_excludes_weeks_outside_window() {
    let mut engine = TrustEngine::new();
    let p = peer(1);
    engine.upsert_peer_device(p, master(0), ts(1_000_000));
    // week 5 is outside a 4-week window ending at week 10 (window: 7..=10)
    engine
        .record_pos_result(p, PosOutcome { week_number: 5, challenged: 10, passed: 10 })
        .unwrap();
    engine
        .record_pos_result(p, PosOutcome { week_number: 9, challenged: 3, passed: 2 })
        .unwrap();
    let (challenged, passed) = engine.recent_pos_stats(&p, 10, 4);
    assert_eq!(challenged, 3);
    assert_eq!(passed, 2);
}

// ─── TRUST-17: trust can exceed 1.0 ────────────────────────────────────────

#[test]
fn trust_can_exceed_one() {
    // P=1.0, I=1.0, S=1.0 → combined = (KP*1 + KI*1) * 1 = 0.4 + 1.75 = 2.15
    let combined = compute_combined(1.0, 1.0, 1.0);
    let expected = KP + KI; // 0.4 + 1.75 = 2.15
    assert!(
        (combined - expected).abs() < 1e-10,
        "expected {expected}, got {combined}"
    );
    assert!(combined > 1.0, "trust should be able to exceed 1.0");
}

// ─── PROP-02: compute_combined bounded across all input combinations ─────────

#[test]
fn trust_combined_bounded_across_inputs() {
    // Sweep P in {0.0, 0.25, 0.5, 0.75, 1.0}, I in {0.0, 0.5, 1.0},
    // S_raw in {0.0, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0}.
    // For each: result must be >= 0.0 and finite.
    let p_values = [0.0_f64, 0.25, 0.5, 0.75, 1.0];
    let i_values = [0.0_f64, 0.5, 1.0];
    let s_values = [0.0_f64, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0];

    for p in p_values {
        for i in i_values {
            for s in s_values {
                let combined = compute_combined(p, i, s);
                assert!(
                    combined >= 0.0,
                    "compute_combined({p}, {i}, {s}) = {combined} — must be >= 0.0"
                );
                assert!(
                    combined.is_finite(),
                    "compute_combined({p}, {i}, {s}) = {combined} — must be finite"
                );
            }
        }
    }
}

// ─── TRUST-20: trust convergence after perfect PoS ──────────────────────────

#[test]
fn trust_converges_after_sustained_perfect_pos() {
    let mut engine = TrustEngine::new();
    let p = peer(1);
    engine.upsert_peer_device(p, master(0), ts(1_000_000));

    // 20 weeks of perfect PoS (challenged=10, passed=10 each week)
    for week in 1..=20 {
        engine
            .record_pos_result(
                p,
                PosOutcome { week_number: week, challenged: 10, passed: 10 },
            )
            .unwrap();
    }

    // Must recalculate to update P and I from weekly data
    let score = engine.recalculate(&p, ts(2_000_000), 20).unwrap();
    // After 20 weeks perfect: P=1.0 (rolling 4-week), I → 1.0 (all weeks perfect)
    assert!(
        (score.p - 1.0).abs() < 1e-10,
        "P should be 1.0 after perfect PoS, got {}",
        score.p
    );
    assert!(
        score.i > 0.9,
        "I should be near 1.0 after 20 perfect weeks, got {}",
        score.i
    );
    // combined = (0.4*1.0 + 1.75*I) * S, S defaults to 1.0
    assert!(
        score.combined > 1.5,
        "combined should be well above 1.0, got {}",
        score.combined
    );
}

// ─── Two-level trust ────────────────────────────────────────────────────────

fn device_trust(p: f64, i: f64) -> DeviceTrustRecord {
    DeviceTrustRecord {
        device_id: DeviceId([1u8; 32]),
        trust_p: p,
        trust_i: i,
        last_week: 10,
    }
}

fn master_trust(combined: f64) -> MasterTrustRecord {
    MasterTrustRecord {
        identity: IdentityPub([2u8; 32]),
        combined,
        last_updated: Timestamp(1_000_000),
    }
}

#[test]
fn compute_effective_trust_new_user_new_device_returns_zero() {
    let result = compute_effective_trust(None, None);
    assert_eq!(result, 0.0);
}

#[test]
fn compute_effective_trust_new_device_old_user() {
    // device_trust=None, master=1.0 → base = 1.0 * 0.3 = 0.3, dt=0, effective=0.3
    let result = compute_effective_trust(None, Some(&master_trust(1.0)));
    let expected = 1.0_f64 * 0.3;
    assert!(
        (result - expected).abs() < 1e-10,
        "expected {expected}, got {result}"
    );
}

#[test]
fn compute_effective_trust_mature_device() {
    // dt = compute_combined(1.0, 1.0, 1.0) = KP + KI = 2.15
    // base = 2.15 * 0.3 = 0.645
    // effective = 0.645 + 2.15 * (1 - 0.645/2.15) = 0.645 + 2.15 * 0.7 = 2.15
    let dt = device_trust(1.0, 1.0);
    let mt = master_trust(MAX_COMBINED_TRUST);
    let result = compute_effective_trust(Some(&dt), Some(&mt));
    let expected = MAX_COMBINED_TRUST;
    assert!(
        (result - expected).abs() < 1e-9,
        "expected {expected}, got {result}"
    );
}

#[test]
fn compute_effective_trust_device_above_master() {
    // dt = 2.15, base = 0.5 * 0.3 = 0.15
    // effective = 0.15 + 2.15 * (1 - 0.15/2.15) = 0.15 + 2.15 * 0.9302... ≈ 2.15
    let dt = device_trust(1.0, 1.0);
    let mt = master_trust(0.5);
    let result = compute_effective_trust(Some(&dt), Some(&mt));
    let base = 0.5_f64 * 0.3;
    let dt_combined = compute_combined(1.0, 1.0, 1.0);
    let expected = base + dt_combined * (1.0 - base / MAX_COMBINED_TRUST);
    assert!(
        (result - expected).abs() < 1e-10,
        "expected {expected}, got {result}"
    );
    // Effective can exceed master.combined — this is correct
    assert!(result > 0.5, "effective should exceed low master trust when device is mature");
}

#[test]
fn compute_effective_trust_zero_device_trust_no_master() {
    let dt = device_trust(0.0, 0.0);
    let result = compute_effective_trust(Some(&dt), None);
    // base = 0.0 * 0.3 = 0.0; dt = compute_combined(0,0,1) = 0; effective = 0
    assert_eq!(result, 0.0);
}

#[test]
fn recompute_master_trust_single_device() {
    let d = device_trust(0.8, 0.8);
    let expected = compute_combined(0.8, 0.8, 1.0);
    let result = recompute_master_trust(&[(d, 1000)]);
    assert!(
        (result - expected).abs() < 1e-10,
        "expected {expected}, got {result}"
    );
}

#[test]
fn recompute_master_trust_weighted_average() {
    let da = device_trust(1.0, 1.0);
    let db = device_trust(0.0, 0.0);
    let dt_a = compute_combined(1.0, 1.0, 1.0);
    let dt_b = 0.0_f64;
    // weighted: (dt_a*2000 + dt_b*1000) / 3000 = dt_a * 2/3
    let expected = (dt_a * 2000.0 + dt_b * 1000.0) / 3000.0;
    let result = recompute_master_trust(&[(da, 2000), (db, 1000)]);
    assert!(
        (result - expected).abs() < 1e-10,
        "expected {expected}, got {result}"
    );
}

#[test]
fn recompute_master_trust_no_devices_returns_zero() {
    let result = recompute_master_trust(&[]);
    assert_eq!(result, 0.0);
}

#[test]
fn recompute_master_trust_equal_weight_when_all_symbols_zero() {
    let da = device_trust(1.0, 1.0);
    let db = device_trust(0.0, 0.0);
    let dt_a = compute_combined(1.0, 1.0, 1.0);
    let dt_b = 0.0_f64;
    let expected = (dt_a + dt_b) / 2.0;
    let result = recompute_master_trust(&[(da, 0), (db, 0)]);
    assert!(
        (result - expected).abs() < 1e-10,
        "expected {expected}, got {result}"
    );
}

#[test]
fn effective_trust_does_not_exceed_max_for_max_inputs() {
    let dt = device_trust(1.0, 1.0);
    let mt = master_trust(MAX_COMBINED_TRUST);
    let result = compute_effective_trust(Some(&dt), Some(&mt));
    assert!(
        result <= MAX_COMBINED_TRUST + 1e-9,
        "effective trust {result} exceeds MAX_COMBINED_TRUST {MAX_COMBINED_TRUST}"
    );
}

#[test]
fn effective_trust_is_nonnegative() {
    // Sweep representative inputs: p/i in {0,0.5,1}, master combined in {0,0.5,1,2.15}
    let p_values = [0.0_f64, 0.5, 1.0];
    let i_values = [0.0_f64, 0.5, 1.0];
    let mt_values = [0.0_f64, 0.5, 1.0, MAX_COMBINED_TRUST];

    for p in p_values {
        for i in i_values {
            for mt_val in mt_values {
                let dt = device_trust(p, i);
                let mt = master_trust(mt_val);
                let result = compute_effective_trust(Some(&dt), Some(&mt));
                assert!(
                    result >= 0.0,
                    "effective_trust({p},{i},{mt_val}) = {result} — must be >= 0.0"
                );
                assert!(
                    result.is_finite(),
                    "effective_trust({p},{i},{mt_val}) = {result} — must be finite"
                );
            }
        }
    }
}
