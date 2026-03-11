use super::*;
use crate::testutil::{test_db, test_peer, week};

fn make_engine() -> (TrustEngine, tempfile::NamedTempFile) {
    let (db, tmp) = test_db();
    (TrustEngine::new(db), tmp)
}

#[test]
fn trust_score_is_error_for_unknown_peer() {
    let (engine, _tmp) = make_engine();
    let peer = test_peer(1);
    let result = engine.score(&peer);
    assert!(matches!(result, Err(TrustError::UnknownPeer(_))));
}

#[test]
fn combined_score_returns_zero_for_unknown_peer() {
    let (engine, _tmp) = make_engine();
    let peer = test_peer(1);
    let result = engine.combined_score(&peer).unwrap();
    assert_eq!(result, 0.0);
}

#[test]
fn upsert_peer_creates_neutral_record() {
    let (engine, _tmp) = make_engine();
    let peer = test_peer(1);
    engine.upsert_peer(&peer, Timestamp(1000)).unwrap();
    let score = engine.score(&peer).unwrap();
    assert_eq!(score.p, 0.0);
    assert_eq!(score.i, 0.0);
    assert_eq!(score.s_raw, 1.0);
    assert_eq!(score.combined, 0.0);
}

#[test]
fn pos_success_increases_p_score() {
    let (engine, _tmp) = make_engine();
    let peer = test_peer(1);
    let t0 = week(0);
    engine.upsert_peer(&peer, t0).unwrap();
    engine.record_pos_result(&peer, PosOutcome { week_number: 1, challenged: 5, passed: 5 }).unwrap();
    let score = engine.recalculate(&peer, week(1), 1).unwrap();
    assert_eq!(score.p, 1.0);
    assert_eq!(score.i, 1.0);
    let expected_combined = (KP * 1.0 + KI * 1.0) * 1.0_f64.clamp(S_CLAMP_MIN, S_CLAMP_MAX);
    assert!((score.combined - expected_combined).abs() < 1e-10);
}

#[test]
fn pos_partial_failure_reduces_p() {
    let (engine, _tmp) = make_engine();
    let peer = test_peer(2);
    engine.upsert_peer(&peer, week(0)).unwrap();
    engine.record_pos_result(&peer, PosOutcome { week_number: 1, challenged: 10, passed: 8 }).unwrap();
    let score = engine.recalculate(&peer, week(1), 1).unwrap();
    assert!((score.p - 0.8).abs() < 1e-10);
    assert!((score.i - 0.8).abs() < 1e-10);
    let expected = (KP * 0.8 + KI * 0.8) * 1.0;
    assert!((score.combined - expected).abs() < 1e-10);
}

#[test]
fn p_window_is_exactly_4_weeks() {
    // Formula: window = [current_week - P_WINDOW_WEEKS + 1, current_week]
    // With P_WINDOW_WEEKS=4, current_week=5 → window = [2, 5]

    // Setup 1: weeks 1-5 all pass, current_week=5
    // Window covers weeks 2,3,4,5 only (week 1 outside). P = 40/40 = 1.0
    {
        let (engine, _tmp) = make_engine();
        let peer = test_peer(3);
        engine.upsert_peer(&peer, week(0)).unwrap();
        for w in 1..=5u32 {
            engine.record_pos_result(&peer, PosOutcome { week_number: w, challenged: 10, passed: 10 }).unwrap();
        }
        let score = engine.recalculate(&peer, week(5), 5).unwrap();
        assert!((score.p - 1.0).abs() < 1e-10, "setup1 p={}", score.p);
    }

    // Setup 2: week 1 fails, weeks 2-4 pass, current_week=4
    // Window = [1, 4]. Week 5 (if it existed) would be excluded.
    // P = (0+10+10+10)/(10+10+10+10) = 30/40 = 0.75
    {
        let (engine, _tmp) = make_engine();
        let peer = test_peer(3);
        engine.upsert_peer(&peer, week(0)).unwrap();
        engine.record_pos_result(&peer, PosOutcome { week_number: 1, challenged: 10, passed: 0 }).unwrap();
        for w in 2..=5u32 {
            engine.record_pos_result(&peer, PosOutcome { week_number: w, challenged: 10, passed: 10 }).unwrap();
        }
        // current_week=4: window=[1,4]. Week 5 is outside. Week 1 (fail) IS inside.
        let score = engine.recalculate(&peer, week(4), 4).unwrap();
        let expected_p = 30.0 / 40.0;
        assert!((score.p - expected_p).abs() < 1e-10, "setup2 p={} expected={}", score.p, expected_p);
        // Verify week 5 data excluded (if included, P would be 40/50=0.8)
        assert!((score.p - 0.8).abs() > 0.01, "setup2 should NOT be 0.8 (would mean 5 weeks included)");
    }
}

#[test]
fn i_is_cumulative_all_time_mean() {
    let (engine, _tmp) = make_engine();
    let peer = test_peer(4);
    engine.upsert_peer(&peer, week(0)).unwrap();
    engine.record_pos_result(&peer, PosOutcome { week_number: 1, challenged: 10, passed: 10 }).unwrap();
    engine.record_pos_result(&peer, PosOutcome { week_number: 2, challenged: 10, passed: 5 }).unwrap();
    engine.record_pos_result(&peer, PosOutcome { week_number: 3, challenged: 10, passed: 0 }).unwrap();
    let score = engine.recalculate(&peer, week(3), 3).unwrap();
    // I = mean(1.0, 0.5, 0.0) = 0.5
    assert!((score.i - 0.5).abs() < 1e-10, "i={}", score.i);
    // P over last 4 weeks (0..3): (10+5+0)/(10+10+10) = 0.5
    assert!((score.p - 0.5).abs() < 1e-10, "p={}", score.p);
}

#[test]
fn silent_week_not_counted_in_i() {
    let (engine, _tmp) = make_engine();
    let peer = test_peer(5);
    engine.upsert_peer(&peer, week(0)).unwrap();
    engine.record_pos_result(&peer, PosOutcome { week_number: 1, challenged: 10, passed: 10 }).unwrap();
    // week 2: no record (silent)
    engine.record_pos_result(&peer, PosOutcome { week_number: 3, challenged: 10, passed: 10 }).unwrap();
    let score = engine.recalculate(&peer, week(3), 3).unwrap();
    // I = mean(1.0, 1.0) = 1.0 (week 2 excluded)
    assert!((score.i - 1.0).abs() < 1e-10, "i={}", score.i);
    // P covers weeks 0..3: weeks 1 and 3 have data: P = 20/20 = 1.0
    assert!((score.p - 1.0).abs() < 1e-10, "p={}", score.p);
}

#[test]
fn s_score_neutral_when_no_transfers() {
    let (engine, _tmp) = make_engine();
    let peer = test_peer(6);
    engine.upsert_peer(&peer, week(0)).unwrap();
    let record = engine.get_peer(&peer).unwrap().unwrap();
    assert_eq!(record.trust_s, 1.0);
}

#[test]
fn s_score_freeloader_gets_minimum() {
    let (engine, _tmp) = make_engine();
    let peer = test_peer(7);
    engine.upsert_peer(&peer, week(0)).unwrap();
    let event = TransferEvent {
        peer,
        bytes_sent_to_peer: 1_000_000_000,
        bytes_received_from_peer: 0,
    };
    engine.record_transfer(&event, week(1)).unwrap();
    let record = engine.get_peer(&peer).unwrap().unwrap();
    assert_eq!(record.trust_s, 0.0);
    // combined uses clamp(0.0, 0.1, 1.0) = 0.1
    let score = engine.score(&peer).unwrap();
    assert!((score.s_raw - 0.0).abs() < 1e-10);
    let expected_combined = (KP * 0.0 + KI * 0.0) * 0.1;
    assert!((score.combined - expected_combined).abs() < 1e-10);
}

#[test]
fn s_score_good_reciprocator() {
    let (engine, _tmp) = make_engine();
    let peer = test_peer(8);
    engine.upsert_peer(&peer, week(0)).unwrap();
    let event = TransferEvent {
        peer,
        bytes_sent_to_peer: 1_000_000_000,
        bytes_received_from_peer: 1_000_000_000,
    };
    engine.record_transfer(&event, week(1)).unwrap();
    let record = engine.get_peer(&peer).unwrap().unwrap();
    assert!((record.trust_s - 1.0).abs() < 1e-10);
}

#[test]
fn s_score_exceeds_one_is_clamped_in_combined() {
    let (engine, _tmp) = make_engine();
    let peer = test_peer(9);
    engine.upsert_peer(&peer, week(0)).unwrap();
    let event = TransferEvent {
        peer,
        bytes_sent_to_peer: 100,
        bytes_received_from_peer: 200,
    };
    engine.record_transfer(&event, week(1)).unwrap();
    let record = engine.get_peer(&peer).unwrap().unwrap();
    assert!((record.trust_s - 2.0).abs() < 1e-10, "s_raw={}", record.trust_s);
    let score = engine.score(&peer).unwrap();
    // clamp(2.0, 0.1, 1.0) = 1.0
    let expected_combined = (KP * 0.0 + KI * 0.0) * 1.0;
    assert!((score.combined - expected_combined).abs() < 1e-10);
}

#[test]
fn zero_trust_clears_scores() {
    let (engine, _tmp) = make_engine();
    let peer = test_peer(10);
    engine.upsert_peer(&peer, week(0)).unwrap();
    engine.record_pos_result(&peer, PosOutcome { week_number: 1, challenged: 5, passed: 5 }).unwrap();
    engine.recalculate(&peer, week(1), 1).unwrap();
    let before = engine.score(&peer).unwrap();
    assert!(before.combined > 0.0);

    engine.zero_trust(&peer, week(2)).unwrap();
    let after = engine.score(&peer).unwrap();
    assert_eq!(after.p, 0.0);
    assert_eq!(after.i, 0.0);
    assert_eq!(after.combined, 0.0);
}

#[test]
fn recalculate_all_updates_all_peers() {
    let (engine, _tmp) = make_engine();
    let peer_a = test_peer(11);
    let peer_b = test_peer(12);
    let t0 = week(0);
    engine.upsert_peer(&peer_a, t0).unwrap();
    engine.upsert_peer(&peer_b, t0).unwrap();
    engine.record_pos_result(&peer_a, PosOutcome { week_number: 1, challenged: 5, passed: 5 }).unwrap();
    engine.record_pos_result(&peer_b, PosOutcome { week_number: 1, challenged: 5, passed: 4 }).unwrap();
    let count = engine.recalculate_all(week(1), 1).unwrap();
    assert_eq!(count, 2);
    let score_a = engine.score(&peer_a).unwrap();
    let score_b = engine.score(&peer_b).unwrap();
    assert!(score_a.combined > score_b.combined);
}

#[test]
fn weeks_in_network_computed_correctly() {
    let (engine, _tmp) = make_engine();
    let peer = test_peer(13);
    engine.upsert_peer(&peer, Timestamp(0)).unwrap();
    engine.recalculate(&peer, Timestamp(604800 * 13), 13).unwrap();
    let record = engine.get_peer(&peer).unwrap().unwrap();
    assert_eq!(record.weeks_in_network, 13);
}

#[test]
fn pos_results_accumulate_within_week() {
    let (engine, _tmp) = make_engine();
    let peer = test_peer(14);
    engine.upsert_peer(&peer, week(0)).unwrap();
    engine.record_pos_result(&peer, PosOutcome { week_number: 1, challenged: 5, passed: 4 }).unwrap();
    engine.record_pos_result(&peer, PosOutcome { week_number: 1, challenged: 5, passed: 5 }).unwrap();
    let score = engine.recalculate(&peer, week(1), 1).unwrap();
    // P = (4+5)/(5+5) = 0.9
    assert!((score.p - 0.9).abs() < 1e-10, "p={}", score.p);
}

#[test]
fn upsert_peer_idempotent() {
    let (engine, _tmp) = make_engine();
    let peer = test_peer(15);
    engine.upsert_peer(&peer, Timestamp(1000)).unwrap();
    engine.upsert_peer(&peer, Timestamp(2000)).unwrap();
    let record = engine.get_peer(&peer).unwrap().unwrap();
    assert_eq!(record.first_seen, Timestamp(1000));
    assert_eq!(record.last_seen, Timestamp(2000));
}

#[test]
fn all_peers_with_scores_returns_all() {
    let (engine, _tmp) = make_engine();
    let peers = crate::testutil::test_peers(3);
    for p in &peers {
        engine.upsert_peer(p, week(0)).unwrap();
    }
    let result = engine.all_peers_with_scores().unwrap();
    assert_eq!(result.len(), 3);
}

#[test]
fn get_peer_returns_none_for_unknown() {
    let (engine, _tmp) = make_engine();
    let result = engine.get_peer(&test_peer(99)).unwrap();
    assert!(result.is_none());
}

#[test]
fn record_transfer_updates_last_seen() {
    let (engine, _tmp) = make_engine();
    let peer = test_peer(20);
    engine.upsert_peer(&peer, week(0)).unwrap();
    let event = TransferEvent {
        peer,
        bytes_sent_to_peer: 1000,
        bytes_received_from_peer: 500,
    };
    engine.record_transfer(&event, week(3)).unwrap();
    let record = engine.get_peer(&peer).unwrap().unwrap();
    assert_eq!(record.last_seen, week(3));
    // s_raw = 500 / 1000 = 0.5
    assert!((record.trust_s - 0.5).abs() < 1e-10);
}

#[test]
fn record_transfer_on_unknown_peer_returns_error() {
    let (engine, _tmp) = make_engine();
    let peer = test_peer(30);
    let event = TransferEvent { peer, bytes_sent_to_peer: 100, bytes_received_from_peer: 100 };
    let result = engine.record_transfer(&event, week(0));
    assert!(matches!(result, Err(TrustError::UnknownPeer(_))));
}

#[test]
fn zero_trust_on_unknown_peer_returns_error() {
    let (engine, _tmp) = make_engine();
    let result = engine.zero_trust(&test_peer(40), week(0));
    assert!(matches!(result, Err(TrustError::UnknownPeer(_))));
}

#[test]
fn zero_trust_preserves_s_raw() {
    let (engine, _tmp) = make_engine();
    let peer = test_peer(50);
    engine.upsert_peer(&peer, week(0)).unwrap();
    let event = TransferEvent {
        peer,
        bytes_sent_to_peer: 100,
        bytes_received_from_peer: 200,
    };
    engine.record_transfer(&event, week(1)).unwrap();
    engine.zero_trust(&peer, week(2)).unwrap();
    let score = engine.score(&peer).unwrap();
    assert_eq!(score.p, 0.0);
    assert_eq!(score.i, 0.0);
    // s_raw should be preserved (2.0)
    assert!((score.s_raw - 2.0).abs() < 1e-10, "s_raw={}", score.s_raw);
}
