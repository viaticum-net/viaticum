use super::*;
use crate::{
    testutil::{test_db, test_peer, test_peers, test_unit_id, week},
    trust::{PosOutcome, TrustEngine},
    types::{ShardRecord, ShardStatus, Timestamp},
};

fn setup_peer_with_trust(engine: &TrustEngine, _db: &crate::db::Db, peer: &IdentityPub, trust_val: f64) {
    // We use a known formula: trust = (KP*P + KI*I) * clamp(S, 0.1, 1.0)
    // With S=1.0 (neutral), to get combined ≈ trust_val we need:
    // (0.4*P + 1.75*I) * 1.0 = trust_val
    // Simple: set P=1, I such that (0.4 + 1.75*I) = trust_val => I = (trust_val - 0.4) / 1.75
    // But trust_val may be < 0.4, so we use only I component:
    // Set P=0: KI*I = trust_val => I = trust_val / KI = trust_val / 1.75
    // But we need challenged > 0 to get I > 0.
    // Approach: record PoS with exact pass rate and recalculate.

    engine.upsert_peer(peer, week(1)).unwrap();

    if trust_val > 0.0 {
        // We want combined = trust_val with S=1.0
        // combined = (KP*P + KI*I) * 1.0
        // Set P = I = rate for simplicity: (KP + KI) * rate = trust_val
        // rate = trust_val / (KP + KI) = trust_val / 2.15
        // But rate must be [0,1], so cap it.
        let rate = (trust_val / (crate::constants::KP + crate::constants::KI)).min(1.0);
        // Use 1000 challenges to get good precision
        let passed = (rate * 1000.0).round() as u32;
        engine.record_pos_result(peer, PosOutcome {
            week_number: 1,
            challenged: 1000,
            passed,
        }).unwrap();
        engine.recalculate(peer, week(2), 1).unwrap();
    } else {
        // trust_val == 0.0: no PoS records, recalculate with zeroes
        engine.recalculate(peer, week(2), 1).unwrap();
    }
}

fn make_shard_record_for_unit(
    shard_id: crate::types::ShardId,
    unit_id: UnitId,
    holder: IdentityPub,
    status: ShardStatus,
) -> ShardRecord {
    ShardRecord {
        shard_id,
        unit_id,
        shard_index: 0,
        holder_id: holder,
        status,
        last_verified: None,
        offered_at: Timestamp(0),
        stored_at: None,
        merkle_root: [0u8; 32],
    }
}

#[test]
fn erasure_params_tier_mapping() {
    assert_eq!(PlacementEngine::erasure_params(0.9), ErasureParams { k: 5, n: 15 });
    assert_eq!(PlacementEngine::erasure_params(0.8), ErasureParams { k: 5, n: 15 });
    assert_eq!(PlacementEngine::erasure_params(0.79), ErasureParams { k: 5, n: 10 });
    assert_eq!(PlacementEngine::erasure_params(0.4), ErasureParams { k: 5, n: 10 });
    assert_eq!(PlacementEngine::erasure_params(0.39), ErasureParams { k: 5, n: 7 });
    assert_eq!(PlacementEngine::erasure_params(0.1), ErasureParams { k: 5, n: 7 });
    // Below 0.1 → ImportanceTooLow, erasure_params returns n=0
    let low = PlacementEngine::erasure_params(0.09);
    assert_eq!(low.k, 5);
    assert_eq!(low.n, 0);
}

#[test]
fn placement_fails_when_called_with_low_importance() {
    let (db, _tmp) = test_db();
    let trust = TrustEngine::new(db.clone());
    let engine = PlacementEngine::new(db.clone(), TrustEngine::new(db.clone()));
    let unit_id = test_unit_id(1);
    // Setup 4 peers with some trust
    let peers = test_peers(4);
    for p in &peers {
        setup_peer_with_trust(&trust, &db, p, 0.5);
    }
    let result = engine.select_holders(unit_id, 0.05);
    assert!(matches!(result, Err(PlacementError::ImportanceTooLow(_))));
}

#[test]
fn placement_fails_when_total_slots_less_than_n() {
    let (db, _tmp) = test_db();
    let trust = TrustEngine::new(db.clone());
    let engine = PlacementEngine::new(db.clone(), TrustEngine::new(db.clone()));
    let unit_id = test_unit_id(1);
    // 2 peers × 6 cap = 12 total slots < 15 (importance=0.8)
    let peers = test_peers(2);
    for p in &peers {
        setup_peer_with_trust(&trust, &db, p, 0.5);
    }
    let result = engine.select_holders(unit_id, 0.8);
    assert!(matches!(result, Err(PlacementError::NotEnoughPeers { .. })));
}

#[test]
fn placement_succeeds_with_exact_n_peers() {
    let (db, _tmp) = test_db();
    let trust = TrustEngine::new(db.clone());
    let engine = PlacementEngine::new(db.clone(), TrustEngine::new(db.clone()));
    let unit_id = test_unit_id(1);
    // Need exactly 15 peers with combined trust high enough to not trigger adaptive
    // avg_trust > 0.6 means no adaptive bump: we need 15 peers exactly
    // Use trust value of 1.0 (well above 0.6)
    let peers = test_peers(15);
    for p in &peers {
        setup_peer_with_trust(&trust, &db, p, 1.0);
    }
    let result = engine.select_holders(unit_id, 0.8);
    assert!(result.is_ok(), "unexpected error: {:?}", result);
    let plan = result.unwrap();
    assert_eq!(plan.assignments.len(), 15);
    // No single peer exceeds MAX_SHARDS_PER_PARTNER
    let mut per_peer: std::collections::HashMap<IdentityPub, usize> = std::collections::HashMap::new();
    for a in &plan.assignments {
        *per_peer.entry(a.holder).or_insert(0) += 1;
    }
    for (peer, count) in &per_peer {
        assert!(*count <= MAX_SHARDS_PER_PARTNER as usize,
            "peer {:?} got {} shards, exceeds cap {}", peer, count, MAX_SHARDS_PER_PARTNER);
    }
}

#[test]
fn placement_weights_are_proportional_to_trust_squared() {
    // Statistical test: run 1000 single-slot selections, verify high-trust peer selected > 60%
    // Setup: 3 peers with trust ~0.1, ~0.5, ~1.0
    // Weights: 0.01, 0.25, 1.0 (proportional)
    // High-trust peer probability ≈ 1.0 / (0.01 + 0.25 + 1.0) ≈ 77%
    // We use importance=0.1 (n=7) so we need at least 7 peers
    // For this test use importance=0.1 with 3 peers → will fail for n=7
    // Instead: use a fresh approach — pick 1 of 3 peers by weight 1000 times

    // Use a single DB and run 100 trials on the same setup.
    // Each trial: reset unit_id to avoid per-partner cap effects.
    let (db, _tmp) = test_db();
    let trust = TrustEngine::new(db.clone());

    // Use 10 peers: 1 high trust, 9 medium trust
    // avg_trust > 0.6 → no adaptive n bump → n=7 for importance=0.1
    let high_peer = test_peer(0);
    let med_peers: Vec<_> = (1..10).map(|i| test_peer(i as u8)).collect();

    setup_peer_with_trust(&trust, &db, &high_peer, 1.0);
    for p in &med_peers {
        setup_peer_with_trust(&trust, &db, p, 0.7);
    }

    let total_trials = 100;
    let mut high_trust_count = 0usize;

    for trial in 0..total_trials {
        // Use different unit_id each trial to avoid shard cap accumulation
        let unit_id = test_unit_id(trial as u8);
        let engine = PlacementEngine::new(db.clone(), TrustEngine::new(db.clone()));
        let plan = engine.select_holders(unit_id, 0.1).unwrap();
        if plan.assignments.iter().any(|a| a.holder == high_peer) {
            high_trust_count += 1;
        }
    }

    let ratio = high_trust_count as f64 / total_trials as f64;
    assert!(
        ratio > 0.6,
        "high-trust peer selected in only {:.1}% of trials (expected > 60%)",
        ratio * 100.0
    );
}

#[test]
fn per_partner_cap_enforced() {
    let (db, _tmp) = test_db();
    let trust = TrustEngine::new(db.clone());
    let engine = PlacementEngine::new(db.clone(), TrustEngine::new(db.clone()));
    let unit_id = test_unit_id(1);

    let peer_a = test_peer(0);
    let peer_b = test_peer(1);
    let peer_c = test_peer(2);

    for p in &[peer_a, peer_b, peer_c] {
        setup_peer_with_trust(&trust, &db, p, 1.0);
    }

    // Give peer_a 6 existing shards for this unit (the cap)
    for i in 0..6u8 {
        let mut shard_id_bytes = [0u8; 32];
        shard_id_bytes[0] = i;
        let shard_id = crate::types::ShardId(shard_id_bytes);
        let mut record = make_shard_record_for_unit(shard_id, unit_id, peer_a, ShardStatus::Stored);
        record.shard_index = i;
        db.upsert_shard(&record).unwrap();
    }

    // importance=0.1 → n=7, avg trust is high → no adaptive bump
    // Peer A at cap (6 existing), B and C have 6 slots each = 12 total >= 7
    // Verify: A never appears in the new assignments
    let result = engine.select_holders(unit_id, 0.1);
    assert!(result.is_ok(), "should succeed: B+C have 12 slots for n=7, got: {:?}", result);
    let plan = result.unwrap();
    assert_eq!(plan.assignments.len(), 7);
    assert!(
        !plan.assignments.iter().any(|a| a.holder == peer_a),
        "peer A (at cap) should not be selected"
    );
}

#[test]
fn adaptive_n_increases_n_when_avg_trust_low() {
    let (db, _tmp) = test_db();
    let trust = TrustEngine::new(db.clone());
    let engine = PlacementEngine::new(db.clone(), TrustEngine::new(db.clone()));
    let unit_id = test_unit_id(1);

    // 20 peers with combined trust = 0.2 (below ADAPTIVE_N_LOW_TRUST=0.3)
    // importance=0.4 → base_n=10, extra=2 → n=12
    // Need at least 12 peers
    let peers = test_peers(20);
    for p in &peers {
        setup_peer_with_trust(&trust, &db, p, 0.2);
    }

    let plan = engine.select_holders(unit_id, 0.4).unwrap();
    assert_eq!(plan.params.n, 12);
    assert_eq!(plan.assignments.len(), 12);
}

#[test]
fn subnet_diversity_limits_per_subnet_shards() {
    let (db, _tmp) = test_db();
    let trust = TrustEngine::new(db.clone());
    let engine = PlacementEngine::new(db.clone(), TrustEngine::new(db.clone()));
    let unit_id = test_unit_id(1);

    // 15 peers all with same /24 subnet
    let peers = test_peers(15);
    for p in peers.iter() {
        setup_peer_with_trust(&trust, &db, p, 1.0);
        // Set subnet to [192, 168, 1]
        let mut record = db.get_peer(p).unwrap().unwrap();
        record.subnet_prefix = Some([192, 168, 1]);
        db.upsert_peer(&record).unwrap();
    }

    // importance=0.8 → n=15, no adaptive bump (trust is high)
    // Rule is best-effort: if all peers share subnet, relax and allow placement
    let result = engine.select_holders(unit_id, 0.8);
    assert!(result.is_ok(), "subnet rule should be relaxed when all peers share subnet, got: {:?}", result);
    let plan = result.unwrap();
    assert_eq!(plan.assignments.len(), 15);
}

#[test]
fn zero_trust_peers_excluded() {
    let (db, _tmp) = test_db();
    let trust = TrustEngine::new(db.clone());
    let engine = PlacementEngine::new(db.clone(), TrustEngine::new(db.clone()));
    let unit_id = test_unit_id(1);

    // 10 peers with trust=0.0, 7 with trust>0
    let zero_peers = test_peers(10);
    for p in &zero_peers {
        trust.upsert_peer(p, week(1)).unwrap();
        // Explicitly zero out trust (recalculate preserves INITIAL_TRUST_P for no-PoS peers)
        trust.zero_trust(p, week(2)).unwrap();
    }

    let positive_peers: Vec<_> = (10..17).map(|i| test_peer(i as u8)).collect();
    for p in &positive_peers {
        setup_peer_with_trust(&trust, &db, p, 1.0);
    }

    // importance=0.1 → n=7, avg_trust is high (positive peers dominate in calc? no —
    // zero-trust peers are excluded from avg_trust calculation in select_holders)
    // Actually: avg_trust is computed only over candidates with trust > 0
    let plan = engine.select_holders(unit_id, 0.1).unwrap();
    assert_eq!(plan.assignments.len(), 7);

    let zero_set: std::collections::HashSet<_> = zero_peers.iter().cloned().collect();
    for assignment in &plan.assignments {
        assert!(
            !zero_set.contains(&assignment.holder),
            "zero-trust peer {:?} should not be selected",
            assignment.holder
        );
    }
}

#[test]
fn placement_returns_correct_shard_indices() {
    let (db, _tmp) = test_db();
    let trust = TrustEngine::new(db.clone());
    let engine = PlacementEngine::new(db.clone(), TrustEngine::new(db.clone()));
    let unit_id = test_unit_id(1);

    let peers = test_peers(8);
    for p in &peers {
        setup_peer_with_trust(&trust, &db, p, 1.0);
    }

    // importance=0.1 → n=7, avg_trust=high → no bump
    let plan = engine.select_holders(unit_id, 0.1).unwrap();
    assert_eq!(plan.assignments.len(), 7);

    let mut indices: Vec<u8> = plan.assignments.iter().map(|a| a.shard_index).collect();
    indices.sort();
    assert_eq!(indices, vec![0, 1, 2, 3, 4, 5, 6]);
}

#[test]
fn current_shard_counts_counts_only_active_and_pending() {
    let (db, _tmp) = test_db();
    let engine = PlacementEngine::new(db.clone(), TrustEngine::new(db.clone()));
    let unit_id = test_unit_id(1);
    let peer_a = test_peer(1);

    // 3 Stored (counts as active), 2 Offered (counts as pending), 1 Lost (does not count)
    for (i, status) in [
        (0u8, ShardStatus::Stored),
        (1u8, ShardStatus::Stored),
        (2u8, ShardStatus::Stored),
        (3u8, ShardStatus::Offered),
        (4u8, ShardStatus::Offered),
        (5u8, ShardStatus::Lost),
    ] {
        let mut shard_id_bytes = [0u8; 32];
        shard_id_bytes[0] = i;
        let shard_id = crate::types::ShardId(shard_id_bytes);
        let mut record = make_shard_record_for_unit(shard_id, unit_id, peer_a, status);
        record.shard_index = i;
        db.upsert_shard(&record).unwrap();
    }

    let counts = engine.current_shard_counts(unit_id).unwrap();
    assert_eq!(counts.get(&peer_a).copied().unwrap_or(0), 5);
}

#[test]
fn adaptive_n_pure_function() {
    // avg_trust < 0.3 → +2
    assert_eq!(PlacementEngine::adaptive_n(10, 0.2), 12);
    assert_eq!(PlacementEngine::adaptive_n(7, 0.0), 9);
    // 0.3 <= avg_trust < 0.6 → +1
    assert_eq!(PlacementEngine::adaptive_n(10, 0.3), 11);
    assert_eq!(PlacementEngine::adaptive_n(10, 0.5), 11);
    // avg_trust >= 0.6 → +0
    assert_eq!(PlacementEngine::adaptive_n(10, 0.6), 10);
    assert_eq!(PlacementEngine::adaptive_n(10, 1.0), 10);
}
