use super::*;
use crate::testutil::{test_db, test_peer, test_shard_id, test_unit_id};
use crate::trust::TrustEngine;
use crate::types::{
    BudgetRecord, FileId, FileRecord, FileType, HoldingRecord, ShardRecord, ShardState,
    ShardStatus, Timestamp, UnitRecord, UnitStatus, UnitType,
};

// ---- helpers ----

fn make_planner() -> (BudgetPlanner, tempfile::NamedTempFile) {
    let (db, tmp) = test_db();
    let trust = TrustEngine::new(db.clone());
    let planner = BudgetPlanner::new(db, trust);
    (planner, tmp)
}

fn make_planner_with_db() -> (BudgetPlanner, crate::db::Db, tempfile::NamedTempFile) {
    let (db, tmp) = test_db();
    let trust = TrustEngine::new(db.clone());
    let planner = BudgetPlanner::new(db.clone(), trust);
    (planner, db, tmp)
}

fn make_file_record(
    path: &str,
    file_id: u64,
    size_bytes: u64,
    importance: f64,
    dirty: bool,
) -> FileRecord {
    FileRecord {
        file_id: FileId(file_id),
        path: path.to_string(),
        content_hash: [0u8; 32],
        size_bytes,
        importance,
        dirty,
        current_unit_id: None,
        last_backed_up: None,
        backed_up: false,
        first_seen: Timestamp(0),
    }
}

fn make_holding_record(
    shard_seed: u8,
    owner_seed: u8,
    importance: f64,
    size_bytes: u64,
    file_type: FileType,
    received_at: Timestamp,
) -> HoldingRecord {
    HoldingRecord {
        shard_id: test_shard_id(shard_seed),
        owner_pub: test_peer(owner_seed),
        importance,
        size_bytes,
        state: ShardState::Active,
        received_at,
        delete_requested_at: None,
        drop_notice_sent_at: None,
        file_type,
        merkle_root: [0u8; 32],
        rs_k: 5,
        rs_n: 10,
        shard_index: 0,
    }
}

fn make_unit_record(seed: u8, size_bytes: u64, rs_n: u8) -> UnitRecord {
    UnitRecord {
        unit_id: test_unit_id(seed),
        unit_type: UnitType::Pack,
        status: UnitStatus::Active,
        member_file_ids: vec![FileId(1)],
        chunk_index: None,
        parent_file_id: None,
        size_bytes,
        plaintext_hash: [0u8; 32],
        created_at: Timestamp(0),
        importance_avg: 0.5,
        rs_k: 5,
        rs_n,
    }
}

fn make_shard_record(
    shard_seed: u8,
    unit_seed: u8,
    holder_seed: u8,
    status: ShardStatus,
) -> ShardRecord {
    ShardRecord {
        shard_id: test_shard_id(shard_seed),
        unit_id: test_unit_id(unit_seed),
        shard_index: 0,
        holder_id: test_peer(holder_seed),
        status,
        last_verified: None,
        offered_at: Timestamp(0),
        stored_at: None,
        merkle_root: [0u8; 32],
    }
}

// ---- test 1 ----

#[test]
fn overhead_factor_returns_correct_multiplier() {
    // High tier: >= 0.8
    assert!((BudgetPlanner::overhead_factor(1.0) - 3.0).abs() < 1e-10);
    assert!((BudgetPlanner::overhead_factor(0.8) - 3.0).abs() < 1e-10);
    // Medium tier: >= 0.4
    assert!((BudgetPlanner::overhead_factor(0.5) - 2.0).abs() < 1e-10);
    assert!((BudgetPlanner::overhead_factor(0.4) - 2.0).abs() < 1e-10);
    // Low tier: >= 0.1
    assert!((BudgetPlanner::overhead_factor(0.2) - 1.4).abs() < 1e-10);
    assert!((BudgetPlanner::overhead_factor(0.1) - 1.4).abs() < 1e-10);
    // Below threshold: not backed up
    assert!((BudgetPlanner::overhead_factor(0.09) - 0.0).abs() < 1e-10);
    assert!((BudgetPlanner::overhead_factor(0.0) - 0.0).abs() < 1e-10);
}

// ---- test 2 ----

#[test]
fn select_backup_batch_sorts_by_importance_descending() {
    let (planner, db, _tmp) = make_planner_with_db();

    // Insert 5 dirty files with varying importance.
    let data = [
        ("file_a", 1u64, 1024u64, 0.3f64),
        ("file_b", 2, 1024, 0.9),
        ("file_c", 3, 1024, 0.1),
        ("file_d", 4, 1024, 0.7),
        ("file_e", 5, 1024, 0.5),
    ];
    for (path, id, size, imp) in data {
        db.upsert_file(&make_file_record(path, id, size, imp, true)).unwrap();
    }

    let batch = planner.select_backup_batch(100.0).unwrap();

    assert_eq!(batch.candidates.len(), 5);
    let importances: Vec<f64> = batch.candidates.iter().map(|c| c.importance).collect();
    assert!(
        importances[0] > importances[1]
            && importances[1] > importances[2]
            && importances[2] > importances[3]
            && importances[3] > importances[4],
        "Expected descending order, got: {:?}",
        importances
    );
    // Check order is [0.9, 0.7, 0.5, 0.3, 0.1]
    assert!((importances[0] - 0.9).abs() < 1e-10);
    assert!((importances[1] - 0.7).abs() < 1e-10);
    assert!((importances[2] - 0.5).abs() < 1e-10);
    assert!((importances[3] - 0.3).abs() < 1e-10);
    assert!((importances[4] - 0.1).abs() < 1e-10);
    assert_eq!(batch.deferred_count, 0);
}

// ---- test 3 ----

#[test]
fn select_backup_batch_cutoff_at_budget() {
    let (planner, db, _tmp) = make_planner_with_db();

    // file_A: 10 GB, importance 0.8, required_gb = 10*3 = 30
    // file_B: 5 GB,  importance 0.5, required_gb = 5*2 = 10
    // file_C: 20 GB, importance 0.1, required_gb = 20*1.4 = 28
    let gb = 1_073_741_824u64;
    db.upsert_file(&make_file_record("file_a", 1, 10 * gb, 0.8, true)).unwrap();
    db.upsert_file(&make_file_record("file_b", 2, 5 * gb, 0.5, true)).unwrap();
    db.upsert_file(&make_file_record("file_c", 3, 20 * gb, 0.1, true)).unwrap();

    let batch = planner.select_backup_batch(40.0).unwrap();

    // A (30) + B (10) = 40 fits; C (28) would push to 68 > 40, deferred.
    assert_eq!(batch.candidates.len(), 2, "candidates: {:?}", batch.candidates.iter().map(|c| &c.path).collect::<Vec<_>>());
    assert!((batch.total_required_gb - 40.0).abs() < 1e-6);
    assert_eq!(batch.deferred_count, 1);
    assert!((batch.candidates[0].importance - 0.8).abs() < 1e-10);
    assert!((batch.candidates[1].importance - 0.5).abs() < 1e-10);
}

// ---- test 4 ----

#[test]
fn select_backup_batch_skips_low_importance_silently() {
    let (planner, db, _tmp) = make_planner_with_db();

    db.upsert_file(&make_file_record("file_a", 1, 1024, 0.09, true)).unwrap();
    db.upsert_file(&make_file_record("file_b", 2, 1024, 0.05, true)).unwrap();

    let batch = planner.select_backup_batch(100.0).unwrap();

    assert!(batch.candidates.is_empty());
    assert_eq!(batch.deferred_count, 0);
}

// ---- test 5 ----

#[test]
fn estimate_budget_uses_committed_plus_headroom() {
    let (planner, db, _tmp) = make_planner_with_db();

    // 3 active shards, each from a unit of 10 GB with rs_n=1 (so each shard = 10 GB).
    let unit_size = 10u64 * 1_073_741_824;
    for i in 0..3u8 {
        let unit = make_unit_record(i, unit_size, 1);
        db.upsert_unit(&unit).unwrap();
        let mut shard = make_shard_record(i, i, i + 10, ShardStatus::Stored);
        shard.unit_id = test_unit_id(i);
        db.upsert_shard(&shard).unwrap();
    }

    // Set budget record with known success rate.
    let budget_record = BudgetRecord {
        estimated_gb: 0.0,
        last_calculated: Timestamp(0),
        placement_success_rate: 0.8,
        weekly_stats: vec![(10, 8)], // non-empty, success_rate = 0.8
    };
    db.set_budget(&budget_record).unwrap();

    let estimate = planner.estimate_budget().unwrap();

    // committed = 30 GB (3 shards × 10 GB each)
    assert!((estimate.committed_gb - 30.0).abs() < 1e-6, "committed_gb={}", estimate.committed_gb);
    // headroom = 30 * 0.8 * 0.5 = 12
    assert!((estimate.headroom_gb - 12.0).abs() < 1e-6, "headroom_gb={}", estimate.headroom_gb);
    assert!((estimate.total_gb - 42.0).abs() < 1e-6, "total_gb={}", estimate.total_gb);
}

// ---- test 6 ----

#[test]
fn estimate_budget_default_rate_on_first_run() {
    let (planner, _tmp) = make_planner();

    // Empty DB: no shards, no budget record.
    let estimate = planner.estimate_budget().unwrap();

    // committed = 0, success_rate = DEFAULT (0.5)
    assert!((estimate.committed_gb - 0.0).abs() < 1e-10);
    assert!((estimate.placement_success_rate - 0.5).abs() < 1e-10);
    assert!((estimate.total_gb - 0.0).abs() < 1e-10);
}

// ---- test 7 ----

#[test]
fn disk_pressure_normal_when_15_percent_free() {
    let (planner, _tmp) = make_planner();

    // quota=100, used=85 → free_ratio = 0.15 → Normal.
    let result = planner.evaluate_pressure(100.0, 85.0, 0).unwrap();
    assert_eq!(result.pressure, DiskPressure::Normal);
    assert!(result.immediate_evictions.is_empty());
    assert!(result.drop_notices.is_empty());
    assert!((result.freed_gb - 0.0).abs() < 1e-10);
}

// ---- test 8 ----

#[test]
fn disk_pressure_soft_when_between_5_and_15_percent_free() {
    let (planner, _tmp) = make_planner();

    // quota=100, used=90 → free_ratio = 0.10 → Soft.
    let result = planner.evaluate_pressure(100.0, 90.0, 0).unwrap();
    assert_eq!(result.pressure, DiskPressure::Soft);
    assert!(result.immediate_evictions.is_empty());
    assert!(result.drop_notices.is_empty());
}

// ---- test 9 ----

#[test]
fn disk_pressure_hard_triggers_phase1_evictions() {
    let (planner, db, _tmp) = make_planner_with_db();

    // 5 shards, each 2 GB, with known priorities.
    // Importance is the main driver (trust_of_owner = UNKNOWN_OWNER_TRUST_FLOOR = 0.1
    // since owners are not in peers table; age_bonus = 0 since received_at = now).
    // priority = importance * 0.1 * 1.0
    // priorities: [0.1*0.1, 0.2*0.1, 0.3*0.1, 0.4*0.1, 0.9*0.1] = [0.01, 0.02, 0.03, 0.04, 0.09]
    // Sorted ascending: shards at importance 0.1, 0.2, 0.3, 0.4, 0.9.
    let two_gb = 2u64 * 1_073_741_824;
    let importances = [0.1f64, 0.2, 0.3, 0.4, 0.9];
    let now_secs = 1_000_000u64;

    for (i, &imp) in importances.iter().enumerate() {
        let mut record = make_holding_record(i as u8, i as u8, imp, two_gb, FileType::User, Timestamp(now_secs));
        record.received_at = Timestamp(now_secs); // just received, age_bonus=0
        db.upsert_holding(&record).unwrap();
    }

    // quota=100 GB, used=96 GB → free=4 GB → free_ratio=0.04 < 0.05 → Hard.
    // deficit = 0.15*100 - 4 = 11 GB. Need to free 11 GB.
    // Each shard is 2 GB. Evict 4 shards to free 8 GB (4+8=12 >= 15).
    // Actually: deficit = target_free - free_gb = 15 - 4 = 11.
    // After 4 evictions: freed = 8 GB. Check: free + freed = 4+8 = 12 >= 15. Stop after 4.
    let result = planner.evaluate_pressure(100.0, 96.0, now_secs).unwrap();

    assert_eq!(result.pressure, DiskPressure::Hard);
    assert_eq!(
        result.immediate_evictions.len(),
        4,
        "expected 4 immediate evictions, got {}",
        result.immediate_evictions.len()
    );
    assert!((result.freed_gb - 8.0).abs() < 1e-6, "freed_gb={}", result.freed_gb);

    // Verify priorities are ascending (lowest first).
    let priorities: Vec<f64> = result.immediate_evictions.iter().map(|e| e.priority).collect();
    for w in priorities.windows(2) {
        assert!(
            w[0] <= w[1],
            "priorities not ascending: {:?}",
            priorities
        );
    }
}

// ---- test 10 ----

#[test]
fn disk_pressure_hard_phase2_drop_notices() {
    let (planner, db, _tmp) = make_planner_with_db();

    let two_gb = 2u64 * 1_073_741_824;
    let importances = [0.1f64, 0.2, 0.3, 0.4, 0.9];
    let now_secs = 1_000_000u64;

    for (i, &imp) in importances.iter().enumerate() {
        let mut record = make_holding_record(i as u8, i as u8, imp, two_gb, FileType::User, Timestamp(now_secs));
        record.received_at = Timestamp(now_secs);
        db.upsert_holding(&record).unwrap();
    }

    let result = planner.evaluate_pressure(100.0, 96.0, now_secs).unwrap();

    // Phase 1: 4 shards evicted (same as test 9).
    assert_eq!(result.immediate_evictions.len(), 4);

    // Phase 2: buffer_gb = 5% * 100 = 5 GB. Remaining 1 shard (2 GB). That 1 shard covers 5 GB need? No.
    // 2 GB < 5 GB, but we only have 1 shard left. So we add it to drop_notices.
    assert_eq!(
        result.drop_notices.len(),
        1,
        "expected 1 drop notice, got {}",
        result.drop_notices.len()
    );

    // Deadline = now + 7 days.
    let expected_deadline = now_secs + DROP_NOTICE_WINDOW_SECS;
    assert_eq!(result.drop_notices[0].deadline, expected_deadline);

    // freed_gb reflects Phase 1 only.
    assert!((result.freed_gb - 8.0).abs() < 1e-6);
}

// ---- test 11 ----

#[test]
fn eviction_priority_increases_with_age() {
    let (planner, db, _tmp) = make_planner_with_db();

    let shard_id = test_shard_id(1);
    let owner = test_peer(1);
    let now_secs = 26u64 * SECS_PER_WEEK + 1_000_000;
    let received_at = Timestamp(now_secs - 26 * SECS_PER_WEEK);

    // Set up peer with known trust.
    db.upsert_peer(&crate::types::PeerRecord {
        identity: owner,
        node_id: None,
        trust_p: 0.6,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_sent_to_peer: 0,
        bytes_received_from_peer: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        weeks_in_network: 0,
        subnet_prefix: None,
        allowlisted: false,
    }).unwrap();

    // Fake combined score: trust.score() returns combined from PeerRecord.
    // combined = (KP*P + KI*I) * clamp(S, 0.1, 1.0) = (0.4*0.6 + 1.75*0.0) * 1.0 = 0.24
    // We want trust_of_owner = 0.6 for the test.
    // Let's set up P and I such that combined = 0.6.
    // (0.4*P + 1.75*I) * 1.0 = 0.6. Simplest: P=0, I=0.6/1.75 ≈ 0.343. But let's just
    // set trust values directly to get a simple combined = 0.6.
    // Try: P=1.0, I=0.0 → combined = 0.4 * 1.0 * 1.0 = 0.4. Not 0.6.
    // Try: P=0.0, I=0.343 → combined = 1.75 * 0.343 * 1.0 ≈ 0.6.
    // Actually, the spec says trust_of_owner = score.combined clamped to [0.0, 1.0].
    // For simplicity, use direct values.
    // Let's just use importance=0.5, trust computed from peer record.
    // We'll verify the formula instead of exact value.

    // Reinsert with values that give combined ≈ 0.6.
    // (KP*P + KI*I) * clamp(S) = 0.6
    // With KP=0.4, KI=1.75: easiest to hit 0.6 with I=0, P=1.5 (not valid, P capped).
    // Instead: set I=0.6/1.75 ≈ 0.3429, P=0, S=1.0.
    let i_val = 0.6f64 / 1.75f64;
    db.upsert_peer(&crate::types::PeerRecord {
        identity: owner,
        node_id: None,
        trust_p: 0.0,
        trust_i: i_val,
        trust_s: 1.0,
        bytes_sent_to_peer: 0,
        bytes_received_from_peer: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        weeks_in_network: 0,
        subnet_prefix: None,
        allowlisted: false,
    }).unwrap();

    let record = make_holding_record(1, 1, 0.5, 1024, FileType::User, received_at);
    db.upsert_holding(&record).unwrap();

    let priority = planner.eviction_priority(shard_id, now_secs).unwrap();

    // age_bonus = min(26/26, 0.3) = 0.3
    // trust_of_owner ≈ 0.6 (combined from peer record)
    // priority = 0.5 * 0.6 * 1.3 = 0.39
    let expected = 0.5 * 0.6 * 1.3;
    assert!(
        (priority - expected).abs() < 1e-6,
        "priority={:.6} expected={:.6}",
        priority,
        expected
    );
}

// ---- test 12 ----

#[test]
fn eviction_priority_age_bonus_capped_at_0_3() {
    let (planner, db, _tmp) = make_planner_with_db();

    let shard_id = test_shard_id(2);
    let owner = test_peer(2);
    let now_secs = 200u64 * SECS_PER_WEEK + 1_000_000;
    let received_at = Timestamp(now_secs - 100 * SECS_PER_WEEK); // 100 weeks ago

    // Set owner with trust combined = 1.0.
    // (KP * P + KI * I) * S = 1.0 with P=0, I=1.0/1.75, S=1.0.
    let i_val = 1.0f64 / 1.75f64;
    db.upsert_peer(&crate::types::PeerRecord {
        identity: owner,
        node_id: None,
        trust_p: 0.0,
        trust_i: i_val,
        trust_s: 1.0,
        bytes_sent_to_peer: 0,
        bytes_received_from_peer: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        weeks_in_network: 0,
        subnet_prefix: None,
        allowlisted: false,
    }).unwrap();

    let record = make_holding_record(2, 2, 1.0, 1024, FileType::User, received_at);
    db.upsert_holding(&record).unwrap();

    let priority = planner.eviction_priority(shard_id, now_secs).unwrap();

    // age_bonus = min(100/26, 0.3) = 0.3
    // trust_of_owner = 1.0
    // priority = 1.0 * 1.0 * 1.3 = 1.3
    let expected = 1.0f64 * 1.0 * 1.3;
    assert!(
        (priority - expected).abs() < 1e-6,
        "priority={:.6} expected={:.6}",
        priority,
        expected
    );
}

// ---- test 13 ----

#[test]
fn system_state_shards_never_evicted() {
    let (planner, db, _tmp) = make_planner_with_db();

    let five_gb = 5u64 * 1_073_741_824;
    let now_secs = 1_000_000u64;

    // System shard: should not appear in immediate_evictions.
    let sys_record = make_holding_record(0, 0, 0.5, five_gb, FileType::System, Timestamp(now_secs));
    db.upsert_holding(&sys_record).unwrap();

    // User shard: low importance, should be evicted.
    let user_record = make_holding_record(1, 1, 0.1, five_gb, FileType::User, Timestamp(now_secs));
    db.upsert_holding(&user_record).unwrap();

    // quota=100, used=99 → very high pressure.
    let result = planner.evaluate_pressure(100.0, 99.0, now_secs).unwrap();

    assert_eq!(result.pressure, DiskPressure::Hard);

    // System shard must NOT be in immediate evictions.
    let evicted_ids: Vec<ShardId> = result.immediate_evictions.iter().map(|e| e.shard_id).collect();
    let system_shard_id = test_shard_id(0);
    assert!(
        !evicted_ids.contains(&system_shard_id),
        "system shard should not be evicted"
    );

    // User shard should be in immediate evictions.
    let user_shard_id = test_shard_id(1);
    assert!(
        evicted_ids.contains(&user_shard_id),
        "user shard should be evicted"
    );
}

// ---- test 14 ----

#[test]
fn record_placement_outcome_rolling_window() {
    let (planner, db, _tmp) = make_planner_with_db();

    // Record 5 weeks: each offered=10, accepted=8.
    for _ in 0..5 {
        planner.record_placement_outcome(10, 8).unwrap();
    }

    let budget = db.get_budget().unwrap().expect("budget should be set");

    // Window = 4; oldest entry (first call) should be dropped.
    assert_eq!(
        budget.weekly_stats.len(),
        4,
        "weekly_stats should have 4 entries, got {}",
        budget.weekly_stats.len()
    );

    // All remaining entries are (10, 8).
    for (offered, accepted) in &budget.weekly_stats {
        assert_eq!(*offered, 10);
        assert_eq!(*accepted, 8);
    }

    // success_rate = 32/40 = 0.8.
    let total_offered: u32 = budget.weekly_stats.iter().map(|(o, _)| o).sum();
    let total_accepted: u32 = budget.weekly_stats.iter().map(|(_, a)| a).sum();
    let rate = total_accepted as f64 / total_offered as f64;
    assert!((rate - 0.8).abs() < 1e-10, "rate={}", rate);
    assert!((budget.placement_success_rate - 0.8).abs() < 1e-10);
}

// ---- test 15 ----

#[test]
fn should_reject_offers_true_when_soft_or_hard() {
    let (planner, _tmp) = make_planner();

    // Soft pressure: free_ratio = 0.14 < 0.15 → reject.
    assert!(
        planner.should_reject_offers(100.0, 86.0),
        "should reject when 14% free"
    );

    // Normal: free_ratio = 0.20 >= 0.15 → accept.
    assert!(
        !planner.should_reject_offers(100.0, 80.0),
        "should NOT reject when 20% free"
    );

    // Hard pressure: free_ratio = 0.02 < 0.05 → reject.
    assert!(
        planner.should_reject_offers(100.0, 98.0),
        "should reject under hard pressure"
    );

    // Exactly at boundary: free_ratio = 0.15 → accept (>= 0.15).
    assert!(
        !planner.should_reject_offers(100.0, 85.0),
        "should NOT reject at exactly 15% free"
    );
}
