use super::*;
use crate::constants::{DEFAULT_SUCCESS_RATE, SECS_PER_WEEK, UNKNOWN_OWNER_TRUST_FLOOR, WEEKLY_STATS_WINDOW};
use crate::types::{BudgetRecord, HoldingRecord, HoldingStatus, IdentityPub, SourceBlockId, Timestamp};

fn gib(n: u64) -> u64 {
    n * 1024 * 1024 * 1024
}

fn mib(n: u64) -> u64 {
    n * 1024 * 1024
}

fn make_holding(
    block_id: [u8; 32],
    owner_id: [u8; 32],
    importance: f64,
    total_bytes: u64,
    status: HoldingStatus,
    received_at: Timestamp,
) -> HoldingRecord {
    HoldingRecord {
        source_block_id: SourceBlockId(block_id),
        owner_id: IdentityPub(owner_id),
        esi_ranges: vec![],
        importance,
        total_bytes,
        status,
        received_at,
        delete_requested_at: None,
        drop_notice_sent_at: None,
    }
}

// ============================================================
// overhead_factor
// ============================================================

#[test]
fn overhead_factor_at_zero_importance() {
    let result = overhead_factor(0.0);
    assert!((result - 1.5).abs() < 1e-9, "expected 1.5, got {result}");
}

#[test]
fn overhead_factor_at_full_importance() {
    let result = overhead_factor(1.0);
    assert!((result - 3.0).abs() < 1e-9, "expected 3.0, got {result}");
}

#[test]
fn overhead_factor_midpoint() {
    let result = overhead_factor(0.5);
    assert!((result - 2.25).abs() < 1e-9, "expected 2.25, got {result}");
}

// ============================================================
// estimate_budget
// ============================================================

#[test]
fn estimate_budget_no_history() {
    let committed_bytes = gib(10);
    let estimate = estimate_budget(committed_bytes, None);

    assert!((estimate.placement_success_rate - DEFAULT_SUCCESS_RATE).abs() < 1e-9);
    // headroom = 10 * 0.5 * 0.5 = 2.5 GiB
    let committed_gb = gib(10) as f64 / 1_073_741_824.0;
    let expected_headroom = committed_gb * DEFAULT_SUCCESS_RATE * 0.5;
    let expected_total = committed_gb + expected_headroom;
    assert!(
        (estimate.committed_gb - committed_gb).abs() < 1e-6,
        "committed_gb mismatch"
    );
    assert!(
        (estimate.headroom_gb - expected_headroom).abs() < 1e-6,
        "headroom_gb mismatch: expected {expected_headroom}, got {}",
        estimate.headroom_gb
    );
    assert!(
        (estimate.total_gb - expected_total).abs() < 1e-6,
        "total_gb mismatch: expected {expected_total}, got {}",
        estimate.total_gb
    );
}

#[test]
fn estimate_budget_with_stats() {
    let committed_bytes = gib(10);
    let record = BudgetRecord {
        estimated_gb: 0.0,
        last_calculated: Timestamp(0),
        placement_success_rate: 0.0,
        weekly_stats: vec![(10, 8), (10, 6)],
    };
    let estimate = estimate_budget(committed_bytes, Some(&record));

    // rate = (8+6)/(10+10) = 14/20 = 0.7
    let expected_rate = 14.0 / 20.0;
    assert!(
        (estimate.placement_success_rate - expected_rate).abs() < 1e-9,
        "rate mismatch"
    );
    let committed_gb = gib(10) as f64 / 1_073_741_824.0;
    // headroom = 10 * 0.7 * 0.5 = 3.5 GiB
    let expected_headroom = committed_gb * expected_rate * 0.5;
    let expected_total = committed_gb + expected_headroom;
    assert!(
        (estimate.total_gb - expected_total).abs() < 1e-6,
        "total_gb mismatch: expected {expected_total}, got {}",
        estimate.total_gb
    );
}

// ============================================================
// select_backup_batch
// ============================================================

#[test]
fn select_backup_batch_fits_all() {
    let candidates = vec![
        ("a.jpg".to_string(), 0.6, mib(50)),
        ("b.doc".to_string(), 0.9, mib(10)),
    ];
    let batch = select_backup_batch(&candidates, 100.0);

    assert_eq!(batch.deferred_count, 0);
    assert_eq!(batch.candidates.len(), 2);
    // sorted by importance DESC: b.doc first, a.jpg second
    assert_eq!(batch.candidates[0].path, "b.doc");
    assert_eq!(batch.candidates[1].path, "a.jpg");
}

#[test]
fn select_backup_batch_defers_overflow() {
    // budget = 40 MiB = 0.04 GiB (approximately)
    let budget_gb = mib(40) as f64 / 1_073_741_824.0;
    let candidates = vec![
        ("big.jpg".to_string(), 0.6, mib(50)),
        ("small.doc".to_string(), 0.9, mib(1)),
    ];
    let batch = select_backup_batch(&candidates, budget_gb);

    assert_eq!(batch.deferred_count, 1, "big.jpg should be deferred");
    assert_eq!(batch.candidates.len(), 1);
    assert_eq!(batch.candidates[0].path, "small.doc");
}

#[test]
fn select_backup_batch_importance_zero_excluded() {
    let candidates = vec![("zero.jpg".to_string(), 0.0, mib(100))];
    let batch = select_backup_batch(&candidates, 1000.0);

    assert_eq!(batch.candidates.len(), 0);
    assert_eq!(batch.deferred_count, 0, "importance=0.0 must not be deferred");
}

// ============================================================
// record_placement_outcome
// ============================================================

#[test]
fn record_placement_outcome_rolling_window() {
    let mut record: Option<BudgetRecord> = None;
    for i in 0..5u32 {
        record = Some(record_placement_outcome(record, 10, i));
    }
    let r = record.unwrap();
    assert_eq!(
        r.weekly_stats.len(),
        WEEKLY_STATS_WINDOW as usize,
        "should have exactly WEEKLY_STATS_WINDOW entries after 5 calls"
    );
    // The oldest entry (offered=10, accepted=0) should have been dropped.
    // Remaining: calls 1,2,3,4 → accepted = 1,2,3,4.
    assert_eq!(r.weekly_stats[0].1, 1, "oldest remaining should be accepted=1");
}

// ============================================================
// eviction_priority
// ============================================================

#[test]
fn eviction_priority_new_data() {
    let now_secs = 1_000_000u64;
    let received_at = Timestamp(now_secs);
    let priority = eviction_priority(0.8, 0.9, received_at, now_secs);
    // age_bonus = 0.0, priority = 0.8 * 0.9 * 1.0 = 0.72
    assert!((priority - 0.72).abs() < 1e-9, "priority={priority}");
}

#[test]
fn eviction_priority_old_data_max_bonus() {
    let now_secs = 26 * SECS_PER_WEEK;
    let received_at = Timestamp(0);
    let priority = eviction_priority(0.8, 0.9, received_at, now_secs);
    // age_bonus = min(26/26, 0.3) = 0.3
    // priority = 0.8 * 0.9 * 1.3 = 0.936
    assert!((priority - 0.936).abs() < 1e-9, "priority={priority}");
}

#[test]
fn eviction_priority_old_data_capped_bonus() {
    let now_secs = 52 * SECS_PER_WEEK;
    let received_at = Timestamp(0);
    let priority = eviction_priority(0.8, 0.9, received_at, now_secs);
    // age_bonus = min(52/26, 0.3) = min(2.0, 0.3) = 0.3 (capped)
    // priority = 0.8 * 0.9 * 1.3 = 0.936 — same as 26 weeks
    assert!((priority - 0.936).abs() < 1e-9, "priority={priority}");
}

#[test]
fn eviction_priority_unknown_owner_uses_floor() {
    let now_secs = 1_000_000u64;
    let received_at = Timestamp(now_secs);
    // Caller passes UNKNOWN_OWNER_TRUST_FLOOR explicitly for unknown peers
    let priority = eviction_priority(0.8, UNKNOWN_OWNER_TRUST_FLOOR, received_at, now_secs);
    // priority = 0.8 * 0.1 * 1.0 = 0.08
    assert!((priority - 0.08).abs() < 1e-9, "priority={priority}");
}

// ============================================================
// evaluate_pressure
// ============================================================

fn unknown_trust(_: &IdentityPub) -> f64 {
    UNKNOWN_OWNER_TRUST_FLOOR
}

#[test]
fn evaluate_pressure_normal() {
    // quota=100 GiB, used=80 GiB → free_ratio=0.20 → Normal
    let result = evaluate_pressure(gib(100), 0, gib(80), &[], unknown_trust, 0);
    assert_eq!(result.pressure, DiskPressure::Normal);
    assert!(result.immediate_evictions.is_empty());
    assert!(result.drop_notices.is_empty());
    assert_eq!(result.freed_bytes, 0);
}

#[test]
fn evaluate_pressure_soft() {
    // quota=100 GiB, used=88 GiB → free_ratio=0.12 → Soft
    let result = evaluate_pressure(gib(100), 0, gib(88), &[], unknown_trust, 0);
    assert_eq!(result.pressure, DiskPressure::Soft);
    assert!(result.immediate_evictions.is_empty());
    assert!(result.drop_notices.is_empty());
}

#[test]
fn evaluate_pressure_hard_evicts_lowest_priority() {
    // quota=100 GiB, used=97 GiB → free_ratio=0.03 → Hard
    // deficit = 0.15*100 - 3 = 12 GiB
    let now_secs = 0u64;
    let holdings = vec![
        // A: importance=0.1, trust=0.5 → priority=0.05, 5 GiB
        make_holding(
            [0u8; 32],
            [1u8; 32],
            0.1,
            gib(5),
            HoldingStatus::Active,
            Timestamp(now_secs),
        ),
        // B: importance=0.9, trust=0.9 → priority=0.81, 5 GiB
        make_holding(
            [1u8; 32],
            [2u8; 32],
            0.9,
            gib(5),
            HoldingStatus::Active,
            Timestamp(now_secs),
        ),
        // C: importance=0.5, trust=0.5 → priority=0.25, 5 GiB
        make_holding(
            [2u8; 32],
            [3u8; 32],
            0.5,
            gib(5),
            HoldingStatus::Active,
            Timestamp(now_secs),
        ),
    ];

    let trust_fn = |id: &IdentityPub| -> f64 {
        if id.0 == [1u8; 32] {
            0.5 // owner of A
        } else if id.0 == [2u8; 32] {
            0.9 // owner of B
        } else {
            0.5 // owner of C
        }
    };

    let result = evaluate_pressure(gib(100), 0, gib(97), &holdings, trust_fn, now_secs);
    assert_eq!(result.pressure, DiskPressure::Hard);

    // Evict order: A (priority=0.05), C (priority=0.25), B (priority=0.81)
    // deficit=12 GiB: A(5)+C(5)=10 < 12, so also B(5) → freed=15 >= 12
    assert_eq!(
        result.immediate_evictions.len(),
        3,
        "all three must be evicted to cover 12 GiB deficit"
    );

    // Verify eviction order: A first, C second, B last
    assert_eq!(result.immediate_evictions[0].source_block_id, SourceBlockId([0u8; 32]));
    assert_eq!(result.immediate_evictions[1].source_block_id, SourceBlockId([2u8; 32]));
    assert_eq!(result.immediate_evictions[2].source_block_id, SourceBlockId([1u8; 32]));
}

// ============================================================
// should_reject_offers
// ============================================================

#[test]
fn should_reject_offers_above_soft() {
    // quota=100 GiB, used=86 GiB → free_ratio=0.14 < 0.15 → true
    assert!(should_reject_offers(gib(100), gib(86)));
}

#[test]
fn should_reject_offers_unlimited_quota() {
    // quota=0 → unlimited → false
    assert!(!should_reject_offers(0, gib(999)));
}

// ============================================================
// compute_effective_quota
// ============================================================

#[test]
fn compute_effective_quota_no_soft_cap() {
    // soft_quota=0 (unlimited), disk_free=100 GiB, reserve=20 GiB → 80 GiB
    let result = compute_effective_quota(0, gib(100), gib(20));
    assert_eq!(result, gib(80));
}

#[test]
fn compute_effective_quota_soft_cap_is_tighter() {
    // soft_quota=50 GiB, disk_free=200 GiB, reserve=20 GiB
    // available_from_disk=180 GiB, effective=min(50,180)=50 GiB
    let result = compute_effective_quota(gib(50), gib(200), gib(20));
    assert_eq!(result, gib(50));
}

#[test]
fn compute_effective_quota_disk_free_is_tighter() {
    // soft_quota=100 GiB, disk_free=30 GiB, reserve=20 GiB
    // available_from_disk=10 GiB, effective=min(100,10)=10 GiB
    let result = compute_effective_quota(gib(100), gib(30), gib(20));
    assert_eq!(result, gib(10));
}

#[test]
fn compute_effective_quota_disk_critically_full() {
    // soft_quota=0, disk_free=10 GiB, reserve=20 GiB → saturating_sub → 0
    let result = compute_effective_quota(0, gib(10), gib(20));
    assert_eq!(result, 0);
}

#[test]
fn compute_effective_quota_soft_cap_zero_and_disk_large() {
    // soft_quota=0, disk_free=1000 GiB, reserve=20 GiB → 980 GiB
    let result = compute_effective_quota(0, gib(1000), gib(20));
    assert_eq!(result, gib(980));
}

#[test]
fn compute_effective_quota_exact_reserve_boundary() {
    // soft_quota=0, disk_free=20 GiB, reserve=20 GiB → 20-20=0
    let result = compute_effective_quota(0, gib(20), gib(20));
    assert_eq!(result, 0);
}

// ============================================================
// evaluate_pressure with hard_quota
// ============================================================

#[test]
fn evaluate_pressure_hard_quota_prevents_eviction() {
    // quota=100 GiB, hard_quota=100 GiB (floor=entire quota → nothing can be evicted)
    // used=97 GiB → free_ratio=0.03 → Hard
    // Evicting A (5 GiB) would leave 92 GiB < 100 GiB floor → skip
    let now_secs = 0u64;
    let holdings = vec![make_holding(
        [0u8; 32],
        [1u8; 32],
        0.1,
        gib(5),
        HoldingStatus::Active,
        Timestamp(now_secs),
    )];
    let trust_fn = |_: &IdentityPub| -> f64 { 0.5 };
    let result = evaluate_pressure(gib(100), gib(100), gib(97), &holdings, trust_fn, now_secs);
    assert_eq!(result.pressure, DiskPressure::Hard);
    assert!(
        result.immediate_evictions.is_empty(),
        "hard_quota floor must block eviction"
    );
    assert_eq!(result.freed_bytes, 0);
}

#[test]
fn evaluate_pressure_hard_quota_partial_eviction() {
    // quota=100 GiB, hard_quota=90 GiB (can free down to 90 GiB usage)
    // used=97 GiB → Hard, deficit=12 GiB
    // A: importance=0.1, trust=0.5 → priority=0.05, 5 GiB
    // B: importance=0.9, trust=0.9 → priority=0.81, 5 GiB
    // Evict A: projected_used=92 >= 90 → allowed. freed=5 GiB.
    // Evict B: projected_used=87 < 90 → SKIP.
    let now_secs = 0u64;
    let holdings = vec![
        make_holding(
            [0u8; 32],
            [1u8; 32],
            0.1,
            gib(5),
            HoldingStatus::Active,
            Timestamp(now_secs),
        ),
        make_holding(
            [1u8; 32],
            [2u8; 32],
            0.9,
            gib(5),
            HoldingStatus::Active,
            Timestamp(now_secs),
        ),
    ];
    let trust_fn = |id: &IdentityPub| -> f64 {
        if id.0 == [1u8; 32] { 0.5 } else { 0.9 }
    };
    let result = evaluate_pressure(gib(100), gib(90), gib(97), &holdings, trust_fn, now_secs);
    assert_eq!(result.pressure, DiskPressure::Hard);
    assert_eq!(
        result.immediate_evictions.len(),
        1,
        "only A should be evicted"
    );
    assert_eq!(
        result.immediate_evictions[0].source_block_id,
        SourceBlockId([0u8; 32])
    );
    assert_eq!(result.freed_bytes, gib(5));
}

#[test]
fn evaluate_pressure_hard_quota_zero_disables_floor() {
    // hard_quota=0 → no floor, same as before
    // quota=100 GiB, used=97 GiB → Hard, deficit=12 GiB
    // A+C+B = 15 GiB freed (all three evicted)
    let now_secs = 0u64;
    let holdings = vec![
        make_holding(
            [0u8; 32],
            [1u8; 32],
            0.1,
            gib(5),
            HoldingStatus::Active,
            Timestamp(now_secs),
        ),
        make_holding(
            [1u8; 32],
            [2u8; 32],
            0.9,
            gib(5),
            HoldingStatus::Active,
            Timestamp(now_secs),
        ),
        make_holding(
            [2u8; 32],
            [3u8; 32],
            0.5,
            gib(5),
            HoldingStatus::Active,
            Timestamp(now_secs),
        ),
    ];
    let trust_fn = |id: &IdentityPub| -> f64 {
        if id.0 == [1u8; 32] { 0.5 }
        else if id.0 == [2u8; 32] { 0.9 }
        else { 0.5 }
    };
    let result = evaluate_pressure(gib(100), 0, gib(97), &holdings, trust_fn, now_secs);
    assert_eq!(result.pressure, DiskPressure::Hard);
    assert_eq!(
        result.immediate_evictions.len(),
        3,
        "all three evicted when no floor"
    );
    assert_eq!(result.freed_bytes, gib(15));
}

#[test]
fn should_reject_offers_with_effective_quota() {
    // soft_quota=80 GiB, disk_free=50 GiB, reserve=20 GiB
    // effective = min(80, 30) = 30 GiB
    // used=26 GiB, free_ratio=(30-26)/30 ≈ 0.133 < 0.15 → true
    let effective = compute_effective_quota(gib(80), gib(50), gib(20));
    assert_eq!(effective, gib(30));
    assert!(should_reject_offers(effective, gib(26)));
}
