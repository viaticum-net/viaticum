use super::*;
use crate::constants::{
    DEFAULT_SUCCESS_RATE, SECS_PER_WEEK, UNKNOWN_OWNER_TRUST_FLOOR, WEEKLY_STATS_WINDOW,
};
use crate::types::{
    BudgetRecord, HoldingRecord, HoldingStatus, IdentityPub, SourceBlockId, Timestamp,
};

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
    let estimate = estimate_budget(committed_bytes, None, 0.0);

    assert!((estimate.placement_success_rate - DEFAULT_SUCCESS_RATE).abs() < 1e-9);
    let committed_gb = gib(10) as f64 / 1_073_741_824.0;
    // headroom = 10 * 0.5 * 1.0 = 5.0 GiB
    let expected_headroom = committed_gb * DEFAULT_SUCCESS_RATE * 1.0;
    let expected_total = (committed_gb + expected_headroom).max(1.0);
    let expected_offer = expected_total / DEFAULT_SUCCESS_RATE.max(0.2);
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
    assert!(
        (estimate.offer_budget_gb - expected_offer).abs() < 1e-6,
        "offer_budget_gb mismatch: expected {expected_offer}, got {}",
        estimate.offer_budget_gb
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
    let estimate = estimate_budget(committed_bytes, Some(&record), 0.0);

    // rate = (8+6)/(10+10) = 14/20 = 0.7
    let expected_rate = 14.0 / 20.0;
    assert!(
        (estimate.placement_success_rate - expected_rate).abs() < 1e-9,
        "rate mismatch"
    );
    let committed_gb = gib(10) as f64 / 1_073_741_824.0;
    // headroom = 10 * 0.7 * 1.0 = 7.0 GiB
    let expected_headroom = committed_gb * expected_rate * 1.0;
    let expected_total = (committed_gb + expected_headroom).max(1.0);
    let expected_offer = expected_total / expected_rate.max(0.2);
    assert!(
        (estimate.total_gb - expected_total).abs() < 1e-6,
        "total_gb mismatch: expected {expected_total}, got {}",
        estimate.total_gb
    );
    assert!(
        (estimate.offer_budget_gb - expected_offer).abs() < 1e-6,
        "offer_budget_gb mismatch: expected {expected_offer}, got {}",
        estimate.offer_budget_gb
    );
}

#[test]
fn bootstrap_allows_first_gb() {
    // committed=0 → raw total=0.0, but FREE_TIER floor raises it to 1.0
    let estimate = estimate_budget(0, None, 0.0);
    assert!(
        (estimate.total_gb - 1.0).abs() < 1e-9,
        "total_gb must be 1.0 (FREE_TIER_GB) when committed=0, got {}",
        estimate.total_gb
    );
    // offer_budget = 1.0 / max(0.5, 0.2) = 1.0 / 0.5 = 2.0
    assert!(
        (estimate.offer_budget_gb - 2.0).abs() < 1e-9,
        "offer_budget_gb must be 2.0 when total=1.0 and sr=0.5, got {}",
        estimate.offer_budget_gb
    );
    assert!(
        (estimate.committed_gb - 0.0).abs() < 1e-9,
        "committed_gb must be 0.0"
    );
}

#[test]
fn offer_budget_inflated_by_success_rate() {
    // committed=1 GiB, sr=0.5 (no history → DEFAULT_SUCCESS_RATE)
    // headroom = 1.0 * 0.5 * 1.0 = 0.5
    // total = max(1.5, 1.0) = 1.5
    // offer = 1.5 / 0.5 = 3.0
    let estimate = estimate_budget(gib(1), None, 0.0);
    assert!(
        (estimate.total_gb - 1.5).abs() < 1e-6,
        "total_gb expected 1.5, got {}",
        estimate.total_gb
    );
    assert!(
        (estimate.offer_budget_gb - 3.0).abs() < 1e-6,
        "offer_budget_gb expected 3.0, got {}",
        estimate.offer_budget_gb
    );
}

#[test]
fn offer_budget_capped_at_5x() {
    // sr=0.1 → below the 0.2 floor → denominator = 0.2 → offer = total / 0.2 (5x)
    // Not total / 0.1 (10x).
    // Use stats that produce sr=0.1: offered=10, accepted=1
    let record = BudgetRecord {
        estimated_gb: 0.0,
        last_calculated: Timestamp(0),
        placement_success_rate: 0.0,
        weekly_stats: vec![(10, 1)],
    };
    let estimate = estimate_budget(gib(1), Some(&record), 0.0);
    // sr = 1/10 = 0.1
    assert!(
        (estimate.placement_success_rate - 0.1).abs() < 1e-9,
        "expected sr=0.1, got {}",
        estimate.placement_success_rate
    );
    // headroom = 1.0 * 0.1 * 1.0 = 0.1
    // total = max(1.1, 1.0) = 1.1
    // offer = 1.1 / 0.2 = 5.5 (not 1.1 / 0.1 = 11.0)
    let expected_offer = estimate.total_gb / 0.2;
    assert!(
        (estimate.offer_budget_gb - expected_offer).abs() < 1e-6,
        "offer_budget_gb expected {} (capped at /0.2), got {}",
        expected_offer,
        estimate.offer_budget_gb
    );
    // Confirm it is NOT the uncapped value
    let uncapped = estimate.total_gb / 0.1;
    assert!(
        (estimate.offer_budget_gb - uncapped).abs() > 1e-6,
        "offer_budget_gb must not be the uncapped value {}",
        uncapped
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
    assert_eq!(
        batch.deferred_count, 0,
        "importance=0.0 must not be deferred"
    );
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
    assert_eq!(
        r.weekly_stats[0].1, 1,
        "oldest remaining should be accepted=1"
    );
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
    let result = evaluate_pressure(Quota::Bytes(gib(100)), 0, gib(80), &[], unknown_trust, 0);
    assert_eq!(result.pressure, DiskPressure::Normal);
    assert!(result.immediate_evictions.is_empty());
    assert!(result.drop_notices.is_empty());
    assert_eq!(result.freed_bytes, 0);
}

#[test]
fn evaluate_pressure_soft() {
    // quota=100 GiB, used=88 GiB → free_ratio=0.12 → Soft
    let result = evaluate_pressure(Quota::Bytes(gib(100)), 0, gib(88), &[], unknown_trust, 0);
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

    let result = evaluate_pressure(
        Quota::Bytes(gib(100)),
        0,
        gib(97),
        &holdings,
        trust_fn,
        now_secs,
    );
    assert_eq!(result.pressure, DiskPressure::Hard);

    // Evict order: A (priority=0.05), C (priority=0.25), B (priority=0.81)
    // deficit=12 GiB: A(5)+C(5)=10 < 12, so also B(5) → freed=15 >= 12
    assert_eq!(
        result.immediate_evictions.len(),
        3,
        "all three must be evicted to cover 12 GiB deficit"
    );

    // Verify eviction order: A first, C second, B last
    assert_eq!(
        result.immediate_evictions[0].source_block_id,
        SourceBlockId([0u8; 32])
    );
    assert_eq!(
        result.immediate_evictions[1].source_block_id,
        SourceBlockId([2u8; 32])
    );
    assert_eq!(
        result.immediate_evictions[2].source_block_id,
        SourceBlockId([1u8; 32])
    );
}

// ============================================================
// should_reject_offers
// ============================================================

#[test]
fn should_reject_offers_above_soft() {
    // quota=100 GiB, used=86 GiB → free_ratio=0.14 < 0.15 → true
    assert!(should_reject_offers(Quota::Bytes(gib(100)), gib(86)));
}

#[test]
fn should_reject_offers_unlimited_quota() {
    // Only the explicit Unlimited (tests) never rejects; 0 is not "unlimited" (holder-i1).
    assert!(!should_reject_offers(Quota::Unlimited, gib(999)));
}

// ============================================================
// compute_effective_quota
// ============================================================

#[test]
fn compute_effective_quota_no_soft_cap() {
    // soft_quota=0 (no soft cap), disk_free=100 GiB, reserve=20 GiB → 80 GiB
    let result = compute_effective_quota(0, Some(gib(100)), 0, gib(20));
    assert_eq!(result, Quota::Bytes(gib(80)));
}

#[test]
fn compute_effective_quota_soft_cap_is_tighter() {
    // soft_quota=50 GiB, disk_free=200 GiB, reserve=20 GiB
    // available_from_disk=180 GiB, effective=min(50,180)=50 GiB
    let result = compute_effective_quota(gib(50), Some(gib(200)), 0, gib(20));
    assert_eq!(result, Quota::Bytes(gib(50)));
}

#[test]
fn compute_effective_quota_disk_free_is_tighter() {
    // soft_quota=100 GiB, disk_free=30 GiB, reserve=20 GiB
    // available_from_disk=10 GiB, effective=min(100,10)=10 GiB
    let result = compute_effective_quota(gib(100), Some(gib(30)), 0, gib(20));
    assert_eq!(result, Quota::Bytes(gib(10)));
}

#[test]
fn compute_effective_quota_disk_critically_full() {
    // soft_quota=0, disk_free=10 GiB, reserve=20 GiB → saturating_sub → 0
    let result = compute_effective_quota(0, Some(gib(10)), 0, gib(20));
    assert_eq!(result, Quota::Bytes(0));
}

#[test]
fn compute_effective_quota_soft_cap_zero_and_disk_large() {
    // soft_quota=0, disk_free=1000 GiB, reserve=20 GiB → 980 GiB
    let result = compute_effective_quota(0, Some(gib(1000)), 0, gib(20));
    assert_eq!(result, Quota::Bytes(gib(980)));
}

#[test]
fn compute_effective_quota_exact_reserve_boundary() {
    // soft_quota=0, disk_free=20 GiB, reserve=20 GiB → 20-20=0
    let result = compute_effective_quota(0, Some(gib(20)), 0, gib(20));
    assert_eq!(result, Quota::Bytes(0));
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
    let result = evaluate_pressure(
        Quota::Bytes(gib(100)),
        gib(100),
        gib(97),
        &holdings,
        trust_fn,
        now_secs,
    );
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
    let trust_fn = |id: &IdentityPub| -> f64 { if id.0 == [1u8; 32] { 0.5 } else { 0.9 } };
    let result = evaluate_pressure(
        Quota::Bytes(gib(100)),
        gib(90),
        gib(97),
        &holdings,
        trust_fn,
        now_secs,
    );
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
        if id.0 == [1u8; 32] {
            0.5
        } else if id.0 == [2u8; 32] {
            0.9
        } else {
            0.5
        }
    };
    let result = evaluate_pressure(
        Quota::Bytes(gib(100)),
        0,
        gib(97),
        &holdings,
        trust_fn,
        now_secs,
    );
    assert_eq!(result.pressure, DiskPressure::Hard);
    assert_eq!(
        result.immediate_evictions.len(),
        3,
        "all three evicted when no floor"
    );
    assert_eq!(result.freed_bytes, gib(15));
}

// ─── BUDGET-07: eviction removes lowest priority first ───────────────────────

#[test]
fn eviction_removes_lowest_priority_first() {
    // quota=100 GiB, used=97 GiB → Hard, deficit=12 GiB.
    // Three holdings with clearly distinct priorities.
    // Eviction should consume from lowest-priority first until deficit is covered.
    let now_secs = 0u64;

    let holdings = vec![
        // H_low: importance=0.1, trust=0.2 → priority=0.02, 8 GiB
        make_holding(
            [10u8; 32],
            [1u8; 32],
            0.1,
            gib(8),
            HoldingStatus::Active,
            Timestamp(now_secs),
        ),
        // H_mid: importance=0.5, trust=0.5 → priority=0.25, 8 GiB
        make_holding(
            [20u8; 32],
            [2u8; 32],
            0.5,
            gib(8),
            HoldingStatus::Active,
            Timestamp(now_secs),
        ),
        // H_high: importance=0.9, trust=0.9 → priority=0.81, 8 GiB
        make_holding(
            [30u8; 32],
            [3u8; 32],
            0.9,
            gib(8),
            HoldingStatus::Active,
            Timestamp(now_secs),
        ),
    ];

    let trust_fn = |id: &IdentityPub| -> f64 {
        if id.0 == [1u8; 32] {
            0.2
        } else if id.0 == [2u8; 32] {
            0.5
        } else {
            0.9
        }
    };

    // quota=100 GiB, used=97 GiB → free_ratio=0.03 → Hard
    // deficit = 0.15*100 - 3 = 12 GiB
    // H_low (8 GiB) + H_mid (8 GiB) = 16 GiB ≥ 12 → both evicted, H_high spared
    let result = evaluate_pressure(
        Quota::Bytes(gib(100)),
        0,
        gib(97),
        &holdings,
        trust_fn,
        now_secs,
    );
    assert_eq!(result.pressure, DiskPressure::Hard);

    // H_low must be first (lowest priority evicted first)
    assert!(!result.immediate_evictions.is_empty(), "expected evictions");
    assert_eq!(
        result.immediate_evictions[0].source_block_id,
        SourceBlockId([10u8; 32]),
        "H_low must be evicted first"
    );

    // H_high must NOT be among evictions (sufficient freed without it)
    let high_evicted = result
        .immediate_evictions
        .iter()
        .any(|e| e.source_block_id == SourceBlockId([30u8; 32]));
    assert!(
        !high_evicted,
        "H_high (highest priority) must be spared if lower-priority holdings cover the deficit"
    );

    assert!(
        result.freed_bytes >= gib(12),
        "freed_bytes={} must cover the 12 GiB deficit",
        result.freed_bytes
    );
}

/// W13: verify that `drop_notices` is non-empty when holdings exist in the buffer zone.
///
/// Scenario:
/// - quota=1000, used=970 → free=30, free_ratio=0.03 → Hard
/// - deficit = 0.15*1000 - 30 = 120 bytes; buffer = 0.05*1000 = 50 bytes
/// - Holding A: 600 bytes, low priority (importance=0.1, trust=0.2)
/// - Holding B: 350 bytes, medium priority (importance=0.5, trust=0.5)
/// - Holding C: 20 bytes, high priority (importance=0.9, trust=0.9)
///
/// Phase 1 (evict): A(600 bytes) covers deficit(120 bytes) → A evicted immediately.
/// Phase 2 (buffer): B(350) → phase2_freed ≥ buffer(50) → B gets drop notice.
/// C is above the buffer threshold and is not touched.
#[test]
fn evaluate_pressure_hard_produces_drop_notice_for_buffer_zone() {
    let now_secs = 0u64;
    let holdings = vec![
        // A: 600 bytes, lowest priority → immediately evicted
        make_holding(
            [0u8; 32],
            [1u8; 32],
            0.1,
            600,
            HoldingStatus::Active,
            Timestamp(now_secs),
        ),
        // B: 350 bytes, medium priority → buffer zone (DropNotice)
        make_holding(
            [1u8; 32],
            [2u8; 32],
            0.5,
            350,
            HoldingStatus::Active,
            Timestamp(now_secs),
        ),
        // C: 20 bytes, high priority → not touched
        make_holding(
            [2u8; 32],
            [3u8; 32],
            0.9,
            20,
            HoldingStatus::Active,
            Timestamp(now_secs),
        ),
    ];
    let trust_fn = |id: &IdentityPub| -> f64 {
        if id.0 == [1u8; 32] {
            0.2
        } else if id.0 == [2u8; 32] {
            0.5
        } else {
            0.9
        }
    };

    let result = evaluate_pressure(Quota::Bytes(1000), 0, 970, &holdings, trust_fn, now_secs);

    assert_eq!(result.pressure, DiskPressure::Hard);

    // A must be immediately evicted.
    assert_eq!(result.immediate_evictions.len(), 1);
    assert_eq!(
        result.immediate_evictions[0].source_block_id,
        SourceBlockId([0u8; 32])
    );

    // B must be in drop_notices (buffer zone).
    assert!(
        !result.drop_notices.is_empty(),
        "drop_notices must be non-empty when buffer-zone holdings exist"
    );
    assert_eq!(
        result.drop_notices[0].source_block_id,
        SourceBlockId([1u8; 32]),
        "B (medium priority) must receive a drop notice"
    );
    // Deadline must be now + DROP_NOTICE_WINDOW_SECS.
    assert_eq!(
        result.drop_notices[0].deadline_secs,
        now_secs + DROP_NOTICE_WINDOW_SECS,
    );

    // C must NOT be evicted or notified.
    let c_evicted = result
        .immediate_evictions
        .iter()
        .any(|e| e.source_block_id == SourceBlockId([2u8; 32]));
    let c_noticed = result
        .drop_notices
        .iter()
        .any(|n| n.source_block_id == SourceBlockId([2u8; 32]));
    assert!(!c_evicted, "C (highest priority) must not be evicted");
    assert!(
        !c_noticed,
        "C (highest priority) must not receive a drop notice"
    );
}

#[test]
fn should_reject_offers_with_effective_quota() {
    // soft_quota=80 GiB, disk_free=24 GiB (holdings already on disk), used=26 GiB,
    // reserve=20 GiB → effective = min(80, 24 + 26 − 20) = 30 GiB
    // free_ratio=(30-26)/30 ≈ 0.133 < 0.15 → true
    let effective = compute_effective_quota(gib(80), Some(gib(24)), gib(26), gib(20));
    assert_eq!(effective, Quota::Bytes(gib(30)));
    assert!(should_reject_offers(effective, gib(26)));
}

// ─── earned_gb / compute_earned_offer_gb ────────────────────────────────────

#[test]
fn compute_earned_offer_gb_zero_when_no_contributions() {
    let result = compute_earned_offer_gb(&[], |_| 1.0, 30.0);
    assert_eq!(result, 0.0);
}

#[test]
fn compute_earned_offer_gb_scales_with_gb_days_and_trust() {
    use crate::constants::MAX_COMBINED_TRUST;
    use crate::types::IdentityPub;

    let peer = IdentityPub([1u8; 32]);
    // 300 gb_days × trust=MAX → weight=1 → 300 / 30 = 10 GB earned.
    let earned = compute_earned_offer_gb(&[(peer, 300.0)], |_| MAX_COMBINED_TRUST, 30.0);
    assert!((earned - 10.0).abs() < 1e-6, "got {earned}");
}

#[test]
fn compute_earned_offer_gb_trust_weights_untrusted_low() {
    use crate::constants::MAX_COMBINED_TRUST;
    use crate::types::IdentityPub;

    let peer = IdentityPub([2u8; 32]);
    // Untrusted peer (0.1 out of 2.15) → weight ≈ 0.0465 → earned ≈ 0.465 / 30
    let earned = compute_earned_offer_gb(&[(peer, 300.0)], |_| 0.1, 30.0);
    let expected = 300.0 * (0.1 / MAX_COMBINED_TRUST) / 30.0;
    assert!(
        (earned - expected).abs() < 1e-6,
        "got {earned} vs {expected}"
    );
}

#[test]
fn compute_earned_offer_gb_sums_across_peers() {
    use crate::constants::MAX_COMBINED_TRUST;
    use crate::types::IdentityPub;

    let a = IdentityPub([1u8; 32]);
    let b = IdentityPub([2u8; 32]);
    let earned = compute_earned_offer_gb(&[(a, 100.0), (b, 200.0)], |_| MAX_COMBINED_TRUST, 30.0);
    assert!((earned - (300.0 / 30.0)).abs() < 1e-6);
}

#[test]
fn earned_gb_raises_total_and_offer_budget() {
    // Fresh owner with zero committed and zero history but 6 GB of earned credit.
    let estimate = estimate_budget(0, None, 6.0);
    assert_eq!(estimate.committed_gb, 0.0);
    assert_eq!(estimate.headroom_gb, 0.0);
    assert_eq!(estimate.earned_gb, 6.0);
    // total_gb = max(0 + 0 + 6, FREE_TIER=1.0) = 6.0
    assert!((estimate.total_gb - 6.0).abs() < 1e-9);
    // offer_budget = 6.0 / 0.5 = 12.0 (default success rate)
    assert!((estimate.offer_budget_gb - 12.0).abs() < 1e-9);
}

#[test]
fn earned_gb_negative_input_treated_as_zero() {
    let estimate = estimate_budget(0, None, -5.0);
    assert_eq!(estimate.earned_gb, 0.0);
    assert!((estimate.total_gb - FREE_TIER_GB).abs() < 1e-9);
}

mod quota_states;
