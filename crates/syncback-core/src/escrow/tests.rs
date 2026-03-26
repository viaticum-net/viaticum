use crate::constants::{DROP_NOTICE_WINDOW_SECS, HOLDER_DELETE_COOLDOWN_SECS};
use crate::escrow::{
    check_restore, compute_restore_budget, should_delete_now, should_drop_after_notice,
    DeleteDecision, DropNoticeDecision, RestoreDecision,
};
use crate::types::Timestamp;

// ============================================================
// compute_restore_budget
// ============================================================

#[test]
fn compute_restore_budget_zero_when_no_contribution() {
    assert_eq!(compute_restore_budget(0.0, 7.0), 0.0);
}

#[test]
fn compute_restore_budget_formula_correct() {
    // stored_gb_days=70.0, k=7.0 → budget=10.0
    let budget = compute_restore_budget(70.0, 7.0);
    assert!((budget - 10.0).abs() < f64::EPSILON);
}

#[test]
fn compute_restore_budget_custom_k_factor() {
    // stored_gb_days=100.0, k=5.0 → budget=20.0
    let budget = compute_restore_budget(100.0, 5.0);
    assert!((budget - 20.0).abs() < f64::EPSILON);
}

#[test]
fn compute_restore_budget_zero_when_k_factor_zero() {
    // Guard against div-by-zero: k=0.0 → 0.0
    assert_eq!(compute_restore_budget(100.0, 0.0), 0.0);
}

#[test]
fn compute_restore_budget_ac1_formula() {
    // AC-1: 10 GB * 14 days = 140 GB·days, K=7 → budget=20 GB
    let budget = compute_restore_budget(140.0, 7.0);
    assert!((budget - 20.0).abs() < f64::EPSILON);
}

// ============================================================
// check_restore
// ============================================================

#[test]
fn check_restore_allowed_when_within_remaining_budget() {
    // stored_gb_days=140.0, already_restored=10.0, this_request=5.0, k=7
    // budget=20, remaining=10, 5<=10 → Allowed
    let decision = check_restore(140.0, 10.0, 5.0, 7.0);
    assert_eq!(decision, RestoreDecision::Allowed);
}

#[test]
fn check_restore_denied_when_already_consumed_full_budget() {
    // stored_gb_days=70.0, already_restored=10.0, this_request=1.0, k=7
    // budget=10, remaining=0, 1>0 → Denied
    let decision = check_restore(70.0, 10.0, 1.0, 7.0);
    assert!(matches!(decision, RestoreDecision::Denied(_)));
}

#[test]
fn check_restore_denied_when_no_contribution() {
    // stored_gb_days=0.0, already_restored=0.0, this_request=0.1, k=7 → Denied
    let decision = check_restore(0.0, 0.0, 0.1, 7.0);
    assert!(matches!(decision, RestoreDecision::Denied(_)));
}

#[test]
fn check_restore_allowed_exactly_at_remaining() {
    // remaining=5.0, this_request=5.0 → Allowed (boundary: <=)
    let decision = check_restore(35.0, 0.0, 5.0, 7.0);
    assert_eq!(decision, RestoreDecision::Allowed);
}

#[test]
fn check_restore_denied_one_epsilon_over_remaining() {
    // remaining=5.0, this_request=5.0+epsilon → Denied
    let decision = check_restore(35.0, 0.0, 5.0 + f64::EPSILON * 10.0, 7.0);
    assert!(matches!(decision, RestoreDecision::Denied(_)));
}

#[test]
fn denial_fields_populated_correctly() {
    // AC-4 denial case: budget=20.0, already_restored=15.0, request=6.0 → Denied
    let decision = check_restore(140.0, 15.0, 6.0, 7.0);
    match decision {
        RestoreDecision::Denied(d) => {
            assert!((d.restore_budget_gb - 20.0).abs() < f64::EPSILON);
            assert!((d.already_restored_gb - 15.0).abs() < f64::EPSILON);
            assert_eq!(d.current_trust, 0.0);
            assert_eq!(d.needed_trust, 0.0);
        }
        RestoreDecision::Allowed => panic!("expected Denied"),
    }
}

#[test]
fn hit_and_run_attack_blocked_with_zero_contribution() {
    // AC-3: stored nothing → budget=0 → any restore denied
    let decision = check_restore(0.0, 0.0, 50.0, 7.0);
    match decision {
        RestoreDecision::Denied(d) => {
            assert_eq!(d.restore_budget_gb, 0.0);
        }
        RestoreDecision::Allowed => panic!("hit-and-run must be denied"),
    }
}

#[test]
fn check_restore_ac4_cumulative_tracking_denied() {
    // AC-4 part 1: budget=20, already_restored=15, request=6 → remaining=5 < 6 → Denied
    let decision = check_restore(140.0, 15.0, 6.0, 7.0);
    assert!(matches!(decision, RestoreDecision::Denied(_)));
}

#[test]
fn check_restore_ac4_cumulative_tracking_allowed() {
    // AC-4 part 2: budget=20, already_restored=15, request=5 → remaining=5 >= 5 → Allowed
    let decision = check_restore(140.0, 15.0, 5.0, 7.0);
    assert_eq!(decision, RestoreDecision::Allowed);
}

#[test]
fn check_restore_ac5_fresh_peer_allowed() {
    // AC-5: fresh peer, already_restored=0, budget=10 → first request up to 10 GB allowed
    let decision = check_restore(70.0, 0.0, 9.9, 7.0);
    assert_eq!(decision, RestoreDecision::Allowed);
}

// ============================================================
// Cooldown tests (unchanged behavior)
// ============================================================

#[test]
fn should_delete_now_before_cooldown() {
    let delete_requested_at = Timestamp(1_000_000);
    let now = Timestamp(1_000_000 + HOLDER_DELETE_COOLDOWN_SECS - 1);
    assert_eq!(
        should_delete_now(delete_requested_at, now),
        DeleteDecision::Keep
    );
}

#[test]
fn should_delete_now_at_cooldown_boundary() {
    let delete_requested_at = Timestamp(1_000_000);
    let now = Timestamp(1_000_000 + HOLDER_DELETE_COOLDOWN_SECS);
    assert_eq!(
        should_delete_now(delete_requested_at, now),
        DeleteDecision::Delete
    );
}

#[test]
fn should_drop_after_notice_before_window() {
    let drop_notice_sent_at = Timestamp(2_000_000);
    let now = Timestamp(2_000_000 + DROP_NOTICE_WINDOW_SECS - 1);
    assert_eq!(
        should_drop_after_notice(drop_notice_sent_at, now),
        DropNoticeDecision::StillWaiting
    );
}

#[test]
fn should_drop_after_notice_at_window_boundary() {
    let drop_notice_sent_at = Timestamp(2_000_000);
    let now = Timestamp(2_000_000 + DROP_NOTICE_WINDOW_SECS);
    assert_eq!(
        should_drop_after_notice(drop_notice_sent_at, now),
        DropNoticeDecision::DeleteNow
    );
}
