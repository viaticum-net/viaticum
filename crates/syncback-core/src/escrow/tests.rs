use crate::constants::{
    DEFAULT_ESCROW_TRUST_FACTOR, DROP_NOTICE_WINDOW_SECS, HOLDER_DELETE_COOLDOWN_SECS,
};
use crate::escrow::{
    check_restore, restore_budget, should_delete_now, should_drop_after_notice, DeleteDecision,
    DropNoticeDecision, RestoreDecision,
};
use crate::types::Timestamp;

#[test]
fn restore_budget_at_zero_trust() {
    let budget = restore_budget(0.0, DEFAULT_ESCROW_TRUST_FACTOR);
    assert_eq!(budget, 1.0);
}

#[test]
fn restore_budget_at_typical_trust() {
    let budget = restore_budget(2.0, DEFAULT_ESCROW_TRUST_FACTOR);
    assert_eq!(budget, 41.0);
}

#[test]
fn restore_budget_negative_trust_clamped_to_free_tier() {
    let budget = restore_budget(-1.0, DEFAULT_ESCROW_TRUST_FACTOR);
    assert_eq!(budget, 1.0);
}

#[test]
fn restore_budget_custom_factor() {
    let budget = restore_budget(1.0, 10.0);
    assert_eq!(budget, 11.0);
}

#[test]
fn check_restore_allowed_within_budget() {
    let decision = check_restore(2.0, 40.0, DEFAULT_ESCROW_TRUST_FACTOR);
    assert_eq!(decision, RestoreDecision::Allowed);
}

#[test]
fn check_restore_allowed_exactly_at_budget() {
    let decision = check_restore(2.0, 41.0, DEFAULT_ESCROW_TRUST_FACTOR);
    assert_eq!(decision, RestoreDecision::Allowed);
}

#[test]
fn check_restore_denied_exceeds_budget() {
    let decision = check_restore(2.0, 42.0, DEFAULT_ESCROW_TRUST_FACTOR);
    match decision {
        RestoreDecision::Denied(d) => {
            assert!((d.current_trust - 2.0).abs() < f64::EPSILON);
            let expected_needed = (42.0 - 1.0) / 20.0;
            assert!((d.needed_trust - expected_needed).abs() < 1e-10);
            assert!((d.restore_budget_gb - 41.0).abs() < f64::EPSILON);
        }
        RestoreDecision::Allowed => panic!("expected Denied"),
    }
}

#[test]
fn check_restore_denied_zero_trust_above_free_tier() {
    let decision = check_restore(0.0, 1.5, DEFAULT_ESCROW_TRUST_FACTOR);
    match decision {
        RestoreDecision::Denied(d) => {
            assert!((d.current_trust - 0.0).abs() < f64::EPSILON);
            let expected_needed = (1.5 - 1.0) / 20.0;
            assert!((d.needed_trust - expected_needed).abs() < 1e-10);
            assert!((d.restore_budget_gb - 1.0).abs() < f64::EPSILON);
        }
        RestoreDecision::Allowed => panic!("expected Denied"),
    }
}

#[test]
fn check_restore_allowed_zero_trust_within_free_tier() {
    let decision = check_restore(0.0, 0.5, DEFAULT_ESCROW_TRUST_FACTOR);
    assert_eq!(decision, RestoreDecision::Allowed);
}

#[test]
fn check_restore_allowed_zero_trust_exactly_free_tier() {
    let decision = check_restore(0.0, 1.0, DEFAULT_ESCROW_TRUST_FACTOR);
    assert_eq!(decision, RestoreDecision::Allowed);
}

#[test]
fn needed_trust_clamped_to_zero_when_restore_within_free_tier() {
    // trust=-0.5, restore_gb=0.8: budget = max(1.0, 1.0 + (-0.5)*20.0) = 1.0 >= 0.8 → Allowed
    let decision = check_restore(-0.5, 0.8, DEFAULT_ESCROW_TRUST_FACTOR);
    assert_eq!(decision, RestoreDecision::Allowed);
}

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
