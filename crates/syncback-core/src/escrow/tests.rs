use crate::constants::{
    DEFAULT_ESCROW_TRUST_FACTOR, DROP_NOTICE_WINDOW_SECS, FREE_TIER_GB, HOLDER_DELETE_COOLDOWN_SECS,
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

// ─── ESCROW-15: hit-and-run attack ──────────────────────────────────────────

#[test]
fn hit_and_run_new_peer_denied_large_restore() {
    // New peer with bootstrap trust (0.04) tries to restore 50 GB → must be denied.
    // Budget = FREE_TIER + trust * factor = 1.0 + 0.04 * 20.0 = 1.8 GB.
    let decision = check_restore(0.04, 50.0, DEFAULT_ESCROW_TRUST_FACTOR);
    match decision {
        RestoreDecision::Denied(d) => {
            assert!(d.restore_budget_gb < 2.0, "budget should be ~1.8 GB, got {}", d.restore_budget_gb);
            assert!(d.needed_trust > 2.0, "should need significant trust for 50 GB");
        }
        RestoreDecision::Allowed => panic!("50 GB restore with trust=0.04 must be denied"),
    }
}

#[test]
fn hit_and_run_zero_trust_only_gets_free_tier() {
    // Zero trust peer can only restore up to FREE_TIER_GB (1.0 GB).
    let allowed = check_restore(0.0, 1.0, DEFAULT_ESCROW_TRUST_FACTOR);
    assert_eq!(allowed, RestoreDecision::Allowed);

    let denied = check_restore(0.0, 1.01, DEFAULT_ESCROW_TRUST_FACTOR);
    assert!(matches!(denied, RestoreDecision::Denied(_)));
}

// ─── ESCROW-14: restore denied when trust too low, fields populated for wire msg

#[test]
fn restore_denied_when_trust_too_low_for_request() {
    // trust=0.04, restore_gb=50.0 — well above the budget for a new peer.
    // Budget = FREE_TIER_GB + 0.04 * DEFAULT_ESCROW_TRUST_FACTOR
    //        = 1.0 + 0.04 * 20.0 = 1.8 GB.
    // Must be denied; denial fields must be populated correctly for
    // building a RestoreDeniedMsg wire message.
    let trust = 0.04_f64;
    let restore_gb = 50.0_f64;
    let factor = DEFAULT_ESCROW_TRUST_FACTOR;

    let decision = check_restore(trust, restore_gb, factor);

    let denial = match decision {
        RestoreDecision::Denied(d) => d,
        RestoreDecision::Allowed => panic!("expected Denied for trust={trust}, restore_gb={restore_gb}"),
    };

    // current_trust must reflect the caller's trust
    assert!(
        (denial.current_trust - trust).abs() < f64::EPSILON,
        "current_trust must be {trust}, got {}",
        denial.current_trust
    );

    // restore_budget_gb = max(FREE_TIER_GB, FREE_TIER_GB + trust * factor)
    let expected_budget = FREE_TIER_GB + trust * factor; // = 1.8
    assert!(
        (denial.restore_budget_gb - expected_budget).abs() < 1e-10,
        "restore_budget_gb must be {expected_budget:.4}, got {:.4}",
        denial.restore_budget_gb
    );

    // needed_trust = (restore_gb - FREE_TIER_GB) / factor = (50.0 - 1.0) / 20.0 = 2.45
    let expected_needed = (restore_gb - FREE_TIER_GB) / factor;
    assert!(
        (denial.needed_trust - expected_needed).abs() < 1e-10,
        "needed_trust must be {expected_needed:.4}, got {:.4}",
        denial.needed_trust
    );

    // Denial fields must all be finite (non-NaN, non-Inf) — required for wire encoding
    assert!(denial.current_trust.is_finite(), "current_trust must be finite");
    assert!(denial.needed_trust.is_finite(), "needed_trust must be finite");
    assert!(denial.restore_budget_gb.is_finite(), "restore_budget_gb must be finite");
}

// ─── PROP-12: restore at 0 GB always allowed (free tier) ─────────────────────

#[test]
fn restore_budget_at_least_free_tier_across_trust_values() {
    // restore_gb=0.0 must always be Allowed regardless of trust score,
    // because FREE_TIER_GB >= 0.0 always holds.
    let trust_values = [0.0_f64, 0.04, 0.1, 0.5, 1.0, 2.0];
    let factor = DEFAULT_ESCROW_TRUST_FACTOR;

    for trust in trust_values {
        let decision = check_restore(trust, 0.0, factor);
        assert_eq!(
            decision,
            RestoreDecision::Allowed,
            "check_restore(trust={trust}, restore_gb=0.0, factor={factor}) must be Allowed \
             because restore_gb=0 <= FREE_TIER_GB={FREE_TIER_GB}"
        );
    }
}
