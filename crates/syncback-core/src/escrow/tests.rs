use crate::constants::{
    DROP_NOTICE_WINDOW_SECS, FREE_TIER_BYTES, HOLDER_DELETE_COOLDOWN_SECS, TIER1_MAX_BYTES,
    TIER2_MAX_BYTES,
};
use crate::escrow::{
    check_restore, remaining_bytes_in_tier, should_delete_now, should_drop_after_notice,
    tier_for_bytes, DeleteDecision, DropNoticeDecision, EscrowTier, RestoreDecision,
};
use crate::types::Timestamp;

#[test]
fn free_tier_always_allowed() {
    let decision = check_restore(0, 0);
    assert_eq!(decision, RestoreDecision::Allowed);
}

#[test]
fn free_tier_boundary_allowed() {
    let decision = check_restore(0, FREE_TIER_BYTES - 1);
    assert_eq!(decision, RestoreDecision::Allowed);
}

#[test]
fn tier1_denied_not_enough_weeks() {
    let decision = check_restore(3, FREE_TIER_BYTES);
    match decision {
        RestoreDecision::Denied(d) => {
            assert_eq!(d.tier, EscrowTier::Tier1);
            assert_eq!(d.required_weeks, 4);
            assert_eq!(d.current_weeks, 3);
        }
        RestoreDecision::Allowed => panic!("expected Denied"),
    }
}

#[test]
fn tier1_allowed_sufficient_weeks() {
    let decision = check_restore(4, FREE_TIER_BYTES);
    assert_eq!(decision, RestoreDecision::Allowed);
}

#[test]
fn tier2_denied_not_enough_weeks() {
    let decision = check_restore(12, TIER1_MAX_BYTES);
    match decision {
        RestoreDecision::Denied(d) => {
            assert_eq!(d.tier, EscrowTier::Tier2);
            assert_eq!(d.required_weeks, 13);
            assert_eq!(d.current_weeks, 12);
        }
        RestoreDecision::Allowed => panic!("expected Denied"),
    }
}

#[test]
fn tier3_denied_not_enough_weeks() {
    let decision = check_restore(25, TIER2_MAX_BYTES);
    match decision {
        RestoreDecision::Denied(d) => {
            assert_eq!(d.tier, EscrowTier::Tier3);
            assert_eq!(d.required_weeks, 26);
            assert_eq!(d.current_weeks, 25);
        }
        RestoreDecision::Allowed => panic!("expected Denied"),
    }
}

#[test]
fn tier3_allowed_at_26_weeks() {
    let decision = check_restore(26, TIER2_MAX_BYTES);
    assert_eq!(decision, RestoreDecision::Allowed);
}

#[test]
fn remaining_bytes_free_tier() {
    assert_eq!(remaining_bytes_in_tier(0), FREE_TIER_BYTES);
}

#[test]
fn remaining_bytes_tier1() {
    let bytes_restored = FREE_TIER_BYTES + 1_000_000;
    let expected = TIER1_MAX_BYTES - bytes_restored;
    assert_eq!(remaining_bytes_in_tier(bytes_restored), expected);
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

#[test]
fn tier_for_bytes_returns_correct_tiers() {
    assert_eq!(tier_for_bytes(0), EscrowTier::FreeTier);
    assert_eq!(tier_for_bytes(FREE_TIER_BYTES - 1), EscrowTier::FreeTier);
    assert_eq!(tier_for_bytes(FREE_TIER_BYTES), EscrowTier::Tier1);
    assert_eq!(tier_for_bytes(TIER1_MAX_BYTES - 1), EscrowTier::Tier1);
    assert_eq!(tier_for_bytes(TIER1_MAX_BYTES), EscrowTier::Tier2);
    assert_eq!(tier_for_bytes(TIER2_MAX_BYTES - 1), EscrowTier::Tier2);
    assert_eq!(tier_for_bytes(TIER2_MAX_BYTES), EscrowTier::Tier3);
}

#[test]
fn remaining_bytes_tier3_is_max() {
    assert_eq!(remaining_bytes_in_tier(TIER2_MAX_BYTES), u64::MAX);
    assert_eq!(remaining_bytes_in_tier(TIER2_MAX_BYTES + 1_000_000), u64::MAX);
}
