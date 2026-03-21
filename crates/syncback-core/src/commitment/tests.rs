use super::{
    age_component, compute_commitment, eviction_risk, flag_for_proactive_repair,
    pos_component, pressure_component, priority_component, CommitmentError, CommitmentScore,
    CommitmentTier, HolderProfile,
};
use crate::constants::SECS_PER_WEEK;
use crate::types::{IdentityPub, Timestamp};

fn peer(byte: u8) -> IdentityPub {
    let mut key = [0u8; 32];
    key[0] = byte;
    IdentityPub(key)
}

fn ts(secs: u64) -> Timestamp {
    Timestamp(secs)
}

const NOW: u64 = 100_000_000;

fn profile_reliable() -> HolderProfile {
    HolderProfile {
        holder_id: peer(1),
        recent_challenges: 10,
        recent_passes: 10,
        consecutive_misses: 0,
        offers_rejected_recently: false,
        drop_notice_sent_recently: false,
        our_eviction_priority: 1.0,
        max_known_eviction_priority: 1.0,
        first_seen: ts(NOW - 30 * SECS_PER_WEEK),
        now: ts(NOW),
    }
}

// --- pos_component tests ---

#[test]
fn pos_component_no_challenges_returns_neutral() {
    assert_eq!(pos_component(0, 0, 0), 0.5);
}

#[test]
fn pos_component_perfect_pass_rate() {
    assert_eq!(pos_component(10, 10, 0), 1.0);
}

#[test]
fn pos_component_zero_pass_rate() {
    assert_eq!(pos_component(10, 0, 0), 0.0);
}

#[test]
fn pos_component_uncertain_miss_degrades_score() {
    // recent_challenges=10, recent_passes=8, consecutive_misses=1 (Uncertain)
    // pass_rate = 0.8, miss_penalty = 0.15 → 0.65
    let result = pos_component(10, 8, 1);
    assert!((result - 0.65).abs() < 1e-9, "expected 0.65, got {result}");
}

#[test]
fn pos_component_presumed_lost_degrades_more() {
    // consecutive_misses=3 → PresumedLost, miss_penalty=0.35
    // pass_rate=0.8 → 0.8 - 0.35 = 0.45
    let result = pos_component(10, 8, 3);
    assert!((result - 0.45).abs() < 1e-9, "expected 0.45, got {result}");
}

#[test]
fn pos_component_miss_cannot_go_below_zero() {
    // pass_rate=0.0, miss_penalty=0.35 → max(0.0, -0.35) = 0.0
    let result = pos_component(4, 0, 5);
    assert_eq!(result, 0.0);
}

// --- pressure_component tests ---

#[test]
fn pressure_component_no_signals() {
    assert_eq!(pressure_component(false, false), 1.0);
}

#[test]
fn pressure_component_rejected_only() {
    assert_eq!(pressure_component(true, false), 0.5);
}

#[test]
fn pressure_component_drop_notice_only() {
    let result = pressure_component(false, true);
    assert!((result - 0.6).abs() < 1e-9, "expected 0.6, got {result}");
}

#[test]
fn pressure_component_both_signals() {
    // 1.0 - 0.5 - 0.4 = 0.1
    let result = pressure_component(true, true);
    assert!((result - 0.1).abs() < 1e-9, "expected 0.1, got {result}");
}

// --- age_component tests ---

#[test]
fn age_component_new_peer() {
    let result = age_component(ts(NOW), ts(NOW));
    assert_eq!(result, 0.0);
}

#[test]
fn age_component_saturates_at_26_weeks() {
    let result = age_component(ts(NOW - 26 * SECS_PER_WEEK), ts(NOW));
    assert!((result - 1.0).abs() < 1e-9, "expected 1.0, got {result}");
}

#[test]
fn age_component_half_saturation() {
    let result = age_component(ts(NOW - 13 * SECS_PER_WEEK), ts(NOW));
    assert!((result - 0.5).abs() < 1e-9, "expected 0.5, got {result}");
}

#[test]
fn age_component_beyond_saturation_capped() {
    let result = age_component(ts(NOW - 52 * SECS_PER_WEEK), ts(NOW));
    assert!((result - 1.0).abs() < 1e-9, "expected 1.0, got {result}");
}

// --- priority_component tests ---

#[test]
fn priority_component_no_reference() {
    let result = priority_component(0.8, 0.0);
    assert_eq!(result, 0.5);
}

#[test]
fn priority_component_highest_priority() {
    let result = priority_component(1.0, 1.0);
    assert!((result - 1.0).abs() < 1e-9);
}

#[test]
fn priority_component_lowest_priority() {
    let result = priority_component(0.0, 1.0);
    assert_eq!(result, 0.0);
}

#[test]
fn priority_component_midpoint() {
    let result = priority_component(0.5, 1.0);
    assert!((result - 0.5).abs() < 1e-9);
}

#[test]
fn priority_component_capped_at_one() {
    let result = priority_component(2.0, 1.0);
    assert!((result - 1.0).abs() < 1e-9);
}

// --- compute_commitment tests ---

#[test]
fn compute_commitment_reliable_holder() {
    // pos=1.0*0.50, pressure=1.0*0.25, age=min(30/26,1)*0.15, priority=1.0*0.10 → 1.0
    let profile = profile_reliable();
    let result = compute_commitment(&profile).unwrap();
    assert!((result.value() - 1.0).abs() < 1e-9, "expected 1.0, got {}", result.value());
    assert_eq!(result.tier(), CommitmentTier::High);
}

#[test]
fn compute_commitment_at_risk_holder() {
    let profile = HolderProfile {
        holder_id: peer(2),
        recent_challenges: 5,
        recent_passes: 0,
        consecutive_misses: 3,
        offers_rejected_recently: true,
        drop_notice_sent_recently: true,
        our_eviction_priority: 0.05,
        max_known_eviction_priority: 1.0,
        first_seen: ts(NOW - SECS_PER_WEEK),
        now: ts(NOW),
    };
    // pos = (0.0-0.35).max(0)*0.50 = 0.0
    // pressure = 0.1*0.25 = 0.025
    // age = (1/26)*0.15 ≈ 0.00577
    // priority = 0.05*0.10 = 0.005
    // total ≈ 0.036
    let result = compute_commitment(&profile).unwrap();
    assert!(result.value() < 0.10, "expected < 0.10, got {}", result.value());
    assert_eq!(result.tier(), CommitmentTier::AtRisk);
}

#[test]
fn compute_commitment_medium_holder() {
    let profile = HolderProfile {
        holder_id: peer(3),
        recent_challenges: 8,
        recent_passes: 6,
        consecutive_misses: 1,
        offers_rejected_recently: true,
        drop_notice_sent_recently: false,
        our_eviction_priority: 0.6,
        max_known_eviction_priority: 1.0,
        first_seen: ts(NOW - 12 * SECS_PER_WEEK),
        now: ts(NOW),
    };
    // pos = (0.75-0.15)*0.50 = 0.30
    // pressure = 0.5*0.25 = 0.125
    // age = (12/26)*0.15 ≈ 0.0692
    // priority = 0.6*0.10 = 0.06
    // total ≈ 0.554
    let result = compute_commitment(&profile).unwrap();
    assert!(result.value() > 0.45 && result.value() < 0.75,
        "expected Medium range, got {}", result.value());
    assert_eq!(result.tier(), CommitmentTier::Medium);
}

#[test]
fn compute_commitment_error_on_inconsistent_counts() {
    let mut profile = profile_reliable();
    profile.recent_challenges = 3;
    profile.recent_passes = 5;
    let result = compute_commitment(&profile);
    assert!(matches!(
        result,
        Err(CommitmentError::InconsistentPoSCounts { passes: 5, challenges: 3 })
    ));
}

// --- eviction_risk tests ---

#[test]
fn eviction_risk_zero_score() {
    let risk = eviction_risk(CommitmentScore(0.0));
    assert!((risk - 1.0).abs() < 1e-9);
}

#[test]
fn eviction_risk_full_score() {
    let risk = eviction_risk(CommitmentScore(1.0));
    assert!((risk - 0.0).abs() < 1e-9);
}

#[test]
fn eviction_risk_mid_score() {
    let risk = eviction_risk(CommitmentScore(0.5));
    assert!((risk - 0.75).abs() < 1e-9);
}

#[test]
fn eviction_risk_high_commitment() {
    let risk = eviction_risk(CommitmentScore(0.9));
    assert!((risk - 0.19).abs() < 1e-9, "expected 0.19, got {risk}");
}

// --- flag_for_proactive_repair tests ---

#[test]
fn flag_for_proactive_repair_at_risk_always_flagged() {
    let holders = vec![
        (peer(1), CommitmentScore(0.10)),
        (peer(2), CommitmentScore(0.80)),
    ];
    let flagged = flag_for_proactive_repair(&holders, 0.3);
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0], peer(1));
}

#[test]
fn flag_for_proactive_repair_low_important_file() {
    let holders = vec![(peer(1), CommitmentScore(0.30))];
    let flagged = flag_for_proactive_repair(&holders, 0.8);
    assert_eq!(flagged.len(), 1);
    assert_eq!(flagged[0], peer(1));
}

#[test]
fn flag_for_proactive_repair_low_unimportant_file() {
    let holders = vec![(peer(1), CommitmentScore(0.30))];
    let flagged = flag_for_proactive_repair(&holders, 0.5);
    assert!(flagged.is_empty());
}

#[test]
fn flag_for_proactive_repair_empty_input() {
    let flagged = flag_for_proactive_repair(&[], 1.0);
    assert!(flagged.is_empty());
}

// --- CommitmentScore tier boundary tests ---

#[test]
fn commitment_score_tier_boundaries() {
    // High/Medium boundary at 0.75
    assert_eq!(CommitmentScore(0.74).tier(), CommitmentTier::Medium);
    assert_eq!(CommitmentScore(0.75).tier(), CommitmentTier::High);
    // Medium/Low boundary at 0.45
    assert_eq!(CommitmentScore(0.44).tier(), CommitmentTier::Low);
    assert_eq!(CommitmentScore(0.45).tier(), CommitmentTier::Medium);
    // Low/AtRisk boundary at 0.20
    assert_eq!(CommitmentScore(0.19).tier(), CommitmentTier::AtRisk);
    assert_eq!(CommitmentScore(0.20).tier(), CommitmentTier::Low);
}
