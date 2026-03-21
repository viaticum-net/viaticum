// Commitment telemetry: estimate how likely a holder is to keep our symbols.
// Pure computation — no DB, no async, no network.
// Signals are assembled by the caller from existing DB records.

use crate::constants::{
    COMMITMENT_AGE_SATURATION_WEEKS, COMMITMENT_AGE_WEIGHT, COMMITMENT_MIN_CHALLENGES,
    COMMITMENT_POS_WEIGHT, COMMITMENT_PRESSURE_WEIGHT, COMMITMENT_PRIORITY_WEIGHT,
    POS_CONSECUTIVE_MISS_PRESUMED_LOST, SECS_PER_WEEK,
};
use crate::types::{IdentityPub, Timestamp};

#[cfg(test)]
mod tests;

/// Commitment score for one holder for one owner's data.
/// Range [0.0, 1.0]. Higher = more committed (less likely to evict).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CommitmentScore(pub f64);

impl CommitmentScore {
    /// Clamps the inner value to [0.0, 1.0].
    pub fn new(raw: f64) -> Self {
        CommitmentScore(raw.clamp(0.0, 1.0))
    }

    pub fn value(self) -> f64 {
        self.0
    }

    /// Human-readable tier for CLI display.
    pub fn tier(self) -> CommitmentTier {
        match self.0 {
            x if x >= 0.75 => CommitmentTier::High,
            x if x >= 0.45 => CommitmentTier::Medium,
            x if x >= 0.20 => CommitmentTier::Low,
            _ => CommitmentTier::AtRisk,
        }
    }
}

/// Qualitative tier. Used only for display; business logic uses f64 score directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitmentTier {
    /// score >= 0.75. Holder is reliable, no action needed.
    High,
    /// 0.45 <= score < 0.75. Acceptable but worth monitoring.
    Medium,
    /// 0.20 <= score < 0.45. Consider proactive repair if importance is high.
    Low,
    /// score < 0.20. Trigger proactive repair regardless of current PlacementStatus.
    AtRisk,
}

/// All inputs needed to compute a CommitmentScore for one holder.
/// Assembled by the caller from DB records. No DB access inside this module.
#[derive(Debug, Clone)]
pub struct HolderProfile {
    /// The holder's identity (informational; not used in computation directly).
    pub holder_id: IdentityPub,

    // --- PoS signals ---

    /// Number of PoS challenges issued to this holder in the last 4 weeks.
    /// 0 = no challenges yet (new peer or very quiet period).
    pub recent_challenges: u32,

    /// Number of those challenges that passed (Pass outcome).
    pub recent_passes: u32,

    /// Consecutive timeout misses on this holder's current placement.
    /// Source: `SymbolPlacement::consecutive_misses`.
    pub consecutive_misses: u32,

    // --- Disk pressure signals ---

    /// Has this holder rejected symbol offers in the last 7 days?
    pub offers_rejected_recently: bool,

    /// Has this holder sent a drop notice to us (or anyone observable) recently?
    pub drop_notice_sent_recently: bool,

    // --- Eviction priority of our data at this holder ---

    /// Eviction priority of our data as computed by the holder's policy.
    /// Computed by the owner using `budget::eviction_priority(importance, holder_trust,
    /// placed_at, now_secs)`.
    pub our_eviction_priority: f64,

    /// Maximum eviction priority seen across all holders for this block.
    /// Used to normalize the priority signal. If 0.0, the priority signal is neutral.
    pub max_known_eviction_priority: f64,

    // --- Relationship age ---

    /// When did we first interact with this holder (Unix seconds).
    pub first_seen: Timestamp,

    /// Current time (Unix seconds).
    pub now: Timestamp,
}

/// Error variants for the commitment module.
#[derive(Debug, thiserror::Error)]
pub enum CommitmentError {
    #[error("holder profile has inconsistent data: recent_passes ({passes}) > recent_challenges ({challenges})")]
    InconsistentPoSCounts { passes: u32, challenges: u32 },
}

/// Compute the PoS-pass-rate component (0.0..=1.0).
/// Exposed as pub for testing and for use by ReliabilityForecast.
pub fn pos_component(recent_challenges: u32, recent_passes: u32, consecutive_misses: u32) -> f64 {
    if recent_challenges < COMMITMENT_MIN_CHALLENGES {
        return 0.5;
    }

    let pass_rate = recent_passes as f64 / recent_challenges as f64;

    let miss_penalty = if consecutive_misses == 0 {
        0.0
    } else if consecutive_misses < POS_CONSECUTIVE_MISS_PRESUMED_LOST {
        0.15
    } else {
        0.35
    };

    (pass_rate - miss_penalty).max(0.0)
}

/// Compute the disk pressure component (0.0..=1.0).
/// Exposed as pub for testing.
pub fn pressure_component(offers_rejected_recently: bool, drop_notice_sent_recently: bool) -> f64 {
    let mut score = 1.0f64;
    if offers_rejected_recently {
        score -= 0.5;
    }
    if drop_notice_sent_recently {
        score -= 0.4;
    }
    score.max(0.0)
}

/// Compute the relationship age component (0.0..=1.0).
/// Exposed as pub for testing.
pub fn age_component(first_seen: Timestamp, now: Timestamp) -> f64 {
    let elapsed = now.0.saturating_sub(first_seen.0);
    let weeks_known = elapsed as f64 / SECS_PER_WEEK as f64;
    (weeks_known / COMMITMENT_AGE_SATURATION_WEEKS).min(1.0)
}

/// Compute the eviction priority component (0.0..=1.0).
/// Exposed as pub for testing.
pub fn priority_component(our_priority: f64, max_priority: f64) -> f64 {
    if max_priority <= 0.0 {
        return 0.5;
    }
    (our_priority / max_priority).min(1.0)
}

/// Compute commitment score for one holder from observable signals.
///
/// Returns Err only if the profile is internally inconsistent (passes > challenges).
/// All other edge cases (0 challenges, unknown priority, new peer) are handled
/// gracefully with conservative defaults.
pub fn compute_commitment(profile: &HolderProfile) -> Result<CommitmentScore, CommitmentError> {
    if profile.recent_passes > profile.recent_challenges {
        return Err(CommitmentError::InconsistentPoSCounts {
            passes: profile.recent_passes,
            challenges: profile.recent_challenges,
        });
    }

    let pos = pos_component(
        profile.recent_challenges,
        profile.recent_passes,
        profile.consecutive_misses,
    );
    let pressure = pressure_component(
        profile.offers_rejected_recently,
        profile.drop_notice_sent_recently,
    );
    let age = age_component(profile.first_seen, profile.now);
    let priority = priority_component(
        profile.our_eviction_priority,
        profile.max_known_eviction_priority,
    );

    let score_raw = pos * COMMITMENT_POS_WEIGHT
        + pressure * COMMITMENT_PRESSURE_WEIGHT
        + age * COMMITMENT_AGE_WEIGHT
        + priority * COMMITMENT_PRIORITY_WEIGHT;

    Ok(CommitmentScore::new(score_raw))
}

/// Convert a CommitmentScore to a probability of losing symbols in the next period.
///
/// eviction_risk = 1.0 - score^2
/// This is a relative ordering tool, not a calibrated probability.
pub fn eviction_risk(score: CommitmentScore) -> f64 {
    1.0 - score.value().powi(2)
}

/// Given a list of (holder, commitment) pairs for one source block,
/// return which holders should have proactive repair triggered.
///
/// A holder is flagged when:
///   tier == AtRisk
///   OR (tier == Low AND importance >= 0.7)
pub fn flag_for_proactive_repair(
    holders: &[(IdentityPub, CommitmentScore)],
    importance: f64,
) -> Vec<IdentityPub> {
    holders
        .iter()
        .filter(|(_, score)| {
            let tier = score.tier();
            tier == CommitmentTier::AtRisk || (tier == CommitmentTier::Low && importance >= 0.7)
        })
        .map(|(id, _)| *id)
        .collect()
}
