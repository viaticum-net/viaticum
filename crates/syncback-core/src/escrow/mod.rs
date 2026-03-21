use crate::constants::{DROP_NOTICE_WINDOW_SECS, FREE_TIER_GB, HOLDER_DELETE_COOLDOWN_SECS};
use crate::types::Timestamp;

// ============================================================
// Types
// ============================================================

/// Decision from check_restore().
#[derive(Debug, Clone, PartialEq)]
pub enum RestoreDecision {
    Allowed,
    Denied(RestoreDenial),
}

/// Reason for denial, sent back to owner as restore_denied message payload.
///
/// Fields map directly to the wire message fields from protocol.md §1.10:
///   restore_denied { shard_id, reason, current_trust, needed_trust, restore_budget_gb }
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RestoreDenial {
    /// Holder's trust score for this owner at the time of denial.
    pub current_trust: f64,
    /// Minimum trust score that would allow this restore.
    /// needed_trust = (restore_gb - FREE_TIER_GB) / escrow_trust_factor
    /// Clamped to 0.0 if restore_gb <= FREE_TIER_GB.
    pub needed_trust: f64,
    /// Max GB restorable at current trust level.
    pub restore_budget_gb: f64,
}

/// Decision for holder cooldown (delete flow).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteDecision {
    Keep,
    Delete,
}

/// Decision for drop notice flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropNoticeDecision {
    DeleteNow,
    StillWaiting,
}

// ============================================================
// Pure functions
// ============================================================

/// Compute max GB restorable at the given trust score.
///
/// Formula: max_restorable_gb = FREE_TIER_GB + trust * escrow_trust_factor
///
/// Trust is allowed to be negative (new peers in edge cases); result is clamped
/// to FREE_TIER_GB minimum so the demo credit is always available.
pub fn restore_budget(trust: f64, escrow_trust_factor: f64) -> f64 {
    (FREE_TIER_GB + trust * escrow_trust_factor).max(FREE_TIER_GB)
}

/// Primary escrow check. Called by holder when owner requests restore.
///
/// Parameters:
///   trust               — holder's pairwise trust score for the owner
///   restore_gb          — size of the requested restore in GB
///   escrow_trust_factor — configurable multiplier (pass DEFAULT_ESCROW_TRUST_FACTOR unless overridden)
///
/// Returns: Allowed if restore_gb <= restore_budget(trust), else Denied.
pub fn check_restore(trust: f64, restore_gb: f64, escrow_trust_factor: f64) -> RestoreDecision {
    let budget = restore_budget(trust, escrow_trust_factor);
    if restore_gb <= budget {
        RestoreDecision::Allowed
    } else {
        let needed_trust = ((restore_gb - FREE_TIER_GB) / escrow_trust_factor).max(0.0);
        RestoreDecision::Denied(RestoreDenial {
            current_trust: trust,
            needed_trust,
            restore_budget_gb: budget,
        })
    }
}

/// Holder-side: should we physically delete symbols now?
/// Called periodically while status == MarkedForDelete.
pub fn should_delete_now(delete_requested_at: Timestamp, now: Timestamp) -> DeleteDecision {
    let elapsed = now.0.saturating_sub(delete_requested_at.0);
    if elapsed >= HOLDER_DELETE_COOLDOWN_SECS {
        DeleteDecision::Delete
    } else {
        DeleteDecision::Keep
    }
}

/// Holder-side: has the drop-notice window expired?
/// Called after sending symbol_drop_notice to owner.
pub fn should_drop_after_notice(
    drop_notice_sent_at: Timestamp,
    now: Timestamp,
) -> DropNoticeDecision {
    let elapsed = now.0.saturating_sub(drop_notice_sent_at.0);
    if elapsed >= DROP_NOTICE_WINDOW_SECS {
        DropNoticeDecision::DeleteNow
    } else {
        DropNoticeDecision::StillWaiting
    }
}

#[cfg(test)]
mod tests;
