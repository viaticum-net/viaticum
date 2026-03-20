use crate::constants::{
    DROP_NOTICE_WINDOW_SECS, ESCROW_TIER1_WEEKS, ESCROW_TIER2_WEEKS, ESCROW_TIER3_WEEKS,
    FREE_TIER_BYTES, HOLDER_DELETE_COOLDOWN_SECS, TIER1_MAX_BYTES, TIER2_MAX_BYTES,
};
use crate::types::Timestamp;

// ============================================================
// Types
// ============================================================

/// The escrow tier a restore request falls into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EscrowTier {
    /// First FREE_TIER_BYTES (1 GiB) restored: no weeks required.
    FreeTier,
    /// bytes_restored in [1 GiB, 5 GiB): requires >= ESCROW_TIER1_WEEKS (4 wk).
    Tier1,
    /// bytes_restored in [5 GiB, 50 GiB): requires >= ESCROW_TIER2_WEEKS (13 wk).
    Tier2,
    /// bytes_restored >= 50 GiB: requires >= ESCROW_TIER3_WEEKS (26 wk).
    Tier3,
}

impl EscrowTier {
    /// Minimum weeks_in_network required for this tier.
    pub fn required_weeks(self) -> u32 {
        match self {
            EscrowTier::FreeTier => 0,
            EscrowTier::Tier1 => ESCROW_TIER1_WEEKS,
            EscrowTier::Tier2 => ESCROW_TIER2_WEEKS,
            EscrowTier::Tier3 => ESCROW_TIER3_WEEKS,
        }
    }

    /// Determine tier from cumulative bytes already restored to this owner.
    pub fn from_bytes_restored(bytes_restored: u64) -> Self {
        if bytes_restored < FREE_TIER_BYTES {
            EscrowTier::FreeTier
        } else if bytes_restored < TIER1_MAX_BYTES {
            EscrowTier::Tier1
        } else if bytes_restored < TIER2_MAX_BYTES {
            EscrowTier::Tier2
        } else {
            EscrowTier::Tier3
        }
    }
}

/// Decision from check_restore().
#[derive(Debug, Clone, PartialEq)]
pub enum RestoreDecision {
    Allowed,
    Denied(RestoreDenial),
}

/// Reason for denial, sent back to owner as restore_denied message payload.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RestoreDenial {
    pub tier: EscrowTier,
    pub required_weeks: u32,
    pub current_weeks: u32,
    /// How many more bytes they can restore before moving to next tier.
    pub remaining_bytes_in_tier: u64,
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

/// Primary escrow check. Called by holder when owner requests restore.
///
/// weeks_in_network: caller looks this up from PeerRecord.weeks_in_network
/// bytes_already_restored: cumulative bytes holder has served to this owner
pub fn check_restore(weeks_in_network: u32, bytes_already_restored: u64) -> RestoreDecision {
    let tier = EscrowTier::from_bytes_restored(bytes_already_restored);
    if tier == EscrowTier::FreeTier {
        return RestoreDecision::Allowed;
    }
    let required = tier.required_weeks();
    if weeks_in_network >= required {
        RestoreDecision::Allowed
    } else {
        RestoreDecision::Denied(RestoreDenial {
            tier,
            required_weeks: required,
            current_weeks: weeks_in_network,
            remaining_bytes_in_tier: remaining_bytes_in_tier(bytes_already_restored),
        })
    }
}

/// Determine which tier applies to the given cumulative bytes restored.
pub fn tier_for_bytes(bytes_restored: u64) -> EscrowTier {
    EscrowTier::from_bytes_restored(bytes_restored)
}

/// How many bytes remain before moving to the next tier.
/// Returns u64::MAX for Tier3 (no upper bound).
pub fn remaining_bytes_in_tier(bytes_restored: u64) -> u64 {
    match EscrowTier::from_bytes_restored(bytes_restored) {
        EscrowTier::FreeTier => FREE_TIER_BYTES - bytes_restored,
        EscrowTier::Tier1 => TIER1_MAX_BYTES - bytes_restored,
        EscrowTier::Tier2 => TIER2_MAX_BYTES - bytes_restored,
        EscrowTier::Tier3 => u64::MAX,
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
