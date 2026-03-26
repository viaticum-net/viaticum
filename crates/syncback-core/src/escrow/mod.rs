use crate::constants::{DROP_NOTICE_WINDOW_SECS, HOLDER_DELETE_COOLDOWN_SECS};
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
/// Wire format compatibility: fields current_trust/needed_trust/restore_budget_gb
/// remain present. For contribution-based denial: current_trust=0.0, needed_trust=0.0,
/// restore_budget_gb = computed budget. Owner sees how large the budget is.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RestoreDenial {
    /// Always 0.0 in the new escrow (trust is not used for gating).
    pub current_trust: f64,
    /// Always 0.0 in the new escrow.
    pub needed_trust: f64,
    /// Max GB restorable given current contribution (stored_gb_days / k_factor).
    pub restore_budget_gb: f64,
    /// GB already consumed from the budget.
    pub already_restored_gb: f64,
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

/// Compute restore budget from contribution.
///
/// Formula: restore_budget_gb = stored_gb_days / k_factor.
/// Returns 0.0 if stored_gb_days == 0 or k_factor <= 0.
pub fn compute_restore_budget(stored_gb_days: f64, k_factor: f64) -> f64 {
    if k_factor <= 0.0 || stored_gb_days <= 0.0 {
        return 0.0;
    }
    stored_gb_days / k_factor
}

/// Primary escrow check. Called by the holder's processor when owner requests restore.
///
/// Parameters:
///   stored_gb_days      — result of db.stored_for_peer_gb_days(owner, now)
///   already_restored_gb — result of db.restored_total_bytes(owner) / BYTES_PER_GB
///   this_request_gb     — size of THIS block's symbols in GB
///   k_factor            — from EscrowCfg (default 7.0)
///
/// Returns Allowed if (budget - already_restored) >= this_request_gb, else Denied.
pub fn check_restore(
    stored_gb_days: f64,
    already_restored_gb: f64,
    this_request_gb: f64,
    k_factor: f64,
) -> RestoreDecision {
    let budget = compute_restore_budget(stored_gb_days, k_factor);
    let remaining = (budget - already_restored_gb).max(0.0);
    if this_request_gb <= remaining {
        RestoreDecision::Allowed
    } else {
        RestoreDecision::Denied(RestoreDenial {
            current_trust: 0.0,
            needed_trust: 0.0,
            restore_budget_gb: budget,
            already_restored_gb,
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
