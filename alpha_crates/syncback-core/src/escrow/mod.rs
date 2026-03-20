use crate::constants::{
    DROP_NOTICE_WINDOW_SECS, ESCROW_TIER1_WEEKS, ESCROW_TIER2_WEEKS, ESCROW_TIER3_WEEKS,
    FREE_TIER_BYTES, HOLDER_DELETE_COOLDOWN_SECS, TIER1_MAX_BYTES, TIER2_MAX_BYTES,
};
use crate::db::Db;
use crate::types::{EscrowRestoreLog, HoldingRecord, IdentityPub, ShardId, ShardState, Timestamp};

// ============================================================
// Escrow types
// ============================================================

/// The three escrow tiers plus the free demo tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EscrowTier {
    /// First 1 GiB: always available without any weeks requirement.
    FreeTier,
    /// < 5 GiB total restored: requires >= 4 weeks in network.
    Tier1,
    /// < 50 GiB total restored: requires >= 13 weeks in network.
    Tier2,
    /// >= 50 GiB total restored: requires >= 26 weeks in network.
    Tier3,
}

impl EscrowTier {
    pub fn required_weeks(self) -> u32 {
        match self {
            EscrowTier::FreeTier => 0,
            EscrowTier::Tier1 => ESCROW_TIER1_WEEKS,
            EscrowTier::Tier2 => ESCROW_TIER2_WEEKS,
            EscrowTier::Tier3 => ESCROW_TIER3_WEEKS,
        }
    }

    fn from_bytes_restored(bytes: u64) -> Self {
        if bytes < FREE_TIER_BYTES {
            EscrowTier::FreeTier
        } else if bytes < TIER1_MAX_BYTES {
            EscrowTier::Tier1
        } else if bytes < TIER2_MAX_BYTES {
            EscrowTier::Tier2
        } else {
            EscrowTier::Tier3
        }
    }
}

/// Reason a restore was denied by escrow.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EscrowDenial {
    pub shard_id: ShardId,
    pub tier: EscrowTier,
    pub required_weeks: u32,
    pub current_weeks: u32,
}

/// Decision returned by check_restore().
#[derive(Debug)]
pub enum RestoreDecision {
    Allowed,
    Denied(EscrowDenial),
}

/// Decision returned by should_delete_now().
#[derive(Debug)]
pub enum DeleteDecision {
    Keep,
    Delete,
}

/// Decision returned by check_drop_notice().
#[derive(Debug)]
pub enum DropNoticeDecision {
    DeleteNow,
    StillWaiting,
}

// ============================================================
// Error
// ============================================================

#[derive(Debug, thiserror::Error)]
pub enum EscrowError {
    #[error("shard not held: {0:?}")]
    ShardNotHeld(ShardId),

    #[error("owner mismatch for shard {shard:?}: expected {expected:?}, got {actual:?}")]
    OwnerMismatch {
        shard: ShardId,
        expected: IdentityPub,
        actual: IdentityPub,
    },

    #[error("db error: {0}")]
    Db(#[from] crate::db::DbError),
}

// ============================================================
// EscrowChecker
// ============================================================

pub struct EscrowChecker {
    db: Db,
}

impl EscrowChecker {
    pub fn new(db: Db) -> Self {
        EscrowChecker { db }
    }

    // -------------------------------------------------------------------------
    // Restore decisions
    // -------------------------------------------------------------------------

    pub fn check_restore(
        &self,
        shard_id: &ShardId,
        owner_pub: &IdentityPub,
        now: Timestamp,
    ) -> Result<RestoreDecision, EscrowError> {
        let record = match self.db.get_holding(shard_id)? {
            Some(r) => r,
            None => {
                tracing::debug!(?shard_id, "check_restore: shard not held");
                return Err(EscrowError::ShardNotHeld(*shard_id));
            }
        };

        if record.owner_pub != *owner_pub {
            return Err(EscrowError::OwnerMismatch {
                shard: *shard_id,
                expected: record.owner_pub,
                actual: *owner_pub,
            });
        }

        if record.state == ShardState::MarkedForDelete {
            let requested_at = record
                .delete_requested_at
                .expect("invariant: MarkedForDelete without delete_requested_at");
            let elapsed = now.0.saturating_sub(requested_at.0);
            if elapsed >= HOLDER_DELETE_COOLDOWN_SECS {
                tracing::debug!(?shard_id, "check_restore: denied — cooldown expired");
                return Ok(RestoreDecision::Denied(EscrowDenial {
                    shard_id: *shard_id,
                    tier: EscrowTier::FreeTier,
                    required_weeks: 0,
                    current_weeks: 0,
                }));
            }
        }

        let bytes_restored = self
            .db
            .get_restore_log(owner_pub)?
            .map(|log| log.bytes_restored)
            .unwrap_or(0);

        let tier = EscrowTier::from_bytes_restored(bytes_restored);

        if tier == EscrowTier::FreeTier {
            tracing::debug!(?shard_id, "check_restore: allowed (free tier)");
            return Ok(RestoreDecision::Allowed);
        }

        let current_weeks = self
            .db
            .get_peer(owner_pub)?
            .map(|p| p.weeks_in_network)
            .unwrap_or(0);

        let required_weeks = tier.required_weeks();

        if current_weeks >= required_weeks {
            tracing::debug!(?shard_id, current_weeks, "check_restore: allowed");
            Ok(RestoreDecision::Allowed)
        } else {
            tracing::debug!(
                ?shard_id,
                current_weeks,
                required_weeks,
                "check_restore: denied"
            );
            Ok(RestoreDecision::Denied(EscrowDenial {
                shard_id: *shard_id,
                tier,
                required_weeks,
                current_weeks,
            }))
        }
    }

    pub fn record_restore(
        &self,
        _shard_id: &ShardId,
        owner_pub: &IdentityPub,
        bytes_served: u64,
        now: Timestamp,
    ) -> Result<(), EscrowError> {
        let mut log = self
            .db
            .get_restore_log(owner_pub)?
            .unwrap_or(EscrowRestoreLog {
                owner_pub: *owner_pub,
                bytes_restored: 0,
                first_restore_at: None,
                last_restore_at: None,
            });

        log.bytes_restored = log.bytes_restored.saturating_add(bytes_served);
        log.last_restore_at = Some(now);
        if log.first_restore_at.is_none() {
            log.first_restore_at = Some(now);
        }

        self.db.upsert_restore_log(&log)?;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Shard lifecycle (delete flow)
    // -------------------------------------------------------------------------

    pub fn mark_for_delete(
        &self,
        shard_id: &ShardId,
        owner_pub: &IdentityPub,
        now: Timestamp,
    ) -> Result<(), EscrowError> {
        let mut record = match self.db.get_holding(shard_id)? {
            Some(r) => r,
            None => return Err(EscrowError::ShardNotHeld(*shard_id)),
        };

        if record.owner_pub != *owner_pub {
            return Err(EscrowError::OwnerMismatch {
                shard: *shard_id,
                expected: record.owner_pub,
                actual: *owner_pub,
            });
        }

        if record.state == ShardState::MarkedForDelete {
            return Ok(());
        }

        record.state = ShardState::MarkedForDelete;
        record.delete_requested_at = Some(now);
        self.db.upsert_holding(&record)?;
        tracing::debug!(?shard_id, "mark_for_delete: state = MarkedForDelete");
        Ok(())
    }

    pub fn cancel_delete(
        &self,
        shard_id: &ShardId,
        owner_pub: &IdentityPub,
    ) -> Result<(), EscrowError> {
        let mut record = match self.db.get_holding(shard_id)? {
            Some(r) => r,
            None => return Err(EscrowError::ShardNotHeld(*shard_id)),
        };

        if record.owner_pub != *owner_pub {
            return Err(EscrowError::OwnerMismatch {
                shard: *shard_id,
                expected: record.owner_pub,
                actual: *owner_pub,
            });
        }

        if record.state == ShardState::Active {
            return Ok(());
        }

        record.state = ShardState::Active;
        record.delete_requested_at = None;
        self.db.upsert_holding(&record)?;
        tracing::debug!(?shard_id, "cancel_delete: state = Active");
        Ok(())
    }

    pub fn should_delete_now(
        &self,
        shard_id: &ShardId,
        now: Timestamp,
    ) -> Result<DeleteDecision, EscrowError> {
        let record = match self.db.get_holding(shard_id)? {
            Some(r) => r,
            None => return Err(EscrowError::ShardNotHeld(*shard_id)),
        };

        if record.state != ShardState::MarkedForDelete {
            return Ok(DeleteDecision::Keep);
        }

        let requested_at = record
            .delete_requested_at
            .expect("invariant: MarkedForDelete without delete_requested_at");

        let elapsed = now.0.saturating_sub(requested_at.0);
        if elapsed >= HOLDER_DELETE_COOLDOWN_SECS {
            Ok(DeleteDecision::Delete)
        } else {
            Ok(DeleteDecision::Keep)
        }
    }

    pub fn mark_silent(&self, shard_id: &ShardId) -> Result<(), EscrowError> {
        let mut record = match self.db.get_holding(shard_id)? {
            Some(r) => r,
            None => return Err(EscrowError::ShardNotHeld(*shard_id)),
        };

        if record.state == ShardState::MarkedForDelete {
            return Ok(());
        }

        record.state = ShardState::Silent;
        self.db.upsert_holding(&record)?;
        tracing::debug!(?shard_id, "mark_silent: state = Silent");
        Ok(())
    }

    pub fn mark_active(&self, shard_id: &ShardId) -> Result<(), EscrowError> {
        let mut record = match self.db.get_holding(shard_id)? {
            Some(r) => r,
            None => return Err(EscrowError::ShardNotHeld(*shard_id)),
        };

        if record.state == ShardState::Active {
            return Ok(());
        }

        record.state = ShardState::Active;
        self.db.upsert_holding(&record)?;
        tracing::debug!(?shard_id, "mark_active: state = Active");
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Disk pressure (holder-initiated eviction, Phase 2)
    // -------------------------------------------------------------------------

    pub fn record_drop_notice(
        &self,
        shard_id: &ShardId,
        now: Timestamp,
    ) -> Result<(), EscrowError> {
        let mut record = match self.db.get_holding(shard_id)? {
            Some(r) => r,
            None => return Err(EscrowError::ShardNotHeld(*shard_id)),
        };

        record.drop_notice_sent_at = Some(now);
        self.db.upsert_holding(&record)?;
        Ok(())
    }

    pub fn check_drop_notice(
        &self,
        shard_id: &ShardId,
        now: Timestamp,
    ) -> Result<DropNoticeDecision, EscrowError> {
        let record = match self.db.get_holding(shard_id)? {
            Some(r) => r,
            None => return Err(EscrowError::ShardNotHeld(*shard_id)),
        };

        match record.drop_notice_sent_at {
            None => Ok(DropNoticeDecision::StillWaiting),
            Some(sent_at) => {
                let elapsed = now.0.saturating_sub(sent_at.0);
                if elapsed >= DROP_NOTICE_WINDOW_SECS {
                    Ok(DropNoticeDecision::DeleteNow)
                } else {
                    Ok(DropNoticeDecision::StillWaiting)
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Queries
    // -------------------------------------------------------------------------

    pub fn expired_deletes(&self, now: Timestamp) -> Result<Vec<ShardId>, EscrowError> {
        let records = self.db.list_all_holding()?;
        let result = records
            .into_iter()
            .filter(|r| {
                if r.state != ShardState::MarkedForDelete {
                    return false;
                }
                let Some(requested_at) = r.delete_requested_at else {
                    return false;
                };
                let elapsed = now.0.saturating_sub(requested_at.0);
                elapsed >= HOLDER_DELETE_COOLDOWN_SECS
            })
            .map(|r| r.shard_id)
            .collect();
        Ok(result)
    }

    pub fn expired_drop_notices(&self, now: Timestamp) -> Result<Vec<ShardId>, EscrowError> {
        let records = self.db.list_all_holding()?;
        let result = records
            .into_iter()
            .filter(|r| {
                let Some(sent_at) = r.drop_notice_sent_at else {
                    return false;
                };
                let elapsed = now.0.saturating_sub(sent_at.0);
                elapsed >= DROP_NOTICE_WINDOW_SECS
            })
            .map(|r| r.shard_id)
            .collect();
        Ok(result)
    }

    pub fn silent_shards(&self) -> Result<Vec<ShardId>, EscrowError> {
        let records = self.db.list_all_holding()?;
        let result = records
            .into_iter()
            .filter(|r| r.state == ShardState::Silent)
            .map(|r| r.shard_id)
            .collect();
        Ok(result)
    }

    pub fn get_holding(&self, shard_id: &ShardId) -> Result<Option<HoldingRecord>, EscrowError> {
        Ok(self.db.get_holding(shard_id)?)
    }

    pub fn all_holdings(&self) -> Result<Vec<HoldingRecord>, EscrowError> {
        Ok(self.db.list_all_holding()?)
    }

    pub fn insert_holding(&self, record: HoldingRecord) -> Result<(), EscrowError> {
        self.db.upsert_holding(&record)?;
        Ok(())
    }

    pub fn remove_holding(&self, shard_id: &ShardId) -> Result<(), EscrowError> {
        self.db.delete_holding(shard_id)?;
        Ok(())
    }
}


#[cfg(test)]
mod tests;
