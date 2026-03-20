use std::path::{Path, PathBuf};

use syncback_core::budget::{BudgetError, BudgetPlanner, DiskPressure, PressureResult};
use syncback_core::db::{Db, DbError};
use syncback_core::escrow::{EscrowChecker, EscrowDenial, EscrowError, RestoreDecision};
use syncback_core::messages::{FileType as MsgFileType, MessageError, SignedShardDescriptor};
use syncback_core::trust::TrustEngine;
use syncback_core::types::{
    FileType, HoldingRecord, IdentityPub, ShardId, ShardState, Timestamp,
};

#[cfg(test)]
mod tests;

// ============================================================
// Constants
// ============================================================

const BLOCK_SIZE: usize = 65_536;
const SHARD_EXT: &str = ".shard";

// ============================================================
// Public types
// ============================================================

#[derive(Debug)]
pub enum OfferDecision {
    Accept,
    RejectFull,
    RejectUnknown,
    RejectNotAllowed,
}

#[derive(Debug)]
pub struct PosAnswer {
    pub block_data_hash: [u8; 32],
    pub merkle_proof: Vec<[u8; 32]>,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("shard blob hash mismatch: expected {expected:?}, got {actual:?}")]
    HashMismatch {
        expected: ShardId,
        actual: [u8; 32],
    },

    #[error("invalid signature on shard descriptor: {0:?}")]
    InvalidSig(ShardId),

    #[error("escrow denied: {0:?}")]
    EscrowDenied(EscrowDenial),

    #[error("no budget: quota exceeded")]
    NoBudget,

    #[error("shard not found: {0:?}")]
    ShardNotFound(ShardId),

    #[error("shard blob file missing on disk: {0:?}")]
    BlobMissing(PathBuf),

    #[error("block index out of range: index {index}, shard has {blocks} blocks")]
    BlockOutOfRange { index: u32, blocks: u32 },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("db error: {0}")]
    Db(#[from] DbError),

    #[error("escrow error: {0}")]
    Escrow(#[from] EscrowError),

    #[error("budget error: {0}")]
    Budget(#[from] BudgetError),

    #[error("message error: {0}")]
    Message(#[from] MessageError),
}

// ============================================================
// StorageManager
// ============================================================

pub struct Storage {
    db: Db,
    shards_dir: PathBuf,
    quota_gb: f64,
    escrow: EscrowChecker,
    budget: BudgetPlanner,
}

impl Storage {
    pub fn new(
        db: Db,
        shards_dir: PathBuf,
        quota_gb: f64,
        trust: TrustEngine,
    ) -> Result<Self, StorageError> {
        std::fs::create_dir_all(&shards_dir)?;
        let escrow = EscrowChecker::new(db.clone());
        let budget = BudgetPlanner::new(db.clone(), trust);
        Ok(Storage {
            db,
            shards_dir,
            quota_gb,
            escrow,
            budget,
        })
    }

    // -------------------------------------------------------------------------
    // Inbound shard acceptance
    // -------------------------------------------------------------------------

    pub fn should_accept_offer(
        &self,
        descriptor: &SignedShardDescriptor,
    ) -> Result<OfferDecision, StorageError> {
        let used_bytes = self.db.total_holding_bytes()?;
        let used_gb = used_bytes as f64 / 1_073_741_824.0;
        if self.budget.should_reject_offers(self.quota_gb, used_gb) {
            return Ok(OfferDecision::RejectFull);
        }
        match self.db.get_peer(&descriptor.owner_pub)? {
            None => return Ok(OfferDecision::RejectUnknown),
            Some(peer) if peer.allowlisted => return Ok(OfferDecision::Accept),
            Some(_) => {}
        }
        Ok(OfferDecision::Accept)
    }

    pub async fn store_shard(
        &self,
        descriptor: &SignedShardDescriptor,
        blob: &[u8],
    ) -> Result<(), StorageError> {
        // 1. Hash verify
        let actual_hash = *blake3::hash(blob).as_bytes();
        if actual_hash != descriptor.shard_id.0 {
            return Err(StorageError::HashMismatch {
                expected: descriptor.shard_id,
                actual: actual_hash,
            });
        }

        // 2. Sig verify
        descriptor
            .verify_sig()
            .map_err(|_| StorageError::InvalidSig(descriptor.shard_id))?;

        // 3. Lazy disk check
        let used_bytes = self.db.total_holding_bytes()?;
        let used_gb = used_bytes as f64 / 1_073_741_824.0;
        let blob_gb = blob.len() as f64 / 1_073_741_824.0;
        let pressure = compute_pressure(self.quota_gb, used_gb);
        match pressure {
            DiskPressure::Normal => {}
            DiskPressure::Soft => return Err(StorageError::NoBudget),
            DiskPressure::Hard => {
                // Check if new shard priority > lowest held priority
                let new_priority = descriptor.importance as f64;
                let new_priority_adjusted =
                    blob_gb * new_priority; // simple proxy for eviction value

                let candidates = self.db.list_holding_for_eviction()?;
                if let Some(lowest) = candidates.first() {
                    let lowest_priority =
                        lowest.importance * lowest.size_bytes as f64 / 1_073_741_824.0;
                    if new_priority_adjusted <= lowest_priority {
                        return Err(StorageError::NoBudget);
                    }
                    // Evict the lowest priority shard to make room
                    let path = shard_path(&self.shards_dir, &lowest.shard_id);
                    if path.exists() {
                        std::fs::remove_file(&path)?;
                    }
                    self.db.delete_holding(&lowest.shard_id)?;
                    tracing::debug!(
                        shard_id = ?lowest.shard_id,
                        "store_shard: evicted lowest-priority shard to make room"
                    );
                } else {
                    return Err(StorageError::NoBudget);
                }
            }
        }

        // 4. Write to disk (atomic via .tmp rename)
        let path = shard_path(&self.shards_dir, &descriptor.shard_id);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let tmp_path = path.with_extension("shard.tmp");
        tokio::fs::write(&tmp_path, blob).await?;
        tokio::fs::rename(&tmp_path, &path).await?;

        // 5. Insert HoldingRecord
        let now = Timestamp::now();
        let record = HoldingRecord {
            shard_id: descriptor.shard_id,
            owner_pub: descriptor.owner_pub,
            importance: descriptor.importance as f64,
            size_bytes: blob.len() as u64,
            state: ShardState::Active,
            received_at: now,
            delete_requested_at: None,
            drop_notice_sent_at: None,
            file_type: convert_file_type(descriptor.file_type),
            merkle_root: descriptor.merkle_root,
            rs_k: descriptor.k,
            rs_n: descriptor.n,
            shard_index: descriptor.shard_index,
        };
        self.db.upsert_holding(&record)?;
        tracing::debug!(shard_id = ?descriptor.shard_id, "store_shard: stored");
        Ok(())
    }

    // -------------------------------------------------------------------------
    // PoS challenge response
    // -------------------------------------------------------------------------

    pub fn answer_pos_challenge(
        &self,
        shard_id: ShardId,
        block_index: u32,
        _nonce: &[u8; 32],
    ) -> Result<PosAnswer, StorageError> {
        let path = shard_path(&self.shards_dir, &shard_id);
        if !path.exists() {
            tracing::error!(shard_id = ?shard_id, path = ?path, "answer_pos_challenge: blob file missing");
            return Err(StorageError::BlobMissing(path));
        }
        let blob = std::fs::read(&path)?;

        let block_count = blob.len().div_ceil(BLOCK_SIZE) as u32;
        // Handle empty blob edge case
        let block_count = block_count.max(1);

        if block_index >= block_count {
            return Err(StorageError::BlockOutOfRange {
                index: block_index,
                blocks: block_count,
            });
        }

        let block_start = block_index as usize * BLOCK_SIZE;
        let block_end = (block_start + BLOCK_SIZE).min(blob.len());
        let block_bytes = &blob[block_start..block_end];

        // Plain leaf hash — matches the Merkle tree leaf (no nonce mixed in).
        // Nonce is a challenge identifier for replay prevention at the protocol level,
        // not part of the cryptographic proof.
        let block_data_hash = *blake3::hash(block_bytes).as_bytes();

        // Build Merkle tree and extract proof
        let tree = build_merkle_tree(&blob);
        let merkle_proof = merkle_proof_path(&tree, block_index as usize);

        Ok(PosAnswer {
            block_data_hash,
            merkle_proof,
        })
    }

    // -------------------------------------------------------------------------
    // Restore
    // -------------------------------------------------------------------------

    pub fn read_shard_for_restore(
        &self,
        shard_id: ShardId,
        owner_pub: &IdentityPub,
        now: Timestamp,
    ) -> Result<Vec<u8>, StorageError> {
        // Check allowlist — allowlisted owners bypass escrow
        let allowlisted = self
            .db
            .get_peer(owner_pub)?
            .map(|p| p.allowlisted)
            .unwrap_or(false);

        if !allowlisted {
            match self.escrow.check_restore(&shard_id, owner_pub, now)? {
                RestoreDecision::Allowed => {}
                RestoreDecision::Denied(denial) => {
                    return Err(StorageError::EscrowDenied(denial));
                }
            }
        }

        let path = shard_path(&self.shards_dir, &shard_id);
        if !path.exists() {
            tracing::error!(shard_id = ?shard_id, path = ?path, "read_shard_for_restore: blob file missing");
            return Err(StorageError::BlobMissing(path));
        }
        let blob = std::fs::read(&path)?;

        self.escrow
            .record_restore(&shard_id, owner_pub, blob.len() as u64, now)?;

        Ok(blob)
    }

    // -------------------------------------------------------------------------
    // Shard lifecycle
    // -------------------------------------------------------------------------

    pub fn handle_delete_request(
        &self,
        shard_id: ShardId,
        owner_pub: &IdentityPub,
        now: Timestamp,
    ) -> Result<(), StorageError> {
        self.db.get_holding(&shard_id)?.ok_or(StorageError::ShardNotFound(shard_id))?;
        self.escrow.mark_for_delete(&shard_id, owner_pub, now)?;
        tracing::debug!(shard_id = ?shard_id, "handle_delete_request: marked for delete");
        Ok(())
    }

    pub fn handle_cancel_delete(
        &self,
        shard_id: ShardId,
        owner_pub: &IdentityPub,
    ) -> Result<(), StorageError> {
        self.escrow.cancel_delete(&shard_id, owner_pub)?;
        tracing::debug!(shard_id = ?shard_id, "handle_cancel_delete: reverted to active");
        Ok(())
    }

    pub fn process_expired_cooldowns(&self, now: Timestamp) -> Result<Vec<ShardId>, StorageError> {
        let expired = self.db.list_holding_cooldown_expired(now)?;
        let mut deleted = Vec::new();
        for record in expired {
            let path = shard_path(&self.shards_dir, &record.shard_id);
            if path.exists() {
                std::fs::remove_file(&path)?;
            }
            self.db.delete_holding(&record.shard_id)?;
            tracing::debug!(shard_id = ?record.shard_id, "process_expired_cooldowns: deleted");
            deleted.push(record.shard_id);
        }
        Ok(deleted)
    }

    pub fn process_expired_drop_notices(
        &self,
        now: Timestamp,
    ) -> Result<Vec<ShardId>, StorageError> {
        let expired = self.db.list_holding_drop_notice_expired(now)?;
        let mut deleted = Vec::new();
        for record in expired {
            let path = shard_path(&self.shards_dir, &record.shard_id);
            if path.exists() {
                std::fs::remove_file(&path)?;
            }
            self.db.delete_holding(&record.shard_id)?;
            tracing::debug!(shard_id = ?record.shard_id, "process_expired_drop_notices: deleted");
            deleted.push(record.shard_id);
        }
        Ok(deleted)
    }

    // -------------------------------------------------------------------------
    // Disk pressure
    // -------------------------------------------------------------------------

    pub fn check_pressure(&self, now: Timestamp) -> Result<PressureResult, StorageError> {
        let used_bytes = self.db.total_holding_bytes()?;
        let used_gb = used_bytes as f64 / 1_073_741_824.0;
        let result = self.budget.evaluate_pressure(self.quota_gb, used_gb, now.0)?;
        Ok(result)
    }

    pub fn evict_shard(
        &self,
        shard_id: ShardId,
        _now: Timestamp,
    ) -> Result<IdentityPub, StorageError> {
        let record = self
            .db
            .get_holding(&shard_id)?
            .ok_or(StorageError::ShardNotFound(shard_id))?;

        if record.file_type == FileType::System {
            panic!("invariant violation: attempted to evict system shard {shard_id:?}");
        }

        let path = shard_path(&self.shards_dir, &shard_id);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        self.db.delete_holding(&shard_id)?;
        tracing::debug!(shard_id = ?shard_id, "evict_shard: evicted");
        Ok(record.owner_pub)
    }

    pub fn record_drop_notice(
        &self,
        shard_id: ShardId,
        now: Timestamp,
    ) -> Result<(), StorageError> {
        self.db.set_drop_notice_sent_at(&shard_id, now)?;
        tracing::debug!(shard_id = ?shard_id, "record_drop_notice: recorded");
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Storage warning
    // -------------------------------------------------------------------------

    pub fn handle_storage_warning(&self, shard_id: ShardId) -> Result<bool, StorageError> {
        let record = match self.db.get_holding(&shard_id)? {
            Some(r) => r,
            None => {
                tracing::debug!(shard_id = ?shard_id, "handle_storage_warning: shard not held");
                return Ok(false);
            }
        };

        let path = shard_path(&self.shards_dir, &shard_id);
        if !path.exists() {
            tracing::error!(shard_id = ?shard_id, "handle_storage_warning: blob file missing");
            return Ok(false);
        }
        let blob = std::fs::read(&path)?;

        // Verify merkle root by recomputing from blob
        let tree = build_merkle_tree(&blob);
        let computed_root = if tree.is_empty() {
            [0u8; 32]
        } else {
            tree[tree.len() - 1]
        };

        let intact = computed_root == record.merkle_root;
        if !intact {
            tracing::error!(
                shard_id = ?shard_id,
                "handle_storage_warning: merkle root mismatch — shard corrupted"
            );
        }
        Ok(intact)
    }

    // -------------------------------------------------------------------------
    // Queries
    // -------------------------------------------------------------------------

    pub fn used_bytes(&self) -> Result<u64, StorageError> {
        Ok(self.db.total_holding_bytes()?)
    }

    pub fn shard_count(&self) -> Result<usize, StorageError> {
        Ok(self.db.list_all_holding()?.len())
    }
}

// ============================================================
// Internal helpers
// ============================================================

fn shard_path(shards_dir: &Path, shard_id: &ShardId) -> PathBuf {
    let hex: String = shard_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let prefix = &hex[..2];
    shards_dir.join(prefix).join(format!("{hex}{SHARD_EXT}"))
}

fn convert_file_type(ft: MsgFileType) -> FileType {
    match ft {
        MsgFileType::User => FileType::User,
        MsgFileType::System => FileType::System,
    }
}

fn compute_pressure(quota_gb: f64, used_gb: f64) -> DiskPressure {
    if quota_gb <= 0.0 {
        return DiskPressure::Hard;
    }
    let free_ratio = (quota_gb - used_gb) / quota_gb;
    use syncback_core::constants::{HARD_PRESSURE_THRESHOLD, SOFT_PRESSURE_THRESHOLD};
    if free_ratio >= SOFT_PRESSURE_THRESHOLD {
        DiskPressure::Normal
    } else if free_ratio >= HARD_PRESSURE_THRESHOLD {
        DiskPressure::Soft
    } else {
        DiskPressure::Hard
    }
}

/// Build the full BLAKE3 Merkle tree over 64 KB blocks of `blob`.
///
/// Returns all tree nodes as a flat Vec where:
///   - indices [0 .. n_leaves) are leaf hashes
///   - the root is the last element
///
/// The tree is padded to the next power of 2 by duplicating the last leaf.
/// Last block is zero-padded to BLOCK_SIZE before hashing.
pub fn build_merkle_tree(blob: &[u8]) -> Vec<[u8; 32]> {
    // Compute leaf hashes
    let block_count = if blob.is_empty() {
        1
    } else {
        blob.len().div_ceil(BLOCK_SIZE)
    };

    let mut leaf_hashes: Vec<[u8; 32]> = Vec::with_capacity(block_count);
    for i in 0..block_count {
        let start = i * BLOCK_SIZE;
        let end = (start + BLOCK_SIZE).min(blob.len());
        let block = &blob[start..end];

        // Zero-pad to BLOCK_SIZE if last block is short
        let hash = if block.len() < BLOCK_SIZE {
            let mut padded = [0u8; BLOCK_SIZE];
            padded[..block.len()].copy_from_slice(block);
            *blake3::hash(&padded).as_bytes()
        } else {
            *blake3::hash(block).as_bytes()
        };
        leaf_hashes.push(hash);
    }

    // Pad leaf_hashes to next power of 2
    let n_leaves = leaf_hashes.len().next_power_of_two();
    while leaf_hashes.len() < n_leaves {
        let last = *leaf_hashes.last().unwrap();
        leaf_hashes.push(last);
    }

    // Build tree bottom-up. Total nodes = 2*n_leaves - 1.
    let mut tree: Vec<[u8; 32]> = Vec::with_capacity(2 * n_leaves - 1);
    tree.extend_from_slice(&leaf_hashes);

    let mut level_start = 0;
    let mut level_size = n_leaves;
    while level_size > 1 {
        let next_level_start = level_start + level_size;
        for i in (0..level_size).step_by(2) {
            let left = tree[level_start + i];
            let right = tree[level_start + i + 1];
            let mut hasher = blake3::Hasher::new();
            hasher.update(&left);
            hasher.update(&right);
            tree.push(*hasher.finalize().as_bytes());
        }
        level_start = next_level_start;
        level_size /= 2;
    }

    tree
}

/// Extract the Merkle proof path for a leaf at `leaf_idx`.
///
/// Returns sibling hashes from leaf level up to (but not including) the root.
/// Length = log2(n_leaves) where n_leaves is the padded power-of-2 leaf count.
pub fn merkle_proof_path(tree: &[[u8; 32]], leaf_idx: usize) -> Vec<[u8; 32]> {
    if tree.is_empty() {
        return Vec::new();
    }

    // Determine n_leaves from tree size: 2*n_leaves - 1 = tree.len()
    // n_leaves must be power of 2
    let n_leaves = tree.len().div_ceil(2);

    if n_leaves == 1 {
        // Single leaf tree — proof is empty
        return Vec::new();
    }

    let mut proof = Vec::new();
    let mut idx = leaf_idx;
    let mut level_start = 0;
    let mut level_size = n_leaves;

    while level_size > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        proof.push(tree[level_start + sibling_idx]);
        level_start += level_size;
        level_size /= 2;
        idx /= 2;
    }

    proof
}
