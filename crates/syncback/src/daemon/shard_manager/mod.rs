use std::collections::HashMap;

use rand::Rng;
use rand_core::{OsRng, RngCore};

use syncback_core::budget::BudgetPlanner;
use syncback_core::db::Db;
use syncback_core::messages::{
    to_cbor, FileType as MsgFileType, MsgId, SignedShardDescriptor, SignedShardDescriptorUnsigned,
    ShardOfferMsg,
};
use syncback_core::placement::{PlacementEngine, PlacementError};
use syncback_core::types::{
    FileType, IdentityPub, ShardId, ShardRecord, ShardStatus, Timestamp, UnitId, UnitRecord,
    UnitStatus,
};

use crate::daemon::{crypto, merkle, NetCommand};

const MAX_POS_CHALLENGES_PER_PEER: usize = 5;

// ============================================================
// Supporting types
// ============================================================

#[derive(Debug, Clone)]
pub struct PosChallenge {
    pub shard_id: ShardId,
    pub holder: IdentityPub,
    pub block_index: u32,
    pub nonce: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct PosResponse {
    pub from: IdentityPub,
    pub shard_id: ShardId,
    pub block_index: u32,
    pub block_data_hash: [u8; 32],
    pub merkle_proof: Vec<[u8; 32]>,
    pub nonce: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosResult {
    Pass,
    Fail,
}

// ============================================================
// Error
// ============================================================

#[derive(Debug, thiserror::Error)]
pub enum ShardManagerError {
    #[error("not enough peers for placement: need {need}, have {have}")]
    NotEnoughPeers { need: usize, have: usize },

    #[error("importance too low to back up: {0}")]
    ImportanceTooLow(f64),

    #[error("shard not found: {0:?}")]
    ShardNotFound(ShardId),

    #[error("unit not found: {0:?}")]
    UnitNotFound(UnitId),

    #[error("plaintext not available for repair (Phase 3 feature)")]
    PlaintextNotAvailable,

    #[error("db error: {0}")]
    Db(#[from] syncback_core::db::DbError),

    #[error("placement error: {0}")]
    Placement(syncback_core::placement::PlacementError),

    #[error("message error: {0}")]
    Message(#[from] syncback_core::messages::MessageError),

    #[error("net channel closed")]
    NetChannelClosed,

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("reed-solomon error: {0}")]
    ReedSolomon(String),
}

impl From<PlacementError> for ShardManagerError {
    fn from(e: PlacementError) -> Self {
        match e {
            PlacementError::NotEnoughPeers { need, have } => {
                ShardManagerError::NotEnoughPeers { need, have }
            }
            PlacementError::ImportanceTooLow(v) => ShardManagerError::ImportanceTooLow(v),
            other => ShardManagerError::Placement(other),
        }
    }
}

// ============================================================
// ShardManager
// ============================================================

pub struct ShardManager {
    db: Db,
    placement: PlacementEngine,
    #[allow(dead_code)]
    budget: BudgetPlanner,
    identity_key: ed25519_dalek::SigningKey,
    identity_pub: IdentityPub,
    net_tx: tokio::sync::mpsc::Sender<NetCommand>,
    pending_blobs: std::sync::Mutex<HashMap<ShardId, Vec<u8>>>,
}

impl ShardManager {
    pub fn new(
        db: Db,
        placement: PlacementEngine,
        budget: BudgetPlanner,
        identity_key: ed25519_dalek::SigningKey,
        identity_pub: IdentityPub,
        net_tx: tokio::sync::mpsc::Sender<NetCommand>,
    ) -> Self {
        ShardManager {
            db,
            placement,
            budget,
            identity_key,
            identity_pub,
            net_tx,
            pending_blobs: std::sync::Mutex::new(HashMap::new()),
        }
    }

    // -------------------------------------------------------------------------
    // Key derivation (public — used by restore path)
    // -------------------------------------------------------------------------

    pub fn derive_unit_key(&self, unit_id: UnitId) -> [u8; 32] {
        let ikm: [u8; 32] = self.identity_key.to_bytes();
        crypto::derive_unit_key(&ikm, unit_id)
    }

    // -------------------------------------------------------------------------
    // Pending blob buffer
    // -------------------------------------------------------------------------

    pub fn get_pending_blob(&self, shard_id: &ShardId) -> Option<Vec<u8>> {
        self.pending_blobs
            .lock()
            .expect("pending_blobs lock poisoned")
            .get(shard_id)
            .cloned()
    }

    pub fn clear_pending_blobs(&self) {
        self.pending_blobs
            .lock()
            .expect("pending_blobs lock poisoned")
            .clear();
    }

    // -------------------------------------------------------------------------
    // Main pipeline: unit -> shards -> upload
    // -------------------------------------------------------------------------

    pub async fn upload_unit(
        &self,
        unit_id: UnitId,
        unit_record: &UnitRecord,
        plaintext: &[u8],
        importance: f64,
        file_type: FileType,
        now: Timestamp,
    ) -> Result<Vec<(ShardId, IdentityPub)>, ShardManagerError> {
        // 1. Derive encryption key and encrypt.
        let key = self.derive_unit_key(unit_id);
        let ciphertext = encrypt_unit(&key, plaintext)?;

        // 2. Determine placement plan (erasure params + holder assignments).
        let plan = self
            .placement
            .select_holders(unit_id, importance)
            .map_err(ShardManagerError::from)?;

        let k = plan.params.k;
        let n = plan.params.n;

        // 3. Erasure-code ciphertext into n shards.
        let shards = encode_unit(&ciphertext, k, n)?;

        // 4. Store blobs in pending map, build shard records and send offers.
        let mut placements: Vec<(ShardId, IdentityPub)> = Vec::with_capacity(n);

        // Collect all data first (no await points), then send network messages.
        struct ShardWork {
            shard_id: ShardId,
            holder: IdentityPub,
            shard_bytes: Vec<u8>,
            payload: Vec<u8>,
            root: [u8; 32],
            shard_index: u8,
        }
        let mut work_items: Vec<ShardWork> = Vec::with_capacity(n);

        for assignment in &plan.assignments {
            let idx = assignment.shard_index as usize;
            let shard_bytes = shards[idx].clone();
            let shard_id = ShardId(*blake3::hash(&shard_bytes).as_bytes());
            let root = merkle::merkle_root(&shard_bytes);
            let holder = assignment.holder;

            // Build and sign SignedShardDescriptor.
            let unsigned = SignedShardDescriptorUnsigned {
                shard_id,
                unit_id,
                shard_index: assignment.shard_index,
                k: k as u8,
                n: n as u8,
                merkle_root: root,
                owner_pub: self.identity_pub,
                importance: importance as f32,
                file_type: convert_file_type(file_type),
                created_at: now.0,
            };
            let descriptor = SignedShardDescriptor::sign(unsigned, &self.identity_key)?;
            let offer_msg = ShardOfferMsg {
                v: 1,
                descriptor,
                ts: now.0,
            };
            let payload = to_cbor(&offer_msg)?;
            work_items.push(ShardWork {
                shard_id,
                holder,
                shard_bytes,
                payload,
                root,
                shard_index: assignment.shard_index,
            });
        }

        // Insert blobs into pending buffer (sync, no await).
        {
            let mut pending = self
                .pending_blobs
                .lock()
                .expect("pending_blobs lock poisoned");
            for item in &work_items {
                pending.insert(item.shard_id, item.shard_bytes.clone());
            }
        }

        for item in &work_items {
            // Send offer via board.
            self.net_tx
                .send(NetCommand::PublishBoard {
                    msg_type: "shard_offer".to_string(),
                    payload: item.payload.clone(),
                    directed_to: Some(item.holder),
                })
                .await
                .map_err(|_| ShardManagerError::NetChannelClosed)?;

            // Insert ShardRecord (status = Offered).
            let record = ShardRecord {
                shard_id: item.shard_id,
                unit_id,
                shard_index: item.shard_index,
                holder_id: item.holder,
                status: ShardStatus::Offered,
                last_verified: None,
                offered_at: now,
                stored_at: None,
                merkle_root: item.root,
            };
            self.db.upsert_shard(&record)?;

            placements.push((item.shard_id, item.holder));
        }

        // Update unit record with RS params.
        let mut updated_unit = unit_record.clone();
        updated_unit.rs_k = k as u8;
        updated_unit.rs_n = n as u8;
        self.db.upsert_unit(&updated_unit)?;

        tracing::info!(
            unit_id = %unit_id,
            k,
            n,
            shards = placements.len(),
            "upload_unit: offers sent"
        );

        Ok(placements)
    }

    // -------------------------------------------------------------------------
    // State updates
    // -------------------------------------------------------------------------

    pub async fn handle_shard_accept(
        &self,
        shard_id: ShardId,
        holder: IdentityPub,
        _offer_msg_id: MsgId,
        now: Timestamp,
    ) -> Result<(), ShardManagerError> {
        let record = self
            .db
            .get_shard(&shard_id)?
            .ok_or(ShardManagerError::ShardNotFound(shard_id))?;

        self.db
            .update_shard_status(&shard_id, ShardStatus::Accepted)?;

        let blob = self
            .pending_blobs
            .lock()
            .expect("pending_blobs lock poisoned")
            .get(&shard_id)
            .cloned();

        match blob {
            Some(data) => {
                self.net_tx
                    .send(NetCommand::UploadShard {
                        shard_id,
                        holder,
                        data,
                    })
                    .await
                    .map_err(|_| ShardManagerError::NetChannelClosed)?;
                tracing::debug!(
                    shard_id = %shard_id,
                    holder = %holder,
                    "shard_accept: blob upload queued"
                );
            }
            None => {
                tracing::debug!(
                    shard_id = %shard_id,
                    unit_id = %record.unit_id,
                    "shard_accept: blob not in pending buffer (offer expired)"
                );
            }
        }

        let _ = now;
        Ok(())
    }

    pub fn handle_shard_stored(
        &self,
        shard_id: ShardId,
        now: Timestamp,
    ) -> Result<(), ShardManagerError> {
        self.db
            .get_shard(&shard_id)?
            .ok_or(ShardManagerError::ShardNotFound(shard_id))?;

        self.db
            .update_shard_status(&shard_id, ShardStatus::Stored)?;

        // Remove from pending buffer.
        self.pending_blobs
            .lock()
            .expect("pending_blobs lock poisoned")
            .remove(&shard_id);

        let _ = now;
        Ok(())
    }

    pub fn handle_shard_reject(
        &self,
        shard_id: ShardId,
        now: Timestamp,
    ) -> Result<(), ShardManagerError> {
        self.db
            .get_shard(&shard_id)?
            .ok_or(ShardManagerError::ShardNotFound(shard_id))?;

        self.db
            .update_shard_status(&shard_id, ShardStatus::Lost)?;

        self.pending_blobs
            .lock()
            .expect("pending_blobs lock poisoned")
            .remove(&shard_id);

        let _ = now;
        Ok(())
    }

    pub fn handle_shard_dropped(
        &self,
        shard_id: ShardId,
        now: Timestamp,
    ) -> Result<(), ShardManagerError> {
        self.db
            .get_shard(&shard_id)?
            .ok_or(ShardManagerError::ShardNotFound(shard_id))?;

        self.db
            .update_shard_status(&shard_id, ShardStatus::Lost)?;

        let _ = now;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Repair flow
    // -------------------------------------------------------------------------

    pub fn find_under_replicated_units(&self) -> Result<Vec<UnitId>, ShardManagerError> {
        let active_units = self.db.list_units_by_status(UnitStatus::Active)?;
        let mut under_replicated = Vec::new();

        for unit in active_units {
            let shards = self.db.list_shards_for_unit(&unit.unit_id)?;
            let stored_count = shards
                .iter()
                .filter(|s| s.status == ShardStatus::Stored)
                .count();
            let k = unit.rs_k as usize;
            let n = unit.rs_n as usize;

            if stored_count < k {
                tracing::error!(
                    unit_id = %unit.unit_id,
                    stored = stored_count,
                    k,
                    "unit is UNRECOVERABLE: fewer than k shards stored"
                );
                // Do not include — data is irrecoverably lost.
            } else if stored_count < n {
                under_replicated.push(unit.unit_id);
            }
        }

        Ok(under_replicated)
    }

    pub async fn repair_unit(
        &self,
        unit_id: UnitId,
        plaintext: Option<&[u8]>,
        now: Timestamp,
    ) -> Result<usize, ShardManagerError> {
        let plaintext = match plaintext {
            Some(p) => p,
            None => return Err(ShardManagerError::PlaintextNotAvailable),
        };

        let unit = self
            .db
            .get_unit(&unit_id)?
            .ok_or(ShardManagerError::UnitNotFound(unit_id))?;

        let shards = self.db.list_shards_for_unit(&unit_id)?;
        let stored_ids: Vec<&ShardRecord> = shards
            .iter()
            .filter(|s| s.status == ShardStatus::Stored)
            .collect();

        let importance = unit.importance_avg;
        let file_type = FileType::User;

        // Find missing shard indices.
        let all_indices: std::collections::HashSet<u8> = (0..unit.rs_n).collect();
        let stored_indices: std::collections::HashSet<u8> =
            stored_ids.iter().map(|s| s.shard_index).collect();
        let missing_indices: Vec<u8> = all_indices
            .difference(&stored_indices)
            .copied()
            .collect();

        if missing_indices.is_empty() {
            return Ok(0);
        }

        // Re-encode from plaintext.
        let key = self.derive_unit_key(unit_id);
        let ciphertext = encrypt_unit(&key, plaintext)?;
        let all_shards = encode_unit(&ciphertext, unit.rs_k as usize, unit.rs_n as usize)?;

        // Select new holders for missing shards.
        let plan = self
            .placement
            .select_holders(unit_id, importance)
            .map_err(ShardManagerError::from)?;

        struct RepairWork {
            shard_id: ShardId,
            holder: IdentityPub,
            shard_bytes: Vec<u8>,
            payload: Vec<u8>,
            root: [u8; 32],
            missing_idx: u8,
        }

        let mut work_items: Vec<RepairWork> = Vec::new();
        for (assignment, missing_idx) in plan.assignments.iter().zip(missing_indices.iter()) {
            let shard_bytes = all_shards[*missing_idx as usize].clone();
            let shard_id = ShardId(*blake3::hash(&shard_bytes).as_bytes());
            let root = merkle::merkle_root(&shard_bytes);
            let holder = assignment.holder;

            let unsigned = SignedShardDescriptorUnsigned {
                shard_id,
                unit_id,
                shard_index: *missing_idx,
                k: unit.rs_k,
                n: unit.rs_n,
                merkle_root: root,
                owner_pub: self.identity_pub,
                importance: importance as f32,
                file_type: convert_file_type(file_type),
                created_at: now.0,
            };
            let descriptor = SignedShardDescriptor::sign(unsigned, &self.identity_key)?;
            let offer_msg = ShardOfferMsg {
                v: 1,
                descriptor,
                ts: now.0,
            };
            let payload = to_cbor(&offer_msg)?;
            work_items.push(RepairWork {
                shard_id,
                holder,
                shard_bytes,
                payload,
                root,
                missing_idx: *missing_idx,
            });
        }

        // Insert blobs into pending buffer (sync, no await).
        {
            let mut pending = self
                .pending_blobs
                .lock()
                .expect("pending_blobs lock poisoned");
            for item in &work_items {
                pending.insert(item.shard_id, item.shard_bytes.clone());
            }
        }

        let mut repaired = 0usize;
        for item in &work_items {
            self.net_tx
                .send(NetCommand::PublishBoard {
                    msg_type: "shard_offer".to_string(),
                    payload: item.payload.clone(),
                    directed_to: Some(item.holder),
                })
                .await
                .map_err(|_| ShardManagerError::NetChannelClosed)?;

            let record = ShardRecord {
                shard_id: item.shard_id,
                unit_id,
                shard_index: item.missing_idx,
                holder_id: item.holder,
                status: ShardStatus::Offered,
                last_verified: None,
                offered_at: now,
                stored_at: None,
                merkle_root: item.root,
            };
            self.db.upsert_shard(&record)?;
            repaired += 1;
        }

        Ok(repaired)
    }

    // -------------------------------------------------------------------------
    // Delete
    // -------------------------------------------------------------------------

    pub async fn delete_unit_shards(
        &self,
        unit_id: UnitId,
        now: Timestamp,
    ) -> Result<usize, ShardManagerError> {
        use syncback_core::messages::{to_cbor, DeleteMsg};

        let shards = self.db.list_shards_for_unit(&unit_id)?;
        let active_shards: Vec<&ShardRecord> = shards
            .iter()
            .filter(|s| {
                matches!(
                    s.status,
                    ShardStatus::Offered | ShardStatus::Accepted | ShardStatus::Stored
                )
            })
            .collect();

        let mut sent = 0usize;
        for shard in active_shards {
            let delete_msg = DeleteMsg {
                v: 1,
                shard_id: shard.shard_id,
                ts: now.0,
            };
            let payload = to_cbor(&delete_msg)?;
            self.net_tx
                .send(NetCommand::PublishBoard {
                    msg_type: "delete".to_string(),
                    payload,
                    directed_to: Some(shard.holder_id),
                })
                .await
                .map_err(|_| ShardManagerError::NetChannelClosed)?;

            self.db
                .update_shard_status(&shard.shard_id, ShardStatus::Deleting)?;
            sent += 1;
        }

        Ok(sent)
    }

    // -------------------------------------------------------------------------
    // PoS challenge generation
    // -------------------------------------------------------------------------

    pub fn sample_pos_challenges(
        &self,
        now: Timestamp,
    ) -> Result<Vec<PosChallenge>, ShardManagerError> {
        let one_week_secs = syncback_core::constants::SECS_PER_WEEK;
        let threshold = Timestamp(now.0.saturating_sub(one_week_secs));
        let shard_ids = self
            .db
            .list_shards_needing_pos(threshold, usize::MAX)?;

        // For each shard_id, look up its ShardRecord to get holder and unit.
        let mut by_holder: HashMap<IdentityPub, Vec<ShardRecord>> = HashMap::new();
        for shard_id in shard_ids {
            if let Some(record) = self.db.get_shard(&shard_id)? {
                if record.status == ShardStatus::Stored {
                    by_holder
                        .entry(record.holder_id)
                        .or_default()
                        .push(record);
                }
            }
        }

        let mut challenges = Vec::new();
        let mut rng = rand::thread_rng();

        for (holder, mut shard_list) in by_holder {
            // Shuffle and take up to MAX_POS_CHALLENGES_PER_PEER.
            let pick_count = MAX_POS_CHALLENGES_PER_PEER.min(shard_list.len());
            // Partial Fisher-Yates for pick_count elements.
            for i in 0..pick_count {
                let j = rng.gen_range(i..shard_list.len());
                shard_list.swap(i, j);
            }

            for record in shard_list.into_iter().take(pick_count) {
                // Approximate block count from unit size / rs_n / BLOCK_SIZE.
                let unit_size = match self.db.get_unit(&record.unit_id)? {
                    Some(u) => u.size_bytes,
                    None => merkle::BLOCK_SIZE as u64,
                };
                let rs_n = {
                    let u = self.db.get_unit(&record.unit_id)?;
                    u.map(|u| u.rs_n as u64).unwrap_or(1)
                };
                let shard_size = (unit_size / rs_n).max(1);
                let block_count = shard_size.div_ceil(merkle::BLOCK_SIZE as u64) as u32;
                let block_index = rng.gen_range(0..block_count.max(1));

                let mut nonce = [0u8; 32];
                OsRng.fill_bytes(&mut nonce);

                challenges.push(PosChallenge {
                    shard_id: record.shard_id,
                    holder,
                    block_index,
                    nonce,
                });
            }
        }

        Ok(challenges)
    }

    pub fn handle_pos_response(
        &self,
        response: PosResponse,
        now: Timestamp,
        _current_week: u32,
    ) -> Result<PosResult, ShardManagerError> {
        let record = self
            .db
            .get_shard(&response.shard_id)?
            .ok_or(ShardManagerError::ShardNotFound(response.shard_id))?;

        if record.holder_id != response.from {
            tracing::debug!(
                shard_id = %response.shard_id,
                expected = %record.holder_id,
                got = %response.from,
                "PoS response from unexpected peer"
            );
            return Ok(PosResult::Fail);
        }

        let valid = merkle::verify_merkle_proof(
            &record.merkle_root,
            &response.block_data_hash,
            response.block_index as usize,
            &response.merkle_proof,
        );

        if valid {
            self.db.record_pos_verified(&response.shard_id, now)?;
            tracing::debug!(shard_id = %response.shard_id, "PoS response: PASS");
            Ok(PosResult::Pass)
        } else {
            self.db
                .update_shard_status(&response.shard_id, ShardStatus::Lost)?;
            tracing::debug!(shard_id = %response.shard_id, "PoS response: FAIL");
            Ok(PosResult::Fail)
        }
    }
}

// ============================================================
// Internal helpers
// ============================================================

fn convert_file_type(ft: FileType) -> MsgFileType {
    match ft {
        FileType::User => MsgFileType::User,
        FileType::System => MsgFileType::System,
    }
}

fn encrypt_unit(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, ShardManagerError> {
    crypto::encrypt_plaintext(key, plaintext).map_err(|e| ShardManagerError::Encryption(e.to_string()))
}

fn decode_unit(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, ShardManagerError> {
    crypto::decrypt_ciphertext(key, ciphertext)
        .map_err(|e| ShardManagerError::Encryption(e.to_string()))
}

fn encode_unit(ciphertext: &[u8], k: usize, n: usize) -> Result<Vec<Vec<u8>>, ShardManagerError> {
    crypto::rs_encode(ciphertext, k, n).map_err(|e| ShardManagerError::ReedSolomon(e.to_string()))
}

// Functions exposed for tests in the child tests module.
#[cfg(test)]
pub(super) fn encrypt_unit_test(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, ShardManagerError> {
    encrypt_unit(key, plaintext)
}

#[cfg(test)]
pub(super) fn encode_unit_test(ciphertext: &[u8], k: usize, n: usize) -> Result<Vec<Vec<u8>>, ShardManagerError> {
    encode_unit(ciphertext, k, n)
}

#[cfg(test)]
pub(super) fn decrypt_unit(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, ShardManagerError> {
    decode_unit(key, ciphertext)
}

#[cfg(test)]
mod tests;
