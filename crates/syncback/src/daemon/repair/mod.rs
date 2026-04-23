// RepairAgent: scans for Lost/PresumedLost placements, selects a new holder,
// encodes symbols, delivers them via SymbolOffer/Accept/Transfer, and updates DB.
//
// Phase 3 scope: full network delivery. The old Phase 2.5 local-only re-encode is
// replaced by the complete repair flow:
//   Lost → select new holder → encode .bin symbols → deliver → Offered → (Alive on Accept)
//
// Key invariants preserved:
//   - ESI ranges never overlap between placements for the same block.
//   - Symbol files use .bin extension (same as BackupCoordinator).
//   - Old Lost placement is deleted before new Offered placement is inserted.
//   - Repair reuses the same delivery path as BackupCoordinator.

use std::sync::Arc;

use syncback_core::constants::DECODE_OVERHEAD;
use syncback_core::db::{Db, DbError};
use syncback_core::erasure::{binding_seed, ErasureEncoder};
use syncback_core::placement::{compute_allocation, HolderCandidate};
use syncback_core::types::{
    hex_encode, DeviceId, ErasureParams, FileId, IdentityPub, PlacementStatus, SourceBlockId,
    SymbolPlacement, Timestamp,
};

#[cfg(test)]
mod tests;

// ============================================================
// Public types
// ============================================================

/// Configuration for the RepairAgent.
#[derive(Debug, Clone)]
pub struct RepairConfig {
    /// Directory where local source block blobs are stored.
    /// Block blob path: `{source_blocks_dir}/{hex(block_id)}/block.bin`
    /// (same directory as symbols_dir in practice — the block lives alongside symbols).
    pub source_blocks_dir: std::path::PathBuf,

    /// Directory for symbol files (`.bin` format, same as BackupCoordinator):
    /// `{symbols_dir}/{hex(block_id)}/{esi}.bin`
    pub symbols_dir: std::path::PathBuf,

    /// Epoch key for re-deriving binding keys (same as BackupCoordinator uses).
    pub epoch_key: [u8; 32],

    /// This node's master identity (for signing SymbolOffer).
    pub own_identity: IdentityPub,

    /// Master signing key (Ed25519). When Some: use SymbolOffer/Accept/Transfer flow.
    /// When None: encode symbols and write to disk but skip network delivery.
    /// None is used in unit tests that do not wire a swarm.
    pub master_signing_key: Option<ed25519_dalek::SigningKey>,

    /// libp2p swarm handle. When Some: deliver repaired symbols over network.
    /// When None: write `.bin` files only (unit tests, offline operation).
    pub swarm: Option<Arc<crate::daemon::network::swarm::SwarmHandle>>,
}

/// One repair job: select new holder and deliver symbols for a Lost placement.
#[derive(Debug, Clone)]
pub struct RepairJob {
    pub source_block_id: SourceBlockId,
    /// The old (failed) holder — excluded from new placement.
    pub old_holder_id: DeviceId,
    pub file_id: FileId,
}

/// Outcome of executing one repair job.
#[derive(Debug)]
pub struct RepairOutcome {
    pub job: RepairJob,
    /// The new holder selected by the placement algorithm.
    pub new_holder_id: DeviceId,
    pub symbols_written: u32,
    /// Status of the new placement after repair.
    /// `Offered` if delivery was attempted (swarm present) or not configured.
    /// `Alive` only if delivery was confirmed synchronously (future: direct mode).
    pub new_placement_status: PlacementStatus,
}

/// Error type for repair operations.
#[derive(Debug, thiserror::Error)]
pub enum RepairError {
    #[error("source block file not found: {0}")]
    SourceBlockMissing(SourceBlockId),

    #[error("source block record missing from DB: {0}")]
    RecordMissing(SourceBlockId),

    #[error("placement record missing from DB: block={0} holder={1}")]
    PlacementMissing(SourceBlockId, DeviceId),

    #[error("erasure encode failed: {0}")]
    EncodeFailed(String),

    /// No viable holder found after excluding the failed holder.
    /// This is a transient condition (peers may come online later).
    /// Logged at WARN, not ERROR.
    #[error("no suitable holder for block {0}: {1}")]
    NoSuitableHolder(SourceBlockId, syncback_core::placement::PlacementError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("db error: {0}")]
    Db(#[from] DbError),

    #[error("delivery failed for block {0} to holder {1}: {2}")]
    DeliveryFailed(SourceBlockId, DeviceId, String),
}

/// Trigger message sent to the RepairAgent via channel.
#[derive(Debug)]
pub enum RepairTrigger {
    /// Immediate repair of a specific placement.
    RepairNow {
        block_id: SourceBlockId,
        holder_id: DeviceId,
    },
    /// Full scan (same as periodic).
    ScanAll,
}

// ============================================================
// RepairAgent
// ============================================================

/// RepairAgent: scans for Lost/PresumedLost placements and delivers repaired symbols
/// to new holders via the SymbolOffer/Accept/Transfer flow.
pub struct RepairAgent {
    db: Db,
    config: RepairConfig,
    encoder: Arc<dyn ErasureEncoder>,
}

impl RepairAgent {
    /// Create a new RepairAgent.
    pub fn new(db: Db, config: RepairConfig, encoder: Arc<dyn ErasureEncoder>) -> Self {
        RepairAgent { db, config, encoder }
    }

    /// Scan DB for placements needing repair and execute all repair jobs.
    ///
    /// Returns (repaired_count, failed_count).
    /// Individual failures are logged but do not abort the scan.
    /// NoSuitableHolder is logged at WARN; all other errors at ERROR.
    pub async fn scan_and_repair(&self) -> (usize, usize) {
        let needing_repair = match self.db.list_placements_needing_repair() {
            Ok(list) => list,
            Err(e) => {
                tracing::error!("scan_and_repair: list_placements_needing_repair failed: {e}");
                return (0, 0);
            }
        };

        if needing_repair.is_empty() {
            tracing::debug!("scan_and_repair: no placements needing repair");
            return (0, 0);
        }

        tracing::info!(count = needing_repair.len(), "scan_and_repair: starting repair batch");

        let mut repaired = 0usize;
        let mut failed = 0usize;

        for placement in &needing_repair {
            match self
                .repair_placement(&placement.source_block_id, &placement.holder_id)
                .await
            {
                Ok(outcome) => {
                    tracing::info!(
                        block_id = %outcome.job.source_block_id,
                        old_holder = %outcome.job.old_holder_id,
                        new_holder = %outcome.new_holder_id,
                        symbols_written = outcome.symbols_written,
                        new_status = ?outcome.new_placement_status,
                        "repair_placement: success"
                    );
                    repaired += 1;
                }
                Err(RepairError::NoSuitableHolder(bid, ref e)) => {
                    tracing::warn!(
                        block_id = %bid,
                        "repair_placement: no suitable holder (transient): {e}"
                    );
                    failed += 1;
                }
                Err(RepairError::PlacementMissing(bid, hid)) => {
                    // Placement was already repaired (idempotent path). Not a failure.
                    tracing::debug!(
                        block_id = %bid,
                        holder = %hid,
                        "repair_placement: placement missing (already repaired)"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        block_id = %placement.source_block_id,
                        holder_id = %placement.holder_id,
                        "repair_placement: failed: {e}"
                    );
                    failed += 1;
                }
            }
        }

        (repaired, failed)
    }

    /// Repair a single Lost/PresumedLost placement by selecting a new holder.
    ///
    /// Steps:
    ///  1. Load SourceBlockRecord (K, T, N, overhead) from DB.
    ///  2. Load old SymbolPlacement from DB.
    ///  3. Compute ESI offset: next_free_esi_for_block().
    ///  4. Build ErasureParams from block record.
    ///  5. Get peer candidates from DB; exclude old_holder_id.
    ///  6. compute_allocation(candidates, params, esi_offset).
    ///     → NoSuitableHolder if PlacementError returned.
    ///  7. Rebuild blob from source files (block.bin is normally absent after delivery).
    ///  8. Encode symbols for the new holder (spawn_blocking).
    ///  9. Write `{esi}.bin` files to `{symbols_dir}/{block_id_hex}/`.
    /// 10. Delete old SymbolPlacement from DB.
    /// 11. Insert new SymbolPlacement { status: Offered } into DB.
    /// 12. deliver_repaired_symbols(...) via swarm (if configured).
    /// 13. Clean up `.bin` files after delivery attempt.
    ///
    /// On error in steps 1–9: return Err, placement unchanged.
    /// On error in step 12 (delivery): return Ok(RepairOutcome) with status Offered.
    ///   The Offered placement will be retried by the scheduler's PoS loop.
    pub async fn repair_placement(
        &self,
        block_id: &SourceBlockId,
        old_holder_id: &DeviceId,
    ) -> Result<RepairOutcome, RepairError> {
        // 1. Get SourceBlockRecord for K, T, N, overhead
        let block_record = self
            .db
            .get_source_block(block_id)?
            .ok_or(RepairError::RecordMissing(*block_id))?;

        // 2. Get old SymbolPlacement (must exist and be Lost/PresumedLost)
        let old_placement = self
            .db
            .get_placement(block_id, old_holder_id)?
            .ok_or(RepairError::PlacementMissing(*block_id, *old_holder_id))?;

        let file_id = old_placement.file_id;

        // 3. Compute ESI offset: scan all placements for this block, take max + 1.
        let next_free_esi = self.next_free_esi_for_block(block_id)?;

        // 4. Compute ESI namespace offset from cluster state (same as backup pipeline).
        let namespace_start: u32 = 0; // Fallback; cluster state not available to repair without extra plumbing.
        // Note: RepairConfig does not hold cluster_state (it would create a circular dep).
        // In a multi-device cluster, the namespace_start would be fetched from ClusterState.
        // For now, we use max(0, next_free_esi) which correctly avoids collision with all
        // existing placements regardless of which device assigned them.
        let esi_offset = next_free_esi.max(namespace_start);

        // 5. Build ErasureParams from block record
        let k = block_record.k;
        let t = block_record.t;
        let overhead = block_record.overhead.unwrap_or(1.5);
        let importance = if overhead > 1.5 { (overhead - 1.5) / 1.5 } else { 0.5 };
        let n = block_record.n.unwrap_or(k * 2);
        let params = ErasureParams {
            k,
            k_eff: k + DECODE_OVERHEAD,
            t,
            overhead,
            n,
        };

        // 6. Get candidates excluding old holder.
        //    Use full allocation: include surviving holders in candidates so compute_allocation
        //    can distribute correctly, then take only the new holder's allocation.
        let candidates = self.get_candidates_excluding(old_holder_id)
            .map_err(|e| RepairError::EncodeFailed(format!("get_candidates: {e}")))?;

        // compute_allocation needs at least 2 candidates.
        let allocations = compute_allocation(&candidates, &params, esi_offset)
            .map_err(|e| RepairError::NoSuitableHolder(*block_id, e))?;

        // Pick the first allocation — compute_allocation sorts by descending symbol_count,
        // so the first entry is the highest-trust new holder.
        let new_alloc = allocations
            .into_iter()
            .next()
            .ok_or_else(|| {
                RepairError::NoSuitableHolder(
                    *block_id,
                    syncback_core::placement::PlacementError::NoCandidates,
                )
            })?;

        let new_holder_id = new_alloc.device_id;

        // 7. Rebuild blob from source files (block.bin is normally absent after delivery).
        let source_data = self.load_or_rebuild_blob(block_id).await?;

        // 8. Encode symbols for the new holder (spawn_blocking for CPU-bound work).
        let source_data_clone = source_data.clone();
        let params_clone = params;
        let block_id_clone = *block_id;
        let new_holder_clone = new_holder_id;
        let start_esi = new_alloc.start_esi;
        let symbol_count = new_alloc.symbol_count;
        let encoder = Arc::clone(&self.encoder);

        let symbols = tokio::task::spawn_blocking(move || {
            encoder.encode(
                &source_data_clone,
                &params_clone,
                start_esi,
                symbol_count,
                &block_id_clone,
                &new_holder_clone,
            )
        })
        .await
        .map_err(|e| RepairError::EncodeFailed(e.to_string()))?
        .map_err(|e| RepairError::EncodeFailed(e.to_string()))?;

        // 9. Write `{esi}.bin` files to `{symbols_dir}/{block_id_hex}/`
        let block_hex = hex_encode(&block_id.0);
        let block_dir = self.config.symbols_dir.join(&block_hex);
        tokio::fs::create_dir_all(&block_dir).await.map_err(RepairError::Io)?;

        let symbols_written = symbols.len() as u32;
        for symbol in &symbols {
            let sym_path = block_dir.join(format!("{}.bin", symbol.esi));
            tokio::fs::write(&sym_path, &symbol.data)
                .await
                .map_err(RepairError::Io)?;
        }

        // 10. Delete old placement from DB.
        self.db.delete_placement(block_id, old_holder_id)?;

        // 11. Insert new placement with status Offered.
        let seed = binding_seed(block_id, &new_holder_id);
        let new_placement = SymbolPlacement {
            source_block_id: *block_id,
            holder_id: new_holder_id,
            file_id,
            esi_ranges: vec![new_alloc.esi_range()],
            binding_seed: seed,
            status: PlacementStatus::Offered,
            last_verified: None,
            placed_at: Timestamp::now(),
            consecutive_misses: 0,
        };
        self.db.upsert_placement(&new_placement)?;

        // 12. Deliver repaired symbols via swarm (if configured).
        //     Delivery failures are non-fatal: the Offered placement will be retried.
        if let Err(e) = self
            .deliver_repaired_symbols(block_id, &new_placement, importance)
            .await
        {
            tracing::warn!(
                block_id = %block_id,
                new_holder = %new_holder_id,
                "repair: delivery failed (placement remains Offered for retry): {e}"
            );
            // Do NOT clean up .bin files — delivery may be retried.
            return Ok(RepairOutcome {
                job: RepairJob {
                    source_block_id: *block_id,
                    old_holder_id: *old_holder_id,
                    file_id,
                },
                new_holder_id,
                symbols_written,
                new_placement_status: PlacementStatus::Offered,
            });
        }

        // 13. Clean up .bin files after successful delivery.
        self.cleanup_repaired_symbols(block_id, &new_placement).await;

        Ok(RepairOutcome {
            job: RepairJob {
                source_block_id: *block_id,
                old_holder_id: *old_holder_id,
                file_id,
            },
            new_holder_id,
            symbols_written,
            new_placement_status: PlacementStatus::Offered,
        })
    }

    /// Process an incoming SymbolDropped message — mark placement Lost.
    ///
    /// Idempotent: if placement is already Lost or Deleting, no-op.
    pub async fn handle_symbol_dropped(
        &self,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
        now: Timestamp,
    ) -> Result<(), RepairError> {
        self.mark_placement_lost(block_id, holder_id, now).await
    }

    /// Process an incoming PosNack message — mark placement Lost.
    ///
    /// Equivalent to handle_symbol_dropped from the owner's perspective.
    /// Idempotent: if placement is already Lost or Deleting, no-op.
    pub async fn handle_pos_nack(
        &self,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
        now: Timestamp,
    ) -> Result<(), RepairError> {
        self.mark_placement_lost(block_id, holder_id, now).await
    }

    /// Run as a periodic background task.
    ///
    /// Every scan_interval_secs, calls scan_and_repair().
    /// Also accepts repair triggers via the rx channel for immediate repairs.
    /// Exits cleanly when rx is dropped (channel closed).
    pub async fn run(
        self,
        scan_interval_secs: u64,
        mut rx: tokio::sync::mpsc::Receiver<RepairTrigger>,
    ) -> anyhow::Result<()> {
        use tokio::time::{interval, Duration, MissedTickBehavior};

        let mut timer = interval(Duration::from_secs(scan_interval_secs));
        timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = timer.tick() => {
                    tracing::info!("RepairAgent: periodic scan triggered");
                    self.scan_and_repair().await;
                }
                maybe_trigger = rx.recv() => {
                    match maybe_trigger {
                        None => {
                            tracing::info!("RepairAgent: trigger channel closed, exiting");
                            break;
                        }
                        Some(RepairTrigger::ScanAll) => {
                            tracing::debug!("RepairAgent: ScanAll trigger received");
                            self.scan_and_repair().await;
                        }
                        Some(RepairTrigger::RepairNow { block_id, holder_id }) => {
                            tracing::debug!(
                                block_id = %block_id,
                                holder_id = %holder_id,
                                "RepairAgent: RepairNow trigger received"
                            );
                            if let Err(e) = self.repair_placement(&block_id, &holder_id).await {
                                match &e {
                                    RepairError::NoSuitableHolder(_, _) => {
                                        tracing::warn!("RepairNow: no suitable holder: {e}");
                                    }
                                    _ => {
                                        tracing::error!("RepairNow failed: {e}");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Compute the next free ESI for a source block.
    ///
    /// Scans all SymbolPlacements for block_id, finds the maximum
    /// assigned ESI across all placements (excluding Lost and Deleting),
    /// and returns max + 1. Returns 0 if no such placements exist.
    ///
    /// This ensures new repair ESIs never collide with surviving placements.
    fn next_free_esi_for_block(&self, block_id: &SourceBlockId) -> Result<u32, RepairError> {
        let placements = self.db.list_placements_for_block(block_id)?;
        let max_end = placements
            .iter()
            .filter(|p| {
                !matches!(p.status, PlacementStatus::Lost | PlacementStatus::Deleting)
            })
            .flat_map(|p| p.esi_ranges.iter())
            .map(|(start, count)| start.saturating_add(*count))
            .max()
            .unwrap_or(0);
        Ok(max_end)
    }

    /// Get holder candidates from DB, excluding one device_id.
    ///
    /// Same trust formula as BackupCoordinator::get_candidates().
    /// Excludes `exclude` from the returned list.
    fn get_candidates_excluding(
        &self,
        exclude: &DeviceId,
    ) -> anyhow::Result<Vec<HolderCandidate>> {
        let peers = self.db.list_all_peers()?;
        let candidates = peers
            .into_iter()
            .filter(|p| &p.device_id != exclude)
            .map(|p| {
                let trust_raw = (syncback_core::constants::KP * p.trust_p
                    + syncback_core::constants::KI * p.trust_i)
                    * p.trust_s.clamp(
                        syncback_core::constants::S_CLAMP_MIN,
                        syncback_core::constants::S_CLAMP_MAX,
                    );
                HolderCandidate {
                    device_id: p.device_id,
                    trust: trust_raw.clamp(0.0, 0.999),
                }
            })
            .collect();
        Ok(candidates)
    }

    /// Deliver symbols to a new holder using the SymbolOffer/Accept/Transfer flow.
    ///
    /// Reuses backup pipeline delivery logic (read_symbols_for_holder + swarm).
    /// Returns Ok(()) if no swarm is configured (no-op for unit tests).
    async fn deliver_repaired_symbols(
        &self,
        block_id: &SourceBlockId,
        placement: &SymbolPlacement,
        importance: f64,
    ) -> anyhow::Result<()> {
        use syncback_core::messages::Message;
        use syncback_core::types::Timestamp;

        let swarm = match self.config.swarm.as_ref() {
            Some(s) => s.clone(),
            None => {
                tracing::debug!("deliver_repaired_symbols: no swarm configured, skipping");
                return Ok(());
            }
        };

        let signing_key = match self.config.master_signing_key.as_ref() {
            Some(k) => k,
            None => {
                // No signing key: fall back to direct SymbolTransfer.
                return self
                    .deliver_repaired_symbols_direct(&swarm, block_id, placement)
                    .await;
            }
        };

        // Build signed SymbolOffer.
        let msg_id: [u8; 16] = rand::random();
        let timestamp = Timestamp::now();
        let offer = syncback_core::messages::build_symbol_offer(
            msg_id,
            *block_id,
            placement.esi_ranges.clone(),
            importance,
            timestamp,
            signing_key,
        );

        // Send SymbolOffer and wait for reply (request-response via libp2p).
        let reply = swarm
            .send_to_device(placement.holder_id, Message::SymbolOffer(offer))
            .await
            .map_err(|e| anyhow::anyhow!("send SymbolOffer: {e}"))?;

        match reply {
            Message::SymbolAccept(_accept) => {
                // Holder accepted — send SymbolTransfer.
                self.deliver_repaired_symbols_direct(&swarm, block_id, placement)
                    .await
            }
            Message::SymbolReject(reject) => {
                anyhow::bail!(
                    "holder {} rejected offer for block {}: {:?}",
                    placement.holder_id,
                    block_id,
                    reject.reason
                )
            }
            other => {
                anyhow::bail!(
                    "unexpected reply to SymbolOffer from {}: {:?}",
                    placement.holder_id,
                    std::mem::discriminant(&other)
                )
            }
        }
    }

    /// Direct SymbolTransfer delivery via libp2p swarm.
    async fn deliver_repaired_symbols_direct(
        &self,
        swarm: &crate::daemon::network::swarm::SwarmHandle,
        block_id: &SourceBlockId,
        placement: &SymbolPlacement,
    ) -> anyhow::Result<()> {
        use syncback_core::constants::SYMBOL_TRANSFER_CHUNK_BUDGET_BYTES;
        use syncback_core::erasure::chunk_symbols_by_size;
        use syncback_core::messages::{Message, SymbolTransferMsg};
        use syncback_core::types::Timestamp;

        let symbols = crate::daemon::backup::pipeline::read_symbols_for_holder(
            &self.config.symbols_dir,
            block_id,
            &placement.esi_ranges,
        )?;

        if symbols.is_empty() {
            anyhow::bail!(
                "no symbol files found for block {} holder {}",
                block_id,
                placement.holder_id
            );
        }

        let symbol_count = symbols.len();
        let chunks = chunk_symbols_by_size(symbols, SYMBOL_TRANSFER_CHUNK_BUDGET_BYTES);
        let total_chunks = chunks.len();
        for (idx, chunk) in chunks.into_iter().enumerate() {
            let msg = SymbolTransferMsg {
                v: 1,
                source_block_id: *block_id,
                symbols: chunk,
                timestamp: Timestamp::now(),
            };
            swarm
                .send_to_device(placement.holder_id, Message::SymbolTransfer(msg))
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "send_symbols chunk {}/{}: {}",
                        idx + 1,
                        total_chunks,
                        e
                    )
                })?;
        }

        tracing::info!(
            holder = %placement.holder_id,
            block_id = %block_id,
            symbols = symbol_count,
            chunks = total_chunks,
            "repair: symbols delivered"
        );

        Ok(())
    }

    /// Clean up .bin files written during repair after successful delivery.
    async fn cleanup_repaired_symbols(
        &self,
        block_id: &SourceBlockId,
        placement: &SymbolPlacement,
    ) {
        let block_hex = hex_encode(&block_id.0);
        let block_dir = self.config.symbols_dir.join(&block_hex);

        for &(start_esi, count) in &placement.esi_ranges {
            for i in 0..count {
                let esi = start_esi + i;
                let path = block_dir.join(format!("{esi}.bin"));
                if let Err(e) = tokio::fs::remove_file(&path).await {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(path = %path.display(), "repair: failed to remove symbol file: {e}");
                    }
                }
            }
        }
    }

    /// Load block.bin from disk, or rebuild it from source files, or fetch it
    /// from holders over the network — in that order.
    ///
    /// Encryption is deterministic (nonce = HKDF(epoch_key, blake3(compressed))),
    /// so re-running compress_and_encrypt on the same plaintext produces the
    /// exact same blob with the same block_id. Likewise, decoding `k_eff`
    /// symbols fetched from holders and truncating to `encrypted_size` yields
    /// the same stored blob bit-for-bit.
    ///
    /// Fallback order (single attempt each, D2):
    ///   1. `block.bin` from `source_blocks_dir`
    ///   2. Re-run compress/encrypt on source files (rebuild_plaintext_from_db)
    ///   3. Fetch k_eff unbound symbols from Alive holders, decode, truncate
    ///
    /// If all three fail the caller (repair_placement) logs at ERROR (D3);
    /// no new `PermanentlyLost` status is introduced.
    async fn load_or_rebuild_blob(
        &self,
        block_id: &SourceBlockId,
    ) -> Result<Vec<u8>, RepairError> {
        let block_file_path = self
            .config
            .source_blocks_dir
            .join(hex_encode(&block_id.0))
            .join("block.bin");

        // (1) block.bin fast path.
        match tokio::fs::read(&block_file_path).await {
            Ok(data) => return Ok(data),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(block_id = %block_id, "block.bin missing, attempting rebuild from source files");
            }
            Err(e) => return Err(RepairError::Io(e)),
        }

        let block_record = self
            .db
            .get_source_block(block_id)?
            .ok_or(RepairError::RecordMissing(*block_id))?;

        // (2) Rebuild from source files.
        match self.rebuild_blob_from_source(block_id, &block_record).await {
            Ok(stored) => {
                tracing::info!(block_id = %block_id, "repair: rebuilt blob from source files");
                return Ok(stored);
            }
            Err(e) => {
                tracing::warn!(
                    block_id = %block_id,
                    "repair: local rebuild failed ({e}); falling back to fetch from holders"
                );
            }
        }

        // (3) Network fallback: fetch from holders and decode.
        self.fetch_and_rebuild_blob(block_id, &block_record).await
    }

    /// Re-run the backup pipeline (read source files → compress → encrypt)
    /// and verify the resulting blob's hash equals `block_id`.
    async fn rebuild_blob_from_source(
        &self,
        block_id: &SourceBlockId,
        block_record: &syncback_core::types::SourceBlockRecord,
    ) -> Result<Vec<u8>, RepairError> {
        let plaintext = crate::daemon::backup::packing::rebuild_plaintext_from_db(
            &self.db,
            block_record,
        )
        .map_err(|e| RepairError::EncodeFailed(format!("rebuild plaintext: {e}")))?;

        let epoch_key = self.config.epoch_key;
        let expected_id = *block_id;

        let stored = tokio::task::spawn_blocking(move || {
            crate::daemon::backup::pipeline::compress_and_encrypt(&plaintext, &epoch_key)
        })
        .await
        .map_err(|e| RepairError::EncodeFailed(e.to_string()))?
        .map_err(|e| RepairError::EncodeFailed(e.to_string()))?;

        let rebuilt_id: [u8; 32] = *blake3::hash(&stored).as_bytes();
        if rebuilt_id != expected_id.0 {
            return Err(RepairError::EncodeFailed(format!(
                "rebuilt blob hash {} != expected block_id {}",
                hex_encode(&rebuilt_id),
                hex_encode(&expected_id.0),
            )));
        }
        Ok(stored)
    }

    /// Fetch k_eff unbound symbols from Alive holders, decode, truncate to
    /// `encrypted_size` — yielding the same ciphertext that was originally
    /// stored as `block.bin`.
    ///
    /// Escrow (D1): holders may reply with `RestoreDenied`; the shared
    /// `symbol_fetch` helper skips them and keeps collecting from the next
    /// holder. If fewer than `k_eff` unbound symbols arrive, returns
    /// `EncodeFailed` (the caller logs at ERROR — D3).
    async fn fetch_and_rebuild_blob(
        &self,
        block_id: &SourceBlockId,
        block_record: &syncback_core::types::SourceBlockRecord,
    ) -> Result<Vec<u8>, RepairError> {
        let swarm = match self.config.swarm.as_ref() {
            Some(s) => s,
            None => {
                return Err(RepairError::EncodeFailed(
                    "no swarm configured; cannot fetch from holders".to_string(),
                ));
            }
        };

        let encrypted_size = block_record.encrypted_size.ok_or_else(|| {
            RepairError::EncodeFailed(format!(
                "block {block_id} has no encrypted_size (legacy record); cannot fetch and rebuild"
            ))
        })?;
        let params = block_record.erasure_params();
        let k_eff = params.k_eff as usize;

        // SymbolPlacement rows describe symbols stored by *other* devices for
        // blocks this node owns — there are no placements where holder == self,
        // so no self-filter is needed here.
        let placements = self.db.list_placements_for_block(block_id)?;
        let reachable: Vec<_> = placements
            .into_iter()
            .filter(|p| matches!(
                p.status,
                syncback_core::types::PlacementStatus::Alive
                    | syncback_core::types::PlacementStatus::Uncertain
                    | syncback_core::types::PlacementStatus::PresumedLost
            ))
            .collect();

        if reachable.is_empty() {
            return Err(RepairError::EncodeFailed(format!(
                "no reachable placements for block {block_id}; cannot fetch"
            )));
        }

        tracing::info!(
            block_id = %block_id,
            reachable = reachable.len(),
            k_eff,
            "repair: fetching symbols from holders to rebuild lost blob"
        );

        let unbound = crate::daemon::symbol_fetch::fetch_unbound_symbols(
            swarm,
            &self.encoder,
            block_id,
            &reachable,
            k_eff,
        )
        .await
        .map_err(|e| RepairError::EncodeFailed(format!("fetch_unbound_symbols: {e}")))?;

        // Decode + truncate in spawn_blocking (decode is CPU-heavy).
        let encoder = Arc::clone(&self.encoder);
        let expected_id = *block_id;
        let stored = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, RepairError> {
            let padded = encoder
                .decode(&unbound, &params)
                .map_err(|e| RepairError::EncodeFailed(format!("decode: {e}")))?;

            if padded.len() < encrypted_size as usize {
                return Err(RepairError::EncodeFailed(format!(
                    "decoded block ({} bytes) smaller than encrypted_size ({})",
                    padded.len(),
                    encrypted_size
                )));
            }
            let stored = padded[..encrypted_size as usize].to_vec();

            // Verify hash — this is our integrity check for the fetched blob.
            let rebuilt_id: [u8; 32] = *blake3::hash(&stored).as_bytes();
            if rebuilt_id != expected_id.0 {
                return Err(RepairError::EncodeFailed(format!(
                    "fetched blob hash {} != expected block_id {}",
                    hex_encode(&rebuilt_id),
                    hex_encode(&expected_id.0),
                )));
            }
            Ok(stored)
        })
        .await
        .map_err(|e| RepairError::EncodeFailed(e.to_string()))??;

        tracing::info!(
            block_id = %block_id,
            "repair: rebuilt blob from holder symbols (network fallback)"
        );
        Ok(stored)
    }

    /// Mark a placement as Lost. Idempotent: no-op if already Lost or Deleting.
    async fn mark_placement_lost(
        &self,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
        _now: Timestamp,
    ) -> Result<(), RepairError> {
        let placement = self
            .db
            .get_placement(block_id, holder_id)?
            .ok_or(RepairError::PlacementMissing(*block_id, *holder_id))?;

        // Idempotent: already lost or deleting → no-op
        if placement.status == PlacementStatus::Lost
            || placement.status == PlacementStatus::Deleting
        {
            return Ok(());
        }

        let mut updated = placement;
        updated.status = PlacementStatus::Lost;
        updated.consecutive_misses = 0;
        self.db.upsert_placement(&updated)?;

        tracing::info!(
            block_id = %block_id,
            holder_id = %holder_id,
            "placement marked Lost (explicit drop/nack)"
        );

        Ok(())
    }
}
