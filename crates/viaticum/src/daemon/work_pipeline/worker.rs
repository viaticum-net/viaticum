// WorkPipeline worker: one encode+deliver cycle for a single block.
//
// This is the core of Wave 11b: replaces both BackupCoordinator::deliver_symbols
// and RepairAgent::repair_placement with a single unified path.
//
// Key invariants:
//   I1: encode_raw called once per block per iteration (not per holder).
//   I2: No disk writes — raw symbols held in RAM, dropped after iteration.
//   I3: CPU-bound encode_raw wrapped in spawn_blocking.
//   I4: Cooldown updated unconditionally at end of iteration.
//
// TODO: this function duplicates deliver_to_holder from BackupCoordinator.
// See spec R6: duplication is intentional — worker context differs from coordinator.
// Future: extract shared delivery helper if the implementations diverge.

use std::sync::{Arc, Mutex};

use viaticum_core::cluster::{ClusterState, esi_namespace_start};
use viaticum_core::constants::DECODE_OVERHEAD;
use viaticum_core::db::Db;
use viaticum_core::erasure::{ErasureEncoder, binding_seed};
use viaticum_core::placement::{HolderCandidate, compute_allocation_with_importance};
use viaticum_core::types::{
    DeviceId, ErasureParams, PlacementStatus, SourceBlockId, SourceBlockRecord, SymbolPlacement,
    Timestamp,
};

use super::{WorkPipelineConfig, pool::PoolSnapshot};
use crate::daemon::network::swarm::SwarmHandle;
use crate::daemon::peer_backoff::PeerBackoff;

/// Outcome of one block encode+deliver cycle.
#[derive(Debug)]
pub(crate) struct WorkOutcome {
    /// Number of holders that returned SymbolStored acks (Offered→Alive).
    pub acked: usize,
    /// Number of holders that failed or timed out.
    pub failed: usize,
    /// Whether encoding was actually run.
    pub encoded: bool,
}

/// Execute one encode+deliver cycle for the given block.
///
/// Steps:
///  1. Load source blob via `rebuild_source_blob` (re-encodes from source files).
///  2. Compute ErasureParams from block record.
///  3. Compute esi_offset = sum of alive/offered symbol counts (non-overlapping namespace).
///  4. Compute allocations via `compute_allocation_with_importance`.
///  5. `encode_raw` once (spawn_blocking — CPU-bound ~30s for 128MB).
///  6. For each allocation: bind symbols inline, send SymbolOffer → SymbolAccept → SymbolTransfer.
///     On `SymbolStored`: transition Offered→Alive + recompute cached fields.
///  7. Drop raw symbols (no disk spill).
///
/// Cooldown (`last_attempted_at`, `last_pool_signature`) is updated by the caller
/// (in `run_iteration`) unconditionally after this function returns.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_block_iteration(
    db: &Db,
    config: &WorkPipelineConfig,
    encoder: &Arc<dyn ErasureEncoder>,
    swarm: &SwarmHandle,
    master_signing_key: Option<&ed25519_dalek::SigningKey>,
    peer_backoff: Option<&PeerBackoff>,
    cluster_state: Option<&Arc<Mutex<ClusterState>>>,
    block: &SourceBlockRecord,
    pool: &PoolSnapshot,
) -> anyhow::Result<WorkOutcome> {
    // 1. Obtain the source blob. SystemState blocks have no backing watch-dir file:
    //    their encoded blob is retained on disk (blake3 == block_id), so load it
    //    directly. All other blocks rebuild from source files (deterministic).
    let source_data = match crate::daemon::system_state::block::try_load_retained_block(
        &config.data_dir,
        &block.block_id,
    )? {
        Some(blob) => blob,
        None => crate::daemon::backup::pipeline::rebuild_source_blob(db, block, &config.epoch_key)
            .await
            .map_err(|e| anyhow::anyhow!("rebuild_source_blob: {e}"))?,
    };

    // 2. Compute ErasureParams.
    let k = block.k;
    let t = block.t;
    let overhead = block.overhead.unwrap_or(1.5);
    let n = block.n.unwrap_or(k * 2);
    let params = ErasureParams {
        k,
        k_eff: k + DECODE_OVERHEAD,
        t,
        overhead,
        n,
    };

    // 3. Compute esi_offset: sum of all alive/offered symbol counts for this block.
    //    This ensures new ESIs don't overlap with existing placements.
    let esi_offset = compute_esi_offset(db, &block.block_id, cluster_state, &config.device_id)?;

    // 4. Compute allocations for available candidates.
    //    Filter out candidates that already hold symbols for this block.
    let existing_holders = get_existing_holder_ids(db, &block.block_id)?;
    let candidates: Vec<HolderCandidate> = pool
        .candidates
        .iter()
        .filter(|c| !existing_holders.contains(&c.device_id))
        .cloned()
        .collect();

    if candidates.is_empty() {
        tracing::info!(
            block_id = %block.block_id,
            "work_pipeline: no new candidates (all pool peers already holding)"
        );
        return Ok(WorkOutcome {
            acked: 0,
            failed: 0,
            encoded: false,
        });
    }

    let allocations = match compute_allocation_with_importance(
        &candidates,
        block.encrypted_size.unwrap_or(0),
        block.importance,
        esi_offset,
    ) {
        Ok(a) if !a.is_empty() => a,
        Ok(_) => {
            tracing::info!(
                block_id = %block.block_id,
                "work_pipeline: compute_allocation returned empty (too few candidates)"
            );
            return Ok(WorkOutcome {
                acked: 0,
                failed: 0,
                encoded: false,
            });
        }
        Err(e) => {
            tracing::warn!(
                block_id = %block.block_id,
                "work_pipeline: compute_allocation failed: {e}"
            );
            return Ok(WorkOutcome {
                acked: 0,
                failed: 0,
                encoded: false,
            });
        }
    };

    // 5. Encode once for all allocations combined.
    let total_count: u32 = allocations.iter().map(|a| a.symbol_count).sum();
    let source_data_arc = Arc::new(source_data);
    let params_clone = params;
    let encoder_clone = Arc::clone(encoder);
    let source_clone = Arc::clone(&source_data_arc);

    let raw_symbols = tokio::task::spawn_blocking(move || {
        encoder_clone.encode_raw(&source_clone, &params_clone, esi_offset, total_count)
    })
    .await
    .map_err(|e| anyhow::anyhow!("spawn_blocking join: {e}"))?
    .map_err(|e| anyhow::anyhow!("encode_raw: {e}"))?;

    // Drop source data early — it's no longer needed.
    drop(source_data_arc);

    tracing::debug!(
        block_id = %block.block_id,
        symbols = raw_symbols.len(),
        esi_offset,
        "work_pipeline: encoded raw symbols"
    );

    // 6. Insert placements as Offered, then deliver to each holder.
    let now = Timestamp::now();
    let primary_file_id = db
        .list_placements_for_block(&block.block_id)?
        .first()
        .map(|p| p.file_id)
        .unwrap_or(viaticum_core::types::FileId(0));

    // Insert all Offered placements before delivery (so retries see them).
    let mut txn = db.write_txn()?;
    for alloc in &allocations {
        let seed = binding_seed(&block.block_id, &alloc.device_id);
        let placement = SymbolPlacement {
            source_block_id: block.block_id,
            holder_id: alloc.device_id,
            file_id: primary_file_id,
            esi_ranges: vec![alloc.esi_range()],
            binding_seed: seed,
            status: PlacementStatus::Offered,
            last_verified: None,
            placed_at: now,
            consecutive_misses: 0,
        };
        txn.upsert_placement(&placement)?;

        // Also record in event log.
        let entry = viaticum_core::types::EventEntry {
            timestamp: now,
            device_id: config.device_id,
            event: viaticum_core::types::Event::SymbolsPlaced {
                source_block_id: block.block_id,
                holder_id: alloc.device_id,
                esi_range: alloc.esi_range(),
            },
        };
        txn.append_event(&entry)?;
    }
    txn.commit()?;

    // 7. Deliver to each holder (binding applied inline at send time).
    let mut acked = 0usize;
    let mut failed = 0usize;

    for alloc in &allocations {
        // Load the Offered placement just inserted.
        let placement = match db.get_placement(&block.block_id, &alloc.device_id) {
            Ok(Some(p)) => p,
            Ok(None) => {
                tracing::warn!(
                    block_id = %block.block_id,
                    holder = %alloc.device_id,
                    "work_pipeline: placement not found after insert (race?)"
                );
                failed += 1;
                continue;
            }
            Err(e) => {
                tracing::error!(
                    block_id = %block.block_id,
                    holder = %alloc.device_id,
                    "work_pipeline: DB error loading placement: {e}"
                );
                failed += 1;
                continue;
            }
        };

        match deliver_to_holder_worker(
            db,
            encoder,
            swarm,
            master_signing_key,
            peer_backoff,
            block,
            &placement,
            &raw_symbols,
            esi_offset,
            block.importance,
        )
        .await
        {
            Ok(true) => {
                acked += 1;
            }
            Ok(false) => {
                // Delivery attempted but no full ack (placement left Offered).
                failed += 1;
            }
            Err(e) => {
                tracing::warn!(
                    block_id = %block.block_id,
                    holder = %alloc.device_id,
                    "work_pipeline: deliver_to_holder_worker failed: {e}"
                );
                failed += 1;
            }
        }
    }

    // 8. Drop raw symbols explicitly (no disk spill).
    drop(raw_symbols);

    Ok(WorkOutcome {
        acked,
        failed,
        encoded: true,
    })
}

/// Deliver symbols for one (block, holder) pair using SymbolOffer/Accept/Transfer flow.
///
/// Returns Ok(true) if the holder acked all chunks (Offered→Alive transitioned).
/// Returns Ok(false) if delivery was attempted but not all chunks acked.
/// Returns Err on network or DB error.
#[allow(clippy::too_many_arguments)]
async fn deliver_to_holder_worker(
    db: &Db,
    encoder: &Arc<dyn ErasureEncoder>,
    swarm: &SwarmHandle,
    master_signing_key: Option<&ed25519_dalek::SigningKey>,
    peer_backoff: Option<&PeerBackoff>,
    block: &SourceBlockRecord,
    placement: &SymbolPlacement,
    raw_symbols: &[viaticum_core::erasure::Symbol],
    esi_offset: u32,
    importance: f64,
) -> anyhow::Result<bool> {
    use viaticum_core::messages::Message;

    // If signing key is present, use SymbolOffer/Accept/Transfer handshake.
    if let Some(signing_key) = master_signing_key {
        let msg_id: [u8; 16] = rand::random();
        let timestamp = Timestamp::now();
        let offer = viaticum_core::messages::build_symbol_offer(
            msg_id,
            block.block_id,
            placement.esi_ranges.clone(),
            importance,
            timestamp,
            signing_key,
        );

        let reply = swarm
            .send_to_device(placement.holder_id, Message::SymbolOffer(offer))
            .await
            .map_err(|e| anyhow::anyhow!("send SymbolOffer: {e}"))?;

        match reply {
            Message::SymbolAccept(_) => {
                if let Some(backoff) = peer_backoff {
                    backoff.record_accept(&placement.holder_id);
                }
                // Holder accepted — send the actual symbols.
                deliver_transfer_worker(
                    db,
                    encoder,
                    swarm,
                    &block.block_id,
                    placement,
                    raw_symbols,
                    esi_offset,
                )
                .await
            }
            Message::SymbolReject(reject) => {
                if let Some(backoff) = peer_backoff {
                    backoff.record_reject(placement.holder_id);
                }
                anyhow::bail!(
                    "holder {} rejected offer for block {}: {:?}",
                    placement.holder_id,
                    block.block_id,
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
    } else {
        // No signing key: fall back to direct SymbolTransfer.
        deliver_transfer_worker(
            db,
            encoder,
            swarm,
            &block.block_id,
            placement,
            raw_symbols,
            esi_offset,
        )
        .await
    }
}

/// Send SymbolTransfer chunks to a holder, wait for SymbolStored acks.
///
/// On full ack: transitions placement Offered→Alive + runs W11a hook.
/// Returns Ok(true) if all chunks were acked, Ok(false) otherwise.
async fn deliver_transfer_worker(
    db: &Db,
    encoder: &Arc<dyn ErasureEncoder>,
    swarm: &SwarmHandle,
    block_id: &SourceBlockId,
    placement: &SymbolPlacement,
    raw_symbols: &[viaticum_core::erasure::Symbol],
    esi_offset: u32,
) -> anyhow::Result<bool> {
    use viaticum_core::constants::SYMBOL_TRANSFER_CHUNK_BUDGET_BYTES;
    use viaticum_core::erasure::{Symbol, chunk_symbols_by_size};
    use viaticum_core::messages::{Message, SymbolTransferMsg};

    // Bind raw symbols inline at send time — no disk read.
    let bound: Vec<Symbol> = placement
        .esi_ranges
        .iter()
        .flat_map(|&(start_esi, count)| {
            (start_esi..start_esi + count).filter_map(|esi| {
                let idx = esi.checked_sub(esi_offset)? as usize;
                let raw = raw_symbols.get(idx)?;
                Some(encoder.apply_binding(raw.clone(), block_id, &placement.holder_id))
            })
        })
        .collect();

    if bound.is_empty() {
        anyhow::bail!(
            "no raw symbols available for block {} holder {} (esi_offset={}, raw_len={})",
            block_id,
            placement.holder_id,
            esi_offset,
            raw_symbols.len(),
        );
    }

    let symbol_count = bound.len();
    let chunks = chunk_symbols_by_size(bound, SYMBOL_TRANSFER_CHUNK_BUDGET_BYTES);
    let total_chunks = chunks.len();
    let mut stored_ok = 0usize;
    let mut saw_old_protocol = false;

    for (idx, chunk) in chunks.into_iter().enumerate() {
        let chunk_len = chunk.len();
        let msg = SymbolTransferMsg {
            v: 1,
            source_block_id: *block_id,
            symbols: chunk,
            timestamp: Timestamp::now(),
        };
        let reply = swarm
            .send_to_device(placement.holder_id, Message::SymbolTransfer(msg))
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "send SymbolTransfer chunk {}/{}: {}",
                    idx + 1,
                    total_chunks,
                    e
                )
            })?;

        match reply {
            Message::SymbolStored(_) => {
                stored_ok += 1;
                tracing::debug!(
                    holder = %placement.holder_id,
                    block_id = %block_id,
                    chunk = idx + 1,
                    total = total_chunks,
                    symbols = chunk_len,
                    "work_pipeline: chunk stored",
                );
                // T-12 safety net: persist holder's dialable addrs learned from the
                // authenticated SymbolTransfer connection. This closes the window where
                // identify hasn't yet propagated the holder's addrs to the PeerRecord,
                // so on the next build_pointer_for_placed call the HolderHint.addrs
                // field will be populated for faster DR dialing.
                //
                // on_peer_identified is the primary source; this is the secondary
                // safety net for the case where identify fires after this point.
                //
                // If addrs are empty (identify not yet done) → skip: on_peer_identified
                // will update the record when identify completes. Empty addrs are fine:
                // DR falls back to Kademlia get_closest_peers(holder_id) per B-1.
                persist_holder_addrs_from_swarm(db, swarm, placement.holder_id).await;
            }
            Message::Ack(_) => {
                // Holder did not confirm storage with SymbolStored (transfer handler
                // failed, or an older/unhandled path replied with a generic Ack).
                saw_old_protocol = true;
            }
            other => {
                tracing::warn!(
                    holder = %placement.holder_id,
                    "work_pipeline: unexpected reply to SymbolTransfer: {:?}",
                    std::mem::discriminant(&other)
                );
            }
        }
    }

    if stored_ok == total_chunks {
        let now = Timestamp::now();
        match db.transition_placement_offered_to_alive(block_id, &placement.holder_id, now) {
            Ok(true) => {
                tracing::info!(
                    holder = %placement.holder_id,
                    block_id = %block_id,
                    symbols = symbol_count,
                    "work_pipeline: symbols confirmed stored, placement Offered→Alive"
                );
                crate::daemon::processor::recompute_and_persist_block_cached_fields(db, block_id);
                return Ok(true);
            }
            Ok(false) => {
                tracing::debug!(
                    holder = %placement.holder_id,
                    "work_pipeline: placement transition skipped (not in Offered state)"
                );
            }
            Err(e) => {
                tracing::error!(
                    holder = %placement.holder_id,
                    err = %e,
                    "work_pipeline: DB error transitioning Offered→Alive"
                );
            }
        }
    } else if saw_old_protocol {
        tracing::debug!(
            holder = %placement.holder_id,
            chunks_ok = stored_ok,
            chunks_total = total_chunks,
            "work_pipeline: holder replied Ack without SymbolStored; placement left Offered"
        );
    } else {
        tracing::warn!(
            holder = %placement.holder_id,
            block_id = %block_id,
            chunks_ok = stored_ok,
            chunks_total = total_chunks,
            "work_pipeline: not all chunks acked; placement left Offered"
        );
    }

    Ok(false)
}

/// Compute the ESI offset for new allocations: sum of alive/offered symbol counts.
///
/// Uses the cluster device namespace offset as the base, then adds existing
/// non-Lost symbol counts to avoid overlapping with existing placements.
fn compute_esi_offset(
    db: &Db,
    block_id: &SourceBlockId,
    cluster_state: Option<&Arc<Mutex<ClusterState>>>,
    device_id: &DeviceId,
) -> anyhow::Result<u32> {
    // Cluster-based namespace start.
    let namespace_start: u32 = cluster_state
        .and_then(|cs| {
            cs.lock()
                .ok()
                .and_then(|guard| guard.get_device(device_id).map(|e| e.device_index))
        })
        .map(esi_namespace_start)
        .unwrap_or(0);

    // Next free ESI = max end of all non-Lost placements.
    let placements = db.list_placements_for_block(block_id)?;
    let max_end = placements
        .iter()
        .filter(|p| !matches!(p.status, PlacementStatus::Lost | PlacementStatus::Deleting))
        .flat_map(|p| p.esi_ranges.iter())
        .map(|(start, count)| start.saturating_add(*count))
        .max()
        .unwrap_or(0);

    Ok(max_end.max(namespace_start))
}

/// T-12 safety net: query the swarm for a holder's identify-received listen addrs
/// and persist them to the PeerRecord if non-empty.
///
/// Called after the owner receives a `SymbolStored` ack from a holder. This
/// ensures the PeerRecord carries dialable addrs even when identify hasn't yet
/// propagated them through `on_peer_identified`.
///
/// If the swarm returns an empty addr list (identify not yet complete for this
/// peer), the function is a no-op — `on_peer_identified` will update the record
/// later when identify completes. Empty addrs are fine: DR uses Kademlia fallback.
pub(crate) async fn persist_holder_addrs_from_swarm(
    db: &Db,
    swarm: &SwarmHandle,
    holder_id: DeviceId,
) {
    let addrs = swarm.get_peer_addrs(holder_id).await;
    if addrs.is_empty() {
        return;
    }
    let addr_strings: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();
    persist_holder_addrs_to_db(db, holder_id, addr_strings);
}

/// T-12 inner: persist holder addr strings to the PeerRecord in DB.
///
/// Extracted for testability — callers provide pre-resolved addr strings.
/// No-op if addrs are empty or already match the stored value.
pub(crate) fn persist_holder_addrs_to_db(db: &Db, holder_id: DeviceId, addr_strings: Vec<String>) {
    if addr_strings.is_empty() {
        return;
    }
    match db.get_peer(&holder_id) {
        Ok(Some(mut record)) => {
            if record.addrs == addr_strings {
                return; // no-op: already up to date
            }
            record.addrs = addr_strings;
            if let Err(e) = db.upsert_peer(&record) {
                tracing::warn!(
                    holder = %holder_id,
                    err = %e,
                    "T-12: failed to persist holder addrs after SymbolStored"
                );
            } else {
                tracing::debug!(
                    holder = %holder_id,
                    "T-12: persisted holder addrs from SymbolStored connection"
                );
            }
        }
        Ok(None) => {
            // Peer record not yet in DB (rare: delivery happened before on_peer_authenticated).
            tracing::debug!(
                holder = %holder_id,
                "T-12: PeerRecord not found after SymbolStored — on_peer_identified will update later"
            );
        }
        Err(e) => {
            tracing::warn!(
                holder = %holder_id,
                err = %e,
                "T-12: db.get_peer failed in persist_holder_addrs_to_db"
            );
        }
    }
}

/// Get the set of DeviceIds with Alive symbols for this block.
/// Offered placements are NOT excluded — the worker retries delivery to peers
/// whose placement is Offered. See W11b spec Step 5:
/// `n_attempt = n_target - current_alive`.
pub(crate) fn get_existing_holder_ids(
    db: &Db,
    block_id: &SourceBlockId,
) -> anyhow::Result<std::collections::HashSet<DeviceId>> {
    let placements = db.list_placements_for_block(block_id)?;
    Ok(placements
        .into_iter()
        .filter(|p| matches!(p.status, PlacementStatus::Alive))
        .map(|p| p.holder_id)
        .collect())
}
