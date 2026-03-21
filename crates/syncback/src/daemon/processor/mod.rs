// Message Router (Processor): routes incoming connections and dispatches messages.
//
// Responsibilities:
//   - Accept new incoming connections from the network accept loop.
//   - Spawn a per-connection read loop for each connection.
//   - Dispatch received messages to the appropriate handler.
//
// Role separation:
//   PosChallenge received   → we are the holder  → load symbol, send PosResponse or PosNack
//   PosResponse received    → we are the owner   → verify, update trust/placement
//   PosNack received        → we are the owner   → mark placement Lost, trigger repair
//   SymbolTransfer received → we are the holder  → write symbols to disk, record HoldingRecord
//   SymbolDropped received  → we are the owner   → mark placement Lost, trigger repair
//   ClusterSyncRequest      → we are cluster peer → serve event log entries
//   ClusterSyncResponse     → we are cluster peer → apply received events
//
// Design note: PosResponseMsg on the wire does not carry source_block_id.
// We recover it by scanning placements for the holder and finding one whose
// ESI ranges include the challenged ESI. This is a Phase 6.3 simplification;
// Phase 6.5 (Scheduler) will track challenge context in a pending table.

use std::path::PathBuf;
use std::sync::Arc;

use syncback_core::constants::DECODE_OVERHEAD;
use syncback_core::db::{Db, WeeklyPosEntry};
use syncback_core::erasure::ErasureEncoder;
use syncback_core::messages::{
    ClusterSyncRequestMsg, ClusterSyncResponseMsg, Message, PosNackMsg, PosResponseMsg,
    SymbolDroppedMsg, SymbolTransferMsg,
};
use syncback_core::pos::{
    apply_pos_outcome, outcome_from_verify, verify_response, PosResponse, VerifyOutcome,
};
use syncback_core::trust::PosOutcome;
use syncback_core::types::{
    ErasureParams, HoldingRecord, HoldingStatus, IdentityPub, PlacementStatus, Timestamp,
};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::daemon::cluster_sync::ClusterSyncManager;
use crate::daemon::network::connection::Connection;
use crate::daemon::repair::RepairTrigger;

#[cfg(test)]
mod tests;

// ─── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ProcessorError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("db error: {0}")]
    Db(#[from] syncback_core::db::DbError),

    #[error("network error: {0}")]
    Network(#[from] crate::daemon::network::NetworkError),

    #[error("pos verify error: {0}")]
    PosVerify(#[from] syncback_core::pos::PosError),

    #[error("cluster sync error: {0}")]
    ClusterSync(#[from] crate::daemon::cluster_sync::ClusterSyncError),

    #[error("task join error: {0}")]
    Join(String),
}

// ─── Processor ────────────────────────────────────────────────────────────────

/// Routes incoming connections and dispatches messages to appropriate handlers.
pub struct Processor {
    db: Db,
    #[allow(dead_code)]
    own_identity: IdentityPub,
    repair_tx: mpsc::Sender<RepairTrigger>,
    cluster_sync: Arc<ClusterSyncManager>,
    encoder: Arc<dyn ErasureEncoder>,
    /// Directory where we store symbols held for others: `{holdings_dir}/{block_id_hex}/{esi}.bin`
    holdings_dir: PathBuf,
    /// Directory where our own source blocks live (for PoS verification as owner):
    /// `{source_blocks_dir}/{block_id_hex}/block.bin`
    source_blocks_dir: PathBuf,
}

impl Processor {
    /// Create a new Processor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Db,
        own_identity: IdentityPub,
        repair_tx: mpsc::Sender<RepairTrigger>,
        cluster_sync: Arc<ClusterSyncManager>,
        encoder: Arc<dyn ErasureEncoder>,
        holdings_dir: PathBuf,
        source_blocks_dir: PathBuf,
    ) -> Self {
        Processor {
            db,
            own_identity,
            repair_tx,
            cluster_sync,
            encoder,
            holdings_dir,
            source_blocks_dir,
        }
    }

    /// Main loop: accept connections and dispatch messages.
    ///
    /// Spawns a per-connection read task for each accepted connection.
    /// All received messages are funneled through a single channel and
    /// then dispatched via tokio::spawn (one task per message).
    pub async fn run(
        self,
        mut incoming_rx: mpsc::Receiver<Connection>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        let (msg_tx, mut msg_rx) =
            mpsc::channel::<(IdentityPub, Message, Arc<Mutex<Connection>>)>(256);
        let this = Arc::new(self);

        info!("processor running");

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("processor: cancellation requested, shutting down");
                    break;
                }

                maybe_conn = incoming_rx.recv() => {
                    match maybe_conn {
                        None => {
                            info!("processor: incoming_rx closed, shutting down");
                            break;
                        }
                        Some(conn) => {
                            let peer_id = conn.peer_identity;
                            let conn_arc = Arc::new(Mutex::new(conn));
                            let conn_arc2 = conn_arc.clone();
                            let tx = msg_tx.clone();

                            tokio::spawn(async move {
                                debug!(peer = %peer_id, "processor: read loop started");
                                loop {
                                    let msg = {
                                        let mut guard = conn_arc2.lock().await;
                                        match guard.recv_message().await {
                                            Ok(m) => m,
                                            Err(e) => {
                                                debug!(
                                                    peer = %peer_id,
                                                    err = %e,
                                                    "processor: connection closed"
                                                );
                                                break;
                                            }
                                        }
                                    };
                                    if tx.send((peer_id, msg, conn_arc2.clone())).await.is_err() {
                                        break;
                                    }
                                }
                                debug!(peer = %peer_id, "processor: read loop exited");
                            });
                        }
                    }
                }

                maybe_msg = msg_rx.recv() => {
                    match maybe_msg {
                        None => break,
                        Some((peer_id, msg, conn)) => {
                            let this2 = this.clone();
                            tokio::spawn(async move {
                                if let Err(e) = this2.dispatch(peer_id, msg, conn).await {
                                    error!(
                                        peer = %peer_id,
                                        err = %e,
                                        "processor: error handling message"
                                    );
                                }
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    // =========================================================
    // Message dispatch
    // =========================================================

    async fn dispatch(
        &self,
        from: IdentityPub,
        msg: Message,
        conn: Arc<Mutex<Connection>>,
    ) -> anyhow::Result<()> {
        match msg {
            Message::SymbolTransfer(transfer) => {
                self.handle_symbol_transfer(from, transfer).await?;
            }
            Message::PosChallenge(challenge) => {
                self.handle_pos_challenge(from, challenge, conn).await?;
            }
            Message::PosResponse(response) => {
                self.handle_pos_response(from, response).await?;
            }
            Message::PosNack(nack) => {
                self.handle_pos_nack(from, nack).await?;
            }
            Message::SymbolDropped(dropped) => {
                self.handle_symbol_dropped(from, dropped).await?;
            }
            Message::ClusterSyncRequest(request) => {
                self.handle_cluster_sync_request(from, request, conn)
                    .await?;
            }
            Message::ClusterSyncResponse(response) => {
                self.handle_cluster_sync_response(from, response).await?;
            }
            other => {
                debug!(
                    peer = %from,
                    "processor: unhandled message variant {:?}, ignoring",
                    std::mem::discriminant(&other)
                );
            }
        }
        Ok(())
    }

    // =========================================================
    // SymbolTransfer: we are the holder
    // =========================================================

    /// Store received symbols on disk and record a HoldingRecord in the DB.
    ///
    /// File layout: `{holdings_dir}/{block_id_hex}/{esi}.bin`
    pub(crate) async fn handle_symbol_transfer(
        &self,
        owner_id: IdentityPub,
        transfer: SymbolTransferMsg,
    ) -> Result<(), ProcessorError> {
        let block_id = transfer.source_block_id;
        let block_hex = to_hex(&block_id.0);
        let block_dir = self.holdings_dir.join(&block_hex);

        tokio::fs::create_dir_all(&block_dir).await?;

        let mut received_esis: Vec<u32> = Vec::with_capacity(transfer.symbols.len());
        let mut total_bytes: u64 = 0;

        for symbol in &transfer.symbols {
            let sym_path = block_dir.join(format!("{}.bin", symbol.esi));
            tokio::fs::write(&sym_path, &symbol.data).await?;
            received_esis.push(symbol.esi);
            total_bytes += symbol.data.len() as u64;
        }

        if received_esis.is_empty() {
            debug!(
                block_id = %block_id,
                owner = %owner_id,
                "processor: SymbolTransfer with no symbols, ignored"
            );
            return Ok(());
        }

        received_esis.sort_unstable();
        let new_ranges = esi_list_to_ranges(&received_esis);

        // Merge with existing HoldingRecord if any.
        let record = match self.db.get_holding(&block_id, &owner_id)? {
            Some(mut existing) => {
                let mut all_esis = ranges_to_esi_list(&existing.esi_ranges);
                for &esi in &received_esis {
                    if !all_esis.contains(&esi) {
                        all_esis.push(esi);
                    }
                }
                all_esis.sort_unstable();
                existing.esi_ranges = esi_list_to_ranges(&all_esis);
                existing.total_bytes += total_bytes;
                existing.status = HoldingStatus::Active;
                existing
            }
            None => HoldingRecord {
                source_block_id: block_id,
                owner_id,
                esi_ranges: new_ranges,
                // SymbolTransferMsg does not carry importance; use default 0.5.
                // The accurate value is available in SymbolOfferMsg (Phase 6.3 limitation).
                importance: 0.5,
                total_bytes,
                status: HoldingStatus::Active,
                received_at: Timestamp::now(),
                delete_requested_at: None,
                drop_notice_sent_at: None,
            },
        };

        self.db.upsert_holding(&record)?;

        info!(
            block_id = %block_id,
            owner = %owner_id,
            symbols = transfer.symbols.len(),
            "processor: stored symbols for block"
        );

        // Send SymbolStored acknowledgement back through the connection.
        // We don't hold conn here; ack is best-effort via NetworkHandle.
        // The BackupCoordinator (sender side) handles the lack of ack gracefully.

        Ok(())
    }

    // =========================================================
    // PosChallenge: we are the holder
    // =========================================================

    /// Load the challenged symbol and send PosResponse, or PosNack if not held.
    ///
    /// Returns the reply message so tests can inspect it without a real connection.
    pub(crate) async fn handle_pos_challenge_inner(
        &self,
        _owner_id: IdentityPub,
        challenge: syncback_core::messages::PosChallengeMsg,
    ) -> Result<Message, ProcessorError> {
        let block_id = challenge.source_block_id;
        let esi = challenge.esi;
        let sym_path = self
            .holdings_dir
            .join(to_hex(&block_id.0))
            .join(format!("{esi}.bin"));

        match tokio::fs::read(&sym_path).await {
            Ok(data) => {
                debug!(
                    block_id = %block_id,
                    esi,
                    "processor: PoS challenge — responding with data"
                );
                Ok(Message::PosResponse(PosResponseMsg {
                    v: 1,
                    challenge_id: challenge.challenge_id,
                    esi,
                    data,
                    timestamp: Timestamp::now(),
                }))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                warn!(
                    block_id = %block_id,
                    esi,
                    "processor: PoS challenge — symbol not held, sending PosNack"
                );
                Ok(Message::PosNack(PosNackMsg {
                    v: 1,
                    challenge_id: challenge.challenge_id,
                    source_block_id: block_id,
                    esi,
                    timestamp: Timestamp::now(),
                }))
            }
            Err(e) => Err(ProcessorError::Io(e)),
        }
    }

    async fn handle_pos_challenge(
        &self,
        from: IdentityPub,
        challenge: syncback_core::messages::PosChallengeMsg,
        conn: Arc<Mutex<Connection>>,
    ) -> Result<(), ProcessorError> {
        let reply = self.handle_pos_challenge_inner(from, challenge).await?;
        let mut guard = conn.lock().await;
        guard.send_message(&reply).await?;
        Ok(())
    }

    // =========================================================
    // PosResponse: we are the owner
    // =========================================================

    /// Verify a PoS response from a holder.
    ///
    /// Looks up the placement by scanning this holder's placements for a
    /// matching ESI, loads the source block from disk, re-encodes and
    /// compares. Updates placement status and trust accordingly.
    ///
    /// Returns the VerifyOutcome for testing.
    pub(crate) async fn handle_pos_response(
        &self,
        holder_id: IdentityPub,
        response: PosResponseMsg,
    ) -> Result<VerifyOutcome, ProcessorError> {
        let esi = response.esi;

        // Recover source_block_id: find the placement for this holder that owns this ESI.
        let placements = self.db.list_placements_for_holder(&holder_id)?;
        let placement = placements.into_iter().find(|p| {
            p.esi_ranges
                .iter()
                .any(|&(start, count)| esi >= start && esi < start + count)
        });

        let placement = match placement {
            Some(p) => p,
            None => {
                warn!(
                    holder = %holder_id,
                    esi,
                    "processor: PosResponse for unknown placement, ignoring"
                );
                return Ok(VerifyOutcome::Pass);
            }
        };

        let block_id = placement.source_block_id;

        let block_record = match self.db.get_source_block(&block_id)? {
            Some(r) => r,
            None => {
                warn!(
                    block_id = %block_id,
                    "processor: PosResponse — source block record missing, ignoring"
                );
                return Ok(VerifyOutcome::Pass);
            }
        };

        let block_path = self
            .source_blocks_dir
            .join(to_hex(&block_id.0))
            .join("block.bin");

        let source_data = match tokio::fs::read(&block_path).await {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                warn!(
                    block_id = %block_id,
                    "processor: PosResponse — source block file missing, cannot verify"
                );
                return Ok(VerifyOutcome::Pass);
            }
            Err(e) => return Err(ProcessorError::Io(e)),
        };

        let params = ErasureParams {
            k: block_record.k,
            k_eff: block_record.k + DECODE_OVERHEAD,
            t: block_record.t,
            overhead: 1.5,
            n: block_record.k * 4,
        };

        let pos_response = PosResponse {
            challenge_id: response.challenge_id,
            esi: response.esi,
            data: response.data,
        };

        let encoder = Arc::clone(&self.encoder);
        let block_id_clone = block_id;
        let holder_id_clone = holder_id;

        let outcome = tokio::task::spawn_blocking(move || {
            verify_response(
                &pos_response,
                &source_data,
                &params,
                &block_id_clone,
                &holder_id_clone,
                encoder.as_ref(),
            )
        })
        .await
        .map_err(|e| ProcessorError::Join(e.to_string()))?
        .map_err(ProcessorError::PosVerify)?;

        // Apply placement state transition.
        let transition = apply_pos_outcome(&placement, &outcome);
        let mut updated = placement;
        updated.status = transition.new_status;
        updated.consecutive_misses = transition.new_consecutive_misses;
        if matches!(outcome, VerifyOutcome::Pass) {
            updated.last_verified = Some(Timestamp::now());
        }
        self.db.upsert_placement(&updated)?;

        // Update PoS weekly stats for trust calculation.
        let week = current_week_number();
        let pos_outcome = outcome_from_verify(&outcome, week);
        record_pos_weekly(&self.db, holder_id, pos_outcome);

        if transition.trigger_repair {
            let _ = self
                .repair_tx
                .send(RepairTrigger::RepairNow {
                    block_id,
                    holder_id,
                })
                .await;
        }

        info!(
            block_id = %block_id,
            holder = %holder_id,
            esi,
            outcome = ?outcome,
            new_status = ?transition.new_status,
            "processor: PoS response processed"
        );

        Ok(outcome)
    }

    // =========================================================
    // PosNack: we are the owner
    // =========================================================

    /// Mark a placement Lost (holder explicitly said it doesn't hold the symbol).
    ///
    /// Idempotent: no-op if already Lost or Deleting.
    /// Returns true if the placement was actually modified.
    pub(crate) fn handle_pos_nack_sync(
        &self,
        holder_id: IdentityPub,
        nack: &PosNackMsg,
    ) -> Result<bool, ProcessorError> {
        let block_id = nack.source_block_id;
        mark_placement_lost(&self.db, &block_id, &holder_id)
    }

    pub(crate) async fn handle_pos_nack(
        &self,
        from: IdentityPub,
        nack: PosNackMsg,
    ) -> Result<(), ProcessorError> {
        let block_id = nack.source_block_id;
        self.handle_pos_nack_sync(from, &nack)?;
        let _ = self
            .repair_tx
            .send(RepairTrigger::RepairNow {
                block_id,
                holder_id: from,
            })
            .await;
        Ok(())
    }

    // =========================================================
    // SymbolDropped: we are the owner
    // =========================================================

    /// Mark a placement Lost (holder evicted the symbols).
    ///
    /// Idempotent: no-op if already Lost or Deleting.
    /// Returns true if the placement was actually modified.
    pub(crate) fn handle_symbol_dropped_sync(
        &self,
        holder_id: IdentityPub,
        dropped: &SymbolDroppedMsg,
    ) -> Result<bool, ProcessorError> {
        let block_id = dropped.source_block_id;
        mark_placement_lost(&self.db, &block_id, &holder_id)
    }

    pub(crate) async fn handle_symbol_dropped(
        &self,
        from: IdentityPub,
        dropped: SymbolDroppedMsg,
    ) -> Result<(), ProcessorError> {
        let block_id = dropped.source_block_id;
        self.handle_symbol_dropped_sync(from, &dropped)?;
        let _ = self
            .repair_tx
            .send(RepairTrigger::RepairNow {
                block_id,
                holder_id: from,
            })
            .await;
        Ok(())
    }

    // =========================================================
    // ClusterSyncRequest: serve event log to a peer device
    // =========================================================

    async fn handle_cluster_sync_request(
        &self,
        from: IdentityPub,
        request: ClusterSyncRequestMsg,
        conn: Arc<Mutex<Connection>>,
    ) -> Result<(), ProcessorError> {
        match self.cluster_sync.handle_sync_request(&request) {
            Ok(response) => {
                let mut guard = conn.lock().await;
                guard
                    .send_message(&Message::ClusterSyncResponse(response))
                    .await?;
                debug!(peer = %from, "processor: ClusterSyncRequest served");
            }
            Err(e) => {
                warn!(peer = %from, err = %e, "processor: ClusterSyncRequest rejected");
            }
        }
        Ok(())
    }

    // =========================================================
    // ClusterSyncResponse: apply events from a peer device
    // =========================================================

    async fn handle_cluster_sync_response(
        &self,
        from: IdentityPub,
        response: ClusterSyncResponseMsg,
    ) -> Result<(), ProcessorError> {
        match self.cluster_sync.process_sync_response(&from, response) {
            Ok(n) => {
                debug!(
                    peer = %from,
                    applied = n,
                    "processor: cluster sync applied events"
                );
            }
            Err(e) => {
                warn!(peer = %from, err = %e, "processor: cluster sync response error");
            }
        }
        Ok(())
    }
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

/// Mark a placement as Lost. Idempotent: no-op if already Lost or Deleting.
/// Returns true if the record was changed.
fn mark_placement_lost(
    db: &Db,
    block_id: &syncback_core::types::SourceBlockId,
    holder_id: &IdentityPub,
) -> Result<bool, ProcessorError> {
    let placement = match db.get_placement(block_id, holder_id)? {
        Some(p) => p,
        None => {
            warn!(
                block_id = %block_id,
                holder = %holder_id,
                "processor: placement not found for mark_placement_lost"
            );
            return Ok(false);
        }
    };

    if placement.status == PlacementStatus::Lost || placement.status == PlacementStatus::Deleting {
        return Ok(false);
    }

    let mut updated = placement;
    updated.status = PlacementStatus::Lost;
    updated.consecutive_misses = 0;
    db.upsert_placement(&updated)?;

    info!(
        block_id = %block_id,
        holder = %holder_id,
        "processor: placement marked Lost"
    );

    Ok(true)
}

/// Record PoS outcome in the weekly stats table (best-effort, logs on error).
fn record_pos_weekly(db: &Db, peer: IdentityPub, outcome: PosOutcome) {
    let week = outcome.week_number;
    let existing = match db.get_pos_weekly(&peer, week) {
        Ok(v) => v,
        Err(e) => {
            error!(peer = %peer, err = %e, "processor: failed to read pos_weekly");
            return;
        }
    };
    let entry = WeeklyPosEntry {
        challenged: existing.as_ref().map(|e| e.challenged).unwrap_or(0) + outcome.challenged,
        passed: existing.as_ref().map(|e| e.passed).unwrap_or(0) + outcome.passed,
    };
    if let Err(e) = db.upsert_pos_weekly(&peer, week, &entry) {
        error!(peer = %peer, err = %e, "processor: failed to update pos_weekly");
    }
}

/// Convert a sorted list of ESIs to compact (start, count) ranges.
pub(crate) fn esi_list_to_ranges(esis: &[u32]) -> Vec<(u32, u32)> {
    if esis.is_empty() {
        return Vec::new();
    }
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    let mut start = esis[0];
    let mut count = 1u32;
    for &esi in &esis[1..] {
        if esi == start + count {
            count += 1;
        } else {
            ranges.push((start, count));
            start = esi;
            count = 1;
        }
    }
    ranges.push((start, count));
    ranges
}

/// Expand (start, count) ranges back to a flat sorted list of ESIs.
pub(crate) fn ranges_to_esi_list(ranges: &[(u32, u32)]) -> Vec<u32> {
    ranges
        .iter()
        .flat_map(|&(start, count)| start..start + count)
        .collect()
}

/// Approximate protocol week number from the current unix timestamp (1-indexed).
fn current_week_number() -> u32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    ((secs / 604_800) as u32).max(1)
}

/// Full hex encoding (lowercase) for directory names.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
