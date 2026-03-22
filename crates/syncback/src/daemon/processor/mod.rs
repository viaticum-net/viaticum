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
//   SymbolOffer received    → we are the holder  → check quota, send Accept or Reject
//   SymbolAccept received   → we are the owner   → log (BackupCoordinator wiring Phase 7.5)
//   SymbolReject received   → we are the owner   → log
//   RestoreRequest received → we are the holder  → load symbols, send RestoreResponse
//   RestoreDenied received  → we are the owner   → log warning
//   BoardSync received      → forward to RelayManager via relay_sync_tx
//   PeerAnnounce received   → upsert peer record in DB + add to known_peers
//   ClusterSyncRequest      → we are cluster peer → serve event log entries
//   ClusterSyncResponse     → we are cluster peer → apply received events
//
// Phase 7.10 — Peer gossip on connect:
//   On every new incoming connection we immediately send our PeerAnnounceMsg
//   so the remote learns our identity ↔ NodeId binding. The peer does the
//   same, so after the first exchange both sides can reach each other by
//   identity. When we receive a PeerAnnounce we upsert the DB record AND
//   call network.add_peer() so future get_connection() calls can reach them.
//
// Design note: PosResponseMsg on the wire does not carry source_block_id.
// We recover it by scanning placements for the holder and finding one whose
// ESI ranges include the challenged ESI. This is a Phase 6.3 simplification;
// Phase 6.5 (Scheduler) will track challenge context in a pending table.

use std::path::PathBuf;
use std::sync::Arc;

use syncback_core::constants::{
    DECODE_OVERHEAD, DEFAULT_ESCROW_TRUST_FACTOR, INITIAL_TRUST_P, KI, KP, P_WINDOW_WEEKS,
    SYMBOL_SIZE,
};
use syncback_core::escrow::{check_restore, RestoreDecision};
use syncback_core::trust::compute_combined;
use syncback_core::db::{Db, WeeklyPosEntry};
use syncback_core::erasure::{ErasureEncoder, Symbol};
use syncback_core::messages::{
    BoardSyncMsg, ClusterSyncRequestMsg, ClusterSyncResponseMsg, Message, PeerAnnounceMsg,
    PosNackMsg, PosResponseMsg, RejectReason, RestoreDeniedMsg, RestoreRequestMsg,
    RestoreResponseMsg, SymbolAcceptMsg, SymbolDroppedMsg, SymbolOfferMsg, SymbolRejectMsg,
    SymbolTransferMsg,
};
use syncback_core::pos::{
    apply_pos_outcome, outcome_from_verify, verify_response, PosResponse, VerifyOutcome,
};
use syncback_core::trust::PosOutcome;
use syncback_core::types::{
    hex_encode, ErasureParams, HoldingRecord, HoldingStatus, IdentityPub, PeerRecord,
    PlacementStatus, Timestamp,
};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::daemon::cluster_sync::ClusterSyncManager;
use crate::daemon::network::connection::Connection;
use crate::daemon::network::NetworkHandle;
use crate::daemon::relay::InboundMessage;
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

    #[error("escrow denied for block {block_id}")]
    EscrowDenied {
        block_id: syncback_core::types::SourceBlockId,
        denial: syncback_core::escrow::RestoreDenial,
    },

    #[error("task join error: {0}")]
    Join(String),
}

// ─── Processor ────────────────────────────────────────────────────────────────

/// Routes incoming connections and dispatches messages to appropriate handlers.
pub struct Processor {
    db: Db,
    /// Our identity — will be used for escrow check (TODO Phase 7.6+).
    _own_identity: IdentityPub,
    repair_tx: mpsc::Sender<RepairTrigger>,
    cluster_sync: Arc<ClusterSyncManager>,
    encoder: Arc<dyn ErasureEncoder>,
    /// Directory where we store symbols held for others: `{holdings_dir}/{block_id_hex}/{esi}.bin`
    holdings_dir: PathBuf,
    /// Directory where our own source blocks live (for PoS verification as owner):
    /// `{source_blocks_dir}/{block_id_hex}/block.bin`
    source_blocks_dir: PathBuf,
    /// Network handle for sending replies (SymbolAccept, SymbolReject, RestoreResponse).
    network: Arc<NetworkHandle>,
    /// Channel to relay manager: push BoardSync entries from incoming connections.
    relay_sync_tx: mpsc::Sender<crate::daemon::relay::SyncTrigger>,
    /// Soft quota in bytes. 0 = unlimited (treat as u64::MAX internally).
    soft_quota_bytes: u64,
    /// Hard quota in bytes: floor; never accept symbols above this held total.
    /// 0 = no hard floor.
    hard_quota_bytes: u64,
    /// Channel to notify BackupCoordinator about symbol accept/reject outcomes.
    backup_event_tx: mpsc::Sender<crate::daemon::backup::BackupEvent>,
    /// Time acceleration factor (1 = real time). Scales week numbers for trust.
    time_scale: u64,
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
        network: Arc<NetworkHandle>,
        relay_sync_tx: mpsc::Sender<crate::daemon::relay::SyncTrigger>,
        soft_quota_bytes: u64,
        hard_quota_bytes: u64,
        backup_event_tx: mpsc::Sender<crate::daemon::backup::BackupEvent>,
        time_scale: u64,
    ) -> Self {
        Processor {
            db,
            _own_identity: own_identity,
            repair_tx,
            cluster_sync,
            encoder,
            holdings_dir,
            source_blocks_dir,
            network,
            relay_sync_tx,
            soft_quota_bytes,
            hard_quota_bytes,
            backup_event_tx,
            time_scale,
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
        mut inbound_rx: mpsc::Receiver<InboundMessage>,
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
                            let network_arc = this.network.clone();

                            // Store in connection pool so send_to_peer can reuse it.
                            network_arc.store_connection_arc(peer_id, conn_arc.clone()).await;

                            // Send our PeerAnnounceMsg immediately so the
                            // remote learns our identity ↔ NodeId mapping.
                            let pa_msg = {
                                let pa = network_arc.build_peer_announce(Timestamp::now());
                                Message::PeerAnnounce(pa)
                            };
                            {
                                let mut guard = conn_arc.lock().await;
                                if let Err(e) = guard.send_message(&pa_msg).await {
                                    warn!(
                                        peer = %peer_id,
                                        err = %e,
                                        "processor: failed to send PeerAnnounce on new connection"
                                    );
                                } else {
                                    debug!(
                                        peer = %peer_id,
                                        "processor: sent PeerAnnounce on new connection"
                                    );
                                }
                            }

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
                                                // Evict the dead connection so get_connection
                                                // reconnects next time instead of reusing the
                                                // stale Arc.
                                                network_arc.evict_connection(peer_id).await;
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

                maybe_relay = inbound_rx.recv() => {
                    match maybe_relay {
                        None => {
                            info!("processor: inbound_rx closed");
                            // Not a fatal condition; relay may be disabled.
                        }
                        Some(relay_msg) => {
                            let this2 = this.clone();
                            tokio::spawn(async move {
                                this2.dispatch_relay(relay_msg).await;
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    // =========================================================
    // Relay dispatch (one-way messages only)
    // =========================================================

    async fn dispatch_relay(&self, msg: InboundMessage) {
        use syncback_core::messages::from_cbor;
        if msg.msg_type == "peer_announce" {
            match from_cbor::<PeerAnnounceMsg>(&msg.payload) {
                Ok(pa) => {
                    if let Err(e) = self.handle_peer_announce(pa).await {
                        warn!(err = %e, "processor: PeerAnnounce via relay failed");
                    }
                }
                Err(e) => {
                    warn!(err = %e, "processor: failed to decode PeerAnnounce from relay");
                }
            }
        } else {
            debug!(msg_type = %msg.msg_type, "processor: relay message, no handler");
        }
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
            Message::SymbolOffer(offer) => {
                self.handle_symbol_offer(from, offer, conn).await?;
            }
            Message::SymbolAccept(accept) => {
                self.handle_symbol_accept(from, accept).await?;
            }
            Message::SymbolReject(reject) => {
                self.handle_symbol_reject(from, reject).await?;
            }
            Message::RestoreRequest(req) => {
                self.handle_restore_request(from, req, conn).await?;
            }
            Message::RestoreDenied(denied) => {
                self.handle_restore_denied(from, denied).await?;
            }
            Message::BoardSync(board_sync) => {
                self.handle_board_sync(from, board_sync).await?;
            }
            Message::PeerAnnounce(pa) => {
                self.handle_peer_announce(pa).await?;
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
        let block_hex = hex_encode(&block_id.0);
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
            .join(hex_encode(&block_id.0))
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
            .join(hex_encode(&block_id.0))
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

        // Update PoS weekly stats and recalculate trust.
        let week = current_week_number_scaled(self.time_scale);
        let pos_outcome = outcome_from_verify(&outcome, week);
        record_pos_weekly(&self.db, holder_id, pos_outcome);

        // Recalculate trust scores from accumulated PoS history.
        if let Some((old_p, old_i, new_p, new_i)) =
            recalculate_trust(&self.db, &holder_id, week)
        {
            let old_combined = compute_combined(old_p, old_i, 1.0);
            let new_combined = compute_combined(new_p, new_i, 1.0);
            info!(
                peer = %holder_id,
                trust_p_before = format!("{old_p:.4}"),
                trust_p_after = format!("{new_p:.4}"),
                trust_i_before = format!("{old_i:.4}"),
                trust_i_after = format!("{new_i:.4}"),
                trust_combined_before = format!("{old_combined:.4}"),
                trust_combined_after = format!("{new_combined:.4}"),
                "trust: score updated after PoS"
            );
        }

        if transition.trigger_repair {
            info!(block_id = %block_id, holder = %holder_id, "repair: triggered");
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
        info!(block_id = %block_id, holder = %from, "repair: triggered");
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
        info!(block_id = %block_id, holder = %from, "repair: triggered");
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
    // SymbolOffer: we are the holder
    // =========================================================

    /// Decide whether to accept or reject a SymbolOffer based on disk quota.
    ///
    /// Returns `true` = accept, `false` = reject.
    /// This is a sync helper used by `handle_symbol_offer` and tests.
    pub(crate) fn decide_symbol_offer(
        &self,
        offer_bytes: u64,
    ) -> Result<bool, ProcessorError> {
        let held_bytes = self.db.total_holding_bytes()?;

        let effective_hard = if self.hard_quota_bytes == 0 {
            u64::MAX
        } else {
            self.hard_quota_bytes
        };
        let effective_soft = if self.soft_quota_bytes == 0 {
            u64::MAX
        } else {
            self.soft_quota_bytes
        };

        if held_bytes >= effective_hard {
            return Ok(false);
        }
        if effective_soft < u64::MAX && held_bytes + offer_bytes > effective_soft {
            return Ok(false);
        }
        Ok(true)
    }

    /// Receive a SymbolOffer, decide Accept or Reject, send reply on conn.
    ///
    /// Does NOT create a HoldingRecord — that happens in handle_symbol_transfer
    /// when symbols actually arrive.
    pub(crate) async fn handle_symbol_offer(
        &self,
        owner_id: IdentityPub,
        offer: SymbolOfferMsg,
        conn: Arc<Mutex<Connection>>,
    ) -> Result<(), ProcessorError> {
        let offer_bytes: u64 = offer
            .esi_ranges
            .iter()
            .map(|&(_start, count)| count as u64 * SYMBOL_SIZE as u64)
            .sum();

        let accept = self.decide_symbol_offer(offer_bytes)?;

        let reply = if accept {
            info!(
                owner = %owner_id,
                block_id = %offer.source_block_id,
                offer_bytes,
                "processor: SymbolOffer accepted"
            );
            Message::SymbolAccept(SymbolAcceptMsg {
                v: 1,
                source_block_id: offer.source_block_id,
                offer_msg_id: offer.msg_id,
                timestamp: Timestamp::now(),
            })
        } else {
            debug!(
                owner = %owner_id,
                block_id = %offer.source_block_id,
                offer_bytes,
                "processor: SymbolOffer rejected (quota full)"
            );
            Message::SymbolReject(SymbolRejectMsg {
                v: 1,
                source_block_id: offer.source_block_id,
                offer_msg_id: offer.msg_id,
                reason: RejectReason::QuotaFull,
                timestamp: Timestamp::now(),
            })
        };

        let mut guard = conn.lock().await;
        guard.send_message(&reply).await?;
        Ok(())
    }

    // =========================================================
    // SymbolAccept / SymbolReject: we are the owner
    // =========================================================

    /// Holder accepted our symbol offer. Notify BackupCoordinator.
    async fn handle_symbol_accept(
        &self,
        holder_id: IdentityPub,
        accept: SymbolAcceptMsg,
    ) -> Result<(), ProcessorError> {
        info!(
            holder = %holder_id,
            block_id = %accept.source_block_id,
            "processor: SymbolAccept received"
        );
        let _ = self.backup_event_tx.send(
            crate::daemon::backup::BackupEvent::SymbolAccepted {
                holder_id,
                source_block_id: accept.source_block_id,
            },
        ).await;
        Ok(())
    }

    /// Holder rejected our symbol offer. Notify BackupCoordinator.
    async fn handle_symbol_reject(
        &self,
        holder_id: IdentityPub,
        reject: SymbolRejectMsg,
    ) -> Result<(), ProcessorError> {
        warn!(
            holder = %holder_id,
            block_id = %reject.source_block_id,
            reason = ?reject.reason,
            "processor: SymbolReject received"
        );
        let _ = self.backup_event_tx.send(
            crate::daemon::backup::BackupEvent::SymbolRejected {
                holder_id,
                source_block_id: reject.source_block_id,
                reason: format!("{:?}", reject.reason),
            },
        ).await;
        Ok(())
    }

    // =========================================================
    // RestoreRequest: we are the holder
    // =========================================================

    /// Load held symbols for owner and return a RestoreResponseMsg.
    ///
    /// Inner method for testability — does not touch the network connection.
    pub(crate) async fn handle_restore_request_inner(
        &self,
        owner_id: IdentityPub,
        request: RestoreRequestMsg,
    ) -> Result<RestoreResponseMsg, ProcessorError> {
        let block_id = request.source_block_id;

        // Check HoldingRecord.
        let holding = self.db.get_holding(&block_id, &owner_id)?;
        let holding = match holding {
            Some(h) if h.status == HoldingStatus::Active => h,
            _ => {
                // Not held or not active: return empty response (not a protocol error).
                return Ok(RestoreResponseMsg {
                    v: 1,
                    source_block_id: block_id,
                    symbols: vec![],
                    timestamp: Timestamp::now(),
                });
            }
        };

        // Escrow check: verify owner has enough trust to unlock restore.
        let trust = match self.db.get_peer(&owner_id)? {
            Some(peer) => compute_combined(peer.trust_p, peer.trust_i, peer.trust_s),
            None => 0.0, // unknown peer → zero trust → free tier only
        };
        let restore_gb = holding
            .esi_ranges
            .iter()
            .map(|&(_start, count)| count as f64 * SYMBOL_SIZE as f64)
            .sum::<f64>()
            / (1024.0 * 1024.0 * 1024.0);
        if let RestoreDecision::Denied(denial) = check_restore(
            trust,
            restore_gb,
            DEFAULT_ESCROW_TRUST_FACTOR,
        ) {
            warn!(
                owner = %owner_id,
                block_id = %block_id,
                current_trust = denial.current_trust,
                needed_trust = denial.needed_trust,
                restore_budget_gb = denial.restore_budget_gb,
                "processor: RestoreRequest denied by escrow check"
            );
            return Err(ProcessorError::EscrowDenied {
                block_id,
                denial,
            });
        }

        // Determine which ESIs to send.
        let held_esis = ranges_to_esi_list(&holding.esi_ranges);
        let esis_to_send: Vec<u32> = if request.esi_list.is_empty() {
            held_esis
        } else {
            let held_set: std::collections::HashSet<u32> = held_esis.into_iter().collect();
            request
                .esi_list
                .into_iter()
                .filter(|esi| held_set.contains(esi))
                .collect()
        };

        // Load symbol files from disk.
        let block_hex = hex_encode(&block_id.0);
        let block_dir = self.holdings_dir.join(&block_hex);
        let mut symbols: Vec<Symbol> = Vec::with_capacity(esis_to_send.len());

        for esi in esis_to_send {
            let sym_path = block_dir.join(format!("{esi}.bin"));
            match tokio::fs::read(&sym_path).await {
                Ok(data) => {
                    symbols.push(Symbol { esi, data });
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    debug!(
                        block_id = %block_id,
                        esi,
                        "processor: RestoreRequest — symbol file missing on disk, skipping"
                    );
                }
                Err(e) => return Err(ProcessorError::Io(e)),
            }
        }

        if symbols.is_empty() {
            warn!(
                block_id = %block_id,
                owner = %owner_id,
                "processor: RestoreRequest — HoldingRecord exists but no symbol files found on disk"
            );
        } else {
            info!(
                block_id = %block_id,
                owner = %owner_id,
                symbols = symbols.len(),
                "processor: sending RestoreResponse"
            );
        }

        Ok(RestoreResponseMsg {
            v: 1,
            source_block_id: block_id,
            symbols,
            timestamp: Timestamp::now(),
        })
    }

    /// Handle a RestoreRequest from an owner: load symbols and send RestoreResponse on conn.
    /// If escrow check fails, sends RestoreDeniedMsg instead.
    pub(crate) async fn handle_restore_request(
        &self,
        owner_id: IdentityPub,
        request: RestoreRequestMsg,
        conn: Arc<Mutex<Connection>>,
    ) -> Result<(), ProcessorError> {
        let block_id = request.source_block_id;
        match self.handle_restore_request_inner(owner_id, request).await {
            Ok(response) => {
                let mut guard = conn.lock().await;
                guard
                    .send_message(&Message::RestoreResponse(response))
                    .await?;
                Ok(())
            }
            Err(ProcessorError::EscrowDenied { denial, .. }) => {
                let denied_msg = RestoreDeniedMsg {
                    v: 1,
                    source_block_id: block_id,
                    reason: "escrow check failed".to_string(),
                    current_trust: denial.current_trust,
                    needed_trust: denial.needed_trust,
                    restore_budget_gb: denial.restore_budget_gb,
                    timestamp: Timestamp::now(),
                };
                let mut guard = conn.lock().await;
                guard
                    .send_message(&Message::RestoreDenied(denied_msg))
                    .await?;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    // =========================================================
    // RestoreDenied: we are the owner
    // =========================================================

    /// Holder denied our restore request. Log warning.
    async fn handle_restore_denied(
        &self,
        holder_id: IdentityPub,
        denied: RestoreDeniedMsg,
    ) -> Result<(), ProcessorError> {
        warn!(
            holder = %holder_id,
            block_id = %denied.source_block_id,
            current_trust = denied.current_trust,
            needed_trust = denied.needed_trust,
            restore_budget_gb = denied.restore_budget_gb,
            "processor: RestoreDenied received"
        );
        Ok(())
    }

    // =========================================================
    // BoardSync: forward to relay manager
    // =========================================================

    /// Peer sent us board entries. Forward to RelayManager via relay_sync_tx.
    async fn handle_board_sync(
        &self,
        from: IdentityPub,
        msg: BoardSyncMsg,
    ) -> Result<(), ProcessorError> {
        let trigger = crate::daemon::relay::SyncTrigger {
            partner_identity: from,
            partner_entries: msg.entries,
        };
        if self.relay_sync_tx.send(trigger).await.is_err() {
            warn!(peer = %from, "processor: relay_sync_tx closed, dropping BoardSync");
        }
        Ok(())
    }

    // =========================================================
    // PeerAnnounce: upsert peer in DB
    // =========================================================

    /// Learn about a peer's identity. Upsert PeerRecord in DB and register
    /// the peer's NodeId in the network layer so future `get_connection` calls
    /// can reach them.
    ///
    /// We build an `EndpointAddr` from the NodeId alone (no socket address).
    /// iroh can still connect to a NodeId-only addr via the relay network
    /// (RelayMode::Default) or direct discovery. For LAN-only setups (tests)
    /// this is a no-op from a routing standpoint, but the record is still
    /// stored for when the peer later connects with a full addr.
    pub(crate) async fn handle_peer_announce(
        &self,
        msg: PeerAnnounceMsg,
    ) -> Result<(), ProcessorError> {
        let now = Timestamp::now();
        let record = match self.db.get_peer(&msg.identity_pub)? {
            None => PeerRecord {
                identity: msg.identity_pub,
                node_id: Some(msg.node_id),
                trust_p: INITIAL_TRUST_P,
                trust_i: 0.0,
                trust_s: 1.0,
                bytes_we_store_for_peer: 0,
                bytes_peer_stores_for_us: 0,
                first_seen: now,
                last_seen: now,
                device_id: None,
                revoked_device_pub_keys: vec![],
                addrs: vec![],
            },
            Some(mut existing) => {
                existing.node_id = Some(msg.node_id);
                existing.last_seen = now;
                existing
            }
        };
        self.db.upsert_peer(&record)?;

        // Register the peer in the network layer so get_connection() can reach
        // them. Build an EndpointAddr from the NodeId (iroh PublicKey) alone;
        // a socket address is not required when the relay is enabled.
        match iroh::PublicKey::from_bytes(&msg.node_id.0) {
            Ok(pubkey) => {
                let addr = iroh::EndpointAddr::new(pubkey);
                self.network.add_peer(msg.identity_pub, addr).await;
                info!(
                    identity = %msg.identity_pub,
                    node_id = %msg.node_id,
                    "processor: PeerAnnounce upserted peer record and registered in network"
                );
            }
            Err(e) => {
                warn!(
                    identity = %msg.identity_pub,
                    node_id = %msg.node_id,
                    err = %e,
                    "processor: PeerAnnounce — invalid NodeId bytes, skipping network.add_peer"
                );
                info!(
                    identity = %msg.identity_pub,
                    node_id = %msg.node_id,
                    "processor: PeerAnnounce upserted peer record (no network entry)"
                );
            }
        }

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
pub(crate) fn record_pos_weekly(db: &Db, peer: IdentityPub, outcome: PosOutcome) {
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

/// Recalculate trust P and I for a peer from pos_weekly data, persist to PeerRecord.
/// Returns (old_p, old_i, new_p, new_i) for logging, or None on error.
pub(crate) fn recalculate_trust(
    db: &Db,
    peer: &IdentityPub,
    current_week: u32,
) -> Option<(f64, f64, f64, f64)> {
    let mut record = match db.get_peer(peer) {
        Ok(Some(r)) => r,
        _ => return None,
    };
    let old_p = record.trust_p;
    let old_i = record.trust_i;

    let entries = db.list_pos_weekly_for_peer(peer).unwrap_or_default();

    // P: rolling window pass rate over last P_WINDOW_WEEKS weeks.
    let window_start = current_week.saturating_sub(P_WINDOW_WEEKS - 1);
    let mut p_challenged = 0u64;
    let mut p_passed = 0u64;
    let mut all_pass_rates: Vec<f64> = Vec::new();
    for (week, entry) in &entries {
        if entry.challenged > 0 {
            let rate = entry.passed as f64 / entry.challenged as f64;
            all_pass_rates.push(rate);
            if *week >= window_start && *week <= current_week {
                p_challenged += entry.challenged as u64;
                p_passed += entry.passed as u64;
            }
        }
    }

    let new_p = if p_challenged == 0 {
        INITIAL_TRUST_P
    } else {
        p_passed as f64 / p_challenged as f64
    };

    // I: cumulative mean of all weekly pass rates.
    let new_i = if all_pass_rates.is_empty() {
        0.0
    } else {
        all_pass_rates.iter().sum::<f64>() / all_pass_rates.len() as f64
    };

    record.trust_p = new_p;
    record.trust_i = new_i;
    if let Err(e) = db.upsert_peer(&record) {
        error!(peer = %peer, err = %e, "processor: failed to persist trust update");
        return None;
    }

    Some((old_p, old_i, new_p, new_i))
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
///
/// When `time_scale` > 1, simulated time advances faster: each real second
/// counts as `time_scale` simulated seconds. This ensures the trust P-window
/// slides during accelerated experiments.
pub(crate) fn current_week_number_scaled(time_scale: u64) -> u32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let scaled = secs.saturating_mul(time_scale.max(1));
    ((scaled / 604_800) as u32).max(1)
}

