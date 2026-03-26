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

use syncback_core::config::EscrowCfg;
use syncback_core::constants::{INITIAL_TRUST_P, P_WINDOW_WEEKS, SYMBOL_SIZE};
use syncback_core::escrow::{check_restore, RestoreDecision};
use syncback_core::db::{Db, SystemStateBlobRecord, WeeklyPosEntry};
use syncback_core::erasure::{ErasureEncoder, Symbol};
use syncback_core::messages::{
    BoardSyncMsg, CancelDeleteMsg, ClusterSyncRequestMsg, ClusterSyncResponseMsg, DeleteMsg,
    DiscoveredPeer, Message, PeerAnnounceMsg, PeerDiscoveryRequestMsg, PeerDiscoveryResponseMsg,
    PosChallengeMsg, PosNackMsg, PosResponseMsg, RejectReason, RestoreDeniedMsg, RestoreRequestMsg,
    RestoreResponseMsg, RevocationBroadcast, SymbolAcceptMsg, SymbolDropNoticeMsg, SymbolDroppedMsg,
    SymbolOfferMsg, SymbolRejectMsg, SymbolTransferMsg, SystemStateAckMsg, SystemStateBackupMsg,
    SystemStateRequestMsg, SystemStateResponseMsg,
};
use syncback_core::pos::{
    apply_pos_outcome, outcome_from_verify, verify_response, PosResponse, VerifyOutcome,
};
use syncback_core::trust::{compute_combined, PosOutcome};
use syncback_core::types::{
    hex_encode, HoldingRecord, HoldingStatus, IdentityPub, PeerRecord, PlacementStatus, Timestamp,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::daemon::cluster_sync::ClusterSyncManager;
use crate::daemon::network::connection::Connection;
use crate::daemon::network::NetworkHandle;
use crate::daemon::relay::{InboundMessage, RelayPost};
use crate::daemon::repair::RepairTrigger;
use crate::daemon::scheduler::PendingChallenges;

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
    /// Our identity — used to skip self in PeerDiscoveryResponse handling.
    own_identity: IdentityPub,
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
    /// Raw soft quota in bytes from config. 0 = use disk-based limit.
    soft_quota_bytes: u64,
    /// Raw hard quota in bytes. 0 = no hard floor.
    hard_quota_bytes: u64,
    /// Data directory path for disk space queries (statvfs).
    data_dir: PathBuf,
    /// Disk reserve bytes — minimum free space to keep on the filesystem.
    disk_reserve_bytes: u64,
    /// Channel to notify BackupCoordinator about symbol accept/reject outcomes.
    backup_event_tx: mpsc::Sender<crate::daemon::backup::BackupEvent>,
    /// Time acceleration factor (1 = real time). Scales week numbers for trust.
    time_scale: u64,
    /// Shared map of in-flight PoS challenges. Written by Scheduler, read here
    /// to resolve challenge_id → source_block_id without scanning placements.
    pending_challenges: PendingChallenges,
    /// Channel to post messages to the relay board (for board-based responses).
    relay_post_tx: mpsc::Sender<RelayPost>,
    /// Cluster state for auto-add on same-identity handshake. None if not initialized.
    cluster_state: Option<Arc<std::sync::Mutex<syncback_core::cluster::ClusterState>>>,
    /// Escrow configuration for contribution-based restore budget checks.
    escrow_cfg: EscrowCfg,
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
        data_dir: PathBuf,
        disk_reserve_bytes: u64,
        backup_event_tx: mpsc::Sender<crate::daemon::backup::BackupEvent>,
        time_scale: u64,
        pending_challenges: PendingChallenges,
        relay_post_tx: mpsc::Sender<RelayPost>,
        cluster_state: Option<Arc<std::sync::Mutex<syncback_core::cluster::ClusterState>>>,
        escrow_cfg: EscrowCfg,
    ) -> Self {
        Processor {
            db,
            own_identity,
            repair_tx,
            cluster_sync,
            encoder,
            holdings_dir,
            source_blocks_dir,
            network,
            relay_sync_tx,
            soft_quota_bytes,
            hard_quota_bytes,
            data_dir,
            disk_reserve_bytes,
            backup_event_tx,
            time_scale,
            pending_challenges,
            relay_post_tx,
            cluster_state,
            escrow_cfg,
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
        mut read_loop_rx: mpsc::UnboundedReceiver<crate::daemon::network::ReadLoopRequest>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        let (msg_tx, mut msg_rx) =
            mpsc::channel::<(IdentityPub, Message, Arc<Connection>)>(256);
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
                            let peer_id = conn.master_identity();

                            // Send PeerAnnounce on this connection before
                            // splitting into separate read-loop and pool entry.
                            let conn_arc = Arc::new(conn);
                            {
                                let pa_msg = {
                                    let pa = this.network.build_peer_announce(Timestamp::now());
                                    Message::PeerAnnounce(pa)
                                };
                                if let Err(e) = conn_arc.send_message(&pa_msg).await {
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

                            // Register peer's address in known_peers so that
                            // send_to_peer can create an outbound connection
                            // later (e.g. for system state push). We do NOT
                            // store the inbound connection in the pool — that
                            // would cause reads and sends to contend on the
                            // same connection from different tasks.
                            //
                            // Use remote_endpoint_addr() to get the full
                            // address (IP:port + relay) from iroh's internal
                            // state, not just the bare NodeId.
                            {
                                let remote_pubkey = conn_arc.inner.remote_id();
                                let endpoint_addr = match this.network
                                    .remote_endpoint_addr(remote_pubkey).await
                                {
                                    Some(addr) => addr,
                                    None => iroh::EndpointAddr::new(remote_pubkey),
                                };
                                this.network.add_peer(peer_id, endpoint_addr.clone()).await;
                                debug!(
                                    peer = %peer_id,
                                    "processor: registered inbound peer in known_peers"
                                );

                                // Auto-add cluster device if same master identity.
                                this.try_auto_add_cluster_device(
                                    Some(peer_id),
                                    conn_arc.peer_device_cert.clone(),
                                    endpoint_addr,
                                ).await;
                            }

                            let conn_arc2 = conn_arc.clone();
                            let tx = msg_tx.clone();
                            let network_arc = this.network.clone();
                            tokio::spawn(async move {
                                debug!(peer = %peer_id, "processor: read loop started");
                                loop {
                                    match conn_arc2.recv_message().await {
                                        Ok(msg) => {
                                            if tx.send((peer_id, msg, conn_arc2.clone())).await.is_err() {
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            debug!(
                                                peer = %peer_id,
                                                err = %e,
                                                "processor: connection closed"
                                            );
                                            network_arc.evict_connection(peer_id).await;
                                            break;
                                        }
                                    }
                                }
                                debug!(peer = %peer_id, "processor: read loop exited");
                            });
                        }
                    }
                }

                // Auto-reconnected outbound connections need a read loop too.
                maybe_rl = read_loop_rx.recv() => {
                    if let Some((peer_id, conn_arc)) = maybe_rl {
                        let conn_arc2 = conn_arc.clone();
                        let tx = msg_tx.clone();
                        let network_arc = this.network.clone();
                        debug!(peer = %peer_id, "processor: read loop started (auto-reconnect)");
                        tokio::spawn(async move {
                            loop {
                                match conn_arc2.recv_message().await {
                                    Ok(msg) => {
                                        if tx.send((peer_id, msg, conn_arc2.clone())).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        debug!(
                                            peer = %peer_id,
                                            err = %e,
                                            "processor: auto-reconnect connection closed"
                                        );
                                        network_arc.evict_connection(peer_id).await;
                                        break;
                                    }
                                }
                            }
                        });
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
    // Cluster auto-add helper
    // =========================================================

    /// Auto-add a cluster device if the incoming connection has the same master identity.
    ///
    /// Checks whether `peer_master_identity == own_identity`. If so, extracts the
    /// device cert from `peer_device_cert`, calls `cluster_state.add_device`, and
    /// registers the device in `cluster_peers` via the network handle.
    ///
    /// Errors from `add_device`:
    ///   - `DeviceAlreadyRegistered` → logged at debug, not an error condition.
    ///   - Other errors → logged at warn.
    ///
    /// Returns `true` if the device was newly added, `false` otherwise.
    pub async fn try_auto_add_cluster_device(
        &self,
        peer_master_identity: Option<syncback_core::types::IdentityPub>,
        peer_device_cert: Option<syncback_core::cluster::DeviceCertificate>,
        endpoint_addr: iroh::EndpointAddr,
    ) -> bool {
        let peer_master = match peer_master_identity {
            Some(id) => id,
            None => return false,
        };
        if peer_master != self.own_identity {
            return false;
        }
        let cert = match peer_device_cert {
            Some(c) => c,
            None => return false,
        };
        let cs = match self.cluster_state.as_ref() {
            Some(cs) => cs,
            None => return false,
        };
        // Store hex of device_pub_key — used to derive iroh NodeId for reconnect.
        let addr_str = syncback_core::types::hex_encode(&cert.device_pub_key);
        let result = {
            let mut guard = cs.lock().unwrap();
            let r = guard.add_device(cert.clone(), Timestamp::now());
            // Persist address for reconnect after restart (best-effort).
            let _ = guard.set_cluster_addr(cert.device_id, addr_str);
            r
        };
        match result {
            Ok(()) => {
                self.network.add_cluster_peer(cert.device_id, endpoint_addr).await;
                true
            }
            Err(syncback_core::cluster::ClusterStateError::DeviceAlreadyRegistered(_)) => {
                // Still update cluster_peers — addr may have changed.
                self.network.add_cluster_peer(cert.device_id, endpoint_addr).await;
                false
            }
            Err(_) => false,
        }
    }

    // =========================================================
    // Relay dispatch (one-way messages only)
    // =========================================================

    async fn dispatch_relay(&self, msg: InboundMessage) {
        use syncback_core::messages::from_cbor;
        match msg.msg_type.as_str() {
            "peer_announce" => {
                match from_cbor::<PeerAnnounceMsg>(&msg.payload) {
                    Ok(pa) => {
                        if let Err(e) = self.handle_peer_announce(pa).await {
                            warn!(err = %e, "processor: PeerAnnounce via relay failed");
                        }
                    }
                    Err(e) => warn!(err = %e, "processor: failed to decode PeerAnnounce from relay"),
                }
            }
            "pos_challenge" => {
                match from_cbor::<PosChallengeMsg>(&msg.payload) {
                    Ok(challenge) => {
                        match self.handle_pos_challenge_inner(msg.from, challenge).await {
                            Ok(reply) => {
                                // Send response back via board (directed to challenger).
                                let (reply_type, reply_payload) = match &reply {
                                    Message::PosResponse(r) => {
                                        match syncback_core::messages::to_cbor(r) {
                                            Ok(bytes) => ("pos_response", bytes),
                                            Err(e) => { warn!(err = %e, "processor: failed to encode PosResponse"); return; }
                                        }
                                    }
                                    Message::PosNack(n) => {
                                        match syncback_core::messages::to_cbor(n) {
                                            Ok(bytes) => ("pos_nack", bytes),
                                            Err(e) => { warn!(err = %e, "processor: failed to encode PosNack"); return; }
                                        }
                                    }
                                    _ => return,
                                };
                                let mut reply_id = [0u8; 16];
                                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut reply_id);
                                let _ = self.relay_post_tx.send(RelayPost {
                                    msg_type: reply_type.to_string(),
                                    target: Some(msg.from),
                                    payload: reply_payload,
                                    msg_id: reply_id,
                                }).await;
                            }
                            Err(e) => warn!(err = %e, "processor: PosChallenge via relay failed"),
                        }
                    }
                    Err(e) => warn!(err = %e, "processor: failed to decode PosChallenge from relay"),
                }
            }
            "pos_response" => {
                match from_cbor::<PosResponseMsg>(&msg.payload) {
                    Ok(response) => {
                        if let Err(e) = self.handle_pos_response(msg.from, response).await {
                            warn!(err = %e, "processor: PosResponse via relay failed");
                        }
                    }
                    Err(e) => warn!(err = %e, "processor: failed to decode PosResponse from relay"),
                }
            }
            "pos_nack" => {
                match from_cbor::<PosNackMsg>(&msg.payload) {
                    Ok(nack) => {
                        if let Err(e) = self.handle_pos_nack(msg.from, nack).await {
                            warn!(err = %e, "processor: PosNack via relay failed");
                        }
                    }
                    Err(e) => warn!(err = %e, "processor: failed to decode PosNack from relay"),
                }
            }
            "delete" => {
                match from_cbor::<DeleteMsg>(&msg.payload) {
                    Ok(delete) => {
                        if let Err(e) = self.handle_delete(msg.from, delete).await {
                            warn!(err = %e, "processor: Delete via relay failed");
                        }
                    }
                    Err(e) => warn!(err = %e, "processor: failed to decode DeleteMsg from relay"),
                }
            }
            "cancel_delete" => {
                match from_cbor::<CancelDeleteMsg>(&msg.payload) {
                    Ok(cancel) => {
                        if let Err(e) = self.handle_cancel_delete(msg.from, cancel).await {
                            warn!(err = %e, "processor: CancelDelete via relay failed");
                        }
                    }
                    Err(e) => warn!(err = %e, "processor: failed to decode CancelDeleteMsg from relay"),
                }
            }
            "symbol_dropped" => {
                match from_cbor::<SymbolDroppedMsg>(&msg.payload) {
                    Ok(dropped) => {
                        if let Err(e) = self.handle_symbol_dropped(msg.from, dropped).await {
                            warn!(err = %e, "processor: SymbolDropped via relay failed");
                        }
                    }
                    Err(e) => warn!(err = %e, "processor: failed to decode SymbolDroppedMsg from relay"),
                }
            }
            "symbol_drop_notice" => {
                match from_cbor::<SymbolDropNoticeMsg>(&msg.payload) {
                    Ok(notice) => {
                        self.handle_symbol_drop_notice(msg.from, notice);
                    }
                    Err(e) => warn!(err = %e, "processor: failed to decode SymbolDropNoticeMsg from relay"),
                }
            }
            "revocation_broadcast" => {
                match from_cbor::<RevocationBroadcast>(&msg.payload) {
                    Ok(broadcast) => {
                        if let Err(e) = self.handle_revocation_broadcast(msg.from, broadcast).await {
                            warn!(err = %e, "processor: RevocationBroadcast via relay failed");
                        }
                    }
                    Err(e) => warn!(err = %e, "processor: failed to decode RevocationBroadcast from relay"),
                }
            }
            other => {
                debug!(msg_type = %other, "processor: relay message, no handler");
            }
        }
    }

    // =========================================================
    // Message dispatch
    // =========================================================

    async fn dispatch(
        &self,
        from: IdentityPub,
        msg: Message,
        conn: Arc<Connection>,
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
                // Use device-level identity as cursor key (per-device cursors).
                // conn.peer_device_cert carries the peer's device_pub_key from the handshake.
                // Fall back to master identity if cert is unavailable (should not happen).
                let device_identity = conn
                    .peer_device_cert
                    .as_ref()
                    .map(|c| IdentityPub(c.device_pub_key))
                    .unwrap_or(from);
                self.handle_cluster_sync_response(device_identity, response).await?;
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
            Message::SystemStateBackup(msg) => {
                self.handle_system_state_backup(from, msg).await?;
            }
            Message::SystemStateAck(msg) => {
                self.handle_system_state_ack(from, msg);
            }
            Message::SystemStateRequest(msg) => {
                self.handle_system_state_request(from, msg, conn).await?;
            }
            Message::SystemStateResponse(msg) => {
                self.handle_system_state_response(from, msg).await;
            }
            Message::PeerDiscoveryRequest(msg) => {
                self.handle_peer_discovery_request(from, msg, conn).await?;
            }
            Message::PeerDiscoveryResponse(msg) => {
                self.handle_peer_discovery_response(from, msg).await;
            }
            Message::Delete(msg) => {
                self.handle_delete(from, msg).await?;
            }
            Message::CancelDelete(msg) => {
                self.handle_cancel_delete(from, msg).await?;
            }
            Message::SymbolDropNotice(msg) => {
                self.handle_symbol_drop_notice(from, msg);
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

        // Refresh trust_s for this peer: we now store more bytes for them.
        if let Err(e) = self.db.refresh_peer_storage_bytes(&owner_id) {
            error!(
                peer = %owner_id,
                err = %e,
                "processor: failed to refresh storage balance after SymbolTransfer"
            );
        }

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
        conn: Arc<Connection>,
    ) -> Result<(), ProcessorError> {
        let reply = self.handle_pos_challenge_inner(from, challenge).await?;
        conn.send_message(&reply).await?;
        Ok(())
    }

    // =========================================================
    // PosResponse: we are the owner
    // =========================================================

    /// Verify a PoS response from a holder.
    ///
    /// Looks up the pending challenge by challenge_id in the shared PendingChallenges
    /// map (written by Scheduler when the challenge was issued). On match, consumes
    /// the entry and proceeds to verify. If no match is found the response is stale
    /// or unknown and is silently dropped.
    ///
    /// Returns the VerifyOutcome for testing.
    pub(crate) async fn handle_pos_response(
        &self,
        holder_id: IdentityPub,
        response: PosResponseMsg,
    ) -> Result<VerifyOutcome, ProcessorError> {
        // Resolve challenge_id → (source_block_id, map key) via the pending map.
        // Linear scan over in-flight challenges is fine: bounded by active placements,
        // typically in the hundreds.
        let pending_key = {
            let guard = self.pending_challenges.lock().await;
            guard
                .iter()
                .find(|(_, v)| v.challenge_id == response.challenge_id)
                .map(|(k, _)| *k)
        };

        let key = match pending_key {
            Some(k) => k,
            None => {
                warn!(
                    holder = %holder_id,
                    challenge_id = %hex_encode(&response.challenge_id),
                    "processor: PosResponse with unknown challenge_id (stale or duplicate), ignoring"
                );
                return Ok(VerifyOutcome::Pass);
            }
        };

        // Consume the entry — challenge lifecycle ends here regardless of outcome.
        // Also capture the challenged ESI for logging below.
        let esi = {
            let mut guard = self.pending_challenges.lock().await;
            guard.remove(&key).map(|c| c.esi).unwrap_or(response.esi)
        };

        let block_id = key.0;

        // Load the placement record from DB.
        let placement = match self.db.get_placement(&block_id, &holder_id)? {
            Some(p) => p,
            None => {
                warn!(
                    block_id = %block_id,
                    holder = %holder_id,
                    "processor: PosResponse — placement missing from DB, ignoring"
                );
                return Ok(VerifyOutcome::Pass);
            }
        };

        let block_record = match self.db.get_source_block(&block_id)? {
            Some(r) => r,
            None => {
                warn!(
                    block_id = %block_id,
                    holder = %holder_id,
                    "processor: PosResponse — source block DB record missing, cannot verify"
                );
                return Ok(VerifyOutcome::CannotVerify);
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
                    holder = %holder_id,
                    path = %block_path.display(),
                    "processor: PosResponse — source block file missing, cannot verify"
                );
                return Ok(VerifyOutcome::CannotVerify);
            }
            Err(e) => return Err(ProcessorError::Io(e)),
        };

        let params = block_record.erasure_params();

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

        // CannotVerify: owner-side data unavailable. Skip all state updates.
        if outcome == VerifyOutcome::CannotVerify {
            debug!(
                block_id = %block_id,
                holder = %holder_id,
                esi,
                "processor: PoS response received but cannot verify (source block unavailable)"
            );
            return Ok(VerifyOutcome::CannotVerify);
        }

        // Apply placement state transition.
        let transition = apply_pos_outcome(&placement, &outcome);
        let mut updated = placement;
        updated.status = transition.new_status;
        updated.consecutive_misses = transition.new_consecutive_misses;
        if matches!(outcome, VerifyOutcome::Pass) {
            updated.last_verified = Some(Timestamp::now());
        }
        self.db.upsert_placement(&updated)?;

        // Refresh trust_s: placement status changed, so bytes_peer_stores_for_us may differ.
        if let Err(e) = self.db.refresh_peer_storage_bytes(&holder_id) {
            error!(
                peer = %holder_id,
                err = %e,
                "processor: failed to refresh storage balance after PosResponse"
            );
        }

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

        // Refresh trust_s: holder no longer stores those symbols for us.
        if let Err(e) = self.db.refresh_peer_storage_bytes(&from) {
            error!(
                peer = %from,
                err = %e,
                "processor: failed to refresh storage balance after PosNack"
            );
        }

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

        // Refresh trust_s: holder evicted our symbols, bytes_peer_stores_for_us decreased.
        if let Err(e) = self.db.refresh_peer_storage_bytes(&from) {
            error!(
                peer = %from,
                err = %e,
                "processor: failed to refresh storage balance after SymbolDropped"
            );
        }

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
    // Delete: we are the holder
    // =========================================================

    /// Handle a Delete request from the owner. Verify signature, then mark
    /// the holding as MarkedForDelete so the cleanup task can process it later.
    pub(crate) async fn handle_delete(
        &self,
        from: IdentityPub,
        delete: DeleteMsg,
    ) -> Result<(), ProcessorError> {
        let block_id = delete.source_block_id;

        // Verify signature against the sender's identity (the owner).
        if let Err(e) = syncback_core::messages::verify_delete_msg(&delete, &from) {
            warn!(
                block_id = %block_id,
                owner = %from,
                err = %e,
                "processor: Delete signature verification failed"
            );
            return Ok(());
        }

        // Look up the holding — only Active holdings can be marked for deletion.
        match self.db.get_holding(&block_id, &from)? {
            Some(mut holding) => {
                if holding.status == HoldingStatus::Active {
                    holding.status = HoldingStatus::MarkedForDelete;
                    holding.delete_requested_at = Some(Timestamp::now());
                    self.db.upsert_holding(&holding)?;
                    info!(
                        block_id = %block_id,
                        owner = %from,
                        "processor: holding marked for deletion"
                    );
                } else {
                    debug!(
                        block_id = %block_id,
                        owner = %from,
                        status = ?holding.status,
                        "processor: Delete ignored — holding not Active"
                    );
                }
            }
            None => {
                debug!(
                    block_id = %block_id,
                    owner = %from,
                    "processor: Delete ignored — no holding for this block"
                );
            }
        }
        Ok(())
    }

    // =========================================================
    // CancelDelete: we are the holder
    // =========================================================

    /// Handle a CancelDelete from the owner. Revert MarkedForDelete → Active.
    pub(crate) async fn handle_cancel_delete(
        &self,
        from: IdentityPub,
        cancel: CancelDeleteMsg,
    ) -> Result<(), ProcessorError> {
        let block_id = cancel.source_block_id;

        if let Err(e) = syncback_core::messages::verify_cancel_delete_msg(&cancel, &from) {
            warn!(
                block_id = %block_id,
                owner = %from,
                err = %e,
                "processor: CancelDelete signature verification failed"
            );
            return Ok(());
        }

        match self.db.get_holding(&block_id, &from)? {
            Some(mut holding) => {
                if holding.status == HoldingStatus::MarkedForDelete {
                    holding.status = HoldingStatus::Active;
                    holding.delete_requested_at = None;
                    self.db.upsert_holding(&holding)?;
                    info!(
                        block_id = %block_id,
                        owner = %from,
                        "processor: cancel delete — holding reverted to Active"
                    );
                } else {
                    debug!(
                        block_id = %block_id,
                        owner = %from,
                        status = ?holding.status,
                        "processor: CancelDelete ignored — holding not MarkedForDelete"
                    );
                }
            }
            None => {
                debug!(
                    block_id = %block_id,
                    owner = %from,
                    "processor: CancelDelete ignored — no holding for this block"
                );
            }
        }
        Ok(())
    }

    // =========================================================
    // SymbolDropNotice: we are the owner (advance warning)
    // =========================================================

    /// Handle advance eviction notice from a holder. Log for now; repair
    /// will be triggered when the actual SymbolDropped arrives.
    pub(crate) fn handle_symbol_drop_notice(
        &self,
        from: IdentityPub,
        notice: SymbolDropNoticeMsg,
    ) {
        info!(
            block_id = %notice.source_block_id,
            holder = %from,
            deadline = notice.deadline.0,
            "processor: received SymbolDropNotice — holder will drop symbols"
        );
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

        // Hard quota: absolute ceiling — always reject above this.
        if self.hard_quota_bytes > 0 && held_bytes >= self.hard_quota_bytes {
            return Ok(false);
        }

        // Effective soft quota: min(config_soft_quota, disk_free - reserve).
        // When soft_quota=0, uses all available disk minus reserve.
        let disk_free = crate::daemon::handle::disk_available_bytes(&self.data_dir);
        let effective = syncback_core::budget::compute_effective_quota(
            self.soft_quota_bytes,
            disk_free,
            self.disk_reserve_bytes,
        );
        if held_bytes + offer_bytes > effective {
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
        conn: Arc<Connection>,
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

        conn.send_message(&reply).await?;
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

        // Escrow check: verify owner has earned enough restore budget through storage contribution.
        const BYTES_PER_GB: f64 = 1_073_741_824.0;
        let k_factor = self.escrow_cfg.k_factor;
        let stored_gb_days = self.db.stored_for_peer_gb_days(&owner_id, Timestamp::now(), self.time_scale)?;
        let already_restored_bytes = self.db.restored_total_bytes(&owner_id)?;
        let already_restored_gb = already_restored_bytes as f64 / BYTES_PER_GB;
        let this_request_gb = holding
            .esi_ranges
            .iter()
            .map(|&(_start, count)| count as f64 * SYMBOL_SIZE as f64)
            .sum::<f64>()
            / BYTES_PER_GB;
        if let RestoreDecision::Denied(denial) =
            check_restore(stored_gb_days, already_restored_gb, this_request_gb, k_factor)
        {
            warn!(
                owner = %owner_id,
                block_id = %block_id,
                stored_gb_days,
                already_restored_gb,
                this_request_gb,
                budget = denial.restore_budget_gb,
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

        // Increment restore-served counter for this owner after successful symbol load.
        let bytes_served: u64 = symbols.iter().map(|s| s.data.len() as u64).sum();
        if bytes_served > 0 {
            if let Err(e) = self.db.record_restore_served(&owner_id, bytes_served) {
                // Non-fatal: log and continue. Worst case: budget is slightly over-estimated next time.
                warn!(owner = %owner_id, err = %e, "processor: failed to record restore_served");
            }
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
        conn: Arc<Connection>,
    ) -> Result<(), ProcessorError> {
        let block_id = request.source_block_id;
        match self.handle_restore_request_inner(owner_id, request).await {
            Ok(response) => {
                conn.send_message(&Message::RestoreResponse(response))
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
                conn.send_message(&Message::RestoreDenied(denied_msg))
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
                x25519_pub: msg.x25519_pub,
            },
            Some(mut existing) => {
                existing.node_id = Some(msg.node_id);
                existing.last_seen = now;
                if msg.x25519_pub.is_some() {
                    existing.x25519_pub = msg.x25519_pub;
                }
                existing
            }
        };
        self.db.upsert_peer(&record)?;

        // Register the peer in the network layer so get_connection() can reach
        // them. Try to get the full address (IP:port + relay) from iroh's
        // internal state first; fall back to NodeId-only if unavailable.
        match iroh::PublicKey::from_bytes(&msg.node_id.0) {
            Ok(pubkey) => {
                let addr = match self.network.remote_endpoint_addr(pubkey).await {
                    Some(full_addr) => full_addr,
                    None => iroh::EndpointAddr::new(pubkey),
                };
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
    // RevocationBroadcast: mark peer device key as revoked
    // =========================================================

    /// Receive a RevocationBroadcast from the relay board.
    ///
    /// Verifies both the DeviceCertificate and RevocationCertificate signatures
    /// against the broadcaster's master identity (msg.from). If valid, adds the
    /// device pub key to `PeerRecord.revoked_device_pub_keys` for that peer.
    ///
    /// Peers we have no record of are ignored — we only track revocations for
    /// known peers. This avoids creating phantom PeerRecords from forged broadcasts.
    async fn handle_revocation_broadcast(
        &self,
        from: IdentityPub,
        broadcast: RevocationBroadcast,
    ) -> Result<(), ProcessorError> {
        // Verify DeviceCertificate: signed by the peer's master key.
        if let Err(e) =
            syncback_core::cluster::verify_device_certificate(&broadcast.device_cert, &from)
        {
            warn!(
                peer = %from,
                err = %e,
                "processor: RevocationBroadcast — invalid DeviceCertificate, ignoring"
            );
            return Ok(());
        }

        // Verify RevocationCertificate: signed by the peer's master key.
        if let Err(e) = syncback_core::cluster::verify_revocation(&broadcast.revocation, &from) {
            warn!(
                peer = %from,
                err = %e,
                "processor: RevocationBroadcast — invalid RevocationCertificate, ignoring"
            );
            return Ok(());
        }

        // Cross-check: both certs must refer to the same device_id.
        if broadcast.revocation.device_id != broadcast.device_cert.device_id {
            warn!(
                peer = %from,
                revocation_device = ?broadcast.revocation.device_id,
                cert_device = ?broadcast.device_cert.device_id,
                "processor: RevocationBroadcast — device_id mismatch, ignoring"
            );
            return Ok(());
        }

        let revoked_pub = broadcast.device_cert.device_pub_key;

        // Only update PeerRecords we already know about. Unknown peers are skipped.
        let mut record = match self.db.get_peer(&from)? {
            Some(r) => r,
            None => {
                debug!(
                    peer = %from,
                    "processor: RevocationBroadcast from unknown peer, ignoring"
                );
                return Ok(());
            }
        };

        if record.revoked_device_pub_keys.contains(&revoked_pub) {
            debug!(peer = %from, "processor: RevocationBroadcast device already in revoked list");
            return Ok(());
        }

        record.revoked_device_pub_keys.push(revoked_pub);
        self.db.upsert_peer(&record)?;

        info!(
            peer = %from,
            device_id = ?broadcast.revocation.device_id,
            "processor: RevocationBroadcast applied — device key marked revoked"
        );

        Ok(())
    }

    // =========================================================
    // ClusterSyncRequest: serve event log to a peer device
    // =========================================================

    async fn handle_cluster_sync_request(
        &self,
        from: IdentityPub,
        request: ClusterSyncRequestMsg,
        conn: Arc<Connection>,
    ) -> Result<(), ProcessorError> {
        match self.cluster_sync.handle_sync_request(&request) {
            Ok(response) => {
                conn.send_message(&Message::ClusterSyncResponse(response))
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

    // =========================================================
    // SystemStateBackup: we are the holder
    // =========================================================

    /// Receive and store a system state blob from a peer.
    /// Only accepts blobs from known peers to prevent storage spam.
    /// Sends a SystemStateAck back regardless of outcome.
    pub(crate) async fn handle_system_state_backup(
        &self,
        owner_id: IdentityPub,
        backup: SystemStateBackupMsg,
    ) -> Result<(), ProcessorError> {
        if backup.encrypted_blob.is_empty() {
            warn!(peer = %owner_id, "processor: SystemStateBackup: empty blob, ignoring");
            let ack = Message::SystemStateAck(SystemStateAckMsg {
                v: 1,
                stored: false,
                timestamp: Timestamp::now(),
            });
            let _ = self.network.send_to_peer(owner_id, &ack).await;
            return Ok(());
        }
        // Only accept from known peers (prevent storage spam from strangers).
        if self.db.get_peer(&owner_id)?.is_none() {
            warn!(peer = %owner_id, "processor: SystemStateBackup: unknown peer, rejecting");
            let ack = Message::SystemStateAck(SystemStateAckMsg {
                v: 1,
                stored: false,
                timestamp: Timestamp::now(),
            });
            let _ = self.network.send_to_peer(owner_id, &ack).await;
            return Ok(());
        }
        let record = SystemStateBlobRecord {
            owner: owner_id,
            encrypted_blob: backup.encrypted_blob,
            created_at: backup.timestamp,
            stored_at: Timestamp::now(),
        };
        self.db.store_system_state_blob(&owner_id, &record)?;
        info!(peer = %owner_id, "processor: SystemStateBackup: stored");
        let ack = Message::SystemStateAck(SystemStateAckMsg {
            v: 1,
            stored: true,
            timestamp: Timestamp::now(),
        });
        let _ = self.network.send_to_peer(owner_id, &ack).await;
        Ok(())
    }

    // =========================================================
    // SystemStateAck: we are the owner
    // =========================================================

    /// Log receipt of a system state ack from a holder.
    pub(crate) fn handle_system_state_ack(&self, peer_id: IdentityPub, ack: SystemStateAckMsg) {
        if ack.stored {
            info!(peer = %peer_id, "processor: SystemStateAck: stored");
        } else {
            warn!(peer = %peer_id, "processor: SystemStateAck: rejected");
        }
    }

    // =========================================================
    // SystemStateRequest: we are the holder
    // =========================================================

    /// Respond to a system state request with the stored blob for the requester.
    /// Sends an empty blob if nothing is stored.
    pub(crate) async fn handle_system_state_request(
        &self,
        requester_id: IdentityPub,
        _req: SystemStateRequestMsg,
        conn: Arc<Connection>,
    ) -> Result<(), ProcessorError> {
        let blob = match self.db.get_system_state_blob(&requester_id)? {
            Some(r) => r.encrypted_blob,
            None => vec![],
        };
        let found = !blob.is_empty();
        debug!(peer = %requester_id, found, "processor: SystemStateRequest: responding");
        let resp = Message::SystemStateResponse(SystemStateResponseMsg {
            v: 1,
            encrypted_blob: blob,
            timestamp: Timestamp::now(),
        });
        conn.send_message(&resp).await?;
        Ok(())
    }

    // =========================================================
    // SystemStateResponse: we are the DR/owner requester
    // =========================================================

    /// Log a system state response.
    /// The disaster recovery flow handles this via a dedicated channel; here we
    /// only log so that the dispatch loop does not drop it silently.
    pub(crate) async fn handle_system_state_response(
        &self,
        peer_id: IdentityPub,
        _resp: SystemStateResponseMsg,
    ) {
        debug!(
            peer = %peer_id,
            "processor: SystemStateResponse: received (not in DR mode, ignoring)"
        );
    }

    // =========================================================
    // PeerDiscoveryRequest: respond with known peer list
    // =========================================================

    /// Respond to a peer discovery request with all peers known to this node.
    pub(crate) async fn handle_peer_discovery_request(
        &self,
        requester_id: IdentityPub,
        _req: PeerDiscoveryRequestMsg,
        conn: Arc<Connection>,
    ) -> Result<(), ProcessorError> {
        let peers = self.db.list_all_peers()?;
        let discovered: Vec<DiscoveredPeer> = peers
            .iter()
            .filter_map(|p| {
                p.node_id.map(|nid| DiscoveredPeer {
                    identity_pub: p.identity,
                    node_id: nid,
                    addrs: p.addrs.clone(),
                })
            })
            .collect();
        debug!(
            peer = %requester_id,
            count = discovered.len(),
            "processor: PeerDiscoveryRequest: responding"
        );
        let resp = Message::PeerDiscoveryResponse(PeerDiscoveryResponseMsg {
            v: 1,
            peers: discovered,
            timestamp: Timestamp::now(),
        });
        conn.send_message(&resp).await?;
        Ok(())
    }

    // =========================================================
    // PeerDiscoveryResponse: we are the bootstrap/DR requester
    // =========================================================

    /// Handle a peer discovery response: register each discovered peer in the
    /// network layer so future `get_connection` calls can reach them.
    ///
    /// For each peer in the response:
    ///   - Skip if identity == our own identity.
    ///   - Try to build an EndpointAddr from the first parseable addr string.
    ///   - Fall back to NodeId-only EndpointAddr (iroh relay/DNS discovery).
    ///   - Call network.add_peer to register in-memory.
    ///   - DB persistence happens later via PeerAnnounce on handshake.
    pub(crate) async fn handle_peer_discovery_response(
        &self,
        peer_id: IdentityPub,
        resp: PeerDiscoveryResponseMsg,
    ) {
        use crate::daemon::network::addr::{parse_node_addr, to_endpoint_addr};

        info!(
            peer = %peer_id,
            discovered_count = resp.peers.len(),
            "processor: PeerDiscoveryResponse: received"
        );

        let mut connected = 0usize;
        for dp in &resp.peers {
            if dp.identity_pub == self.own_identity {
                debug!(
                    peer = %dp.identity_pub,
                    "processor: PeerDiscoveryResponse: skipping self"
                );
                continue;
            }

            if self.db.get_peer(&dp.identity_pub).ok().flatten().is_none() {
                debug!(
                    peer = %dp.identity_pub,
                    "processor: PeerDiscoveryResponse: new peer discovered"
                );
            }

            // Build EndpointAddr: try each addr string, use first parseable one.
            // Fall back to NodeId-only if none parse (iroh relay/DNS will resolve).
            let endpoint_addr = match iroh::PublicKey::from_bytes(&dp.node_id.0) {
                Err(e) => {
                    warn!(
                        identity = %dp.identity_pub,
                        err = %e,
                        "processor: PeerDiscoveryResponse: invalid NodeId bytes, skipping"
                    );
                    continue;
                }
                Ok(pubkey) => {
                    let mut resolved: Option<iroh::EndpointAddr> = None;
                    for addr_str in &dp.addrs {
                        match parse_node_addr(addr_str) {
                            Ok(parsed) => match to_endpoint_addr(&parsed) {
                                Ok(ea) => {
                                    resolved = Some(ea);
                                    break;
                                }
                                Err(e) => {
                                    debug!(
                                        addr = %addr_str,
                                        err = %e,
                                        "processor: PeerDiscoveryResponse: to_endpoint_addr failed"
                                    );
                                }
                            },
                            Err(e) => {
                                debug!(
                                    addr = %addr_str,
                                    err = %e,
                                    "processor: PeerDiscoveryResponse: addr parse failed"
                                );
                            }
                        }
                    }
                    resolved.unwrap_or_else(|| iroh::EndpointAddr::new(pubkey))
                }
            };

            self.network.add_peer(dp.identity_pub, endpoint_addr).await;

            // Connect to a limited number of discovered peers per response.
            // Remaining peers are in known_peers and will be connected in
            // future discovery rounds or when get_connection is called.
            if connected < 5 {
                match self.network.get_connection(dp.identity_pub).await {
                    Ok(_) => {
                        connected += 1;
                        info!(
                            identity = %dp.identity_pub,
                            "processor: PeerDiscoveryResponse: connected to discovered peer"
                        );
                    }
                    Err(e) => {
                        debug!(
                            identity = %dp.identity_pub,
                            err = %e,
                            "processor: PeerDiscoveryResponse: connect failed (peer may be offline)"
                        );
                    }
                }
            }
        }
        info!(
            peer = %peer_id,
            added = resp.peers.len(),
            connected,
            "processor: PeerDiscoveryResponse: done"
        );
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

