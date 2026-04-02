// Message Router (Processor): routes incoming connections and dispatches messages.
//
// Responsibilities:
//   - Accept ProtocolEvent from the libp2p SwarmHandle event_rx.
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
//   PeerAnnounce received   → upsert peer record in DB
//   ClusterSyncRequest      → we are cluster peer → serve event log entries
//   ClusterSyncResponse     → we are cluster peer → apply received events
//
// ε.2 — libp2p wiring:
//   Processor now consumes ProtocolEvent from SwarmHandle.
//   PeerAuthenticated → upsert PeerRecord, auto-add cluster device, send PeerAnnounce.
//   InboundRequest    → dispatch_libp2p: match Message variant, call handler, send via ResponseChannel.
//   ConnectionClosed  → remove from peer_cert_map.
//   One-way messages (PoS, Delete, Drop) still arrive via relay board (dispatch_relay).
//
// Design note: PosResponseMsg on the wire does not carry source_block_id.
// We recover it by scanning placements for the holder and finding one whose
// ESI ranges include the challenged ESI. This is a Phase 6.3 simplification;
// Phase 6.5 (Scheduler) will track challenge context in a pending table.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use libp2p::request_response::ResponseChannel;
use libp2p::PeerId;
use syncback_core::cluster::DeviceCertificate;
use syncback_core::config::EscrowCfg;
use syncback_core::constants::{
    HANDSHAKE_FRESHNESS_SECS, INITIAL_TRUST_P, P_WINDOW_WEEKS, SYMBOL_OFFER_EXPIRY_SECS,
    SYMBOL_SIZE,
};
use syncback_core::escrow::{check_restore, RestoreDecision};
use syncback_core::db::{Db, SystemStateBlobRecord, WeeklyPosEntry};
use syncback_core::erasure::{ErasureEncoder, Symbol};
use syncback_core::messages::{
    verify_symbol_offer, AckMsg, BoardSyncMsg, CancelDeleteMsg, ClusterSyncRequestMsg,
    ClusterSyncResponseMsg, DeleteMsg, Message, PeerAnnounceMsg,
    PosChallengeMsg, PosNackMsg, PosResponseMsg,
    RejectReason, RestoreDeniedMsg, RestoreRequestMsg, RestoreResponseMsg, RevocationBroadcast,
    SymbolAcceptMsg, SymbolDropNoticeMsg, SymbolDroppedMsg, SymbolOfferMsg, SymbolRejectMsg,
    SymbolTransferMsg, SystemStateAckMsg, SystemStateBackupMsg, SystemStateRequestMsg,
    SystemStateResponseMsg, verify_peer_announce,
};
use syncback_core::pos::{
    apply_pos_outcome, outcome_from_verify, verify_response, PosResponse, VerifyOutcome,
};
use syncback_core::trust::{
    compute_combined, recompute_master_trust, DeviceTrustRecord, MasterTrustRecord, PosOutcome,
};
use syncback_core::types::{
    hex_encode, DeviceId, HoldingRecord, HoldingStatus, IdentityPub, PeerRecord, PlacementStatus,
    SourceBlockId, Timestamp,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::daemon::cluster_sync::ClusterSyncManager;
use crate::daemon::network::swarm::{ProtocolEvent, SwarmHandle};
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

    #[error("swarm error: {0}")]
    Swarm(#[from] crate::daemon::network::swarm::SwarmError),

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

// ─── Offer / delivery state ───────────────────────────────────────────────────

/// An accepted symbol offer awaiting transfer from the owner.
#[derive(Debug, Clone)]
pub struct AcceptedOffer {
    pub owner_id: IdentityPub,
    pub source_block_id: SourceBlockId,
    pub esi_ranges: Vec<(u32, u32)>,
    pub importance: f64,
    pub accepted_at: Timestamp,
}

/// Shared map of accepted offers: (owner_id, block_id) → AcceptedOffer.
/// Written by handle_symbol_offer, read+removed by handle_symbol_transfer.
/// Uses std::sync::Mutex (not tokio::sync::Mutex) because locks are never held
/// across .await points — only brief insert/remove under the lock.
pub type AcceptedOffers = Arc<Mutex<HashMap<(IdentityPub, SourceBlockId), AcceptedOffer>>>;

/// Construct an empty `AcceptedOffers` map (useful in tests and wiring).
pub fn make_empty_accepted_offers() -> AcceptedOffers {
    Arc::new(Mutex::new(HashMap::new()))
}

// ─── Processor ────────────────────────────────────────────────────────────────

/// Routes incoming connections and dispatches messages to appropriate handlers.
pub struct Processor {
    db: Db,
    /// Our identity.
    pub(crate) own_identity: IdentityPub,
    repair_tx: mpsc::Sender<RepairTrigger>,
    cluster_sync: Arc<ClusterSyncManager>,
    encoder: Arc<dyn ErasureEncoder>,
    /// Directory where we store symbols held for others: `{holdings_dir}/{block_id_hex}/{esi}.bin`
    holdings_dir: PathBuf,
    /// Directory where our own source blocks live (for PoS verification as owner):
    /// `{source_blocks_dir}/{block_id_hex}/block.bin`
    source_blocks_dir: PathBuf,
    /// libp2p swarm handle.
    swarm: Arc<SwarmHandle>,
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
    /// Accepted symbol offers awaiting SymbolTransfer from the owner.
    /// Key: (owner_id, block_id). Entries expire after SYMBOL_OFFER_EXPIRY_SECS.
    pub(crate) accepted_offers: AcceptedOffers,
    /// Authenticated peer map: DeviceId → (IdentityPub, DeviceCertificate).
    /// Written by on_peer_authenticated, cleared by on_connection_closed.
    /// Used by handle_cluster_sync_request_libp2p to validate from_device_id.
    peer_cert_map: Arc<std::sync::Mutex<HashMap<DeviceId, (IdentityPub, DeviceCertificate)>>>,
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
        swarm: Arc<SwarmHandle>,
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
        accepted_offers: AcceptedOffers,
    ) -> Self {
        Processor {
            db,
            own_identity,
            repair_tx,
            cluster_sync,
            encoder,
            holdings_dir,
            source_blocks_dir,
            swarm,
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
            accepted_offers,
            peer_cert_map: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Main loop: receive ProtocolEvents from the libp2p swarm and relay-board messages.
    ///
    /// Dispatches each event to its handler in a new tokio::spawn task (I4 preserved).
    /// - swarm_rx: ProtocolEvent stream from SwarmHandle (PeerAuthenticated, InboundRequest, ConnectionClosed)
    /// - inbound_rx: relay board one-way messages (PoS, Delete, Drop, PeerAnnounce, etc.)
    pub async fn run(
        self,
        mut swarm_rx: mpsc::Receiver<ProtocolEvent>,
        mut inbound_rx: mpsc::Receiver<InboundMessage>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        let this = Arc::new(self);

        info!("processor running");

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("processor: cancellation requested, shutting down");
                    break;
                }

                maybe_event = swarm_rx.recv() => {
                    match maybe_event {
                        None => {
                            info!("processor: swarm_rx closed, shutting down");
                            break;
                        }
                        Some(ProtocolEvent::PeerAuthenticated {
                            peer_id,
                            device_id,
                            identity_pub,
                            device_cert,
                            x25519_pub,
                        }) => {
                            let this2 = this.clone();
                            tokio::spawn(async move {
                                this2.on_peer_authenticated(
                                    peer_id, device_id, identity_pub, device_cert, x25519_pub,
                                ).await;
                            });
                        }
                        Some(ProtocolEvent::InboundRequest {
                            from_device,
                            from_master,
                            message,
                            response_channel,
                        }) => {
                            let this2 = this.clone();
                            tokio::spawn(async move {
                                if let Err(e) = this2
                                    .dispatch_libp2p(
                                        from_device,
                                        from_master,
                                        message,
                                        response_channel,
                                    )
                                    .await
                                {
                                    error!(
                                        device = %from_device,
                                        err = %e,
                                        "processor: error handling libp2p message"
                                    );
                                }
                            });
                        }
                        Some(ProtocolEvent::ConnectionClosed { peer_id, device_id }) => {
                            let this2 = this.clone();
                            tokio::spawn(async move {
                                this2.on_connection_closed(peer_id, device_id).await;
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
    // libp2p event handlers
    // =========================================================

    /// Called when DeviceCertExchange succeeds for a peer (AC-1, AC-2).
    ///
    /// 1. Stores (identity_pub, device_cert) in peer_cert_map under device_id.
    /// 2. Upserts PeerRecord in DB (sets device_id and x25519_pub fields).
    /// 3. Calls try_auto_add_cluster_device if peer has same master identity.
    /// 4. Sends PeerAnnounce to the newly authenticated peer via swarm.
    async fn on_peer_authenticated(
        &self,
        _peer_id: PeerId,
        device_id: DeviceId,
        identity_pub: IdentityPub,
        device_cert: DeviceCertificate,
        x25519_pub: Option<[u8; 32]>,
    ) {
        // 1. Store in peer_cert_map.
        {
            let mut map = self.peer_cert_map.lock().unwrap();
            map.insert(device_id, (identity_pub, device_cert.clone()));
        }

        // 2. Upsert PeerRecord in DB (keyed by DeviceId).
        let now = Timestamp::now();
        let record = match self.db.get_peer(&device_id) {
            Ok(Some(mut existing)) => {
                existing.master_identity = identity_pub;
                existing.last_seen = now;
                if x25519_pub.is_some() {
                    existing.x25519_pub = x25519_pub;
                }
                if existing.trust_p == 0.0 && existing.trust_i == 0.0 {
                    existing.trust_p = INITIAL_TRUST_P;
                }
                existing
            }
            Ok(None) => PeerRecord {
                device_id,
                master_identity: identity_pub,
                trust_p: INITIAL_TRUST_P,
                trust_i: 0.0,
                trust_s: 1.0,
                bytes_we_store_for_peer: 0,
                bytes_peer_stores_for_us: 0,
                first_seen: now,
                last_seen: now,
                revoked_device_pub_keys: vec![],
                addrs: vec![],
                x25519_pub,
            },
            Err(e) => {
                error!(
                    device = %device_id,
                    err = %e,
                    "processor: on_peer_authenticated: db.get_peer failed"
                );
                return;
            }
        };
        if let Err(e) = self.db.upsert_peer(&record) {
            error!(
                device = %device_id,
                err = %e,
                "processor: on_peer_authenticated: db.upsert_peer failed"
            );
        }

        // Store device-to-master mapping for two-level trust.
        if let Err(e) = self.db.set_master_for_device(&device_id, &identity_pub) {
            error!(
                device = %device_id,
                err = %e,
                "processor: on_peer_authenticated: failed to store device-to-master mapping"
            );
        }

        // 3. Auto-add cluster device if same master identity.
        self.try_auto_add_cluster_device(Some(identity_pub), Some(device_cert)).await;

        // 4. Send PeerAnnounce so the peer learns our identity ↔ DeviceId binding.
        let pa = self.swarm.build_peer_announce(Timestamp::now());
        let pa_msg = Message::PeerAnnounce(pa);
        if let Err(e) = self.swarm.send_to_device(device_id, pa_msg).await {
            warn!(
                device = %device_id,
                err = %e,
                "processor: on_peer_authenticated: failed to send PeerAnnounce"
            );
        } else {
            debug!(device = %device_id, "processor: sent PeerAnnounce after authentication");
        }
    }

    /// Dispatch a libp2p InboundRequest to the correct handler.
    ///
    /// Every request must receive a response (libp2p request-response contract).
    /// Handlers that previously used conn.send_message now send via ResponseChannel.
    async fn dispatch_libp2p(
        &self,
        from_device: DeviceId,
        from_master: IdentityPub,
        message: Message,
        response_channel: ResponseChannel<Message>,
    ) -> anyhow::Result<()> {
        match message {
            Message::SymbolTransfer(transfer) => {
                self.handle_symbol_transfer(from_master, transfer).await?;
                let ack = Message::SystemStateAck(SystemStateAckMsg {
                    v: 1,
                    stored: true,
                    timestamp: Timestamp::now(),
                });
                let _ = self.swarm.respond(response_channel, ack);
            }
            Message::PosChallenge(challenge) => {
                match self.handle_pos_challenge_inner(from_master, challenge).await {
                    Ok(reply) => {
                        let _ = self.swarm.respond(response_channel, reply);
                    }
                    Err(e) => {
                        warn!(device = %from_device, err = %e, "processor: PosChallenge handler failed");
                    }
                }
            }
            Message::SymbolOffer(offer) => {
                let reply = self.handle_symbol_offer_inner(from_master, offer);
                let _ = self.swarm.respond(response_channel, reply);
            }
            Message::RestoreRequest(req) => {
                let block_id = req.source_block_id;
                let reply = match self.handle_restore_request_inner(from_master, req).await {
                    Ok(resp) => Message::RestoreResponse(resp),
                    Err(ProcessorError::EscrowDenied { denial, .. }) => {
                        let _ = &denial;
                        Message::RestoreDenied(RestoreDeniedMsg {
                            v: 1,
                            source_block_id: block_id,
                            reason: "escrow check failed".to_string(),
                            current_trust: 0.0,
                            needed_trust: 0.0,
                            restore_budget_gb: 0.0,
                            timestamp: Timestamp::now(),
                        })
                    }
                    Err(e) => {
                        warn!(device = %from_device, err = %e, "processor: RestoreRequest handler failed");
                        return Ok(());
                    }
                };
                let _ = self.swarm.respond(response_channel, reply);
            }
            Message::BoardSync(msg) => {
                if let Err(e) = self.handle_board_sync(from_master, msg).await {
                    warn!(device = %from_device, err = %e, "processor: BoardSync handler failed");
                }
                let ack = Message::SystemStateAck(SystemStateAckMsg {
                    v: 1,
                    stored: true,
                    timestamp: Timestamp::now(),
                });
                let _ = self.swarm.respond(response_channel, ack);
            }
            Message::SystemStateBackup(backup) => {
                let ack = self.handle_system_state_backup_inner(from_master, backup).await;
                let _ = self.swarm.respond(response_channel, Message::SystemStateAck(ack));
            }
            Message::SystemStateRequest(req) => {
                let resp = self.handle_system_state_request_inner(from_master, req).await;
                let _ = self.swarm.respond(response_channel, Message::SystemStateResponse(resp));
            }
            Message::ClusterSyncRequest(req) => {
                self.handle_cluster_sync_request_libp2p(
                    from_device,
                    from_master,
                    req,
                    response_channel,
                )
                .await?;
            }
            Message::ClusterSyncResponse(resp) => {
                if from_master != self.own_identity {
                    warn!(
                        from = %from_master,
                        own = %self.own_identity,
                        "processor: ClusterSyncResponse from non-cluster peer, ignoring"
                    );
                    let _ = self.swarm.respond(response_channel, Message::Ack(AckMsg { v: 1 }));
                    return Ok(());
                }
                if let Err(e) = self.handle_cluster_sync_response(from_device, resp).await {
                    warn!(device = %from_device, err = %e, "processor: ClusterSyncResponse handler failed");
                }
                let ack = Message::SystemStateAck(SystemStateAckMsg {
                    v: 1,
                    stored: true,
                    timestamp: Timestamp::now(),
                });
                let _ = self.swarm.respond(response_channel, ack);
            }
            Message::SymbolAccept(accept) => {
                if let Err(e) = self.handle_symbol_accept(from_master, accept).await {
                    warn!(device = %from_device, err = %e, "processor: SymbolAccept handler failed");
                }
                let ack = Message::SystemStateAck(SystemStateAckMsg {
                    v: 1,
                    stored: true,
                    timestamp: Timestamp::now(),
                });
                let _ = self.swarm.respond(response_channel, ack);
            }
            Message::SymbolReject(reject) => {
                if let Err(e) = self.handle_symbol_reject(from_master, reject).await {
                    warn!(device = %from_device, err = %e, "processor: SymbolReject handler failed");
                }
                let ack = Message::SystemStateAck(SystemStateAckMsg {
                    v: 1,
                    stored: true,
                    timestamp: Timestamp::now(),
                });
                let _ = self.swarm.respond(response_channel, ack);
            }
            Message::RestoreDenied(denied) => {
                if let Err(e) = self.handle_restore_denied(from_master, denied).await {
                    warn!(device = %from_device, err = %e, "processor: RestoreDenied handler failed");
                }
                let ack = Message::SystemStateAck(SystemStateAckMsg {
                    v: 1,
                    stored: true,
                    timestamp: Timestamp::now(),
                });
                let _ = self.swarm.respond(response_channel, ack);
            }
            Message::PeerAnnounce(pa) => {
                if let Err(e) = self.handle_peer_announce(pa).await {
                    warn!(device = %from_device, err = %e, "processor: PeerAnnounce handler failed");
                }
                let ack = Message::SystemStateAck(SystemStateAckMsg {
                    v: 1,
                    stored: true,
                    timestamp: Timestamp::now(),
                });
                let _ = self.swarm.respond(response_channel, ack);
            }
            Message::SystemStateAck(ack) => {
                self.handle_system_state_ack(from_master, ack);
                let resp = Message::SystemStateAck(SystemStateAckMsg {
                    v: 1,
                    stored: true,
                    timestamp: Timestamp::now(),
                });
                let _ = self.swarm.respond(response_channel, resp);
            }
            Message::SystemStateResponse(resp) => {
                self.handle_system_state_response(from_master, resp).await;
                let ack = Message::SystemStateAck(SystemStateAckMsg {
                    v: 1,
                    stored: true,
                    timestamp: Timestamp::now(),
                });
                let _ = self.swarm.respond(response_channel, ack);
            }
            other => {
                warn!(
                    device = %from_device,
                    "processor: dispatch_libp2p: unhandled message variant {:?}",
                    std::mem::discriminant(&other)
                );
                let ack = Message::SystemStateAck(SystemStateAckMsg {
                    v: 1,
                    stored: false,
                    timestamp: Timestamp::now(),
                });
                let _ = self.swarm.respond(response_channel, ack);
            }
        }
        Ok(())
    }

    /// Called when a libp2p connection closes (AC-13).
    ///
    /// Removes the device from peer_cert_map if present.
    async fn on_connection_closed(&self, _peer_id: PeerId, device_id: Option<DeviceId>) {
        if let Some(dev_id) = device_id {
            let removed = {
                let mut map = self.peer_cert_map.lock().unwrap();
                map.remove(&dev_id).is_some()
            };
            debug!(device = %dev_id, removed, "processor: connection closed, removed from peer_cert_map");
        } else {
            debug!("processor: unauthenticated connection closed");
        }
    }

    // =========================================================
    // Cluster auto-add helper
    // =========================================================

    /// Auto-add a cluster device if the peer has the same master identity as this node.
    ///
    /// Checks whether `peer_master_identity == own_identity`. If so, calls
    /// `cluster_state.add_device`. Routing is by DeviceId via SwarmHandle's
    /// internal authenticated map — no explicit address registration needed.
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
        // Store hex of device_id.0 (= device pub key) — used for reconnect.
        let addr_str = syncback_core::types::hex_encode(&cert.device_id.0);
        let result = {
            let mut guard = cs.lock().unwrap();
            let r = guard.add_device(cert.clone(), Timestamp::now());
            // Persist address for reconnect after restart (best-effort).
            let _ = guard.set_cluster_addr(cert.device_id, addr_str);
            r
        };
        match result {
            Ok(()) => {
                // libp2p routing is by DeviceId via SwarmHandle's authenticated map.
                // No explicit address registration needed (unlike iroh).
                true
            }
            Err(syncback_core::cluster::ClusterStateError::DeviceAlreadyRegistered(_)) => {
                // libp2p routing is by DeviceId; no explicit address update needed.
                debug!(device = %cert.device_id, "cluster: device already registered, skipping add");
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
                        // Resolve DeviceId: use device_id from message body if present,
                        // else fall back to first device for the master (msg.from).
                        let holder_device = response.device_id
                            .or_else(|| self.db.get_devices_for_master(&msg.from).ok()
                                .and_then(|ds| ds.into_iter().next()))
                            .unwrap_or(DeviceId(msg.from.0));
                        if let Err(e) = self.handle_pos_response(holder_device, response).await {
                            warn!(err = %e, "processor: PosResponse via relay failed");
                        }
                    }
                    Err(e) => warn!(err = %e, "processor: failed to decode PosResponse from relay"),
                }
            }
            "pos_nack" => {
                match from_cbor::<PosNackMsg>(&msg.payload) {
                    Ok(nack) => {
                        // Resolve DeviceId: use device_id from message body if present,
                        // else fall back to first device for the master (msg.from).
                        let from_device = nack.device_id
                            .or_else(|| self.db.get_devices_for_master(&msg.from).ok()
                                .and_then(|ds| ds.into_iter().next()))
                            .unwrap_or(DeviceId(msg.from.0));
                        if let Err(e) = self.handle_pos_nack(from_device, nack).await {
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
                        // SymbolDropped comes from a holder — resolve DeviceId from master.
                        let from_device = self.db.get_devices_for_master(&msg.from).ok()
                            .and_then(|ds| ds.into_iter().next())
                            .unwrap_or(DeviceId(msg.from.0));
                        if let Err(e) = self.handle_symbol_dropped(from_device, dropped).await {
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
    // SymbolTransfer: we are the holder
    // =========================================================

    /// Store received symbols on disk and record a HoldingRecord in the DB.
    ///
    /// File layout: `{holdings_dir}/{block_id_hex}/{esi}.bin`
    ///
    /// Requires a prior accepted offer in `accepted_offers` for `(owner_id, block_id)`.
    /// If no offer is found: silently rejects (does not store anything).
    /// If the offer is expired: removes and silently rejects.
    /// If any ESI is outside the accepted ranges: rejects (offer consumed).
    pub(crate) async fn handle_symbol_transfer(
        &self,
        owner_id: IdentityPub,
        transfer: SymbolTransferMsg,
    ) -> Result<(), ProcessorError> {
        let block_id = transfer.source_block_id;

        // ── Offer lookup + validation ─────────────────────────────────────────
        let (importance, accepted_esi_ranges) = {
            let mut map = self.accepted_offers.lock().unwrap();
            let key = (owner_id, block_id);
            match map.remove(&key) {
                None => {
                    warn!(
                        block_id = %block_id,
                        owner = %owner_id,
                        "processor: SymbolTransfer rejected — no accepted offer"
                    );
                    return Ok(());
                }
                Some(entry) => {
                    let now = Timestamp::now().0;
                    let age = now.saturating_sub(entry.accepted_at.0);
                    if age > SYMBOL_OFFER_EXPIRY_SECS {
                        debug!(
                            block_id = %block_id,
                            owner = %owner_id,
                            age_secs = age,
                            "processor: accepted offer expired — rejecting SymbolTransfer"
                        );
                        return Ok(());
                    }
                    (entry.importance, entry.esi_ranges)
                }
            }
        };

        // ── ESI range validation ──────────────────────────────────────────────
        for symbol in &transfer.symbols {
            let esi = symbol.esi;
            let in_range = accepted_esi_ranges
                .iter()
                .any(|&(start, count)| esi >= start && esi < start + count);
            if !in_range {
                warn!(
                    block_id = %block_id,
                    owner = %owner_id,
                    esi,
                    "processor: SymbolTransfer rejected — ESI out of accepted range"
                );
                return Ok(());
            }
        }

        // ── Write symbols to disk ─────────────────────────────────────────────
        let block_hex = hex_encode(&block_id.0);
        let block_dir = self.holdings_dir.join(&block_hex);

        tokio::fs::create_dir_all(&block_dir).await?;

        let mut received_esis: Vec<u32> = Vec::with_capacity(transfer.symbols.len());
        let mut total_bytes: u64 = 0;

        for symbol in &transfer.symbols {
            // Reject oversized symbols: expected size is SYMBOL_SIZE (65535 bytes).
            // Without this check, a malicious peer could write up to MAX_MESSAGE_SIZE
            // per symbol, bypassing quota accounting.
            if symbol.data.len() > SYMBOL_SIZE as usize {
                warn!(
                    block_id = %block_id,
                    owner = %owner_id,
                    esi = symbol.esi,
                    size = symbol.data.len(),
                    expected = SYMBOL_SIZE,
                    "processor: SymbolTransfer rejected — oversized symbol"
                );
                return Ok(());
            }
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
                // importance: keep existing value (BR-7). New offer may have different
                // importance, but the holding was already accepted at its original importance.
                existing
            }
            None => HoldingRecord {
                source_block_id: block_id,
                owner_id,
                esi_ranges: new_ranges,
                // importance comes from the validated AcceptedOffer (verified by handle_symbol_offer).
                importance,
                total_bytes,
                status: HoldingStatus::Active,
                received_at: Timestamp::now(),
                delete_requested_at: None,
                drop_notice_sent_at: None,
            },
        };

        self.db.upsert_holding(&record)?;

        // Refresh trust_s for all devices of this peer's master identity.
        for did in self.db.get_devices_for_master(&owner_id).unwrap_or_default() {
            if let Err(e) = self.db.refresh_peer_storage_bytes(&did) {
                error!(
                    peer = %owner_id,
                    device = %did,
                    err = %e,
                    "processor: failed to refresh storage balance after SymbolTransfer"
                );
            }
        }

        info!(
            block_id = %block_id,
            owner = %owner_id,
            symbols = transfer.symbols.len(),
            "processor: stored symbols for block"
        );

        // In the libp2p path an Ack is sent via ResponseChannel in dispatch_libp2p.
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
        owner_id: IdentityPub,
        challenge: syncback_core::messages::PosChallengeMsg,
    ) -> Result<Message, ProcessorError> {
        let block_id = challenge.source_block_id;
        let esi = challenge.esi;

        // Verify we actually hold symbols for this owner+block.
        // Without this check, any authenticated peer could probe our holdings
        // for arbitrary block IDs and receive symbol data.
        match self.db.get_holding(&block_id, &owner_id)? {
            Some(_) => {}
            None => {
                warn!(
                    block_id = %block_id,
                    challenger = %owner_id,
                    "processor: PoS challenge from non-owner, ignoring"
                );
                return Ok(Message::PosNack(PosNackMsg {
                    v: 1,
                    challenge_id: challenge.challenge_id,
                    source_block_id: block_id,
                    esi,
                    timestamp: Timestamp::now(),
                    device_id: challenge.device_id,
                }));
            }
        }

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
                    device_id: challenge.device_id,
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
                    device_id: challenge.device_id,
                }))
            }
            Err(e) => Err(ProcessorError::Io(e)),
        }
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
        holder_id: DeviceId,
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
                return Ok(VerifyOutcome::CannotVerify);
            }
        };

        // Consume the entry — challenge lifecycle ends here regardless of outcome.
        // Also capture the challenged ESI for logging below.
        let esi = {
            let mut guard = self.pending_challenges.lock().await;
            guard.remove(&key).map(|c| c.esi).unwrap_or(response.esi)
        };

        let block_id = key.0;

        // Load the placement record from DB (keyed by DeviceId).
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
        holder_id: DeviceId,
        nack: &PosNackMsg,
    ) -> Result<bool, ProcessorError> {
        let block_id = nack.source_block_id;
        mark_placement_lost(&self.db, &block_id, &holder_id)
    }

    pub(crate) async fn handle_pos_nack(
        &self,
        from_device: DeviceId,
        nack: PosNackMsg,
    ) -> Result<(), ProcessorError> {
        let block_id = nack.source_block_id;
        self.handle_pos_nack_sync(from_device, &nack)?;

        // Refresh trust_s: holder no longer stores those symbols for us.
        if let Err(e) = self.db.refresh_peer_storage_bytes(&from_device) {
            error!(
                device = %from_device,
                err = %e,
                "processor: failed to refresh storage balance after PosNack"
            );
        }

        info!(block_id = %block_id, holder = %from_device, "repair: triggered");
        let _ = self
            .repair_tx
            .send(RepairTrigger::RepairNow {
                block_id,
                holder_id: from_device,
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
        holder_id: DeviceId,
        dropped: &SymbolDroppedMsg,
    ) -> Result<bool, ProcessorError> {
        let block_id = dropped.source_block_id;
        mark_placement_lost(&self.db, &block_id, &holder_id)
    }

    pub(crate) async fn handle_symbol_dropped(
        &self,
        from: DeviceId,
        dropped: SymbolDroppedMsg,
    ) -> Result<(), ProcessorError> {
        let block_id = dropped.source_block_id;
        self.handle_symbol_dropped_sync(from, &dropped)?;

        // Refresh trust_s: holder evicted our symbols, bytes_peer_stores_for_us decreased.
        if let Err(e) = self.db.refresh_peer_storage_bytes(&from) {
            error!(
                device = %from,
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

        // Reject stale/replayed messages (same freshness window as handshake).
        let now = Timestamp::now();
        let age = now.0.saturating_sub(delete.timestamp.0);
        if age > syncback_core::constants::HANDSHAKE_FRESHNESS_SECS {
            warn!(
                block_id = %block_id,
                owner = %from,
                age_secs = age,
                "processor: Delete rejected — timestamp too old (possible replay)"
            );
            return Ok(());
        }

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

        // Reject stale/replayed messages.
        let now = Timestamp::now();
        let age = now.0.saturating_sub(cancel.timestamp.0);
        if age > syncback_core::constants::HANDSHAKE_FRESHNESS_SECS {
            warn!(
                block_id = %block_id,
                owner = %from,
                age_secs = age,
                "processor: CancelDelete rejected — timestamp too old (possible replay)"
            );
            return Ok(());
        }

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

    /// Receive a SymbolOffer, decide Accept or Reject, return the reply Message.
    ///
    /// Does NOT create a HoldingRecord — that happens in handle_symbol_transfer
    /// when symbols actually arrive.
    ///
    /// Security checks (in order):
    ///   1. Freshness: |now - timestamp| <= HANDSHAKE_FRESHNESS_SECS
    ///   2. Signature: verify_symbol_offer against owner_id (master identity from handshake)
    ///   3. Quota: decide_symbol_offer
    ///
    /// Called from dispatch_libp2p; reply is sent via ResponseChannel by caller.
    pub(crate) fn handle_symbol_offer_inner(
        &self,
        owner_id: IdentityPub,
        offer: SymbolOfferMsg,
    ) -> Message {
        let now = Timestamp::now().0;
        let ts = offer.timestamp.0;
        let delta = now.abs_diff(ts);
        if delta > HANDSHAKE_FRESHNESS_SECS {
            warn!(
                owner = %owner_id,
                block_id = %offer.source_block_id,
                delta_secs = delta,
                "processor: SymbolOffer rejected — stale timestamp"
            );
            return Message::SymbolReject(SymbolRejectMsg {
                v: 1,
                source_block_id: offer.source_block_id,
                offer_msg_id: offer.msg_id,
                reason: RejectReason::Other,
                timestamp: Timestamp::now(),
            });
        }

        if let Err(e) = verify_symbol_offer(&offer, &owner_id) {
            warn!(
                owner = %owner_id,
                block_id = %offer.source_block_id,
                err = %e,
                "processor: SymbolOffer rejected — sig verification failed"
            );
            return Message::SymbolReject(SymbolRejectMsg {
                v: 1,
                source_block_id: offer.source_block_id,
                offer_msg_id: offer.msg_id,
                reason: RejectReason::Other,
                timestamp: Timestamp::now(),
            });
        }

        let offer_bytes: u64 = offer
            .esi_ranges
            .iter()
            .map(|&(_start, count)| count as u64 * SYMBOL_SIZE as u64)
            .sum();

        let accept = match self.decide_symbol_offer(offer_bytes) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    owner = %owner_id,
                    block_id = %offer.source_block_id,
                    err = %e,
                    "processor: SymbolOffer — quota check failed"
                );
                return Message::SymbolReject(SymbolRejectMsg {
                    v: 1,
                    source_block_id: offer.source_block_id,
                    offer_msg_id: offer.msg_id,
                    reason: RejectReason::QuotaFull,
                    timestamp: Timestamp::now(),
                });
            }
        };

        if accept {
            info!(
                owner = %owner_id,
                block_id = %offer.source_block_id,
                offer_bytes,
                "processor: SymbolOffer accepted"
            );
            // Store accepted offer so handle_symbol_transfer can validate the transfer.
            {
                let accepted_offer = AcceptedOffer {
                    owner_id,
                    source_block_id: offer.source_block_id,
                    esi_ranges: offer.esi_ranges.clone(),
                    importance: offer.importance,
                    accepted_at: Timestamp::now(),
                };
                let key = (owner_id, offer.source_block_id);
                let mut map = self.accepted_offers.lock().unwrap();
                map.insert(key, accepted_offer);
            }
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
        }
    }

    // =========================================================
    // SymbolAccept / SymbolReject: we are the owner
    // =========================================================

    /// Holder accepted our symbol offer. Notify BackupCoordinator and signal pending delivery.
    async fn handle_symbol_accept(
        &self,
        from_master: IdentityPub,
        accept: SymbolAcceptMsg,
    ) -> Result<(), ProcessorError> {
        info!(
            holder = %from_master,
            block_id = %accept.source_block_id,
            "processor: SymbolAccept received"
        );
        // BackupEvent now uses DeviceId — resolve from master.
        let holder_device = self.db.get_devices_for_master(&from_master)
            .unwrap_or_default()
            .into_iter()
            .next()
            .unwrap_or(DeviceId(from_master.0));
        let _ = self.backup_event_tx.send(
            crate::daemon::backup::BackupEvent::SymbolAccepted {
                holder_id: holder_device,
                source_block_id: accept.source_block_id,
            },
        ).await;
        Ok(())
    }

    /// Holder rejected our symbol offer. Notify BackupCoordinator and signal pending delivery.
    async fn handle_symbol_reject(
        &self,
        from_master: IdentityPub,
        reject: SymbolRejectMsg,
    ) -> Result<(), ProcessorError> {
        warn!(
            holder = %from_master,
            block_id = %reject.source_block_id,
            reason = ?reject.reason,
            "processor: SymbolReject received"
        );
        // BackupEvent now uses DeviceId — resolve from master.
        let holder_device = self.db.get_devices_for_master(&from_master)
            .unwrap_or_default()
            .into_iter()
            .next()
            .unwrap_or(DeviceId(from_master.0));
        let _ = self.backup_event_tx.send(
            crate::daemon::backup::BackupEvent::SymbolRejected {
                holder_id: holder_device,
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

    /// Learn about a peer's identity. Upsert PeerRecord in DB.
    ///
    /// In the libp2p path, network routing is by PeerId/DeviceId via the
    /// SwarmHandle's authenticated map — no explicit address registration needed.
    /// The node_id field is kept in PeerRecord for backward compatibility
    /// (used in relay board key derivation); it may be a zero placeholder for
    /// libp2p peers.
    pub(crate) async fn handle_peer_announce(
        &self,
        msg: PeerAnnounceMsg,
    ) -> Result<(), ProcessorError> {
        // Verify Ed25519 signature before trusting any fields.
        if let Err(e) = verify_peer_announce(&msg) {
            warn!(
                identity = %msg.identity_pub,
                err = %e,
                "processor: PeerAnnounce signature verification failed, ignoring"
            );
            return Ok(());
        }

        let now = Timestamp::now();
        // PeerRecord is keyed by DeviceId. Look up all known devices for this master identity.
        // If we have device records — update x25519_pub and last_seen.
        // If no devices known yet — record is created later by on_peer_authenticated.
        let devices = self.db.get_devices_for_master(&msg.identity_pub).unwrap_or_default();
        for did in &devices {
            if let Some(mut existing) = self.db.get_peer(did)? {
                existing.last_seen = now;
                if msg.x25519_pub.is_some() {
                    existing.x25519_pub = msg.x25519_pub;
                }
                if existing.trust_p == 0.0 && existing.trust_i == 0.0 {
                    existing.trust_p = INITIAL_TRUST_P;
                }
                self.db.upsert_peer(&existing)?;
            }
        }

        info!(
            identity = %msg.identity_pub,
            "processor: PeerAnnounce upserted peer record"
        );

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

        // device_id.0 IS the device pub key — use it for the revocation list.
        let revoked_pub = broadcast.device_cert.device_id.0;

        // Only update PeerRecords we already know about. Unknown peers are skipped.
        // PeerRecord is keyed by DeviceId; find any device of this master.
        let devices = self.db.get_devices_for_master(&from).unwrap_or_default();
        if devices.is_empty() {
            debug!(
                peer = %from,
                "processor: RevocationBroadcast from unknown peer, ignoring"
            );
            return Ok(());
        }
        for did in &devices {
            let mut record = match self.db.get_peer(did)? {
                Some(r) => r,
                None => continue,
            };
            if !record.revoked_device_pub_keys.contains(&revoked_pub) {
                record.revoked_device_pub_keys.push(revoked_pub);
                self.db.upsert_peer(&record)?;
            }
        }

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

    /// Handle a ClusterSyncRequest via libp2p (AC-6).
    ///
    /// Validates that the claimed from_device_id matches the authenticated cert
    /// stored in peer_cert_map. On mismatch: drops the ResponseChannel (no reply),
    /// which causes libp2p to return an error to the sender.
    async fn handle_cluster_sync_request_libp2p(
        &self,
        from_device: DeviceId,
        from_master: IdentityPub,
        request: ClusterSyncRequestMsg,
        response_channel: ResponseChannel<Message>,
    ) -> Result<(), ProcessorError> {
        // Validate: the device cert stored in peer_cert_map must match from_device_id.
        let cert_ok = {
            let map = self.peer_cert_map.lock().unwrap();
            map.get(&from_device)
                .map(|(_, cert)| cert.device_id == request.from_device_id)
                .unwrap_or(false)
        };
        if !cert_ok {
            warn!(
                device = %from_device,
                claimed_device = ?request.from_device_id,
                "processor: ClusterSyncRequest device_id mismatch, dropping"
            );
            // Drop response_channel — libp2p will return an error to the sender.
            drop(response_channel);
            return Ok(());
        }

        match self.cluster_sync.handle_sync_request(&request) {
            Ok(response) => {
                let _ = self
                    .swarm
                    .respond(response_channel, Message::ClusterSyncResponse(response));
                debug!(peer = %from_master, "processor: ClusterSyncRequest served");
            }
            Err(e) => {
                warn!(peer = %from_master, err = %e, "processor: ClusterSyncRequest rejected");
                drop(response_channel);
            }
        }
        Ok(())
    }

    // =========================================================
    // ClusterSyncResponse: apply events from a peer device
    // =========================================================

    pub(crate) async fn handle_cluster_sync_response(
        &self,
        from_device: DeviceId,
        response: ClusterSyncResponseMsg,
    ) -> Result<(), ProcessorError> {
        match self.cluster_sync.process_sync_response(&from_device, response) {
            Ok(n) => {
                debug!(
                    device = %from_device,
                    applied = n,
                    "processor: cluster sync applied events"
                );
            }
            Err(e) => {
                warn!(device = %from_device, err = %e, "processor: cluster sync response error");
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
    /// Receive and store a system state blob from a peer. Returns the ack.
    ///
    /// In the libp2p path the ack is returned to the caller (dispatch_libp2p)
    /// which sends it via ResponseChannel.
    pub(crate) async fn handle_system_state_backup_inner(
        &self,
        owner_id: IdentityPub,
        backup: SystemStateBackupMsg,
    ) -> SystemStateAckMsg {
        if backup.encrypted_blob.is_empty() {
            warn!(peer = %owner_id, "processor: SystemStateBackup: empty blob, ignoring");
            return SystemStateAckMsg { v: 1, stored: false, timestamp: Timestamp::now() };
        }
        // Only accept from known peers (prevent storage spam from strangers).
        // PeerRecord is keyed by DeviceId; check if any device of this master is known.
        let known = self.db.get_devices_for_master(&owner_id)
            .map(|ds| !ds.is_empty())
            .unwrap_or(false);
        if !known {
            warn!(peer = %owner_id, "processor: SystemStateBackup: unknown peer, rejecting");
            return SystemStateAckMsg { v: 1, stored: false, timestamp: Timestamp::now() };
        }
        let record = SystemStateBlobRecord {
            owner: owner_id,
            encrypted_blob: backup.encrypted_blob,
            created_at: backup.timestamp,
            stored_at: Timestamp::now(),
        };
        match self.db.store_system_state_blob(&owner_id, &record) {
            Ok(()) => {
                info!(peer = %owner_id, "processor: SystemStateBackup: stored");
                SystemStateAckMsg { v: 1, stored: true, timestamp: Timestamp::now() }
            }
            Err(e) => {
                error!(peer = %owner_id, err = %e, "processor: SystemStateBackup: store failed");
                SystemStateAckMsg { v: 1, stored: false, timestamp: Timestamp::now() }
            }
        }
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

    /// Respond to a system state request. Returns the response message.
    ///
    /// In the libp2p path the response is sent via ResponseChannel by the caller.
    pub(crate) async fn handle_system_state_request_inner(
        &self,
        requester_id: IdentityPub,
        _req: SystemStateRequestMsg,
    ) -> SystemStateResponseMsg {
        let blob = match self.db.get_system_state_blob(&requester_id) {
            Ok(Some(r)) => r.encrypted_blob,
            Ok(None) => vec![],
            Err(e) => {
                error!(peer = %requester_id, err = %e, "processor: SystemStateRequest: db error");
                vec![]
            }
        };
        let found = !blob.is_empty();
        debug!(peer = %requester_id, found, "processor: SystemStateRequest: responding");
        SystemStateResponseMsg {
            v: 1,
            encrypted_blob: blob,
            timestamp: Timestamp::now(),
        }
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

}
// PeerDiscoveryRequest and PeerDiscoveryResponse removed in ε.2 (AC-12).
// Replaced by Kademlia DHT in ε.3.

// ─── Shared helpers ───────────────────────────────────────────────────────────

/// Mark a placement as Lost. Idempotent: no-op if already Lost or Deleting.
/// Returns true if the record was changed.
fn mark_placement_lost(
    db: &Db,
    block_id: &syncback_core::types::SourceBlockId,
    holder_id: &DeviceId,
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
pub(crate) fn record_pos_weekly(db: &Db, device: DeviceId, outcome: PosOutcome) {
    let week = outcome.week_number;
    let existing = match db.get_pos_weekly(&device, week) {
        Ok(v) => v,
        Err(e) => {
            error!(device = %device, err = %e, "processor: failed to read pos_weekly");
            return;
        }
    };
    let entry = WeeklyPosEntry {
        challenged: existing.as_ref().map(|e| e.challenged).unwrap_or(0) + outcome.challenged,
        passed: existing.as_ref().map(|e| e.passed).unwrap_or(0) + outcome.passed,
    };
    if let Err(e) = db.upsert_pos_weekly(&device, week, &entry) {
        error!(device = %device, err = %e, "processor: failed to update pos_weekly");
    }
}

/// Recalculate trust P and I for a device from pos_weekly data, persist to PeerRecord.
/// Returns (old_p, old_i, new_p, new_i) for logging, or None on error.
pub(crate) fn recalculate_trust(
    db: &Db,
    device: &DeviceId,
    current_week: u32,
) -> Option<(f64, f64, f64, f64)> {
    let mut record = match db.get_peer(device) {
        Ok(Some(r)) => r,
        _ => return None,
    };
    let old_p = record.trust_p;
    let old_i = record.trust_i;

    let entries = db.list_pos_weekly_for_peer(device).unwrap_or_default();

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
        error!(device = %device, err = %e, "processor: failed to persist trust update");
        return None;
    }

    // --- Two-level trust update ---
    // Update DeviceTrustRecord for this specific device.
    let dtr = DeviceTrustRecord {
        device_id: *device,
        trust_p: new_p,
        trust_i: new_i,
        last_week: current_week,
    };
    if let Err(e) = db.set_device_trust(&dtr) {
        error!(device = %device, err = %e, "processor: failed to update device trust");
    }

    // Recompute master trust from all device trusts of this device's master.
    let master_identity = record.master_identity;
    let devices_for_master = db.get_devices_for_master(&master_identity).unwrap_or_default();
    let device_data: Vec<(DeviceTrustRecord, u64)> = devices_for_master
        .iter()
        .filter_map(|did| {
            db.get_device_trust(did).ok().flatten().map(|dt| {
                // Weight = total alive symbol count for this device.
                let weight: u64 = db
                    .list_placements_for_holder(did)
                    .unwrap_or_default()
                    .iter()
                    .filter(|p| p.status == syncback_core::types::PlacementStatus::Alive)
                    .map(|p| p.symbol_count() as u64)
                    .sum();
                (dt, weight.max(1))
            })
        })
        .collect();
    let master_combined = recompute_master_trust(&device_data);
    let mtr = MasterTrustRecord {
        identity: master_identity,
        combined: master_combined,
        last_updated: Timestamp::now(),
    };
    if let Err(e) = db.set_master_trust(&mtr) {
        error!(device = %device, err = %e, "processor: failed to update master trust");
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

