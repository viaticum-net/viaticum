// Message Router (Processor): routes incoming connections and dispatches messages.
//
// Responsibilities:
//   - Accept ProtocolEvent from the libp2p SwarmHandle event_rx.
//   - Dispatch received messages to the appropriate handler.
//
// Role separation:
//   PosHashChallenge received → we are the holder  → compute chain hash, send PosHashResponse or PosHashNack
//   PosHashResponse received  → we are the owner   → verify hash, update trust/placement
//   PosHashNack received      → we are the owner   → mark placement Lost, trigger repair
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
//   One-way messages (PosHash, Delete, Drop) still arrive via relay board (dispatch_relay).
//
// Design note: PosHashResponseMsg on the wire does not carry source_block_id.
// We recover it by looking up the challenge_id in the shared PendingChallenges
// map (written by Scheduler when the challenge was issued).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use libp2p::request_response::ResponseChannel;
use syncback_core::cluster::DeviceCertificate;
use syncback_core::config::EscrowCfg;
use syncback_core::constants::SYMBOL_OFFER_EXPIRY_SECS;
use syncback_core::db::Db;
use syncback_core::messages::{
    AckMsg, CancelDeleteMsg, DeleteMsg, Message, PeerAnnounceMsg,
    PosHashChallengeMsg, PosHashNackMsg, PosHashResponseMsg,
    RestoreDeniedMsg, RevocationBroadcast,
    SymbolDropNoticeMsg, SymbolDroppedMsg,
    SymbolStoredMsg, SystemStateAckMsg,
};
use syncback_core::types::{
    DeviceId, IdentityPub, PlacementStatus, SourceBlockId, Timestamp,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::daemon::cluster_sync::ClusterSyncManager;
use crate::daemon::network::swarm::{ProtocolEvent, SwarmHandle};
use crate::daemon::relay::{InboundMessage, RelayPost};
use crate::daemon::repair::RepairTrigger;
use crate::daemon::scheduler::PendingChallenges;

mod cluster;
mod peer;
mod pos;
mod restore;
mod symbol;

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

/// Drop any accepted offers whose age exceeds `SYMBOL_OFFER_EXPIRY_SECS`.
///
/// Review B1 / H-1: without this sweep, an accepted offer that is never followed
/// by a matching `SymbolTransfer` lives in the map forever — a slow memory leak
/// that a malicious owner can weaponise by flooding `SymbolOffer` messages and
/// never delivering. Called periodically by the scheduler.
///
/// Returns the number of entries evicted.
pub fn prune_expired_accepted_offers(accepted: &AcceptedOffers, now: Timestamp) -> usize {
    let mut map = accepted.lock().unwrap();
    let before = map.len();
    map.retain(|_, offer| {
        let age = now.0.saturating_sub(offer.accepted_at.0);
        age <= SYMBOL_OFFER_EXPIRY_SECS
    });
    before - map.len()
}

// ─── Processor ────────────────────────────────────────────────────────────────

/// Routes incoming connections and dispatches messages to appropriate handlers.
pub struct Processor {
    db: Db,
    /// Our identity.
    pub(crate) own_identity: IdentityPub,
    repair_tx: mpsc::Sender<RepairTrigger>,
    cluster_sync: Arc<ClusterSyncManager>,
    /// Directory where we store symbols held for others: `{holdings_dir}/{block_id_hex}/{esi}.bin`
    holdings_dir: PathBuf,
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
    /// Master identity signing key for producing signed messages.
    /// Used to sign PosHashNackMsg (holder side) and other protocol messages requiring
    /// master identity proof.
    master_signing_key: ed25519_dalek::SigningKey,
    /// Channel to notify the WorkPipeline worker of peer authentication events.
    /// When Some: `on_peer_authenticated` sends `WorkEvent::PeerAuthenticated`.
    /// None in tests that do not wire the work pipeline.
    pub(crate) work_event_tx: Option<mpsc::Sender<crate::daemon::work_pipeline::WorkEvent>>,
}

impl Processor {
    /// Create a new Processor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Db,
        own_identity: IdentityPub,
        repair_tx: mpsc::Sender<RepairTrigger>,
        cluster_sync: Arc<ClusterSyncManager>,
        holdings_dir: PathBuf,
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
        master_signing_key: ed25519_dalek::SigningKey,
    ) -> Self {
        Processor {
            db,
            own_identity,
            repair_tx,
            cluster_sync,
            holdings_dir,
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
            master_signing_key,
            work_event_tx: None,
        }
    }

    /// Set the work event sender for the unified pipeline worker.
    ///
    /// Called from `handle/mod.rs::start()` after constructing both Processor and WorkPipeline.
    pub fn set_work_event_tx(
        &mut self,
        tx: mpsc::Sender<crate::daemon::work_pipeline::WorkEvent>,
    ) {
        self.work_event_tx = Some(tx);
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
                            // Heavy messages (SymbolTransfer, RestoreRequest) carry
                            // large payloads (25-50 MB). Processing them inline
                            // (sequential) keeps peak RSS low — only one transfer
                            // in memory at a time. Light messages are spawned for
                            // concurrency.
                            let is_heavy = matches!(
                                message,
                                Message::SymbolTransfer(_) | Message::RestoreRequest(_)
                            );
                            if is_heavy {
                                if let Err(e) = this
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
                            } else {
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
                        }
                        Some(ProtocolEvent::ConnectionClosed { peer_id, device_id }) => {
                            let this2 = this.clone();
                            tokio::spawn(async move {
                                this2.on_connection_closed(peer_id, device_id).await;
                            });
                        }
                        Some(ProtocolEvent::PeerIdentified { device_id, listen_addrs }) => {
                            let this2 = this.clone();
                            tokio::spawn(async move {
                                this2.on_peer_identified(device_id, listen_addrs).await;
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
                let block_id = transfer.source_block_id;
                // Extract ESI list before moving transfer into handle_symbol_transfer.
                let mut esi_list: Vec<u32> =
                    transfer.symbols.iter().map(|s| s.esi).collect();
                esi_list.sort_unstable();
                match self.handle_symbol_transfer(from_master, transfer).await {
                    Ok(()) => {
                        let stored_ranges = esi_list_to_ranges(&esi_list);
                        let reply = Message::SymbolStored(SymbolStoredMsg {
                            v: 1,
                            source_block_id: block_id,
                            esi_ranges: stored_ranges,
                            timestamp: Timestamp::now(),
                        });
                        let _ = self.swarm.respond(response_channel, reply);
                    }
                    Err(e) => {
                        warn!(device = %from_device, err = %e, "processor: SymbolTransfer failed");
                        let ack = Message::SystemStateAck(SystemStateAckMsg {
                            v: 1,
                            stored: false,
                            timestamp: Timestamp::now(),
                        });
                        let _ = self.swarm.respond(response_channel, ack);
                    }
                }
            }
            Message::PosHashChallenge(challenge) => {
                match self.handle_pos_hash_challenge_inner(from_master, challenge).await {
                    Ok(reply) => {
                        let _ = self.swarm.respond(response_channel, reply);
                    }
                    Err(e) => {
                        warn!(device = %from_device, err = %e, "processor: PosHashChallenge handler failed");
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
                        Message::RestoreDenied(RestoreDeniedMsg {
                            v: 1,
                            source_block_id: block_id,
                            reason: "escrow check failed".to_string(),
                            current_trust: denial.current_trust,
                            needed_trust: denial.needed_trust,
                            restore_budget_gb: denial.restore_budget_gb,
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
            "pos_hash_challenge" => {
                match from_cbor::<PosHashChallengeMsg>(&msg.payload) {
                    Ok(challenge) => {
                        // In cluster mode (shared mnemonic), relay broadcasts reach
                        // every cluster device because they all share `master_pub`.
                        // Only the targeted device should respond; otherwise non-holder
                        // cluster members would emit valid-signed Nacks that the owner
                        // would mis-attribute to the real holder.
                        if let Some(target) = challenge.device_id {
                            if target != self.swarm.device_id {
                                debug!(
                                    target = %target,
                                    own = %self.swarm.device_id,
                                    "processor: PoS challenge not addressed to us, ignoring"
                                );
                                return;
                            }
                        }
                        match self.handle_pos_hash_challenge_inner(msg.from, challenge).await {
                            Ok(reply) => {
                                // Send response back via board (directed to challenger).
                                let (reply_type, reply_payload) = match &reply {
                                    Message::PosHashResponse(r) => {
                                        match syncback_core::messages::to_cbor(r) {
                                            Ok(bytes) => ("pos_hash_response", bytes),
                                            Err(e) => { warn!(err = %e, "processor: failed to encode PosHashResponse"); return; }
                                        }
                                    }
                                    Message::PosHashNack(n) => {
                                        match syncback_core::messages::to_cbor(n) {
                                            Ok(bytes) => ("pos_hash_nack", bytes),
                                            Err(e) => { warn!(err = %e, "processor: failed to encode PosHashNack"); return; }
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
                            Err(e) => warn!(err = %e, "processor: PosHashChallenge via relay failed"),
                        }
                    }
                    Err(e) => warn!(err = %e, "processor: failed to decode PosHashChallenge from relay"),
                }
            }
            "pos_hash_response" => {
                match from_cbor::<PosHashResponseMsg>(&msg.payload) {
                    Ok(response) => {
                        // Resolve DeviceId: use device_id from message body if present,
                        // else fall back to first device for the master (msg.from).
                        let holder_device = response.device_id
                            .or_else(|| self.db.get_devices_for_master(&msg.from).ok()
                                .and_then(|ds| ds.into_iter().next()))
                            .unwrap_or(DeviceId(msg.from.0));
                        if let Err(e) = self.handle_pos_hash_response(holder_device, response).await {
                            warn!(err = %e, "processor: PosHashResponse via relay failed");
                        }
                    }
                    Err(e) => warn!(err = %e, "processor: failed to decode PosHashResponse from relay"),
                }
            }
            "pos_hash_nack" => {
                match from_cbor::<PosHashNackMsg>(&msg.payload) {
                    Ok(nack) => {
                        // Resolve DeviceId: use device_id from message body if present,
                        // else fall back to first device for the master (msg.from).
                        let from_device = nack.device_id
                            .or_else(|| self.db.get_devices_for_master(&msg.from).ok()
                                .and_then(|ds| ds.into_iter().next()))
                            .unwrap_or(DeviceId(msg.from.0));
                        if let Err(e) = self.handle_pos_hash_nack(from_device, nack).await {
                            warn!(err = %e, "processor: PosHashNack via relay failed");
                        }
                    }
                    Err(e) => warn!(err = %e, "processor: failed to decode PosHashNack from relay"),
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
            "symbol_stored" => {
                // Informational notification from a holder — Delta-era protocol
                // surface kept for wire compatibility. No action taken: the owner
                // already tracks placement state via SymbolAccept/SymbolTransfer.
                debug!(from = %msg.from, "processor: symbol_stored — informational, no-op");
            }
            "storage_warning" => {
                // Informational bit-rot / PoS pre-warning. No-op for now; the
                // authoritative signal is PosNack / SymbolDropped which are
                // already handled and trigger repair.
                debug!(from = %msg.from, "processor: storage_warning — informational, no-op");
            }
            other => {
                let safe_type: String = other.chars().take(64).filter(|c| c.is_ascii_graphic() || *c == ' ').collect();
                debug!("dispatch_relay: unknown msg_type={safe_type}");
            }
        }
    }
}
// PeerDiscoveryRequest and PeerDiscoveryResponse removed in ε.2 (AC-12).
// Replaced by Kademlia DHT in ε.3.

// ─── Shared helpers ───────────────────────────────────────────────────────────

/// Mark a placement as Lost. Idempotent: no-op if already Lost or Deleting.
/// Returns true if the record was changed.
pub(crate) fn mark_placement_lost(
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

/// Recompute `current_alive` and `current_reliability` for a block from DB state,
/// then persist via `update_block_cached_fields`.
///
/// Call this immediately after any placement-status transition that changes whether
/// a placement counts as Alive/Uncertain. The function reads all placements for the
/// block, counts Alive+Uncertain, assembles per-holder survival probabilities via
/// `commitment_to_survival_prob(peer.trust_p)`, calls `block_reliability`, and
/// writes back. Errors are logged and silently swallowed — the primary placement
/// transition already succeeded before this is called.
///
/// `last_attempted_at` and `last_pool_signature` are preserved from the existing
/// block record (not modified by this function).
pub(crate) fn recompute_and_persist_block_cached_fields(db: &Db, block_id: &SourceBlockId) {
    // 1. Load block record.
    let block = match db.get_source_block(block_id) {
        Ok(Some(b)) => b,
        Ok(None) => {
            warn!(
                block_id = %block_id,
                "placement hook: source block not found, skipping cached-fields update"
            );
            return;
        }
        Err(e) => {
            error!(
                block_id = %block_id,
                err = %e,
                "placement hook: get_source_block failed"
            );
            return;
        }
    };

    // 2. List all placements for block; count Alive+Uncertain.
    let placements = match db.list_placements_for_block(block_id) {
        Ok(p) => p,
        Err(e) => {
            error!(
                block_id = %block_id,
                err = %e,
                "placement hook: list_placements_for_block failed"
            );
            return;
        }
    };

    let new_current_alive: u32 = placements
        .iter()
        .filter(|p| {
            p.status == PlacementStatus::Alive || p.status == PlacementStatus::Uncertain
        })
        .count() as u32;

    // 3. Assemble HolderReliabilityInput for each Alive/Uncertain placement.
    let k_eff = block.erasure_params().k_eff;
    let holder_inputs: Vec<syncback_core::reliability::HolderReliabilityInput> = placements
        .iter()
        .filter(|p| {
            p.status == PlacementStatus::Alive || p.status == PlacementStatus::Uncertain
        })
        .map(|p| {
            let survival_prob = db
                .get_peer(&p.holder_id)
                .ok()
                .flatten()
                .map(|peer| {
                    syncback_core::reliability::commitment_to_survival_prob(
                        syncback_core::commitment::CommitmentScore::new(peer.trust_p),
                    )
                })
                .unwrap_or(0.5); // neutral prior for unknown peers
            syncback_core::reliability::HolderReliabilityInput {
                holder_id: p.holder_id,
                alive_symbols: p.symbol_count(),
                survival_prob,
            }
        })
        .collect();

    // 4. Compute new_reliability.
    let reliability_input = syncback_core::reliability::BlockReliabilityInput {
        block_id: *block_id,
        k_eff,
        holders: holder_inputs,
    };
    let new_reliability = match syncback_core::reliability::block_reliability(&reliability_input) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                block_id = %block_id,
                err = %e,
                "placement hook: block_reliability failed, using 0.0"
            );
            0.0
        }
    };

    // 5. Persist. Preserve last_attempted_at and last_pool_signature.
    if let Err(e) = db.update_block_cached_fields(
        block_id,
        block.importance,
        new_current_alive,
        new_reliability,
        block.target_reliability,
        block.last_attempted_at,
        block.last_pool_signature,
    ) {
        error!(
            block_id = %block_id,
            err = %e,
            "placement hook: update_block_cached_fields failed"
        );
    }
}

/// Record PoS outcome in the weekly stats table (best-effort, logs on error).
pub(crate) fn record_pos_weekly(db: &Db, device: DeviceId, outcome: syncback_core::trust::PosOutcome) {
    use syncback_core::db::WeeklyPosEntry;
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

// ESI range helpers moved to syncback_core::types — use those directly.
pub(crate) use syncback_core::types::{esi_list_to_ranges, ranges_to_esi_list};

// Re-export for tests.
#[cfg(test)]
pub(crate) use syncback_core::trust::recalculate_trust;

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
