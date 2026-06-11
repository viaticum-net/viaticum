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
//   PeerAnnounce received   → upsert peer record in DB
//   ClusterSyncRequest      → we are cluster peer → serve event log entries
//   ClusterSyncResponse     → we are cluster peer → apply received events
//
// ε.2 — libp2p wiring:
//   Processor now consumes ProtocolEvent from SwarmHandle.
//   PeerAuthenticated → upsert PeerRecord, auto-add cluster device, send PeerAnnounce.
//   InboundRequest    → dispatch_libp2p: match Message variant, call handler, send via ResponseChannel.
//   ConnectionClosed  → remove from peer_cert_map.
//
// A2 (T-13b-3) — relay board retired. One-way directed messages (PoS, Delete,
//   CancelDelete, DropNotice, Revocation) now arrive via the mailbox poll loop;
//   their handler bodies live in pos.rs / symbol.rs and are reached through the
//   mailbox dispatch handlers, not through this Processor's inbound path.
//
// Design note: PosHashResponseMsg carries source_block_id (bound by the holder's
// signature so a postman cannot retarget a captured response). The owner still locates
// the matching pending challenge by challenge_id in the shared PendingChallenges map
// (written by Scheduler when the challenge was issued), then verifies the response
// signature against the master of pending.holder_id before applying any outcome (CS-ID-1).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use libp2p::request_response::ResponseChannel;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use viaticum_core::cluster::DeviceCertificate;
use viaticum_core::config::EscrowCfg;
use viaticum_core::constants::SYMBOL_OFFER_EXPIRY_SECS;
use viaticum_core::db::Db;
use viaticum_core::messages::{AckMsg, Message, RestoreDeniedMsg, SymbolStoredMsg};
use viaticum_core::types::{DeviceId, IdentityPub, PlacementStatus, SourceBlockId, Timestamp};

use crate::daemon::cluster_sync::ClusterSyncManager;
use crate::daemon::mailbox::candidate::KademliaRoutingView;
use crate::daemon::network::swarm::{ProtocolEvent, SwarmHandle, device_id_to_peer_id};

mod cluster;
pub mod mailbox;
mod peer;
mod pos;
mod restore;
mod symbol;

// Re-export for handle/mod.rs wiring (T-6: mailbox poll → PosResponder bridge).
pub use pos::{PosResponder, ProcessorPosHandler};
// Re-export for handle/mod.rs wiring (T-7: mailbox poll → SymbolDropHandler bridge).
pub use symbol::{ProcessorDropHandler, SymbolDropHandler};
// Re-export for handle/mod.rs wiring (T-13b-1: mailbox poll → Delete/CancelDelete bridge).
pub use symbol::{DeleteMailboxHandler, ProcessorDeleteHandler};
// Re-export for handle/mod.rs wiring (T-13b-2: mailbox poll → Revocation bridge).
pub use symbol::{ProcessorRevocationHandler, RevocationHandler, RevocationMailboxHandler};

#[cfg(test)]
mod tests;

// ─── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ProcessorError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("db error: {0}")]
    Db(#[from] viaticum_core::db::DbError),

    #[error("swarm error: {0}")]
    Swarm(#[from] crate::daemon::network::swarm::SwarmError),

    #[error("pos verify error: {0}")]
    PosVerify(#[from] viaticum_core::pos::PosError),

    #[error("unauthenticated PoS challenge (bad/absent owner signature)")]
    UnauthenticatedChallenge,

    /// SM-1: a signed-but-abusive PoS challenge requested more (or malformed) ESIs than
    /// the holder actually holds — rejected BEFORE the unbounded `esi_ranges` expansion so a
    /// malicious-but-authenticated owner cannot OOM the holder with `[(0, u32::MAX)]`.
    #[error(
        "oversized/malformed PoS challenge for block {block_id} (requested {requested} ESIs, hold {held})"
    )]
    OversizedChallenge {
        block_id: viaticum_core::types::SourceBlockId,
        requested: u64,
        held: u32,
    },

    #[error("cluster sync error: {0}")]
    ClusterSync(#[from] crate::daemon::cluster_sync::ClusterSyncError),

    #[error("escrow denied for block {block_id}")]
    EscrowDenied {
        block_id: viaticum_core::types::SourceBlockId,
        denial: viaticum_core::escrow::RestoreDenial,
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
    cluster_sync: Arc<ClusterSyncManager>,
    /// Directory where we store symbols held for others: `{holdings_dir}/{block_id_hex}/{esi}.bin`
    holdings_dir: PathBuf,
    /// libp2p swarm handle.
    swarm: Arc<SwarmHandle>,
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
    /// Cluster state for auto-add on same-identity handshake. None if not initialized.
    cluster_state: Option<Arc<std::sync::Mutex<viaticum_core::cluster::ClusterState>>>,
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
        cluster_sync: Arc<ClusterSyncManager>,
        holdings_dir: PathBuf,
        swarm: Arc<SwarmHandle>,
        soft_quota_bytes: u64,
        hard_quota_bytes: u64,
        data_dir: PathBuf,
        disk_reserve_bytes: u64,
        backup_event_tx: mpsc::Sender<crate::daemon::backup::BackupEvent>,
        time_scale: u64,
        cluster_state: Option<Arc<std::sync::Mutex<viaticum_core::cluster::ClusterState>>>,
        escrow_cfg: EscrowCfg,
        accepted_offers: AcceptedOffers,
        master_signing_key: ed25519_dalek::SigningKey,
    ) -> Self {
        Processor {
            db,
            own_identity,
            cluster_sync,
            holdings_dir,
            swarm,
            soft_quota_bytes,
            hard_quota_bytes,
            data_dir,
            disk_reserve_bytes,
            backup_event_tx,
            time_scale,
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
    pub fn set_work_event_tx(&mut self, tx: mpsc::Sender<crate::daemon::work_pipeline::WorkEvent>) {
        self.work_event_tx = Some(tx);
    }

    /// Build a KademliaRoutingView from known peers in the DB.
    ///
    /// Converts each stored PeerRecord's device_id to a libp2p PeerId.
    /// Peers whose device_id cannot be converted (bad key bytes) are silently skipped.
    /// The routing view is used for mailbox candidate-set checks (should_store).
    fn build_routing_view(&self) -> KademliaRoutingView {
        let peers = match self.db.list_all_peers() {
            Ok(p) => p,
            Err(e) => {
                warn!(err = %e, "processor: build_routing_view: list_all_peers failed, using empty view");
                return KademliaRoutingView::new(vec![]);
            }
        };
        let peer_ids: Vec<_> = peers
            .iter()
            .filter_map(|p| device_id_to_peer_id(&p.device_id).ok())
            .collect();
        KademliaRoutingView::new(peer_ids)
    }

    /// Main loop: receive ProtocolEvents from the libp2p swarm.
    ///
    /// Dispatches each event to its handler in a new tokio::spawn task (I4 preserved).
    /// - swarm_rx: ProtocolEvent stream from SwarmHandle (PeerAuthenticated, InboundRequest, ConnectionClosed)
    pub async fn run(
        self,
        mut swarm_rx: mpsc::Receiver<ProtocolEvent>,
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
                let mut esi_list: Vec<u32> = transfer.symbols.iter().map(|s| s.esi).collect();
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
                        let ack = Message::Ack(AckMsg { v: 1 });
                        let _ = self.swarm.respond(response_channel, ack);
                    }
                }
            }
            Message::PosHashChallenge(challenge) => {
                match self
                    .handle_pos_hash_challenge_inner(from_master, challenge)
                    .await
                {
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
                    let _ = self
                        .swarm
                        .respond(response_channel, Message::Ack(AckMsg { v: 1 }));
                    return Ok(());
                }
                if let Err(e) = self.handle_cluster_sync_response(from_device, resp).await {
                    warn!(device = %from_device, err = %e, "processor: ClusterSyncResponse handler failed");
                }
                let _ = self
                    .swarm
                    .respond(response_channel, Message::Ack(AckMsg { v: 1 }));
            }
            Message::SymbolAccept(accept) => {
                if let Err(e) = self.handle_symbol_accept(from_master, accept).await {
                    warn!(device = %from_device, err = %e, "processor: SymbolAccept handler failed");
                }
                let _ = self
                    .swarm
                    .respond(response_channel, Message::Ack(AckMsg { v: 1 }));
            }
            Message::SymbolReject(reject) => {
                if let Err(e) = self.handle_symbol_reject(from_master, reject).await {
                    warn!(device = %from_device, err = %e, "processor: SymbolReject handler failed");
                }
                let _ = self
                    .swarm
                    .respond(response_channel, Message::Ack(AckMsg { v: 1 }));
            }
            Message::RestoreDenied(denied) => {
                if let Err(e) = self.handle_restore_denied(from_master, denied).await {
                    warn!(device = %from_device, err = %e, "processor: RestoreDenied handler failed");
                }
                let _ = self
                    .swarm
                    .respond(response_channel, Message::Ack(AckMsg { v: 1 }));
            }
            Message::PeerAnnounce(pa) => {
                if let Err(e) = self.handle_peer_announce(pa).await {
                    warn!(device = %from_device, err = %e, "processor: PeerAnnounce handler failed");
                }
                let _ = self
                    .swarm
                    .respond(response_channel, Message::Ack(AckMsg { v: 1 }));
            }
            Message::MailboxStoreRequest(req) => {
                // Build routing view from known peers in the DB.
                let routing_view = self.build_routing_view();
                let my_peer_id = self.swarm.peer_id;
                let resp = mailbox::handle_mailbox_store(&self.db, &routing_view, &my_peer_id, req);
                let _ = self
                    .swarm
                    .respond(response_channel, Message::MailboxStoreResponse(resp));
            }
            Message::MailboxFetchRequest(req) => {
                let now = Timestamp::now().0;
                let resp = mailbox::handle_mailbox_fetch(&self.db, req, from_master, now);
                let _ = self
                    .swarm
                    .respond(response_channel, Message::MailboxFetchResponse(resp));
            }
            other => {
                warn!(
                    device = %from_device,
                    "processor: dispatch_libp2p: unhandled message variant {:?}",
                    std::mem::discriminant(&other)
                );
                let _ = self
                    .swarm
                    .respond(response_channel, Message::Ack(AckMsg { v: 1 }));
            }
        }
        Ok(())
    }
}
// PeerDiscoveryRequest and PeerDiscoveryResponse removed in ε.2 (AC-12).
// Replaced by Kademlia DHT in ε.3.

// ─── Shared helpers ───────────────────────────────────────────────────────────

/// Mark a placement as Lost. Idempotent: no-op if already Lost or Deleting.
/// Returns true if the record was changed.
pub(crate) fn mark_placement_lost(
    db: &Db,
    block_id: &viaticum_core::types::SourceBlockId,
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
        .filter(|p| p.status == PlacementStatus::Alive || p.status == PlacementStatus::Uncertain)
        .count() as u32;

    // 3. Assemble HolderReliabilityInput for each Alive/Uncertain placement.
    let k_eff = block.erasure_params().k_eff;
    let holder_inputs: Vec<viaticum_core::reliability::HolderReliabilityInput> = placements
        .iter()
        .filter(|p| p.status == PlacementStatus::Alive || p.status == PlacementStatus::Uncertain)
        .map(|p| {
            let survival_prob = db
                .get_peer(&p.holder_id)
                .ok()
                .flatten()
                .map(|peer| {
                    viaticum_core::reliability::commitment_to_survival_prob(
                        viaticum_core::commitment::CommitmentScore::new(peer.trust_p),
                    )
                })
                // Neutral prior for unknown peers: a 0.5 commitment through the same
                // mapping (≈0.225 under the physical ceiling), NOT a bare 0.5 — that
                // would rank an unknown peer above a mediocre known one post-ceiling.
                .unwrap_or_else(|| {
                    viaticum_core::reliability::commitment_to_survival_prob(
                        viaticum_core::commitment::CommitmentScore::new(0.5),
                    )
                });
            viaticum_core::reliability::HolderReliabilityInput {
                holder_id: p.holder_id,
                alive_symbols: p.symbol_count(),
                survival_prob,
            }
        })
        .collect();

    // 4. Compute new_reliability.
    let reliability_input = viaticum_core::reliability::BlockReliabilityInput {
        block_id: *block_id,
        k_eff,
        holders: holder_inputs,
    };
    let new_reliability = match viaticum_core::reliability::block_reliability(&reliability_input) {
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

    // 5. Persist the cached reliability fields. Worker cooldown is RAM-only (B-4),
    // so it is untouched by this recompute.
    if let Err(e) = db.update_block_cached_fields(
        block_id,
        block.importance,
        new_current_alive,
        new_reliability,
        block.target_reliability,
    ) {
        error!(
            block_id = %block_id,
            err = %e,
            "placement hook: update_block_cached_fields failed"
        );
    }
}

/// Record PoS outcome in the weekly stats table (best-effort, logs on error).
pub(crate) fn record_pos_weekly(
    db: &Db,
    device: DeviceId,
    outcome: viaticum_core::trust::PosOutcome,
) {
    use viaticum_core::db::WeeklyPosEntry;
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

// ESI range helpers moved to viaticum_core::types — use those directly.
pub(crate) use viaticum_core::types::{esi_list_to_ranges, ranges_to_esi_list};

// Re-export for tests.
#[cfg(test)]
pub(crate) use viaticum_core::trust::recalculate_trust;

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
