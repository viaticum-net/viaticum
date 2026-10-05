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
//   RestoreRequest received → we are the holder  → load symbols, send RestoreResponse (no gate)
//   PeerAnnounce received   → upsert peer record in DB
//   ClusterSyncRequest      → we are cluster peer → serve event log entries
//   ClusterSyncResponse     → we are cluster peer → apply received events
//
// ε.2 — libp2p wiring:
//   Processor now consumes ProtocolEvent from SwarmHandle.
//   PeerAuthenticated → admission (revocation, peer_cert_map), then the PeerRecord
//                       writer (peer_record_writer: one ordered queue, batches in one
//                       transaction, C-DK C4 fix round 3) upserts the record and spawns
//                       cluster auto-add + PeerAnnounce + wake after the commit.
//   PeerIdentified    → the same writer, behind the authentication it follows.
//   InboundRequest    → dispatch_libp2p: match Message variant, call handler, send via ResponseChannel.
//   ConnectionClosed  → remove from peer_cert_map.
//
// A2 (T-13b-3) — relay board retired. One-way directed messages (PoS, Delete,
//   CancelDelete, DropNotice, Revocation) now arrive via the mailbox poll loop;
//   their handler bodies live in pos.rs / symbol.rs and are reached through the
//   mailbox dispatch handlers, not through this Processor's inbound path.
//
// Design note: PosHashResponseMsg carries source_block_id (bound by the holder's
// signature so a postman cannot retarget a captured response). The owner's Scheduler
// (not this Processor) locates the matching pending challenge by challenge_id in its
// PendingIndex (written when the challenge was issued, read by the mailbox poll loop),
// then verifies the response signature against the holder master captured in the pending
// before applying any outcome (CS-ID-1, CS-POS-3).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use libp2p::request_response::ResponseChannel;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use viaticum_core::cluster::DeviceCertificate;
use viaticum_core::constants::SYMBOL_OFFER_EXPIRY_SECS;
use viaticum_core::db::Db;
use viaticum_core::messages::{AckMsg, Message, SymbolStoredMsg, SymbolTransferMsg};
use viaticum_core::pair_ledger::{LossCause, drop_event_for, ledger_master_for_device};
use viaticum_core::types::{
    DeviceId, DropKind, IdentityPub, PlacementStatus, SourceBlockId, SymbolPlacement, Timestamp,
};

use crate::daemon::cluster_sync::ClusterSyncManager;
use crate::daemon::mailbox::candidate::KademliaRoutingView;
use crate::daemon::network::swarm::{ProtocolEvent, SwarmHandle, device_id_to_peer_id};

mod cluster;
pub mod mailbox;
mod offer_shadow;
mod peer;
mod peer_record_writer;
mod pos;
mod restore;
mod symbol;
mod work_wake;
use peer_record_writer::PeerRecordEvent;
use symbol::TransferResult;

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

    /// pos-i5-a: a signed challenge older than the TTL + clock skew (a replay).
    #[error("stale PoS challenge ({age_secs} s old)")]
    StaleChallenge { age_secs: u64 },

    /// pos-i15: the challenge is addressed to another device of our own master.
    #[error("PoS challenge addressed to a sibling device")]
    NotAddressedToThisDevice,

    /// pos-i15: the challenge is addressed to a device we do not know as ours.
    #[error("PoS challenge addressed to a device that is not of this master")]
    NotAddressedToThisMaster,

    #[error("cluster sync error: {0}")]
    ClusterSync(#[from] crate::daemon::cluster_sync::ClusterSyncError),

    #[error("task join error: {0}")]
    Join(String),
}

// ─── Offer / delivery state ───────────────────────────────────────────────────

/// An accepted symbol offer awaiting transfer from the owner.
///
/// Keyed by the sending DEVICE: two devices of one master offering the same block keep
/// separate offers (backup-i19). `owner_id` stays the master: the holding is per master.
#[derive(Debug, Clone)]
pub struct AcceptedOffer {
    pub owner_id: IdentityPub,
    pub from_device: DeviceId,
    pub source_block_id: SourceBlockId,
    pub esi_ranges: Vec<(u32, u32)>,
    pub importance: f64,
    pub accepted_at: Timestamp,
}

/// Shared map of accepted offers: (sending device, block_id) → AcceptedOffer. Keyed by DEVICE,
/// not master: siblings of one master share block ids (deterministic nonce, shared epoch key) and
/// would overwrite each other's offer mid-delivery (backup-i19).
/// Written by handle_symbol_offer, read+removed by handle_symbol_transfer.
/// Uses std::sync::Mutex (not tokio::sync::Mutex) because locks are never held
/// across .await points — only brief insert/remove under the lock.
pub type AcceptedOffers = Arc<Mutex<HashMap<(DeviceId, SourceBlockId), AcceptedOffer>>>;

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
    /// Cluster state for auto-add on same-identity handshake. None if not initialized.
    cluster_state: Option<Arc<std::sync::Mutex<viaticum_core::cluster::ClusterState>>>,
    /// Accepted symbol offers awaiting SymbolTransfer from the owner.
    /// Key: (owner_id, block_id). Entries expire after SYMBOL_OFFER_EXPIRY_SECS.
    pub(crate) accepted_offers: AcceptedOffers,
    /// Authenticated peer map: DeviceId → (IdentityPub, DeviceCertificate).
    /// Written by on_peer_authenticated, cleared by on_connection_closed.
    /// Used by handle_cluster_sync_request_libp2p to validate from_device_id.
    peer_cert_map: Arc<std::sync::Mutex<HashMap<DeviceId, (IdentityPub, DeviceCertificate)>>>,
    /// This device's signing key. Signs the PoS response / Nack (pos-i16): the owner
    /// accepts them only for a placement on this device.
    device_signing_key: ed25519_dalek::SigningKey,
    /// Channel to notify the WorkPipeline worker of peer authentication events.
    /// When Some: `on_peer_authenticated` sends `WorkEvent::PeerAuthenticated`.
    /// None in tests that do not wire the work pipeline.
    pub(crate) work_event_tx: Option<mpsc::Sender<crate::daemon::work_pipeline::WorkEvent>>,
    /// В-0b: the `[four_r]` dials of the offer SHADOW (logs only; defaults until
    /// [`Processor::set_four_r`]).
    pub(crate) four_r: viaticum_core::four_r_holder::FourRParams,
    /// В-0b (4r-i50): ONE offer shadow at a time, off the reply path; a busy slot skips.
    pub(crate) shadow_offer_slot: Arc<tokio::sync::Semaphore>,
    /// Offers whose shadow was skipped since the last logged offer shadow.
    pub(crate) shadow_offers_skipped: Arc<std::sync::atomic::AtomicU64>,
    /// C-DK Р-18: the last work-pipeline wake per device.
    work_wake: std::sync::Mutex<work_wake::WorkWakeLimiter>,
    /// C-DK C4 fix round 3: the PeerRecord writer's queue. `run` pushes the
    /// authentication / identify events, the writer task owns the writes.
    peer_records: peer_record_writer::PeerRecordQueue,
    /// K-b4 (pos-i14): the holder's PoS answers that read a share at once; shared with the
    /// mailbox path's responder (`pos_responder`).
    pos_slots: Arc<tokio::sync::Semaphore>,
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
        cluster_state: Option<Arc<std::sync::Mutex<viaticum_core::cluster::ClusterState>>>,
        accepted_offers: AcceptedOffers,
        device_signing_key: ed25519_dalek::SigningKey,
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
            cluster_state,
            accepted_offers,
            peer_cert_map: Arc::new(std::sync::Mutex::new(HashMap::new())),
            device_signing_key,
            work_event_tx: None,
            four_r: viaticum_core::four_r_holder::FourRParams::default(),
            shadow_offer_slot: Arc::new(tokio::sync::Semaphore::new(1)),
            shadow_offers_skipped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            work_wake: std::sync::Mutex::new(work_wake::WorkWakeLimiter::default()),
            peer_records: peer_record_writer::PeerRecordQueue::new(peer_record_writer::PENDING_MAX),
            pos_slots: pos::new_pos_slots(),
        }
    }

    /// K-b4: a mailbox-path responder that waits on THIS processor's answer semaphore: the
    /// direct and the mailbox path share one limit of `HOLDER_POS_CONCURRENCY` readers.
    pub fn pos_responder(&self, responder: PosResponder) -> PosResponder {
        responder.with_pos_slots(Arc::clone(&self.pos_slots))
    }

    /// Set the work event sender for the unified pipeline worker.
    ///
    /// Called from `handle/mod.rs::start()` after constructing both Processor and WorkPipeline.
    pub fn set_work_event_tx(&mut self, tx: mpsc::Sender<crate::daemon::work_pipeline::WorkEvent>) {
        self.work_event_tx = Some(tx);
    }

    /// В-0b: the `[four_r]` dials for the offer shadow (logs only; the reply never reads them).
    /// Called from `handle/mod.rs::start()` next to [`Processor::set_work_event_tx`].
    pub fn set_four_r(&mut self, p: viaticum_core::four_r_holder::FourRParams) {
        self.four_r = p;
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
    /// Dispatches each event to its handler in a new tokio::spawn task (I4 preserved);
    /// PeerRecord events go to the PeerRecord writer task this loop owns — the loop
    /// never waits for the disk on them.
    /// - swarm_rx: ProtocolEvent stream from SwarmHandle (PeerAuthenticated, PeerIdentified,
    ///   InboundRequest, ConnectionClosed)
    pub async fn run(
        self,
        mut swarm_rx: mpsc::Receiver<ProtocolEvent>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        let this = Arc::new(self);
        // The PeerRecord writer: stopped (after writing what is queued) when
        // this loop ends, whichever way. Its own token, NOT a child of `cancel`:
        // a child would stop the writer at the same moment as the loop, and the
        // loop's `select!` may still take one more event and push it after the
        // writer has written its last batch — that event would be lost (fix
        // round 4, N2). Cancelled below, after the loop has ended.
        let writer_cancel = CancellationToken::new();
        let writer = tokio::spawn(peer_record_writer::run_writer(
            this.clone(),
            writer_cancel.clone(),
        ));

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
                            listen_addrs,
                        }) => {
                            // Admission here (revocation, peer_cert_map: no write);
                            // the PeerRecord to the writer, in the swarm's order,
                            // without waiting for it (C-DK C4 fix round 3). The
                            // writer spawns the after-steps once the record is
                            // committed.
                            let _ = peer_id;
                            if this.admit_authenticated(device_id, identity_pub, &device_cert)
                                && !this.peer_records.push(PeerRecordEvent::Authenticated {
                                    device_id,
                                    identity_pub,
                                    device_cert: Box::new(device_cert),
                                    x25519_pub,
                                    listen_addrs: peer::addr_strings(&listen_addrs),
                                })
                            {
                                this.swarm.note_peer_record_dropped();
                            }
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
                            // To the writer, behind the authentication it follows.
                            if !this.peer_records.push(PeerRecordEvent::Identified {
                                device_id,
                                listen_addrs: peer::addr_strings(&listen_addrs),
                            }) {
                                this.swarm.note_peer_record_dropped();
                            }
                        }
                    }
                }
            }
        }

        // Every push of this loop is done: now the writer may write the rest and stop.
        writer_cancel.cancel();
        if let Err(e) = writer.await {
            error!(err = %e, "processor: PeerRecord writer task failed");
        }
        Ok(())
    }

    /// The reply to a `SymbolTransfer`: `SymbolStored` with the chunk's ESIs only if every one of
    /// them is on this holder's disk afterwards; `Ack` otherwise (backup-i19). Split from
    /// `dispatch_libp2p` because a libp2p `ResponseChannel` cannot be built in a unit test.
    pub(crate) async fn symbol_transfer_reply(
        &self,
        from_device: DeviceId,
        from_master: IdentityPub,
        transfer: SymbolTransferMsg,
    ) -> Message {
        let block_id = transfer.source_block_id;
        let mut esi_list: Vec<u32> = transfer.symbols.iter().map(|s| s.esi).collect();
        esi_list.sort_unstable();
        match self
            .handle_symbol_transfer(from_device, from_master, transfer)
            .await
        {
            Ok(TransferResult::Stored) => Message::SymbolStored(SymbolStoredMsg {
                v: 1,
                source_block_id: block_id,
                esi_ranges: esi_list_to_ranges(&esi_list),
                timestamp: Timestamp::now(),
            }),
            Ok(TransferResult::NotStored(reason)) => {
                warn!(device = %from_device, block_id = %block_id, reason = ?reason,
                      "processor: SymbolTransfer not stored");
                Message::Ack(AckMsg { v: 1 })
            }
            Err(e) => {
                warn!(device = %from_device, err = %e, "processor: SymbolTransfer failed");
                Message::Ack(AckMsg { v: 1 })
            }
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
                let reply = self
                    .symbol_transfer_reply(from_device, from_master, transfer)
                    .await;
                self.swarm.respond_logged(response_channel, reply);
            }
            Message::PosHashChallenge(challenge) => {
                match self
                    .handle_pos_hash_challenge_inner(from_master, challenge)
                    .await
                {
                    Ok(reply) => {
                        self.swarm.respond_logged(response_channel, reply);
                    }
                    Err(e) => {
                        warn!(device = %from_device, err = %e, "processor: PosHashChallenge handler failed");
                    }
                }
            }
            Message::SymbolOffer(offer) => {
                let reply = self.handle_symbol_offer_inner(from_device, from_master, offer);
                self.swarm.respond_logged(response_channel, reply);
            }
            Message::RestoreRequest(req) => {
                let reply = match self.handle_restore_request_inner(from_master, req).await {
                    Ok(resp) => Message::RestoreResponse(resp),
                    Err(e) => {
                        warn!(device = %from_device, err = %e, "processor: RestoreRequest handler failed");
                        return Ok(());
                    }
                };
                self.swarm.respond_logged(response_channel, reply);
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
                    self.swarm
                        .respond_logged(response_channel, Message::Ack(AckMsg { v: 1 }));
                    return Ok(());
                }
                if let Err(e) = self.handle_cluster_sync_response(from_device, resp).await {
                    warn!(device = %from_device, err = %e, "processor: ClusterSyncResponse handler failed");
                }
                self.swarm
                    .respond_logged(response_channel, Message::Ack(AckMsg { v: 1 }));
            }
            Message::SymbolAccept(accept) => {
                if let Err(e) = self.handle_symbol_accept(from_master, accept).await {
                    warn!(device = %from_device, err = %e, "processor: SymbolAccept handler failed");
                }
                self.swarm
                    .respond_logged(response_channel, Message::Ack(AckMsg { v: 1 }));
            }
            Message::SymbolReject(reject) => {
                if let Err(e) = self.handle_symbol_reject(from_master, reject).await {
                    warn!(device = %from_device, err = %e, "processor: SymbolReject handler failed");
                }
                self.swarm
                    .respond_logged(response_channel, Message::Ack(AckMsg { v: 1 }));
            }
            Message::PeerAnnounce(pa) => {
                if let Err(e) = self.handle_peer_announce(pa).await {
                    warn!(device = %from_device, err = %e, "processor: PeerAnnounce handler failed");
                }
                self.swarm
                    .respond_logged(response_channel, Message::Ack(AckMsg { v: 1 }));
            }
            Message::MailboxStoreRequest(req) => {
                // Build routing view from known peers in the DB.
                let routing_view = self.build_routing_view();
                let my_peer_id = self.swarm.peer_id;
                let now = Timestamp::now().0;
                let resp =
                    mailbox::handle_mailbox_store(&self.db, &routing_view, &my_peer_id, req, now);
                self.swarm
                    .respond_logged(response_channel, Message::MailboxStoreResponse(resp));
            }
            Message::MailboxFetchRequest(req) => {
                let now = Timestamp::now().0;
                let resp =
                    mailbox::handle_mailbox_fetch(&self.db, req, from_master, from_device, now);
                self.swarm
                    .respond_logged(response_channel, Message::MailboxFetchResponse(resp));
            }
            other => {
                warn!(
                    device = %from_device,
                    "processor: dispatch_libp2p: unhandled message variant {:?}",
                    std::mem::discriminant(&other)
                );
                self.swarm
                    .respond_logged(response_channel, Message::Ack(AckMsg { v: 1 }));
            }
        }
        Ok(())
    }
}
// PeerDiscoveryRequest and PeerDiscoveryResponse removed in ε.2 (AC-12).
// Replaced by Kademlia DHT in ε.3.

// ─── Shared helpers ───────────────────────────────────────────────────────────

/// The seen-set write that rides in the placement transaction (DN-1, Д-DN1-5): "the signed
/// letter with this (verified) signature has been applied", committed together with the
/// transition it caused. See `Db::record_signed_letter_seen`.
#[derive(Clone, Copy)]
pub(crate) struct SeenWrite<'a> {
    pub sig: &'a [u8; 64],
    pub class: viaticum_core::types::SignedLetterClass,
    pub now: Timestamp,
    pub forget_after: Timestamp,
}

/// Mark a placement as Lost. Idempotent: no-op if already Lost or Deleting.
/// Returns true if the record was changed.
///
/// `evidence_at` is the signed `timestamp` of the DropNotice that caused the call: the
/// 4R pair ledger counts the transition as an ANNOUNCED drop only if that notice is strictly
/// younger than the placement's episode (У-4, [`persist_placement_change`]). The transition
/// itself does not depend on it. A re-delivered notice never reaches this function (DN-1 in
/// `SymbolDropHandler::apply`); the first delivery of an old notice still marks a fresh
/// placement Lost (DN-1 Д-DN1-2: time is not part of the rule).
///
/// `seen` (DN-1): when `Some`, the notice is remembered in the SAME write transaction as the
/// transition (and its У-4 event), see [`persist_placement_change`]. Not written when nothing
/// changes (missing / already Lost / Deleting) — the caller decides about those.
pub(crate) fn mark_placement_lost(
    db: &Db,
    block_id: &viaticum_core::types::SourceBlockId,
    holder_id: &DeviceId,
    evidence_at: Timestamp,
    seen: Option<SeenWrite<'_>>,
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

    let mut updated = placement.clone();
    updated.status = PlacementStatus::Lost;
    updated.consecutive_misses = 0;
    persist_placement_change(
        db,
        &placement,
        &updated,
        Some(LossCause::DropNotice),
        evidence_at,
        seen,
    )?;

    info!(
        block_id = %block_id,
        holder = %holder_id,
        "processor: placement marked Lost"
    );

    Ok(true)
}

/// Persist a placement status change and, if it is the first loss of a HELD placement
/// ([`viaticum_core::pair_ledger::drop_event_for`]), record the drop event for the 4R pair
/// ledger in the SAME write transaction (У-4, Д-K). Returns the kind recorded, if any.
///
/// The placement write is exactly what `Db::upsert_placement(updated)` did before (AC-7):
/// without an event it IS that call; with one, `DbWriteTxn::upsert_placement` (same table
/// writes, same hot-cache delta, applied after commit) plus `record_drop_event`, committed
/// together — the transition and its event exist together or not at all. The recorder can
/// never block the transition: an unresolvable master (no `PeerRecord`, placeholder, or a
/// failed read) only drops the EVENT, with a `warn!`/`error!`.
///
/// Log lines — a contract with `experiments/local_ledger_drop_test.sh`, under the fixed
/// target `viaticum::ledger` at debug (enable with `RUST_LOG=info,viaticum::ledger=debug`):
/// `pair-ledger drop event` (`kind master block_id holder`) and `pair-ledger drop not
/// counted` (`reason cause block_id holder`, only for a changed status landing in
/// `Lost`/`PresumedLost` — not on every `Uncertain`). Both are printed only AFTER a
/// successful commit, so every event line is an event in the database.
///
/// `seen` (DN-1, Д-DN1-5): with `Some`, EVERY branch writes through one `db.write_txn()` —
/// the placement, the event if there is one, and the applied-notice row — and commits once.
/// With `None` every branch is exactly the У-4 code (AC-7 of У-4): the PoS callers in
/// `scheduler` pass `None`.
pub(crate) fn persist_placement_change(
    db: &Db,
    before: &SymbolPlacement,
    updated: &SymbolPlacement,
    cause: Option<LossCause>,
    evidence_at: Timestamp,
    seen: Option<SeenWrite<'_>>,
) -> Result<Option<DropKind>, viaticum_core::db::DbError> {
    let decision = match cause {
        Some(cause) if updated.status != before.status => Some((
            cause,
            drop_event_for(
                before.status,
                updated.status,
                cause,
                evidence_at,
                before.placed_at,
            ),
        )),
        _ => None,
    };

    let (cause, kind) = match decision {
        Some((cause, Ok(kind))) => (cause, kind),
        Some((cause, Err(reason))) => {
            upsert_placement_with_seen(db, updated, seen)?;
            if matches!(
                updated.status,
                PlacementStatus::Lost | PlacementStatus::PresumedLost
            ) {
                debug!(
                    target: "viaticum::ledger",
                    reason = ?reason,
                    cause = ?cause,
                    block_id = %updated.source_block_id,
                    holder = %updated.holder_id,
                    "pair-ledger drop not counted"
                );
            }
            return Ok(None);
        }
        None => {
            upsert_placement_with_seen(db, updated, seen)?;
            return Ok(None);
        }
    };

    // Resolve the master BEFORE opening the write transaction (a read inside it would not
    // see anything the transaction changes anyway, and redb allows one writer at a time).
    let master = match ledger_master_for_device(db, &updated.holder_id) {
        Ok(Some(master)) => master,
        Ok(None) => {
            upsert_placement_with_seen(db, updated, seen)?;
            warn!(
                target: "viaticum::ledger",
                kind = ?kind,
                cause = ?cause,
                block_id = %updated.source_block_id,
                holder = %updated.holder_id,
                "pair-ledger drop not recorded: the holder device has no known master"
            );
            return Ok(None);
        }
        Err(e) => {
            upsert_placement_with_seen(db, updated, seen)?;
            error!(
                target: "viaticum::ledger",
                kind = ?kind,
                block_id = %updated.source_block_id,
                holder = %updated.holder_id,
                err = %e,
                "pair-ledger drop not recorded: master lookup failed"
            );
            return Ok(None);
        }
    };

    // INVARIANT (Д-K): the placement change and its event are ONE write transaction. The
    // placement status IS the dedup key — "already counted" means "no longer Alive/Uncertain"
    // — so the two must become visible together. Split them and a crash (or a failed write)
    // in the window between the commits breaks the count in either direction:
    //   * placement first, event second: the transition is on disk, the event is not, and no
    //     re-delivery can bring it back (the placement is already Lost) — a permanent
    //     UNDER-count;
    //   * event first, placement second: the event is on disk, the placement is still held,
    //     so the next re-delivery of the same notice (the mailbox hands it out on every poll
    //     for its whole TTL) counts it AGAIN — an OVER-count.
    // No unit test guards this (there is no failure injection between two writes of one
    // transaction without a test-only production API); it is stated here and in the Cannot
    // close of `experiments/local_ledger_drop_test.sh`. Do not split it.
    let mut txn = db.write_txn()?;
    txn.upsert_placement(updated)?;
    txn.record_drop_event(&master, kind)?;
    // DN-1 (Д-DN1-5): the applied notice rides in the same transaction — a crash cannot leave
    // "transition + event" without "seen" (one more application) or the reverse (a swallowed
    // drop).
    if let Some(seen) = seen {
        txn.record_signed_letter_seen(seen.sig, seen.class, seen.now, seen.forget_after)?;
    }
    if let Err(e) = txn.commit() {
        error!(
            target: "viaticum::ledger",
            kind = ?kind,
            block_id = %updated.source_block_id,
            holder = %updated.holder_id,
            err = %e,
            "pair-ledger drop event: transaction failed, neither the placement change nor the event was written"
        );
        return Err(e);
    }
    debug!(
        target: "viaticum::ledger",
        kind = ?kind,
        master = %master,
        block_id = %updated.source_block_id,
        holder = %updated.holder_id,
        "pair-ledger drop event"
    );
    Ok(Some(kind))
}

/// The placement write of the no-event branches of [`persist_placement_change`]. Without
/// `seen` it IS `Db::upsert_placement` (the У-4 code, unchanged); with `seen` the placement and
/// the applied-notice row are one transaction (DN-1, Д-DN1-5).
fn upsert_placement_with_seen(
    db: &Db,
    updated: &SymbolPlacement,
    seen: Option<SeenWrite<'_>>,
) -> Result<(), viaticum_core::db::DbError> {
    let Some(seen) = seen else {
        return db.upsert_placement(updated);
    };
    let mut txn = db.write_txn()?;
    txn.upsert_placement(updated)?;
    txn.record_signed_letter_seen(seen.sig, seen.class, seen.now, seen.forget_after)?;
    txn.commit()
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
        return;
    }

    // 6. Log only when the "at target" verdict flips (low volume): the owner's own
    // judgement "this block is at its target" becomes observable (repair-i3), with the
    // raw numbers that decided it.
    let at_target = |current: f64| {
        block.target_reliability > 0.0
            && viaticum_core::reliability::meets_target(current, block.target_reliability)
    };
    let was_at_target = at_target(block.current_reliability);
    let now_at_target = at_target(new_reliability);
    if was_at_target != now_at_target {
        info!(
            block_id = %block_id,
            current_alive = new_current_alive,
            current_reliability = new_reliability,
            target_reliability = block.target_reliability,
            at_target = now_at_target,
            "placement hook: block target status changed"
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
