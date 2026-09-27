// Mailbox routing helper: sender-side fanout for publish and poll.
//
// T-4: MailboxRouter publishes entries to write-fanout candidates and polls
// from read-fanout candidates. Candidate set = top-N peers by XOR(SHA256(target_pub),
// SHA256(peer_id)), ranked by combined_trust × avail_ewma for write-fanout.
//
// Candidate sourcing: peers known from DB (list_all_peers) converted to PeerId
// via device_id_to_peer_id. This covers all historically authenticated peers,
// which is the right source for a mailbox candidate set (not just currently-connected
// peers — the whole point is to reach peers that have likely seen the target recently).
//
// dr_collect_pointers: the spec calls for "expanding Kademlia batches [100, 300, 1000]".
// Live Kademlia get_closest_peers is an async DHT walk not readily queryable synchronously.
// Design choice: use the DB-sourced XOR-ranked list with expanding batch sizes.
// This is equivalent when the DB is well-populated (post-bootstrap) and degrades
// gracefully to "try all known peers" when the DB is sparse (early DR run on
// a fresh node). A future enhancement could add a SwarmHandle::kad_closest_peers()
// command that drives the Kademlia query internally; deferred as not needed for
// correctness (spec B-1: Kademlia-lookup is a first-class DR path when addrs are stale
// or absent, not a requirement for the initial walk implementation).
//
// Avail observation wiring (T-4a §5):
// Successful MailboxStoreAck / MailboxFetchResponse → positive observation:
//   record.avail_ewma = ewma_contact_observed(record.avail_ewma, AVAIL_EWMA_ALPHA)
//   record.last_avail_sample = now_secs
// This is the only place T-4a wiring belongs in the sender path.
//
// See A2 spec §2.5 for full design.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use libp2p::PeerId;
use tokio::time::{Duration, timeout};
use tracing::{debug, warn};
use viaticum_core::constants::{
    AVAIL_EWMA_ALPHA, AVAIL_EWMA_INITIAL, MAILBOX_CANDIDATES_N, MAILBOX_DR_WALK_BATCHES,
    MAILBOX_READ_FANOUT, MAILBOX_WRITE_FANOUT,
};
use viaticum_core::db::Db;
use viaticum_core::mailbox::MailboxClass;
use viaticum_core::messages::{
    MailboxFetchRequest, MailboxFetchResponse, MailboxStoreRequest, MailboxStoreResponse, Message,
};
use viaticum_core::system_state::{SelfPointer, verify_self_pointer};
use viaticum_core::trust::compute_combined;
use viaticum_core::types::{DeviceId, IdentityPub, ewma_contact_observed, from_cbor_bytes};

use crate::daemon::mailbox::candidate::KademliaRoutingView;
use crate::daemon::network::swarm::{SwarmHandle, device_id_to_peer_id};

// ─── DR collection result ─────────────────────────────────────────────────────

/// What `MailboxRouter::dr_collect_pointers` found.
#[derive(Debug, Clone)]
pub struct DrWalk {
    /// Every distinct (by signature) signature-verified SelfPointer of the identity.
    pub pointers: Vec<SelfPointer>,
    /// Peers the walk could ask (0 = no peer known at all).
    pub candidates: usize,
    /// Peers that answered the fetch.
    pub responders: usize,
}

// ─── Per-request network timeout ─────────────────────────────────────────────

/// Per-peer request timeout. Mailbox operations are best-effort and parallelized;
/// a slow peer must not stall the whole fanout.
const PEER_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

// ============================================================
// MailboxNetworkSender — test seam
// ============================================================

/// Abstract sender for MailboxStoreRequest / MailboxFetchRequest.
///
/// Exists solely for testability (spec §2.5: "integration, requires mock swarm").
/// The production impl wraps SwarmHandle; tests inject a MockSender.
///
/// Convention note: this trait is NOT speculative extensibility — it is the
/// prescribed test seam from the T-4 spec. Only two impls: SwarmSender (prod)
/// and MockSender (tests).
#[async_trait]
pub trait MailboxNetworkSender: Send + Sync {
    /// Send a MailboxStoreRequest to a specific device. Best-effort: returns Ok(Ack)
    /// on success, Err on network failure (timeout, not-authenticated, etc.).
    async fn send_store(
        &self,
        device: DeviceId,
        req: MailboxStoreRequest,
    ) -> anyhow::Result<MailboxStoreResponse>;

    /// Send a MailboxFetchRequest to a specific device. Best-effort.
    async fn send_fetch(
        &self,
        device: DeviceId,
        req: MailboxFetchRequest,
    ) -> anyhow::Result<MailboxFetchResponse>;
}

// ─── Production impl: wraps SwarmHandle ──────────────────────────────────────

/// Production MailboxNetworkSender that sends through the live libp2p swarm.
pub struct SwarmSender {
    swarm: Arc<SwarmHandle>,
}

impl SwarmSender {
    pub fn new(swarm: Arc<SwarmHandle>) -> Self {
        SwarmSender { swarm }
    }
}

#[async_trait]
impl MailboxNetworkSender for SwarmSender {
    async fn send_store(
        &self,
        device: DeviceId,
        req: MailboxStoreRequest,
    ) -> anyhow::Result<MailboxStoreResponse> {
        let msg = Message::MailboxStoreRequest(req);
        let resp = timeout(PEER_REQUEST_TIMEOUT, self.swarm.send_to_device(device, msg))
            .await
            .map_err(|_| anyhow::anyhow!("mailbox store timeout to {device}"))?
            .map_err(|e| anyhow::anyhow!("mailbox store to {device}: {e}"))?;
        match resp {
            Message::MailboxStoreResponse(r) => Ok(r),
            other => anyhow::bail!(
                "unexpected response to MailboxStoreRequest: {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    async fn send_fetch(
        &self,
        device: DeviceId,
        req: MailboxFetchRequest,
    ) -> anyhow::Result<MailboxFetchResponse> {
        let msg = Message::MailboxFetchRequest(req);
        let resp = timeout(PEER_REQUEST_TIMEOUT, self.swarm.send_to_device(device, msg))
            .await
            .map_err(|_| anyhow::anyhow!("mailbox fetch timeout to {device}"))?
            .map_err(|e| anyhow::anyhow!("mailbox fetch to {device}: {e}"))?;
        match resp {
            Message::MailboxFetchResponse(r) => Ok(r),
            other => anyhow::bail!(
                "unexpected response to MailboxFetchRequest: {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }
}

// ============================================================
// MailboxRouter
// ============================================================

/// Sender-side mailbox routing: publish entries and poll for owned entries.
///
/// Builds candidate sets from the local DB (all known peers, XOR-ranked for
/// target), selects write-fanout top-N by combined_trust × avail_ewma, and
/// sends in parallel. Returns success counts / deduplicated entry lists.
pub struct MailboxRouter {
    sender: Arc<dyn MailboxNetworkSender>,
    db: Db,
    /// Candidate pool size (top-N closest by XOR).
    pub candidates_n: usize,
    /// Write fanout: top-K peers by trust × avail_ewma.
    pub write_fanout: usize,
    /// Read fanout: broader for overlap guarantee.
    pub read_fanout: usize,
}

impl MailboxRouter {
    /// Construct with real SwarmHandle (production path).
    pub fn new(swarm: Arc<SwarmHandle>, db: Db) -> Self {
        MailboxRouter {
            sender: Arc::new(SwarmSender::new(swarm)),
            db,
            candidates_n: MAILBOX_CANDIDATES_N,
            write_fanout: MAILBOX_WRITE_FANOUT,
            read_fanout: MAILBOX_READ_FANOUT,
        }
    }

    /// Construct with an injected sender (test path).
    pub fn with_sender(sender: Arc<dyn MailboxNetworkSender>, db: Db) -> Self {
        MailboxRouter {
            sender,
            db,
            candidates_n: MAILBOX_CANDIDATES_N,
            write_fanout: MAILBOX_WRITE_FANOUT,
            read_fanout: MAILBOX_READ_FANOUT,
        }
    }

    // ─── Candidate building ───────────────────────────────────────────────────

    /// Build a XOR-ranked list of (DeviceId, PeerId) candidates for `target`.
    ///
    /// Source: all peers in DB. PeerId derived deterministically from DeviceId
    /// via device_id_to_peer_id (Ed25519 pubkey → libp2p PeerId).
    fn build_ranked_candidates(&self, target: &IdentityPub) -> Vec<(DeviceId, PeerId)> {
        let peers = match self.db.list_all_peers() {
            Ok(p) => p,
            Err(e) => {
                warn!(err = %e, "mailbox router: failed to list peers");
                return vec![];
            }
        };

        let target_key = KademliaRoutingView::target_key(target);

        let mut with_dist: Vec<([u8; 32], DeviceId, PeerId)> = peers
            .into_iter()
            .filter_map(|record| {
                let peer_id = match device_id_to_peer_id(&record.device_id) {
                    Ok(pid) => pid,
                    Err(e) => {
                        debug!(
                            device = %record.device_id,
                            err = %e,
                            "mailbox router: skip peer — cannot derive PeerId"
                        );
                        return None;
                    }
                };
                let peer_key = KademliaRoutingView::peer_key(&peer_id);
                let dist = KademliaRoutingView::xor_distance(&target_key, &peer_key);
                Some((dist, record.device_id, peer_id))
            })
            .collect();

        // Sort ascending by XOR distance (closest first).
        with_dist.sort_by_key(|a| a.0);

        with_dist
            .into_iter()
            .map(|(_, device_id, peer_id)| (device_id, peer_id))
            .collect()
    }

    // ─── Public API ───────────────────────────────────────────────────────────

    /// Publish an entry to the write-fanout (top-30) of candidates for `target`.
    ///
    /// Returns count of successful Acks.
    /// Avail observation: on Ack, updates avail_ewma + last_avail_sample for the
    /// responding peer in the DB.
    pub async fn publish(
        &self,
        target: &IdentityPub,
        entry: viaticum_core::mailbox::MailboxEntry,
    ) -> anyhow::Result<usize> {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let ranked = self.build_ranked_candidates(target);

        // Select write-fanout peers.
        let write_peers = self.select_write_peers_from_ranked(&ranked, target, now_secs);

        let req = MailboxStoreRequest {
            v: 1,
            target: *target,
            entry: entry.clone(),
        };

        // Send in parallel, collect results.
        let mut handles = Vec::with_capacity(write_peers.len());
        for device_id in &write_peers {
            let sender = Arc::clone(&self.sender);
            let req_clone = req.clone();
            let dev = *device_id;
            handles.push(tokio::spawn(async move {
                (dev, sender.send_store(dev, req_clone).await)
            }));
        }

        let mut ack_count = 0usize;
        for handle in handles {
            match handle.await {
                Ok((device_id, Ok(MailboxStoreResponse::Ack { .. }))) => {
                    ack_count += 1;
                    self.record_avail_contact(device_id, now_secs);
                }
                Ok((device_id, Ok(MailboxStoreResponse::Reject { reason, .. }))) => {
                    debug!(
                        device = %device_id,
                        ?reason,
                        "mailbox publish: peer rejected store"
                    );
                }
                Ok((device_id, Err(e))) => {
                    debug!(device = %device_id, err = %e, "mailbox publish: store failed");
                }
                Err(join_err) => {
                    warn!("mailbox publish: task panicked: {join_err}");
                }
            }
        }

        if ack_count == 0 {
            warn!(
                target = %target,
                peers_tried = write_peers.len(),
                "mailbox publish: 0 acks — entry may not be stored; will retry on next tick"
            );
        } else {
            debug!(
                target = %target,
                ack_count,
                peers_tried = write_peers.len(),
                "mailbox publish: stored"
            );
        }

        Ok(ack_count)
    }

    /// Poll entries addressed to `my_master_pub` from read-fanout (300) candidates.
    ///
    /// Returns unique non-expired entries, deduped by msg_id (most-recent wins on dup).
    /// Avail observation: on successful FetchResponse, updates avail_ewma for the responding peer.
    pub async fn poll(
        &self,
        my_master_pub: &IdentityPub,
        since_stored_at: Option<u64>,
    ) -> anyhow::Result<Vec<viaticum_core::mailbox::MailboxEntry>> {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let ranked = self.build_ranked_candidates(my_master_pub);

        // Read-fanout: top-300 closest peers.
        let read_peers: Vec<DeviceId> = ranked
            .iter()
            .take(self.read_fanout)
            .map(|(d, _)| *d)
            .collect();

        let req = MailboxFetchRequest {
            v: 1,
            target: *my_master_pub,
            since_stored_at,
        };

        // Send in parallel to all read-fanout peers.
        let mut handles = Vec::with_capacity(read_peers.len());
        for device_id in &read_peers {
            let sender = Arc::clone(&self.sender);
            let req_clone = req.clone();
            let dev = *device_id;
            handles.push(tokio::spawn(async move {
                (dev, sender.send_fetch(dev, req_clone).await)
            }));
        }

        // Collect all responses; dedup by msg_id.
        // Last writer (by stored_at) wins on duplicate msg_id from different peers.
        let mut by_msg_id: HashMap<[u8; 16], viaticum_core::mailbox::MailboxEntry> = HashMap::new();

        for handle in handles {
            match handle.await {
                Ok((device_id, Ok(resp))) => {
                    self.record_avail_contact(device_id, now_secs);
                    for entry in resp.entries {
                        // Skip expired entries (should not happen; postman filters them,
                        // but be defensive against clock skew).
                        if entry.expires_at <= now_secs {
                            continue;
                        }
                        // Dedup: keep highest stored_at per msg_id.
                        by_msg_id
                            .entry(entry.msg_id)
                            .and_modify(|existing| {
                                if entry.stored_at > existing.stored_at {
                                    *existing = entry.clone();
                                }
                            })
                            .or_insert(entry);
                    }
                }
                Ok((device_id, Err(e))) => {
                    debug!(device = %device_id, err = %e, "mailbox poll: fetch failed");
                }
                Err(join_err) => {
                    warn!("mailbox poll: task panicked: {join_err}");
                }
            }
        }

        let entries: Vec<_> = by_msg_id.into_values().collect();
        debug!(
            my_master = %my_master_pub,
            entry_count = entries.len(),
            peers_tried = read_peers.len(),
            "mailbox poll: collected entries"
        );

        Ok(entries)
    }

    /// DR: collect EVERY signature-verified SelfPointer of `my_master_pub` from the
    /// candidate set (CS-DR-1).
    ///
    /// Candidates are the DB peers ranked by XOR distance to the target (closest first),
    /// queried in the expanding batches of `MAILBOX_DR_WALK_BATCHES` ([100, 300, 1000]).
    /// Each peer is asked at most once: batch k sends only to `ranked[prev_len..size]`;
    /// a batch that adds no new peer ends the walk. There is no early exit on the first
    /// batch that returned a pointer — a fresher pointer, or another catalog history of
    /// the same identity, may sit in a later batch. Choosing between the pointers is the
    /// caller's job (`system_state::catalog::select_catalog`).
    ///
    /// Candidates come from `db.list_all_peers()`: on a fresh DR node the caller must
    /// have run Kademlia stabilization (peers upserted on authentication) first,
    /// otherwise `candidates == 0`.
    pub async fn dr_collect_pointers(&self, my_master_pub: &IdentityPub) -> anyhow::Result<DrWalk> {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let ranked = self.build_ranked_candidates(my_master_pub);
        let max_batch = MAILBOX_DR_WALK_BATCHES.last().copied().unwrap_or(0);
        let candidates = ranked.len().min(max_batch);

        tracing::info!(
            ranked_candidates = ranked.len(),
            candidates,
            "dr_walk: candidates built from DB"
        );

        let req = MailboxFetchRequest {
            v: 1,
            target: *my_master_pub,
            since_stored_at: None,
        };

        let mut pointers: Vec<SelfPointer> = Vec::new();
        let mut seen_sigs: std::collections::HashSet<[u8; 64]> = std::collections::HashSet::new();
        let mut responders = 0usize;
        let mut prev_len = 0usize;

        for &batch_size in MAILBOX_DR_WALK_BATCHES {
            let end = batch_size.min(ranked.len());
            if end <= prev_len {
                tracing::info!(
                    batch_size,
                    queried = prev_len,
                    "dr_walk: no new candidates for this batch, walk complete"
                );
                break;
            }
            let batch: Vec<DeviceId> = ranked[prev_len..end].iter().map(|(d, _)| *d).collect();
            prev_len = end;

            tracing::info!(
                batch_size,
                peers = batch.len(),
                "dr_walk: sending fetch to batch"
            );

            let mut handles = Vec::with_capacity(batch.len());
            for device_id in batch {
                let sender = Arc::clone(&self.sender);
                let req_clone = req.clone();
                handles.push(tokio::spawn(async move {
                    (device_id, sender.send_fetch(device_id, req_clone).await)
                }));
            }

            for handle in handles {
                match handle.await {
                    Ok((device_id, Ok(resp))) => {
                        responders += 1;
                        tracing::info!(
                            device = %device_id,
                            entries = resp.entries.len(),
                            "dr_walk: fetch response from peer"
                        );
                        self.record_avail_contact(device_id, now_secs);
                        for entry in resp.entries {
                            if entry.class != MailboxClass::SelfPointer {
                                continue;
                            }
                            match from_cbor_bytes::<SelfPointer>(&entry.payload) {
                                Ok(pointer) => {
                                    if verify_self_pointer(&pointer, my_master_pub).is_err() {
                                        debug!(
                                            device = %device_id,
                                            "dr_walk: pointer signature verification failed"
                                        );
                                        continue;
                                    }
                                    if seen_sigs.insert(pointer.signature) {
                                        pointers.push(pointer);
                                    }
                                }
                                Err(e) => {
                                    debug!(
                                        device = %device_id,
                                        err = %e,
                                        "dr_walk: failed to decode SelfPointer payload"
                                    );
                                }
                            }
                        }
                    }
                    Ok((device_id, Err(e))) => {
                        tracing::info!(device = %device_id, err = %e, "dr_walk: fetch failed for peer");
                    }
                    Err(join_err) => {
                        warn!("dr_walk: task panicked: {join_err}");
                    }
                }
            }
        }

        tracing::info!(
            candidates,
            responders,
            pointers = pointers.len(),
            "dr_walk: collection complete"
        );
        Ok(DrWalk {
            pointers,
            candidates,
            responders,
        })
    }

    // ─── Peer selection ───────────────────────────────────────────────────────

    /// Select write-fanout: top `write_fanout` peers from `candidates` by
    /// `combined_trust × avail_ewma`.
    ///
    /// `candidates` is a pre-XOR-ranked slice (closest first); the caller is responsible
    /// for the ordering. This function only does trust × avail scoring and takes the top
    /// `write_fanout` entries.
    ///
    /// `avail_ewma` — rolling EWMA availability [0.0, 1.0] stored in `PeerRecord`.
    /// New peers start at AVAIL_EWMA_INITIAL (pessimistic 0.1 — earned, not assumed).
    ///
    /// `combined_trust` = compute_combined(trust_p, trust_i, trust_s) for known peers;
    /// 0.0 for peers not in DB.
    ///
    /// `now_secs` is available for future time-gated scoring; not used in current formula.
    ///
    /// This is the canonical ranking function used by both production (`publish`) and tests.
    pub fn select_write_peers(
        &self,
        candidates: &[PeerId],
        _target_pub: &IdentityPub,
        _now_secs: u64,
    ) -> Vec<DeviceId> {
        // Load peer records for trust + avail lookup.
        let peer_records = match self.db.list_all_peers() {
            Ok(p) => p,
            Err(e) => {
                warn!(err = %e, "select_write_peers: failed to list peers");
                return vec![];
            }
        };

        let record_map: HashMap<PeerId, _> = peer_records
            .into_iter()
            .filter_map(|record| {
                let pid = device_id_to_peer_id(&record.device_id).ok()?;
                Some((pid, record))
            })
            .collect();

        // Score each candidate by combined_trust × avail_ewma.
        let mut scored: Vec<(f64, DeviceId)> = candidates
            .iter()
            .filter_map(|peer_id| {
                let (combined_trust, avail_ewma, device_id) = match record_map.get(peer_id) {
                    Some(record) => {
                        let combined =
                            compute_combined(record.trust_p, record.trust_i, record.trust_s);
                        (combined, record.avail_ewma, record.device_id)
                    }
                    None => {
                        // Unknown peer (not in DB): use AVAIL_EWMA_INITIAL and zero trust.
                        // In practice, all candidates come from the DB, so this is rare.
                        let device_id = peer_id_to_device_id_best_effort(peer_id)?;
                        (0.0_f64, AVAIL_EWMA_INITIAL, device_id)
                    }
                };

                let score = combined_trust * avail_ewma;
                Some((score, device_id))
            })
            .collect();

        // Sort descending by score.
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        scored
            .into_iter()
            .take(self.write_fanout)
            .map(|(_, device_id)| device_id)
            .collect()
    }

    // ─── Internal helpers ─────────────────────────────────────────────────────

    /// Extract top `candidates_n` PeerIds from an already-XOR-ranked list and delegate
    /// to `select_write_peers` for scoring. Production `publish` calls this.
    fn select_write_peers_from_ranked(
        &self,
        ranked: &[(DeviceId, PeerId)],
        target_pub: &IdentityPub,
        now_secs: u64,
    ) -> Vec<DeviceId> {
        let candidate_peer_ids: Vec<PeerId> = ranked
            .iter()
            .take(self.candidates_n)
            .map(|(_, pid)| *pid)
            .collect();
        self.select_write_peers(&candidate_peer_ids, target_pub, now_secs)
    }

    /// Apply a positive avail observation for `device_id` in the DB.
    ///
    /// Called after a successful MailboxStoreAck or MailboxFetchResponse.
    /// Non-fatal: logs warning on DB error.
    fn record_avail_contact(&self, device_id: DeviceId, now_secs: u64) {
        match self.db.get_peer(&device_id) {
            Ok(Some(mut record)) => {
                record.avail_ewma = ewma_contact_observed(record.avail_ewma, AVAIL_EWMA_ALPHA);
                record.last_avail_sample = now_secs;
                if let Err(e) = self.db.upsert_peer(&record) {
                    warn!(
                        device = %device_id,
                        err = %e,
                        "mailbox router: failed to persist avail_ewma contact observation"
                    );
                }
            }
            Ok(None) => {
                // Peer not in DB (unusual — they were a candidate). No-op.
                debug!(device = %device_id, "mailbox router: avail contact for unknown peer");
            }
            Err(e) => {
                warn!(
                    device = %device_id,
                    err = %e,
                    "mailbox router: failed to load peer for avail update"
                );
            }
        }
    }
}

// ─── Utility ─────────────────────────────────────────────────────────────────

/// Attempt to recover DeviceId from PeerId (best-effort, only works for Ed25519 PeerIds).
///
/// PeerId encodes the Ed25519 public key for Viaticum peers. Used in select_write_peers
/// for peers that exist in the candidate PeerId list but are somehow absent from the DB.
fn peer_id_to_device_id_best_effort(peer_id: &PeerId) -> Option<DeviceId> {
    use libp2p::identity::PublicKey;
    let multihash = peer_id.as_ref();
    // Try to decode as identity multihash (inline key, Ed25519 nodes use this).
    let pub_key = PublicKey::try_decode_protobuf(multihash.digest()).ok()?;
    let ed_key = pub_key.try_into_ed25519().ok()?;
    Some(DeviceId(ed_key.to_bytes()))
}

// ─── Pure helper: dedup entries by msg_id ────────────────────────────────────

/// Deduplicate a slice of entries by msg_id, keeping the one with highest stored_at.
/// Exposed for unit testing.
pub fn dedup_entries(
    entries: Vec<viaticum_core::mailbox::MailboxEntry>,
) -> Vec<viaticum_core::mailbox::MailboxEntry> {
    let mut by_msg_id: HashMap<[u8; 16], viaticum_core::mailbox::MailboxEntry> = HashMap::new();
    for entry in entries {
        by_msg_id
            .entry(entry.msg_id)
            .and_modify(|existing| {
                if entry.stored_at > existing.stored_at {
                    *existing = entry.clone();
                }
            })
            .or_insert(entry);
    }
    by_msg_id.into_values().collect()
}

#[cfg(test)]
mod tests;
