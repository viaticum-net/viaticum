// Mailbox routing helper: sender-side fanout for publish and poll.
//
// T-4: MailboxRouter publishes entries to write-fanout candidates and polls
// from read-fanout candidates. Candidate set = top-N peers by XOR(SHA256(address),
// SHA256(peer_id)), ranked by combined_trust × avail_ewma for write-fanout.
// CROWN-1 C2: the address is a `MailboxAddress` taken from the entry itself.
//
// Candidate sourcing: peers known from DB (list_all_peers) converted to PeerId
// via device_id_to_peer_id. This covers all historically authenticated peers,
// which is the right source for a mailbox candidate set (not just currently-connected
// peers — the whole point is to reach peers that have likely seen the target recently).
//
// dr_collect_pointers (submodule `dr_walk`): the DB-sourced XOR-ranked list in expanding
// batches [100, 300, 1000]; DR fills the DB from Kademlia (get_closest_peers of the
// rendezvous address) before the walk.
//
// publish_detailed: per-postman outcome (acks, refusals, errors) and its verdict, so the
// pointer publisher can name a refusal (CROWN-1 V.3, V.15.3). It returns at the needed
// number of acks, not after the slowest postman (mailbox-i60, submodule `fanout`).
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
    AVAIL_EWMA_INITIAL, MAILBOX_CANDIDATES_N, MAILBOX_READ_FANOUT, MAILBOX_WRITE_FANOUT,
};
use viaticum_core::db::Db;
use viaticum_core::mailbox::{MailboxAddress, MailboxEntry};
use viaticum_core::messages::{
    MAILBOX_WIRE_VERSION, MailboxFetchRequest, MailboxFetchResponse, MailboxStoreRequest,
    MailboxStoreResponse, Message,
};
use viaticum_core::trust::compute_combined;
use viaticum_core::types::DeviceId;

use crate::daemon::mailbox::candidate::KademliaRoutingView;
use crate::daemon::network::swarm::{SwarmHandle, device_id_to_peer_id};

mod dr_walk;
mod fanout;
mod verdict;

use fanout::{record_avail_contact, record_contact_off_runtime, store_fanout, unix_now};

pub use dr_walk::DrWalk;
pub use verdict::{PublishOutcome, PublishVerdict};

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
    fn build_ranked_candidates(&self, target: &MailboxAddress) -> Vec<(DeviceId, PeerId)> {
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

    /// Publish an entry to the write-fanout (top-30) of candidates for `entry.target`
    /// and report what the postmen answered by the time it returned.
    ///
    /// mailbox-i60: returns as soon as `need` postmen acked (directed classes and PoS:
    /// 1, the W-3 gate; a SelfPointer: the dr-i39 threshold), or when every postman
    /// answered, or after 15 s, whichever comes first. The stores still reach every
    /// postman; a late Ack records its contact (avail, `last_seen`) from the postman's
    /// own task, a late refusal or error is only logged (see `fanout`).
    ///
    /// `target_sig`: signature by the secret key of `entry.target` over
    /// `store_sig_input(&entry)`. Postmen require it for class SelfPointer (only the
    /// box key holder writes a pointer box) and ignore it for directed classes. The
    /// box address comes only from the entry (no second `target`, F3).
    pub async fn publish_detailed(
        &self,
        entry: MailboxEntry,
        target_sig: Option<[u8; 64]>,
        need: usize,
    ) -> PublishOutcome {
        let target = entry.target;
        let ranked = self.build_ranked_candidates(&target);
        let write_peers = self.select_write_peers_from_ranked(&ranked, &target, unix_now());
        let req = MailboxStoreRequest {
            v: MAILBOX_WIRE_VERSION,
            entry,
            target_sig,
        };
        let outcome = store_fanout(&self.sender, &self.db, &write_peers, req, need).await;

        if outcome.acks.is_empty() {
            warn!(
                target = %target,
                peers_tried = write_peers.len(),
                refused = outcome.rejects.len(),
                no_answer_in_time = outcome.pending,
                "mailbox publish: 0 acks — entry may not be stored; will retry on next tick"
            );
        } else {
            debug!(
                target = %target,
                ack_count = outcome.acks.len(),
                still_answering = outcome.pending,
                peers_tried = write_peers.len(),
                "mailbox publish: stored"
            );
        }
        outcome
    }

    /// Publish and return the number of Acks (directed producers): returns at the
    /// first Ack (mailbox-i60), so the count is ≥ 1 on success, not the fanout size.
    pub async fn publish(
        &self,
        entry: MailboxEntry,
        target_sig: Option<[u8; 64]>,
    ) -> anyhow::Result<usize> {
        Ok(self.publish_detailed(entry, target_sig, 1).await.acks.len())
    }

    /// Poll the box `target` from read-fanout (300) candidates.
    ///
    /// `proof` is `None` for our own master box (the postman checks the transport
    /// identity); a pointer box needs a fetch proof bound to our device, and then the
    /// postman serves only SelfPointer entries.
    ///
    /// Returns unique non-expired entries, deduped by msg_id (most-recent wins on dup).
    /// Avail observation: on successful FetchResponse, updates avail_ewma for the responding peer.
    pub async fn poll(
        &self,
        target: &MailboxAddress,
        proof: Option<[u8; 64]>,
        since_stored_at: Option<u64>,
    ) -> anyhow::Result<Vec<MailboxEntry>> {
        let now_secs = unix_now();
        let ranked = self.build_ranked_candidates(target);

        // Read-fanout: top-300 closest peers.
        let read_peers: Vec<DeviceId> = ranked
            .iter()
            .take(self.read_fanout)
            .map(|(d, _)| *d)
            .collect();

        let req = MailboxFetchRequest {
            v: MAILBOX_WIRE_VERSION,
            target: *target,
            since_stored_at,
            target_proof: proof,
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
        let mut by_msg_id: HashMap<[u8; 16], MailboxEntry> = HashMap::new();

        for handle in handles {
            match handle.await {
                Ok((device_id, Ok(resp))) => {
                    record_contact_off_runtime(&self.db, device_id, now_secs);
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
            target = %target,
            entry_count = entries.len(),
            peers_tried = read_peers.len(),
            "mailbox poll: collected entries"
        );

        Ok(entries)
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
        _target: &MailboxAddress,
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
        target: &MailboxAddress,
        now_secs: u64,
    ) -> Vec<DeviceId> {
        let candidate_peer_ids: Vec<PeerId> = ranked
            .iter()
            .take(self.candidates_n)
            .map(|(_, pid)| *pid)
            .collect();
        self.select_write_peers(&candidate_peer_ids, target, now_secs)
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
pub fn dedup_entries(entries: Vec<MailboxEntry>) -> Vec<MailboxEntry> {
    let mut by_msg_id: HashMap<[u8; 16], MailboxEntry> = HashMap::new();
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
