// Mailbox candidate-set check: should this node store entries for a given target?
//
// Design: each node stores mailbox entries only for targets whose hash falls
// within its Kademlia neighborhood. This bounds per-node storage and creates
// predictable redundancy (write-fanout 30, read-fanout 300 all hit the same
// candidate-set of MAILBOX_CANDIDATES_N=1000 nodes).
//
// See A2 spec §2.3 for full design.

use libp2p::PeerId;
use sha2::{Digest, Sha256};
use viaticum_core::types::IdentityPub;

// ============================================================
// KademliaRoutingView
// ============================================================

/// A lightweight snapshot of known Kademlia peers for distance checks.
///
/// Extracted as a testable type: no network I/O, built from a plain Vec<PeerId>.
/// Callers (T-4 MailboxRouter) build this from the live swarm peer list or DB.
pub struct KademliaRoutingView {
    /// All peer_ids currently known (routing table or authenticated peers).
    known_peers: Vec<PeerId>,
}

impl KademliaRoutingView {
    /// Construct from a snapshot of known peer IDs.
    pub fn new(known_peers: Vec<PeerId>) -> Self {
        KademliaRoutingView { known_peers }
    }

    /// Compute the Kademlia target key for a mailbox target identity.
    ///
    /// target_key = SHA256(target_pub.0)
    /// Stable across restarts. This is the point in the Kademlia key space where
    /// postmen are ranked. It is NOT what DR passes to `get_closest_peers`: libp2p-kad
    /// hashes the key it is given (`kbucket::Key::new` = SHA256 of the preimage), so DR
    /// passes the PREIMAGE `target_pub.0` (`dr::dr_lookup_key`, F12) and libp2p arrives
    /// at this same key. Passing this hash would walk to SHA256(SHA256(target_pub)).
    pub fn target_key(target_pub: &IdentityPub) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(target_pub.0);
        hasher.finalize().into()
    }

    /// Compute the Kademlia node key for a PeerId.
    ///
    /// node_key = SHA256(peer_id.to_bytes())
    /// Matches how libp2p Kademlia derives the node key from a PeerId.
    pub fn peer_key(peer_id: &PeerId) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(peer_id.to_bytes());
        hasher.finalize().into()
    }

    /// XOR distance between two 32-byte keys.
    ///
    /// Returns a 32-byte value; smaller = closer in XOR metric.
    pub fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = a[i] ^ b[i];
        }
        result
    }

    /// All known peers held by this view.
    pub fn known_peers(&self) -> &[PeerId] {
        &self.known_peers
    }
}

// ============================================================
// should_store
// ============================================================

/// Check whether this node should store mailbox entries for `target_pub`.
///
/// Uses the local Kademlia routing table snapshot to compute XOR distances and
/// determine whether `my_peer_id` falls within the top-N closest peers known.
///
/// Cold-start rule: if the routing table is empty (new node, no known peers),
/// returns `true` — conservative accept. Better to store extra entries than
/// to drop messages that may never reach their destination.
///
/// # Arguments
/// * `routing_table` — snapshot of known peers (from swarm / DB)
/// * `target_pub`    — mailbox target identity (owner's master public key)
/// * `my_peer_id`    — this node's libp2p PeerId
/// * `candidates_n`  — top-N threshold (typically `MAILBOX_CANDIDATES_N = 1000`)
pub fn should_store(
    routing_table: &KademliaRoutingView,
    target_pub: &IdentityPub,
    my_peer_id: &PeerId,
    candidates_n: usize,
) -> bool {
    let known = routing_table.known_peers();

    // Cold-start: empty routing table → accept conservatively.
    if known.is_empty() {
        return true;
    }

    let target_key = KademliaRoutingView::target_key(target_pub);
    let my_key = KademliaRoutingView::peer_key(my_peer_id);
    let my_dist = KademliaRoutingView::xor_distance(&target_key, &my_key);

    // Count how many known peers are strictly closer to target than we are.
    // If fewer than candidates_n peers are closer, we are in the top-N.
    let closer_count = known
        .iter()
        .filter(|&peer_id| {
            if peer_id == my_peer_id {
                return false; // don't count self
            }
            let peer_key = KademliaRoutingView::peer_key(peer_id);
            let peer_dist = KademliaRoutingView::xor_distance(&target_key, &peer_key);
            peer_dist < my_dist
        })
        .count();

    closer_count < candidates_n
}
