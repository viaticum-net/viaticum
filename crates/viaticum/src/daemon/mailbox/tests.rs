use super::candidate::{KademliaRoutingView, should_store};
use libp2p::PeerId;
use sha2::{Digest, Sha256};
use viaticum_core::types::IdentityPub;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn random_identity_pub() -> IdentityPub {
    IdentityPub(rand::random())
}

/// Build N random peer IDs.
fn random_peers(n: usize) -> Vec<PeerId> {
    (0..n).map(|_| PeerId::random()).collect()
}

/// For a given target, sort a list of peers by XOR distance and return
/// the rank (0-based) of `needle` in that ordering.
fn rank_in_set(target: &IdentityPub, peers: &[PeerId], needle: &PeerId) -> usize {
    let target_key = KademliaRoutingView::target_key(target);
    let needle_key = KademliaRoutingView::peer_key(needle);
    let needle_dist = KademliaRoutingView::xor_distance(&target_key, &needle_key);

    peers
        .iter()
        .filter(|&p| {
            if p == needle {
                return false;
            }
            let pk = KademliaRoutingView::peer_key(p);
            let d = KademliaRoutingView::xor_distance(&target_key, &pk);
            d < needle_dist
        })
        .count()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn should_store_true_on_empty_routing_table() {
    let view = KademliaRoutingView::new(vec![]);
    let target = random_identity_pub();
    let my_peer_id = PeerId::random();
    assert!(should_store(&view, &target, &my_peer_id, 1000));
}

#[test]
fn should_store_true_when_in_top_n() {
    // Create a fixed target and 100 peers.
    let target = random_identity_pub();
    let mut peers: Vec<PeerId> = random_peers(100);
    // Insert our peer_id into the list and find its rank.
    let my_peer_id = PeerId::random();
    peers.push(my_peer_id);

    // Find the rank of my_peer_id (how many peers are strictly closer).
    let my_rank = rank_in_set(&target, &peers, &my_peer_id);

    // With 101 peers total (including us), use N = my_rank + 1 so we are exactly
    // at the boundary. We should store.
    let view = KademliaRoutingView::new(peers.clone());
    let n = my_rank + 1;
    assert!(
        should_store(&view, &target, &my_peer_id, n),
        "peer at rank {my_rank} should store when candidates_n={n}"
    );
}

#[test]
fn should_store_false_when_beyond_top_n() {
    let target = random_identity_pub();
    let mut peers: Vec<PeerId> = random_peers(100);
    let my_peer_id = PeerId::random();
    peers.push(my_peer_id);

    let my_rank = rank_in_set(&target, &peers, &my_peer_id);

    // Use N = my_rank (strictly less than our position) → should NOT store.
    if my_rank == 0 {
        // my_peer_id is already the closest peer — can't make it be outside top-N
        // in this set. Skip this specific case.
        return;
    }
    let view = KademliaRoutingView::new(peers.clone());
    let n = my_rank; // N is one less than needed to include us
    assert!(
        !should_store(&view, &target, &my_peer_id, n),
        "peer at rank {my_rank} should NOT store when candidates_n={n}"
    );
}

#[test]
fn should_store_true_when_only_known_peer() {
    // Routing table has only my_peer_id itself. Rank = 0 < any N.
    let target = random_identity_pub();
    let my_peer_id = PeerId::random();
    let view = KademliaRoutingView::new(vec![my_peer_id]);
    assert!(should_store(&view, &target, &my_peer_id, 1));
}

#[test]
fn should_store_respects_candidates_n_boundary() {
    // Build exactly N peers that are all closer than us to the target.
    // To achieve deterministic ordering, we compute distances manually.
    let target = random_identity_pub();
    let target_key = KademliaRoutingView::target_key(&target);

    let my_peer_id = PeerId::random();
    let my_key = KademliaRoutingView::peer_key(&my_peer_id);
    let my_dist = KademliaRoutingView::xor_distance(&target_key, &my_key);

    // Generate peers until we have exactly 5 that are strictly closer than us.
    let mut closer_peers: Vec<PeerId> = Vec::new();
    let mut attempts = 0usize;
    while closer_peers.len() < 5 && attempts < 100_000 {
        let p = PeerId::random();
        let pk = KademliaRoutingView::peer_key(&p);
        let d = KademliaRoutingView::xor_distance(&target_key, &pk);
        if d < my_dist {
            closer_peers.push(p);
        }
        attempts += 1;
    }
    // If we couldn't find 5 closer peers (very unlikely), skip.
    if closer_peers.len() < 5 {
        return;
    }

    // Build routing table: 5 closer peers + my_peer_id.
    let mut all_peers = closer_peers.clone();
    all_peers.push(my_peer_id);

    let view = KademliaRoutingView::new(all_peers);

    // N=5: exactly 5 peers closer → my rank=5 → NOT in top-5 → false
    assert!(
        !should_store(&view, &target, &my_peer_id, 5),
        "5 closer peers exist, should NOT store with N=5"
    );

    // N=6: 5 peers closer → my rank=5 → IN top-6 → true
    assert!(
        should_store(&view, &target, &my_peer_id, 6),
        "5 closer peers exist, should store with N=6"
    );
}

#[test]
fn target_key_is_sha256_of_identity_pub() {
    let target = IdentityPub([42u8; 32]);
    let got = KademliaRoutingView::target_key(&target);

    let mut hasher = Sha256::new();
    hasher.update([42u8; 32]);
    let expected: [u8; 32] = hasher.finalize().into();

    assert_eq!(got, expected);
}

#[test]
fn xor_distance_is_symmetric() {
    let a = [0u8; 32];
    let mut b = [0u8; 32];
    b[0] = 0xff;
    b[31] = 0x01;

    let d_ab = KademliaRoutingView::xor_distance(&a, &b);
    let d_ba = KademliaRoutingView::xor_distance(&b, &a);
    assert_eq!(d_ab, d_ba, "XOR distance must be symmetric");
}

#[test]
fn xor_distance_is_zero_for_equal_keys() {
    let key = [0x5a; 32];
    assert_eq!(KademliaRoutingView::xor_distance(&key, &key), [0u8; 32]);
}

#[test]
fn xor_distance_smaller_means_closer() {
    // Peer A differs in last byte only; peer B differs in first byte.
    // First-byte difference means much larger XOR distance.
    let target = [0u8; 32];
    let mut closer = [0u8; 32];
    closer[31] = 0x01; // only last byte differs → small distance
    let mut farther = [0u8; 32];
    farther[0] = 0x80; // MSB differs → large distance

    let d_closer = KademliaRoutingView::xor_distance(&target, &closer);
    let d_farther = KademliaRoutingView::xor_distance(&target, &farther);
    assert!(
        d_closer < d_farther,
        "closer peer should have smaller XOR distance"
    );
}

#[test]
fn should_store_large_network_top_1000_check() {
    // Simulate N=1000 with 2000 total peers. We pick our peer to be
    // in the top-1000 by construction.
    let target = random_identity_pub();
    let target_key = KademliaRoutingView::target_key(&target);

    let my_peer_id = PeerId::random();
    let my_key = KademliaRoutingView::peer_key(&my_peer_id);
    let my_dist = KademliaRoutingView::xor_distance(&target_key, &my_key);

    // Collect 2000 random peers.
    let other_peers: Vec<PeerId> = random_peers(2000);

    // Count how many are closer than us.
    let closer = other_peers
        .iter()
        .filter(|p| {
            let pk = KademliaRoutingView::peer_key(p);
            KademliaRoutingView::xor_distance(&target_key, &pk) < my_dist
        })
        .count();

    let mut all_peers = other_peers;
    all_peers.push(my_peer_id);
    let view = KademliaRoutingView::new(all_peers);

    // should_store with N = closer + 1 must return true (we are exactly at boundary).
    assert!(
        should_store(&view, &target, &my_peer_id, closer + 1),
        "should store when N = closer+1 (rank {closer})"
    );

    // should_store with N = closer must return false (we are one beyond boundary).
    if closer > 0 {
        assert!(
            !should_store(&view, &target, &my_peer_id, closer),
            "should NOT store when N = closer (rank {closer})"
        );
    }
}
