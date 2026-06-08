// T-3 test scenarios (spec §2.4)
//
// All 7 required scenarios:
//   handle_mailbox_store_accepts_valid_entry
//   handle_mailbox_store_rejects_when_not_in_candidate_set
//   handle_mailbox_store_rejects_oversized_entry
//   handle_mailbox_fetch_returns_entries_for_correct_target
//   handle_mailbox_fetch_rejects_wrong_target
//   handle_mailbox_fetch_returns_only_non_expired_entries
//   handle_mailbox_fetch_incremental_since_stored_at

use libp2p::PeerId;
use viaticum_core::db::testutil::test_db;
use viaticum_core::mailbox::{MailboxClass, MailboxEngine, MailboxEntry, MailboxRejectReason};
use viaticum_core::messages::{MailboxFetchRequest, MailboxStoreRequest, MailboxStoreResponse};
use viaticum_core::types::IdentityPub;

use crate::daemon::mailbox::candidate::KademliaRoutingView;

use super::{handle_mailbox_fetch, handle_mailbox_store};

// ============================================================
// Helpers
// ============================================================

fn make_target(seed: u8) -> IdentityPub {
    IdentityPub([seed; 32])
}

fn make_msg_id(seed: u8) -> [u8; 16] {
    [seed; 16]
}

fn make_entry(
    target: IdentityPub,
    msg_id: [u8; 16],
    payload_size: usize,
    stored_at: u64,
    ttl_secs: u64,
) -> MailboxEntry {
    MailboxEntry {
        target,
        msg_id,
        class: MailboxClass::PosChallenge,
        payload_version: 1,
        payload: vec![0u8; payload_size],
        expires_at: stored_at + ttl_secs,
        stored_at,
        sender: None,
    }
}

fn make_store_request(entry: MailboxEntry) -> MailboxStoreRequest {
    MailboxStoreRequest {
        v: 1,
        target: entry.target,
        entry,
    }
}

fn make_fetch_request(target: IdentityPub, since: Option<u64>) -> MailboxFetchRequest {
    MailboxFetchRequest {
        v: 1,
        target,
        since_stored_at: since,
    }
}

/// Build a routing view where `my_peer_id` is the only known peer,
/// guaranteeing `should_store` returns true (cold-start / sole peer).
fn routing_view_accepts(my_peer_id: PeerId) -> KademliaRoutingView {
    // Single known peer = self. should_store returns true: no peers closer than self.
    KademliaRoutingView::new(vec![my_peer_id])
}

/// Build a routing view with 1001+ peers all closer to `target` than `my_peer_id`.
///
/// Since `should_store` uses `MAILBOX_CANDIDATES_N=1000`, having 1001 closer peers
/// guarantees rejection. Uses random Keypair generation to find peers whose SHA256-
/// based key produces a smaller XOR distance to the target hash than `my_peer_id`.
fn routing_view_rejects(target: &IdentityPub, my_peer_id: &PeerId) -> KademliaRoutingView {
    use sha2::{Digest, Sha256};
    // Compute my distance to target.
    let target_key: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(target.0);
        h.finalize().into()
    };
    let my_key: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(my_peer_id.to_bytes());
        h.finalize().into()
    };
    let my_dist: [u8; 32] = {
        let mut d = [0u8; 32];
        for i in 0..32 {
            d[i] = target_key[i] ^ my_key[i];
        }
        d
    };

    // Generate 1001 PeerIds whose XOR distance to target is strictly less than my_dist.
    use libp2p::identity::Keypair;
    let mut closer_peers = Vec::new();
    let mut attempts = 0u64;
    while closer_peers.len() < 1001 {
        let kp = Keypair::generate_ed25519();
        let pid = kp.public().to_peer_id();
        let pk: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(pid.to_bytes());
            h.finalize().into()
        };
        let dist: [u8; 32] = {
            let mut d = [0u8; 32];
            for i in 0..32 {
                d[i] = target_key[i] ^ pk[i];
            }
            d
        };
        if dist < my_dist {
            closer_peers.push(pid);
        }
        attempts += 1;
        if attempts > 200_000 {
            // Safety valve: extremely unlikely to reach this.
            break;
        }
    }

    // Include my_peer_id in the view too (should_store needs to know about self).
    closer_peers.push(*my_peer_id);
    KademliaRoutingView::new(closer_peers)
}

// ============================================================
// T-3 test scenarios
// ============================================================

#[test]
fn handle_mailbox_store_accepts_valid_entry() {
    let db = test_db();
    let target = make_target(1);
    let now = 1_000_000u64;
    let entry = make_entry(target, make_msg_id(1), 100, now, 3600);
    let req = make_store_request(entry.clone());

    // Use a routing view where we are the only peer → should_store = true.
    let my_peer_id = PeerId::random();
    let view = routing_view_accepts(my_peer_id);

    let resp = handle_mailbox_store(&db, &view, &my_peer_id, req);
    assert!(
        matches!(resp, MailboxStoreResponse::Ack { msg_id } if msg_id == entry.msg_id),
        "valid entry should be accepted with Ack, got {:?}",
        resp
    );

    // Verify entry is actually stored.
    let engine = MailboxEngine::new(db);
    let fetched = engine.fetch(&target, now).unwrap();
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0].msg_id, entry.msg_id);
}

#[test]
fn handle_mailbox_store_rejects_when_not_in_candidate_set() {
    let db = test_db();
    let target = make_target(2);
    let now = 1_000_000u64;
    let entry = make_entry(target, make_msg_id(2), 100, now, 3600);
    let req = make_store_request(entry);

    let my_peer_id = PeerId::random();
    let view = routing_view_rejects(&target, &my_peer_id);

    let resp = handle_mailbox_store(&db, &view, &my_peer_id, req);
    assert!(
        matches!(
            resp,
            MailboxStoreResponse::Reject {
                reason: MailboxRejectReason::NotInCandidateSet,
                ..
            }
        ),
        "should reject when not in candidate set, got {:?}",
        resp
    );

    // Entry must NOT be stored.
    let engine = MailboxEngine::new(db);
    let fetched = engine.fetch(&target, now).unwrap();
    assert!(fetched.is_empty());
}

#[test]
fn handle_mailbox_store_rejects_oversized_entry() {
    use viaticum_core::mailbox::class_config::MAX_ENTRY_BYTES;

    let db = test_db();
    let target = make_target(3);
    let now = 1_000_000u64;
    // Payload slightly larger than the limit. The serialized size includes CBOR
    // overhead (~40-100 bytes), so MAX_ENTRY_BYTES payload will definitely exceed.
    let entry = make_entry(target, make_msg_id(3), MAX_ENTRY_BYTES + 1, now, 3600);
    let req = make_store_request(entry);

    let my_peer_id = PeerId::random();
    let view = routing_view_accepts(my_peer_id);

    let resp = handle_mailbox_store(&db, &view, &my_peer_id, req);
    assert!(
        matches!(
            resp,
            MailboxStoreResponse::Reject {
                reason: MailboxRejectReason::EntryTooLarge,
                ..
            }
        ),
        "oversized entry should be rejected with EntryTooLarge, got {:?}",
        resp
    );
}

#[test]
fn handle_mailbox_fetch_returns_entries_for_correct_target() {
    let db = test_db();
    let target = make_target(4);
    let now = 2_000_000u64;
    let engine = MailboxEngine::new(db.clone());

    let entry = make_entry(target, make_msg_id(4), 50, now, 3600);
    engine.store(&entry, now).unwrap();

    let req = make_fetch_request(target, None);
    let resp = handle_mailbox_fetch(&db, req, target, now);

    assert_eq!(
        resp.entries.len(),
        1,
        "should return 1 entry for correct target"
    );
    assert_eq!(resp.entries[0].msg_id, entry.msg_id);
    assert_eq!(resp.served_msg_ids.len(), 1);
    assert_eq!(resp.served_msg_ids[0], entry.msg_id);
}

#[test]
fn handle_mailbox_fetch_rejects_wrong_target() {
    let db = test_db();
    let target = make_target(5);
    let requester = make_target(6); // different from target
    let now = 2_000_000u64;
    let engine = MailboxEngine::new(db.clone());

    let entry = make_entry(target, make_msg_id(5), 50, now, 3600);
    engine.store(&entry, now).unwrap();

    // Requester claims to fetch for `target`, but their master identity is `requester`.
    let req = make_fetch_request(target, None);
    let resp = handle_mailbox_fetch(&db, req, requester, now);

    assert!(
        resp.entries.is_empty(),
        "should return empty when requester != target (no error leak)"
    );
    assert!(resp.served_msg_ids.is_empty());
}

#[test]
fn handle_mailbox_fetch_returns_only_non_expired_entries() {
    let db = test_db();
    let target = make_target(7);
    let now = 3_000_000u64;
    let engine = MailboxEngine::new(db.clone());

    // Entry that is still valid at now+1000.
    let live_entry = make_entry(target, make_msg_id(10), 50, now, 3600);
    // Entry that expires soon (at now + 100).
    let expiring_entry = make_entry(target, make_msg_id(11), 50, now, 100);

    engine.store(&live_entry, now).unwrap();
    engine.store(&expiring_entry, now).unwrap();

    // Fetch well after expiring_entry's TTL.
    let fetch_at = now + 200;
    let req = make_fetch_request(target, None);
    let resp = handle_mailbox_fetch(&db, req, target, fetch_at);

    // Only the live entry should be returned.
    assert_eq!(
        resp.entries.len(),
        1,
        "only non-expired entries should be returned"
    );
    assert_eq!(resp.entries[0].msg_id, live_entry.msg_id);
}

#[test]
fn handle_mailbox_fetch_incremental_since_stored_at() {
    let db = test_db();
    let target = make_target(8);
    let now = 4_000_000u64;
    let engine = MailboxEngine::new(db.clone());

    // Store entries at different timestamps.
    let old_entry = make_entry(target, make_msg_id(20), 50, now, 3600);
    let new_entry = make_entry(target, make_msg_id(21), 50, now + 100, 3600);

    engine.store(&old_entry, now).unwrap();
    engine.store(&new_entry, now + 100).unwrap();

    // Incremental fetch: only entries newer than `now` (stored_at > now).
    let req = make_fetch_request(target, Some(now));
    let resp = handle_mailbox_fetch(&db, req, target, now + 200);

    // Only new_entry (stored_at = now + 100 > now) should be returned.
    assert_eq!(
        resp.entries.len(),
        1,
        "incremental fetch should return only entries newer than since_stored_at"
    );
    assert_eq!(resp.entries[0].msg_id, new_entry.msg_id);
    assert_eq!(resp.served_msg_ids.len(), 1);
    assert_eq!(resp.served_msg_ids[0], new_entry.msg_id);
}
