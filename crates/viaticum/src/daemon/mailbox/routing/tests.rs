// T-4 test scenarios (spec §2.5).
//
// Test strategy:
//   - Pure functions (select_write_peers ranking, merge_poll_answers): unit tests, no network.
//   - Integration scenarios (publish, poll, dr_walk): inject MockSender to stub network.
//     No real SwarmHandle needed — all I/O goes through the MailboxNetworkSender trait.
//
// Required spec scenarios:
//   publish_sends_to_write_fanout_peers
//   poll_returns_deduplicated_entries_from_read_fanout
//   dr_walk_prefers_fresher_pointer_in_later_batch (CS-DR-1: collect from every batch)
//
// Additional unit tests:
//   select_write_peers_orders_by_combined_trust_times_avail_ewma
//   merge_* / forged_record_with_honest_msg_id_does_not_hide_the_honest_one (mailbox-i69)

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use viaticum_core::constants::{
    AVAIL_EWMA_ALPHA, AVAIL_EWMA_INITIAL, INITIAL_TRUST_P, MAILBOX_WRITE_FANOUT,
};
use viaticum_core::db::testutil::test_db;
use viaticum_core::mailbox::{MailboxAddress, MailboxClass, MailboxEntry, MailboxRejectReason};
use viaticum_core::messages::{
    MailboxFetchRequest, MailboxFetchResponse, MailboxStoreRequest, MailboxStoreResponse,
};
use viaticum_core::system_state::{
    BlockRef, CatalogLineageId, CatalogSummary, SelfPointer, sign_self_pointer,
};
use viaticum_core::types::{
    DeviceId, IdentityPub, PeerRecord, SourceBlockId, Timestamp, ewma_contact_observed,
};

use super::{
    MailboxNetworkSender, MailboxRouter, PublishOutcome, PublishVerdict, merge_poll_answers,
};
use crate::daemon::network::swarm::device_id_to_peer_id;

// ─── Test helpers ─────────────────────────────────────────────────────────────

fn make_identity(seed: u8) -> IdentityPub {
    IdentityPub([seed; 32])
}

fn make_msg_id(seed: u8) -> [u8; 16] {
    [seed; 16]
}

fn make_entry(
    target: IdentityPub,
    msg_id: [u8; 16],
    stored_at: u64,
    class: MailboxClass,
) -> MailboxEntry {
    let ttl = class.default_ttl_secs();
    MailboxEntry {
        target: MailboxAddress::for_master(&target),
        msg_id,
        class,
        payload_version: 1,
        payload: vec![0u8; 32],
        expires_at: stored_at + ttl,
        stored_at,
        sender: None,
    }
}

fn make_peer_record(
    device_id: DeviceId,
    trust_p: f64,
    trust_i: f64,
    avail_ewma: f64,
) -> PeerRecord {
    let now = Timestamp::now();
    PeerRecord {
        device_id,
        master_identity: IdentityPub(device_id.0),
        trust_p,
        trust_i,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma,
        last_avail_sample: 0,
    }
}

// ─── MockSender ───────────────────────────────────────────────────────────────

/// Mock network sender for integration tests.
///
/// Records all store calls and returns configurable responses.
/// For fetch calls, returns a pre-loaded set of entries per peer.
#[allow(clippy::type_complexity)]
struct MockSender {
    /// store_calls: all (device_id, msg_id) pairs received.
    store_calls: Arc<Mutex<Vec<(DeviceId, [u8; 16])>>>,
    /// fetch_calls: all device_ids that were fetched from.
    fetch_calls: Arc<Mutex<Vec<DeviceId>>>,
    /// Per-device fetch response: DeviceId → entries to return.
    fetch_responses: Arc<HashMap<DeviceId, Vec<MailboxEntry>>>,
    /// Whether store requests get Acked (true) or Rejected (false).
    store_acks: bool,
    /// Whether store requests should fail at network level.
    store_fails: bool,
}

impl MockSender {
    fn new() -> Self {
        MockSender {
            store_calls: Arc::new(Mutex::new(vec![])),
            fetch_calls: Arc::new(Mutex::new(vec![])),
            fetch_responses: Arc::new(HashMap::new()),
            store_acks: true,
            store_fails: false,
        }
    }

    fn with_fetch_responses(mut self, responses: HashMap<DeviceId, Vec<MailboxEntry>>) -> Self {
        self.fetch_responses = Arc::new(responses);
        self
    }

    fn store_calls(&self) -> Vec<(DeviceId, [u8; 16])> {
        self.store_calls.lock().unwrap().clone()
    }

    fn fetch_calls(&self) -> Vec<DeviceId> {
        self.fetch_calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl MailboxNetworkSender for MockSender {
    async fn send_store(
        &self,
        device: DeviceId,
        req: MailboxStoreRequest,
    ) -> anyhow::Result<MailboxStoreResponse> {
        if self.store_fails {
            return Err(anyhow::anyhow!("simulated network failure"));
        }
        self.store_calls
            .lock()
            .unwrap()
            .push((device, req.entry.msg_id));
        if self.store_acks {
            Ok(MailboxStoreResponse::Ack {
                msg_id: req.entry.msg_id,
            })
        } else {
            Ok(MailboxStoreResponse::Reject {
                msg_id: req.entry.msg_id,
                reason: MailboxRejectReason::NotInCandidateSet,
            })
        }
    }

    async fn send_fetch(
        &self,
        device: DeviceId,
        _req: MailboxFetchRequest,
    ) -> anyhow::Result<MailboxFetchResponse> {
        self.fetch_calls.lock().unwrap().push(device);
        let entries = self
            .fetch_responses
            .get(&device)
            .cloned()
            .unwrap_or_default();
        let served_msg_ids: Vec<[u8; 16]> = entries.iter().map(|e| e.msg_id).collect();
        Ok(MailboxFetchResponse {
            v: 1,
            entries,
            served_msg_ids,
        })
    }
}

// ─── Helper: build router with n peers in DB ─────────────────────────────────

/// Generate a real Ed25519 DeviceId that can be round-tripped through device_id_to_peer_id.
/// Uses libp2p Keypair::generate_ed25519 which produces a valid Ed25519 pubkey.
fn gen_device_id() -> DeviceId {
    use libp2p::identity::Keypair;
    let kp = Keypair::generate_ed25519();
    let ed = kp.try_into_ed25519().unwrap();
    DeviceId(ed.public().to_bytes())
}

/// Build a MailboxRouter with a mock sender and N real-key peers in the DB.
/// Each peer gets: trust_p = INITIAL_TRUST_P, avail_ewma = AVAIL_EWMA_INITIAL.
///
/// Uses real Ed25519 keys so device_id_to_peer_id succeeds for all peers.
///
/// Returns (router, peer_device_ids).
fn build_router_with_peers(n: usize, sender: Arc<MockSender>) -> (MailboxRouter, Vec<DeviceId>) {
    let db = test_db();
    let mut device_ids = Vec::with_capacity(n);
    for _ in 0..n {
        let device_id = gen_device_id();
        let record = make_peer_record(device_id, INITIAL_TRUST_P, 0.0, AVAIL_EWMA_INITIAL);
        db.upsert_peer(&record).unwrap();
        device_ids.push(device_id);
    }
    let router = MailboxRouter::with_sender(sender, db);
    (router, device_ids)
}

// ============================================================
// Pure unit tests
// ============================================================

/// `make_entry` sets `expires_at` from `stored_at` + the class TTL; every entry below is
/// live at this moment.
const MERGE_NOW: u64 = 1;

fn with_payload(mut e: MailboxEntry, payload: &[u8]) -> MailboxEntry {
    e.payload = payload.to_vec();
    e
}

#[test]
fn merge_keeps_highest_stored_at_of_identical_bytes() {
    let target = make_identity(1);
    let msg_id = make_msg_id(1);
    let older = make_entry(target, msg_id, 1000, MailboxClass::PosChallenge);
    let newer = make_entry(target, msg_id, 2000, MailboxClass::PosChallenge);
    assert_eq!(older.payload, newer.payload);

    let merged = merge_poll_answers(vec![vec![older], vec![newer]], MERGE_NOW);
    assert_eq!(
        merged.len(),
        1,
        "same bytes from two postmen are one record"
    );
    assert_eq!(merged[0].stored_at, 2000);
}

#[test]
fn merge_single_entry_unchanged() {
    let entry = make_entry(
        make_identity(2),
        make_msg_id(2),
        1000,
        MailboxClass::PosChallenge,
    );
    let merged = merge_poll_answers(vec![vec![entry.clone()]], MERGE_NOW);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].msg_id, entry.msg_id);
}

#[test]
fn merge_of_no_answers_is_empty() {
    assert!(merge_poll_answers(vec![], MERGE_NOW).is_empty());
    assert!(merge_poll_answers(vec![vec![], vec![]], MERGE_NOW).is_empty());
}

#[test]
fn merge_keeps_all_distinct_msg_ids() {
    let target = make_identity(3);
    let entries: Vec<_> = (0..5u8)
        .map(|i| {
            make_entry(
                target,
                make_msg_id(i),
                1000 + i as u64,
                MailboxClass::PosChallenge,
            )
        })
        .collect();
    assert_eq!(merge_poll_answers(vec![entries], MERGE_NOW).len(), 5);
}

/// mailbox-i69: a postman's forgery under the honest msg_id, stored later, does not
/// replace the honest record from another postman — both reach the handlers.
#[test]
fn forged_record_with_honest_msg_id_does_not_hide_the_honest_one() {
    let target = make_identity(4);
    let msg_id = make_msg_id(4);
    let honest = with_payload(
        make_entry(target, msg_id, 1000, MailboxClass::PosResponse),
        b"honest signed response",
    );
    let forged = with_payload(
        make_entry(target, msg_id, 9000, MailboxClass::PosResponse),
        b"forged response",
    );

    let merged = merge_poll_answers(vec![vec![honest.clone()], vec![forged.clone()]], MERGE_NOW);
    assert_eq!(merged.len(), 2, "both variants go to the handlers");
    assert!(merged.iter().any(|e| e.payload == honest.payload));
    assert!(merged.iter().any(|e| e.payload == forged.payload));
}

/// mailbox-i69 (review B1): a postman stores per (msg_id, class), so a forgery of
/// another class under the honest msg_id, with a later stored_at, sits in the SAME
/// honest postman's answer — it must not displace the honest record there.
#[test]
fn forgery_of_another_class_in_the_same_answer_does_not_hide_the_honest_one() {
    let target = make_identity(5);
    let msg_id = make_msg_id(5);
    let honest = with_payload(
        make_entry(target, msg_id, 1000, MailboxClass::PosResponse),
        b"honest signed response",
    );
    let forged = with_payload(
        make_entry(target, msg_id, 9000, MailboxClass::Generic),
        b"junk",
    );

    let merged = merge_poll_answers(vec![vec![honest.clone(), forged]], MERGE_NOW);
    assert!(
        merged
            .iter()
            .any(|e| e.class == MailboxClass::PosResponse && e.payload == honest.payload),
        "the honest PosResponse must reach the handlers"
    );
}

/// Every distinct variant a postman returns reaches the handlers; nothing is decided
/// by the postman's own ordering.
#[test]
fn every_distinct_variant_in_one_answer_is_kept() {
    let target = make_identity(8);
    let msg_id = make_msg_id(8);
    let answer: Vec<_> = (0..10u8)
        .map(|i| {
            with_payload(
                make_entry(target, msg_id, 1000 + i as u64, MailboxClass::PosResponse),
                &[i; 8],
            )
        })
        .collect();
    assert_eq!(merge_poll_answers(vec![answer], MERGE_NOW).len(), 10);
}

#[test]
fn same_msg_id_in_another_class_is_another_record() {
    let target = make_identity(6);
    let msg_id = make_msg_id(6);
    let a = with_payload(
        make_entry(target, msg_id, 1000, MailboxClass::PosChallenge),
        b"x",
    );
    let b = with_payload(
        make_entry(target, msg_id, 1000, MailboxClass::DropNotice),
        b"x",
    );
    assert_eq!(
        merge_poll_answers(vec![vec![a], vec![b]], MERGE_NOW).len(),
        2
    );
}

#[test]
fn merge_drops_expired_records() {
    let mut e = make_entry(
        make_identity(7),
        make_msg_id(7),
        1000,
        MailboxClass::PosChallenge,
    );
    e.expires_at = 500;
    assert!(merge_poll_answers(vec![vec![e]], 500).is_empty());
}

#[test]
fn select_write_peers_orders_by_combined_trust_times_avail_ewma() {
    // Build a DB with 3 peers having different trust × avail_ewma scores.
    // Peer A: high trust, low avail → medium score
    // Peer B: low trust, high avail → low score
    // Peer C: high trust, high avail → highest score
    //
    // Expected write-fanout order: C, A, B (with write_fanout = 3).
    use viaticum_core::constants::{KI, KP, S_CLAMP_MAX, S_CLAMP_MIN};

    let db = test_db();

    // Use real device keys so device_id_to_peer_id works.
    let keys = [
        viaticum_core::cluster::derive_device_key(&[0x10u8; 64], &[0x01u8; 32]).unwrap(),
        viaticum_core::cluster::derive_device_key(&[0x20u8; 64], &[0x02u8; 32]).unwrap(),
        viaticum_core::cluster::derive_device_key(&[0x30u8; 64], &[0x03u8; 32]).unwrap(),
    ];

    struct PeerConfig {
        trust_p: f64,
        trust_i: f64,
        avail_ewma: f64,
    }
    // Chosen so scores are unambiguous: C > A > B.
    // score = (KP*p + KI*i) * clamp(s, S_MIN, S_MAX) * avail
    // With KP=0.4, KI=1.75, S_CLAMP_MAX=1.0 (s_raw=1.0 clamped to 1.0):
    //   A: (0.4*0.8 + 1.75*0.5) * 0.7 = (0.32 + 0.875) * 0.7 ≈ 0.837
    //   B: (0.4*0.1 + 1.75*0.1) * 0.3 = (0.04 + 0.175) * 0.3 ≈ 0.064
    //   C: (0.4*0.9 + 1.75*0.9) * 0.9 = (0.36 + 1.575) * 0.9 ≈ 1.742
    let configs = [
        PeerConfig {
            trust_p: 0.8,
            trust_i: 0.5,
            avail_ewma: 0.7,
        }, // A: medium score
        PeerConfig {
            trust_p: 0.1,
            trust_i: 0.1,
            avail_ewma: 0.3,
        }, // B: lowest score
        PeerConfig {
            trust_p: 0.9,
            trust_i: 0.9,
            avail_ewma: 0.9,
        }, // C: highest score
    ];

    let mut device_ids = Vec::new();
    let mut peer_ids = Vec::new();

    for (key, cfg) in keys.iter().zip(configs.iter()) {
        let device_id = DeviceId(key.verifying_key().to_bytes());
        let peer_id = device_id_to_peer_id(&device_id).unwrap();
        let mut record = make_peer_record(device_id, cfg.trust_p, cfg.trust_i, cfg.avail_ewma);
        record.trust_s = 1.0; // trust_s = 1.0 → clamped at S_CLAMP_MAX ≥ 1.0? Let's check.
        // Actually S_CLAMP_MAX ≥ 1.0, so clamp(1.0, min, max) = 1.0 or S_CLAMP_MAX.
        // compute_combined uses clamp(s_raw, S_CLAMP_MIN, S_CLAMP_MAX).
        db.upsert_peer(&record).unwrap();
        device_ids.push(device_id);
        peer_ids.push(peer_id);
    }

    let sender = Arc::new(MockSender::new());
    let router = MailboxRouter::with_sender(sender, db);

    // Compute expected scores.
    let score = |p: f64, i: f64, avail: f64| {
        // compute_combined(p, i, s_raw=1.0) * avail
        // S = clamp(1.0, S_CLAMP_MIN, S_CLAMP_MAX)
        // For S_CLAMP_MAX >= 1.0 and S_CLAMP_MIN <= 1.0: S = 1.0.
        let combined = (KP * p + KI * i) * 1.0_f64.clamp(S_CLAMP_MIN, S_CLAMP_MAX);
        combined * avail
    };

    let score_a = score(0.8, 0.5, 0.7);
    let score_b = score(0.1, 0.1, 0.3);
    let score_c = score(0.9, 0.9, 0.9);

    // Highest score must be C > A > B (all reasonable values).
    assert!(
        score_c > score_a && score_a > score_b,
        "expected C > A > B: {score_c} > {score_a} > {score_b}"
    );

    // Use all 3 as candidates; write_fanout = 3 so all 3 should be returned.
    let target = make_identity(99);
    let now = 0u64;
    let selected = router.select_write_peers(&peer_ids, &MailboxAddress::for_master(&target), now);

    // Must select all 3 (or at least C first).
    assert!(!selected.is_empty(), "must select at least one peer");

    // Verify C's device_id is first (highest score).
    let device_c = device_ids[2]; // C is index 2
    assert_eq!(
        selected[0], device_c,
        "peer C (highest combined_trust × avail_ewma) must be ranked first"
    );
}

// ============================================================
// Integration tests (mock swarm)
// ============================================================

#[tokio::test]
async fn publish_sends_to_write_fanout_peers() {
    // Spec scenario: publish() sends MailboxStoreRequest to exactly write_fanout peers.
    //
    // We set up MAILBOX_WRITE_FANOUT + 10 peers in DB. All peers have identical
    // trust/avail. Publish must send to exactly MAILBOX_WRITE_FANOUT of them.
    let n_peers = MAILBOX_WRITE_FANOUT + 10;
    let sender = Arc::new(MockSender::new());
    let (router, _device_ids) = build_router_with_peers(n_peers, Arc::clone(&sender));

    let target = make_identity(42);
    let entry = make_entry(
        target,
        make_msg_id(1),
        1_000_000,
        MailboxClass::PosChallenge,
    );

    let ack_count = router.publish(entry, None).await.unwrap();

    // All sent peers acked (mock always acks).
    let calls = sender.store_calls();
    let unique_peers: std::collections::HashSet<DeviceId> = calls.iter().map(|(d, _)| *d).collect();

    assert_eq!(
        unique_peers.len(),
        MAILBOX_WRITE_FANOUT,
        "publish must send to exactly MAILBOX_WRITE_FANOUT distinct peers (got {})",
        unique_peers.len()
    );
    assert_eq!(
        ack_count, MAILBOX_WRITE_FANOUT,
        "all write-fanout peers must ack (mock always acks)"
    );
}

#[tokio::test]
async fn poll_returns_deduplicated_entries_from_read_fanout() {
    // Spec scenario: poll() returns unique entries even when multiple peers return
    // the same msg_id. Dedup by msg_id, keep highest stored_at.
    //
    // Setup: 2 peers each return the same entry (same msg_id, same stored_at).
    // Plus peer 1 returns an extra unique entry.
    // Expected: 2 unique entries total.

    let my_master = make_identity(99);

    // Use real keys so device_id_to_peer_id works.
    let key1 = viaticum_core::cluster::derive_device_key(&[0x11u8; 64], &[0x01u8; 32]).unwrap();
    let key2 = viaticum_core::cluster::derive_device_key(&[0x22u8; 64], &[0x02u8; 32]).unwrap();

    let device1 = DeviceId(key1.verifying_key().to_bytes());
    let device2 = DeviceId(key2.verifying_key().to_bytes());

    // Use current time so expires_at is in the future (not filtered by poll's now_secs).
    let now_ts = Timestamp::now().0;
    let shared_entry = make_entry(
        my_master,
        make_msg_id(10),
        now_ts,
        MailboxClass::PosChallenge,
    );
    let unique_entry = make_entry(
        my_master,
        make_msg_id(11),
        now_ts + 1,
        MailboxClass::PosChallenge,
    );

    // Peer 1 returns both entries; peer 2 returns only the shared one.
    let mut responses: HashMap<DeviceId, Vec<MailboxEntry>> = HashMap::new();
    responses.insert(device1, vec![shared_entry.clone(), unique_entry.clone()]);
    responses.insert(device2, vec![shared_entry.clone()]);

    let db = test_db();
    let record1 = make_peer_record(device1, INITIAL_TRUST_P, 0.0, AVAIL_EWMA_INITIAL);
    let record2 = make_peer_record(device2, INITIAL_TRUST_P, 0.0, AVAIL_EWMA_INITIAL);
    db.upsert_peer(&record1).unwrap();
    db.upsert_peer(&record2).unwrap();

    let sender = Arc::new(MockSender::new().with_fetch_responses(responses));
    let router = MailboxRouter::with_sender(sender, db);

    let entries = router
        .poll(&MailboxAddress::for_master(&my_master), None, None)
        .await
        .unwrap();

    assert_eq!(
        entries.len(),
        2,
        "poll must dedup by msg_id — expected 2 unique entries, got {}",
        entries.len()
    );

    let msg_ids: std::collections::HashSet<[u8; 16]> = entries.iter().map(|e| e.msg_id).collect();
    assert!(
        msg_ids.contains(&shared_entry.msg_id),
        "shared entry must be present"
    );
    assert!(
        msg_ids.contains(&unique_entry.msg_id),
        "unique entry must be present"
    );
}

#[tokio::test]
async fn publish_returns_zero_acks_when_all_fail() {
    // If all peers fail at network level, publish returns 0 acks and warns (no panic).
    let mut sender = MockSender::new();
    sender.store_fails = true;
    let n_peers = 5;
    let sender = Arc::new(sender);
    let (router, _) = build_router_with_peers(n_peers, Arc::clone(&sender));

    let target = make_identity(7);
    let entry = make_entry(
        target,
        make_msg_id(5),
        1_000_000,
        MailboxClass::PosChallenge,
    );

    let ack_count = router.publish(entry, None).await.unwrap();
    assert_eq!(ack_count, 0, "all-fail scenario must return 0 acks");
}

#[tokio::test]
async fn poll_records_avail_on_successful_fetch() {
    // After a successful poll response, avail_ewma must increase for the responding peer.

    let my_master = make_identity(55);
    let key = viaticum_core::cluster::derive_device_key(&[0x55u8; 64], &[0x01u8; 32]).unwrap();
    let device_id = DeviceId(key.verifying_key().to_bytes());

    let db = test_db();
    let initial_avail = 0.5_f64;
    let record = make_peer_record(device_id, INITIAL_TRUST_P, 0.0, initial_avail);
    db.upsert_peer(&record).unwrap();

    // Peer returns one entry (stored_at = now so expires_at is in the future).
    let now_ts = Timestamp::now().0;
    let entry = make_entry(
        my_master,
        make_msg_id(99),
        now_ts,
        MailboxClass::PosChallenge,
    );
    let mut responses: HashMap<DeviceId, Vec<MailboxEntry>> = HashMap::new();
    responses.insert(device_id, vec![entry]);

    let sender = Arc::new(MockSender::new().with_fetch_responses(responses));
    let router = MailboxRouter::with_sender(sender, db.clone());

    let _entries = router
        .poll(&MailboxAddress::for_master(&my_master), None, None)
        .await
        .unwrap();

    // Check avail_ewma was updated.
    let updated = db.get_peer(&device_id).unwrap().unwrap();
    let expected = ewma_contact_observed(initial_avail, AVAIL_EWMA_ALPHA);
    assert!(
        (updated.avail_ewma - expected).abs() < 1e-12,
        "avail_ewma must be updated to {expected} after successful fetch, got {}",
        updated.avail_ewma
    );
}

// ─── FIX-3: poll filters expired entries ──────────────────────────────────────

#[tokio::test]
async fn poll_filters_expired_entries_from_response() {
    // poll() must drop entries where expires_at <= now_secs, even when the postman
    // returns them (defensive against clock skew).
    //
    // Setup: one peer returns two entries — one expired (expires_at in the past),
    // one non-expired (expires_at far in the future). Assert only the non-expired
    // entry comes back.

    let my_master = make_identity(66);
    let key = viaticum_core::cluster::derive_device_key(&[0x66u8; 64], &[0x01u8; 32]).unwrap();
    let device_id = DeviceId(key.verifying_key().to_bytes());

    let db = test_db();
    let record = make_peer_record(device_id, INITIAL_TRUST_P, 0.0, AVAIL_EWMA_INITIAL);
    db.upsert_peer(&record).unwrap();

    let now_ts = Timestamp::now().0;

    // Expired: expires_at is 1 second in the past.
    let mut expired = make_entry(
        my_master,
        make_msg_id(20),
        now_ts - 1000,
        MailboxClass::PosChallenge,
    );
    expired.expires_at = now_ts - 1; // force expired

    // Non-expired: expires_at far in the future.
    let mut live = make_entry(
        my_master,
        make_msg_id(21),
        now_ts,
        MailboxClass::PosChallenge,
    );
    live.expires_at = now_ts + 9999;

    let mut responses: HashMap<DeviceId, Vec<MailboxEntry>> = HashMap::new();
    responses.insert(device_id, vec![expired.clone(), live.clone()]);

    let sender = Arc::new(MockSender::new().with_fetch_responses(responses));
    let router = MailboxRouter::with_sender(sender, db);

    let entries = router
        .poll(&MailboxAddress::for_master(&my_master), None, None)
        .await
        .unwrap();

    assert_eq!(
        entries.len(),
        1,
        "poll must filter expired entries — expected 1 live entry, got {}",
        entries.len()
    );
    assert_eq!(
        entries[0].msg_id, live.msg_id,
        "the surviving entry must be the non-expired one"
    );
}

// ─── FIX-4: publish records avail on ack ──────────────────────────────────────

#[tokio::test]
async fn publish_records_avail_on_ack() {
    // A peer that Acks a MailboxStoreRequest must have its avail_ewma raised and
    // last_avail_sample updated in the DB. Symmetric to poll_records_avail_on_successful_fetch.

    let target = make_identity(77);
    let key = viaticum_core::cluster::derive_device_key(&[0x77u8; 64], &[0x01u8; 32]).unwrap();
    let device_id = DeviceId(key.verifying_key().to_bytes());

    let db = test_db();
    let initial_avail = 0.3_f64;
    let record = make_peer_record(device_id, INITIAL_TRUST_P, 0.0, initial_avail);
    db.upsert_peer(&record).unwrap();

    // MockSender acks by default (store_acks = true).
    let sender = Arc::new(MockSender::new());
    let router = MailboxRouter::with_sender(sender, db.clone());

    let now_ts = Timestamp::now().0;
    let entry = make_entry(target, make_msg_id(50), now_ts, MailboxClass::PosChallenge);

    let ack_count = router.publish(entry, None).await.unwrap();
    assert_eq!(ack_count, 1, "the single peer must ack");

    // Check avail_ewma was raised.
    let updated = db.get_peer(&device_id).unwrap().unwrap();
    let expected = ewma_contact_observed(initial_avail, AVAIL_EWMA_ALPHA);
    assert!(
        (updated.avail_ewma - expected).abs() < 1e-12,
        "avail_ewma must be updated to {expected} after Ack, got {}",
        updated.avail_ewma
    );
    // last_avail_sample must be non-zero (set to now_secs at publish time).
    assert!(
        updated.last_avail_sample > 0,
        "last_avail_sample must be set after Ack, got {}",
        updated.last_avail_sample
    );
}

/// CROWN-1 V.17.1: a postman's answer is a contact — its `last_seen` moves to now, so
/// a holder on a long-lived connection (no re-authentication) keeps counting for the
/// strength of an SS base.
#[tokio::test]
async fn contact_on_ack_refreshes_last_seen() {
    let key = viaticum_core::cluster::derive_device_key(&[0x78u8; 64], &[0x01u8; 32]).unwrap();
    let device_id = DeviceId(key.verifying_key().to_bytes());
    let db = test_db();
    let mut record = make_peer_record(device_id, INITIAL_TRUST_P, 0.0, 0.3);
    record.last_seen = Timestamp(1_000);
    db.upsert_peer(&record).unwrap();
    let router = MailboxRouter::with_sender(Arc::new(MockSender::new()), db.clone());
    let before = Timestamp::now().0;
    let entry = make_entry(
        make_identity(78),
        make_msg_id(51),
        before,
        MailboxClass::PosChallenge,
    );
    assert_eq!(router.publish(entry, None).await.unwrap(), 1);
    assert!(db.get_peer(&device_id).unwrap().unwrap().last_seen.0 >= before);
}

/// dr-i50 / pos-i8: a postman's answer to our poll's fetch is a contact too — its
/// `last_seen` moves to now inside `MailboxRouter::poll`, before the entries are
/// returned, whatever the poll loop then does with them (the PoS memory of pos-i5
/// skips most of them).
#[tokio::test]
async fn poll_fetch_contact_refreshes_last_seen() {
    let key = viaticum_core::cluster::derive_device_key(&[0x79u8; 64], &[0x01u8; 32]).unwrap();
    let device_id = DeviceId(key.verifying_key().to_bytes());
    let db = test_db();
    let mut record = make_peer_record(device_id, INITIAL_TRUST_P, 0.0, 0.3);
    record.last_seen = Timestamp(1_000);
    db.upsert_peer(&record).unwrap();

    let my_master = make_identity(79);
    let before = Timestamp::now().0;
    let entry = make_entry(
        my_master,
        make_msg_id(52),
        before,
        MailboxClass::PosChallenge,
    );
    let mut responses: HashMap<DeviceId, Vec<MailboxEntry>> = HashMap::new();
    responses.insert(device_id, vec![entry]);
    let sender = Arc::new(MockSender::new().with_fetch_responses(responses));
    let router = MailboxRouter::with_sender(sender, db.clone());

    let entries = router
        .poll(&MailboxAddress::for_master(&my_master), None, None)
        .await
        .unwrap();

    assert_eq!(entries.len(), 1);
    assert!(
        db.get_peer(&device_id).unwrap().unwrap().last_seen.0 >= before,
        "a fetch answer must refresh the postman's last_seen"
    );
}

// ─── CS-DR-1: DR collects every pointer from every batch ─────────────────────
//
// CROWN-1 C3a: the pointers live sealed in the seed-derived rendezvous box; the walk
// opens them with the phrase's keys and never looks at the local clock.

use viaticum_core::mailbox::seal::{
    PointerPlace, RendezvousKeys, SEALED_PAYLOAD_VERSION, seal_self_pointer,
};

/// The keys of one test phrase: the master signing key and the rendezvous keys, both
/// from the same seed (as in production).
fn phrase_keys(tag: u8) -> (ed25519_dalek::SigningKey, IdentityPub, RendezvousKeys) {
    let seed = [tag; 64];
    let master = viaticum_core::cluster::derive_master_key(&seed).unwrap();
    let me = viaticum_core::cluster::master_identity(&master);
    (master, me, RendezvousKeys::derive(&seed))
}

/// `n` real-key peers in a fresh DB, returned in the XOR order `dr_collect_pointers`
/// uses for `target` (closest first) — replicates `build_ranked_candidates`.
fn ranked_peers(
    db: &viaticum_core::db::Db,
    n: usize,
    tag: u8,
    target: &MailboxAddress,
) -> Vec<DeviceId> {
    use crate::daemon::mailbox::candidate::KademliaRoutingView;
    let target_key = KademliaRoutingView::target_key(target);
    let mut ranked: Vec<([u8; 32], DeviceId)> = (0..n)
        .map(|i| {
            let key = viaticum_core::cluster::derive_device_key(
                &{
                    let mut k = [0u8; 64];
                    k[0] = (i & 0xff) as u8;
                    k[1] = ((i >> 8) & 0xff) as u8;
                    k[2] = tag;
                    k
                },
                &[tag; 32],
            )
            .unwrap();
            let device_id = DeviceId(key.verifying_key().to_bytes());
            db.upsert_peer(&make_peer_record(
                device_id,
                INITIAL_TRUST_P,
                0.0,
                AVAIL_EWMA_INITIAL,
            ))
            .unwrap();
            let peer_key =
                KademliaRoutingView::peer_key(&device_id_to_peer_id(&device_id).unwrap());
            (
                KademliaRoutingView::xor_distance(&target_key, &peer_key),
                device_id,
            )
        })
        .collect();
    ranked.sort_by_key(|(d, _)| *d);
    ranked.into_iter().map(|(_, d)| d).collect()
}

fn signed_pointer(
    master: &ed25519_dalek::SigningKey,
    lineage: u8,
    files: u32,
    generation: u32,
    created_at: u64,
) -> SelfPointer {
    sign_self_pointer(
        master,
        generation,
        BlockRef {
            block_id: SourceBlockId([generation as u8; 32]),
            encrypted_size: 128,
            holders: vec![],
        },
        vec![],
        Timestamp(created_at),
        CatalogSummary {
            lineage: CatalogLineageId([lineage; 16]),
            publisher: DeviceId([0xD0; 32]),
            files,
        },
    )
}

/// `p` sealed into place `place` of its history in the rendezvous box.
fn sealed_entry(rv: &RendezvousKeys, p: &SelfPointer, place: PointerPlace) -> MailboxEntry {
    seal_self_pointer(
        rv,
        &p.catalog.lineage.0,
        place,
        &viaticum_core::types::to_cbor_bytes(p),
        u64::MAX,
        p.created_at.0,
    )
    .unwrap()
    .entry()
    .clone()
}

fn pointers_of(walk: &super::DrWalk) -> Vec<SelfPointer> {
    walk.pointers.iter().map(|(_, p)| p.clone()).collect()
}

/// The first batch (100 closest) holds an older pointer, a peer of the second batch
/// holds a fresher one of the same history. The collection returns both, so the
/// choice gets the fresh one.
#[tokio::test]
async fn dr_walk_prefers_fresher_pointer_in_later_batch() {
    use viaticum_core::constants::MAILBOX_DR_WALK_BATCHES;
    use viaticum_core::system_state::catalog::select_catalog;

    let (master, me, rv) = phrase_keys(0xA1);
    let db = test_db();
    let ranked = ranked_peers(&db, 150, 0xA1, &rv.address);
    let first = MAILBOX_DR_WALK_BATCHES[0];

    let stale = signed_pointer(&master, 7, 3, 1, 1_000);
    let fresh = signed_pointer(&master, 7, 4, 2, 2_000);
    let mut responses: HashMap<DeviceId, Vec<MailboxEntry>> = HashMap::new();
    responses.insert(ranked[0], vec![sealed_entry(&rv, &stale, PointerPlace::A)]);
    responses.insert(
        ranked[first + 10],
        vec![sealed_entry(&rv, &fresh, PointerPlace::A)],
    );

    let sender = Arc::new(MockSender::new().with_fetch_responses(responses));
    let router = MailboxRouter::with_sender(sender.clone(), db);
    let walk = router
        .dr_collect_pointers(&rv, &me, &gen_device_id())
        .await
        .unwrap();

    assert_eq!(walk.pointers.len(), 2, "both batches are collected");
    let choice = select_catalog(pointers_of(&walk), None).unwrap();
    assert_eq!(
        choice.selected.generation, 2,
        "the fresher pointer of batch 2 wins"
    );
    assert_eq!(choice.selected.catalog.files, 4);
}

#[tokio::test]
async fn dr_collect_queries_each_candidate_once() {
    let (_master, me, rv) = phrase_keys(0xA2);
    let db = test_db();
    let ranked = ranked_peers(&db, 150, 0xA2, &rv.address);

    let sender = Arc::new(MockSender::new());
    let router = MailboxRouter::with_sender(sender.clone(), db);
    let walk = router
        .dr_collect_pointers(&rv, &me, &gen_device_id())
        .await
        .unwrap();

    let calls = sender.fetch_calls();
    let unique: std::collections::HashSet<DeviceId> = calls.iter().copied().collect();
    assert_eq!(
        calls.len(),
        150,
        "every peer asked exactly once (no re-asking batch 1)"
    );
    assert_eq!(unique.len(), 150);
    assert_eq!(unique, ranked.iter().copied().collect());
    assert_eq!(walk.candidates, 150);
    assert_eq!(walk.responders, 150);
}

#[tokio::test]
async fn dr_collect_returns_pointers_of_all_lineages() {
    let (master, me, rv) = phrase_keys(0xA3);
    let db = test_db();
    let ranked = ranked_peers(&db, 20, 0xA3, &rv.address);
    let owner = signed_pointer(&master, 1, 3, 5, 1_000);
    let shadow = signed_pointer(&master, 2, 0, 1, 9_000);
    let mut responses: HashMap<DeviceId, Vec<MailboxEntry>> = HashMap::new();
    // The same owner pointer at two postmen (dedup), the shadow's at a third.
    let owner_entry = sealed_entry(&rv, &owner, PointerPlace::A);
    responses.insert(ranked[0], vec![owner_entry.clone()]);
    responses.insert(ranked[1], vec![owner_entry]);
    responses.insert(ranked[2], vec![sealed_entry(&rv, &shadow, PointerPlace::A)]);

    let sender = Arc::new(MockSender::new().with_fetch_responses(responses));
    let router = MailboxRouter::with_sender(sender, db);
    let walk = router
        .dr_collect_pointers(&rv, &me, &gen_device_id())
        .await
        .unwrap();

    assert_eq!(
        walk.pointers.len(),
        2,
        "distinct pointers, deduplicated by signature"
    );
    let lineages: std::collections::HashSet<CatalogLineageId> = walk
        .pointers
        .iter()
        .map(|(_, p)| p.catalog.lineage)
        .collect();
    assert_eq!(lineages.len(), 2, "both histories are returned");
}

/// A pointer signed by another master, sealed with THIS phrase's box keys, opens but
/// does not verify: it is not returned.
#[tokio::test]
async fn dr_collect_ignores_pointers_of_another_identity() {
    let (_master, me, rv) = phrase_keys(0xA4);
    let (stranger, _, _) = phrase_keys(0xA5);
    let db = test_db();
    let ranked = ranked_peers(&db, 5, 0xA4, &rv.address);
    let forged = signed_pointer(&stranger, 1, 99, 1, 9_000);
    let mut responses: HashMap<DeviceId, Vec<MailboxEntry>> = HashMap::new();
    responses.insert(ranked[0], vec![sealed_entry(&rv, &forged, PointerPlace::A)]);
    let sender = Arc::new(MockSender::new().with_fetch_responses(responses));
    let router = MailboxRouter::with_sender(sender, db);
    let walk = router
        .dr_collect_pointers(&rv, &me, &gen_device_id())
        .await
        .unwrap();
    assert!(walk.pointers.is_empty());
    assert_eq!(walk.responders, 5);
}

#[tokio::test]
async fn dr_collect_distinguishes_no_candidates_from_no_pointer() {
    let (_master, me, rv) = phrase_keys(0xA6);

    let empty = MailboxRouter::with_sender(Arc::new(MockSender::new()), test_db());
    let walk = empty
        .dr_collect_pointers(&rv, &me, &gen_device_id())
        .await
        .unwrap();
    assert_eq!((walk.candidates, walk.responders), (0, 0));
    assert!(walk.pointers.is_empty());

    let db = test_db();
    ranked_peers(&db, 3, 0xA6, &rv.address);
    let quiet = MailboxRouter::with_sender(Arc::new(MockSender::new()), db);
    let walk = quiet
        .dr_collect_pointers(&rv, &me, &gen_device_id())
        .await
        .unwrap();
    assert_eq!((walk.candidates, walk.responders), (3, 3));
    assert!(walk.pointers.is_empty());
}

/// Batch 1 (100 closest) holds nothing; the only pointer is at a peer of batch 2.
#[tokio::test]
async fn dr_walk_expands_to_next_batch_when_first_misses() {
    use viaticum_core::constants::MAILBOX_DR_WALK_BATCHES;
    let (master, me, rv) = phrase_keys(0xCD);
    let db = test_db();
    let ranked = ranked_peers(&db, 200, 0xF5, &rv.address);
    let first = MAILBOX_DR_WALK_BATCHES[0];
    let p = signed_pointer(&master, 3, 1, 2, 5_000);
    let entry = sealed_entry(&rv, &p, PointerPlace::A);
    let mut responses: HashMap<DeviceId, Vec<MailboxEntry>> = HashMap::new();
    for d in &ranked[first..] {
        responses.insert(*d, vec![entry.clone()]);
    }
    let sender = Arc::new(MockSender::new().with_fetch_responses(responses));
    let router = MailboxRouter::with_sender(sender.clone(), db);
    let walk = router
        .dr_collect_pointers(&rv, &me, &gen_device_id())
        .await
        .unwrap();
    assert_eq!(walk.pointers.len(), 1);
    assert_eq!(walk.pointers[0].1.generation, 2);
    assert!(
        sender.fetch_calls().len() > first,
        "the walk went past batch 1"
    );
}

/// V.15.2 (mailbox-i39, V.13 п.5): DR does not look at its own clock. A postman serves
/// an entry with `expires_at = 1`, `stored_at = 1` (1970): the walk still opens it and
/// returns the pointer.
#[tokio::test]
async fn dr_collect_keeps_entries_regardless_of_local_clock() {
    let (master, me, rv) = phrase_keys(0xB1);
    let db = test_db();
    let ranked = ranked_peers(&db, 2, 0xB1, &rv.address);
    let p = signed_pointer(&master, 4, 2, 1, 1);
    let old = seal_self_pointer(
        &rv,
        &p.catalog.lineage.0,
        PointerPlace::A,
        &viaticum_core::types::to_cbor_bytes(&p),
        1,
        1,
    )
    .unwrap()
    .entry()
    .clone();
    let mut responses: HashMap<DeviceId, Vec<MailboxEntry>> = HashMap::new();
    responses.insert(ranked[0], vec![old]);
    let router = MailboxRouter::with_sender(
        Arc::new(MockSender::new().with_fetch_responses(responses)),
        db,
    );
    let walk = router
        .dr_collect_pointers(&rv, &me, &gen_device_id())
        .await
        .unwrap();
    assert_eq!(
        walk.pointers.len(),
        1,
        "an expired-by-our-clock entry is kept"
    );
    assert_eq!(walk.pointers[0].1.signature, p.signature);
}

/// V.6 DR row / dr-i47: two versions of ONE place from lagging postmen (same slot, other
/// contents) are both returned, each with its slot — they become fallbacks.
#[tokio::test]
async fn dr_collect_keeps_distinct_versions_of_one_slot() {
    let (master, me, rv) = phrase_keys(0xB2);
    let db = test_db();
    let ranked = ranked_peers(&db, 3, 0xB2, &rv.address);
    let v1 = signed_pointer(&master, 6, 1, 1, 1_000);
    let v2 = signed_pointer(&master, 6, 2, 1, 2_000);
    let mut responses: HashMap<DeviceId, Vec<MailboxEntry>> = HashMap::new();
    responses.insert(ranked[0], vec![sealed_entry(&rv, &v1, PointerPlace::A)]);
    responses.insert(ranked[1], vec![sealed_entry(&rv, &v2, PointerPlace::A)]);
    let router = MailboxRouter::with_sender(
        Arc::new(MockSender::new().with_fetch_responses(responses)),
        db,
    );
    let walk = router
        .dr_collect_pointers(&rv, &me, &gen_device_id())
        .await
        .unwrap();
    assert_eq!(walk.pointers.len(), 2);
    let slot_a = rv.pointer_slot(&[6; 16], PointerPlace::A);
    assert!(walk.pointers.iter().all(|(slot, _)| *slot == slot_a));
}

/// V.6 DR row: junk in the box (a v2 SelfPointer that does not open, a plaintext
/// pointer, a directed class) is skipped with `mailbox: open failed`; the walk goes on
/// and returns the real pointer from the same answer.
#[tokio::test]
async fn dr_collect_logs_open_failed_for_junk_pointer_and_continues() {
    let (master, me, rv) = phrase_keys(0xB3);
    let db = test_db();
    let ranked = ranked_peers(&db, 1, 0xB3, &rv.address);
    let real = signed_pointer(&master, 8, 5, 3, 3_000);
    let junk = MailboxEntry {
        target: rv.address,
        msg_id: [0xEE; 16],
        class: MailboxClass::SelfPointer,
        payload_version: SEALED_PAYLOAD_VERSION,
        payload: vec![0x5A; 200],
        expires_at: u64::MAX,
        stored_at: 9_999,
        sender: None,
    };
    let plaintext = MailboxEntry {
        payload_version: 1,
        payload: viaticum_core::types::to_cbor_bytes(&real),
        msg_id: [0xEF; 16],
        ..junk.clone()
    };
    let mut responses: HashMap<DeviceId, Vec<MailboxEntry>> = HashMap::new();
    responses.insert(
        ranked[0],
        vec![junk, plaintext, sealed_entry(&rv, &real, PointerPlace::B)],
    );
    let router = MailboxRouter::with_sender(
        Arc::new(MockSender::new().with_fetch_responses(responses)),
        db,
    );
    let walk = router
        .dr_collect_pointers(&rv, &me, &gen_device_id())
        .await
        .unwrap();
    assert_eq!(walk.pointers.len(), 1);
    assert_eq!(walk.pointers[0].1.signature, real.signature);
    assert_eq!(
        walk.pointers[0].0,
        rv.pointer_slot(&[8; 16], PointerPlace::B)
    );
}

/// AC-5′(а): a pointer published years ago and not yet expired is found (no lower
/// time bound anywhere on the DR path).
#[tokio::test]
async fn dr_collect_finds_pointer_published_years_ago() {
    let (master, me, rv) = phrase_keys(0xB4);
    let db = test_db();
    let ranked = ranked_peers(&db, 1, 0xB4, &rv.address);
    let four_years_ago = Timestamp::now().0 - 4 * 365 * 24 * 3600;
    let p = signed_pointer(&master, 9, 1, 1, four_years_ago);
    let mut responses: HashMap<DeviceId, Vec<MailboxEntry>> = HashMap::new();
    responses.insert(ranked[0], vec![sealed_entry(&rv, &p, PointerPlace::A)]);
    let router = MailboxRouter::with_sender(
        Arc::new(MockSender::new().with_fetch_responses(responses)),
        db,
    );
    let walk = router
        .dr_collect_pointers(&rv, &me, &gen_device_id())
        .await
        .unwrap();
    assert_eq!(walk.pointers.len(), 1);
}

// ─── Publish verdicts (V.3, V.15.3; mailbox-i42, i49) ────────────────────────

fn outcome(acks: usize, rejects: &[MailboxRejectReason], errors: usize) -> PublishOutcome {
    PublishOutcome {
        acks: (0..acks).map(|i| DeviceId([i as u8; 32])).collect(),
        rejects: rejects
            .iter()
            .enumerate()
            .map(|(i, r)| (DeviceId([0x80 + i as u8; 32]), r.clone()))
            .collect(),
        errors,
        pending: 0,
    }
}

#[test]
fn publish_verdict_all_clock_skew() {
    use MailboxRejectReason::ClockSkew;
    assert_eq!(
        outcome(0, &[ClockSkew, ClockSkew], 3).verdict(),
        PublishVerdict::AllClockSkew,
        "network errors do not break 'all refused'"
    );
}

#[test]
fn publish_verdict_all_superseded() {
    use MailboxRejectReason::Superseded;
    assert_eq!(
        outcome(0, &[Superseded, Superseded, Superseded], 0).verdict(),
        PublishVerdict::AllSuperseded,
        "Superseded is never counted as an acceptance"
    );
}

#[test]
fn publish_verdict_all_slots_full() {
    use MailboxRejectReason::QuotaExceeded;
    assert_eq!(
        outcome(0, &[QuotaExceeded, QuotaExceeded], 0).verdict(),
        PublishVerdict::AllSlotsFull
    );
}

#[test]
fn publish_verdict_mixed_refusal() {
    use MailboxRejectReason::{ClockSkew, NotInCandidateSet, QuotaExceeded, Superseded};
    assert_eq!(
        outcome(
            0,
            &[
                ClockSkew,
                Superseded,
                Superseded,
                QuotaExceeded,
                NotInCandidateSet
            ],
            1
        )
        .verdict(),
        PublishVerdict::MixedRefusal {
            clock: 1,
            superseded: 2,
            slots_full: 1,
            other: 1
        }
    );
}

#[test]
fn publish_verdict_one_reject_among_acks_is_stored() {
    assert_eq!(
        outcome(2, &[MailboxRejectReason::Superseded], 0).verdict(),
        PublishVerdict::Stored { acks: 2 }
    );
    assert_eq!(outcome(0, &[], 4).verdict(), PublishVerdict::NoAck);
}

// ============================================================
// CROWN-1: router ↔ REAL postman handlers (InProcessPostmanNet)
// ============================================================
//
// These go through `handle_mailbox_store` / `handle_mailbox_fetch` on real redb, so
// the router's wire (entry.target as the only address, target_sig, target_proof) is
// checked against the actual postman rules rather than a mock that acks anything.

use crate::daemon::mailbox::test_postman::InProcessPostmanNet;
use viaticum_core::mailbox::sign_store;

/// A router whose DB knows `n` postmen, all reachable through one in-process net.
fn router_over_postmen(
    n: usize,
    requester_master: IdentityPub,
    requester_device: DeviceId,
) -> (MailboxRouter, Arc<InProcessPostmanNet>, Vec<DeviceId>) {
    let db = test_db();
    let devices: Vec<DeviceId> = (0..n).map(|_| gen_device_id()).collect();
    for d in &devices {
        db.upsert_peer(&make_peer_record(
            *d,
            INITIAL_TRUST_P,
            0.0,
            AVAIL_EWMA_INITIAL,
        ))
        .unwrap();
    }
    let net = Arc::new(InProcessPostmanNet::new(
        &devices,
        requester_master,
        requester_device,
    ));
    let router = MailboxRouter::with_sender(Arc::clone(&net) as Arc<dyn MailboxNetworkSender>, db);
    (router, net, devices)
}

/// A sealed pointer of history 0xC2, place A, stored now.
fn sealed_now(master_key: &ed25519_dalek::SigningKey, rv: &RendezvousKeys) -> MailboxEntry {
    let now = Timestamp::now().0;
    let pointer = signed_pointer(master_key, 0xC2, 1, 7, now);
    seal_self_pointer(
        rv,
        &pointer.catalog.lineage.0,
        PointerPlace::A,
        &viaticum_core::types::to_cbor_bytes(&pointer),
        now + 3600,
        now,
    )
    .unwrap()
    .entry()
    .clone()
}

/// C3a layout end to end: the sealed pointer sits in the rendezvous box, signed by the
/// box key; every real postman stores it and the DR walk (proof bound to the DR
/// device) opens it.
#[tokio::test]
async fn signed_self_pointer_is_stored_by_real_postmen_and_found_by_dr_walk() {
    let (master_key, master, rv) = phrase_keys(0x21);
    let dr_device = gen_device_id();
    let (router, net, devices) = router_over_postmen(4, master, dr_device);

    let entry = sealed_now(&master_key, &rv);
    let sig = rv.sign_store(&entry);
    let acks = router.publish(entry.clone(), Some(sig)).await.unwrap();
    assert_eq!(acks, devices.len(), "every postman acks the signed pointer");
    for d in &devices {
        let held = net
            .postman(d)
            .db
            .mailbox_list_for_target(&entry.target, 0)
            .unwrap();
        assert_eq!(held.len(), 1, "postman {d} stores the pointer");
    }

    let walk = router
        .dr_collect_pointers(&rv, &master, &dr_device)
        .await
        .unwrap();
    let generations: Vec<u32> = walk.pointers.iter().map(|(_, p)| p.generation).collect();
    assert_eq!(generations, vec![7]);
}

/// AC-7 end to end: the same pointer without `target_sig` is refused by every real
/// postman — publish sees 0 acks and nothing is stored anywhere. A plaintext pointer
/// is refused even with a valid signature (§7.5 п.1).
#[tokio::test]
async fn unsigned_self_pointer_publish_is_refused_by_real_postmen() {
    let (master_key, master, rv) = phrase_keys(0x22);
    let (router, net, devices) = router_over_postmen(3, master, gen_device_id());

    let entry = sealed_now(&master_key, &rv);
    assert_eq!(router.publish(entry.clone(), None).await.unwrap(), 0);
    // A signature by another key is refused as well.
    let other = viaticum_core::cluster::derive_master_key(&[0x23u8; 64]).unwrap();
    let forged = sign_store(&other, &entry);
    assert_eq!(
        router.publish(entry.clone(), Some(forged)).await.unwrap(),
        0
    );
    let mut plain = entry.clone();
    plain.payload_version = 1;
    let out = router
        .publish_detailed(plain.clone(), Some(rv.sign_store(&plain)), 1)
        .await;
    assert!(out.acks.is_empty());
    assert!(
        out.rejects
            .iter()
            .all(|(_, r)| *r == MailboxRejectReason::PlaintextPayload)
    );
    for d in &devices {
        assert!(
            net.postman(d)
                .db
                .mailbox_list_for_target(&entry.target, 0)
                .unwrap()
                .is_empty()
        );
    }
}

/// AC-9 / AC-20 end to end on a rendezvous box: a proof-gated poll returns only
/// the pointers, never the directed junk planted at the same address; without a
/// proof (and not being the master of that address) the poll returns nothing.
#[tokio::test]
async fn rendezvous_poll_through_real_postmen_needs_proof_and_returns_only_pointers() {
    let requester_device = gen_device_id();
    let (router, _net, _devices) =
        router_over_postmen(3, IdentityPub([0x31; 32]), requester_device);
    let (master_key, _me, rv) = phrase_keys(0x24);

    let now = Timestamp::now().0;
    let pointer = sealed_now(&master_key, &rv);
    let sig = rv.sign_store(&pointer);
    assert_eq!(router.publish(pointer, Some(sig)).await.unwrap(), 3);
    for i in 0..5u8 {
        let junk = MailboxEntry {
            target: rv.address,
            msg_id: [0x40 + i; 16],
            class: MailboxClass::DropNotice,
            payload_version: 1,
            payload: vec![0xEE; 64],
            expires_at: now + 3600,
            stored_at: now,
            sender: None,
        };
        assert_eq!(
            router.publish(junk, None).await.unwrap(),
            3,
            "junk is accepted (directed)"
        );
    }

    let without = router.poll(&rv.address, None, None).await.unwrap();
    assert!(
        without.is_empty(),
        "no proof, not the master of the box: nothing"
    );

    let proof = rv.fetch_proof(&requester_device);
    let with = router.poll(&rv.address, Some(proof), None).await.unwrap();
    assert_eq!(
        with.len(),
        1,
        "exactly the one pointer (deduped across 3 postmen)"
    );
    assert_eq!(with[0].class, MailboxClass::SelfPointer);
}
