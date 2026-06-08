// T-4 test scenarios (spec §2.5).
//
// Test strategy:
//   - Pure functions (select_write_peers ranking, dedup_entries): unit tests, no network.
//   - Integration scenarios (publish, poll, dr_walk): inject MockSender to stub network.
//     No real SwarmHandle needed — all I/O goes through the MailboxNetworkSender trait.
//
// Required spec scenarios:
//   publish_sends_to_write_fanout_peers
//   poll_returns_deduplicated_entries_from_read_fanout
//   dr_walk_stops_at_first_batch_with_pointer
//
// Additional unit tests:
//   select_write_peers_orders_by_combined_trust_times_avail_ewma
//   dedup_entries_keeps_highest_stored_at
//   dedup_entries_single_entry_unchanged
//   dedup_entries_empty_is_empty

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use viaticum_core::constants::{
    AVAIL_EWMA_ALPHA, AVAIL_EWMA_INITIAL, INITIAL_TRUST_P, MAILBOX_WRITE_FANOUT,
};
use viaticum_core::db::testutil::test_db;
use viaticum_core::mailbox::{MailboxClass, MailboxEntry};
use viaticum_core::messages::{
    MailboxFetchRequest, MailboxFetchResponse, MailboxStoreRequest, MailboxStoreResponse,
};
use viaticum_core::system_state::{BlockRef, sign_self_pointer};
use viaticum_core::types::{
    DeviceId, IdentityPub, PeerRecord, SourceBlockId, Timestamp, ewma_contact_observed,
};

use super::{MailboxNetworkSender, MailboxRouter, dedup_entries};
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
        target,
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
                reason: viaticum_core::mailbox::MailboxRejectReason::NotInCandidateSet,
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

#[test]
fn dedup_entries_keeps_highest_stored_at() {
    let target = make_identity(1);
    let msg_id = make_msg_id(1);

    // Same msg_id, different stored_at.
    let older = {
        let mut e = make_entry(target, msg_id, 1000, MailboxClass::PosChallenge);
        e.stored_at = 1000;
        e
    };
    let newer = {
        let mut e = make_entry(target, msg_id, 2000, MailboxClass::PosChallenge);
        e.stored_at = 2000;
        e
    };

    let deduped = dedup_entries(vec![older, newer]);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].stored_at, 2000, "must keep highest stored_at");
}

#[test]
fn dedup_entries_single_entry_unchanged() {
    let target = make_identity(2);
    let entry = make_entry(target, make_msg_id(2), 1000, MailboxClass::PosChallenge);
    let deduped = dedup_entries(vec![entry.clone()]);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].msg_id, entry.msg_id);
}

#[test]
fn dedup_entries_empty_is_empty() {
    let deduped = dedup_entries(vec![]);
    assert!(deduped.is_empty());
}

#[test]
fn dedup_entries_distinct_msg_ids_all_kept() {
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
    let deduped = dedup_entries(entries);
    assert_eq!(deduped.len(), 5, "all distinct msg_ids must be kept");
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
    let selected = router.select_write_peers(&peer_ids, &target, now);

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

    let ack_count = router.publish(&target, entry).await.unwrap();

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

    let entries = router.poll(&my_master, None).await.unwrap();

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
async fn dr_walk_stops_at_first_batch_with_pointer() {
    // Spec scenario: dr_walk_for_pointer stops at the first batch [100, 300, 1000]
    // that returns a valid SelfPointer entry.
    //
    // Setup: first batch (100 peers) returns no pointer;
    //        second batch (300 peers, including first batch) returns a valid pointer
    //        from peer at index 150 (not in first batch).
    // Expected: dr_walk returns a pointer and does NOT fetch from the third batch (1000).
    //
    // We verify by checking that fetch_calls contains peers from the second batch
    // but not from a third-batch-only peer (index 500+).

    // Generate keys for 300 peers.
    let n_peers = 350usize; // more than second batch (300) but fewer than third (1000)
    let db = test_db();
    let mut device_ids = Vec::with_capacity(n_peers);

    for i in 0..n_peers {
        // Use varied seeds so XOR distances are different.
        let seed = (i & 0xff) as u8;
        let key = viaticum_core::cluster::derive_device_key(
            &{
                let mut k = [0u8; 64];
                k[0] = seed;
                k[1] = (i >> 8) as u8;
                k
            },
            &{
                let mut s = [0u8; 32];
                s[0] = seed;
                s[1] = 0xBB;
                s
            },
        )
        .unwrap();
        let device_id = DeviceId(key.verifying_key().to_bytes());
        let record = make_peer_record(device_id, INITIAL_TRUST_P, 0.0, AVAIL_EWMA_INITIAL);
        db.upsert_peer(&record).unwrap();
        device_ids.push(device_id);
    }

    // Build a real master key for signing the SelfPointer.
    let master_key = viaticum_core::cluster::derive_master_key(&[0xABu8; 64]).expect("master key");
    let my_master_pub = viaticum_core::cluster::master_identity(&master_key);

    // Build a valid SelfPointer payload for device at index 150 to return.
    let pointer = sign_self_pointer(
        &master_key,
        1,
        BlockRef {
            block_id: SourceBlockId([0xCC; 32]),
            encrypted_size: 256,
            holders: vec![],
        },
        vec![],
        Timestamp::now(),
    );
    let pointer_payload = viaticum_core::types::to_cbor_bytes(&pointer);

    // The pointer entry will be returned by "some peer in 101..300 range".
    // We inject it for device at index 120 (will be in 2nd batch but not 1st).
    // The key insight is that the XOR ordering determines which peers are in which batch.
    // Instead of manipulating XOR ordering, we inject the pointer for ALL 300 peers.
    // dr_walk sends to all peers in each batch (inclusive); stopping at first batch with
    // a result means: if batch 2 (300 peers) has the pointer, we don't fetch batch 3 (1000).
    // Since n_peers = 350, and batch sizes are [100, 300, 1000], the 3rd batch would
    // need 1000 peers but we only have 350 → dr_walk exhausts known peers at batch 2.
    //
    // Simplify: inject pointer for device at index 100 (present in 2nd batch, not 1st).
    // This requires knowing which device is XOR-ranked at position 100 for my_master_pub.
    // That's hard to control deterministically. Instead:
    //
    // Alternative: inject the pointer for ALL 350 peers. With batch 1 = 100 peers, all
    // 100 of them return the pointer. dr_walk should stop after batch 1 and return it.
    // This still tests "stops at first batch" — just at batch 1.
    //
    // But the spec says "stops at first batch WITH pointer". If all peers have it, the
    // first batch (100) yields a pointer and we stop there.

    let pointer_entry = MailboxEntry {
        target: my_master_pub,
        msg_id: make_msg_id(77),
        class: MailboxClass::SelfPointer,
        payload_version: 1,
        payload: pointer_payload,
        expires_at: u64::MAX,
        stored_at: 1_000_000,
        sender: None,
    };

    // Inject for all devices — first batch will find it and stop.
    let mut fetch_responses: HashMap<DeviceId, Vec<MailboxEntry>> = HashMap::new();
    for &device_id in &device_ids {
        fetch_responses.insert(device_id, vec![pointer_entry.clone()]);
    }

    let sender = Arc::new(MockSender::new().with_fetch_responses(fetch_responses));
    let sender_arc = Arc::clone(&sender);
    let router = MailboxRouter::with_sender(sender_arc, db);

    let result = router.dr_walk_for_pointer(&my_master_pub).await.unwrap();

    assert!(result.is_some(), "dr_walk must return a SelfPointer");
    let found = result.unwrap();
    assert_eq!(found.generation, 1, "must return the pointer we signed");

    // Verify that fetch_calls contains at most 100 unique devices (first batch stopped).
    let fetch_calls = sender.fetch_calls();
    let unique_fetched: std::collections::HashSet<DeviceId> = fetch_calls.iter().cloned().collect();
    assert!(
        unique_fetched.len() <= 100,
        "dr_walk must stop at first batch (≤100 unique peers fetched), got {}",
        unique_fetched.len()
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

    let ack_count = router.publish(&target, entry).await.unwrap();
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

    let _entries = router.poll(&my_master, None).await.unwrap();

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

    let entries = router.poll(&my_master, None).await.unwrap();

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

    let ack_count = router.publish(&target, entry).await.unwrap();
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

// ─── FIX-5: dr_walk batch expansion ───────────────────────────────────────────

#[tokio::test]
async fn dr_walk_expands_to_next_batch_when_first_misses() {
    // dr_walk_for_pointer must expand to the next batch when the first batch
    // returns no valid SelfPointer. Concretely: batch 1 (100 closest peers) returns
    // nothing; a peer that lands in batch 2 (101..300) holds the pointer.
    // The walk must find the pointer and return it.
    //
    // Implementation note: we cannot deterministically control which device ends up
    // at which XOR-rank. Instead we use a small peer set (200 peers) so the first
    // batch (100) necessarily covers only half of them. We inject the pointer for
    // ONLY the second half (by DB-insertion order, which is a proxy for varied keys).
    // Since XOR ordering is hash-based (unpredictable), we must be conservative:
    // inject the pointer for ALL 200 peers but make batch-1 peers return an EMPTY
    // response, and batch-2 peers return the pointer. We achieve this by using
    // separate device_ids for "batch-1 only" and "batch-2+" peers and routing the
    // MockSender accordingly — but that requires knowing the XOR order in advance.
    //
    // Simpler, still meaningful: build 200 peers, give the pointer to peers with
    // index >= 100. Since the XOR order is random, approximately half of batch 1
    // will have no pointer. But the test would be flaky. Instead:
    //
    // Correct approach — two distinct populations:
    //   - "no_pointer_peers": 100 peers whose MockSender response is always empty.
    //   - "pointer_peer": 1 peer whose MockSender response contains the pointer.
    // We insert all 101 into the DB, then force the pointer_peer to be ranked
    // beyond position 100 by giving it an XOR distance larger than all no_pointer_peers.
    // XOR distance is SHA256(target) XOR SHA256(peer_id) — impossible to force without
    // controlling the keys. We cannot reliably force a specific key to rank > 100.
    //
    // Practical alternative that still tests the expansion invariant without XOR control:
    // Use MAILBOX_DR_WALK_BATCHES = [100, 300, 1000]. Build 101 peers total. The first
    // batch asks 100 of them; if all 100 return empty, we must expand to 300. With 101
    // peers the second batch will include the 101st peer. We inject the pointer for
    // exactly ONE peer (whose position we do not control). With 101 peers in DB:
    //   - P(pointer_peer is in first 100) ≈ 100/101 ≈ 99% → test would pass batch-1
    //     99% of the time (wrong behavior, test would be vacuously green).
    //
    // The reliable approach: inject the pointer for ALL peers but set batch 1 to return
    // an *invalid* (bad signature) pointer, and batch 2 peers return the *valid* one.
    // That requires per-peer routing in MockSender.
    //
    // Extend MockSender in-test with two response maps: "invalid" (fails verify_self_pointer)
    // and "valid". Assign invalid pointer to devices in the first 100 by XOR rank; valid
    // to the rest. Since we don't know XOR rank statically, we do it the other way:
    // build the router, call build_ranked_candidates (not exposed), or — simplest —
    // just use a large enough population with valid pointer only in positions > 100 in
    // DB insertion order, accept that XOR shuffles them, and assert final result is Some.
    // This tests expansion (if batch 1 had the pointer, fine — expansion is not needed
    // and the test still passes, just tests a different code path). The thing we MUST
    // test is that the walk DOES NOT give up after batch 1 if batch 1 returns nothing.
    //
    // Final design: 200 peers, NO pointer for any of them. Confirm walk returns None.
    // Then add ONE more peer (index 201) with the pointer. Confirm walk returns Some.
    // This proves the walk can find a pointer at all (regression: walk not stopping early
    // when it shouldn't). The specific batch-expansion is implicitly tested because if
    // the walk only ever looked at batch 1 (100 peers) it would miss the peer at position
    // 101+ (by XOR rank, random) with probability ~50%.
    //
    // To make the expansion test definitive without XOR control: use ONLY 1 peer total
    // and give it the pointer but set candidates_n = 0 for batch 1 (impossible via API).
    //
    // ── FINAL PRAGMATIC APPROACH ──────────────────────────────────────────────────
    // Build exactly 101 peers. Inject the pointer for ALL 101 peers but use a custom
    // MockSender that returns the pointer only for the LAST-inserted DeviceId (which has
    // a random XOR rank). Repeat the assertion 1 time. If the walk returns Some, it
    // expanded past batch 1 (if last-inserted happens to be rank > 100) OR found it in
    // batch 1 (if rank <= 100). Either way the walk finds the pointer — that's the
    // regression we care about. The "expansion specifically" path is definitively
    // covered by `dr_walk_stops_at_first_batch_with_pointer` (all 350 peers return it,
    // so batch 1 always wins) combined with this test (only 1 peer returns it, and only
    // after the walk considers all batches does it succeed ~50% at batch 1, ~50% at
    // batch 2). Since we cannot deterministically force batch-2, we use 1 peer total
    // (smaller than batch 1 = 100) — that guarantees we test the "only 1 peer in DB"
    // path, but doesn't test expansion per se.
    //
    // ── ACTUALLY DETERMINISTIC APPROACH ──────────────────────────────────────────
    // The only way to test expansion definitively is to control XOR order. We CAN do
    // that by using a two-tier MockSender: all peers return an INVALID pointer (bad
    // payload), except one peer that returns a VALID one. Even if the valid peer is in
    // batch 1, the valid pointer will be found. Since all peers hold something
    // (invalid or valid), the walk doesn't "miss" batch 1 — but it correctly picks the
    // valid one. This tests sig-verification gating but not expansion.
    //
    // ── SIMPLEST TEST THAT ADDS REAL VALUE ───────────────────────────────────────
    // Test: 300 peers, NONE have a pointer in batch 1 (first 100 by XOR rank).
    // A peer in position 100..300 returns the pointer. Since XOR is random, we cannot
    // guarantee which 100 are "batch 1". Instead: set ALL 300 peers to return no
    // pointer EXCEPT peers with a specific DeviceId (the "pointer_peer"). We build
    // the router, drive a dr_walk, and check the result. We use 1 pointer_peer and
    // 299 no-pointer peers. The walk will:
    //   - If pointer_peer is in first 100 by XOR: find it in batch 1 (≤ 100/300 chance).
    //   - If pointer_peer is in 100..300: find it in batch 2 (≥ 200/300 chance).
    //   - Either way: walk returns Some → test passes.
    // This always passes when the walk is correct, and always fails when the walk
    // stops early (after batch 1 returning nothing for the non-pointer peers, it would
    // need to expand to batch 2 to find pointer_peer). But with prob ~1/3 the pointer
    // is in batch 1 so the test would not catch early-stop. Not reliable enough.
    //
    // ── DEFINITIVE APPROACH (what we actually implement) ─────────────────────────
    // Use the internal `build_ranked_candidates` ordering by building the router, calling
    // `build_ranked_candidates` (private — not exposed). Instead, replicate the XOR rank
    // computation in the test: compute XOR(SHA256(target), SHA256(peer_id)) for each
    // peer, sort ascending, take positions 100+ as "batch-2 only". Inject pointer for
    // those; inject empty for batch-1 peers. This deterministically ensures batch 1
    // returns nothing and batch 2 finds the pointer.

    use sha2::{Digest, Sha256};
    use viaticum_core::constants::MAILBOX_DR_WALK_BATCHES;

    // Build master key first — my_master_pub is the XOR target for dr_walk.
    let master_key = viaticum_core::cluster::derive_master_key(&[0xCDu8; 64]).expect("master key");
    let my_master_pub = viaticum_core::cluster::master_identity(&master_key);

    // Replicate KademliaRoutingView XOR distance computation (must match routing.rs).
    let xor_dist = |target: &IdentityPub, peer_id: &libp2p::PeerId| -> [u8; 32] {
        let target_hash: [u8; 32] = Sha256::digest(target.0).into();
        let pid_bytes = peer_id.to_bytes();
        let peer_hash: [u8; 32] = Sha256::digest(&pid_bytes).into();
        let mut dist = [0u8; 32];
        for i in 0..32 {
            dist[i] = target_hash[i] ^ peer_hash[i];
        }
        dist
    };

    // Generate enough peers to populate at least 2 batches.
    // batch sizes: [100, 300, 1000]. We need at least 101 peers so batch 2 adds new ones.
    let n_peers = 200usize;
    let db = test_db();
    let mut devices: Vec<(DeviceId, libp2p::PeerId)> = Vec::with_capacity(n_peers);

    for i in 0..n_peers {
        let key = viaticum_core::cluster::derive_device_key(
            &{
                let mut k = [0u8; 64];
                k[0] = (i & 0xff) as u8;
                k[1] = ((i >> 8) & 0xff) as u8;
                k[2] = 0xF5; // distinct from other tests
                k
            },
            &{
                let mut s = [0u8; 32];
                s[0] = (i & 0xff) as u8;
                s[1] = 0xE1;
                s
            },
        )
        .unwrap();
        let device_id = DeviceId(key.verifying_key().to_bytes());
        let peer_id = device_id_to_peer_id(&device_id).unwrap();
        let record = make_peer_record(device_id, INITIAL_TRUST_P, 0.0, AVAIL_EWMA_INITIAL);
        db.upsert_peer(&record).unwrap();
        devices.push((device_id, peer_id));
    }

    // Compute XOR order using my_master_pub as target — same target dr_walk_for_pointer uses.
    let mut ranked: Vec<(DeviceId, libp2p::PeerId, [u8; 32])> = devices
        .iter()
        .map(|(d, p)| (*d, *p, xor_dist(&my_master_pub, p)))
        .collect();
    ranked.sort_by_key(|(_, _, dist)| *dist);

    // First batch size (MAILBOX_DR_WALK_BATCHES[0]).
    let first_batch_size = MAILBOX_DR_WALK_BATCHES[0];

    let pointer = sign_self_pointer(
        &master_key,
        2,
        BlockRef {
            block_id: SourceBlockId([0xEE; 32]),
            encrypted_size: 128,
            holders: vec![],
        },
        vec![],
        Timestamp::now(),
    );
    let pointer_payload = viaticum_core::types::to_cbor_bytes(&pointer);

    let pointer_entry = MailboxEntry {
        target: my_master_pub,
        msg_id: make_msg_id(88),
        class: MailboxClass::SelfPointer,
        payload_version: 1,
        payload: pointer_payload,
        expires_at: u64::MAX,
        stored_at: 2_000_000,
        sender: None,
    };

    // Give the pointer ONLY to peers that are NOT in the first batch (positions >= first_batch_size).
    // Peers in positions 0..first_batch_size get empty responses.
    // This guarantees batch 1 returns nothing; the walk MUST expand to batch 2 to find the pointer.
    let mut fetch_responses: HashMap<DeviceId, Vec<MailboxEntry>> = HashMap::new();
    for (idx, (device_id, _peer_id, _dist)) in ranked.iter().enumerate() {
        if idx >= first_batch_size {
            fetch_responses.insert(*device_id, vec![pointer_entry.clone()]);
        } else {
            fetch_responses.insert(*device_id, vec![]);
        }
    }

    let sender = Arc::new(MockSender::new().with_fetch_responses(fetch_responses));
    let sender_arc = Arc::clone(&sender);
    let router = MailboxRouter::with_sender(sender_arc, db);

    let result = router.dr_walk_for_pointer(&my_master_pub).await.unwrap();

    assert!(
        result.is_some(),
        "dr_walk must find the pointer in batch 2 after batch 1 misses"
    );
    let found = result.unwrap();
    assert_eq!(found.generation, 2, "must return the pointer from batch 2");

    // Confirm batch 1 was contacted (the walk did start).
    let fetch_calls = sender.fetch_calls();
    let unique_fetched: std::collections::HashSet<DeviceId> = fetch_calls.iter().cloned().collect();
    assert!(
        unique_fetched.len() > first_batch_size,
        "dr_walk must have expanded beyond batch 1 ({} unique peers fetched, expected > {})",
        unique_fetched.len(),
        first_batch_size
    );
}
