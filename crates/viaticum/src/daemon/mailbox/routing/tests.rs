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
//   dr_walk_prefers_fresher_pointer_in_later_batch (CS-DR-1: collect from every batch)
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
use viaticum_core::system_state::{
    BlockRef, CatalogLineageId, CatalogSummary, SelfPointer, sign_self_pointer,
};
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

// ─── CS-DR-1: DR collects every pointer from every batch ─────────────────────

/// `n` real-key peers in a fresh DB, returned in the XOR order `dr_collect_pointers`
/// uses for `target` (closest first) — replicates `build_ranked_candidates`.
fn ranked_peers(
    db: &viaticum_core::db::Db,
    n: usize,
    tag: u8,
    target: &IdentityPub,
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

fn pointer_entry(target: IdentityPub, p: &SelfPointer, msg: u8) -> MailboxEntry {
    MailboxEntry {
        target,
        msg_id: make_msg_id(msg),
        class: MailboxClass::SelfPointer,
        payload_version: 1,
        payload: viaticum_core::types::to_cbor_bytes(p),
        expires_at: u64::MAX,
        stored_at: 1_000_000 + msg as u64,
        sender: None,
    }
}

/// The first batch (100 closest) holds an older pointer, a peer of the second batch
/// holds a fresher one of the same history. The old walk stopped at batch 1 and
/// returned the stale pointer; the collection must return both, so the choice gets
/// the fresh one.
#[tokio::test]
async fn dr_walk_prefers_fresher_pointer_in_later_batch() {
    use viaticum_core::constants::MAILBOX_DR_WALK_BATCHES;
    use viaticum_core::system_state::catalog::select_catalog;

    let master = viaticum_core::cluster::derive_master_key(&[0xA1u8; 64]).unwrap();
    let me = viaticum_core::cluster::master_identity(&master);
    let db = test_db();
    let ranked = ranked_peers(&db, 150, 0xA1, &me);
    let first = MAILBOX_DR_WALK_BATCHES[0];

    let stale = signed_pointer(&master, 7, 3, 1, 1_000);
    let fresh = signed_pointer(&master, 7, 4, 2, 2_000);
    let mut responses: HashMap<DeviceId, Vec<MailboxEntry>> = HashMap::new();
    responses.insert(ranked[0], vec![pointer_entry(me, &stale, 1)]);
    responses.insert(ranked[first + 10], vec![pointer_entry(me, &fresh, 2)]);

    let sender = Arc::new(MockSender::new().with_fetch_responses(responses));
    let router = MailboxRouter::with_sender(sender.clone(), db);
    let walk = router.dr_collect_pointers(&me).await.unwrap();

    assert_eq!(walk.pointers.len(), 2, "both batches are collected");
    let choice = select_catalog(walk.pointers, None).unwrap();
    assert_eq!(
        choice.selected.generation, 2,
        "the fresher pointer of batch 2 wins"
    );
    assert_eq!(choice.selected.catalog.files, 4);
}

#[tokio::test]
async fn dr_collect_queries_each_candidate_once() {
    let master = viaticum_core::cluster::derive_master_key(&[0xA2u8; 64]).unwrap();
    let me = viaticum_core::cluster::master_identity(&master);
    let db = test_db();
    let ranked = ranked_peers(&db, 150, 0xA2, &me);

    let sender = Arc::new(MockSender::new());
    let router = MailboxRouter::with_sender(sender.clone(), db);
    let walk = router.dr_collect_pointers(&me).await.unwrap();

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
    let master = viaticum_core::cluster::derive_master_key(&[0xA3u8; 64]).unwrap();
    let me = viaticum_core::cluster::master_identity(&master);
    let db = test_db();
    let ranked = ranked_peers(&db, 20, 0xA3, &me);
    let owner = signed_pointer(&master, 1, 3, 5, 1_000);
    let shadow = signed_pointer(&master, 2, 0, 1, 9_000);
    let mut responses: HashMap<DeviceId, Vec<MailboxEntry>> = HashMap::new();
    // The same owner pointer at two postmen (dedup), the shadow's at a third.
    responses.insert(ranked[0], vec![pointer_entry(me, &owner, 1)]);
    responses.insert(ranked[1], vec![pointer_entry(me, &owner, 1)]);
    responses.insert(ranked[2], vec![pointer_entry(me, &shadow, 2)]);

    let sender = Arc::new(MockSender::new().with_fetch_responses(responses));
    let router = MailboxRouter::with_sender(sender, db);
    let walk = router.dr_collect_pointers(&me).await.unwrap();

    assert_eq!(
        walk.pointers.len(),
        2,
        "distinct pointers, deduplicated by signature"
    );
    let lineages: std::collections::HashSet<CatalogLineageId> =
        walk.pointers.iter().map(|p| p.catalog.lineage).collect();
    assert_eq!(lineages.len(), 2, "both histories are returned");
}

#[tokio::test]
async fn dr_collect_ignores_pointers_of_another_identity() {
    let master = viaticum_core::cluster::derive_master_key(&[0xA4u8; 64]).unwrap();
    let me = viaticum_core::cluster::master_identity(&master);
    let stranger = viaticum_core::cluster::derive_master_key(&[0xA5u8; 64]).unwrap();
    let db = test_db();
    let ranked = ranked_peers(&db, 5, 0xA4, &me);
    let forged = signed_pointer(&stranger, 1, 99, 1, 9_000);
    let mut responses: HashMap<DeviceId, Vec<MailboxEntry>> = HashMap::new();
    responses.insert(ranked[0], vec![pointer_entry(me, &forged, 1)]);
    let sender = Arc::new(MockSender::new().with_fetch_responses(responses));
    let router = MailboxRouter::with_sender(sender, db);
    let walk = router.dr_collect_pointers(&me).await.unwrap();
    assert!(walk.pointers.is_empty());
    assert_eq!(walk.responders, 5);
}

#[tokio::test]
async fn dr_collect_distinguishes_no_candidates_from_no_pointer() {
    let master = viaticum_core::cluster::derive_master_key(&[0xA6u8; 64]).unwrap();
    let me = viaticum_core::cluster::master_identity(&master);

    let empty = MailboxRouter::with_sender(Arc::new(MockSender::new()), test_db());
    let walk = empty.dr_collect_pointers(&me).await.unwrap();
    assert_eq!((walk.candidates, walk.responders), (0, 0));
    assert!(walk.pointers.is_empty());

    let db = test_db();
    ranked_peers(&db, 3, 0xA6, &me);
    let quiet = MailboxRouter::with_sender(Arc::new(MockSender::new()), db);
    let walk = quiet.dr_collect_pointers(&me).await.unwrap();
    assert_eq!((walk.candidates, walk.responders), (3, 3));
    assert!(walk.pointers.is_empty());
}

/// Batch 1 (100 closest) holds nothing; the only pointer is at a peer of batch 2.
#[tokio::test]
async fn dr_walk_expands_to_next_batch_when_first_misses() {
    use viaticum_core::constants::MAILBOX_DR_WALK_BATCHES;
    let master = viaticum_core::cluster::derive_master_key(&[0xCDu8; 64]).unwrap();
    let me = viaticum_core::cluster::master_identity(&master);
    let db = test_db();
    let ranked = ranked_peers(&db, 200, 0xF5, &me);
    let first = MAILBOX_DR_WALK_BATCHES[0];
    let p = signed_pointer(&master, 3, 1, 2, 5_000);
    let mut responses: HashMap<DeviceId, Vec<MailboxEntry>> = HashMap::new();
    for d in &ranked[first..] {
        responses.insert(*d, vec![pointer_entry(me, &p, 9)]);
    }
    let sender = Arc::new(MockSender::new().with_fetch_responses(responses));
    let router = MailboxRouter::with_sender(sender.clone(), db);
    let walk = router.dr_collect_pointers(&me).await.unwrap();
    assert_eq!(walk.pointers.len(), 1);
    assert_eq!(walk.pointers[0].generation, 2);
    assert!(
        sender.fetch_calls().len() > first,
        "the walk went past batch 1"
    );
}
