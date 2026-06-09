// Tests for the holder cleanup module.
//
// T-7 changes:
//   - check_pressure now requires mailbox_router + holder_master_pub parameters.
//   - DropNotice (advance notice) is published via mailbox, NOT relay.
//   - SymbolDropped (immediate eviction) stays on relay.
//   - Existing relay-channel tests updated; new mailbox tests added.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use tempfile::TempDir;
use tokio::sync::mpsc;
use viaticum_core::db::Db;
use viaticum_core::mailbox::MailboxRejectReason;
use viaticum_core::messages::{
    MailboxFetchRequest, MailboxFetchResponse, MailboxStoreRequest, MailboxStoreResponse,
    SymbolDropNoticeBatchMsg,
};
use viaticum_core::types::{
    DeviceId, HoldingRecord, HoldingStatus, IdentityPub, PeerRecord, SourceBlockId, Timestamp,
    from_cbor_bytes,
};

use crate::daemon::mailbox::routing::{MailboxNetworkSender, MailboxRouter};
use crate::daemon::relay::RelayPost;

// ─── Mock MailboxNetworkSender that records store requests ────────────────────

struct RecordingMailboxSender {
    stored: tokio::sync::Mutex<Vec<MailboxStoreRequest>>,
}

impl RecordingMailboxSender {
    fn new() -> Self {
        RecordingMailboxSender {
            stored: tokio::sync::Mutex::new(vec![]),
        }
    }

    async fn drain(&self) -> Vec<MailboxStoreRequest> {
        let mut locked = self.stored.lock().await;
        std::mem::take(&mut *locked)
    }
}

#[async_trait]
impl MailboxNetworkSender for RecordingMailboxSender {
    async fn send_store(
        &self,
        _device: viaticum_core::types::DeviceId,
        req: MailboxStoreRequest,
    ) -> anyhow::Result<MailboxStoreResponse> {
        self.stored.lock().await.push(req.clone());
        Ok(MailboxStoreResponse::Ack {
            msg_id: req.entry.msg_id,
        })
    }

    async fn send_fetch(
        &self,
        _device: viaticum_core::types::DeviceId,
        _req: MailboxFetchRequest,
    ) -> anyhow::Result<MailboxFetchResponse> {
        Ok(MailboxFetchResponse {
            v: 1,
            entries: vec![],
            served_msg_ids: vec![],
        })
    }
}

// ─── Mock MailboxNetworkSender that always returns Reject (0 acks) ────────────

/// Rejects every store request. Used to exercise the W-4 retry-on-zero-acks path.
/// Counts total `send_store` calls so the test can assert the retry fired.
struct ZeroAckSender {
    call_count: Arc<AtomicUsize>,
}

impl ZeroAckSender {
    fn new() -> (Self, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        (
            ZeroAckSender {
                call_count: Arc::clone(&counter),
            },
            counter,
        )
    }
}

#[async_trait]
impl MailboxNetworkSender for ZeroAckSender {
    async fn send_store(
        &self,
        _device: DeviceId,
        req: MailboxStoreRequest,
    ) -> anyhow::Result<MailboxStoreResponse> {
        self.call_count.fetch_add(1, Ordering::Relaxed);
        Ok(MailboxStoreResponse::Reject {
            msg_id: req.entry.msg_id,
            reason: MailboxRejectReason::QuotaExceeded,
        })
    }

    async fn send_fetch(
        &self,
        _device: DeviceId,
        _req: MailboxFetchRequest,
    ) -> anyhow::Result<MailboxFetchResponse> {
        Ok(MailboxFetchResponse {
            v: 1,
            entries: vec![],
            served_msg_ids: vec![],
        })
    }
}

/// Build a router backed by `ZeroAckSender` and insert one valid peer into the DB
/// so that `build_ranked_candidates` returns a candidate. Returns the router and the
/// shared call counter.
fn make_zero_ack_router(db: &Db) -> (Arc<MailboxRouter>, Arc<AtomicUsize>) {
    let device_id = gen_test_device_id();
    let peer = PeerRecord {
        device_id,
        master_identity: IdentityPub([0xACu8; 32]),
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: 0.5,
        last_avail_sample: 0,
    };
    db.upsert_peer(&peer).unwrap();

    let (sender, counter) = ZeroAckSender::new();
    let router = Arc::new(MailboxRouter::with_sender(
        Arc::new(sender) as Arc<dyn MailboxNetworkSender>,
        db.clone(),
    ));
    (router, counter)
}

/// Generate a real Ed25519 DeviceId that round-trips through device_id_to_peer_id.
fn gen_test_device_id() -> DeviceId {
    use libp2p::identity::Keypair;
    let kp = Keypair::generate_ed25519();
    let ed = kp.try_into_ed25519().unwrap();
    DeviceId(ed.public().to_bytes())
}

/// Build a router backed by `RecordingMailboxSender` and insert one valid peer into
/// the DB so that `build_ranked_candidates` returns at least one candidate on publish.
/// Without a peer, the write-fanout is empty and `send_store` is never called.
fn make_router_and_sender(db: &Db) -> (Arc<MailboxRouter>, Arc<RecordingMailboxSender>) {
    // Insert a real Ed25519 peer so the candidate-set is non-empty.
    let device_id = gen_test_device_id();
    let peer = PeerRecord {
        device_id,
        master_identity: IdentityPub([0xABu8; 32]),
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: 0.5,
        last_avail_sample: 0,
    };
    db.upsert_peer(&peer).unwrap();

    let sender = Arc::new(RecordingMailboxSender::new());
    let router = Arc::new(MailboxRouter::with_sender(
        Arc::clone(&sender) as Arc<dyn MailboxNetworkSender>,
        db.clone(),
    ));
    (router, sender)
}

fn holder_master_pub() -> IdentityPub {
    IdentityPub([0xFFu8; 32])
}

// ─── helpers ────────────────────────────────────────────────────────────────

fn block_id(byte: u8) -> SourceBlockId {
    SourceBlockId([byte; 32])
}

fn owner_id(byte: u8) -> IdentityPub {
    IdentityPub([byte; 32])
}

/// Build a HoldingRecord with MarkedForDelete status and an expired cooldown.
/// `delete_requested_at` is set to Timestamp(0), so the cooldown expired at
/// Timestamp(HOLDER_DELETE_COOLDOWN_SECS). Pass `now` >= that value.
fn expired_holding(block_seed: u8, owner: IdentityPub) -> HoldingRecord {
    HoldingRecord {
        source_block_id: block_id(block_seed),
        owner_id: owner,
        esi_ranges: vec![(0, 10)],
        importance: 0.5,
        total_bytes: 1000,
        status: HoldingStatus::MarkedForDelete,
        received_at: Timestamp(100),
        delete_requested_at: Some(Timestamp(0)), // expired at T(COOLDOWN)
        drop_notice_sent_at: None,
    }
}

/// Build an mpsc channel pair sized for the tests (capacity 16).
fn relay_channel() -> (mpsc::Sender<RelayPost>, mpsc::Receiver<RelayPost>) {
    mpsc::channel(16)
}

fn test_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32])
}

// ─── test 1: cleanup_expired_deletes_files_and_posts_symbol_dropped ─────────

#[tokio::test]
async fn cleanup_expired_deletes_files_and_posts_symbol_dropped() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (relay_post_tx, mut relay_post_rx) = relay_channel();

    let owner = owner_id(0xBB);
    let block = block_id(0xAA);
    let holding = expired_holding(0xAA, owner);
    db.upsert_holding(&holding).unwrap();

    // Create the symbol directory on disk so cleanup has something to delete.
    let block_hex = viaticum_core::types::hex_encode(&block.0);
    let block_dir = holdings_dir.path().join(&block_hex);
    tokio::fs::create_dir_all(&block_dir).await.unwrap();
    tokio::fs::write(block_dir.join("symbol_0.bin"), b"fake symbol data")
        .await
        .unwrap();

    // Use a `now` timestamp that is well past the cooldown.
    // cleanup_expired calls Timestamp::now() internally, so we rely on the
    // real wall-clock being >> HOLDER_DELETE_COOLDOWN_SECS (which is 4 weeks
    // in seconds, ~2.4 million). Any Unix timestamp past 2024 qualifies.
    super::cleanup_expired(&db, holdings_dir.path(), &relay_post_tx, 1, &test_key())
        .await
        .unwrap();

    // DB record must be gone.
    assert!(
        db.get_holding(&block, &owner).unwrap().is_none(),
        "holding should be removed from DB"
    );

    // Symbol directory must be deleted.
    assert!(
        !block_dir.exists(),
        "symbol directory should be deleted from disk"
    );

    // A SymbolDropped message must have been posted.
    let post = relay_post_rx
        .try_recv()
        .expect("relay_post_tx should have received a SymbolDropped message");
    assert_eq!(
        post.msg_type, "symbol_dropped",
        "posted message type should be symbol_dropped"
    );
    assert_eq!(
        post.target,
        Some(owner),
        "SymbolDropped should be directed at the owner"
    );
}

// ─── test 2: cleanup_expired_tolerates_missing_files ────────────────────────

#[tokio::test]
async fn cleanup_expired_tolerates_missing_files() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (relay_post_tx, mut relay_post_rx) = relay_channel();

    let owner = owner_id(0xCC);
    let block = block_id(0xDD);
    let holding = expired_holding(0xDD, owner);
    db.upsert_holding(&holding).unwrap();

    // Intentionally do NOT create any files on disk.

    // Should not error even though no files exist.
    super::cleanup_expired(&db, holdings_dir.path(), &relay_post_tx, 1, &test_key())
        .await
        .unwrap();

    // DB record must still be gone.
    assert!(
        db.get_holding(&block, &owner).unwrap().is_none(),
        "holding should be removed from DB even when files were absent"
    );

    // A SymbolDropped message must still be posted.
    let post = relay_post_rx
        .try_recv()
        .expect("relay_post_tx should have received a SymbolDropped message");
    assert_eq!(post.msg_type, "symbol_dropped");
    assert_eq!(post.target, Some(owner));
}

// ─── test 3: check_pressure_normal_does_nothing ─────────────────────────────

#[tokio::test]
async fn check_pressure_normal_does_nothing() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (relay_post_tx, mut relay_post_rx) = relay_channel();
    let (router, sender) = make_router_and_sender(&db);

    // Insert a few active holdings so the DB is not empty.
    for seed in 0..3u8 {
        let h = HoldingRecord {
            source_block_id: block_id(seed),
            owner_id: owner_id(seed),
            esi_ranges: vec![(0, 5)],
            importance: 0.5,
            total_bytes: 512,
            status: HoldingStatus::Active,
            received_at: Timestamp(1_000_000),
            delete_requested_at: None,
            drop_notice_sent_at: None,
        };
        db.upsert_holding(&h).unwrap();
    }

    // Pass u64::MAX for soft quota, 0 for hard quota → pressure is always Normal.
    super::check_pressure(
        &db,
        holdings_dir.path(),
        &relay_post_tx,
        &router,
        holder_master_pub(),
        u64::MAX,
        0,
        holdings_dir.path(),
        0,
        &test_key(),
    )
    .await
    .unwrap();

    // No evictions should occur — relay_post_tx must remain empty (SymbolDropped path).
    assert!(
        relay_post_rx.try_recv().is_err(),
        "no messages should be posted when disk pressure is Normal"
    );

    // No mailbox publish should happen either.
    let mailbox_reqs = sender.drain().await;
    assert!(
        mailbox_reqs.is_empty(),
        "no mailbox publish when disk pressure is Normal"
    );

    // All holdings must still be in the DB.
    for seed in 0..3u8 {
        assert!(
            db.get_holding(&block_id(seed), &owner_id(seed))
                .unwrap()
                .is_some(),
            "holding {seed} should not have been evicted"
        );
    }
}

// ─── T-7 tests ────────────────────────────────────────────────────────────────

/// T-7: Under hard pressure with a buffer-zone holding, `check_pressure` publishes
/// a DropNotice via mailbox (NOT relay) and records `drop_notice_sent_at`.
#[tokio::test]
async fn drop_notice_published_to_mailbox_on_eviction() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (relay_post_tx, mut relay_post_rx) = relay_channel();
    let (router, sender) = make_router_and_sender(&db);

    let owner_a = owner_id(0x01);
    let owner_b = owner_id(0x02);

    // Holding A: low priority, will be immediately evicted under hard pressure.
    let holding_a = HoldingRecord {
        source_block_id: block_id(0xAA),
        owner_id: owner_a,
        esi_ranges: vec![(0, 10)],
        importance: 0.1,
        total_bytes: 600,
        status: HoldingStatus::Active,
        received_at: Timestamp(0), // old → low priority
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    // Holding B: higher priority, will receive DropNotice (buffer zone).
    let holding_b = HoldingRecord {
        source_block_id: block_id(0xBB),
        owner_id: owner_b,
        esi_ranges: vec![(0, 5)],
        importance: 0.9,
        total_bytes: 350,
        status: HoldingStatus::Active,
        received_at: Timestamp(Timestamp::now().0),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    // Top-up to push free_ratio below 0.05 → Hard pressure.
    let top_up = HoldingRecord {
        source_block_id: block_id(0xCC),
        owner_id: owner_id(0x03),
        esi_ranges: vec![(0, 1)],
        importance: 0.5,
        total_bytes: 20,
        status: HoldingStatus::Active,
        received_at: Timestamp(Timestamp::now().0),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    db.upsert_holding(&holding_a).unwrap();
    db.upsert_holding(&holding_b).unwrap();
    db.upsert_holding(&top_up).unwrap();
    // used = 970, free_ratio = 0.03 < 0.05 → Hard ✓

    super::check_pressure(
        &db,
        holdings_dir.path(),
        &relay_post_tx,
        &router,
        holder_master_pub(),
        1000, // soft_quota_bytes
        0,    // hard_quota_bytes = 0 (no floor)
        holdings_dir.path(),
        0, // disk_reserve_bytes
        &test_key(),
    )
    .await
    .unwrap();

    // SymbolDropped (immediate eviction of holding A) must go via relay.
    let mut symbol_dropped_found = false;
    while let Ok(post) = relay_post_rx.try_recv() {
        if post.msg_type == "symbol_dropped" {
            symbol_dropped_found = true;
        }
        // DropNotice must NOT appear on relay (scope fence: moved to mailbox in T-7).
        assert_ne!(
            post.msg_type, "symbol_drop_notice",
            "DropNotice must NOT be sent via relay in T-7 (must go via mailbox)"
        );
    }
    assert!(
        symbol_dropped_found,
        "SymbolDropped for immediately-evicted holding A must still go via relay"
    );

    // DropNotice for holding B must be published via mailbox.
    let mailbox_reqs = sender.drain().await;
    assert!(
        !mailbox_reqs.is_empty(),
        "at least one MailboxStoreRequest should be sent for DropNotice"
    );

    // Find the DropNotice entry for owner_b.
    let drop_notice_req = mailbox_reqs
        .iter()
        .find(|req| req.entry.target == owner_b)
        .expect("a MailboxStoreRequest targeting owner_b should exist");

    assert_eq!(
        drop_notice_req.entry.class,
        viaticum_core::mailbox::MailboxClass::DropNotice,
        "mailbox entry class must be DropNotice"
    );
    assert_eq!(
        drop_notice_req.entry.sender,
        Some(holder_master_pub()),
        "sender must be the holder's own master_pub"
    );

    // DB must record drop_notice_sent_at for holding B.
    let updated_b = db
        .get_holding(&holding_b.source_block_id, &holding_b.owner_id)
        .unwrap();
    match updated_b {
        Some(h) => {
            assert!(
                h.drop_notice_sent_at.is_some(),
                "drop_notice_sent_at must be set after mailbox publish"
            );
        }
        None => {
            panic!(
                "holding B was evicted instead of receiving DropNotice — \
                 setup arithmetic is off"
            );
        }
    }
}

/// T-7: DropNotice entry `expires_at - stored_at == DROP_NOTICE_TTL` (14 days).
#[tokio::test]
async fn drop_notice_has_correct_ttl() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (relay_post_tx, _relay_post_rx) = relay_channel();
    let (router, sender) = make_router_and_sender(&db);

    let owner = owner_id(0x10);
    let holding_low = HoldingRecord {
        source_block_id: block_id(0x10),
        owner_id: owner_id(0x11),
        esi_ranges: vec![(0, 1)],
        importance: 0.1,
        total_bytes: 600,
        status: HoldingStatus::Active,
        received_at: Timestamp(0),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    let holding_buf = HoldingRecord {
        source_block_id: block_id(0x12),
        owner_id: owner,
        esi_ranges: vec![(0, 5)],
        importance: 0.9,
        total_bytes: 350,
        status: HoldingStatus::Active,
        received_at: Timestamp(Timestamp::now().0),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    let top_up = HoldingRecord {
        source_block_id: block_id(0x13),
        owner_id: owner_id(0x14),
        esi_ranges: vec![(0, 1)],
        importance: 0.5,
        total_bytes: 20,
        status: HoldingStatus::Active,
        received_at: Timestamp(Timestamp::now().0),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    db.upsert_holding(&holding_low).unwrap();
    db.upsert_holding(&holding_buf).unwrap();
    db.upsert_holding(&top_up).unwrap();

    super::check_pressure(
        &db,
        holdings_dir.path(),
        &relay_post_tx,
        &router,
        holder_master_pub(),
        1000,
        0,
        holdings_dir.path(),
        0,
        &test_key(),
    )
    .await
    .unwrap();

    let reqs = sender.drain().await;
    let drop_req = reqs
        .iter()
        .find(|r| r.entry.target == owner)
        .expect("DropNotice mailbox entry for buffer-zone owner expected");

    let ttl_actual = drop_req
        .entry
        .expires_at
        .saturating_sub(drop_req.entry.stored_at);
    let ttl_expected = viaticum_core::mailbox::class_config::DROP_NOTICE_TTL.as_secs();

    assert_eq!(
        ttl_actual, ttl_expected,
        "DropNotice TTL must be DROP_NOTICE_TTL = 14 days"
    );
}

/// T-7: Many notices for the SAME owner → ONE (or minimal ≤ cap) batch entry.
#[tokio::test]
async fn mass_eviction_batches_into_single_mailbox_entry() {
    let db = Db::open_in_memory().unwrap();
    let _holdings_dir = TempDir::new().unwrap();
    let (_relay_post_tx, _relay_post_rx) = relay_channel();
    let (router, sender) = make_router_and_sender(&db);

    let owner = owner_id(0x20);

    // Create many buffer-zone holdings for the same owner.
    // We need pressure high enough so many holdings get DropNotice.
    // Use a tiny quota (1) and many small holdings; rely on evaluate_pressure
    // to put them in the buffer zone.
    // Actually — a simpler approach: call publish_drop_notices_via_mailbox directly
    // with a Vec of synthetic DropNoticeTargets.

    // For the mock, directly test the batching function.
    let now = Timestamp::now();
    let drop_notices: Vec<viaticum_core::budget::DropNoticeTarget> = (0u8..10)
        .map(|i| {
            let bid = block_id(i);
            let h = HoldingRecord {
                source_block_id: bid,
                owner_id: owner,
                esi_ranges: vec![(0, 3)],
                importance: 0.5,
                total_bytes: 100,
                status: HoldingStatus::Active,
                received_at: now,
                delete_requested_at: None,
                drop_notice_sent_at: None,
            };
            db.upsert_holding(&h).unwrap();
            viaticum_core::budget::DropNoticeTarget {
                source_block_id: bid,
                owner_id: owner,
                deadline_secs: now.0 + 86400 * 7,
            }
        })
        .collect();

    super::publish_drop_notices_via_mailbox(&db, &drop_notices, &router, holder_master_pub(), now)
        .await;

    let reqs = sender.drain().await;

    // All entries should target the same owner.
    for req in &reqs {
        assert_eq!(req.entry.target, owner, "all entries should target owner");
    }

    // Decode the batch payloads and count total notices.
    let total_notices: usize = reqs
        .iter()
        .map(|req| {
            let batch: SymbolDropNoticeBatchMsg =
                from_cbor_bytes(&req.entry.payload).expect("decode batch");
            batch.notices.len()
        })
        .sum();

    assert_eq!(
        total_notices, 10,
        "all 10 notices must appear across the batch entries"
    );

    // With 10 notices × ~100 bytes each = ~1 KB → well under 256 KB → ONE entry expected.
    assert_eq!(
        reqs.len(),
        1,
        "10 small notices should fit in ONE batch entry (well under MAX_ENTRY_BYTES)"
    );
}

/// T-7: Notices for owner A and owner B → separate mailbox entries for each.
#[tokio::test]
async fn drop_notices_for_different_owners_go_to_separate_entries() {
    let db = Db::open_in_memory().unwrap();
    let (router, sender) = make_router_and_sender(&db);

    let owner_a = owner_id(0x30);
    let owner_b = owner_id(0x31);
    let now = Timestamp::now();

    let notices: Vec<viaticum_core::budget::DropNoticeTarget> = vec![
        // 2 notices for owner A
        (block_id(0x30), owner_a),
        (block_id(0x31), owner_a),
        // 3 notices for owner B
        (block_id(0x32), owner_b),
        (block_id(0x33), owner_b),
        (block_id(0x34), owner_b),
    ]
    .into_iter()
    .map(|(bid, oid)| {
        let h = HoldingRecord {
            source_block_id: bid,
            owner_id: oid,
            esi_ranges: vec![(0, 2)],
            importance: 0.5,
            total_bytes: 100,
            status: HoldingStatus::Active,
            received_at: now,
            delete_requested_at: None,
            drop_notice_sent_at: None,
        };
        db.upsert_holding(&h).unwrap();
        viaticum_core::budget::DropNoticeTarget {
            source_block_id: bid,
            owner_id: oid,
            deadline_secs: now.0 + 86400 * 7,
        }
    })
    .collect();

    super::publish_drop_notices_via_mailbox(&db, &notices, &router, holder_master_pub(), now).await;

    let reqs = sender.drain().await;

    // Should have entries for owner_a and owner_b (may be 1 or 2 each if chunked,
    // but with tiny notices all fit in one each).
    let reqs_a: Vec<_> = reqs.iter().filter(|r| r.entry.target == owner_a).collect();
    let reqs_b: Vec<_> = reqs.iter().filter(|r| r.entry.target == owner_b).collect();

    assert!(!reqs_a.is_empty(), "owner_a must have a mailbox entry");
    assert!(!reqs_b.is_empty(), "owner_b must have a mailbox entry");

    // Decode and verify notice counts.
    let count_a: usize = reqs_a
        .iter()
        .map(|r| {
            let b: SymbolDropNoticeBatchMsg = from_cbor_bytes(&r.entry.payload).unwrap();
            b.notices.len()
        })
        .sum();
    let count_b: usize = reqs_b
        .iter()
        .map(|r| {
            let b: SymbolDropNoticeBatchMsg = from_cbor_bytes(&r.entry.payload).unwrap();
            b.notices.len()
        })
        .sum();

    assert_eq!(count_a, 2, "owner A should have exactly 2 notices");
    assert_eq!(count_b, 3, "owner B should have exactly 3 notices");

    // Each entry targets the right owner exclusively.
    for r in &reqs_a {
        assert_eq!(r.entry.target, owner_a, "entry targeting owner_a");
    }
    for r in &reqs_b {
        assert_eq!(r.entry.target, owner_b, "entry targeting owner_b");
    }
}

/// T-7: drop_notice_sent_at is not overwritten on second pressure tick.
#[tokio::test]
async fn holder_drop_notice_sent_at_not_overwritten_on_second_send() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (relay_post_tx, _relay_post_rx) = relay_channel();
    let (router, _sender) = make_router_and_sender(&db);

    let earlier_time = Timestamp(1_000_000); // a past timestamp

    // Insert a holding whose drop_notice_sent_at is already set.
    let holding = HoldingRecord {
        source_block_id: block_id(0xDD),
        owner_id: owner_id(0x04),
        esi_ranges: vec![(0, 10)],
        importance: 0.5,
        total_bytes: 10,
        status: HoldingStatus::Active,
        received_at: Timestamp(0),
        delete_requested_at: None,
        drop_notice_sent_at: Some(earlier_time),
    };
    db.upsert_holding(&holding).unwrap();

    // Add a low-priority holding to trigger hard pressure at quota=100.
    let holding_low = HoldingRecord {
        source_block_id: block_id(0xEE),
        owner_id: owner_id(0x05),
        esi_ranges: vec![(0, 1)],
        importance: 0.1,
        total_bytes: 92,
        status: HoldingStatus::Active,
        received_at: Timestamp(0),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    db.upsert_holding(&holding_low).unwrap();
    // used = 10 + 92 = 102 > 0.95 * 100 = 95 → Hard

    super::check_pressure(
        &db,
        holdings_dir.path(),
        &relay_post_tx,
        &router,
        holder_master_pub(),
        100, // soft_quota_bytes = 100
        0,
        holdings_dir.path(),
        0,
        &test_key(),
    )
    .await
    .unwrap();

    // The holding must survive with its original drop_notice_sent_at.
    let updated = db
        .get_holding(&holding.source_block_id, &holding.owner_id)
        .expect("db query failed")
        .expect(
            "holding was evicted instead of surviving in buffer zone — \
                 setup arithmetic is off",
        );
    assert_eq!(
        updated.drop_notice_sent_at,
        Some(earlier_time),
        "drop_notice_sent_at must not be overwritten when already set"
    );
}

// ─── W13 holder-side drop notice tests (legacy relay behavior — now mailbox) ──

/// Build a Hard-pressure scenario:
/// - quota = 1000 bytes
/// - used = 970 bytes (free_ratio = 0.03 < HARD_PRESSURE_THRESHOLD=0.05 → Hard)
/// - Holdings A (600 bytes, low priority) covers deficit; B (350 bytes, medium
///   priority) falls into the buffer zone and receives a DropNotice.
///
/// Returns (db, holdings_dir, relay_post_tx, relay_post_rx, holding_b)
/// where holding_b is the buffer-zone holding that should receive a drop notice.
async fn setup_hard_pressure_with_buffer_zone() -> (
    Db,
    TempDir,
    mpsc::Sender<RelayPost>,
    mpsc::Receiver<RelayPost>,
    HoldingRecord,
    Arc<MailboxRouter>,
    Arc<RecordingMailboxSender>,
) {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (relay_post_tx, relay_post_rx) = mpsc::channel::<RelayPost>(16);
    let (router, sender) = make_router_and_sender(&db);

    // Holding A: 600 bytes, importance=0.1, received at T=0 (old → low priority).
    let holding_a = HoldingRecord {
        source_block_id: block_id(0xAA),
        owner_id: owner_id(0x01),
        esi_ranges: vec![(0, 10)],
        importance: 0.1,
        total_bytes: 600,
        status: HoldingStatus::Active,
        received_at: Timestamp(0),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    // Holding B: 350 bytes, importance=0.9, received at T=now (new → medium priority).
    let holding_b = HoldingRecord {
        source_block_id: block_id(0xBB),
        owner_id: owner_id(0x02),
        esi_ranges: vec![(0, 10)],
        importance: 0.9,
        total_bytes: 350,
        status: HoldingStatus::Active,
        received_at: Timestamp(Timestamp::now().0),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    let top_up = HoldingRecord {
        source_block_id: block_id(0xCC),
        owner_id: owner_id(0x03),
        esi_ranges: vec![(0, 1)],
        importance: 0.5,
        total_bytes: 20,
        status: HoldingStatus::Active,
        received_at: Timestamp(Timestamp::now().0),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    db.upsert_holding(&holding_a).unwrap();
    db.upsert_holding(&holding_b).unwrap();
    db.upsert_holding(&top_up).unwrap();

    (
        db,
        holdings_dir,
        relay_post_tx,
        relay_post_rx,
        holding_b,
        router,
        sender,
    )
}

/// Test: under hard pressure with a buffer zone holding, check_pressure sends a
/// DropNotice via MAILBOX (not relay) and records `drop_notice_sent_at` in the DB.
#[tokio::test]
async fn holder_pressure_sets_drop_notice_sent_at_on_first_send() {
    let (db, holdings_dir, relay_post_tx, _relay_post_rx, holding_b, router, sender) =
        setup_hard_pressure_with_buffer_zone().await;

    super::check_pressure(
        &db,
        holdings_dir.path(),
        &relay_post_tx,
        &router,
        holder_master_pub(),
        1000, // soft_quota_bytes
        0,    // hard_quota_bytes = 0 (no floor)
        holdings_dir.path(),
        0, // disk_reserve_bytes
        &test_key(),
    )
    .await
    .unwrap();

    // DropNotice must be published via mailbox, not relay.
    let mailbox_reqs = sender.drain().await;
    let drop_notice_found = mailbox_reqs
        .iter()
        .any(|r| r.entry.target == holding_b.owner_id);
    assert!(
        drop_notice_found,
        "check_pressure must publish DropNotice via mailbox for the buffer-zone holding"
    );

    // DB must have recorded drop_notice_sent_at for holding B.
    let updated_b = db
        .get_holding(&holding_b.source_block_id, &holding_b.owner_id)
        .unwrap();
    match updated_b {
        Some(h) => {
            assert!(
                h.drop_notice_sent_at.is_some(),
                "drop_notice_sent_at must be set after mailbox publish"
            );
        }
        None => {
            panic!(
                "holding B was evicted instead of receiving DropNotice — \
                    setup_hard_pressure_with_buffer_zone arithmetic is off"
            );
        }
    }
}

/// W-4: when every peer rejects the store (0 acks), `publish_drop_notices_via_mailbox`
/// retries once (two `send_store` calls total per chunk) then continues without panic.
/// Also verifies that `drop_notice_sent_at` is stamped on the holding regardless
/// of delivery outcome (best-effort: we proceed even if no peer acked).
#[tokio::test]
async fn drop_notice_zero_ack_retries_once_then_continues() {
    let db = Db::open_in_memory().unwrap();
    // make_zero_ack_router inserts exactly one peer, so write-fanout selects that
    // one peer → each publish() call issues exactly 1 send_store().
    // W-4 logic: initial publish → 0 acks → retry publish → 0 acks again.
    // Total send_store calls = 2 (one per publish, two publishes).
    let (router, call_counter) = make_zero_ack_router(&db);

    let owner = owner_id(0x50);
    let now = Timestamp::now();
    let block = block_id(0x50);

    let holding = HoldingRecord {
        source_block_id: block,
        owner_id: owner,
        esi_ranges: vec![(0, 4)],
        importance: 0.5,
        total_bytes: 200,
        status: HoldingStatus::Active,
        received_at: now,
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    db.upsert_holding(&holding).unwrap();

    let drop_notices = vec![viaticum_core::budget::DropNoticeTarget {
        source_block_id: block,
        owner_id: owner,
        deadline_secs: now.0 + 86400 * 7,
    }];

    // Must complete without panic.
    super::publish_drop_notices_via_mailbox(&db, &drop_notices, &router, holder_master_pub(), now)
        .await;

    // (a) No panic above; function completed.

    // (b) Exactly 2 send_store calls: 1 initial + 1 retry (one peer, two publishes).
    let total_calls = call_counter.load(Ordering::Relaxed);
    assert_eq!(
        total_calls, 2,
        "W-4: expected 2 send_store calls (initial + retry); got {total_calls}"
    );

    // (c) drop_notice_sent_at is stamped regardless of delivery (best-effort).
    let updated = db
        .get_holding(&block, &owner)
        .expect("db query succeeded")
        .expect("holding still exists");
    assert!(
        updated.drop_notice_sent_at.is_some(),
        "drop_notice_sent_at must be set even when all acks were 0 (best-effort)"
    );
}
