// Tests for the holdings integrity module.
//
// T-13a: migrated from relay (SymbolDropped) to mailbox (DropNotice, deadline=now).

use std::sync::Arc;

use async_trait::async_trait;
use tempfile::TempDir;
use viaticum_core::db::Db;
use viaticum_core::mailbox::MailboxClass;
use viaticum_core::messages::{
    MailboxFetchRequest, MailboxFetchResponse, MailboxStoreRequest, MailboxStoreResponse,
    SymbolDropNoticeBatchMsg, from_cbor,
};
use viaticum_core::types::{
    DeviceId, HoldingRecord, HoldingStatus, IdentityPub, PeerRecord, SourceBlockId, Timestamp,
    hex_encode,
};

use crate::daemon::mailbox::routing::{MailboxNetworkSender, MailboxRouter};

// ─── helpers ────────────────────────────────────────────────────────────────

fn block_id(byte: u8) -> SourceBlockId {
    SourceBlockId([byte; 32])
}

fn owner_id(byte: u8) -> IdentityPub {
    IdentityPub([byte; 32])
}

fn active_holding(block_seed: u8, owner: IdentityPub) -> HoldingRecord {
    HoldingRecord {
        source_block_id: block_id(block_seed),
        owner_id: owner,
        esi_ranges: vec![(0, 10)],
        importance: 0.5,
        total_bytes: 1000,
        status: HoldingStatus::Active,
        received_at: Timestamp(1_000_000),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    }
}

fn make_block_dir(holdings_dir: &std::path::Path, block_seed: u8) -> std::path::PathBuf {
    let block_hex = hex_encode(&block_id(block_seed).0);
    let dir = holdings_dir.join(&block_hex);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn test_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32])
}

fn holder_master_pub() -> IdentityPub {
    // Derived from test_key() — use a fixed known-key value.
    use viaticum_core::cluster::master_identity;
    master_identity(&test_key())
}

// ─── Mock MailboxNetworkSender ────────────────────────────────────────────────

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
        _device: DeviceId,
        req: MailboxStoreRequest,
    ) -> anyhow::Result<MailboxStoreResponse> {
        self.stored.lock().await.push(req.clone());
        Ok(MailboxStoreResponse::Ack {
            msg_id: req.entry.msg_id,
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

/// Generate a real Ed25519 DeviceId that round-trips through device_id_to_peer_id.
fn gen_test_device_id() -> DeviceId {
    use libp2p::identity::Keypair;
    let kp = Keypair::generate_ed25519();
    let ed = kp.try_into_ed25519().unwrap();
    DeviceId(ed.public().to_bytes())
}

/// Build a router backed by `RecordingMailboxSender` and insert one valid peer into
/// the DB so that `build_ranked_candidates` returns at least one candidate on publish.
fn make_router_and_sender(db: &Db) -> (Arc<MailboxRouter>, Arc<RecordingMailboxSender>) {
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

// ─── check_holding_on_disk tests ─────────────────────────────────────────────

#[test]
fn check_holding_on_disk_returns_true_when_directory_exists() {
    let tmp = TempDir::new().unwrap();
    let owner = owner_id(0x01);
    let holding = active_holding(0x01, owner);
    make_block_dir(tmp.path(), 0x01);

    assert!(super::check_holding_on_disk(&holding, tmp.path()));
}

#[test]
fn check_holding_on_disk_returns_false_when_directory_missing() {
    let tmp = TempDir::new().unwrap();
    let owner = owner_id(0x02);
    let holding = active_holding(0x02, owner);
    // No directory created.

    assert!(!super::check_holding_on_disk(&holding, tmp.path()));
}

#[test]
fn check_holding_on_disk_returns_false_when_holdings_dir_itself_missing() {
    let non_existent = std::path::PathBuf::from("/tmp/nonexistent_holdings_dir_xyz_12345");
    let owner = owner_id(0x03);
    let holding = active_holding(0x03, owner);

    assert!(!super::check_holding_on_disk(&holding, &non_existent));
}

// ─── scan_holdings tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn scan_holdings_reports_missing_active_holding() {
    let db = Db::open_in_memory().unwrap();
    let tmp = TempDir::new().unwrap();
    let (router, sender) = make_router_and_sender(&db);

    let owner = owner_id(0xAA);
    let block = block_id(0xAA);
    let holding = active_holding(0xAA, owner);
    db.upsert_holding(&holding).unwrap();
    // No directory on disk.

    let count = super::scan_holdings(
        &db,
        tmp.path(),
        &router,
        holder_master_pub(),
        1,
        &test_key(),
    )
    .await
    .unwrap();

    assert_eq!(count, 1, "should report 1 missing holding");
    assert!(
        db.get_holding(&block, &owner).unwrap().is_none(),
        "holding should be removed from DB"
    );

    // Verify DropNotice was published via mailbox
    let stored = sender.drain().await;
    assert!(!stored.is_empty(), "should have published a DropNotice");
    let entry = &stored[0].entry;
    assert_eq!(entry.class, MailboxClass::DropNotice);
    assert_eq!(entry.target, owner);

    let batch: SymbolDropNoticeBatchMsg = from_cbor(&entry.payload).unwrap();
    assert_eq!(batch.notices.len(), 1);
    let notice = &batch.notices[0];
    assert_eq!(notice.source_block_id, block);

    // Immediate drop: deadline should be <= now + small epsilon
    let now = Timestamp::now().0;
    assert!(
        notice.deadline.0 <= now + 60,
        "immediate drop: deadline should be approximately now"
    );
}

#[tokio::test]
async fn scan_holdings_does_not_report_present_holding() {
    let db = Db::open_in_memory().unwrap();
    let tmp = TempDir::new().unwrap();
    let (router, sender) = make_router_and_sender(&db);

    let owner = owner_id(0xBB);
    let block = block_id(0xBB);
    let holding = active_holding(0xBB, owner);
    db.upsert_holding(&holding).unwrap();
    make_block_dir(tmp.path(), 0xBB);

    let count = super::scan_holdings(
        &db,
        tmp.path(),
        &router,
        holder_master_pub(),
        1,
        &test_key(),
    )
    .await
    .unwrap();

    assert_eq!(count, 0);
    assert!(
        db.get_holding(&block, &owner).unwrap().is_some(),
        "holding should still be in DB"
    );

    let stored = sender.drain().await;
    assert!(
        stored.is_empty(),
        "no messages should be posted for present holding"
    );
}

#[tokio::test]
async fn scan_holdings_skips_marked_for_delete_holdings() {
    let db = Db::open_in_memory().unwrap();
    let tmp = TempDir::new().unwrap();
    let (router, sender) = make_router_and_sender(&db);

    let owner = owner_id(0xCC);
    let holding = HoldingRecord {
        source_block_id: block_id(0xCC),
        owner_id: owner,
        esi_ranges: vec![(0, 5)],
        importance: 0.5,
        total_bytes: 500,
        status: HoldingStatus::MarkedForDelete,
        received_at: Timestamp(1_000_000),
        delete_requested_at: Some(Timestamp(0)),
        drop_notice_sent_at: None,
    };
    db.upsert_holding(&holding).unwrap();
    // No directory on disk.

    let count = super::scan_holdings(
        &db,
        tmp.path(),
        &router,
        holder_master_pub(),
        1,
        &test_key(),
    )
    .await
    .unwrap();

    assert_eq!(count, 0);
    let stored = sender.drain().await;
    assert!(stored.is_empty(), "no messages for MarkedForDelete");
}

#[tokio::test]
async fn scan_holdings_skips_silent_holdings() {
    let db = Db::open_in_memory().unwrap();
    let tmp = TempDir::new().unwrap();
    let (router, sender) = make_router_and_sender(&db);

    let owner = owner_id(0xDD);
    let holding = HoldingRecord {
        source_block_id: block_id(0xDD),
        owner_id: owner,
        esi_ranges: vec![(0, 5)],
        importance: 0.5,
        total_bytes: 500,
        status: HoldingStatus::Silent,
        received_at: Timestamp(1_000_000),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    db.upsert_holding(&holding).unwrap();
    // No directory on disk.

    let count = super::scan_holdings(
        &db,
        tmp.path(),
        &router,
        holder_master_pub(),
        1,
        &test_key(),
    )
    .await
    .unwrap();

    assert_eq!(count, 0);
    let stored = sender.drain().await;
    assert!(stored.is_empty(), "no messages for Silent");
}

#[tokio::test]
async fn scan_holdings_handles_mix_of_present_and_missing() {
    let db = Db::open_in_memory().unwrap();
    let tmp = TempDir::new().unwrap();
    let (router, sender) = make_router_and_sender(&db);

    // 3 active holdings: 2 with directories, 1 without.
    for seed in [0x10u8, 0x20, 0x30] {
        db.upsert_holding(&active_holding(seed, owner_id(seed)))
            .unwrap();
    }
    make_block_dir(tmp.path(), 0x10);
    make_block_dir(tmp.path(), 0x20);
    // 0x30 has no directory.

    let count = super::scan_holdings(
        &db,
        tmp.path(),
        &router,
        holder_master_pub(),
        1,
        &test_key(),
    )
    .await
    .unwrap();

    assert_eq!(count, 1, "exactly 1 missing");
    // Holdings 0x10 and 0x20 should still be present.
    assert!(
        db.get_holding(&block_id(0x10), &owner_id(0x10))
            .unwrap()
            .is_some()
    );
    assert!(
        db.get_holding(&block_id(0x20), &owner_id(0x20))
            .unwrap()
            .is_some()
    );
    // Holding 0x30 should be removed.
    assert!(
        db.get_holding(&block_id(0x30), &owner_id(0x30))
            .unwrap()
            .is_none()
    );

    // Verify DropNotice was published via mailbox for the missing holding (0x30).
    let stored = sender.drain().await;
    assert_eq!(stored.len(), 1, "exactly 1 DropNotice published");
    let entry = &stored[0].entry;
    assert_eq!(entry.class, MailboxClass::DropNotice);
    assert_eq!(entry.target, owner_id(0x30));

    let batch: SymbolDropNoticeBatchMsg = from_cbor(&entry.payload).unwrap();
    assert_eq!(batch.notices[0].source_block_id, block_id(0x30));
}

#[tokio::test]
async fn scan_holdings_does_not_fire_when_holdings_dir_missing() {
    let db = Db::open_in_memory().unwrap();
    let non_existent = std::path::PathBuf::from("/tmp/nonexistent_holdings_xyz_99999");
    let (router, sender) = make_router_and_sender(&db);

    // Insert 2 active holdings.
    for seed in [0x40u8, 0x50] {
        db.upsert_holding(&active_holding(seed, owner_id(seed)))
            .unwrap();
    }

    let count = super::scan_holdings(
        &db,
        &non_existent,
        &router,
        holder_master_pub(),
        1,
        &test_key(),
    )
    .await
    .unwrap();

    assert_eq!(
        count, 0,
        "systemic guard: 0 reported when holdings_dir missing"
    );
    let stored = sender.drain().await;
    assert!(stored.is_empty(), "no messages when holdings_dir missing");
}

// ─── report_missing_holding tests ────────────────────────────────────────────

#[tokio::test]
async fn report_missing_holding_removes_from_db_and_posts_symbol_dropped() {
    let db = Db::open_in_memory().unwrap();
    let (router, sender) = make_router_and_sender(&db);

    let owner = owner_id(0x60);
    let block = block_id(0x60);
    let holding = active_holding(0x60, owner);
    db.upsert_holding(&holding).unwrap();

    super::report_missing_holding(&db, &holding, &router, holder_master_pub(), 1, &test_key())
        .await
        .unwrap();

    assert!(
        db.get_holding(&block, &owner).unwrap().is_none(),
        "holding should be removed from DB"
    );

    // Verify DropNotice published via mailbox
    let stored = sender.drain().await;
    assert!(!stored.is_empty(), "DropNotice should be published");
    let entry = &stored[0].entry;
    assert_eq!(entry.class, MailboxClass::DropNotice);
    assert_eq!(entry.target, owner);
}

#[tokio::test]
async fn report_missing_holding_drop_notice_fields_correct() {
    let db = Db::open_in_memory().unwrap();
    let (router, sender) = make_router_and_sender(&db);

    let owner = owner_id(0x70);
    let block = block_id(0x70);
    let holding = HoldingRecord {
        source_block_id: block,
        owner_id: owner,
        esi_ranges: vec![(5, 15), (20, 30)],
        importance: 0.8,
        total_bytes: 2000,
        status: HoldingStatus::Active,
        received_at: Timestamp(1_000_000),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    db.upsert_holding(&holding).unwrap();

    super::report_missing_holding(&db, &holding, &router, holder_master_pub(), 1, &test_key())
        .await
        .unwrap();

    let stored = sender.drain().await;
    assert!(!stored.is_empty());
    let entry = &stored[0].entry;
    assert_eq!(entry.class, MailboxClass::DropNotice);
    assert_eq!(entry.target, owner);

    let batch: SymbolDropNoticeBatchMsg = from_cbor(&entry.payload).unwrap();
    assert_eq!(batch.notices.len(), 1);
    let notice = &batch.notices[0];
    assert_eq!(notice.source_block_id, block);
    assert_eq!(notice.esi_ranges, vec![(5, 15), (20, 30)]);
    assert_eq!(notice.v, 1);

    // Immediate drop: deadline ~= now
    let now = Timestamp::now().0;
    assert!(
        notice.deadline.0 <= now + 60,
        "immediate drop: deadline should be approximately now, got {} vs now {}",
        notice.deadline.0,
        now
    );
}
