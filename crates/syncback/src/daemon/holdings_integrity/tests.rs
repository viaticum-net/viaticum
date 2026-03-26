// Tests for the holdings integrity module.

use syncback_core::db::Db;
use syncback_core::messages::{from_cbor, SymbolDroppedMsg};
use syncback_core::types::{hex_encode, HoldingRecord, HoldingStatus, IdentityPub, SourceBlockId, Timestamp};
use tempfile::TempDir;
use tokio::sync::mpsc;

use crate::daemon::relay::RelayPost;

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

fn relay_channel() -> (mpsc::Sender<RelayPost>, mpsc::Receiver<RelayPost>) {
    mpsc::channel(16)
}

fn make_block_dir(holdings_dir: &std::path::Path, block_seed: u8) -> std::path::PathBuf {
    let block_hex = hex_encode(&block_id(block_seed).0);
    let dir = holdings_dir.join(&block_hex);
    std::fs::create_dir_all(&dir).unwrap();
    dir
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
    let (relay_tx, mut relay_rx) = relay_channel();

    let owner = owner_id(0xAA);
    let block = block_id(0xAA);
    let holding = active_holding(0xAA, owner);
    db.upsert_holding(&holding).unwrap();
    // No directory on disk.

    let count = super::scan_holdings(&db, tmp.path(), &relay_tx).await.unwrap();

    assert_eq!(count, 1, "should report 1 missing holding");
    assert!(
        db.get_holding(&block, &owner).unwrap().is_none(),
        "holding should be removed from DB"
    );
    let post = relay_rx.try_recv().expect("should have received SymbolDropped");
    assert_eq!(post.msg_type, "symbol_dropped");
    assert_eq!(post.target, Some(owner));
}

#[tokio::test]
async fn scan_holdings_does_not_report_present_holding() {
    let db = Db::open_in_memory().unwrap();
    let tmp = TempDir::new().unwrap();
    let (relay_tx, mut relay_rx) = relay_channel();

    let owner = owner_id(0xBB);
    let block = block_id(0xBB);
    let holding = active_holding(0xBB, owner);
    db.upsert_holding(&holding).unwrap();
    make_block_dir(tmp.path(), 0xBB);

    let count = super::scan_holdings(&db, tmp.path(), &relay_tx).await.unwrap();

    assert_eq!(count, 0);
    assert!(
        db.get_holding(&block, &owner).unwrap().is_some(),
        "holding should still be in DB"
    );
    assert!(relay_rx.try_recv().is_err(), "no messages should be posted");
}

#[tokio::test]
async fn scan_holdings_skips_marked_for_delete_holdings() {
    let db = Db::open_in_memory().unwrap();
    let tmp = TempDir::new().unwrap();
    let (relay_tx, mut relay_rx) = relay_channel();

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

    let count = super::scan_holdings(&db, tmp.path(), &relay_tx).await.unwrap();

    assert_eq!(count, 0);
    assert!(relay_rx.try_recv().is_err(), "no messages for MarkedForDelete");
}

#[tokio::test]
async fn scan_holdings_skips_silent_holdings() {
    let db = Db::open_in_memory().unwrap();
    let tmp = TempDir::new().unwrap();
    let (relay_tx, mut relay_rx) = relay_channel();

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

    let count = super::scan_holdings(&db, tmp.path(), &relay_tx).await.unwrap();

    assert_eq!(count, 0);
    assert!(relay_rx.try_recv().is_err(), "no messages for Silent");
}

#[tokio::test]
async fn scan_holdings_handles_mix_of_present_and_missing() {
    let db = Db::open_in_memory().unwrap();
    let tmp = TempDir::new().unwrap();
    let (relay_tx, mut relay_rx) = relay_channel();

    // 3 active holdings: 2 with directories, 1 without.
    for seed in [0x10u8, 0x20, 0x30] {
        db.upsert_holding(&active_holding(seed, owner_id(seed))).unwrap();
    }
    make_block_dir(tmp.path(), 0x10);
    make_block_dir(tmp.path(), 0x20);
    // 0x30 has no directory.

    let count = super::scan_holdings(&db, tmp.path(), &relay_tx).await.unwrap();

    assert_eq!(count, 1, "exactly 1 missing");
    // Holdings 0x10 and 0x20 should still be present.
    assert!(db.get_holding(&block_id(0x10), &owner_id(0x10)).unwrap().is_some());
    assert!(db.get_holding(&block_id(0x20), &owner_id(0x20)).unwrap().is_some());
    // Holding 0x30 should be removed.
    assert!(db.get_holding(&block_id(0x30), &owner_id(0x30)).unwrap().is_none());

    let post = relay_rx.try_recv().expect("should have received SymbolDropped for 0x30");
    assert_eq!(post.target, Some(owner_id(0x30)));
    assert!(relay_rx.try_recv().is_err(), "only 1 message posted");
}

#[tokio::test]
async fn scan_holdings_does_not_fire_when_holdings_dir_missing() {
    let db = Db::open_in_memory().unwrap();
    let non_existent = std::path::PathBuf::from("/tmp/nonexistent_holdings_xyz_99999");
    let (relay_tx, mut relay_rx) = relay_channel();

    // Insert 2 active holdings.
    for seed in [0x40u8, 0x50] {
        db.upsert_holding(&active_holding(seed, owner_id(seed))).unwrap();
    }

    let count = super::scan_holdings(&db, &non_existent, &relay_tx).await.unwrap();

    assert_eq!(count, 0, "systemic guard: 0 reported when holdings_dir missing");
    assert!(relay_rx.try_recv().is_err(), "no messages when holdings_dir missing");
}

// ─── report_missing_holding tests ────────────────────────────────────────────

#[tokio::test]
async fn report_missing_holding_removes_from_db_and_posts_symbol_dropped() {
    let db = Db::open_in_memory().unwrap();
    let (relay_tx, mut relay_rx) = relay_channel();

    let owner = owner_id(0x60);
    let block = block_id(0x60);
    let holding = active_holding(0x60, owner);
    db.upsert_holding(&holding).unwrap();

    super::report_missing_holding(&db, &holding, &relay_tx).await.unwrap();

    assert!(
        db.get_holding(&block, &owner).unwrap().is_none(),
        "holding should be removed from DB"
    );
    let post = relay_rx.try_recv().expect("SymbolDropped should be posted");
    assert_eq!(post.msg_type, "symbol_dropped");
    assert_eq!(post.target, Some(owner));
}

#[tokio::test]
async fn report_missing_holding_symbol_dropped_fields_correct() {
    let db = Db::open_in_memory().unwrap();
    let (relay_tx, mut relay_rx) = relay_channel();

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

    super::report_missing_holding(&db, &holding, &relay_tx).await.unwrap();

    let post = relay_rx.try_recv().unwrap();
    assert_eq!(post.msg_type, "symbol_dropped");
    assert_eq!(post.target, Some(owner));

    let msg: SymbolDroppedMsg = from_cbor(&post.payload).unwrap();
    assert_eq!(msg.source_block_id, block);
    assert_eq!(msg.esi_ranges, vec![(5, 15), (20, 30)]);
    assert_eq!(msg.v, 1);
}
