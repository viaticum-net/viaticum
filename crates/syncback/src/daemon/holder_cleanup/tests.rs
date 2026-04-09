// Tests for the holder cleanup module.

use syncback_core::db::Db;
use syncback_core::types::{HoldingRecord, HoldingStatus, IdentityPub, SourceBlockId, Timestamp};
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

// ─── test 1: cleanup_expired_deletes_files_and_posts_symbol_dropped ─────────

fn test_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32])
}

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
    let block_hex = syncback_core::types::hex_encode(&block.0);
    let block_dir = holdings_dir.path().join(&block_hex);
    tokio::fs::create_dir_all(&block_dir).await.unwrap();
    tokio::fs::write(block_dir.join("symbol_0.bin"), b"fake symbol data")
        .await
        .unwrap();

    // Use a `now` timestamp that is well past the cooldown.
    // cleanup_expired calls Timestamp::now() internally, so we rely on the
    // real wall-clock being >> HOLDER_DELETE_COOLDOWN_SECS (which is 4 weeks
    // in seconds, ~2.4 million). Any Unix timestamp past 2024 qualifies.
    super::cleanup_expired(&db, &holdings_dir.path().to_path_buf(), &relay_post_tx, 1, &test_key())
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
    super::cleanup_expired(&db, &holdings_dir.path().to_path_buf(), &relay_post_tx, 1, &test_key())
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
    // data_dir = holdings_dir (any existing path for statvfs).
    super::check_pressure(
        &db,
        &holdings_dir.path().to_path_buf(),
        &relay_post_tx,
        u64::MAX,
        0,
        &holdings_dir.path().to_path_buf(),
        0,
        &test_key(),
    )
    .await
    .unwrap();

    // No evictions should occur — relay_post_tx must remain empty.
    assert!(
        relay_post_rx.try_recv().is_err(),
        "no messages should be posted when disk pressure is Normal"
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
