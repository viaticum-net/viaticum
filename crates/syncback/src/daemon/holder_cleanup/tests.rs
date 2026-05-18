// Tests for the holder cleanup module.

use syncback_core::db::Db;
use syncback_core::types::{HoldingRecord, HoldingStatus, IdentityPub, SourceBlockId, Timestamp};
use tempfile::TempDir;
use tokio::sync::mpsc;

use crate::daemon::relay::RelayPost;

// ─── W13 holder-side drop notice tests ───────────────────────────────────────

/// Build a Hard-pressure scenario:
/// - quota = 1000 bytes
/// - used = 960 bytes (free_ratio = 0.04 < HARD_PRESSURE_THRESHOLD=0.05 → Hard)
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
) {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (relay_post_tx, relay_post_rx) = mpsc::channel::<RelayPost>(16);

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
    db.upsert_holding(&holding_a).unwrap();
    db.upsert_holding(&holding_b).unwrap();

    (db, holdings_dir, relay_post_tx, relay_post_rx, holding_b)
}

/// Test: under hard pressure with a buffer zone holding, check_pressure sends a
/// SymbolDropNotice and records `drop_notice_sent_at` in the DB.
///
/// quota = 1000, used = 960 → free_ratio=0.04 → Hard.
/// Holding A (600 bytes, low priority) covers deficit (110 bytes).
/// Holding B (350 bytes, higher priority) is in buffer zone → DropNotice.
#[tokio::test]
async fn holder_pressure_sets_drop_notice_sent_at_on_first_send() {
    let (db, holdings_dir, relay_post_tx, mut relay_post_rx, holding_b) =
        setup_hard_pressure_with_buffer_zone().await;

    // soft_quota_bytes = 1000. data_dir = holdings_dir (any real path for statvfs).
    // Disk free >> 1000, so effective_quota = min(1000, disk_free) = 1000.
    // used_bytes = 600 + 350 = 950. Wait — we need used > 0.95 * 1000 = 950.
    // Let me use 960: add a 10-byte dummy to holdings.
    // Actually, used_bytes from DB = sum of total_bytes = 600 + 350 = 950.
    // 950 / 1000 = 0.95. free_ratio = 0.05 = HARD_PRESSURE_THRESHOLD exactly.
    // Need free_ratio < 0.05, so used > 950. Add a 20-byte holding to tip it over.
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
    db.upsert_holding(&top_up).unwrap();
    // used = 970, free = 30, free_ratio = 0.03 < 0.05 → Hard ✓

    super::check_pressure(
        &db,
        &holdings_dir.path().to_path_buf(),
        &relay_post_tx,
        1000,        // soft_quota_bytes
        0,           // hard_quota_bytes = 0 (no floor)
        &holdings_dir.path().to_path_buf(),
        0,           // disk_reserve_bytes
        &test_key(),
    )
    .await
    .unwrap();

    // At least one DropNotice should have been sent (holding B is in buffer zone).
    let mut drop_notice_found = false;
    while let Ok(post) = relay_post_rx.try_recv() {
        if post.msg_type == "symbol_drop_notice" {
            drop_notice_found = true;
        }
    }
    assert!(drop_notice_found, "check_pressure must post a symbol_drop_notice for the buffer-zone holding");

    // DB must have recorded drop_notice_sent_at for holding B.
    let updated_b = db
        .get_holding(&holding_b.source_block_id, &holding_b.owner_id)
        .unwrap();
    match updated_b {
        Some(h) => {
            assert!(
                h.drop_notice_sent_at.is_some(),
                "drop_notice_sent_at must be set after first send"
            );
        }
        None => {
            // Holding B should be in the buffer zone — it must NOT be immediately
            // evicted. If it's gone, the test setup arithmetic is wrong and the
            // assertion above is silently skipped. Fail loud to surface this.
            panic!("holding B was evicted instead of receiving DropNotice — \
                    setup_hard_pressure_with_buffer_zone arithmetic is off");
        }
    }
}

/// Test: when `drop_notice_sent_at` is already set on a holding, `check_pressure`
/// does NOT update the DB record again (the timestamp is not overwritten).
///
/// The underlying SymbolDropNotice message is sent again (this is expected behavior —
/// the deduplication is caller-side via `cleanup_drop_notices` expiry), but the
/// `drop_notice_sent_at` field in the DB must not be overwritten with a later timestamp.
#[tokio::test]
async fn holder_drop_notice_sent_at_not_overwritten_on_second_send() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (relay_post_tx, _relay_post_rx) = mpsc::channel::<RelayPost>(16);

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

    // Even if check_pressure runs under hard pressure, the sent_at timestamp
    // must remain `earlier_time` and not be overwritten by a newer value.
    // Simulate by calling the guard directly: if sent_at is Some, skip DB write.
    // We verify by reading the DB record after a hypothetical second send.

    // Directly test the guard: after upserting a holding with sent_at=Some,
    // calling upsert again with sent_at=None should NOT happen in the real code.
    // Verify: the DB record still has the original earlier_time after a second
    // call to check_pressure.

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
        &holdings_dir.path().to_path_buf(),
        &relay_post_tx,
        100,         // soft_quota_bytes = 100 → effective_quota = min(100, disk_free) = 100
        0,           // hard_quota_bytes = 0 (no floor)
        &holdings_dir.path().to_path_buf(),
        0,           // disk_reserve_bytes
        &test_key(),
    )
    .await
    .unwrap();

    // The holding must survive (its `drop_notice_sent_at` was already set;
    // setup_hard_pressure_with_buffer_zone places it in the buffer zone, not
    // for immediate eviction). If it's gone, the setup arithmetic is wrong
    // and the contract test below is silently skipped — fail loud.
    let updated = db
        .get_holding(&holding.source_block_id, &holding.owner_id)
        .expect("db query failed")
        .expect("holding was evicted instead of surviving in buffer zone — \
                 setup_hard_pressure_with_buffer_zone arithmetic is off");
    assert_eq!(
        updated.drop_notice_sent_at,
        Some(earlier_time),
        "drop_notice_sent_at must not be overwritten when already set"
    );
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
