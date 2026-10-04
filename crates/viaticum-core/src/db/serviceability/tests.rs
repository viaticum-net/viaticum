// L1b (backup-i21, P-C3): the serviceable-block rule and the reads inside a write txn.

use crate::db::Db;
use crate::db::testutil::test_db;
use crate::types::{
    DeviceId, FileId, PlacementStatus, SourceBlockId, SourceBlockRecord, SourceBlockStatus,
    SourceBlockType, SymbolPlacement, Timestamp,
};

use super::Serviceability;

fn block(seed: u8, status: SourceBlockStatus) -> SourceBlockRecord {
    SourceBlockRecord {
        seal_generation: 0,
        esi_high_water: 0,
        block_id: SourceBlockId([seed; 32]),
        k: 4,
        t: 1024,
        block_type: SourceBlockType::Single,
        status,
        created_at: Timestamp(1),
        encrypted_size: Some(4096),
        n: Some(8),
        overhead: Some(1.5),
        drop_notice_sent_at: None,
        importance: 0.5,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.9,
    }
}

fn placement(seed: u8, holder: u8, status: PlacementStatus) -> SymbolPlacement {
    SymbolPlacement {
        source_block_id: SourceBlockId([seed; 32]),
        holder_id: DeviceId([holder; 32]),
        file_id: FileId(1),
        esi_ranges: vec![(0, 4)],
        binding_seed: [0u8; 32],
        status,
        last_verified: None,
        placed_at: Timestamp(1),
        consecutive_misses: 0,
    }
}

fn of(db: &Db, seed: u8) -> Serviceability {
    db.block_serviceability(&SourceBlockId([seed; 32])).unwrap()
}

#[test]
fn serviceability_is_missing_without_record() {
    let db = test_db();
    // A placement without a record does not make the block exist.
    db.upsert_placement(&placement(1, 9, PlacementStatus::Alive))
        .unwrap();
    assert_eq!(of(&db, 1), Serviceability::Missing);
}

#[test]
fn serviceability_is_releasing_for_deleting_and_deleted_status() {
    let db = test_db();
    db.upsert_source_block(&block(1, SourceBlockStatus::Deleting))
        .unwrap();
    db.upsert_source_block(&block(2, SourceBlockStatus::Deleted))
        .unwrap();
    assert_eq!(of(&db, 1), Serviceability::Releasing);
    assert_eq!(of(&db, 2), Serviceability::Releasing);
}

#[test]
fn serviceability_is_releasing_when_active_block_has_a_deleting_placement() {
    let db = test_db();
    db.upsert_source_block(&block(1, SourceBlockStatus::Active))
        .unwrap();
    db.upsert_placement(&placement(1, 9, PlacementStatus::Alive))
        .unwrap();
    db.upsert_placement(&placement(1, 10, PlacementStatus::Deleting))
        .unwrap();
    assert_eq!(of(&db, 1), Serviceability::Releasing);
}

#[test]
fn serviceability_is_window_for_stale() {
    let db = test_db();
    db.upsert_source_block(&block(1, SourceBlockStatus::Stale))
        .unwrap();
    assert_eq!(of(&db, 1), Serviceability::Window);
    // A Deleting placement outranks the window.
    db.upsert_placement(&placement(1, 9, PlacementStatus::Deleting))
        .unwrap();
    assert_eq!(of(&db, 1), Serviceability::Releasing);
}

#[test]
fn serviceability_is_serviceable_for_active_without_deleting_placements() {
    let db = test_db();
    db.upsert_source_block(&block(1, SourceBlockStatus::Active))
        .unwrap();
    assert_eq!(of(&db, 1), Serviceability::Serviceable);
    for (holder, status) in [
        (9, PlacementStatus::Offered),
        (10, PlacementStatus::Alive),
        (11, PlacementStatus::Uncertain),
        (12, PlacementStatus::PresumedLost),
        (13, PlacementStatus::Lost),
    ] {
        db.upsert_placement(&placement(1, holder, status)).unwrap();
    }
    assert_eq!(of(&db, 1), Serviceability::Serviceable);
    assert!(of(&db, 1).is_serviceable());
    // Another block's Deleting placement does not leak into this one.
    db.upsert_placement(&placement(2, 9, PlacementStatus::Deleting))
        .unwrap();
    assert_eq!(of(&db, 1), Serviceability::Serviceable);
}

#[test]
fn write_txn_reads_its_own_block_and_placements() {
    let db = test_db();
    db.upsert_source_block(&block(1, SourceBlockStatus::Active))
        .unwrap();
    db.upsert_placement(&placement(1, 9, PlacementStatus::Alive))
        .unwrap();
    db.upsert_placement(&placement(2, 9, PlacementStatus::Alive))
        .unwrap();
    let id = SourceBlockId([1; 32]);

    let mut txn = db.write_txn().unwrap();
    // Committed state is visible.
    assert_eq!(
        txn.get_source_block(&id).unwrap().unwrap().status,
        SourceBlockStatus::Active
    );
    assert_eq!(txn.placements_for_block(&id).unwrap().len(), 1);
    assert_eq!(
        txn.block_serviceability(&id).unwrap(),
        Serviceability::Serviceable
    );
    // Its own uncommitted writes are visible to it, not to the committed view.
    txn.upsert_placement(&placement(1, 10, PlacementStatus::Deleting))
        .unwrap();
    txn.upsert_source_block(&block(3, SourceBlockStatus::Active))
        .unwrap();
    assert_eq!(txn.placements_for_block(&id).unwrap().len(), 2);
    assert_eq!(
        txn.block_serviceability(&id).unwrap(),
        Serviceability::Releasing
    );
    assert!(
        txn.get_source_block(&SourceBlockId([3; 32]))
            .unwrap()
            .is_some()
    );
    assert_eq!(
        txn.block_serviceability(&SourceBlockId([4; 32])).unwrap(),
        Serviceability::Missing
    );
    drop(txn);
    // Rolled back.
    assert_eq!(of(&db, 1), Serviceability::Serviceable);
    assert_eq!(of(&db, 3), Serviceability::Missing);
}
