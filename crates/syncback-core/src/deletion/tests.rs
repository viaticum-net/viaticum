use crate::constants::{HOLDER_DELETE_COOLDOWN_SECS, OWNER_DELETE_COOLDOWN_SECS};
use crate::deletion::{DeletionAction, DeletionEngine, DeletionError, MarkDeletedResult};
use crate::types::{
    DeviceId, FileId, FileRecord, FileVersion, IdentityPub, LocalState, PackEntry, PlacementStatus,
    SourceBlockId, SourceBlockRecord, SourceBlockStatus, SourceBlockType, SymbolPlacement,
    Timestamp,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn device(n: u8) -> DeviceId {
    DeviceId([n; 16])
}

fn holder(n: u8) -> IdentityPub {
    IdentityPub([n; 32])
}

fn block_id(n: u8) -> SourceBlockId {
    SourceBlockId([n; 32])
}

fn file_id(n: u64) -> FileId {
    FileId(n)
}

fn ts(secs: u64) -> Timestamp {
    Timestamp(secs)
}

fn make_file(
    fid: FileId,
    devices: Vec<(DeviceId, LocalState)>,
    versions: Vec<FileVersion>,
) -> FileRecord {
    FileRecord {
        file_id: fid,
        path: format!("/test/{}", fid.0),
        importance: 0.5,
        devices,
        versions,
        first_seen: ts(0),
    }
}

fn make_version(bid: SourceBlockId) -> FileVersion {
    FileVersion {
        content_hash: [0u8; 32],
        source_block_id: bid,
        k: 1,
        t: 1024,
        created_at: ts(0),
        backed_up_at: None,
    }
}

fn make_block(bid: SourceBlockId, status: SourceBlockStatus, block_type: SourceBlockType) -> SourceBlockRecord {
    SourceBlockRecord {
        block_id: bid,
        k: 1,
        t: 1024,
        block_type,
        status,
        created_at: ts(0),
        encrypted_size: None,
    }
}

fn make_placement(bid: SourceBlockId, hid: IdentityPub, fid: FileId, status: PlacementStatus) -> SymbolPlacement {
    SymbolPlacement {
        source_block_id: bid,
        holder_id: hid,
        file_id: fid,
        esi_ranges: vec![(0, 10)],
        binding_seed: [0u8; 32],
        status,
        last_verified: None,
        placed_at: ts(0),
        consecutive_misses: 0,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn mark_deleted_single_device_starts_cooldown() {
    let engine = DeletionEngine::new();
    let dev_a = device(1);
    let fid = file_id(1);
    let record = make_file(fid, vec![(dev_a, LocalState::Present)], vec![]);

    let result = engine.mark_deleted(&record, dev_a, ts(1000)).unwrap();

    assert_eq!(
        result,
        MarkDeletedResult::CooldownStarted {
            deleted_at: ts(1000),
            notify_after: ts(1000 + OWNER_DELETE_COOLDOWN_SECS),
        }
    );
}

#[test]
fn mark_deleted_multi_device_waits_for_others() {
    let engine = DeletionEngine::new();
    let dev_a = device(1);
    let dev_b = device(2);
    let fid = file_id(1);
    let record = make_file(
        fid,
        vec![(dev_a, LocalState::Present), (dev_b, LocalState::Present)],
        vec![],
    );

    let result = engine.mark_deleted(&record, dev_a, ts(1000)).unwrap();

    assert_eq!(result, MarkDeletedResult::WaitForOtherDevices);
}

#[test]
fn mark_deleted_last_device_starts_cooldown() {
    let engine = DeletionEngine::new();
    let dev_a = device(1);
    let dev_b = device(2);
    let fid = file_id(1);
    let record = make_file(
        fid,
        vec![
            (dev_a, LocalState::Deleted(ts(500))),
            (dev_b, LocalState::Present),
        ],
        vec![],
    );

    let result = engine.mark_deleted(&record, dev_b, ts(1000)).unwrap();

    assert_eq!(
        result,
        MarkDeletedResult::CooldownStarted {
            deleted_at: ts(1000),
            notify_after: ts(1000 + OWNER_DELETE_COOLDOWN_SECS),
        }
    );
}

#[test]
fn mark_deleted_unknown_device_returns_error() {
    let engine = DeletionEngine::new();
    let dev_a = device(1);
    let dev_b = device(2);
    let fid = file_id(1);
    let record = make_file(fid, vec![(dev_a, LocalState::Present)], vec![]);

    let err = engine.mark_deleted(&record, dev_b, ts(1000)).unwrap_err();

    assert!(matches!(err, DeletionError::DeviceNotFound(f, d) if f == fid && d == dev_b));
}

#[test]
fn process_cooldowns_owner_cooldown_not_elapsed() {
    let engine = DeletionEngine::new();
    let dev_a = device(1);
    let fid = file_id(1);
    let bid = block_id(1);

    let file = make_file(
        fid,
        vec![(dev_a, LocalState::Deleted(ts(0)))],
        vec![make_version(bid)],
    );
    let block = make_block(bid, SourceBlockStatus::Active, SourceBlockType::Single);
    let now = ts(OWNER_DELETE_COOLDOWN_SECS - 1);

    let actions = engine.process_cooldowns(&[file], &[block], &[], now);

    assert!(actions.is_empty());
}

#[test]
fn process_cooldowns_sends_drop_notice_at_owner_cooldown_expiry() {
    let engine = DeletionEngine::new();
    let dev_a = device(1);
    let fid = file_id(1);
    let bid = block_id(1);
    let holder_a = holder(10);
    let holder_b = holder(11);

    let file = make_file(
        fid,
        vec![(dev_a, LocalState::Deleted(ts(0)))],
        vec![make_version(bid)],
    );
    let block = make_block(bid, SourceBlockStatus::Active, SourceBlockType::Single);
    let p_a = make_placement(bid, holder_a, fid, PlacementStatus::Alive);
    let p_b = make_placement(bid, holder_b, fid, PlacementStatus::Alive);
    let now = ts(OWNER_DELETE_COOLDOWN_SECS);

    let actions = engine.process_cooldowns(&[file], &[block], &[p_a, p_b], now);

    assert_eq!(actions.len(), 2);
    assert!(actions.contains(&DeletionAction::SendDropNotice {
        source_block_id: bid,
        holder_id: holder_a,
    }));
    assert!(actions.contains(&DeletionAction::SendDropNotice {
        source_block_id: bid,
        holder_id: holder_b,
    }));
}

#[test]
fn process_cooldowns_skip_already_deleting_placements() {
    let engine = DeletionEngine::new();
    let dev_a = device(1);
    let fid = file_id(1);
    let bid = block_id(1);
    let holder_a = holder(10);
    let holder_b = holder(11);

    let file = make_file(
        fid,
        vec![(dev_a, LocalState::Deleted(ts(0)))],
        vec![make_version(bid)],
    );
    let block = make_block(bid, SourceBlockStatus::Deleting, SourceBlockType::Single);
    let p_a = make_placement(bid, holder_a, fid, PlacementStatus::Deleting);
    let p_b = make_placement(bid, holder_b, fid, PlacementStatus::Alive);
    let now = ts(OWNER_DELETE_COOLDOWN_SECS + 10);

    let actions = engine.process_cooldowns(&[file], &[block], &[p_a, p_b], now);

    assert_eq!(actions.len(), 1);
    assert_eq!(
        actions[0],
        DeletionAction::SendDropNotice {
            source_block_id: bid,
            holder_id: holder_b,
        }
    );
}

#[test]
fn process_cooldowns_cleanup_after_holder_cooldown() {
    let engine = DeletionEngine::new();
    let dev_a = device(1);
    let fid = file_id(1);
    let bid = block_id(1);
    let holder_a = holder(10);

    let file = make_file(
        fid,
        vec![(dev_a, LocalState::Deleted(ts(0)))],
        vec![make_version(bid)],
    );
    let block = make_block(bid, SourceBlockStatus::Deleting, SourceBlockType::Single);
    let p_a = make_placement(bid, holder_a, fid, PlacementStatus::Deleting);
    let now = ts(OWNER_DELETE_COOLDOWN_SECS + HOLDER_DELETE_COOLDOWN_SECS);

    let actions = engine.process_cooldowns(&[file], &[block], &[p_a], now);

    assert!(actions.contains(&DeletionAction::CleanupPlacement {
        source_block_id: bid,
        holder_id: holder_a,
    }));
    assert!(actions.contains(&DeletionAction::CleanupBlock {
        source_block_id: bid,
        file_id: fid,
    }));
}

#[test]
fn process_cooldowns_cleanup_waits_for_all_holders() {
    let engine = DeletionEngine::new();
    let dev_a = device(1);
    let fid = file_id(1);
    let bid = block_id(1);
    let holder_a = holder(10);
    let holder_b = holder(11);

    let file = make_file(
        fid,
        vec![(dev_a, LocalState::Deleted(ts(0)))],
        vec![make_version(bid)],
    );
    let block = make_block(bid, SourceBlockStatus::Deleting, SourceBlockType::Single);
    let p_a = make_placement(bid, holder_a, fid, PlacementStatus::Deleting);
    let p_b = make_placement(bid, holder_b, fid, PlacementStatus::Alive);
    let now = ts(OWNER_DELETE_COOLDOWN_SECS + HOLDER_DELETE_COOLDOWN_SECS);

    let actions = engine.process_cooldowns(&[file], &[block], &[p_a, p_b], now);

    assert!(actions.contains(&DeletionAction::CleanupPlacement {
        source_block_id: bid,
        holder_id: holder_a,
    }));
    assert!(actions.contains(&DeletionAction::SendDropNotice {
        source_block_id: bid,
        holder_id: holder_b,
    }));
    assert!(!actions.contains(&DeletionAction::CleanupBlock {
        source_block_id: bid,
        file_id: fid,
    }));
}

#[test]
fn process_cooldowns_file_still_present_on_one_device_skipped() {
    let engine = DeletionEngine::new();
    let dev_a = device(1);
    let dev_b = device(2);
    let fid = file_id(1);
    let bid = block_id(1);

    let file = make_file(
        fid,
        vec![
            (dev_a, LocalState::Deleted(ts(0))),
            (dev_b, LocalState::Present),
        ],
        vec![make_version(bid)],
    );
    let block = make_block(bid, SourceBlockStatus::Active, SourceBlockType::Single);
    let now = ts(OWNER_DELETE_COOLDOWN_SECS + 1_000_000);

    let actions = engine.process_cooldowns(&[file], &[block], &[], now);

    assert!(actions.is_empty());
}

#[test]
fn should_vacuum_above_threshold() {
    let engine = DeletionEngine::new();
    assert!(engine.should_vacuum(10, 6));
}

#[test]
fn should_vacuum_at_threshold_returns_false() {
    let engine = DeletionEngine::new();
    assert!(!engine.should_vacuum(10, 5));
}

#[test]
fn should_vacuum_below_threshold() {
    let engine = DeletionEngine::new();
    assert!(!engine.should_vacuum(10, 4));
}

#[test]
fn should_vacuum_all_invalid() {
    let engine = DeletionEngine::new();
    assert!(engine.should_vacuum(5, 5));
}

#[test]
fn should_vacuum_one_invalid_of_two() {
    let engine = DeletionEngine::new();
    // 1/2 = 0.50 exactly — not strictly greater
    assert!(!engine.should_vacuum(2, 1));
}

#[test]
fn process_cooldowns_vacuum_triggered_for_stale_pack() {
    let engine = DeletionEngine::new();
    let bid1 = block_id(1);
    let bid2 = block_id(2);

    let fid1 = file_id(1); // valid: latest version → B1
    let fid2 = file_id(2); // superseded: latest version → B2
    let fid3 = file_id(3); // all devices deleted
    let fid4 = file_id(4); // no version pointing to B1

    let dev_a = device(1);

    let f1 = make_file(
        fid1,
        vec![(dev_a, LocalState::Present)],
        vec![make_version(bid1)],
    );
    let f2 = make_file(
        fid2,
        vec![(dev_a, LocalState::Present)],
        vec![make_version(bid1), make_version(bid2)],
    );
    let f3 = make_file(
        fid3,
        vec![(dev_a, LocalState::Deleted(ts(100)))],
        vec![make_version(bid1)],
    );
    let f4 = make_file(
        fid4,
        vec![(dev_a, LocalState::Present)],
        vec![make_version(bid2)],
    );

    let block1 = make_block(
        bid1,
        SourceBlockStatus::Active,
        SourceBlockType::Pack {
            entries: vec![
                PackEntry { file_id: fid1, offset: 0, size: 100 },
                PackEntry { file_id: fid2, offset: 100, size: 100 },
                PackEntry { file_id: fid3, offset: 200, size: 100 },
                PackEntry { file_id: fid4, offset: 300, size: 100 },
            ],
        },
    );
    let block2 = make_block(bid2, SourceBlockStatus::Active, SourceBlockType::Single);

    let now = ts(1000);
    let actions = engine.process_cooldowns(&[f1, f2, f3, f4], &[block1, block2], &[], now);

    assert_eq!(actions.len(), 1);
    assert!(matches!(
        &actions[0],
        DeletionAction::VacuumBlock { source_block_id, valid_file_ids }
        if *source_block_id == bid1 && *valid_file_ids == vec![fid1]
    ));
}

#[test]
fn process_cooldowns_no_vacuum_for_single_block_type() {
    let engine = DeletionEngine::new();
    let bid = block_id(1);
    let fid = file_id(1);
    let dev_a = device(1);

    let file = make_file(
        fid,
        vec![(dev_a, LocalState::Deleted(ts(0)))],
        vec![make_version(bid)],
    );
    let block = make_block(bid, SourceBlockStatus::Active, SourceBlockType::Single);
    let now = ts(1000);

    let actions = engine.process_cooldowns(&[file], &[block], &[], now);

    assert!(!actions.iter().any(|a| matches!(a, DeletionAction::VacuumBlock { .. })));
}

#[test]
fn process_cooldowns_no_vacuum_for_stale_block() {
    let engine = DeletionEngine::new();
    let bid = block_id(1);
    let fid1 = file_id(1);
    let fid2 = file_id(2);
    let dev_a = device(1);

    let f1 = make_file(
        fid1,
        vec![(dev_a, LocalState::Deleted(ts(0)))],
        vec![make_version(bid)],
    );
    let f2 = make_file(
        fid2,
        vec![(dev_a, LocalState::Deleted(ts(0)))],
        vec![make_version(bid)],
    );
    let block = make_block(
        bid,
        SourceBlockStatus::Stale,
        SourceBlockType::Pack {
            entries: vec![
                PackEntry { file_id: fid1, offset: 0, size: 100 },
                PackEntry { file_id: fid2, offset: 100, size: 100 },
            ],
        },
    );
    let now = ts(1000);

    let actions = engine.process_cooldowns(&[f1, f2], &[block], &[], now);

    assert!(!actions.iter().any(|a| matches!(a, DeletionAction::VacuumBlock { .. })));
}

#[test]
fn process_cooldowns_idempotent() {
    let engine = DeletionEngine::new();
    let dev_a = device(1);
    let fid = file_id(1);
    let bid = block_id(1);
    let holder_a = holder(10);

    let file = make_file(
        fid,
        vec![(dev_a, LocalState::Deleted(ts(0)))],
        vec![make_version(bid)],
    );
    let block = make_block(bid, SourceBlockStatus::Active, SourceBlockType::Single);
    let p_a = make_placement(bid, holder_a, fid, PlacementStatus::Alive);
    let now = ts(OWNER_DELETE_COOLDOWN_SECS + 100);

    let actions1 = engine.process_cooldowns(&[file.clone()], &[block.clone()], &[p_a.clone()], now);
    let actions2 = engine.process_cooldowns(&[file], &[block], &[p_a], now);

    assert_eq!(actions1, actions2);
}

#[test]
fn process_cooldowns_empty_inputs_returns_empty() {
    let engine = DeletionEngine::new();
    let actions = engine.process_cooldowns(&[], &[], &[], ts(9_999_999));
    assert!(actions.is_empty());
}
