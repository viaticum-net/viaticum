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
        n: None,
        overhead: None,
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

// ─── DEL-13: single device deletion cooldown starts immediately ─────────────

#[test]
fn single_device_deletion_cooldown_starts_immediately() {
    // With only one device, deleting it triggers the cooldown right away —
    // no waiting for other devices (there are none).
    let engine = DeletionEngine::new();
    let dev_a = device(1);
    let fid = file_id(10);
    let bid = block_id(10);
    let holder_a = holder(20);

    let deleted_at = ts(1_000_000);

    let file = make_file(
        fid,
        vec![(dev_a, LocalState::Deleted(deleted_at))],
        vec![make_version(bid)],
    );
    let block = make_block(bid, SourceBlockStatus::Active, SourceBlockType::Single);
    let placement = make_placement(bid, holder_a, fid, PlacementStatus::Alive);

    // Before owner cooldown: no actions
    let before = ts(deleted_at.0 + OWNER_DELETE_COOLDOWN_SECS - 1);
    let actions = engine.process_cooldowns(&[file.clone()], &[block.clone()], &[placement.clone()], before);
    assert!(
        actions.is_empty(),
        "cooldown not yet elapsed — no actions expected"
    );

    // Exactly at owner cooldown expiry: SendDropNotice must be issued immediately
    let at_expiry = ts(deleted_at.0 + OWNER_DELETE_COOLDOWN_SECS);
    let actions = engine.process_cooldowns(&[file], &[block], &[placement], at_expiry);
    assert!(
        actions.contains(&DeletionAction::SendDropNotice {
            source_block_id: bid,
            holder_id: holder_a,
        }),
        "single-device file must start owner cooldown immediately upon deletion"
    );
}

#[test]
fn multi_device_deletion_cooldown_starts_only_when_all_deleted() {
    // With two devices, the cooldown does NOT start until both are deleted.
    // Contrast with single-device: the engine waits for the second device.
    let engine = DeletionEngine::new();
    let dev_a = device(1);
    let dev_b = device(2);
    let fid = file_id(11);
    let bid = block_id(11);
    let holder_a = holder(21);

    let dev_a_deleted_at = ts(1_000_000);

    // Only dev_a deleted; dev_b still Present
    let file = make_file(
        fid,
        vec![
            (dev_a, LocalState::Deleted(dev_a_deleted_at)),
            (dev_b, LocalState::Present),
        ],
        vec![make_version(bid)],
    );
    let block = make_block(bid, SourceBlockStatus::Active, SourceBlockType::Single);
    let placement = make_placement(bid, holder_a, fid, PlacementStatus::Alive);

    // Even well after dev_a cooldown would have expired: no actions because dev_b is Present
    let much_later = ts(dev_a_deleted_at.0 + OWNER_DELETE_COOLDOWN_SECS + 1_000_000);
    let actions = engine.process_cooldowns(&[file], &[block], &[placement], much_later);
    assert!(
        actions.is_empty(),
        "cooldown must not start until all devices are deleted"
    );
}

// ─── DEL-11: ransomware protection ──────────────────────────────────────────

#[test]
fn ransomware_protection_no_physical_delete_before_8_weeks() {
    // Scenario: file backed up, then ransomware deletes it 2 days later.
    // The 8-week cooldown (4 owner + 4 holder) must protect the backup.
    let engine = DeletionEngine::new();
    let dev_a = device(1);
    let fid = file_id(1);
    let bid = block_id(1);
    let holder_a = holder(10);

    let backup_time = ts(1_000_000);
    let ransomware_time = ts(backup_time.0 + 2 * 86_400); // 2 days later

    let file = make_file(
        fid,
        vec![(dev_a, LocalState::Deleted(ransomware_time))],
        vec![make_version(bid)],
    );
    let block = make_block(bid, SourceBlockStatus::Active, SourceBlockType::Single);
    let placement = make_placement(bid, holder_a, fid, PlacementStatus::Alive);

    // At every point before 8 weeks: no CleanupPlacement/CleanupBlock
    let eight_weeks = OWNER_DELETE_COOLDOWN_SECS + HOLDER_DELETE_COOLDOWN_SECS;
    for weeks in 0..8 {
        let check_time = ts(ransomware_time.0 + weeks * 7 * 86_400);
        let actions =
            engine.process_cooldowns(&[file.clone()], &[block.clone()], &[placement.clone()], check_time);
        assert!(
            !actions.iter().any(|a| matches!(
                a,
                DeletionAction::CleanupPlacement { .. } | DeletionAction::CleanupBlock { .. }
            )),
            "physical delete must not happen at week {weeks}"
        );
    }

    // At exactly 8 weeks (owner cooldown + holder cooldown): physical delete happens
    let delete_time = ts(ransomware_time.0 + eight_weeks);
    let block_deleting = make_block(bid, SourceBlockStatus::Deleting, SourceBlockType::Single);
    let placement_deleting = make_placement(bid, holder_a, fid, PlacementStatus::Deleting);
    let actions =
        engine.process_cooldowns(&[file], &[block_deleting], &[placement_deleting], delete_time);
    assert!(
        actions.iter().any(|a| matches!(a, DeletionAction::CleanupPlacement { .. })),
        "physical delete should happen at 8 weeks"
    );
}

// ─── DEL-12: cancel delete in owner cooldown reverses deletion ───────────────

#[test]
fn cancel_delete_in_owner_cooldown_reverses_deletion() {
    // Scenario: device A deletes the file (cooldown starts), but then the
    // delete is cancelled — device A is set back to Present (simulating
    // CancelDelete/user restores the file before the cooldown expires).
    // Even at a time past the original cooldown expiry, process_cooldowns
    // must produce NO delete actions because the file has a Present device.
    let engine = DeletionEngine::new();
    let dev_a = device(1);
    let fid = file_id(100);
    let bid = block_id(100);
    let holder_a = holder(50);

    let deleted_at = ts(1_000_000);

    // After CancelDelete: device is back to Present.
    // This is what the daemon would persist after receiving a cancel signal.
    let file_after_cancel = make_file(
        fid,
        vec![(dev_a, LocalState::Present)],
        vec![make_version(bid)],
    );
    let block = make_block(bid, SourceBlockStatus::Active, SourceBlockType::Single);
    let placement = make_placement(bid, holder_a, fid, PlacementStatus::Alive);

    // Check at a time well after the original cooldown would have expired
    let after_cooldown = ts(deleted_at.0 + OWNER_DELETE_COOLDOWN_SECS + 1_000_000);
    let actions = engine.process_cooldowns(
        &[file_after_cancel],
        &[block],
        &[placement],
        after_cooldown,
    );

    assert!(
        actions.is_empty(),
        "after CancelDelete (device Present), no delete actions must be produced; got: {actions:?}"
    );
}

// ─── PROP-18: process_cooldowns delete actions monotone in time ───────────────

#[test]
fn should_delete_now_monotone_in_time() {
    // If process_cooldowns produces a SendDropNotice action at time T,
    // it must also produce it at any time T' > T (monotone in time).
    // We test with: file deleted at t=0, block Active, one holder Alive.
    let engine = DeletionEngine::new();
    let dev_a = device(1);
    let fid = file_id(42);
    let bid = block_id(42);
    let holder_a = holder(42);

    let file = make_file(
        fid,
        vec![(dev_a, LocalState::Deleted(ts(0)))],
        vec![make_version(bid)],
    );
    let block = make_block(bid, SourceBlockStatus::Active, SourceBlockType::Single);
    let placement = make_placement(bid, holder_a, fid, PlacementStatus::Alive);

    // Before owner cooldown: no actions.
    let before = ts(OWNER_DELETE_COOLDOWN_SECS - 1);
    let actions_before = engine.process_cooldowns(&[file.clone()], &[block.clone()], &[placement.clone()], before);
    assert!(
        actions_before.is_empty(),
        "expected no actions before owner cooldown, got {actions_before:?}"
    );

    // From the owner cooldown boundary onward: SendDropNotice must be present
    // at every subsequent week-step (monotone property).
    let week_secs = 7 * 24 * 3600_u64;
    for extra_weeks in 0u64..6 {
        let check_time = ts(OWNER_DELETE_COOLDOWN_SECS + extra_weeks * week_secs);
        let actions = engine.process_cooldowns(
            &[file.clone()],
            &[block.clone()],
            &[placement.clone()],
            check_time,
        );
        assert!(
            actions.iter().any(|a| matches!(a, DeletionAction::SendDropNotice { .. })),
            "expected SendDropNotice at extra_weeks={extra_weeks}, got {actions:?}"
        );
    }
}
