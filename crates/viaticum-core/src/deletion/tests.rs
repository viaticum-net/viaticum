#![allow(clippy::cloned_ref_to_slice_refs)]

use crate::constants::{HOLDER_DELETE_COOLDOWN_SECS, OWNER_DELETE_COOLDOWN_SECS};
use crate::deletion::{
    DeletionAction, DeletionEngine, DeletionError, MarkDeletedResult, latest_deletion_per_block,
    live_referenced_blocks,
};
use crate::types::{
    DeviceId, FileId, FileRecord, FileVersion, LocalState, PackEntry, PlacementStatus,
    SourceBlockId, SourceBlockRecord, SourceBlockStatus, SourceBlockType, SymbolPlacement,
    Timestamp,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn device(n: u8) -> DeviceId {
    DeviceId([n; 32])
}

fn holder(n: u8) -> DeviceId {
    DeviceId([n; 32])
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

fn make_block(
    bid: SourceBlockId,
    status: SourceBlockStatus,
    block_type: SourceBlockType,
) -> SourceBlockRecord {
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
        drop_notice_sent_at: None,
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
    }
}

fn make_placement(
    bid: SourceBlockId,
    hid: DeviceId,
    fid: FileId,
    status: PlacementStatus,
) -> SymbolPlacement {
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

    let actions = engine.process_cooldowns(&[file], &[block], &[], now, 1);

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

    let actions = engine.process_cooldowns(&[file], &[block], &[p_a, p_b], now, 1);

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

    let actions = engine.process_cooldowns(&[file], &[block], &[p_a, p_b], now, 1);

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

    let actions = engine.process_cooldowns(&[file], &[block], &[p_a], now, 1);

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

    let actions = engine.process_cooldowns(&[file], &[block], &[p_a, p_b], now, 1);

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

    let actions = engine.process_cooldowns(&[file], &[block], &[], now, 1);

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
fn should_vacuum_returns_false_for_zero_files() {
    // CS-DEL-9: should_vacuum is a public API; total_files == 0 must return false,
    // not panic (an empty pack has nothing to vacuum).
    let engine = DeletionEngine::new();
    assert!(!engine.should_vacuum(0, 0));
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
                PackEntry {
                    file_id: fid1,
                    offset: 0,
                    size: 100,
                },
                PackEntry {
                    file_id: fid2,
                    offset: 100,
                    size: 100,
                },
                PackEntry {
                    file_id: fid3,
                    offset: 200,
                    size: 100,
                },
                PackEntry {
                    file_id: fid4,
                    offset: 300,
                    size: 100,
                },
            ],
        },
    );
    let block2 = make_block(bid2, SourceBlockStatus::Active, SourceBlockType::Single);

    let now = ts(1000);
    let actions = engine.process_cooldowns(&[f1, f2, f3, f4], &[block1, block2], &[], now, 1);

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

    let actions = engine.process_cooldowns(&[file], &[block], &[], now, 1);

    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, DeletionAction::VacuumBlock { .. }))
    );
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
                PackEntry {
                    file_id: fid1,
                    offset: 0,
                    size: 100,
                },
                PackEntry {
                    file_id: fid2,
                    offset: 100,
                    size: 100,
                },
            ],
        },
    );
    let now = ts(1000);

    let actions = engine.process_cooldowns(&[f1, f2], &[block], &[], now, 1);

    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, DeletionAction::VacuumBlock { .. }))
    );
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

    let actions1 =
        engine.process_cooldowns(&[file.clone()], &[block.clone()], &[p_a.clone()], now, 1);
    let actions2 = engine.process_cooldowns(&[file], &[block], &[p_a], now, 1);

    assert_eq!(actions1, actions2);
}

#[test]
fn process_cooldowns_empty_inputs_returns_empty() {
    let engine = DeletionEngine::new();
    let actions = engine.process_cooldowns(&[], &[], &[], ts(9_999_999), 1);
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
    let actions = engine.process_cooldowns(
        &[file.clone()],
        &[block.clone()],
        &[placement.clone()],
        before,
        1,
    );
    assert!(
        actions.is_empty(),
        "cooldown not yet elapsed — no actions expected"
    );

    // Exactly at owner cooldown expiry: SendDropNotice must be issued immediately
    let at_expiry = ts(deleted_at.0 + OWNER_DELETE_COOLDOWN_SECS);
    let actions = engine.process_cooldowns(&[file], &[block], &[placement], at_expiry, 1);
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
    let actions = engine.process_cooldowns(&[file], &[block], &[placement], much_later, 1);
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
        let actions = engine.process_cooldowns(
            &[file.clone()],
            &[block.clone()],
            &[placement.clone()],
            check_time,
            1,
        );
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
    let actions = engine.process_cooldowns(
        &[file],
        &[block_deleting],
        &[placement_deleting],
        delete_time,
        1,
    );
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, DeletionAction::CleanupPlacement { .. })),
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
        1,
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
    let actions_before = engine.process_cooldowns(
        &[file.clone()],
        &[block.clone()],
        &[placement.clone()],
        before,
        1,
    );
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
            1,
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, DeletionAction::SendDropNotice { .. })),
            "expected SendDropNotice at extra_weeks={extra_weeks}, got {actions:?}"
        );
    }
}

// ── delete-i3: release guard (live references, latest deletion per block) ────

fn make_backed_version(bid: SourceBlockId, backed_up_at: Option<u64>) -> FileVersion {
    FileVersion {
        backed_up_at: backed_up_at.map(ts),
        ..make_version(bid)
    }
}

fn make_pack(bid: SourceBlockId, status: SourceBlockStatus, fids: &[FileId]) -> SourceBlockRecord {
    let entries = fids
        .iter()
        .enumerate()
        .map(|(i, fid)| PackEntry {
            file_id: *fid,
            offset: i as u64 * 100,
            size: 100,
        })
        .collect();
    make_block(bid, status, SourceBlockType::Pack { entries })
}

/// Actions other than VacuumBlock (vacuum is advisory and not part of the release flow).
fn release_actions(actions: Vec<DeletionAction>) -> Vec<DeletionAction> {
    actions
        .into_iter()
        .filter(|a| !matches!(a, DeletionAction::VacuumBlock { .. }))
        .collect()
}

#[test]
fn deleted_and_present_records_on_same_block_emit_no_release_actions() {
    // Two paths with identical content dedup onto one Single block; one path deleted
    // long ago, the other still present.
    let engine = DeletionEngine::new();
    let dev = device(1);
    let bid = block_id(1);
    let deleted = make_file(
        file_id(1),
        vec![(dev, LocalState::Deleted(ts(0)))],
        vec![make_backed_version(bid, Some(0))],
    );
    let present = make_file(
        file_id(2),
        vec![(dev, LocalState::Present)],
        vec![make_backed_version(bid, Some(0))],
    );
    let block = make_block(bid, SourceBlockStatus::Active, SourceBlockType::Single);
    let placements = vec![
        make_placement(bid, holder(10), file_id(1), PlacementStatus::Alive),
        make_placement(bid, holder(11), file_id(1), PlacementStatus::Alive),
    ];
    let now = ts(10 * (OWNER_DELETE_COOLDOWN_SECS + HOLDER_DELETE_COOLDOWN_SECS));

    let actions = engine.process_cooldowns(&[deleted, present], &[block], &placements, now, 1);

    assert_eq!(actions, vec![]);
}

#[test]
fn pack_with_one_of_n_files_deleted_is_not_released() {
    let engine = DeletionEngine::new();
    let dev = device(1);
    let bid = block_id(1);
    let fids = [file_id(1), file_id(2), file_id(3), file_id(4)];
    let mut files = vec![make_file(
        fids[0],
        vec![(dev, LocalState::Deleted(ts(0)))],
        vec![make_backed_version(bid, Some(0))],
    )];
    for fid in &fids[1..] {
        files.push(make_file(
            *fid,
            vec![(dev, LocalState::Present)],
            vec![make_backed_version(bid, Some(0))],
        ));
    }
    let block = make_pack(bid, SourceBlockStatus::Active, &fids);
    let placements = vec![
        make_placement(bid, holder(10), fids[0], PlacementStatus::Alive),
        make_placement(bid, holder(11), fids[0], PlacementStatus::Alive),
    ];
    let now = ts(OWNER_DELETE_COOLDOWN_SECS + HOLDER_DELETE_COOLDOWN_SECS + 1);

    let actions = engine.process_cooldowns(&files, &[block], &placements, now, 1);

    assert_eq!(release_actions(actions), vec![]);
}

#[test]
fn pack_with_all_files_deleted_is_released() {
    let engine = DeletionEngine::new();
    let dev = device(1);
    let bid = block_id(1);
    let fids = [file_id(1), file_id(2), file_id(3)];
    let files: Vec<FileRecord> = fids
        .iter()
        .map(|fid| {
            make_file(
                *fid,
                vec![(dev, LocalState::Deleted(ts(0)))],
                vec![make_backed_version(bid, Some(0))],
            )
        })
        .collect();
    let placements = vec![
        make_placement(bid, holder(10), fids[0], PlacementStatus::Alive),
        make_placement(bid, holder(11), fids[0], PlacementStatus::Alive),
    ];

    // Owner window elapsed: one DropNotice per holder, not one per referencing record.
    let active = make_pack(bid, SourceBlockStatus::Active, &fids);
    let actions = engine.process_cooldowns(
        &files,
        &[active],
        &placements,
        ts(OWNER_DELETE_COOLDOWN_SECS),
        1,
    );
    assert_eq!(
        release_actions(actions),
        vec![
            DeletionAction::SendDropNotice {
                source_block_id: bid,
                holder_id: holder(10),
            },
            DeletionAction::SendDropNotice {
                source_block_id: bid,
                holder_id: holder(11),
            },
        ]
    );

    // Holder window elapsed: each placement cleaned once, CleanupBlock per deleted record.
    let deleting = make_pack(bid, SourceBlockStatus::Deleting, &fids);
    let placements: Vec<SymbolPlacement> = placements
        .into_iter()
        .map(|mut p| {
            p.status = PlacementStatus::Deleting;
            p
        })
        .collect();
    let actions = engine.process_cooldowns(
        &files,
        &[deleting],
        &placements,
        ts(OWNER_DELETE_COOLDOWN_SECS + HOLDER_DELETE_COOLDOWN_SECS),
        1,
    );
    let mut expected = vec![
        DeletionAction::CleanupPlacement {
            source_block_id: bid,
            holder_id: holder(10),
        },
        DeletionAction::CleanupPlacement {
            source_block_id: bid,
            holder_id: holder(11),
        },
    ];
    for fid in fids {
        expected.push(DeletionAction::CleanupBlock {
            source_block_id: bid,
            file_id: fid,
        });
    }
    assert_eq!(actions, expected);
}

#[test]
fn block_referenced_only_by_old_version_of_live_file_is_not_protected() {
    // Live file edited: v1 on old_bid, v2 (current, backed up) on new_bid. A deleted
    // record also points at old_bid. P2: old versions of live files are not held.
    let engine = DeletionEngine::new();
    let dev = device(1);
    let old_bid = block_id(1);
    let new_bid = block_id(2);
    let live = make_file(
        file_id(1),
        vec![(dev, LocalState::Present)],
        vec![
            make_backed_version(old_bid, Some(0)),
            make_backed_version(new_bid, Some(5)),
        ],
    );
    let deleted = make_file(
        file_id(2),
        vec![(dev, LocalState::Deleted(ts(0)))],
        vec![make_backed_version(old_bid, Some(0))],
    );
    let blocks = [
        make_block(old_bid, SourceBlockStatus::Active, SourceBlockType::Single),
        make_block(new_bid, SourceBlockStatus::Active, SourceBlockType::Single),
    ];
    let placements = vec![
        make_placement(old_bid, holder(10), file_id(1), PlacementStatus::Alive),
        make_placement(new_bid, holder(11), file_id(1), PlacementStatus::Alive),
    ];

    assert!(!live_referenced_blocks(&[live.clone(), deleted.clone()]).contains(&old_bid));
    let actions = engine.process_cooldowns(
        &[live, deleted],
        &blocks,
        &placements,
        ts(OWNER_DELETE_COOLDOWN_SECS),
        1,
    );

    assert_eq!(
        actions,
        vec![DeletionAction::SendDropNotice {
            source_block_id: old_bid,
            holder_id: holder(10),
        }]
    );
}

#[test]
fn live_referenced_blocks_includes_latest_and_latest_backed_up_version() {
    let dev = device(1);
    let oldest = block_id(1);
    let backed = block_id(2);
    let queued = block_id(3);
    let deleted_bid = block_id(4);
    let live = make_file(
        file_id(1),
        vec![(dev, LocalState::Present)],
        vec![
            make_backed_version(oldest, Some(1)),
            make_backed_version(backed, Some(2)),
            make_backed_version(queued, None),
        ],
    );
    let deleted = make_file(
        file_id(2),
        vec![(dev, LocalState::Deleted(ts(3)))],
        vec![make_backed_version(deleted_bid, Some(1))],
    );

    let live_blocks = live_referenced_blocks(&[live, deleted]);

    assert_eq!(live_blocks, [backed, queued].into_iter().collect());
}

#[test]
fn deleting_block_that_is_live_referenced_gets_no_cleanup_actions() {
    // DropNotice already went out (block Deleting, one placement Deleting), then a
    // live record started referencing the block again (restored file moved to a new
    // path). The guard stops the flow; it does not undo the DropNotice.
    let engine = DeletionEngine::new();
    let dev = device(1);
    let bid = block_id(1);
    let deleted = make_file(
        file_id(1),
        vec![(dev, LocalState::Deleted(ts(0)))],
        vec![make_backed_version(bid, Some(0))],
    );
    let moved = make_file(
        file_id(2),
        vec![(dev, LocalState::Present)],
        vec![make_backed_version(bid, Some(0))],
    );
    let block = make_block(bid, SourceBlockStatus::Deleting, SourceBlockType::Single);
    let placements = vec![
        make_placement(bid, holder(10), file_id(1), PlacementStatus::Deleting),
        make_placement(bid, holder(11), file_id(1), PlacementStatus::Alive),
    ];
    let now = ts(10 * (OWNER_DELETE_COOLDOWN_SECS + HOLDER_DELETE_COOLDOWN_SECS));

    let actions = engine.process_cooldowns(&[deleted, moved], &[block], &placements, now, 1);

    assert_eq!(actions, vec![]);
}

#[test]
fn record_with_no_devices_counts_as_live() {
    let engine = DeletionEngine::new();
    let bid = block_id(1);
    let orphan = make_file(file_id(1), vec![], vec![make_backed_version(bid, Some(0))]);
    let deleted = make_file(
        file_id(2),
        vec![(device(1), LocalState::Deleted(ts(0)))],
        vec![make_backed_version(bid, Some(0))],
    );
    let block = make_block(bid, SourceBlockStatus::Active, SourceBlockType::Single);
    let placements = vec![make_placement(
        bid,
        holder(10),
        file_id(2),
        PlacementStatus::Alive,
    )];

    assert!(live_referenced_blocks(&[orphan.clone()]).contains(&bid));
    let actions = engine.process_cooldowns(
        &[orphan, deleted],
        &[block],
        &placements,
        ts(OWNER_DELETE_COOLDOWN_SECS + HOLDER_DELETE_COOLDOWN_SECS),
        1,
    );

    assert_eq!(actions, vec![]);
}

#[test]
fn pack_member_deleted_later_keeps_its_own_undo_window() {
    // X1 deleted at t0; X2..X4 deleted at t1 > t0 + window. The block's owner window
    // runs from t1: nothing at t1 + window - 1, DropNotice at t1 + window.
    let engine = DeletionEngine::new();
    let dev = device(1);
    let bid = block_id(1);
    let fids = [file_id(1), file_id(2), file_id(3), file_id(4)];
    let t0 = 1_000;
    let t1 = t0 + OWNER_DELETE_COOLDOWN_SECS + HOLDER_DELETE_COOLDOWN_SECS + 7;
    let files: Vec<FileRecord> = fids
        .iter()
        .enumerate()
        .map(|(i, fid)| {
            let deleted_at = if i == 0 { t0 } else { t1 };
            make_file(
                *fid,
                vec![(dev, LocalState::Deleted(ts(deleted_at)))],
                vec![make_backed_version(bid, Some(0))],
            )
        })
        .collect();
    let block = make_pack(bid, SourceBlockStatus::Active, &fids);
    let placements = vec![make_placement(
        bid,
        holder(10),
        fids[0],
        PlacementStatus::Alive,
    )];

    let before = engine.process_cooldowns(
        &files,
        std::slice::from_ref(&block),
        &placements,
        ts(t1 + OWNER_DELETE_COOLDOWN_SECS - 1),
        1,
    );
    let at = engine.process_cooldowns(
        &files,
        &[block],
        &placements,
        ts(t1 + OWNER_DELETE_COOLDOWN_SECS),
        1,
    );

    assert_eq!(release_actions(before), vec![]);
    assert_eq!(
        release_actions(at),
        vec![DeletionAction::SendDropNotice {
            source_block_id: bid,
            holder_id: holder(10),
        }]
    );
}

#[test]
fn latest_deletion_per_block_takes_max_over_referencing_records() {
    let a = block_id(1);
    let b = block_id(2);
    let c = block_id(3);
    let files = vec![
        make_file(
            file_id(1),
            vec![(device(1), LocalState::Deleted(ts(50)))],
            vec![make_version(a)],
        ),
        make_file(
            file_id(2),
            vec![(device(1), LocalState::Deleted(ts(90)))],
            vec![make_version(a), make_version(b)],
        ),
        make_file(
            file_id(3),
            vec![(device(1), LocalState::Deleted(ts(70)))],
            vec![make_version(a)],
        ),
        // Multi-device record: deleted at the latest device deletion (120).
        make_file(
            file_id(4),
            vec![
                (device(1), LocalState::Deleted(ts(20))),
                (device(2), LocalState::Deleted(ts(120))),
            ],
            vec![make_version(b)],
        ),
        // Live record: contributes no deletion time.
        make_file(
            file_id(5),
            vec![(device(1), LocalState::Present)],
            vec![make_version(c)],
        ),
    ];

    let latest = latest_deletion_per_block(&files);

    assert_eq!(latest.len(), 2);
    assert_eq!(latest.get(&a), Some(&ts(90)));
    assert_eq!(latest.get(&b), Some(&ts(120)));
    assert_eq!(latest.get(&c), None);
}
