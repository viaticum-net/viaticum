use super::*;
use crate::deletion::{DeletionEngine, MarkDeletedResult};
use crate::system_state::{BlockRef, sign_self_pointer};
use crate::types::{FileId, SourceBlockId};

fn master() -> ed25519_dalek::SigningKey {
    crate::cluster::derive_master_key(&[5u8; 32]).unwrap()
}

fn lineage(b: u8) -> CatalogLineageId {
    CatalogLineageId([b; 16])
}

fn device(b: u8) -> DeviceId {
    DeviceId([b; 32])
}

/// A signed pointer of history `l` with `files` live files, published by device 0xD0.
fn pointer(l: CatalogLineageId, files: u32, created_at: u64, generation: u32) -> SelfPointer {
    sign_self_pointer(
        &master(),
        generation,
        BlockRef {
            block_id: SourceBlockId([generation as u8; 32]),
            holders: vec![],
            encrypted_size: 100,
        },
        vec![],
        Timestamp(created_at),
        CatalogSummary {
            lineage: l,
            publisher: device(0xD0),
            files,
        },
    )
}

fn file(path: &str, devices: Vec<(DeviceId, LocalState)>) -> FileRecord {
    FileRecord {
        file_id: FileId(1),
        path: path.to_string(),
        importance: 0.5,
        devices,
        versions: vec![],
        first_seen: Timestamp(1),
    }
}

// ── select_catalog ──────────────────────────────────────────────────────────

#[test]
fn select_catalog_single_lineage_picks_freshest_pointer() {
    let l = lineage(1);
    let got = select_catalog(
        vec![
            pointer(l, 3, 100, 1),
            pointer(l, 3, 300, 1),
            pointer(l, 3, 200, 2),
        ],
        None,
    )
    .unwrap();
    assert_eq!(got.reason, ChoiceReason::OnlyCatalog);
    assert_eq!(got.selected.created_at, Timestamp(300));
    assert_eq!(got.rows.len(), 1);
    assert_eq!(got.rows[0].created_at, Timestamp(300));
}

#[test]
fn select_catalog_within_lineage_newer_smaller_wins() {
    // Honest deletions inside one history: the newer, smaller pointer is the catalog.
    let l = lineage(1);
    let got = select_catalog(vec![pointer(l, 10, 100, 1), pointer(l, 4, 200, 2)], None).unwrap();
    assert_eq!(got.selected.catalog.files, 4);
    assert_eq!(got.rows[0].files, 4);
}

#[test]
fn select_catalog_generation_breaks_created_at_tie_inside_lineage() {
    let l = lineage(1);
    let got = select_catalog(vec![pointer(l, 3, 100, 4), pointer(l, 3, 100, 7)], None).unwrap();
    assert_eq!(got.selected.generation, 7);
}

#[test]
fn select_catalog_counts_distinct_pointers_per_lineage() {
    let l = lineage(1);
    let p = pointer(l, 3, 100, 1);
    let got = select_catalog(vec![p.clone(), p.clone(), p, pointer(l, 3, 200, 2)], None).unwrap();
    assert_eq!(got.rows[0].pointers_seen, 2, "duplicates count once");
}

#[test]
fn select_catalog_two_lineages_needs_choice_even_if_one_is_empty_and_fresher() {
    // The shadow `init --mnemonic` node: 0 files, newest pointer. Picking the freshest
    // pointer across histories would restore it — the choice must go to the user.
    let owner = lineage(1);
    let shadow = lineage(2);
    let err = select_catalog(
        vec![pointer(owner, 3, 100, 5), pointer(shadow, 0, 900, 1)],
        None,
    )
    .unwrap_err();
    match err {
        CatalogSelectError::NeedsChoice { rows } => {
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[0].lineage, shadow, "rows freshest first");
            assert_eq!(rows[1].lineage, owner);
            assert_eq!(rows[1].files, 3);
        }
        other => panic!("expected NeedsChoice, got {other:?}"),
    }
}

#[test]
fn select_catalog_two_lineages_needs_choice_even_if_freshest_is_largest() {
    // No automatic choice between histories in B2.2a, whatever the numbers.
    let err = select_catalog(
        vec![
            pointer(lineage(1), 3, 100, 1),
            pointer(lineage(2), 9, 900, 1),
        ],
        None,
    )
    .unwrap_err();
    assert!(matches!(err, CatalogSelectError::NeedsChoice { .. }));
    assert!(err.to_string().contains("--catalog"), "{err}");
}

#[test]
fn select_catalog_requested_prefix_picks_that_lineage_even_if_older_and_smaller() {
    let owner = lineage(0xab);
    let other = lineage(0x12);
    let got = select_catalog(
        vec![pointer(owner, 3, 100, 5), pointer(other, 9, 900, 1)],
        Some("abababab"),
    )
    .unwrap();
    assert_eq!(got.reason, ChoiceReason::Requested);
    assert_eq!(got.selected.catalog.lineage, owner);
    assert_eq!(got.rows[0].lineage, owner, "selected row first");
    assert_eq!(got.rows[1].lineage, other);
}

#[test]
fn select_catalog_requested_prefix_is_case_insensitive_and_trimmed() {
    let owner = lineage(0xab);
    let got = select_catalog(vec![pointer(owner, 3, 100, 5)], Some("  ABABABAB ")).unwrap();
    assert_eq!(got.reason, ChoiceReason::Requested);
}

#[test]
fn select_catalog_prefix_shorter_than_8_is_bad_prefix() {
    let err = select_catalog(vec![pointer(lineage(0xab), 3, 100, 5)], Some("ababab")).unwrap_err();
    assert!(
        matches!(err, CatalogSelectError::BadPrefix { .. }),
        "{err:?}"
    );
}

#[test]
fn select_catalog_non_hex_prefix_is_bad_prefix() {
    let err =
        select_catalog(vec![pointer(lineage(0xab), 3, 100, 5)], Some("ababzzzz")).unwrap_err();
    assert!(
        matches!(err, CatalogSelectError::BadPrefix { .. }),
        "{err:?}"
    );
}

#[test]
fn select_catalog_ambiguous_prefix_is_error_with_rows() {
    let mut a = [0xabu8; 16];
    let mut b = [0xabu8; 16];
    a[15] = 1;
    b[15] = 2;
    let err = select_catalog(
        vec![
            pointer(CatalogLineageId(a), 3, 100, 1),
            pointer(CatalogLineageId(b), 4, 200, 1),
        ],
        Some("abababab"),
    )
    .unwrap_err();
    match &err {
        CatalogSelectError::Ambiguous { rows, .. } => assert_eq!(rows.len(), 2),
        other => panic!("expected Ambiguous, got {other:?}"),
    }
    assert_eq!(err.rows().len(), 2);
}

#[test]
fn select_catalog_unknown_prefix_is_error_with_rows() {
    let err =
        select_catalog(vec![pointer(lineage(0xab), 3, 100, 5)], Some("cdcdcdcd")).unwrap_err();
    match err {
        CatalogSelectError::NoMatch { rows, .. } => assert_eq!(rows.len(), 1),
        other => panic!("expected NoMatch, got {other:?}"),
    }
}

#[test]
fn select_catalog_empty_is_error() {
    assert!(matches!(
        select_catalog(vec![], None).unwrap_err(),
        CatalogSelectError::Empty
    ));
}

#[test]
fn select_catalog_rows_carry_publisher_of_the_head() {
    let l = lineage(1);
    let mut late = pointer(l, 3, 200, 2);
    late.catalog.publisher = device(0xEE);
    // Re-sign after changing the publisher so the pointer is consistent.
    late = sign_self_pointer(
        &master(),
        late.generation,
        late.base.clone(),
        late.diffs.clone(),
        late.created_at,
        late.catalog,
    );
    let got = select_catalog(vec![pointer(l, 3, 100, 1), late], None).unwrap();
    assert_eq!(got.rows[0].publisher, device(0xEE));
    assert_eq!(got.selected.catalog.publisher, device(0xEE));
}

// ── ownership (dr-i19) ──────────────────────────────────────────────────────

#[test]
fn restored_file_records_belong_to_the_dr_device() {
    // The friend's path: plain `init` (random device D_rand) → machine lost → DR
    // (deterministic device D*). The restored record must list D*, not D_rand, so a
    // later deletion on the recovered machine starts the owner cooldown.
    let d_rand = device(0x11);
    let d_star = device(0x22);
    let mut files = vec![file("/f1", vec![(d_rand, LocalState::Present)])];

    assert_eq!(reassign_history_device(&mut files, d_rand, d_star), 1);
    assert_eq!(files[0].devices, vec![(d_star, LocalState::Present)]);

    let got = DeletionEngine::new()
        .mark_deleted(&files[0], d_star, Timestamp(1_000))
        .unwrap();
    assert!(
        matches!(got, MarkDeletedResult::CooldownStarted { .. }),
        "deleting on the DR device must start the cooldown, got {got:?}"
    );
}

#[test]
fn without_reassign_deletion_waits_for_the_lost_device_forever() {
    // The defect dr-i19 closes, pinned so the test above cannot pass for another reason.
    let d_rand = device(0x11);
    let d_star = device(0x22);
    let mut record = file("/f1", vec![(d_rand, LocalState::Present)]);
    record.devices.push((d_star, LocalState::Present)); // the file came back on D*
    let got = DeletionEngine::new()
        .mark_deleted(&record, d_star, Timestamp(1_000))
        .unwrap();
    assert_eq!(got, MarkDeletedResult::WaitForOtherDevices);
}

#[test]
fn reassign_history_device_keeps_sibling_devices() {
    let lost = device(1);
    let new = device(2);
    let sibling = device(3);
    let mut files = vec![file(
        "/f",
        vec![
            (lost, LocalState::Deleted(Timestamp(5))),
            (sibling, LocalState::Present),
        ],
    )];
    reassign_history_device(&mut files, lost, new);
    assert_eq!(
        files[0].devices,
        vec![
            (new, LocalState::Deleted(Timestamp(5))),
            (sibling, LocalState::Present)
        ]
    );
}

#[test]
fn reassign_history_device_absorbs_existing_new_device_entry() {
    let lost = device(1);
    let new = device(2);
    let mut files = vec![file(
        "/f",
        vec![
            (new, LocalState::Present),
            (lost, LocalState::Deleted(Timestamp(9))),
        ],
    )];
    assert_eq!(reassign_history_device(&mut files, lost, new), 1);
    assert_eq!(
        files[0].devices,
        vec![(new, LocalState::Deleted(Timestamp(9)))],
        "the lost device's state wins, no duplicate entry for the new device"
    );
}

#[test]
fn reassign_history_device_same_device_is_noop() {
    let d = device(1);
    let mut files = vec![file("/f", vec![(d, LocalState::Present)])];
    assert_eq!(reassign_history_device(&mut files, d, d), 0);
    assert_eq!(files[0].devices, vec![(d, LocalState::Present)]);
}

#[test]
fn reassign_history_device_leaves_records_without_the_lost_device() {
    let mut files = vec![file("/f", vec![(device(3), LocalState::Present)])];
    assert_eq!(reassign_history_device(&mut files, device(1), device(2)), 0);
    assert_eq!(files[0].devices, vec![(device(3), LocalState::Present)]);
}

// ── ids and liveness ────────────────────────────────────────────────────────

#[test]
fn catalog_lineage_random_ids_differ() {
    let a = CatalogLineageId::random();
    let b = CatalogLineageId::random();
    assert_ne!(a, b);
    assert_eq!(a.to_hex().len(), 32);
    assert_eq!(format!("{a}"), a.to_hex());
}

#[test]
fn is_live_file_false_only_when_deleted_on_every_device() {
    let deleted = LocalState::Deleted(Timestamp(1));
    assert!(!is_live_file(&file("/a", vec![(device(1), deleted)])));
    assert!(!is_live_file(&file(
        "/a",
        vec![(device(1), deleted), (device(2), deleted)]
    )));
    assert!(is_live_file(&file(
        "/a",
        vec![(device(1), deleted), (device(2), LocalState::Present)]
    )));
    assert!(is_live_file(&file(
        "/a",
        vec![(device(1), LocalState::Present)]
    )));
}

#[test]
fn is_live_file_true_for_record_without_devices() {
    assert!(is_live_file(&file("/a", vec![])));
}

#[test]
fn live_file_count_counts_only_live_records() {
    let files = vec![
        file("/a", vec![(device(1), LocalState::Present)]),
        file("/b", vec![(device(1), LocalState::Deleted(Timestamp(1)))]),
        file("/c", vec![]),
    ];
    assert_eq!(live_file_count(&files), 2);
}

#[test]
fn select_catalog_returns_older_pointers_of_the_chosen_history_as_fallbacks() {
    // dr-i35: freshest first, the head excluded, other histories never mixed in.
    let owner = lineage(0xab);
    let other = lineage(0x12);
    let got = select_catalog(
        vec![
            pointer(owner, 3, 100, 1),
            pointer(other, 9, 950, 1),
            pointer(owner, 3, 300, 3),
            pointer(owner, 3, 200, 2),
        ],
        Some("abababab"),
    )
    .unwrap();
    assert_eq!(got.selected.created_at, Timestamp(300));
    let order: Vec<u64> = got.fallbacks.iter().map(|p| p.created_at.0).collect();
    assert_eq!(order, vec![200, 100]);
    assert!(got.fallbacks.iter().all(|p| p.catalog.lineage == owner));
}

#[test]
fn check_catalog_prefix_normalizes_and_rejects_bad_forms() {
    assert_eq!(check_catalog_prefix("  ABCDEF01 ").unwrap(), "abcdef01");
    assert!(matches!(
        check_catalog_prefix("abc"),
        Err(CatalogSelectError::BadPrefix { .. })
    ));
    assert!(matches!(
        check_catalog_prefix("zzzzzzzz"),
        Err(CatalogSelectError::BadPrefix { .. })
    ));
}

#[test]
fn select_catalog_bad_prefix_after_the_network_carries_the_rows() {
    let err = select_catalog(vec![pointer(lineage(0xab), 3, 100, 5)], Some("xyz")).unwrap_err();
    assert_eq!(err.rows().len(), 1, "the table is still printed");
}
