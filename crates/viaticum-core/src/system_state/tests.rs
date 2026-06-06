use super::*;
use crate::db::WeeklyPosEntry;
use crate::db::testutil::test_db;
use crate::types::{
    DeviceId, FileId, FileRecord, IdentityPub, LocalState, PeerRecord, PlacementStatus,
    SourceBlockId, SourceBlockRecord, SourceBlockStatus, SourceBlockType, SymbolPlacement,
    Timestamp,
};

// ============================================================
// Test helpers
// ============================================================

fn make_key() -> [u8; 32] {
    [42u8; 32]
}

fn make_alt_key() -> [u8; 32] {
    [99u8; 32]
}

fn make_file(path: &str, id: u64) -> FileRecord {
    FileRecord {
        file_id: FileId(id),
        path: path.to_string(),
        importance: 0.5,
        devices: vec![(DeviceId([0u8; 32]), LocalState::Present)],
        versions: vec![],
        first_seen: Timestamp(1000),
    }
}

fn make_source_block(seed: u8) -> SourceBlockRecord {
    SourceBlockRecord {
        block_id: SourceBlockId([seed; 32]),
        k: 10,
        t: 65535,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(1000),
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

fn make_placement(block_seed: u8, holder: DeviceId, file_id: FileId) -> SymbolPlacement {
    SymbolPlacement {
        source_block_id: SourceBlockId([block_seed; 32]),
        holder_id: holder,
        file_id,
        esi_ranges: vec![(0, 10)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp(1000),
        consecutive_misses: 0,
    }
}

fn make_peer(seed: u8) -> PeerRecord {
    PeerRecord {
        device_id: DeviceId([seed; 32]),
        master_identity: IdentityPub([seed; 32]),
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(1000),
        last_seen: Timestamp(2000),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    }
}

// ============================================================
// Tests
// ============================================================

#[test]
fn empty_db_roundtrip() {
    // Snapshot empty DB, pack, unpack, restore — all counts = 0.
    let db = test_db();
    let key = make_key();

    let state = snapshot_db(&db).unwrap();
    assert_eq!(state.files.len(), 0);
    assert_eq!(state.peers.len(), 0);
    assert_eq!(state.source_blocks.len(), 0);
    assert_eq!(state.symbol_placements.len(), 0);
    assert_eq!(state.pos_weekly.len(), 0);
    assert!(state.cluster_state.is_none());

    let blob = pack_system_state(&state, &key).unwrap();
    let unpacked = unpack_system_state(&blob, &key).unwrap();
    assert_eq!(unpacked.files.len(), 0);
    assert_eq!(unpacked.peers.len(), 0);
    assert_eq!(unpacked.version, SYSTEM_STATE_VERSION);

    let db2 = test_db();
    restore_db(&db2, &unpacked).unwrap();
    assert_eq!(db2.list_all_files().unwrap().len(), 0);
    assert_eq!(db2.list_all_peers().unwrap().len(), 0);
}

#[test]
fn roundtrip_snapshot_pack_unpack_restore() {
    // Populate DB with test data, snapshot, pack, unpack, restore to new DB, verify.
    let db = test_db();
    let key = make_key();

    // Insert data
    let file1 = make_file("docs/a.txt", 1);
    let file2 = make_file("photos/b.jpg", 2);
    db.upsert_file(&file1).unwrap();
    db.upsert_file(&file2).unwrap();

    let sb1 = make_source_block(1);
    let sb2 = make_source_block(2);
    db.upsert_source_block(&sb1).unwrap();
    db.upsert_source_block(&sb2).unwrap();

    let holder = DeviceId([7u8; 32]);
    let placement = make_placement(1, holder, FileId(1));
    db.upsert_placement(&placement).unwrap();

    let peer1 = make_peer(10);
    let peer2 = make_peer(20);
    db.upsert_peer(&peer1).unwrap();
    db.upsert_peer(&peer2).unwrap();

    // Insert a pos_weekly entry
    db.upsert_pos_weekly(
        &DeviceId([10u8; 32]),
        5,
        &WeeklyPosEntry {
            challenged: 3,
            passed: 2,
        },
    )
    .unwrap();

    // Snapshot + pack + unpack
    let state = snapshot_db(&db).unwrap();
    assert_eq!(state.files.len(), 2);
    assert_eq!(state.source_blocks.len(), 2);
    assert_eq!(state.symbol_placements.len(), 1);
    assert_eq!(state.peers.len(), 2);
    assert_eq!(state.pos_weekly.len(), 1);

    let blob = pack_system_state(&state, &key).unwrap();
    let unpacked = unpack_system_state(&blob, &key).unwrap();

    assert_eq!(unpacked.files.len(), 2);
    assert_eq!(unpacked.source_blocks.len(), 2);
    assert_eq!(unpacked.symbol_placements.len(), 1);
    assert_eq!(unpacked.peers.len(), 2);
    assert_eq!(unpacked.pos_weekly.len(), 1);
    assert_eq!(unpacked.version, SYSTEM_STATE_VERSION);

    // Restore into fresh DB and verify
    let db2 = test_db();
    restore_db(&db2, &unpacked).unwrap();

    assert_eq!(db2.list_all_files().unwrap().len(), 2);
    assert_eq!(db2.list_all_source_blocks().unwrap().len(), 2);
    assert_eq!(db2.list_all_placements().unwrap().len(), 1);
    assert_eq!(db2.list_all_peers().unwrap().len(), 2);

    // Verify pos_weekly was restored
    let pos_entry = db2
        .get_pos_weekly(&DeviceId([10u8; 32]), 5)
        .unwrap()
        .unwrap();
    assert_eq!(pos_entry.challenged, 3);
    assert_eq!(pos_entry.passed, 2);

    // Verify file paths round-tripped
    let paths: Vec<String> = db2
        .list_all_files()
        .unwrap()
        .iter()
        .map(|f| f.path.clone())
        .collect();
    assert!(paths.contains(&"docs/a.txt".to_string()));
    assert!(paths.contains(&"photos/b.jpg".to_string()));
}

#[test]
fn wrong_key_fails() {
    // Pack with key A, unpack with key B → Encryption error.
    let db = test_db();
    let key_a = make_key();
    let key_b = make_alt_key();

    let state = snapshot_db(&db).unwrap();
    let blob = pack_system_state(&state, &key_a).unwrap();

    let result = unpack_system_state(&blob, &key_b);
    assert!(
        matches!(result, Err(SystemStateError::Encryption(_))),
        "expected Encryption error, got: {result:?}"
    );
}

#[test]
fn blob_too_short_fails() {
    // unpack with blob shorter than 52 bytes → BlobTooShort.
    let key = make_key();

    let result = unpack_system_state(&[0u8; 10], &key);
    assert!(
        matches!(
            result,
            Err(SystemStateError::BlobTooShort {
                expected: 52,
                got: 10
            })
        ),
        "expected BlobTooShort, got: {result:?}"
    );

    // Exactly 51 bytes — still too short.
    let result = unpack_system_state(&[0u8; 51], &key);
    assert!(
        matches!(result, Err(SystemStateError::BlobTooShort { .. })),
        "expected BlobTooShort for 51-byte blob"
    );

    // Empty blob.
    let result = unpack_system_state(&[], &key);
    assert!(matches!(result, Err(SystemStateError::BlobTooShort { .. })));
}

#[test]
fn restore_into_nonempty_db_fails() {
    // Populate DB, try restore_db → DbNotEmpty.
    // restore_db_force should succeed.
    let db = test_db();
    let key = make_key();

    // Get an empty state blob
    let empty_db = test_db();
    let state = snapshot_db(&empty_db).unwrap();
    let blob = pack_system_state(&state, &key).unwrap();
    let unpacked = unpack_system_state(&blob, &key).unwrap();

    // Put data in db
    db.upsert_file(&make_file("x.txt", 1)).unwrap();

    // restore_db should refuse
    let result = restore_db(&db, &unpacked);
    assert!(
        matches!(result, Err(SystemStateError::DbNotEmpty)),
        "expected DbNotEmpty, got: {result:?}"
    );

    // restore_db_force should succeed
    restore_db_force(&db, &unpacked).unwrap();
}

#[test]
fn pack_produces_different_blobs() {
    // Same state packed twice → different blobs (random salt + nonce).
    let db = test_db();
    let key = make_key();

    let state = snapshot_db(&db).unwrap();
    let blob1 = pack_system_state(&state, &key).unwrap();
    let blob2 = pack_system_state(&state, &key).unwrap();

    // Both should decode correctly
    unpack_system_state(&blob1, &key).unwrap();
    unpack_system_state(&blob2, &key).unwrap();

    // But the blobs themselves must differ (random salt)
    assert_ne!(
        blob1, blob2,
        "two packs of the same state should produce different blobs"
    );
}

#[test]
fn cluster_state_roundtrip() {
    // SystemState with cluster_state = None round-trips correctly.
    // (Full cluster state test would require cluster module setup.)
    let db = test_db();
    let key = make_key();

    let state = snapshot_db(&db).unwrap();
    assert!(state.cluster_state.is_none());

    let blob = pack_system_state(&state, &key).unwrap();
    let unpacked = unpack_system_state(&blob, &key).unwrap();
    assert!(unpacked.cluster_state.is_none());

    let db2 = test_db();
    restore_db(&db2, &unpacked).unwrap();
    assert!(db2.get_cluster_state().unwrap().is_none());
}

#[test]
fn multiple_pos_weekly_entries_roundtrip() {
    // Multiple pos_weekly entries across different peers and weeks.
    let db = test_db();
    let key = make_key();

    let peer_a = DeviceId([1u8; 32]);
    let peer_b = DeviceId([2u8; 32]);

    db.upsert_pos_weekly(
        &peer_a,
        1,
        &WeeklyPosEntry {
            challenged: 10,
            passed: 8,
        },
    )
    .unwrap();
    db.upsert_pos_weekly(
        &peer_a,
        2,
        &WeeklyPosEntry {
            challenged: 20,
            passed: 18,
        },
    )
    .unwrap();
    db.upsert_pos_weekly(
        &peer_b,
        1,
        &WeeklyPosEntry {
            challenged: 5,
            passed: 5,
        },
    )
    .unwrap();

    let state = snapshot_db(&db).unwrap();
    assert_eq!(state.pos_weekly.len(), 3);

    let blob = pack_system_state(&state, &key).unwrap();
    let unpacked = unpack_system_state(&blob, &key).unwrap();

    let db2 = test_db();
    restore_db(&db2, &unpacked).unwrap();

    let a1 = db2.get_pos_weekly(&peer_a, 1).unwrap().unwrap();
    assert_eq!(a1.challenged, 10);
    assert_eq!(a1.passed, 8);

    let a2 = db2.get_pos_weekly(&peer_a, 2).unwrap().unwrap();
    assert_eq!(a2.challenged, 20);
    assert_eq!(a2.passed, 18);

    let b1 = db2.get_pos_weekly(&peer_b, 1).unwrap().unwrap();
    assert_eq!(b1.challenged, 5);
    assert_eq!(b1.passed, 5);
}

// ============================================================
// Diff: diff_states / apply_diffs
// ============================================================

fn base_state() -> SystemState {
    SystemState {
        version: SYSTEM_STATE_VERSION,
        created_at: Timestamp(1000),
        files: vec![make_file("a.txt", 1), make_file("b.txt", 2)],
        source_blocks: vec![make_source_block(1)],
        symbol_placements: vec![make_placement(1, DeviceId([7u8; 32]), FileId(1))],
        peers: vec![make_peer(10)],
        pos_weekly: vec![PosWeeklyEntry {
            key: {
                let mut k = vec![5u8; 32];
                k.extend_from_slice(&7u32.to_be_bytes());
                k
            },
            value: vec![1, 2, 3],
        }],
        cluster_state: None,
    }
}

/// Order-independent structural equality of two SystemStates (ignores Vec ordering).
fn assert_states_eq(a: &SystemState, b: &SystemState) {
    use std::collections::BTreeMap;
    let fa: BTreeMap<u64, Vec<u8>> = a.files.iter().map(|f| (f.file_id.0, to_cbor(f))).collect();
    let fb: BTreeMap<u64, Vec<u8>> = b.files.iter().map(|f| (f.file_id.0, to_cbor(f))).collect();
    assert_eq!(fa, fb, "files differ");

    let ba: BTreeMap<[u8; 32], Vec<u8>> = a
        .source_blocks
        .iter()
        .map(|s| (s.block_id.0, to_cbor(s)))
        .collect();
    let bb: BTreeMap<[u8; 32], Vec<u8>> = b
        .source_blocks
        .iter()
        .map(|s| (s.block_id.0, to_cbor(s)))
        .collect();
    assert_eq!(ba, bb, "source_blocks differ");

    let pa: BTreeMap<([u8; 32], [u8; 32]), Vec<u8>> = a
        .symbol_placements
        .iter()
        .map(|p| ((p.source_block_id.0, p.holder_id.0), to_cbor(p)))
        .collect();
    let pb: BTreeMap<([u8; 32], [u8; 32]), Vec<u8>> = b
        .symbol_placements
        .iter()
        .map(|p| ((p.source_block_id.0, p.holder_id.0), to_cbor(p)))
        .collect();
    assert_eq!(pa, pb, "placements differ");

    let ra: BTreeMap<[u8; 32], Vec<u8>> =
        a.peers.iter().map(|p| (p.device_id.0, to_cbor(p))).collect();
    let rb: BTreeMap<[u8; 32], Vec<u8>> =
        b.peers.iter().map(|p| (p.device_id.0, to_cbor(p))).collect();
    assert_eq!(ra, rb, "peers differ");

    let wa: BTreeMap<Vec<u8>, Vec<u8>> = a
        .pos_weekly
        .iter()
        .map(|e| (e.key.clone(), e.value.clone()))
        .collect();
    let wb: BTreeMap<Vec<u8>, Vec<u8>> = b
        .pos_weekly
        .iter()
        .map(|e| (e.key.clone(), e.value.clone()))
        .collect();
    assert_eq!(wa, wb, "pos_weekly differ");

    assert_eq!(
        to_cbor(&a.cluster_state),
        to_cbor(&b.cluster_state),
        "cluster_state differ"
    );
}

fn to_cbor<T: serde::Serialize>(v: &T) -> Vec<u8> {
    crate::types::to_cbor_bytes(v)
}

#[test]
fn diff_then_apply_reconstructs_target() {
    let base = base_state();
    let mut target = base.clone();
    // modify file 1, delete file 2, add file 3
    target.files.retain(|f| f.file_id != FileId(2));
    target.files.push(make_file("c.txt", 3));
    if let Some(f) = target.files.iter_mut().find(|f| f.file_id == FileId(1)) {
        f.importance = 0.9;
    }
    // replace the placement (delete old, add new with different holder)
    target.symbol_placements = vec![make_placement(1, DeviceId([8u8; 32]), FileId(1))];
    // add a peer
    target.peers.push(make_peer(20));
    // add a new source block
    target.source_blocks.push(make_source_block(2));
    // change a pos_weekly value
    target.pos_weekly[0].value = vec![9, 9, 9];

    let diff = diff_states(&base, &target);
    assert!(!diff.is_empty(), "diff of changed states must be non-empty");

    let result = apply_diffs(base.clone(), std::slice::from_ref(&diff));
    assert_states_eq(&result, &target);
}

#[test]
fn diff_of_identical_states_is_empty() {
    let base = base_state();
    assert!(diff_states(&base, &base).is_empty());
}

#[test]
fn apply_empty_diff_list_is_identity() {
    let base = base_state();
    let result = apply_diffs(base.clone(), &[]);
    assert_states_eq(&result, &base);
}

#[test]
fn ordered_diffs_apply_in_sequence() {
    let base = base_state();
    let mut s1 = base.clone();
    s1.files.push(make_file("new.txt", 99));
    let d1 = diff_states(&base, &s1);

    let mut s2 = s1.clone();
    if let Some(f) = s2.files.iter_mut().find(|f| f.file_id == FileId(99)) {
        f.importance = 0.123;
    }
    let d2 = diff_states(&s1, &s2);

    let result = apply_diffs(base.clone(), &[d1, d2]);
    assert_states_eq(&result, &s2);
}

// ============================================================
// SelfPointer: sign / verify / CBOR
// ============================================================

fn master() -> ed25519_dalek::SigningKey {
    crate::cluster::derive_master_key(&[3u8; 32]).unwrap()
}

fn sample_base_ref() -> BlockRef {
    BlockRef {
        block_id: SourceBlockId([1u8; 32]),
        holders: vec![HolderHint {
            holder_id: DeviceId([7u8; 32]),
            addrs: vec!["/ip4/10.0.0.1/tcp/4001".to_string()],
        }],
    }
}

fn sample_diff_refs() -> Vec<BlockRef> {
    vec![BlockRef {
        block_id: SourceBlockId([2u8; 32]),
        holders: vec![HolderHint {
            holder_id: DeviceId([8u8; 32]),
            addrs: vec![],
        }],
    }]
}

#[test]
fn self_pointer_signs_and_verifies() {
    let mk = master();
    let id = crate::cluster::master_identity(&mk);
    let p = sign_self_pointer(
        &mk,
        5,
        sample_base_ref(),
        sample_diff_refs(),
        Timestamp(1234),
    );
    assert_eq!(p.generation, 5);
    verify_self_pointer(&p, &id).expect("freshly signed pointer must verify");
}

#[test]
fn self_pointer_tamper_fails_verify() {
    let mk = master();
    let id = crate::cluster::master_identity(&mk);
    let p = sign_self_pointer(
        &mk,
        5,
        sample_base_ref(),
        sample_diff_refs(),
        Timestamp(1234),
    );

    let mut t_gen = p.clone();
    t_gen.generation = 6;
    assert!(
        verify_self_pointer(&t_gen, &id).is_err(),
        "tampered generation must fail"
    );

    let mut t_base = p.clone();
    t_base.base.block_id = SourceBlockId([0x99u8; 32]);
    assert!(
        verify_self_pointer(&t_base, &id).is_err(),
        "tampered base block_id must fail"
    );

    let mut t_holder = p.clone();
    t_holder.base.holders[0].holder_id = DeviceId([0xAAu8; 32]);
    assert!(
        verify_self_pointer(&t_holder, &id).is_err(),
        "tampered holder hint must fail"
    );
}

#[test]
fn self_pointer_wrong_signer_fails() {
    let mk = master();
    let other = crate::cluster::derive_master_key(&[8u8; 32]).unwrap();
    let other_id = crate::cluster::master_identity(&other);
    let p = sign_self_pointer(&mk, 1, sample_base_ref(), vec![], Timestamp(1));
    assert!(
        verify_self_pointer(&p, &other_id).is_err(),
        "pointer signed by a different master must not verify"
    );
}

#[test]
fn self_pointer_cbor_roundtrip() {
    let mk = master();
    let id = crate::cluster::master_identity(&mk);
    let p = sign_self_pointer(
        &mk,
        7,
        sample_base_ref(),
        sample_diff_refs(),
        Timestamp(9000),
    );
    let bytes = crate::types::to_cbor_bytes(&p);
    let decoded: SelfPointer = crate::types::from_cbor_bytes(&bytes).unwrap();
    assert_eq!(decoded.generation, 7);
    assert_eq!(decoded.base.block_id, p.base.block_id);
    verify_self_pointer(&decoded, &id).expect("decoded pointer must still verify");
}
