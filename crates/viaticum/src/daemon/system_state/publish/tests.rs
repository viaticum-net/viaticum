use super::*;
use viaticum_core::db::Db;
use viaticum_core::system_state::{DiffOp, diff_states, snapshot_db};
use viaticum_core::types::{
    DeviceId, FileId, FileRecord, FileVersion, IdentityPub, PeerRecord, PlacementStatus,
    SourceBlockId, SourceBlockType, SymbolPlacement, Timestamp, from_cbor_bytes,
};

fn dr_key() -> [u8; 32] {
    [0x7Eu8; 32]
}

/// Decrypt + decompress a retained SS block blob with the DR key and CBOR-decode it.
fn decode_retained<T: serde::de::DeserializeOwned>(
    data_dir: &std::path::Path,
    block_id: &SourceBlockId,
) -> T {
    let blob = block::load_retained_block(data_dir, block_id).unwrap();
    let plaintext =
        crate::daemon::backup::pipeline::decrypt_and_decompress(&blob, &dr_key()).unwrap();
    from_cbor_bytes::<T>(&plaintext).unwrap()
}

fn sample_file(db: &Db, id: u64, path: &str) {
    let rec = FileRecord {
        file_id: FileId(id),
        path: path.to_string(),
        importance: 0.5,
        devices: vec![],
        versions: vec![FileVersion {
            content_hash: [id as u8; 32],
            source_block_id: SourceBlockId([id as u8; 32]),
            k: 1,
            t: 1024,
            created_at: Timestamp(1000),
            backed_up_at: None,
        }],
        first_seen: Timestamp(1000),
    };
    db.upsert_file(&rec).unwrap();
}

#[test]
fn publish_base_block_persists_retains_and_registers() {
    let db = Db::open_in_memory().unwrap();
    sample_file(&db, 1, "a.txt");
    let dir = tempfile::tempdir().unwrap();
    let state = snapshot_db(&db).unwrap();

    let block_id = publish_base_block(&db, dir.path(), &dr_key(), 1, &state).unwrap();

    // Retained blob decrypts back to the exact snapshot.
    let recovered: viaticum_core::system_state::SystemState =
        decode_retained(dir.path(), &block_id);
    assert_eq!(recovered.files.len(), state.files.len());
    // SystemState has no PartialEq; compare canonical CBOR (round-trip proxy).
    assert_eq!(
        viaticum_core::types::to_cbor_bytes(&recovered),
        viaticum_core::types::to_cbor_bytes(&state),
        "retained base must decode to the snapshot"
    );

    // Source block record registered at MAX importance so the pipeline places it.
    let rec = db
        .get_source_block(&block_id)
        .unwrap()
        .expect("record exists");
    assert!(
        (rec.importance - 1.0).abs() < 1e-12,
        "SS block = MAX importance"
    );
    assert_eq!(rec.block_type, SourceBlockType::Single);
}

#[test]
fn publish_diff_block_roundtrips() {
    let db = Db::open_in_memory().unwrap();
    let dir = tempfile::tempdir().unwrap();

    let old = snapshot_db(&db).unwrap();
    sample_file(&db, 2, "b.txt");
    let new = snapshot_db(&db).unwrap();
    let diffs: Vec<DiffOp> = diff_states(&old, &new);
    assert!(!diffs.is_empty(), "adding a file must produce a diff");

    let block_id = publish_diff_block(&db, dir.path(), &dr_key(), 1, &diffs).unwrap();

    let recovered: Vec<DiffOp> = decode_retained(dir.path(), &block_id);
    // DiffOp has no PartialEq; compare canonical CBOR (round-trip proxy).
    assert_eq!(
        viaticum_core::types::to_cbor_bytes(&recovered),
        viaticum_core::types::to_cbor_bytes(&diffs),
        "retained diff must decode to the DiffOps"
    );

    let rec = db
        .get_source_block(&block_id)
        .unwrap()
        .expect("record exists");
    assert!((rec.importance - 1.0).abs() < 1e-12);
}

fn alive_placement(block_id: SourceBlockId, holder: DeviceId) -> SymbolPlacement {
    SymbolPlacement {
        source_block_id: block_id,
        holder_id: holder,
        file_id: FileId(0),
        esi_ranges: vec![(0, 12)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp(1000),
        consecutive_misses: 0,
    }
}

fn peer_with_addrs(holder: DeviceId, addrs: Vec<String>) -> PeerRecord {
    PeerRecord {
        device_id: holder,
        master_identity: IdentityPub([0u8; 32]),
        trust_p: 0.0,
        trust_i: 0.0,
        trust_s: 0.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(1),
        last_seen: Timestamp(1),
        revoked_device_pub_keys: vec![],
        addrs,
        x25519_pub: None,
        avail_ewma: viaticum_core::constants::AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    }
}

#[test]
fn block_ref_carries_alive_holders_with_esi_and_addrs() {
    let db = Db::open_in_memory().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let state = snapshot_db(&db).unwrap();
    let base_id = publish_base_block(&db, dir.path(), &dr_key(), 1, &state).unwrap();

    let holder = DeviceId([0x42u8; 32]);
    db.upsert_placement(&alive_placement(base_id, holder))
        .unwrap();
    db.upsert_peer(&peer_with_addrs(
        holder,
        vec!["abc@1.2.3.4:9000".to_string()],
    ))
    .unwrap();

    let expected_size = db
        .get_source_block(&base_id)
        .unwrap()
        .unwrap()
        .encrypted_size
        .unwrap();
    let bref = block_ref_from_placements(&db, &base_id).unwrap();
    assert_eq!(bref.block_id, base_id);
    assert_eq!(
        bref.encrypted_size, expected_size,
        "BlockRef must carry encrypted_size for DR param recompute"
    );
    assert_eq!(bref.holders.len(), 1);
    assert_eq!(bref.holders[0].holder_id, holder);
    assert_eq!(bref.holders[0].esi_ranges, vec![(0, 12)]);
    assert_eq!(bref.holders[0].addrs, vec!["abc@1.2.3.4:9000".to_string()]);
}

#[test]
fn block_ref_skips_non_alive_placements() {
    let db = Db::open_in_memory().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let state = snapshot_db(&db).unwrap();
    let base_id = publish_base_block(&db, dir.path(), &dr_key(), 1, &state).unwrap();

    let holder = DeviceId([0x43u8; 32]);
    let mut p = alive_placement(base_id, holder);
    p.status = PlacementStatus::Lost;
    db.upsert_placement(&p).unwrap();

    let bref = block_ref_from_placements(&db, &base_id).unwrap();
    assert!(
        bref.holders.is_empty(),
        "non-Alive holders excluded from pointer"
    );
}

#[test]
fn built_pointer_verifies_against_master_identity() {
    let db = Db::open_in_memory().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let state = snapshot_db(&db).unwrap();
    let base_id = publish_base_block(&db, dir.path(), &dr_key(), 1, &state).unwrap();

    let master = viaticum_core::cluster::derive_master_key(&[9u8; 32]).unwrap();
    let id = viaticum_core::cluster::master_identity(&master);

    let pointer = build_pointer(&db, &master, 3, &base_id, &[], Timestamp(5000)).unwrap();
    assert_eq!(pointer.generation, 3);
    assert_eq!(pointer.base.block_id, base_id);
    viaticum_core::system_state::verify_self_pointer(&pointer, &id)
        .expect("owner-built pointer must verify against its master identity");
}

#[test]
fn published_block_is_in_ledger_and_excluded_from_snapshot() {
    let db = Db::open_in_memory().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let state = snapshot_db(&db).unwrap();
    let base_id = publish_base_block(&db, dir.path(), &dr_key(), 7, &state).unwrap();

    assert!(
        db.is_ss_block(&base_id).unwrap(),
        "publish marks the SS ledger"
    );
    assert_eq!(db.list_ss_blocks().unwrap(), vec![(base_id, 7)]);

    // The SS record lives in source_blocks but must not appear in a fresh snapshot.
    assert!(db.get_source_block(&base_id).unwrap().is_some());
    let snap = snapshot_db(&db).unwrap();
    assert!(
        !snap.source_blocks.iter().any(|b| b.block_id == base_id),
        "SS block must be excluded from the snapshot (no self-reference)"
    );
}

#[test]
fn retire_removes_block_record_placements_blob_and_ledger() {
    let db = Db::open_in_memory().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let state = snapshot_db(&db).unwrap();
    let base_id = publish_base_block(&db, dir.path(), &dr_key(), 1, &state).unwrap();
    let holder = DeviceId([0x55u8; 32]);
    db.upsert_placement(&alive_placement(base_id, holder))
        .unwrap();

    retire_ss_block(&db, dir.path(), &base_id);

    assert!(!db.is_ss_block(&base_id).unwrap(), "ledger entry removed");
    assert!(
        db.get_source_block(&base_id).unwrap().is_none(),
        "record deleted"
    );
    assert!(
        db.list_placements_for_block(&base_id).unwrap().is_empty(),
        "placements deleted"
    );
    assert!(
        block::load_retained_block(dir.path(), &base_id).is_err(),
        "retained blob removed"
    );
}

#[test]
fn placed_prefix_pointer_is_none_until_base_placed() {
    let db = Db::open_in_memory().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let state = snapshot_db(&db).unwrap();
    let base_id = publish_base_block(&db, dir.path(), &dr_key(), 1, &state).unwrap();

    let master = viaticum_core::cluster::derive_master_key(&[3u8; 32]).unwrap();
    // Base has no Alive holders yet → no useful pointer to advertise.
    let p = build_pointer_for_placed(&db, &master, 1, &base_id, &[], Timestamp(1)).unwrap();
    assert!(p.is_none(), "no pointer until the base is placed");
}

#[test]
fn placed_prefix_pointer_stops_at_first_unplaced_diff() {
    let db = Db::open_in_memory().unwrap();
    let dir = tempfile::tempdir().unwrap();

    let s0 = snapshot_db(&db).unwrap();
    let base_id = publish_base_block(&db, dir.path(), &dr_key(), 1, &s0).unwrap();
    sample_file(&db, 1, "a.txt");
    let s1 = snapshot_db(&db).unwrap();
    let d0 = publish_diff_block(&db, dir.path(), &dr_key(), 1, &diff_states(&s0, &s1)).unwrap();
    sample_file(&db, 2, "b.txt");
    let s2 = snapshot_db(&db).unwrap();
    let d1 = publish_diff_block(&db, dir.path(), &dr_key(), 1, &diff_states(&s1, &s2)).unwrap();

    // Place base and d0, but NOT d1.
    let h = DeviceId([0x71u8; 32]);
    db.upsert_placement(&alive_placement(base_id, h)).unwrap();
    db.upsert_placement(&alive_placement(d0, h)).unwrap();

    let master = viaticum_core::cluster::derive_master_key(&[4u8; 32]).unwrap();
    let id = viaticum_core::cluster::master_identity(&master);
    let p = build_pointer_for_placed(&db, &master, 2, &base_id, &[d0, d1], Timestamp(9))
        .unwrap()
        .expect("base placed → Some");

    viaticum_core::system_state::verify_self_pointer(&p, &id).unwrap();
    assert_eq!(p.base.block_id, base_id);
    assert_eq!(
        p.diffs.len(),
        1,
        "stops at the first unplaced diff (d1 omitted)"
    );
    assert_eq!(p.diffs[0].block_id, d0);
}

/// AC-7: Bug-G — staged rotation guard.
///
/// The pointer must NOT be published for a new base block until that base is
/// DR-recoverable from its current alive holders.
///
/// For SS base blocks specifically: the placement solver (Phase-B DEEPEN) assigns
/// `k_eff` symbols per holder when k_eff is small (typical SS block ≤ 10 KB →
/// k_eff ≈ 4) and only a few holders are opened. Each holder therefore carries a
/// full independently-decodable copy of the block. The DR-recoverability threshold
/// is thus **≥1 alive holder with a non-empty ESI range** — verified by the
/// `holders.is_empty()` guard in `build_pointer_for_placed`.
///
/// This test names the scenario explicitly (AC-7 coverage), transitions the base
/// from 0 → 1 alive holder, and confirms the guard flips accordingly.
#[test]
fn pointer_not_updated_before_base_reaches_min_alive() {
    let db = Db::open_in_memory().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let state = snapshot_db(&db).unwrap();
    let base_id = publish_base_block(&db, dir.path(), &dr_key(), 1, &state).unwrap();

    let master = viaticum_core::cluster::derive_master_key(&[0xBBu8; 32]).unwrap();
    let master_id = viaticum_core::cluster::master_identity(&master);

    // Phase 1: base has 0 alive holders → pointer must be None (un-placed prefix).
    let p = build_pointer_for_placed(&db, &master, 1, &base_id, &[], Timestamp(100)).unwrap();
    assert!(
        p.is_none(),
        "pointer must be None when base has no alive holders (not DR-recoverable yet)"
    );

    // Phase 2: one alive holder with ESI ranges appears (full-replica copy).
    // For SS blocks, k_eff is small and each holder gets k_eff symbols from the
    // placement solver → single holder is independently decodable → DR-recoverable.
    let holder = DeviceId([0xAAu8; 32]);
    db.upsert_placement(&alive_placement(base_id, holder))
        .unwrap();

    let p = build_pointer_for_placed(&db, &master, 1, &base_id, &[], Timestamp(200))
        .unwrap()
        .expect("pointer must be Some once base has ≥1 alive holder (DR-recoverable)");

    // Pointer references the correct base and is validly signed.
    viaticum_core::system_state::verify_self_pointer(&p, &master_id)
        .expect("pointer must verify against master identity");
    assert_eq!(p.base.block_id, base_id);
    assert_eq!(
        p.base.holders.len(),
        1,
        "pointer base must list the one alive holder"
    );
    assert_eq!(p.base.holders[0].holder_id, holder);
    assert!(
        p.diffs.is_empty(),
        "no diffs registered → pointer diffs must be empty"
    );
}

// ─── T-12: HolderHint addr propagation ───────────────────────────────────────

/// T-12 AC: `build_pointer_for_placed` populates `HolderHint.addrs` when the
/// holder's PeerRecord contains dialable addrs.
///
/// This is the path that DR uses for fast dialing (B-1): addrs = acceleration,
/// not a condition for recoverability.
#[test]
fn holder_hint_includes_addr_when_peer_record_has_addr() {
    let db = Db::open_in_memory().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let state = viaticum_core::system_state::snapshot_db(&db).unwrap();
    let base_id = publish_base_block(&db, dir.path(), &dr_key(), 1, &state).unwrap();

    let holder = DeviceId([0xC1u8; 32]);
    let expected_addr = "/ip4/10.20.30.40/tcp/4001".to_string();

    db.upsert_placement(&alive_placement(base_id, holder))
        .unwrap();
    db.upsert_peer(&peer_with_addrs(holder, vec![expected_addr.clone()]))
        .unwrap();

    let master = viaticum_core::cluster::derive_master_key(&[0xEEu8; 32]).unwrap();
    let pointer = build_pointer_for_placed(&db, &master, 1, &base_id, &[], Timestamp(1))
        .unwrap()
        .expect("pointer must be Some with an alive holder");

    assert_eq!(
        pointer.base.holders.len(),
        1,
        "pointer must list the one alive holder"
    );
    assert_eq!(
        pointer.base.holders[0].addrs,
        vec![expected_addr],
        "HolderHint.addrs must carry the holder's stored dialable addr"
    );
}

/// T-12 AC: `build_pointer_for_placed` returns `Some` even when the holder's
/// PeerRecord has no addrs (empty Vec). DR recoverability must NOT depend on
/// addrs; empty HolderHint.addrs is a normal INFO/DEBUG case, never an error.
///
/// B-1 invariant: DR falls back to Kademlia `get_closest_peers(holder_id)`.
#[test]
fn holder_hint_empty_addr_is_ok() {
    let db = Db::open_in_memory().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let state = viaticum_core::system_state::snapshot_db(&db).unwrap();
    let base_id = publish_base_block(&db, dir.path(), &dr_key(), 1, &state).unwrap();

    let holder = DeviceId([0xC2u8; 32]);

    db.upsert_placement(&alive_placement(base_id, holder))
        .unwrap();
    // Insert PeerRecord with empty addrs.
    db.upsert_peer(&peer_with_addrs(holder, vec![])).unwrap();

    let master = viaticum_core::cluster::derive_master_key(&[0xFFu8; 32]).unwrap();
    let pointer = build_pointer_for_placed(&db, &master, 1, &base_id, &[], Timestamp(1))
        .unwrap()
        .expect("pointer must be Some even with empty HolderHint.addrs (B-1: Kademlia fallback)");

    assert_eq!(pointer.base.holders.len(), 1);
    assert!(
        pointer.base.holders[0].addrs.is_empty(),
        "empty addrs must be propagated as-is (not an error, not gated)"
    );
}

#[test]
fn distinct_states_yield_distinct_base_blocks() {
    let db = Db::open_in_memory().unwrap();
    let dir = tempfile::tempdir().unwrap();

    let s0 = snapshot_db(&db).unwrap();
    let id0 = publish_base_block(&db, dir.path(), &dr_key(), 1, &s0).unwrap();

    sample_file(&db, 3, "c.txt");
    let s1 = snapshot_db(&db).unwrap();
    let id1 = publish_base_block(&db, dir.path(), &dr_key(), 1, &s1).unwrap();

    assert_ne!(
        id0, id1,
        "different snapshots must be different content-addressed blocks"
    );
}
