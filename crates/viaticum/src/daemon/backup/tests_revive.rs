// L1b К2 (backup-i8, backup-i21, delete-i9): the serviceable-block dedup gate and the
// generation a packed plaintext is sealed at (N1).
//
// Real redb (in memory), real files in a TempDir, real pipeline (mock holders only feed the
// N solver). "Released" = what the deletion executor leaves: block `Deleting`, placement
// `Deleting`. Spec: private/beta-planning/tasks/c_l1b_serviceable_block.md (v1.1) §2.2.

use tempfile::TempDir;
use viaticum_core::constants::MAX_BLOCK_GENERATIONS;
use viaticum_core::db::{Db, Serviceability};
use viaticum_core::types::{
    DeviceId, FileId, FileRecord, FileVersion, LocalState, PlacementStatus, SourceBlockId,
    SourceBlockRecord, SourceBlockStatus, SymbolPlacement, Timestamp,
};

use super::events::{DedupLookup, select_dedup_source};
use super::generation::{Committed, choose_generation, commit_block_record};
use super::packing::build_plaintext;
use super::pipeline::{
    BlockTypeTag, compress_and_encrypt, compress_block, decrypt_and_decompress,
    rebuild_blob_blocking, run_pipeline, seal_compressed,
};
use super::rebuild::RebuildScope;
use super::tests_current::{
    DEV, active_block, backed_up, content, coord, event, flush, hash, last, queued_paths, record,
    write,
};
use super::{BackupCoordinator, DirtyKind, QueuedFile};

const KEY: [u8; 32] = [42u8; 32];
const HOLDER: DeviceId = DeviceId([0x77; 32]);

/// What the deletion executor leaves after publishing the Delete: the block and its
/// placement `Deleting`.
fn release(db: &Db, block: SourceBlockId) {
    let mut rec = db.get_source_block(&block).unwrap().expect("block record");
    rec.status = SourceBlockStatus::Deleting;
    db.upsert_source_block(&rec).unwrap();
    db.upsert_placement(&placement(block, PlacementStatus::Deleting))
        .unwrap();
}

fn placement(block: SourceBlockId, status: PlacementStatus) -> SymbolPlacement {
    SymbolPlacement {
        source_block_id: block,
        holder_id: HOLDER,
        file_id: FileId(1),
        esi_ranges: vec![(0, 4)],
        binding_seed: [0u8; 32],
        status,
        last_verified: None,
        placed_at: Timestamp(1),
        consecutive_misses: 0,
    }
}

/// The file at `path` is removed and its deletion event processed.
fn delete(c: &mut BackupCoordinator, path: &str) {
    std::fs::remove_file(path).unwrap();
    c.process_event(event(path, DirtyKind::Deleted)).unwrap();
}

fn block(db: &Db, id: SourceBlockId) -> SourceBlockRecord {
    db.get_source_block(&id).unwrap().expect("block record")
}

/// A record at `path` whose only version holds `content_hash` on `block`, backed up.
fn record_on(db: &Db, id: u64, path: &str, content_hash: [u8; 32], block: SourceBlockId) {
    db.upsert_file(&FileRecord {
        file_id: FileId(id),
        path: path.to_string(),
        importance: 0.5,
        devices: vec![(DEV, LocalState::Present)],
        versions: vec![FileVersion {
            content_hash,
            source_block_id: block,
            k: 3,
            t: 1024,
            created_at: Timestamp(100),
            backed_up_at: Some(Timestamp(100)),
        }],
        first_seen: Timestamp(100),
        on_disk_confirmed: true,
    })
    .unwrap();
}

fn unserviceable(lookup: DedupLookup) -> Vec<SourceBlockId> {
    match lookup {
        DedupLookup::Unserviceable { blocks } => blocks,
        other => panic!("expected Unserviceable, got {other:?}"),
    }
}

/// `p` backed up alone (a pack of one), deleted, and its block released; returns the block.
fn backed_up_deleted_released(
    c: &mut BackupCoordinator,
    db: &Db,
    dir: &TempDir,
    name: &str,
    bytes: &[u8],
) -> (String, SourceBlockId) {
    let p = write(dir, name, bytes);
    let x0 = backed_up(c, db, &p, DirtyKind::Added);
    delete(c, &p);
    release(db, x0);
    (p, x0)
}

// ─── Seal (N1) ────────────────────────────────────────────────────────────────

/// Generation 0 is `compress_and_encrypt` (INV-G0); each later generation gives another id
/// and the blob still decrypts to the same plaintext (the nonce is read from the blob).
#[test]
fn seal_distinct_generations_give_distinct_ids_and_decrypt_to_same_plaintext() {
    let plaintext = content(1, 10_000);
    let compressed = compress_block(&plaintext).unwrap();
    let g0 = seal_compressed(&compressed, &KEY, 0).unwrap();
    assert_eq!(g0, compress_and_encrypt(&plaintext, &KEY).unwrap());
    let mut ids = std::collections::BTreeSet::new();
    for g in 0..5 {
        let stored = seal_compressed(&compressed, &KEY, g).unwrap();
        assert_eq!(
            stored,
            seal_compressed(&compressed, &KEY, g).unwrap(),
            "deterministic"
        );
        assert!(
            ids.insert(*blake3::hash(&stored).as_bytes()),
            "g={g} new id"
        );
        assert_eq!(decrypt_and_decompress(&stored, &KEY).unwrap(), plaintext);
    }
}

// ─── The gate (backup-i21) ───────────────────────────────────────────────────

#[test]
fn dedup_skips_version_on_deleting_block_and_reports_unserviceable() {
    let db = Db::open_in_memory().unwrap();
    let x = SourceBlockId([0x31; 32]);
    active_block(&db, x);
    let mut rec = block(&db, x);
    rec.status = SourceBlockStatus::Deleting;
    db.upsert_source_block(&rec).unwrap();
    record_on(&db, 1, "/w/a.bin", [0xA1; 32], x);

    let blocks = unserviceable(select_dedup_source(&db, &[0xA1; 32], None).unwrap());
    assert_eq!(blocks, vec![x]);
}

/// M12: `Active` with a `Deleting` placement is not in service.
#[test]
fn dedup_skips_block_with_a_deleting_placement() {
    let db = Db::open_in_memory().unwrap();
    let x = SourceBlockId([0x32; 32]);
    active_block(&db, x);
    db.upsert_placement(&placement(x, PlacementStatus::Deleting))
        .unwrap();
    record_on(&db, 1, "/w/a.bin", [0xA2; 32], x);

    assert_eq!(
        unserviceable(select_dedup_source(&db, &[0xA2; 32], None).unwrap()),
        vec![x]
    );
}

#[test]
fn dedup_skips_version_whose_block_record_is_missing() {
    let db = Db::open_in_memory().unwrap();
    let x = SourceBlockId([0x33; 32]);
    record_on(&db, 1, "/w/a.bin", [0xA3; 32], x);

    assert_eq!(
        unserviceable(select_dedup_source(&db, &[0xA3; 32], None).unwrap()),
        vec![x]
    );
}

/// `Stale` (the L2 release window) is not a dedup target in L1b; L2 K-5 turns this over.
#[test]
fn dedup_skips_stale_block() {
    let db = Db::open_in_memory().unwrap();
    let x = SourceBlockId([0x34; 32]);
    active_block(&db, x);
    let mut rec = block(&db, x);
    rec.status = SourceBlockStatus::Stale;
    db.upsert_source_block(&rec).unwrap();
    record_on(&db, 1, "/w/a.bin", [0xA4; 32], x);

    assert_eq!(
        unserviceable(select_dedup_source(&db, &[0xA4; 32], None).unwrap()),
        vec![x]
    );
}

/// M11: the gate filters before the ranking — the own path, whose last backed-up version
/// is this content on a releasing block, does not win over another path's serviceable one.
#[test]
fn dedup_gate_applies_to_own_path_before_preference() {
    let db = Db::open_in_memory().unwrap();
    let (x, y) = (SourceBlockId([0x35; 32]), SourceBlockId([0x36; 32]));
    active_block(&db, x);
    active_block(&db, y);
    release(&db, x);
    let h = [0xA5; 32];
    record_on(&db, 1, "/w/own.bin", h, x);
    record_on(&db, 2, "/w/zzz-other.bin", h, y);

    match select_dedup_source(&db, &h, Some("/w/own.bin")).unwrap() {
        DedupLookup::Source(src) => {
            assert_eq!(src.record.path, "/w/zzz-other.bin");
            assert_eq!(src.version.source_block_id, y);
        }
        other => panic!("expected the serviceable source, got {other:?}"),
    }
}

/// Through the event: a returned path whose own block is being released points at the
/// same content on another path's block in service, without traffic.
#[test]
fn dedup_prefers_serviceable_block_of_other_path_over_own_releasing_one() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let a = content(2, 4096);
    let (p, x0) = backed_up_deleted_released(&mut c, &db, &dir, "p.bin", &a);
    let y = SourceBlockId([0x37; 32]);
    active_block(&db, y);
    record_on(&db, 99, "/elsewhere/q.bin", hash(&a), y);

    write(&dir, "p.bin", &a);
    c.process_event(event(&p, DirtyKind::Added)).unwrap();

    let v = last(&db, &p);
    assert_eq!(v.source_block_id, y);
    assert_ne!(v.source_block_id, x0);
    assert!(v.backed_up_at.is_some());
    assert!(queued_paths(&c).is_empty(), "no traffic");
}

/// backup-i21 control: returned before the Delete (block `Active`, the record deleted) —
/// by the same path and as a copy elsewhere — both point at the old block, no new block.
#[test]
fn return_before_delete_dedups_onto_active_block_of_deleted_record() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let a = content(3, 4096);
    let p = write(&dir, "s.bin", &a);
    let xs = backed_up(&mut c, &db, &p, DirtyKind::Added);
    delete(&mut c, &p);

    write(&dir, "s.bin", &a);
    let copy = write(&dir, "s-copy.bin", &a);
    c.process_event(event(&p, DirtyKind::Added)).unwrap();
    c.process_event(event(&copy, DirtyKind::Added)).unwrap();

    assert!(queued_paths(&c).is_empty(), "0 new blocks: nothing queued");
    assert_eq!(flush(&mut c), 0);
    assert_eq!(db.list_all_source_blocks().unwrap().len(), 1);
    for path in [&p, &copy] {
        assert_eq!(last(&db, path).source_block_id, xs);
    }
    assert_eq!(
        record(&db, &p).devices,
        vec![(DEV, LocalState::Present)],
        "revived"
    );
}

// ─── The generation (N1, delete-i9) ──────────────────────────────────────────

/// Returned to its path, a pack of one: the same plaintext. Its generation-0 id is being
/// released, so the pack takes generation 1 — another id — and the old record and its
/// placement are untouched.
#[test]
fn returned_file_same_packing_takes_next_generation_when_block_is_deleting() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let a = content(4, 4096);
    let (p, x0) = backed_up_deleted_released(&mut c, &db, &dir, "r.bin", &a);
    let old = block(&db, x0);

    write(&dir, "r.bin", &a);
    c.process_event(event(&p, DirtyKind::Added)).unwrap();
    assert_eq!(queued_paths(&c).len(), 1, "backed up again, not deduped");
    assert_eq!(flush(&mut c), 1);

    let v = last(&db, &p);
    assert!(v.backed_up_at.is_some());
    assert_ne!(v.source_block_id, x0, "a new id");
    let x1 = block(&db, v.source_block_id);
    assert_eq!(x1.seal_generation, 1);
    assert_eq!(x1.status, SourceBlockStatus::Active);
    let after = block(&db, x0);
    assert_eq!(after.status, SourceBlockStatus::Deleting);
    assert_eq!(after.seal_generation, 0);
    assert_eq!(after.created_at, old.created_at);
    let ps = db.list_placements_for_block(&x0).unwrap();
    assert_eq!(ps.len(), 1);
    assert_eq!(ps[0].status, PlacementStatus::Deleting);
    // The same id the seal at generation 1 gives.
    let plaintext = build_plaintext(&[(queued(&db, &p, &a), a.clone())]);
    let stored = seal_compressed(&compress_block(&plaintext).unwrap(), &KEY, 1).unwrap();
    assert_eq!(blake3::hash(&stored).as_bytes(), &x1.block_id.0);
}

/// The queue entry the pack of `p` was built from.
fn queued(db: &Db, p: &str, bytes: &[u8]) -> QueuedFile {
    QueuedFile {
        path: p.to_string(),
        file_id: record(db, p).file_id,
        content_hash: hash(bytes),
        size_bytes: bytes.len() as u64,
        category: viaticum_core::types::FileCategory::Document,
        importance: 0.5,
    }
}

#[test]
fn returned_file_takes_generation_two_when_zero_and_one_are_releasing() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let a = content(5, 4096);
    let (p, x0) = backed_up_deleted_released(&mut c, &db, &dir, "r.bin", &a);
    write(&dir, "r.bin", &a);
    let x1 = backed_up(&mut c, &db, &p, DirtyKind::Added);
    assert_eq!(block(&db, x1).seal_generation, 1);
    delete(&mut c, &p);
    release(&db, x1);

    write(&dir, "r.bin", &a);
    let x2 = backed_up(&mut c, &db, &p, DirtyKind::Added);

    assert_eq!(block(&db, x2).seal_generation, 2);
    assert!(x2 != x0 && x2 != x1);
}

/// Once the old record is gone (CleanupBlock), no Delete can address its id any more
/// (INV-N1): generation 0 is free and taken again.
#[test]
fn generation_zero_is_reused_when_old_record_is_gone() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let a = content(6, 4096);
    let (p, x0) = backed_up_deleted_released(&mut c, &db, &dir, "r.bin", &a);
    db.delete_placement(&x0, &HOLDER).unwrap();
    db.delete_source_block(&x0).unwrap();

    write(&dir, "r.bin", &a);
    let again = backed_up(&mut c, &db, &p, DirtyKind::Added);

    assert_eq!(again, x0);
    assert_eq!(block(&db, again).seal_generation, 0);
}

/// M10: packing a plaintext whose id is in service keeps the record as it is (its cached
/// reliability, creation time and placements) and returns its parameters.
#[test]
fn pipeline_keeps_serviceable_record_and_its_cached_fields() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let a = content(7, 4096);
    let p = write(&dir, "k.bin", &a);
    let x = backed_up(&mut c, &db, &p, DirtyKind::Added);
    let mut rec = block(&db, x);
    rec.current_alive = 5;
    rec.current_reliability = 0.93;
    rec.created_at = Timestamp(7);
    db.upsert_source_block(&rec).unwrap();
    db.upsert_placement(&placement(x, PlacementStatus::Alive))
        .unwrap();

    let batch = vec![(queued(&db, &p, &a), a.clone())];
    let result = run_pipeline(
        &db,
        &c.config,
        &c.encoder,
        &batch,
        BlockTypeTag::Pack,
        &c.config.mock_holders,
        &[],
        0.5,
    )
    .unwrap();

    assert_eq!(result.source_block_id, x);
    assert_eq!(result.k, rec.k);
    let kept = block(&db, x);
    assert_eq!(kept.current_alive, 5);
    assert_eq!(kept.current_reliability, 0.93);
    assert_eq!(kept.created_at, Timestamp(7));
    assert_eq!(db.list_all_source_blocks().unwrap().len(), 1);
    assert_eq!(db.list_placements_for_block(&x).unwrap().len(), 1);
}

/// Р-4: the block turns `Deleting` between the choice and the write → nothing is written,
/// and the next choice takes the next generation.
#[test]
fn pipeline_rechecks_choice_inside_write_txn() {
    let db = Db::open_in_memory().unwrap();
    let compressed = compress_block(&content(8, 4096)).unwrap();
    let sealed = choose_generation(&db, &compressed, &KEY).unwrap();
    assert_eq!(sealed.generation, 0);
    assert!(sealed.skipped.is_empty());

    // The deletion executor writes this id `Deleting` meanwhile.
    active_block(&db, sealed.block_id);
    release(&db, sealed.block_id);
    let mut fresh = block(&db, sealed.block_id);
    fresh.status = SourceBlockStatus::Active;
    fresh.created_at = Timestamp(12_345);
    match commit_block_record(&db, &fresh).unwrap() {
        Committed::Changed(s) => assert_eq!(s, Serviceability::Releasing),
        other => panic!("expected Changed, got {other:?}"),
    }
    assert_eq!(
        block(&db, sealed.block_id).status,
        SourceBlockStatus::Deleting,
        "nothing written over the released id"
    );

    let again = choose_generation(&db, &compressed, &KEY).unwrap();
    assert_eq!(again.generation, 1);
    assert_eq!(
        again.skipped,
        vec![(sealed.block_id, Serviceability::Releasing)]
    );
    // A free id is written; an id in service is kept.
    let mut rec1 = fresh.clone();
    rec1.block_id = again.block_id;
    rec1.seal_generation = 1;
    assert!(matches!(
        commit_block_record(&db, &rec1).unwrap(),
        Committed::Written
    ));
    assert!(matches!(
        commit_block_record(&db, &rec1).unwrap(),
        Committed::Kept(_)
    ));
}

/// Every generation of this plaintext is being released: the pack fails with an error and
/// the file stays queued and pending.
#[test]
fn pipeline_fails_after_max_generations_and_keeps_files_queued() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let a = content(9, 4096);
    let p = write(&dir, "m.bin", &a);
    c.process_event(event(&p, DirtyKind::Added)).unwrap();
    let qf = c.queues.values().flatten().next().unwrap().clone();
    let compressed = compress_block(&build_plaintext(&[(qf, a.clone())])).unwrap();
    let template = {
        active_block(&db, SourceBlockId([0; 32]));
        let mut t = block(&db, SourceBlockId([0; 32]));
        db.delete_source_block(&SourceBlockId([0; 32])).unwrap();
        t.status = SourceBlockStatus::Deleting;
        t
    };
    let mut txn = db.write_txn().unwrap();
    for g in 0..MAX_BLOCK_GENERATIONS {
        let stored = seal_compressed(&compressed, &KEY, g).unwrap();
        let mut rec = template.clone();
        rec.block_id = SourceBlockId(*blake3::hash(&stored).as_bytes());
        rec.seal_generation = g;
        txn.upsert_source_block(&rec).unwrap();
    }
    txn.commit().unwrap();

    assert!(c.flush_all(true, &Default::default()).is_err());

    assert_eq!(queued_paths(&c), [p.clone()].into());
    assert!(last(&db, &p).backed_up_at.is_none());
    assert_eq!(
        db.list_all_source_blocks().unwrap().len(),
        MAX_BLOCK_GENERATIONS as usize
    );
}

/// M6: the rebuild seals at the record's generation; at generation 0 it would not match.
#[test]
fn rebuild_uses_record_generation() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let a = content(10, 4096);
    let (p, _x0) = backed_up_deleted_released(&mut c, &db, &dir, "r.bin", &a);
    write(&dir, "r.bin", &a);
    let x1 = backed_up(&mut c, &db, &p, DirtyKind::Added);
    let rec = block(&db, x1);
    assert_eq!(rec.seal_generation, 1);
    let scope = RebuildScope::new(DEV, None);

    let blob = rebuild_blob_blocking(&db, &rec, &KEY, &scope).unwrap();
    assert_eq!(blake3::hash(&blob).as_bytes(), &x1.0);

    let mut at_zero = rec.clone();
    at_zero.seal_generation = 0;
    assert!(rebuild_blob_blocking(&db, &at_zero, &KEY, &scope).is_err());
}

/// К10: a queued file changed before the flush to content that lies only on a block being
/// released is packed (the flush-time "already in the network" check inherits the gate).
#[test]
fn flush_packs_file_changed_to_content_only_on_releasing_block() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let (a, b) = (content(11, 4096), content(12, 4096));
    let xb = SourceBlockId([0x38; 32]);
    active_block(&db, xb);
    release(&db, xb);
    record_on(&db, 99, "/elsewhere/b.bin", hash(&b), xb);
    let p = write(&dir, "f.bin", &a);
    c.process_event(event(&p, DirtyKind::Added)).unwrap();
    write(&dir, "f.bin", &b);

    assert_eq!(flush(&mut c), 1);

    let v = last(&db, &p);
    assert!(v.backed_up_at.is_some(), "packed, not skipped");
    assert_eq!(v.content_hash, hash(&b));
    assert_ne!(v.source_block_id, xb);
}

/// backup-i8 (2026-09-30): a whole folder returned by one `mv` and packed from the same
/// members in the same order is the same plaintext as the pack being released: it takes the
/// next generation of the pack, and every member points at it.
#[test]
fn returned_pack_of_same_members_takes_next_generation() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let members: Vec<(String, Vec<u8>)> = (0..3u8)
        .map(|i| {
            let bytes = content(40 + i, 4096);
            (write(&dir, &format!("m{i}.bin"), &bytes), bytes)
        })
        .collect();
    for (p, _) in &members {
        c.process_event(event(p, DirtyKind::Added)).unwrap();
    }
    assert_eq!(flush(&mut c), 1, "setup: one pack");
    let pm = last(&db, &members[0].0).source_block_id;
    for (p, _) in &members {
        assert_eq!(
            last(&db, p).source_block_id,
            pm,
            "setup: members on one pack"
        );
        delete(&mut c, p);
    }
    release(&db, pm);

    for (p, bytes) in &members {
        std::fs::write(p, bytes).unwrap();
        c.process_event(event(p, DirtyKind::Added)).unwrap();
    }
    assert_eq!(flush(&mut c), 1);

    let again = last(&db, &members[0].0).source_block_id;
    assert_ne!(again, pm);
    assert_eq!(block(&db, again).seal_generation, 1, "the same plaintext");
    for (p, _) in &members {
        let v = last(&db, p);
        assert_eq!(v.source_block_id, again);
        assert!(v.backed_up_at.is_some());
    }
    assert_eq!(block(&db, pm).status, SourceBlockStatus::Deleting);
}

/// Р-4 through `run_pipeline`: the deletion executor writes the chosen id between the choice
/// and the write transaction → nothing is written over it, the loop chooses again and takes
/// the next generation.
#[test]
fn run_pipeline_takes_next_generation_when_chosen_id_turns_releasing_before_the_write() {
    use super::generation::BEFORE_COMMIT;
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let p = write(&dir, "race.bin", &content(50, 4096));
    c.process_event(event(&p, DirtyKind::Added)).unwrap();
    let seen: std::rc::Rc<std::cell::RefCell<Vec<SourceBlockId>>> = Default::default();
    let seen_in_hook = std::rc::Rc::clone(&seen);
    BEFORE_COMMIT.with(|h| {
        *h.borrow_mut() = Some(Box::new(move |db: &Db, id: SourceBlockId| {
            if seen_in_hook.borrow().is_empty() {
                active_block(db, id);
                release(db, id);
            }
            seen_in_hook.borrow_mut().push(id);
        }));
    });

    let packed = flush(&mut c);
    BEFORE_COMMIT.with(|h| *h.borrow_mut() = None);

    assert_eq!(packed, 1);
    let ids = seen.borrow().clone();
    assert_eq!(ids.len(), 2, "chosen twice: {ids:?}");
    assert_ne!(ids[0], ids[1]);
    let v = last(&db, &p);
    assert_eq!(v.source_block_id, ids[1]);
    assert_eq!(block(&db, ids[1]).seal_generation, 1);
    let raced = block(&db, ids[0]);
    assert_eq!(
        raced.status,
        SourceBlockStatus::Deleting,
        "not written over"
    );
    assert_eq!(raced.seal_generation, 0);
}
