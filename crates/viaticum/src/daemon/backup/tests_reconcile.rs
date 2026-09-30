// L1b К3 (backup-i8, backup-i25; INV-B1, INV-RC): the reconcile hands paths to the watcher.
//
// Real redb (in memory), real files in a TempDir, real pipeline. The watcher is a test
// receiver: a handed path is re-submitted here with `process_event(Modified)`, as the watcher
// does after its checks (those are unit-tested in `watcher/tests_resubmit.rs`).
// Spec: private/beta-planning/tasks/c_l1b_serviceable_block.md (v1.1) §1.5 Р-5, §2.2.

use std::path::PathBuf;

use tempfile::TempDir;
use tokio::sync::mpsc;
use viaticum_core::db::Db;
use viaticum_core::types::{
    DeviceId, FileId, FileRecord, FileVersion, LocalState, PlacementStatus, SourceBlockId,
    SourceBlockStatus, SymbolPlacement, Timestamp, to_cbor_bytes,
};

use super::reconcile::{ReconcileStats, ResubmitBatch, ResubmitReason, SERVICEABILITY_LOADS};
use super::tests_current::{
    DEV, active_block, backed_up, content, coord, event, flush, last, write,
};
use super::{BackupCoordinator, DirtyKind};

/// A coordinator whose reconcile sends to a test receiver of `capacity` batches.
fn wired(db: &Db, capacity: usize) -> (BackupCoordinator, mpsc::Receiver<ResubmitBatch>) {
    let (tx, rx) = mpsc::channel(capacity);
    let mut c = coord(db);
    c.config.resubmit_tx = Some(tx);
    (c, rx)
}

/// The batches waiting in the channel, flattened.
fn received(rx: &mut mpsc::Receiver<ResubmitBatch>) -> Vec<(PathBuf, ResubmitReason)> {
    std::iter::from_fn(|| rx.try_recv().ok())
        .flat_map(|b| b.items)
        .collect()
}

fn release(db: &Db, block: SourceBlockId) {
    let mut rec = db.get_source_block(&block).unwrap().expect("block record");
    rec.status = SourceBlockStatus::Deleting;
    db.upsert_source_block(&rec).unwrap();
    db.upsert_placement(&SymbolPlacement {
        source_block_id: block,
        holder_id: DeviceId([0x77; 32]),
        file_id: FileId(1),
        esi_ranges: vec![(0, 4)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Deleting,
        last_verified: None,
        placed_at: Timestamp(1),
        consecutive_misses: 0,
    })
    .unwrap();
}

/// A record at `path` (never on disk) with one version: backed up on `block`, or pending.
fn record(db: &Db, id: u64, path: &str, block: Option<SourceBlockId>, confirmed: bool) {
    db.upsert_file(&FileRecord {
        file_id: FileId(id),
        path: path.to_string(),
        importance: 0.5,
        devices: vec![(DEV, LocalState::Present)],
        versions: vec![FileVersion {
            content_hash: [id as u8; 32],
            source_block_id: block.unwrap_or(SourceBlockId([0; 32])),
            k: 3,
            t: 1024,
            created_at: Timestamp(100),
            backed_up_at: block.map(|_| Timestamp(100)),
        }],
        first_seen: Timestamp(100),
        on_disk_confirmed: confirmed,
    })
    .unwrap();
}

fn stats(c: &mut BackupCoordinator) -> ReconcileStats {
    c.reconcile_current_blocks().unwrap()
}

/// M5, INV-B1: a live file whose current block turned `Deleting` (a return racing the
/// deletion tick) goes to the watcher; its re-submission is backed up again at the next
/// generation.
#[test]
fn reconcile_hands_live_file_whose_current_block_is_deleting_to_watcher() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let (mut c, mut rx) = wired(&db, 4);
    let a = content(20, 4096);
    let p = write(&dir, "live.bin", &a);
    let x0 = backed_up(&mut c, &db, &p, DirtyKind::Added);
    assert_eq!(
        stats(&mut c),
        ReconcileStats::default(),
        "in service: nothing"
    );
    release(&db, x0);

    let s = stats(&mut c);

    assert_eq!(s.releasing, 1);
    assert_eq!(
        received(&mut rx),
        vec![(PathBuf::from(&p), ResubmitReason::Releasing)]
    );
    // The watcher re-submits it.
    c.process_event(event(&p, DirtyKind::Modified)).unwrap();
    assert_eq!(flush(&mut c), 1);
    let v = last(&db, &p);
    assert_ne!(v.source_block_id, x0);
    let x1 = db.get_source_block(&v.source_block_id).unwrap().unwrap();
    assert_eq!(x1.seal_generation, 1);
    assert_eq!(stats(&mut c), ReconcileStats::default(), "converged");
}

#[test]
fn reconcile_hands_live_file_whose_current_block_is_missing_to_watcher() {
    let db = Db::open_in_memory().unwrap();
    let (mut c, mut rx) = wired(&db, 4);
    record(
        &db,
        1,
        "/w/lost-block.bin",
        Some(SourceBlockId([0x41; 32])),
        true,
    );

    assert_eq!(stats(&mut c).releasing, 1);
    assert_eq!(
        received(&mut rx),
        vec![(
            PathBuf::from("/w/lost-block.bin"),
            ResubmitReason::Releasing
        )]
    );
}

/// A deleted record on a released block is the deletion working: nothing to hand over.
#[test]
fn reconcile_ignores_deleted_record_on_releasing_block() {
    let db = Db::open_in_memory().unwrap();
    let (mut c, mut rx) = wired(&db, 4);
    let x = SourceBlockId([0x42; 32]);
    active_block(&db, x);
    release(&db, x);
    record(&db, 1, "/w/gone.bin", Some(x), true);
    let mut rec = db.get_file("/w/gone.bin").unwrap().unwrap();
    rec.devices = vec![(DEV, LocalState::Deleted(Timestamp(200)))];
    db.upsert_file(&rec).unwrap();
    // Present on another device only: not this device's to re-submit.
    record(&db, 2, "/w/other.bin", Some(x), true);
    let mut other = db.get_file("/w/other.bin").unwrap().unwrap();
    other.devices = vec![(DeviceId([9; 32]), LocalState::Present)];
    db.upsert_file(&other).unwrap();

    assert_eq!(stats(&mut c), ReconcileStats::default());
    assert!(received(&mut rx).is_empty());
}

/// `Stale` (the L2 window) is L2's to revive: the reconcile leaves it.
#[test]
fn reconcile_ignores_stale_current_block() {
    let db = Db::open_in_memory().unwrap();
    let (mut c, mut rx) = wired(&db, 4);
    let x = SourceBlockId([0x43; 32]);
    active_block(&db, x);
    let mut b = db.get_source_block(&x).unwrap().unwrap();
    b.status = SourceBlockStatus::Stale;
    db.upsert_source_block(&b).unwrap();
    record(&db, 1, "/w/window.bin", Some(x), true);

    assert_eq!(stats(&mut c), ReconcileStats::default());
    assert!(received(&mut rx).is_empty());
}

/// M4, backup-i25: the queue died with the process (`kill -9` before the idle flush); the
/// pending version is handed over at the next start.
#[test]
fn reconcile_hands_pending_version_in_no_queue_to_watcher() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = write(&dir, "q.bin", &content(21, 4096));
    {
        let mut before_kill = coord(&db);
        before_kill
            .process_event(event(&p, DirtyKind::Added))
            .unwrap();
        // killed: its queue is gone, the pending version stays in the catalog.
    }
    let (mut c, mut rx) = wired(&db, 4);

    assert_eq!(stats(&mut c).pending, 1);
    assert_eq!(
        received(&mut rx),
        vec![(PathBuf::from(&p), ResubmitReason::Pending)]
    );
    c.process_event(event(&p, DirtyKind::Modified)).unwrap();
    assert_eq!(flush(&mut c), 1);
    assert!(last(&db, &p).backed_up_at.is_some());
}

#[test]
fn reconcile_leaves_queued_pending_version_alone() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let (mut c, mut rx) = wired(&db, 4);
    let p = write(&dir, "q.bin", &content(22, 4096));
    c.process_event(event(&p, DirtyKind::Added)).unwrap();

    assert_eq!(stats(&mut c), ReconcileStats::default());
    assert!(received(&mut rx).is_empty());
}

/// INV-RC: the paths are not on disk at all, and the catalog, blocks and placements are
/// byte-identical after the pass.
#[test]
fn reconcile_reads_no_file_and_writes_nothing() {
    let db = Db::open_in_memory().unwrap();
    let (mut c, mut rx) = wired(&db, 4);
    let x = SourceBlockId([0x44; 32]);
    active_block(&db, x);
    release(&db, x);
    record(&db, 1, "/nowhere/a.bin", Some(x), true);
    record(&db, 2, "/nowhere/b.bin", None, false);
    let snapshot = |db: &Db| {
        (
            to_cbor_bytes(&db.list_all_files().unwrap()),
            to_cbor_bytes(&db.list_all_source_blocks().unwrap()),
            to_cbor_bytes(&db.list_all_placements().unwrap()),
        )
    };
    let before = snapshot(&db);

    let s = stats(&mut c);

    assert_eq!((s.releasing, s.pending), (1, 1));
    assert_eq!(received(&mut rx).len(), 2);
    assert_eq!(snapshot(&db), before);
}

/// N6: a path whose record does not change after its re-submission is skipped 1, 2, 4 …
/// passes; a change of the record resets.
#[test]
fn reconcile_backs_off_path_whose_record_did_not_change() {
    let db = Db::open_in_memory().unwrap();
    let (mut c, mut rx) = wired(&db, 64);
    record(&db, 1, "/w/stuck.bin", None, true);
    let mut sent = Vec::new();
    for _ in 0..16 {
        let s = stats(&mut c);
        sent.push(s.pending);
        assert_eq!(s.pending + s.backing_off, 1);
    }
    assert_eq!(sent, vec![1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0]);
    assert_eq!(received(&mut rx).len(), 4);

    // The record changes (a new pending version): sent at once, the backoff starts over.
    let mut rec = db.get_file("/w/stuck.bin").unwrap().unwrap();
    rec.versions[0].created_at = Timestamp(999);
    db.upsert_file(&rec).unwrap();
    let again: Vec<u32> = (0..3).map(|_| stats(&mut c).pending).collect();
    assert_eq!(again, vec![1, 0, 1]);
}

/// The coordinator never waits on the watcher: a full channel answers at once, and the
/// batch is built again by the next pass (the backoff did not advance).
#[test]
fn reconcile_channel_full_keeps_batch_for_next_pass_without_blocking() {
    let db = Db::open_in_memory().unwrap();
    let (mut c, mut rx) = wired(&db, 1);
    record(&db, 1, "/w/p.bin", None, true);
    c.config
        .resubmit_tx
        .as_ref()
        .unwrap()
        .try_send(ResubmitBatch { items: vec![] })
        .unwrap();

    let s = stats(&mut c);
    assert!(s.channel_full);
    assert_eq!(s.pending, 1);

    assert!(received(&mut rx).is_empty(), "only the filler was there");
    let s = stats(&mut c);
    assert!(!s.channel_full);
    assert_eq!(
        received(&mut rx),
        vec![(PathBuf::from("/w/p.bin"), ResubmitReason::Pending)]
    );
}

#[test]
fn reconcile_loads_blocks_and_placements_once_per_pass() {
    let db = Db::open_in_memory().unwrap();
    let (mut c, _rx) = wired(&db, 4);
    for i in 0..5u8 {
        let x = SourceBlockId([0x50 + i; 32]);
        active_block(&db, x);
        record(&db, u64::from(i) + 1, &format!("/w/{i}.bin"), Some(x), true);
    }
    let before = SERVICEABILITY_LOADS.with(|l| l.get());

    stats(&mut c);

    assert_eq!(SERVICEABILITY_LOADS.with(|l| l.get()) - before, 1);
}

/// After DR (records unconfirmed): only a releasing or pending current version is handed
/// over; a record in service is not touched (dr-i64: the reconcile confirms nothing).
#[test]
fn reconcile_on_unconfirmed_records_touches_only_releasing_or_pending() {
    let db = Db::open_in_memory().unwrap();
    let (mut c, mut rx) = wired(&db, 4);
    let (ok, rel) = (SourceBlockId([0x61; 32]), SourceBlockId([0x62; 32]));
    active_block(&db, ok);
    active_block(&db, rel);
    release(&db, rel);
    record(&db, 1, "/dr/served.bin", Some(ok), false);
    record(&db, 2, "/dr/released.bin", Some(rel), false);
    record(&db, 3, "/dr/pending.bin", None, false);

    stats(&mut c);

    let mut got = received(&mut rx);
    got.sort();
    assert_eq!(
        got,
        vec![
            (PathBuf::from("/dr/pending.bin"), ResubmitReason::Pending),
            (PathBuf::from("/dr/released.bin"), ResubmitReason::Releasing),
        ]
    );
    for p in ["/dr/served.bin", "/dr/released.bin", "/dr/pending.bin"] {
        assert!(!db.get_file(p).unwrap().unwrap().on_disk_confirmed);
    }
}
