// L0 К2b (backup-i22, INV-RB): a pack stays rebuildable after renames, copies, swaps,
// rollbacks — the catalog is built by processing the events in EVERY order, and the
// check is the one PoS and repair rely on: `rebuild_source_blob` succeeds, i.e.
// blake3(rebuilt blob) == block id.
//
// Real redb (in memory), real files in a TempDir, real pipeline.

use std::path::PathBuf;

use tempfile::TempDir;
use viaticum_core::db::Db;
use viaticum_core::types::{DeviceId, LocalState, SourceBlockId};

use super::pipeline::rebuild_source_blob;
use super::rebuild::{RebuildError, RebuildScope};
use super::tests_current::{DEV, content, coord, event, flush, hash, last, record};
use super::{BackupCoordinator, DirtyEvent, DirtyKind};

const KEY: [u8; 32] = [42u8; 32];
const OTHER: DeviceId = DeviceId([9u8; 32]);

/// Every permutation of `0..n`.
fn orders(n: usize) -> Vec<Vec<usize>> {
    fn go(rest: &mut Vec<usize>, cur: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if rest.is_empty() {
            out.push(cur.clone());
            return;
        }
        for i in 0..rest.len() {
            let x = rest.remove(i);
            cur.push(x);
            go(rest, cur, out);
            cur.pop();
            rest.insert(i, x);
        }
    }
    let mut out = Vec::new();
    go(&mut (0..n).collect(), &mut Vec::new(), &mut out);
    out
}

struct World {
    db: Db,
    dir: TempDir,
    c: BackupCoordinator,
}

impl World {
    fn new() -> Self {
        let db = Db::open_in_memory().unwrap();
        let c = coord(&db);
        World {
            db,
            dir: TempDir::new().unwrap(),
            c,
        }
    }

    fn path(&self, name: &str) -> String {
        self.dir.path().join(name).to_string_lossy().into_owned()
    }

    fn put(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.path(name), bytes).unwrap();
    }

    fn mv(&self, from: &str, to: &str) {
        std::fs::rename(self.path(from), self.path(to)).unwrap();
    }

    fn rm(&self, name: &str) {
        std::fs::remove_file(self.path(name)).unwrap();
    }

    fn ev(&self, name: &str, kind: DirtyKind) -> DirtyEvent {
        event(&self.path(name), kind)
    }

    /// Write `files` and back them up in one pack; returns its block.
    fn pack(&mut self, files: &[(&str, &[u8])]) -> SourceBlockId {
        for (name, bytes) in files {
            self.put(name, bytes);
            let e = self.ev(name, DirtyKind::Added);
            self.c.process_event(e).unwrap();
        }
        assert_eq!(flush(&mut self.c), 1, "setup: one block");
        let block = last(&self.db, &self.path(files[0].0)).source_block_id;
        for (name, _) in files {
            assert_eq!(
                last(&self.db, &self.path(name)).source_block_id,
                block,
                "setup: {name} in the pack"
            );
        }
        block
    }

    fn apply(&mut self, events: &[DirtyEvent], order: &[usize]) {
        for i in order {
            self.c.process_event(events[*i].clone()).unwrap();
        }
    }

    async fn rebuild(&self, block: SourceBlockId, scope: &RebuildScope) -> anyhow::Result<()> {
        let sb = self
            .db
            .get_source_block(&block)
            .unwrap()
            .expect("block record");
        rebuild_source_blob(&self.db, &sb, &KEY, scope)
            .await
            .map(|_| ())
    }

    async fn rebuilds(&self, block: SourceBlockId) -> anyhow::Result<()> {
        self.rebuild(block, &RebuildScope::new(DEV, None)).await
    }
}

/// `mv a a2`: the member is read from its new path, whichever event comes first.
#[tokio::test]
async fn rebuild_after_rename_reads_new_path_in_any_order() {
    let (a, b) = (content(1, 4096), content(2, 4096));
    for order in orders(2) {
        let mut w = World::new();
        let x = w.pack(&[("a.bin", &a), ("b.bin", &b)]);
        w.mv("a.bin", "a2.bin");
        let evs = [
            w.ev("a.bin", DirtyKind::Deleted),
            w.ev("a2.bin", DirtyKind::Added),
        ];
        w.apply(&evs, &order);

        w.rebuilds(x)
            .await
            .unwrap_or_else(|e| panic!("order {order:?}: {e:#}"));
        assert_eq!(last(&w.db, &w.path("a2.bin")).source_block_id, x);
    }
}

/// `mv a b` (b in another pack), then a new `a`: a's member content A is read at b.
#[tokio::test]
async fn rebuild_after_mv_a_b_then_new_a_reads_b_in_any_order() {
    let (a, b, c, n) = (
        content(3, 4096),
        content(4, 4096),
        content(5, 4096),
        content(6, 4096),
    );
    for order in orders(2) {
        let mut w = World::new();
        let x = w.pack(&[("a.bin", &a), ("c.bin", &c)]);
        w.pack(&[("b.bin", &b)]);
        w.mv("a.bin", "b.bin");
        w.put("a.bin", &n);
        let evs = [
            w.ev("b.bin", DirtyKind::Added),
            w.ev("a.bin", DirtyKind::Added),
        ];
        w.apply(&evs, &order);

        w.rebuilds(x)
            .await
            .unwrap_or_else(|e| panic!("order {order:?}: {e:#}"));
    }
}

/// a (pack X) and b (pack Y) swapped via tmp: both packs rebuild.
#[tokio::test]
async fn rebuild_after_swap_via_tmp_across_packs_in_any_order() {
    let (a, b, c, d) = (
        content(7, 4096),
        content(8, 4096),
        content(9, 4096),
        content(10, 4096),
    );
    for order in orders(3) {
        let mut w = World::new();
        let x = w.pack(&[("a.bin", &a), ("c.bin", &c)]);
        let y = w.pack(&[("b.bin", &b), ("d.bin", &d)]);
        w.mv("a.bin", "tmp.bin");
        w.mv("b.bin", "a.bin");
        w.mv("tmp.bin", "b.bin");
        let evs = [
            w.ev("tmp.bin", DirtyKind::Deleted),
            w.ev("a.bin", DirtyKind::Added),
            w.ev("b.bin", DirtyKind::Added),
        ];
        w.apply(&evs, &order);

        w.rebuilds(x)
            .await
            .unwrap_or_else(|e| panic!("X, order {order:?}: {e:#}"));
        w.rebuilds(y)
            .await
            .unwrap_or_else(|e| panic!("Y, order {order:?}: {e:#}"));
    }
}

/// a and b of ONE pack swapped via tmp: each record's last version now holds its
/// neighbour's content on the same block; the member hash comes from the FIRST version
/// (guard of M12: "last version" puts b's bytes into a's slot).
#[tokio::test]
async fn rebuild_after_swap_via_tmp_within_one_pack_in_any_order() {
    let (a, b) = (content(11, 4096), content(12, 4096));
    for order in orders(3) {
        let mut w = World::new();
        let x = w.pack(&[("a.bin", &a), ("b.bin", &b)]);
        w.mv("a.bin", "tmp.bin");
        w.mv("b.bin", "a.bin");
        w.mv("tmp.bin", "b.bin");
        let evs = [
            w.ev("tmp.bin", DirtyKind::Deleted),
            w.ev("a.bin", DirtyKind::Added),
            w.ev("b.bin", DirtyKind::Added),
        ];
        w.apply(&evs, &order);
        let ra = record(&w.db, &w.path("a.bin"));
        assert_eq!(ra.versions.first().unwrap().content_hash, hash(&a));
        assert_eq!(ra.versions.last().unwrap().content_hash, hash(&b));
        assert_eq!(ra.versions.last().unwrap().source_block_id, x);

        w.rebuilds(x)
            .await
            .unwrap_or_else(|e| panic!("order {order:?}: {e:#}"));
    }
}

/// `mv b a` inside one pack, A kept elsewhere (`keep`): a's member is read at keep, b's
/// member at a. Without a copy of A the pack is honestly not rebuildable (F-pack, L3).
#[tokio::test]
async fn rebuild_after_mv_b_over_a_within_one_pack_in_any_order() {
    let (a, b) = (content(13, 4096), content(14, 4096));
    for order in orders(3) {
        let mut w = World::new();
        let x = w.pack(&[("a.bin", &a), ("b.bin", &b)]);
        w.put("keep.bin", &a);
        w.mv("b.bin", "a.bin");
        let evs = [
            w.ev("keep.bin", DirtyKind::Added),
            w.ev("a.bin", DirtyKind::Added),
            w.ev("b.bin", DirtyKind::Deleted),
        ];
        w.apply(&evs, &order);

        w.rebuilds(x)
            .await
            .unwrap_or_else(|e| panic!("order {order:?}: {e:#}"));
    }
}

/// `cp b a` inside one pack, A kept elsewhere: as above, b still in place.
#[tokio::test]
async fn rebuild_after_cp_b_over_a_within_one_pack_in_any_order() {
    let (a, b) = (content(15, 4096), content(16, 4096));
    for order in orders(2) {
        let mut w = World::new();
        let x = w.pack(&[("a.bin", &a), ("b.bin", &b)]);
        w.put("keep.bin", &a);
        w.put("a.bin", &b);
        let evs = [
            w.ev("keep.bin", DirtyKind::Added),
            w.ev("a.bin", DirtyKind::Modified),
        ];
        w.apply(&evs, &order);

        w.rebuilds(x)
            .await
            .unwrap_or_else(|e| panic!("order {order:?}: {e:#}"));
    }
}

/// Ransomware renames a to a.locked and encrypts it; the user puts A back under the old
/// name from a restore: a is Present on A's block again and the pack rebuilds.
#[tokio::test]
async fn rebuild_after_ransomware_rename_and_restore_under_old_name() {
    let (a, b, e) = (content(17, 4096), content(18, 4096), content(19, 4096));
    for order in orders(2) {
        let mut w = World::new();
        let x = w.pack(&[("a.bin", &a), ("b.bin", &b)]);
        w.mv("a.bin", "a.bin.locked");
        w.put("a.bin.locked", &e);
        let evs = [
            w.ev("a.bin", DirtyKind::Deleted),
            w.ev("a.bin.locked", DirtyKind::Added),
        ];
        w.apply(&evs, &order);
        w.put("a.bin", &a);
        let back = w.ev("a.bin", DirtyKind::Added);
        w.c.process_event(back).unwrap();

        let ra = record(&w.db, &w.path("a.bin"));
        assert_eq!(ra.devices, vec![(DEV, LocalState::Present)]);
        assert_eq!(ra.versions.last().unwrap().source_block_id, x);
        w.rebuilds(x)
            .await
            .unwrap_or_else(|e| panic!("order {order:?}: {e:#}"));
    }
}

/// a edited (new block), its version 1 restored under another name: the old pack reads
/// a's packed content at the restored copy.
#[tokio::test]
async fn rebuild_after_restore_version_under_other_name() {
    let (a, b, a2) = (content(20, 4096), content(21, 4096), content(22, 4096));
    let mut w = World::new();
    let x = w.pack(&[("a.bin", &a), ("b.bin", &b)]);
    w.put("a.bin", &a2);
    let edit = w.ev("a.bin", DirtyKind::Modified);
    w.c.process_event(edit).unwrap();
    assert_eq!(flush(&mut w.c), 1, "setup: a2 on its own block");
    w.put("a-v1.bin", &a);
    let restored = w.ev("a-v1.bin", DirtyKind::Added);
    w.c.process_event(restored).unwrap();

    w.rebuilds(x).await.unwrap();
}

/// `cp a c; rm a`: the copy holds a's member.
#[tokio::test]
async fn rebuild_after_original_deleted_reads_copy() {
    let (a, b) = (content(23, 4096), content(24, 4096));
    for order in orders(2) {
        let mut w = World::new();
        let x = w.pack(&[("a.bin", &a), ("b.bin", &b)]);
        w.put("c.bin", &a);
        w.rm("a.bin");
        let evs = [
            w.ev("c.bin", DirtyKind::Added),
            w.ev("a.bin", DirtyKind::Deleted),
        ];
        w.apply(&evs, &order);

        w.rebuilds(x)
            .await
            .unwrap_or_else(|e| panic!("order {order:?}: {e:#}"));
    }
}

/// `cp a c; edit a`: the copy holds a's member.
#[tokio::test]
async fn rebuild_after_original_edited_reads_copy() {
    let (a, b, a2) = (content(25, 4096), content(26, 4096), content(27, 4096));
    for order in orders(2) {
        let mut w = World::new();
        let x = w.pack(&[("a.bin", &a), ("b.bin", &b)]);
        w.put("c.bin", &a);
        w.put("a.bin", &a2);
        let evs = [
            w.ev("c.bin", DirtyKind::Added),
            w.ev("a.bin", DirtyKind::Modified),
        ];
        w.apply(&evs, &order);

        w.rebuilds(x)
            .await
            .unwrap_or_else(|e| panic!("order {order:?}: {e:#}"));
    }
}

/// A candidate that cannot be read for another reason than NotFound (here: a directory
/// now stands at its path) is skipped for the next one, and is not reported gone (N3).
#[tokio::test]
async fn rebuild_skips_candidate_with_read_error_other_than_not_found() {
    let (a, b) = (content(28, 4096), content(29, 4096));
    let mut w = World::new();
    let x = w.pack(&[("a.bin", &a), ("b.bin", &b)]);
    w.put("c.bin", &a);
    let copy = w.ev("c.bin", DirtyKind::Added);
    w.c.process_event(copy).unwrap();
    w.rm("a.bin");
    std::fs::create_dir(w.path("a.bin")).unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    w.rebuild(x, &RebuildScope::new(DEV, Some(tx)))
        .await
        .unwrap();
    assert!(
        rx.try_recv().is_err(),
        "a path that exists is not reported gone"
    );
}

/// A renamed member whose old path's event was lost: the rebuild succeeds from the new
/// path AND reports the old path for a recheck (N2).
#[tokio::test]
async fn rebuild_sends_recheck_for_missing_candidate_even_on_success() {
    let (a, b) = (content(30, 4096), content(31, 4096));
    let mut w = World::new();
    let x = w.pack(&[("a.bin", &a), ("b.bin", &b)]);
    w.mv("a.bin", "a2.bin");
    let moved_in = w.ev("a2.bin", DirtyKind::Added);
    w.c.process_event(moved_in).unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    w.rebuild(x, &RebuildScope::new(DEV, Some(tx)))
        .await
        .unwrap();
    assert_eq!(rx.try_recv().ok(), Some(PathBuf::from(w.path("a.bin"))));
    assert!(rx.try_recv().is_err(), "only the gone path");
}

/// The content of a member is nowhere: `SourceMissing` naming the member, still
/// recognisable through the context `rebuild_source_blob` adds.
#[tokio::test]
async fn rebuild_reports_source_missing_when_content_nowhere() {
    let (a, b) = (content(32, 4096), content(33, 4096));
    let mut w = World::new();
    let x = w.pack(&[("a.bin", &a), ("b.bin", &b)]);
    let a_id = record(&w.db, &w.path("a.bin")).file_id;
    w.rm("a.bin");

    let err = w.rebuilds(x).await.expect_err("a's content is gone");
    match err.downcast_ref::<RebuildError>() {
        Some(RebuildError::SourceMissing { block, missing }) => {
            assert_eq!(*block, x);
            assert_eq!(missing, &vec![a_id]);
        }
        other => panic!("expected SourceMissing, got {other:?} ({err:#})"),
    }
}

/// A copy recorded for another device is not read for this device's rebuild.
#[tokio::test]
async fn rebuild_ignores_records_of_other_devices() {
    let (a, b) = (content(34, 4096), content(35, 4096));
    let mut w = World::new();
    let x = w.pack(&[("a.bin", &a), ("b.bin", &b)]);
    w.put("c.bin", &a);
    let copy = w.ev("c.bin", DirtyKind::Added);
    w.c.process_event(copy).unwrap();
    w.rm("a.bin");
    let mut rc = record(&w.db, &w.path("c.bin"));
    rc.devices = vec![(OTHER, LocalState::Present)];
    w.db.upsert_file(&rc).unwrap();

    let err = w.rebuilds(x).await.expect_err("c is another device's");
    assert!(matches!(
        err.downcast_ref::<RebuildError>(),
        Some(RebuildError::SourceMissing { .. })
    ));

    // Control: the same copy on this device is read.
    rc.devices = vec![(DEV, LocalState::Present)];
    w.db.upsert_file(&rc).unwrap();
    w.rebuilds(x).await.unwrap();
}

/// A catalog from before L1: the version records the hash of the file at enqueue while
/// the pack holds other bytes (those of the flush). No path has the recorded hash; the
/// member's own path, read unchecked as the last candidate, rebuilds the block — the
/// block id check still guards the result.
#[tokio::test]
async fn rebuild_reads_own_path_unchecked_when_version_hash_differs_from_packed_bytes() {
    let (a, b) = (content(36, 4096), content(37, 4096));
    let mut w = World::new();
    let x = w.pack(&[("a.bin", &a), ("b.bin", &b)]);
    let mut ra = record(&w.db, &w.path("a.bin"));
    ra.versions[0].content_hash = [7u8; 32];
    w.db.upsert_file(&ra).unwrap();

    w.rebuilds(x).await.unwrap();
}

/// The unchecked last candidate never hides a real loss: an edited member whose packed
/// content is nowhere still reports `SourceMissing` (the unchecked bytes do not give the
/// block id).
#[tokio::test]
async fn rebuild_of_edited_member_without_copy_stays_source_missing() {
    let (a, b, a2) = (content(38, 4096), content(39, 4096), content(40, 4096));
    let mut w = World::new();
    let x = w.pack(&[("a.bin", &a), ("b.bin", &b)]);
    w.put("a.bin", &a2);

    let err = w.rebuilds(x).await.expect_err("a's packed content is gone");
    assert!(
        matches!(
            err.downcast_ref::<RebuildError>(),
            Some(RebuildError::SourceMissing { .. })
        ),
        "error type lost: {err:#}"
    );
}
