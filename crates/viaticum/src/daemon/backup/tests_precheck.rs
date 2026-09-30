// R1-d-b (W3): `precheck_sources` judges by `metadata` alone whether a block can be rebuilt from
// this device's files — before anybody takes memory or reads a byte. `Missing` and `OverLimit`
// mean a rebuild fails; `Ready` means a candidate file exists within the size limit.
//
// Real redb (in memory), real files in a TempDir, the real pipeline makes the blocks.

use tempfile::TempDir;
use viaticum_core::db::Db;
use viaticum_core::types::{SourceBlockRecord, SourceBlockType};

use super::rebuild::{RebuildScope, SourceCheck, precheck_sources};
use super::tests_current::{DEV, coord, event, flush, last};
use super::{BackupCoordinator, DirtyKind};

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

    /// Write `files` and back them up into one block; returns its record.
    fn block_of(&mut self, files: &[(&str, &[u8])]) -> SourceBlockRecord {
        for (name, bytes) in files {
            std::fs::write(self.path(name), bytes).unwrap();
            let e = event(&self.path(name), DirtyKind::Added);
            self.c.process_event(e).unwrap();
        }
        assert_eq!(flush(&mut self.c), 1, "setup: one block");
        let id = last(&self.db, &self.path(files[0].0)).source_block_id;
        self.db.get_source_block(&id).unwrap().expect("record")
    }

    fn check(&self, block: &SourceBlockRecord, scope: &RebuildScope) -> SourceCheck {
        precheck_sources(&self.db, block, scope).expect("catalog read")
    }
}

fn scope() -> RebuildScope {
    RebuildScope::new(DEV, None)
}

#[test]
fn precheck_is_ready_when_every_member_file_is_there() {
    let mut w = World::new();
    let block = w.block_of(&[("a.txt", b"alpha alpha"), ("b.txt", b"beta beta beta")]);
    assert!(matches!(block.block_type, SourceBlockType::Pack { .. }));
    assert_eq!(w.check(&block, &scope()), SourceCheck::Ready);
}

#[test]
fn precheck_is_missing_when_a_pack_member_is_gone() {
    let mut w = World::new();
    let block = w.block_of(&[("a.txt", b"alpha alpha"), ("b.txt", b"beta beta beta")]);
    std::fs::remove_file(w.path("b.txt")).unwrap();
    assert_eq!(w.check(&block, &scope()), SourceCheck::Missing);
}

#[test]
fn precheck_is_over_limit_when_a_member_is_above_the_limit() {
    let mut w = World::new();
    let block = w.block_of(&[("a.txt", b"alpha alpha"), ("b.txt", &[7u8; 4096])]);
    let small = scope().with_max_source_bytes(1024);
    assert_eq!(w.check(&block, &small), SourceCheck::OverLimit);
    // The same files are fine under a limit that holds them.
    assert_eq!(
        w.check(&block, &scope().with_max_source_bytes(4096)),
        SourceCheck::Ready
    );
}

/// A Single block: its one file, found by the content hash of the first version that points at
/// the block, anywhere on the device.
#[test]
fn precheck_of_a_single_block_follows_its_file() {
    let mut w = World::new();
    let mut block = w.block_of(&[("only.txt", b"just one file here")]);
    block.block_type = SourceBlockType::Single;
    assert_eq!(w.check(&block, &scope()), SourceCheck::Ready);
    assert_eq!(
        w.check(&block, &scope().with_max_source_bytes(4)),
        SourceCheck::OverLimit
    );
    std::fs::remove_file(w.path("only.txt")).unwrap();
    assert_eq!(w.check(&block, &scope()), SourceCheck::Missing);
}

/// A copy of the content on another path serves the member: the file the record names is gone,
/// yet the block is rebuildable, and the precheck says so (it looks where the rebuild looks).
#[test]
fn precheck_finds_the_content_on_another_path() {
    let mut w = World::new();
    let mut block = w.block_of(&[("orig.txt", b"content that moves")]);
    block.block_type = SourceBlockType::Single;
    // The watcher sees the copy as a new file with the same content.
    std::fs::copy(w.path("orig.txt"), w.path("copy.txt")).unwrap();
    let e = event(&w.path("copy.txt"), DirtyKind::Added);
    w.c.process_event(e).unwrap();
    flush(&mut w.c);
    std::fs::remove_file(w.path("orig.txt")).unwrap();
    assert_eq!(w.check(&block, &scope()), SourceCheck::Ready);
}

/// No catalog record at all for the block's content: nothing to look for.
#[test]
fn precheck_is_missing_for_a_block_no_file_points_to() {
    let mut w = World::new();
    let mut block = w.block_of(&[("a.txt", b"alpha alpha"), ("b.txt", b"beta beta beta")]);
    block.block_id = viaticum_core::types::SourceBlockId([0x77; 32]);
    block.block_type = SourceBlockType::Single;
    assert_eq!(w.check(&block, &scope()), SourceCheck::Missing);
}
