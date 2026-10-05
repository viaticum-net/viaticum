// R1-d-a (backup-i4, backup-i5, backup-i7): a file above this machine's size limit is
// marked and not read, a grown protected file keeps its earlier version, the marks are
// judged again at start, and the packs and rebuilds are bounded.
//
// Real redb (in memory), real files in a TempDir, real pipeline. Spec:
// private/beta-planning/tasks/r1_bigfile_refusal.md §2A.3, §2A.4, §2A.6.

use std::io::Write;
use std::sync::{Arc, Mutex};

use tempfile::TempDir;
use viaticum_core::config::WatchConfig;
use viaticum_core::db::Db;
use viaticum_core::types::{SourceBlockId, SourceBlockType};

use super::pipeline::{
    compress_and_encrypt, compress_block, compress_framed, derive_block_key, derive_nonce,
    rebuild_blob_blocking, seal_compressed, seal_framed, unseal_framed,
};
use super::rebuild::{RebuildError, RebuildScope};
use super::tests_current::{
    BLOCK, DEV, backed_up, content, coord, event, flush, hash, last, queued_paths, record, write,
};
use super::{BackupCoordinator, DirtyKind};

const KEY: [u8; 32] = [42u8; 32];
/// The limit of these tests: a file above it is "too large".
const LIMIT: u64 = 100 * 1024;
/// The pack size of these tests (at most half the limit, J9): a file of this size or more is
/// a block of its own.
const PACK: u64 = 32 * 1024;

fn limited(db: &Db, dir: &TempDir) -> BackupCoordinator {
    let mut c = coord(db);
    c.config.max_file_size_bytes = LIMIT;
    c.config.source_block_size = PACK;
    c.config.watch_configs = vec![watch(dir)];
    c
}

fn watch(dir: &TempDir) -> WatchConfig {
    WatchConfig {
        path: dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 1.0,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    }
}

#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Run `f` and return what it logged at DEBUG and above (this thread only).
fn logged<T>(f: impl FnOnce() -> T) -> (T, String) {
    let buf = LogBuf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    let out = f();
    drop(guard);
    let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    (out, text)
}

fn count(logs: &str, needle: &str) -> usize {
    logs.lines().filter(|l| l.contains(needle)).count()
}

fn big(seed: u8) -> Vec<u8> {
    content(seed, LIMIT as usize + 1)
}

fn block_type(db: &Db, id: SourceBlockId) -> SourceBlockType {
    db.get_source_block(&id).unwrap().unwrap().block_type
}

// ─── Marks: the event ───────────────────────────────────────────────────────

#[test]
fn added_file_over_limit_gets_mark_and_no_version() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = limited(&db, &dir);
    let p = write(&dir, "huge.bin", &big(1));

    c.process_event(event(&p, DirtyKind::Added)).unwrap();

    let mark = db.get_too_large(&p).unwrap().expect("mark");
    assert_eq!(mark.size_bytes, LIMIT + 1);
    assert_eq!(mark.limit_bytes, LIMIT);
    assert!(db.get_file(&p).unwrap().is_none(), "no record, no version");
    assert!(queued_paths(&c).is_empty());
    assert_eq!(flush(&mut c), 0, "no block");

    // A file of exactly the limit is backed up (size == N).
    let edge = write(&dir, "edge.bin", &content(2, LIMIT as usize));
    c.process_event(event(&edge, DirtyKind::Added)).unwrap();
    assert!(db.get_too_large(&edge).unwrap().is_none());
    assert!(db.get_file(&edge).unwrap().is_some());
}

#[test]
fn added_file_over_limit_warns_once_on_repeated_events() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = limited(&db, &dir);
    let p = write(&dir, "huge.bin", &big(3));

    let ((), logs) = logged(|| {
        for kind in [DirtyKind::Added, DirtyKind::Modified, DirtyKind::Modified] {
            c.process_event(event(&p, kind)).unwrap();
        }
    });
    assert_eq!(count(&logs, "file too large to back up"), 1, "{logs}");
    assert_eq!(count(&logs, "too large, mark unchanged"), 2, "{logs}");
    assert!(logs.contains(&p), "the path is in the line: {logs}");

    // The limit changed (still below the size): a new WARN, first_seen kept.
    let first_seen = db.get_too_large(&p).unwrap().unwrap().first_seen;
    c.config.max_file_size_bytes = LIMIT - 1024;
    let ((), logs) = logged(|| c.process_event(event(&p, DirtyKind::Modified)).unwrap());
    assert_eq!(count(&logs, "file too large to back up"), 1, "{logs}");
    let mark = db.get_too_large(&p).unwrap().unwrap();
    assert_eq!(mark.limit_bytes, LIMIT - 1024);
    assert_eq!(mark.first_seen, first_seen);
}

#[test]
fn protected_file_growing_over_limit_keeps_old_version_supersedes_pending_and_gets_mark() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = limited(&db, &dir);
    let p = write(&dir, "grow.bin", &content(4, 4096));
    let xa = backed_up(&mut c, &db, &p, DirtyKind::Added);

    // An edit waits in the queue ...
    write(&dir, "grow.bin", &content(5, 4096));
    c.process_event(event(&p, DirtyKind::Modified)).unwrap();
    assert_eq!(queued_paths(&c).len(), 1, "setup: edit queued");
    assert_eq!(record(&db, &p).versions.len(), 2, "setup: pending version");

    // ... and then the file grows over the limit.
    write(&dir, "grow.bin", &big(6));
    c.process_event(event(&p, DirtyKind::Modified)).unwrap();

    assert!(db.get_too_large(&p).unwrap().is_some());
    let rec = record(&db, &p);
    assert_eq!(rec.versions.len(), 1, "pending edit dropped, none added");
    assert_eq!(rec.versions[0].source_block_id, xa, "the earlier version");
    assert!(rec.versions[0].backed_up_at.is_some());
    assert!(rec.on_disk_confirmed);
    assert!(queued_paths(&c).is_empty(), "queue entry dropped");
    assert_eq!(flush(&mut c), 0, "the grown content gets no block");
}

#[test]
fn marked_file_shrinking_under_limit_is_backed_up_and_mark_cleared() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = limited(&db, &dir);
    let p = write(&dir, "s.bin", &big(7));
    c.process_event(event(&p, DirtyKind::Added)).unwrap();
    assert!(db.get_too_large(&p).unwrap().is_some());

    write(&dir, "s.bin", &content(8, 4096));
    let ((), logs) = logged(|| c.process_event(event(&p, DirtyKind::Modified)).unwrap());
    assert!(db.get_too_large(&p).unwrap().is_none(), "mark cleared");
    assert_eq!(count(&logs, "within the size limit again"), 1, "{logs}");
    assert_eq!(flush(&mut c), 1);
    assert!(last(&db, &p).backed_up_at.is_some());
}

#[test]
fn deleted_marked_file_clears_mark() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = limited(&db, &dir);
    let p = write(&dir, "d.bin", &big(9));
    c.process_event(event(&p, DirtyKind::Added)).unwrap();
    assert!(db.get_too_large(&p).unwrap().is_some());

    std::fs::remove_file(&p).unwrap();
    c.process_event(event(&p, DirtyKind::Deleted)).unwrap();
    assert!(db.get_too_large(&p).unwrap().is_none());
}

#[test]
fn recheck_deletion_of_grown_file_clears_mark_and_starts_the_window() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = limited(&db, &dir);
    let p = write(&dir, "g.bin", &content(10, 4096));
    c.process_event(event(&p, DirtyKind::Added)).unwrap();
    assert_eq!(flush(&mut c), 1);
    write(&dir, "g.bin", &big(11));
    c.process_event(event(&p, DirtyKind::Modified)).unwrap();
    assert!(
        db.get_too_large(&p).unwrap().is_some(),
        "setup: grown, marked"
    );

    std::fs::remove_file(&p).unwrap();
    c.process_event(event(&p, DirtyKind::GoneOnRecheck))
        .unwrap();

    assert!(db.get_too_large(&p).unwrap().is_none(), "mark cleared");
    let deleted = record(&db, &p)
        .devices
        .iter()
        .any(|(d, s)| *d == DEV && matches!(s, viaticum_core::types::LocalState::Deleted(_)));
    assert!(deleted, "the deletion window runs");
}

#[test]
fn deleted_directory_clears_marks_under_it() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = limited(&db, &dir);
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    std::fs::create_dir(dir.path().join("keep")).unwrap();
    let a = write(&dir, "sub/a.bin", &big(10));
    let b = write(&dir, "sub/b.bin", &big(11));
    let other = write(&dir, "keep/c.bin", &big(12));
    for p in [&a, &b, &other] {
        c.process_event(event(p, DirtyKind::Added)).unwrap();
    }
    assert_eq!(db.list_too_large().unwrap().len(), 3);

    std::fs::remove_dir_all(dir.path().join("sub")).unwrap();
    let sub = dir.path().join("sub").to_string_lossy().into_owned();
    c.process_event(event(&sub, DirtyKind::Deleted)).unwrap();

    let left: Vec<String> = db
        .list_too_large()
        .unwrap()
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    assert_eq!(
        left,
        vec![other],
        "only the mark outside the directory stays"
    );
}

#[test]
fn root_lost_leaves_marks_alone() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = limited(&db, &dir);
    let p = write(&dir, "r.bin", &big(13));
    c.process_event(event(&p, DirtyKind::Added)).unwrap();

    let root = dir.path().to_string_lossy().into_owned();
    c.process_event(event(&root, DirtyKind::RootLost)).unwrap();
    c.process_event(event(&root, DirtyKind::RootChanged))
        .unwrap();
    assert!(db.get_too_large(&p).unwrap().is_some());
}

// ─── Marks: the start pass ──────────────────────────────────────────────────

#[test]
fn reconcile_on_start_requeues_marked_file_now_under_limit() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = limited(&db, &dir);
    let shrunk = write(&dir, "shrunk.bin", &big(14));
    let raised = write(&dir, "raised.bin", &big(15));
    let still_big = write(&dir, "still_big.bin", &content(16, LIMIT as usize + 2048));
    for p in [&shrunk, &raised, &still_big] {
        c.process_event(event(p, DirtyKind::Added)).unwrap();
    }
    assert_eq!(db.list_too_large().unwrap().len(), 3, "setup");

    // While the daemon is down one file shrinks, and the limit is raised (config change)
    // above the second one but not above the third.
    write(&dir, "shrunk.bin", &content(17, 4096));
    c.config.max_file_size_bytes = LIMIT + 1024;
    let ((), logs) = logged(|| c.reconcile_too_large_marks());

    assert!(
        db.list_too_large()
            .unwrap()
            .iter()
            .map(|(p, _)| p)
            .eq([&still_big])
    );
    let kept = db.get_too_large(&still_big).unwrap().expect("kept");
    assert_eq!(kept.limit_bytes, LIMIT + 1024, "refreshed silently");
    assert_eq!(kept.size_bytes, LIMIT + 2048);
    assert_eq!(
        count(&logs, "file too large to back up"),
        0,
        "no second WARN: {logs}"
    );
    assert_eq!(
        count(
            &logs,
            "requeued=2 dropped_missing=0 kept=1 dropped_outside=0"
        ),
        1,
        "{logs}"
    );
    // The small one waits for its pack; the raised one is a block of its own at once.
    assert!(queued_paths(&c).contains(&shrunk), "back in the queue");
    assert!(last(&db, &raised).backed_up_at.is_some(), "backed up now");
    assert_eq!(flush(&mut c), 1);
    assert!(last(&db, &shrunk).backed_up_at.is_some());
}

#[test]
fn reconcile_on_start_drops_mark_of_missing_file_without_catalog_change() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = limited(&db, &dir);
    // A protected file that grew, and a never-protected big one.
    let g = write(&dir, "g.bin", &content(17, 4096));
    let xg = backed_up(&mut c, &db, &g, DirtyKind::Added);
    write(&dir, "g.bin", &big(18));
    c.process_event(event(&g, DirtyKind::Modified)).unwrap();
    let never = write(&dir, "never.bin", &big(19));
    c.process_event(event(&never, DirtyKind::Added)).unwrap();
    assert_eq!(db.list_too_large().unwrap().len(), 2);
    let before = record(&db, &g);

    // Both vanish while the daemon is down.
    std::fs::remove_file(&g).unwrap();
    std::fs::remove_file(&never).unwrap();
    let ((), logs) = logged(|| c.reconcile_too_large_marks());

    assert!(db.list_too_large().unwrap().is_empty());
    let after = record(&db, &g);
    assert_eq!(after.versions.len(), before.versions.len());
    assert_eq!(after.versions[0].source_block_id, xg);
    assert_eq!(after.devices, before.devices, "not marked deleted (dr-i63)");
    assert!(
        db.get_file(&never).unwrap().is_none(),
        "no catalog record appears"
    );
    assert_eq!(
        count(
            &logs,
            "requeued=0 dropped_missing=2 kept=0 dropped_outside=0"
        ),
        1,
        "{logs}"
    );
}

#[test]
fn reconcile_on_start_drops_mark_outside_watch_dirs() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let elsewhere = TempDir::new().unwrap();
    let mut c = limited(&db, &dir);
    let p = write(&elsewhere, "o.bin", &big(20));
    c.process_event(event(&p, DirtyKind::Added)).unwrap();
    assert!(db.get_too_large(&p).unwrap().is_some());

    let ((), logs) = logged(|| c.reconcile_too_large_marks());
    assert!(db.get_too_large(&p).unwrap().is_none());
    assert_eq!(count(&logs, "dropped_outside=1"), 1, "{logs}");
}

// ─── The flush ──────────────────────────────────────────────────────────────

#[test]
fn flush_queue_skips_file_that_grew_over_limit_and_flushes_the_rest() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = limited(&db, &dir);
    let (a, b, d) = (
        write(&dir, "a.bin", &content(21, 4096)),
        write(&dir, "b.bin", &content(22, 4096)),
        write(&dir, "d.bin", &content(23, 4096)),
    );
    for p in [&a, &b, &d] {
        c.process_event(event(p, DirtyKind::Added)).unwrap();
    }
    assert_eq!(queued_paths(&c).len(), 3, "setup");

    // b grows over the limit before the flush.
    write(&dir, "b.bin", &big(24));
    let results = c.flush_all(true, &Default::default()).unwrap();

    assert_eq!(results.len(), 1, "a and d are packed");
    assert!(db.get_too_large(&b).unwrap().is_some(), "b is marked");
    assert!(
        db.get_file(&b).unwrap().is_none(),
        "b's only pending version is gone"
    );
    assert!(last(&db, &a).backed_up_at.is_some());
    assert!(last(&db, &d).backed_up_at.is_some());
    assert!(queued_paths(&c).is_empty(), "nothing left in the queue");
}

#[test]
fn flush_queue_sends_file_grown_past_pack_size_to_single_block() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = limited(&db, &dir);
    let (a, g, d) = (
        write(&dir, "a.bin", &content(25, 4096)),
        write(&dir, "g.bin", &content(26, 4096)),
        write(&dir, "d.bin", &content(27, 4096)),
    );
    for p in [&a, &g, &d] {
        c.process_event(event(p, DirtyKind::Added)).unwrap();
    }
    // g grows to the pack size and more, still within the limit.
    let grown = content(28, PACK as usize + 100);
    assert!((grown.len() as u64) < LIMIT);
    write(&dir, "g.bin", &grown);

    let results = c.flush_all(true, &Default::default()).unwrap();

    assert_eq!(results.len(), 2, "one pack and one block of its own");
    let vg = last(&db, &g);
    assert_eq!(vg.content_hash, hash(&grown), "hash of the bytes packed");
    assert!(vg.backed_up_at.is_some());
    assert_eq!(block_type(&db, vg.source_block_id), SourceBlockType::Single);
    for p in [&a, &d] {
        let v = last(&db, p);
        assert!(v.backed_up_at.is_some());
        assert!(
            matches!(
                block_type(&db, v.source_block_id),
                SourceBlockType::Pack { .. }
            ),
            "small files stay in the pack"
        );
        assert_ne!(v.source_block_id, vg.source_block_id);
    }
}

// ─── The rebuild ────────────────────────────────────────────────────────────

/// A protected Single block whose source grew over the limit: the candidate is not read
/// (DEBUG), the path is not reported gone, and there is no recheck; another candidate with
/// the block's own bytes, within the limit, serves the rebuild.
#[test]
fn rebuild_skips_candidate_over_limit_without_reading_and_without_recheck() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let original = content(30, BLOCK as usize + 1024);
    let p = write(&dir, "p.bin", &original);
    // A file of the pack size or more is a block of its own at once (no flush).
    c.process_event(event(&p, DirtyKind::Added)).unwrap();
    let x = last(&db, &p).source_block_id;
    let sb = db.get_source_block(&x).unwrap().unwrap();
    let limit = original.len() as u64;
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let scope = RebuildScope::new(DEV, Some(tx)).with_max_source_bytes(limit);

    // Control: within the limit the rebuild succeeds.
    let blob = rebuild_blob_blocking(&db, &sb, &KEY, &scope).unwrap();
    assert_eq!(blake3::hash(&blob).as_bytes(), &x.0);

    // The only candidate grows over the limit: nothing to read, not "gone".
    write(&dir, "p.bin", &content(31, original.len() + 1));
    let (err, logs) = logged(|| rebuild_blob_blocking(&db, &sb, &KEY, &scope).unwrap_err());
    assert!(
        matches!(
            err.downcast_ref::<RebuildError>(),
            Some(RebuildError::SourceMissing { .. })
        ),
        "{err:#}"
    );
    assert_eq!(
        count(&logs, "source over the size limit, not read"),
        1,
        "{logs}"
    );
    assert!(
        logs.contains(&p) && logs.contains(&format!("limit={limit}")),
        "{logs}"
    );
    assert!(
        rx.try_recv().is_err(),
        "no recheck for a file that is there"
    );

    // A copy with the block's bytes, within the limit, is the next candidate.
    let q = write(&dir, "q.bin", &original);
    c.process_event(event(&q, DirtyKind::Added)).unwrap();
    let blob = rebuild_blob_blocking(&db, &sb, &KEY, &scope).unwrap();
    assert_eq!(blake3::hash(&blob).as_bytes(), &x.0);
    assert!(rx.try_recv().is_err(), "still no recheck");
}

// ─── F3: one buffer, the same bytes ─────────────────────────────────────────

/// The stored blob of `compressed` at `generation`, built by hand as before R1-d: the
/// nonce, the ciphertext into a second buffer, the nonce prepended into a third. Calls
/// neither `seal_framed` nor `seal_compressed`.
fn reference_seal(compressed: &[u8], key: &[u8; 32], generation: u32) -> Vec<u8> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
    let cipher = ChaCha20Poly1305::new(&derive_block_key(key).into());
    let nonce = derive_nonce(key, compressed, generation);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), compressed)
        .unwrap();
    let mut stored = Vec::with_capacity(12 + ciphertext.len());
    stored.extend_from_slice(&nonce);
    stored.extend_from_slice(&ciphertext);
    stored
}

/// The implementation before R1-d: compress, then seal at generation 0.
fn reference_compress_and_encrypt(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let compressed = zstd::encode_all(std::io::Cursor::new(plaintext), 3).unwrap();
    reference_seal(&compressed, key, 0)
}

/// Incompressible bytes, deterministic per `seed` (blake3 in XOF mode: fast even unoptimised).
fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut out = vec![0u8; len];
    blake3::Hasher::new()
        .update(&seed.to_le_bytes())
        .finalize_xof()
        .fill(&mut out);
    out
}

#[test]
fn compress_and_encrypt_single_buffer_matches_reference() {
    let inputs: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("one byte", vec![0x5a]),
        (
            "1 MiB random",
            pseudo_random(1 << 20, 0x1234_5678_9abc_def1),
        ),
        ("1 MiB zeros", vec![0u8; 1 << 20]),
        (
            "8 MiB random",
            pseudo_random(8 << 20, 0x0bad_cafe_dead_beef),
        ),
        (
            "16 MiB random",
            pseudo_random(16 << 20, 0x1357_9bdf_2468_ace1),
        ),
    ];
    for (name, plaintext) in inputs {
        let reference = reference_compress_and_encrypt(&plaintext, &KEY);
        let got = compress_and_encrypt(&plaintext, &KEY).unwrap();
        assert_eq!(got, reference, "{name}: byte for byte as before");
        // The two-step form is the same bytes too (generation 0).
        let compressed = compress_block(&plaintext).unwrap();
        assert_eq!(
            seal_compressed(&compressed, &KEY, 0).unwrap(),
            reference,
            "{name}"
        );
    }
}

#[test]
fn compress_framed_and_in_place_seal_match_the_two_step_form_at_every_generation() {
    let plaintext = pseudo_random(300_000, 77);
    let compressed = compress_block(&plaintext).unwrap();
    let framed = compress_framed(&plaintext).unwrap();
    assert_eq!(
        &framed[12..],
        compressed.as_slice(),
        "the same compressed bytes"
    );
    assert!(
        framed.capacity() <= framed.len() + 16,
        "the reserved compress bound is given back: {} > {}",
        framed.capacity(),
        framed.len() + 16
    );

    let mut buf = framed.clone();
    for generation in [0u32, 1, 2, 0] {
        seal_framed(&mut buf, &KEY, generation).unwrap();
        let reference = reference_seal(&compressed, &KEY, generation);
        assert_eq!(
            buf, reference,
            "generation {generation}: the hand-built blob"
        );
        assert_eq!(
            seal_compressed(&compressed, &KEY, generation).unwrap(),
            reference,
            "generation {generation}: the two-step form"
        );
        unseal_framed(&mut buf, &KEY).unwrap();
        assert_eq!(&buf[12..], compressed.as_slice(), "unsealed back");
    }
}

/// The window of a zstd frame, from its header (RFC 8878 §3.1.1.1): the window descriptor, or the
/// content size of a single-segment frame.
fn frame_window_bytes(frame: &[u8]) -> u64 {
    assert_eq!(frame[..4], [0x28, 0xB5, 0x2F, 0xFD], "a zstd frame");
    let descriptor = frame[4];
    let single_segment = descriptor & 0x20 != 0;
    if single_segment {
        return match descriptor >> 6 {
            0 => frame[5] as u64,
            1 => u16::from_le_bytes([frame[5], frame[6]]) as u64 + 256,
            2 => u32::from_le_bytes(frame[5..9].try_into().unwrap()) as u64,
            _ => u64::from_le_bytes(frame[5..13].try_into().unwrap()),
        };
    }
    let window = frame[5];
    let log = 10 + (window >> 3) as u32;
    let base = 1u64 << log;
    base + base / 8 * (window & 7) as u64
}

/// W4 (spec v3.9b): the frames the backup writes have `windowLog` at most 21 (a window of 2 MiB),
/// whatever the size of the block — the restore's estimate holds `ZSTD_WINDOW_BYTES` (the window
/// and a block of 128 KiB) for the decompression of them. Both ways to compress: `compress_block`
/// and `compress_framed` (the nonce in front is skipped).
#[test]
fn backup_frames_have_window_log_at_most_21() {
    let inputs: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("one byte", vec![0x5a]),
        ("100 KiB random", pseudo_random(100 << 10, 11)),
        ("1 MiB zeros", vec![0u8; 1 << 20]),
        ("5 MiB random", pseudo_random(5 << 20, 12)),
        (
            "24 MiB mixed",
            [pseudo_random(1 << 20, 13), vec![7u8; 23 << 20]].concat(),
        ),
    ];
    for (name, plaintext) in inputs {
        let block = compress_block(&plaintext).unwrap();
        let framed = compress_framed(&plaintext).unwrap();
        for (how, frame) in [
            ("compress_block", &block[..]),
            ("compress_framed", &framed[12..]),
        ] {
            let window = frame_window_bytes(frame);
            assert!(
                window <= 1 << 21,
                "{name}, {how}: window {window} B is above 2 MiB (windowLog 21)"
            );
            assert!(
                window + 128 * 1024 <= crate::daemon::mem_budget::ZSTD_WINDOW_BYTES,
                "{name}, {how}: the estimate holds {} B",
                crate::daemon::mem_budget::ZSTD_WINDOW_BYTES
            );
        }
    }
}
