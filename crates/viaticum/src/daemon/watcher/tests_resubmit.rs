// L1b К3 (backup-i8, backup-i25, dr-i64; W2 of the intent review): the watcher re-submits
// the reconcile's paths only under an active, accepted root with the recorded identity and
// through the scan filters. A real `WatchLoop` over temp dirs.

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use arc_swap::ArcSwap;
use notify::{Event, RecommendedWatcher, Watcher};
use tempfile::TempDir;
use tokio::sync::mpsc;
use viaticum_core::types::DeviceId;

use super::event_loop::{LoopParams, ResubmitCounts, WatchLoop};
use super::{IgnoreSet, WatcherCommand};
use crate::daemon::backup::reconcile::{ResubmitBatch, ResubmitReason};
use crate::daemon::backup::{DirtyEvent, DirtyKind};

const DEV: DeviceId = DeviceId([1u8; 32]);

struct H {
    lp: WatchLoop,
    rx: mpsc::Receiver<DirtyEvent>,
}

impl H {
    async fn start(roots: &[PathBuf], data_dir: &Path) -> H {
        let (tx, rx) = mpsc::channel(1024);
        let ignore = Arc::new(ArcSwap::new(Arc::new(IgnoreSet::build(roots).unwrap())));
        let notify =
            RecommendedWatcher::new(|_: notify::Result<Event>| {}, notify::Config::default())
                .unwrap();
        let mut lp = WatchLoop::new(
            LoopParams {
                device_id: DEV,
                debounce: Duration::from_millis(20),
                data_dir: data_dir.to_path_buf(),
                watch_states: Some(Arc::new(RwLock::new(HashMap::new()))),
                recheck_every: Duration::from_secs(1),
            },
            tx,
            notify,
            ignore,
            roots.to_vec(),
        );
        lp.register_all();
        lp.check_roots_at_start().await.unwrap();
        H { lp, rx }
    }

    /// Re-submit `items` (all `Pending` unless named); returns the counts and what was sent.
    async fn resubmit(
        &mut self,
        items: &[(&Path, ResubmitReason)],
    ) -> (BTreeMap<String, ResubmitCounts>, Vec<(String, DirtyKind)>) {
        let batch = ResubmitBatch {
            items: items.iter().map(|(p, r)| (p.to_path_buf(), *r)).collect(),
        };
        let counts = self.lp.on_resubmit(batch).await.unwrap();
        let sent = std::iter::from_fn(|| self.rx.try_recv().ok())
            .map(|e| (e.path, e.kind))
            .collect();
        (counts, sent)
    }
}

/// A temp dir with a watch root holding one file, and a data dir.
fn setup() -> (TempDir, PathBuf, PathBuf) {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("root");
    let data = tmp.path().join("data");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&data).unwrap();
    std::fs::write(root.join("keep.bin"), b"keeps the root non-empty").unwrap();
    (tmp, root, data)
}

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn counts_of(map: &BTreeMap<String, ResubmitCounts>, root: &Path) -> ResubmitCounts {
    *map.get(&s(root)).expect("counts for the root")
}

#[tokio::test]
async fn resubmit_emits_modified_for_file_under_active_accepted_root() {
    let (_tmp, root, data) = setup();
    let (a, b) = (root.join("a.bin"), root.join("sub/b.bin"));
    std::fs::write(&a, b"a").unwrap();
    std::fs::create_dir(root.join("sub")).unwrap();
    std::fs::write(&b, b"b").unwrap();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;

    let (counts, sent) = h
        .resubmit(&[
            (&a, ResubmitReason::Pending),
            (&b, ResubmitReason::Releasing),
        ])
        .await;

    assert_eq!(
        sent,
        vec![(s(&a), DirtyKind::Modified), (s(&b), DirtyKind::Modified)]
    );
    let c = counts_of(&counts, &root);
    assert_eq!((c.pending, c.releasing), (1, 1));
}

/// M13: `.viaticumignore`, the default ignores and hidden paths hold for a resubmit too.
#[tokio::test]
async fn resubmit_skips_ignored_path() {
    let (_tmp, root, data) = setup();
    std::fs::write(root.join(".viaticumignore"), "*.tmp\n").unwrap();
    std::fs::create_dir(root.join("node_modules")).unwrap();
    let paths = [
        root.join("draft.tmp"),
        root.join("node_modules/x.bin"),
        root.join(".secret.bin"),
    ];
    for p in &paths {
        std::fs::write(p, b"x").unwrap();
    }
    let mut h = H::start(std::slice::from_ref(&root), &data).await;

    let items: Vec<(&Path, ResubmitReason)> = paths
        .iter()
        .map(|p| (p.as_path(), ResubmitReason::Pending))
        .collect();
    let (counts, sent) = h.resubmit(&items).await;

    assert!(sent.is_empty());
    assert_eq!(counts_of(&counts, &root).filtered, 3);
}

/// M13: a folder removed from the watch list is no root any more.
#[tokio::test]
async fn resubmit_skips_path_outside_every_root() {
    let (_tmp, root, data) = setup();
    let a = root.join("a.bin");
    std::fs::write(&a, b"a").unwrap();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    h.lp.on_command(WatcherCommand::Remove { path: root.clone() })
        .await
        .unwrap();

    let (counts, sent) = h.resubmit(&[(&a, ResubmitReason::Releasing)]).await;

    assert!(sent.is_empty());
    assert_eq!(counts.get("(none)").unwrap().filtered, 1);
}

/// M13, dr-i64: under the root rule (the root was moved away) nothing under it is re-read,
/// even once the same directory is back with its recorded identity — until it heals on a
/// Scan or the periodic scan.
#[tokio::test]
async fn resubmit_skips_path_under_errored_root() {
    let (tmp, root, data) = setup();
    let a = root.join("a.bin");
    std::fs::write(&a, b"a").unwrap();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    let away = tmp.path().join("away");
    std::fs::rename(&root, &away).unwrap();
    h.lp.on_command(WatcherCommand::Scan { path: root.clone() })
        .await
        .unwrap();
    assert!(h.lp.lost.contains(&root), "setup: root rule fired");
    while h.rx.try_recv().is_ok() {}
    std::fs::rename(&away, &root).unwrap();

    let (counts, sent) = h.resubmit(&[(&a, ResubmitReason::Pending)]).await;

    assert!(sent.is_empty());
    assert_eq!(counts_of(&counts, &root).root_unavailable, 1);
}

/// backup-i25 / backup-i8 (2026-09-30): a root whose watch failed (inotify limit, an
/// unreadable subfolder) but is the recorded directory is scanned, so it takes a resubmit.
#[tokio::test]
async fn resubmit_emits_for_watch_failed_root_with_same_identity() {
    let (_tmp, root, data) = setup();
    let a = root.join("a.bin");
    std::fs::write(&a, b"a").unwrap();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    // What `register_all` records when `watch()` fails.
    h.lp.watch_failed.insert(root.clone());

    let (counts, sent) = h.resubmit(&[(&a, ResubmitReason::Pending)]).await;

    assert_eq!(sent, vec![(s(&a), DirtyKind::Modified)]);
    assert_eq!(counts_of(&counts, &root).pending, 1);
}

/// dr-i64: another directory stands at the root (not noticed by an event yet): its files
/// are not taken for the recorded folder's.
#[tokio::test]
async fn resubmit_skips_path_under_root_with_other_identity() {
    let (tmp, root, data) = setup();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    std::fs::rename(&root, tmp.path().join("root-old")).unwrap();
    std::fs::create_dir(&root).unwrap();
    let a = root.join("a.bin");
    std::fs::write(&a, b"a").unwrap();

    let (counts, sent) = h.resubmit(&[(&a, ResubmitReason::Releasing)]).await;

    assert!(sent.is_empty());
    assert_eq!(counts_of(&counts, &root).root_unavailable, 1);
}

#[tokio::test]
async fn resubmit_skips_gone_path() {
    let (_tmp, root, data) = setup();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    let a = root.join("never-there.bin");

    let (counts, sent) = h.resubmit(&[(&a, ResubmitReason::Pending)]).await;

    assert!(sent.is_empty());
    assert_eq!(counts_of(&counts, &root).gone, 1);
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

/// One INFO line per root per batch, with its counts (the E2E reads this line).
#[tokio::test]
async fn resubmit_logs_one_line_per_root_with_counts() {
    let tmp = TempDir::new().unwrap();
    let (r1, r2, data) = (
        tmp.path().join("one"),
        tmp.path().join("two"),
        tmp.path().join("data"),
    );
    for d in [&r1, &r2, &data] {
        std::fs::create_dir(d).unwrap();
    }
    let (a, b, c) = (r1.join("a.bin"), r1.join("b.bin"), r2.join("c.bin"));
    for p in [&a, &b, &c] {
        std::fs::write(p, b"x").unwrap();
    }
    let mut h = H::start(&[r1.clone(), r2.clone()], &data).await;
    let buf = LogBuf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);

    let gone = r2.join("gone.bin");
    h.resubmit(&[
        (&a, ResubmitReason::Pending),
        (&b, ResubmitReason::Releasing),
        (&c, ResubmitReason::Pending),
        (&gone, ResubmitReason::Pending),
    ])
    .await;
    drop(guard);

    let logs = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    let lines: Vec<&str> = logs
        .lines()
        .filter(|l| l.contains("reconcile: resubmitted"))
        .collect();
    assert_eq!(lines.len(), 2, "{logs}");
    let one = format!(
        "root={} pending=1 releasing=1 gone=0 filtered=0 root_unavailable=0",
        r1.display()
    );
    let two = format!(
        "root={} pending=1 releasing=0 gone=1 filtered=0 root_unavailable=0",
        r2.display()
    );
    assert!(lines.iter().any(|l| l.contains(&one)), "{logs}");
    assert!(lines.iter().any(|l| l.contains(&two)), "{logs}");
}
