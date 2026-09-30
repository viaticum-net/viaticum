// L0 К3 (delete-i12, backup-i22, dr-i64): moves resolved by the disk, the watch root
// rule and its self-heal, root identity in watch_roots.json, overflow rescan, rechecks,
// one path spelling per file. Synthetic notify events (built as notify builds them)
// go through the callback's filter (`raw_items`) into a real `WatchLoop` over temp dirs.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use notify::event::{CreateKind, DataChange, Flag, ModifyKind, RemoveKind, RenameMode};
use notify::{Event, EventKind, RecommendedWatcher, Watcher};
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use viaticum_core::types::DeviceId;

use super::event_loop::{LoopParams, ROOT_LOST_ERROR, Raw, WatchLoop};
use super::roots::{RootId, WATCH_ROOTS_FILE};
use super::{IgnoreSet, WatcherCommand, WatcherConfig, raw_items, start_watcher};
use crate::daemon::backup::{DirtyEvent, DirtyKind};
use crate::daemon::watch_admin::{WatchEntryState, WatcherStatusSignal};

const DEV: DeviceId = DeviceId([1u8; 32]);
const DEBOUNCE: Duration = Duration::from_millis(20);

type States = Arc<RwLock<HashMap<PathBuf, WatchEntryState>>>;

struct H {
    lp: WatchLoop,
    rx: mpsc::Receiver<DirtyEvent>,
    states: States,
    t: Instant,
}

impl H {
    /// A loop over `roots`, identities recorded under `data_dir`, started.
    async fn start(roots: &[PathBuf], data_dir: &Path) -> H {
        let (tx, rx) = mpsc::channel(1024);
        let states: States = Arc::new(RwLock::new(HashMap::new()));
        let ignore = Arc::new(ArcSwap::new(Arc::new(IgnoreSet::build(roots).unwrap())));
        let notify =
            RecommendedWatcher::new(|_: notify::Result<Event>| {}, notify::Config::default())
                .unwrap();
        let mut lp = WatchLoop::new(
            LoopParams {
                device_id: DEV,
                debounce: DEBOUNCE,
                data_dir: data_dir.to_path_buf(),
                watch_states: Some(Arc::clone(&states)),
                recheck_every: Duration::from_secs(1),
            },
            tx,
            notify,
            ignore,
            roots.to_vec(),
        );
        lp.register_all();
        lp.check_roots_at_start().await.unwrap();
        H {
            lp,
            rx,
            states,
            t: Instant::now(),
        }
    }

    /// Feed one notify event through the callback's filter.
    fn feed(&mut self, event: Event) {
        let ig = self.lp.ignore.load_full();
        for raw in raw_items(&event, &ig) {
            self.lp.ingest(raw, self.t);
        }
    }

    /// Let every debounce run out and resolve; returns what was sent.
    async fn flush(&mut self) -> Vec<(String, DirtyKind)> {
        self.t += DEBOUNCE * 2;
        self.lp.flush_due(self.t).await.unwrap();
        self.drain()
    }

    fn drain(&mut self) -> Vec<(String, DirtyKind)> {
        std::iter::from_fn(|| self.rx.try_recv().ok())
            .map(|e| (e.path, e.kind))
            .collect()
    }

    fn status(&self, root: &Path) -> (WatcherStatusSignal, Option<String>) {
        let map = self.states.read().unwrap();
        let s = map.get(root).expect("status of the root");
        (s.status.clone(), s.error.clone())
    }
}

fn ev(kind: EventKind, paths: &[&Path]) -> Event {
    paths
        .iter()
        .fold(Event::new(kind), |e, p| e.add_path(p.to_path_buf()))
}

fn name(mode: RenameMode) -> EventKind {
    EventKind::Modify(ModifyKind::Name(mode))
}

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// A temp dir holding a watch root `root/` and a data dir; returns (tmp, root, data).
fn setup() -> (TempDir, PathBuf, PathBuf) {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("root");
    let data = tmp.path().join("data");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&data).unwrap();
    (tmp, root, data)
}

// ─── Moves resolved by the disk ────────────────────────────────────────────────

#[tokio::test]
async fn name_from_of_gone_path_resolves_deleted() {
    let (tmp, root, data) = setup();
    let f = root.join("t.bin");
    std::fs::write(&f, b"x").unwrap();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    std::fs::rename(&f, tmp.path().join("t.bin")).unwrap();

    h.feed(ev(name(RenameMode::From), &[&f]));

    assert_eq!(h.flush().await, vec![(s(&f), DirtyKind::Deleted)]);
}

#[tokio::test]
async fn name_to_of_existing_file_resolves_added() {
    let (_tmp, root, data) = setup();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    let f = root.join("in.bin");
    std::fs::write(&f, b"x").unwrap();

    h.feed(ev(name(RenameMode::To), &[&f]));

    assert_eq!(h.flush().await, vec![(s(&f), DirtyKind::Added)]);
}

#[tokio::test]
async fn name_both_resolves_deleted_for_from_and_added_for_to() {
    let (_tmp, root, data) = setup();
    let a = root.join("a.bin");
    let b = root.join("b.bin");
    std::fs::write(&a, b"x").unwrap();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    std::fs::rename(&a, &b).unwrap();

    h.feed(ev(name(RenameMode::Both), &[&a, &b]));

    let mut got = h.flush().await;
    got.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        got,
        vec![(s(&a), DirtyKind::Deleted), (s(&b), DirtyKind::Added)]
    );
}

/// FSEvents gives `Name(Any)` without a pair: the disk decides for each path.
#[tokio::test]
async fn name_any_resolves_by_existence() {
    let (_tmp, root, data) = setup();
    let gone = root.join("gone.bin");
    let here = root.join("here.bin");
    std::fs::write(&gone, b"x").unwrap();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    std::fs::remove_file(&gone).unwrap();
    std::fs::write(&here, b"y").unwrap();

    h.feed(ev(name(RenameMode::Any), &[&gone]));
    h.feed(ev(name(RenameMode::Any), &[&here]));

    let mut got = h.flush().await;
    got.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        got,
        vec![(s(&gone), DirtyKind::Deleted), (s(&here), DirtyKind::Added)]
    );
}

/// An editor's atomic save: tmp written, renamed over the target. Only the target is
/// reported; the tmp, created and gone within the debounce, leaves nothing.
#[tokio::test]
async fn atomic_save_tmp_then_rename_over_emits_added_for_target_only() {
    let (_tmp, root, data) = setup();
    let target = root.join("S.bin");
    let tmp = root.join("S.bin.tmp-1");
    std::fs::write(&target, b"old").unwrap();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    std::fs::write(&tmp, b"new").unwrap();
    std::fs::rename(&tmp, &target).unwrap();

    h.feed(ev(EventKind::Create(CreateKind::File), &[&tmp]));
    h.feed(ev(
        EventKind::Modify(ModifyKind::Data(DataChange::Any)),
        &[&tmp],
    ));
    h.feed(ev(name(RenameMode::From), &[&tmp]));
    h.feed(ev(name(RenameMode::To), &[&target]));
    h.feed(ev(name(RenameMode::Both), &[&tmp, &target]));

    assert_eq!(h.flush().await, vec![(s(&target), DirtyKind::Added)]);
}

/// A directory moved in gives no event per file (A2): its subtree is scanned.
#[tokio::test]
async fn name_to_of_directory_scans_subtree() {
    let (tmp, root, data) = setup();
    let src = tmp.path().join("album");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("p1.jpg"), b"1").unwrap();
    std::fs::create_dir(src.join("sub")).unwrap();
    std::fs::write(src.join("sub/p2.jpg"), b"2").unwrap();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    let album = root.join("album");
    std::fs::rename(&src, &album).unwrap();

    h.feed(ev(name(RenameMode::To), &[&album]));

    let mut got = h.flush().await;
    got.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        got,
        vec![
            (s(&album.join("p1.jpg")), DirtyKind::Added),
            (s(&album.join("sub/p2.jpg")), DirtyKind::Added),
        ]
    );
}

#[tokio::test]
async fn name_to_of_hidden_or_ignored_directory_dropped() {
    let (_tmp, root, data) = setup();
    std::fs::write(root.join(".viaticumignore"), "flood/\n").unwrap();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    let hidden = root.join(".Trash-1000");
    let ignored = root.join("flood");
    for d in [&hidden, &ignored] {
        std::fs::create_dir(d).unwrap();
        std::fs::write(d.join("f.bin"), b"x").unwrap();
    }

    h.feed(ev(name(RenameMode::To), &[&hidden]));
    h.feed(ev(name(RenameMode::To), &[&ignored]));
    h.feed(ev(name(RenameMode::To), &[&hidden.join("f.bin")]));

    assert_eq!(h.flush().await, vec![]);
}

// ─── The root rule ─────────────────────────────────────────────────────────────

/// `rm -rf` of the watch root: no deletion, the root rule once; the folder in error.
#[tokio::test]
async fn remove_events_after_root_removed_emit_root_lost_not_deleted() {
    let (_tmp, root, data) = setup();
    let f = root.join("a.bin");
    std::fs::write(&f, b"x").unwrap();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    std::fs::remove_dir_all(&root).unwrap();

    h.feed(ev(EventKind::Remove(RemoveKind::File), &[&f]));
    h.feed(ev(EventKind::Remove(RemoveKind::Folder), &[&root]));

    assert_eq!(h.flush().await, vec![(s(&root), DirtyKind::RootLost)]);
    assert_eq!(
        h.status(&root),
        (
            WatcherStatusSignal::Error,
            Some(ROOT_LOST_ERROR.to_string())
        )
    );
    // Later events under it are dropped while it is in error.
    h.feed(ev(EventKind::Remove(RemoveKind::File), &[&f]));
    assert_eq!(h.flush().await, vec![]);
}

/// A file manager moving the root away file by file (copy + delete, the root last):
/// the first files are deleted while the root is there, then the root rule fires.
#[tokio::test]
async fn slow_file_by_file_move_emits_deleted_then_root_lost() {
    let (_tmp, root, data) = setup();
    let a = root.join("keep1.bin");
    let b = root.join("keep2.bin");
    std::fs::write(&a, b"1").unwrap();
    std::fs::write(&b, b"2").unwrap();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;

    std::fs::remove_file(&a).unwrap();
    h.feed(ev(EventKind::Remove(RemoveKind::File), &[&a]));
    let first = h.flush().await;
    std::fs::remove_file(&b).unwrap();
    std::fs::remove_dir(&root).unwrap();
    h.feed(ev(EventKind::Remove(RemoveKind::File), &[&b]));
    h.feed(ev(EventKind::Remove(RemoveKind::Folder), &[&root]));
    let then = h.flush().await;

    assert_eq!(first, vec![(s(&a), DirtyKind::Deleted)]);
    assert_eq!(then, vec![(s(&root), DirtyKind::RootLost)]);
}

/// The root renamed away and a new directory created under its name: an event for a
/// path under it (inotify still reports the old spelling) finds another directory — the
/// root rule, sent as `RootChanged` (handled as `RootLost` by the backup).
#[tokio::test]
async fn moved_events_after_root_replaced_by_new_dir_emit_root_lost() {
    let (tmp, root, data) = setup();
    let f = root.join("a.bin");
    std::fs::write(&f, b"x").unwrap();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    std::fs::rename(&root, tmp.path().join("root.old")).unwrap();
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("other.bin"), b"y").unwrap();

    h.feed(ev(name(RenameMode::From), &[&f]));

    assert_eq!(h.flush().await, vec![(s(&root), DirtyKind::RootChanged)]);
    assert!(h.lp.lost.contains(&root));
}

/// The identity is read from metadata: no descriptor on the root stays open, so the
/// root's file system can be unmounted (К8).
#[cfg(target_os = "linux")]
#[tokio::test]
async fn root_identity_holds_no_open_descriptor() {
    let (_tmp, root, data) = setup();
    std::fs::write(root.join("a.bin"), b"x").unwrap();
    let _h = H::start(std::slice::from_ref(&root), &data).await;

    let canon = std::fs::canonicalize(&root).unwrap();
    let open: Vec<PathBuf> = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .flatten()
        .filter_map(|e| std::fs::read_link(e.path()).ok())
        .filter(|target| target == &canon || target == &root)
        .collect();
    assert!(open.is_empty(), "descriptors open on the root: {open:?}");
    assert!(data.join(WATCH_ROOTS_FILE).is_file(), "identity persisted");
}

/// A root replaced while the daemon was down is caught at start from watch_roots.json.
#[tokio::test]
async fn root_changed_while_down_detected_at_start_from_watch_roots_json() {
    let (tmp, root, data) = setup();
    std::fs::write(root.join("a.bin"), b"x").unwrap();
    let first = H::start(std::slice::from_ref(&root), &data).await;
    drop(first);
    std::fs::rename(&root, tmp.path().join("root.old")).unwrap();
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("b.bin"), b"y").unwrap();

    let mut second = H::start(std::slice::from_ref(&root), &data).await;
    // The rule runs first (the backup undoes and unconfirms), then the start accepts the
    // non-empty directory (Р-13, dr-i64): new identity, error cleared, scanned.
    assert_eq!(
        second.drain(),
        vec![
            (s(&root), DirtyKind::RootChanged),
            (s(&root.join("b.bin")), DirtyKind::Added),
        ]
    );
    assert!(second.lp.lost.is_empty());
    assert_eq!(second.status(&root).0, WatcherStatusSignal::Idle);

    // Recorded: the next start does not fire again.
    drop(second);
    let mut third = H::start(std::slice::from_ref(&root), &data).await;
    assert_eq!(third.drain(), vec![]);
}

/// The same at the periodic scan: a root replaced by another non-empty directory without
/// an event reaching the loop gets the rule and is accepted in that scan; the next scan
/// only scans.
#[tokio::test]
async fn root_changed_at_periodic_scan_is_accepted_when_not_empty() {
    let (tmp, root, data) = setup();
    std::fs::write(root.join("a.bin"), b"x").unwrap();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    std::fs::rename(&root, tmp.path().join("root.old")).unwrap();
    std::fs::create_dir(&root).unwrap();
    let b = root.join("b.bin");
    std::fs::write(&b, b"y").unwrap();

    h.lp.periodic_scan().await.unwrap();

    assert_eq!(
        h.drain(),
        vec![
            (s(&root), DirtyKind::RootChanged),
            (s(&b), DirtyKind::Added)
        ]
    );
    assert!(h.lp.lost.is_empty());
    assert_eq!(h.status(&root).0, WatcherStatusSignal::Idle);
    h.lp.periodic_scan().await.unwrap();
    assert_eq!(h.drain(), vec![(s(&b), DirtyKind::Added)], "no second rule");
}

/// Self-heal on Scan: the root is back and not empty → identity renewed, error
/// cleared, the scan reports what is there.
#[tokio::test]
async fn root_error_heals_on_scan_when_root_back_and_not_empty() {
    let (tmp, root, data) = setup();
    let f = root.join("a.bin");
    std::fs::write(&f, b"x").unwrap();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    std::fs::rename(&root, tmp.path().join("elsewhere")).unwrap();
    h.feed(ev(name(RenameMode::From), &[&root]));
    assert_eq!(h.flush().await, vec![(s(&root), DirtyKind::RootLost)]);

    std::fs::rename(tmp.path().join("elsewhere"), &root).unwrap();
    h.lp.on_command(WatcherCommand::Scan { path: root.clone() })
        .await
        .unwrap();

    assert_eq!(h.drain(), vec![(s(&f), DirtyKind::Added)]);
    assert!(h.lp.lost.is_empty());
    assert_eq!(h.status(&root).0, WatcherStatusSignal::Idle);
    // Healed: a deletion under it is a deletion again.
    std::fs::remove_file(&f).unwrap();
    h.feed(ev(EventKind::Remove(RemoveKind::File), &[&f]));
    assert_eq!(h.flush().await, vec![(s(&f), DirtyKind::Deleted)]);
}

/// An empty root (an empty mount point) does not heal: the error stays.
#[tokio::test]
async fn root_error_stays_on_scan_when_root_empty() {
    let (_tmp, root, data) = setup();
    std::fs::write(root.join("a.bin"), b"x").unwrap();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    std::fs::remove_dir_all(&root).unwrap();
    h.feed(ev(EventKind::Remove(RemoveKind::Folder), &[&root]));
    assert_eq!(h.flush().await, vec![(s(&root), DirtyKind::RootLost)]);

    std::fs::create_dir(&root).unwrap();
    h.lp.on_command(WatcherCommand::Scan { path: root.clone() })
        .await
        .unwrap();

    assert_eq!(h.drain(), vec![]);
    assert!(h.lp.lost.contains(&root));
    assert_eq!(h.status(&root).0, WatcherStatusSignal::Error);
}

// ─── Overflow and recheck ──────────────────────────────────────────────────────

/// An inotify overflow (`Rescan` flag) schedules a full scan after a quiet window.
#[tokio::test]
async fn rescan_flag_triggers_full_scan_after_quiet_window() {
    let (_tmp, root, data) = setup();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    let f = root.join("after.bin");
    std::fs::write(&f, b"x").unwrap();
    let overflow = Event::new(EventKind::Other).set_flag(Flag::Rescan);
    assert_eq!(
        raw_items(&overflow, &h.lp.ignore.load_full()),
        vec![Raw::Rescan]
    );

    h.lp.ingest(Raw::Rescan, h.t);
    h.lp.flush_due(h.t).await.unwrap();
    assert_eq!(h.drain(), vec![], "not before the quiet window");

    assert_eq!(h.flush().await, vec![(s(&f), DirtyKind::Added)]);
}

#[tokio::test]
async fn recheck_emits_deleted_for_gone_path_under_intact_root() {
    let (_tmp, root, data) = setup();
    std::fs::write(root.join("other.bin"), b"x").unwrap();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    let gone = root.join("m3.bin");

    h.lp.on_recheck(gone.clone(), h.t).await.unwrap();

    assert_eq!(h.drain(), vec![(s(&gone), DirtyKind::GoneOnRecheck)]);
    // The same path again within the interval: ignored.
    h.lp.on_recheck(gone.clone(), h.t).await.unwrap();
    assert_eq!(h.drain(), vec![]);
}

/// An empty or missing parent (an unmounted or emptied folder) is no evidence of a
/// deletion.
#[tokio::test]
async fn recheck_ignores_path_whose_parent_is_empty() {
    let (_tmp, root, data) = setup();
    std::fs::create_dir(root.join("sub")).unwrap();
    std::fs::write(root.join("other.bin"), b"x").unwrap();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;

    h.lp.on_recheck(root.join("sub/a.bin"), h.t).await.unwrap();
    h.lp.on_recheck(root.join("nodir/a.bin"), h.t)
        .await
        .unwrap();

    assert_eq!(h.drain(), vec![]);
}

#[tokio::test]
async fn recheck_ignores_path_under_errored_root() {
    let (tmp, root, data) = setup();
    std::fs::write(root.join("a.bin"), b"x").unwrap();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    std::fs::rename(&root, tmp.path().join("elsewhere")).unwrap();
    h.feed(ev(name(RenameMode::From), &[&root]));
    assert_eq!(h.flush().await, vec![(s(&root), DirtyKind::RootLost)]);
    // Back on disk, not healed yet (no Scan).
    std::fs::rename(tmp.path().join("elsewhere"), &root).unwrap();
    std::fs::write(root.join("b.bin"), b"y").unwrap();

    h.lp.on_recheck(root.join("gone.bin"), h.t).await.unwrap();

    assert_eq!(h.drain(), vec![]);
}

/// Rechecks travel on their own bounded channel: a full one refuses at once (the
/// rebuild's `try_send` drops the path) and WatchAdmin commands still go through.
#[tokio::test]
async fn recheck_channel_full_does_not_block_watch_admin_commands() {
    let (_tmp, root, data) = setup();
    let f = root.join("a.bin");
    std::fs::write(&f, b"x").unwrap();
    // A recent scan marker: no initial scan, the Added below comes from the command.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    std::fs::write(data.join("last_scan"), now.to_string()).unwrap();
    let (recheck_tx, recheck_rx) = mpsc::channel::<PathBuf>(2);
    let (ctrl_tx, ctrl_rx) = mpsc::channel::<WatcherCommand>(8);
    let (dirty_tx, mut dirty_rx) = mpsc::channel(64);
    let cancel = CancellationToken::new();
    let config = WatcherConfig {
        watch_dirs: vec![root.clone()],
        device_id: DEV,
        debounce_ms: 20,
        data_dir: data.clone(),
        rescan_interval_secs: 604800,
        watch_states: None,
        time_scale: 1,
        recheck_rx: Some(recheck_rx),
    };
    // Full before the watcher runs: the next send is refused, not awaited.
    recheck_tx.try_send(root.join("x1")).unwrap();
    recheck_tx.try_send(root.join("x2")).unwrap();
    assert!(recheck_tx.try_send(root.join("x3")).is_err());

    tokio::spawn(start_watcher(config, dirty_tx, ctrl_rx, cancel.clone()));
    ctrl_tx
        .send(WatcherCommand::Scan { path: root.clone() })
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let e = dirty_rx.recv().await.expect("watcher alive");
            if e.kind == DirtyKind::Added {
                return e.path;
            }
        }
    })
    .await
    .expect("the Scan command went through");
    assert_eq!(got, s(&f));
    cancel.cancel();
}

// ─── One spelling per path (v3.1, macOS canonical paths) ───────────────────────

/// A root configured through a symlink (`/var` on macOS): a live event reported under
/// the canonical path (as FSEvents does) and the scan give the same catalog path.
#[tokio::test]
async fn live_event_under_canonical_alias_and_scan_give_one_path() {
    let (tmp, real, data) = setup();
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    std::fs::write(real.join("p.jpg"), b"x").unwrap();
    let mut h = H::start(std::slice::from_ref(&link), &data).await;

    h.lp.on_command(WatcherCommand::Scan { path: link.clone() })
        .await
        .unwrap();
    let scanned = h.drain();
    let canonical = std::fs::canonicalize(&real).unwrap().join("p.jpg");
    h.feed(ev(EventKind::Create(CreateKind::File), &[&canonical]));
    let live = h.flush().await;

    let want = vec![(s(&link.join("p.jpg")), DirtyKind::Added)];
    assert_eq!(scanned, want);
    assert_eq!(live, want);
}

// ─── Root checked at start and on scans (L0 review BLOCK-2, W1) ────────────────

/// The root went while the daemon was down — or within the debounce before a shutdown,
/// its DELETE_SELF lost with the process: at start it is simply missing. That is the
/// root rule, not just a watch error: RootLost, the folder error, heal on Scan.
#[tokio::test]
async fn root_missing_at_start_fires_root_rule() {
    let (tmp, root, data) = setup();
    std::fs::write(root.join("keep1.bin"), b"x").unwrap();
    drop(H::start(std::slice::from_ref(&root), &data).await);
    std::fs::rename(&root, tmp.path().join("elsewhere")).unwrap();

    let mut h = H::start(std::slice::from_ref(&root), &data).await;

    assert_eq!(h.drain(), vec![(s(&root), DirtyKind::RootLost)]);
    assert_eq!(
        h.status(&root),
        (
            WatcherStatusSignal::Error,
            Some(ROOT_LOST_ERROR.to_string())
        )
    );
    std::fs::rename(tmp.path().join("elsewhere"), &root).unwrap();
    h.lp.on_command(WatcherCommand::Scan { path: root.clone() })
        .await
        .unwrap();
    assert_eq!(
        h.drain(),
        vec![(s(&root.join("keep1.bin")), DirtyKind::Added)]
    );
    assert!(h.lp.lost.is_empty());
}

/// The root went with no event reaching the loop: the periodic scan finds it missing,
/// fires the root rule, scans nothing; a later periodic scan heals it once it is back.
#[tokio::test]
async fn root_missing_at_periodic_scan_fires_root_rule() {
    let (tmp, root, data) = setup();
    let f = root.join("keep1.bin");
    std::fs::write(&f, b"x").unwrap();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    std::fs::rename(&root, tmp.path().join("elsewhere")).unwrap();

    h.lp.periodic_scan().await.unwrap();

    assert_eq!(h.drain(), vec![(s(&root), DirtyKind::RootLost)]);
    assert_eq!(h.status(&root).0, WatcherStatusSignal::Error);
    std::fs::rename(tmp.path().join("elsewhere"), &root).unwrap();
    h.lp.periodic_scan().await.unwrap();
    assert_eq!(h.drain(), vec![(s(&f), DirtyKind::Added)]);
    assert!(h.lp.lost.is_empty());
}

/// An empty directory is never taken as a root identity (W1 b): replaced by an empty
/// directory (an unmounted mount point), the root is in error and a Scan does not
/// accept it; once files are there, a Scan does.
#[tokio::test]
async fn root_replaced_by_empty_dir_is_not_accepted_until_not_empty() {
    let (tmp, root, data) = setup();
    std::fs::write(root.join("a.bin"), b"x").unwrap();
    drop(H::start(std::slice::from_ref(&root), &data).await);
    std::fs::rename(&root, tmp.path().join("mounted-elsewhere")).unwrap();
    std::fs::create_dir(&root).unwrap();

    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    assert_eq!(h.drain(), vec![(s(&root), DirtyKind::RootChanged)]);
    h.lp.on_command(WatcherCommand::Scan { path: root.clone() })
        .await
        .unwrap();
    assert!(
        h.lp.lost.contains(&root),
        "an empty directory is not accepted"
    );

    std::fs::write(root.join("b.bin"), b"y").unwrap();
    h.lp.on_command(WatcherCommand::Scan { path: root.clone() })
        .await
        .unwrap();
    assert!(h.lp.lost.is_empty());
    assert_eq!(h.drain(), vec![(s(&root.join("b.bin")), DirtyKind::Added)]);
}

/// A new root that is empty is not recorded: a deletion under it before any file was
/// seen there is the root rule, never a deletion.
#[tokio::test]
async fn empty_new_root_is_not_recorded_and_deletes_nothing() {
    let (_tmp, root, data) = setup();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;
    assert!(
        !data.join(WATCH_ROOTS_FILE).exists(),
        "nothing recorded for an empty root"
    );

    h.feed(ev(
        EventKind::Remove(RemoveKind::File),
        &[&root.join("x.bin")],
    ));

    assert_eq!(h.flush().await, vec![(s(&root), DirtyKind::RootLost)]);
}

/// W1 a: with both creation times known the device number is ignored (it changes on
/// USB re-enumeration, dm/LUKS reorder, btrfs subvolumes, NFS remount); without them
/// (device, inode) decide.
#[test]
fn same_dir_ignores_device_when_creation_times_are_known() {
    let born = Some((1_700_000_000, 5));
    assert!(RootId::for_test(1, 42, born).same_dir(&RootId::for_test(2, 42, born)));
    assert!(!RootId::for_test(1, 42, born).same_dir(&RootId::for_test(1, 43, born)));
    assert!(!RootId::for_test(1, 42, born).same_dir(&RootId::for_test(
        1,
        42,
        Some((1_700_000_000, 6))
    )));
}

#[test]
fn same_dir_uses_device_and_inode_without_creation_time() {
    assert!(RootId::for_test(1, 42, None).same_dir(&RootId::for_test(1, 42, None)));
    assert!(!RootId::for_test(1, 42, None).same_dir(&RootId::for_test(2, 42, None)));
    assert!(!RootId::for_test(1, 42, Some((1, 0))).same_dir(&RootId::for_test(2, 42, None)));
}

/// A removal event whose path is back on disk at the end of the debounce is resolved by
/// the disk: `Added`, never a deletion.
#[tokio::test]
async fn remove_event_of_path_back_on_disk_resolves_added() {
    let (_tmp, root, data) = setup();
    let f = root.join("f.bin");
    std::fs::write(&f, b"x").unwrap();
    let mut h = H::start(std::slice::from_ref(&root), &data).await;

    h.feed(ev(EventKind::Remove(RemoveKind::File), &[&f]));

    assert_eq!(h.flush().await, vec![(s(&f), DirtyKind::Added)]);
}
