// Tests for what never enters the backup through the watcher (R1-c1):
// backup-i13 (Viaticum data dirs), backup-i14 (hidden below the root),
// backup-i15 / W4 (symlinks to directories are not followed).
//
// Roots are made with a non-dot prefix and everything inside them is named by
// hand: a `TempDir` is `.tmpXXXX`, i.e. hidden, and a data dir made with it would
// be skipped as hidden, not as a data dir (N9).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use viaticum_core::types::DeviceId;

use super::{
    FolderRefusal, IgnoreSet, WatcherCommand, WatcherConfig, absolute_watch_dir, data_dir_between,
    has_hidden_component_below, is_viaticum_data_dir, refuse_folder, run_full_scan_one,
    should_watch_path, start_watcher,
};
use crate::daemon::backup::DirtyEvent;
use crate::daemon::identity::{
    DB_FILE_NAME, HOLDINGS_DIR_NAME, KEYFILE_NAME, SYSTEM_STATE_DIR_NAME,
};
use crate::daemon::watch_admin::{WatchEntryState, WatcherStatusSignal};

const DEVICE: DeviceId = DeviceId([7u8; 32]);
const DEBOUNCE_MS: u64 = 50;

/// A temp dir whose own name is not hidden.
fn visible_tempdir() -> TempDir {
    tempfile::Builder::new().prefix("vtest").tempdir().unwrap()
}

/// A data dir as the daemon leaves it after its first start: both marker files.
fn fake_data_dir(dir: &Path) {
    std::fs::create_dir_all(dir.join(HOLDINGS_DIR_NAME).join("ab")).unwrap();
    std::fs::write(dir.join(KEYFILE_NAME), b"not parsed: db.redb is next to it").unwrap();
    std::fs::write(dir.join(DB_FILE_NAME), b"db").unwrap();
    std::fs::write(dir.join(HOLDINGS_DIR_NAME).join("ab").join("0.bin"), b"sym").unwrap();
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// Paths the scan of `root` emits (Added), with the matcher built for `root`.
async fn scan_paths(root: &Path) -> Vec<String> {
    let ig = IgnoreSet::build(&[root.to_path_buf()]).unwrap();
    let (tx, mut rx) = mpsc::channel(1024);
    let n = run_full_scan_one(root, DEVICE, &tx, &ig).await;
    drop(tx);
    let mut out = Vec::new();
    while let Some(ev) = rx.recv().await {
        out.push(ev.path);
    }
    assert_eq!(n as usize, out.len());
    out
}

/// Watcher config for `dirs` with a fresh data dir outside them; `scan` = run the
/// initial scan (no `last_scan` marker) or skip it.
fn config(
    dirs: Vec<PathBuf>,
    scan: bool,
    states: Option<Arc<RwLock<HashMap<PathBuf, WatchEntryState>>>>,
) -> (WatcherConfig, TempDir) {
    let data_dir = visible_tempdir();
    if !scan {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        std::fs::write(data_dir.path().join("last_scan"), now.to_string()).unwrap();
    }
    let cfg = WatcherConfig {
        watch_dirs: dirs,
        device_id: DEVICE,
        debounce_ms: DEBOUNCE_MS,
        data_dir: data_dir.path().to_path_buf(),
        rescan_interval_secs: 604800,
        watch_states: states,
    };
    (cfg, data_dir)
}

/// Collect events until one for `control` arrives (5 s deadline), then 400 ms more
/// (8 debounce windows) so anything flushed with or after it is seen too.
async fn events_until(rx: &mut mpsc::Receiver<DirtyEvent>, control: &Path) -> Vec<String> {
    let control = control.to_string_lossy().into_owned();
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !seen.contains(&control) {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, rx.recv()).await {
            Ok(Some(ev)) => seen.push(ev.path),
            _ => panic!("no event for the control file {control}; got {seen:?}"),
        }
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    while let Ok(ev) = rx.try_recv() {
        seen.push(ev.path);
    }
    seen
}

// ─── pure rules ──────────────────────────────────────────────────────────────

#[test]
fn has_hidden_component_below_checks_only_below_the_root() {
    let root = Path::new("/home/u/.local/share/Photos");
    assert!(!has_hidden_component_below(root, &root.join("2026/a.jpg")));
    assert!(has_hidden_component_below(
        root,
        &root.join(".thumbs/a.jpg")
    ));
    assert!(has_hidden_component_below(root, &root.join("2026/.a.jpg")));
    assert!(has_hidden_component_below(root, &root.join("a/.git/b/c")));
}

#[test]
fn should_watch_path_rejects_file_under_hidden_dir_below_root() {
    let root = visible_tempdir();
    let file = root.path().join(".config/app/settings.json");
    write(&file, b"x");
    let visible = root.path().join("docs/a.txt");
    write(&visible, b"x");
    let ig = IgnoreSet::build(&[root.path().to_path_buf()]).unwrap();
    assert!(!should_watch_path(&file, &ig));
    assert!(should_watch_path(&visible, &ig));
}

#[test]
fn should_watch_path_accepts_file_when_root_itself_is_inside_hidden_dir() {
    // `~/.local/share/Photos` can be watched: the hidden component is above the root.
    let base = visible_tempdir();
    let root = base.path().join(".local/share/Photos");
    let file = root.join("2026/a.jpg");
    write(&file, b"x");
    let ig = IgnoreSet::build(std::slice::from_ref(&root)).unwrap();
    assert!(should_watch_path(&file, &ig));
}

#[test]
fn should_watch_path_rejects_path_outside_every_root() {
    // N3: an event under no known folder (removed meanwhile) is dropped, not
    // judged by its file name.
    let root = visible_tempdir();
    let elsewhere = visible_tempdir();
    let file = elsewhere.path().join("a.txt");
    write(&file, b"x");
    let ig = IgnoreSet::build(&[root.path().to_path_buf()]).unwrap();
    assert!(!should_watch_path(&file, &ig));
}

#[test]
fn ignore_set_root_of_picks_longest_root_and_canonical_alias() {
    let base = visible_tempdir();
    let outer = base.path().join("outer");
    let inner = outer.join("inner");
    std::fs::create_dir_all(&inner).unwrap();
    let link = base.path().join("link");
    std::os::unix::fs::symlink(&outer, &link).unwrap();
    let ig = IgnoreSet::build(&[link.clone(), inner.clone()]).unwrap();
    // inotify spelling (as configured) and FSEvents spelling (canonical) both map.
    assert_eq!(ig.root_of(&link.join("a.txt")), Some(link.as_path()));
    let canon_outer = std::fs::canonicalize(&outer).unwrap();
    assert_eq!(
        ig.root_of(&canon_outer.join("a.txt")),
        Some(canon_outer.as_path())
    );
    assert_eq!(ig.root_of(&inner.join("b.txt")), Some(inner.as_path()));
    assert_eq!(ig.root_of(Path::new("/nowhere/x")), None);
}

#[test]
fn absolute_watch_dir_resolves_relative_path_against_cwd() {
    let rel = Path::new("some/folder");
    let abs = absolute_watch_dir(rel);
    assert!(abs.is_absolute());
    assert_eq!(abs, std::env::current_dir().unwrap().join(rel));
    let already = Path::new("/srv/photos");
    assert_eq!(absolute_watch_dir(already), already);
}

#[test]
fn is_viaticum_data_dir_recognizes_fresh_init_without_db() {
    // N6: between `init` and the first daemon start there is no db.redb yet.
    let base = visible_tempdir();
    let dd = base.path().join("vdata");
    crate::daemon::identity::init_identity(&dd).unwrap();
    assert!(!dd.join(DB_FILE_NAME).exists());
    assert!(is_viaticum_data_dir(&dd));
}

#[test]
fn is_viaticum_data_dir_rejects_foreign_identity_key_without_db() {
    let base = visible_tempdir();
    write(
        &base.path().join("project").join(KEYFILE_NAME),
        b"-----BEGIN KEY-----",
    );
    assert!(!is_viaticum_data_dir(&base.path().join("project")));
    assert!(!is_viaticum_data_dir(base.path()));
}

#[test]
fn refuse_folder_is_data_dir() {
    let base = visible_tempdir();
    let dd = base.path().join("vdata");
    fake_data_dir(&dd);
    assert_eq!(refuse_folder(&dd), Some(FolderRefusal::IsDataDir));
}

#[test]
fn refuse_folder_inside_holdings_of_data_dir() {
    let base = visible_tempdir();
    let dd = base.path().join("vdata");
    fake_data_dir(&dd);
    assert_eq!(
        refuse_folder(&dd.join(HOLDINGS_DIR_NAME)),
        Some(FolderRefusal::InsideDaemonStorage)
    );
    assert_eq!(
        refuse_folder(&dd.join(HOLDINGS_DIR_NAME).join("ab")),
        Some(FolderRefusal::InsideDaemonStorage)
    );
    // N2: retained SystemState blobs are daemon storage too.
    let ss = dd.join(SYSTEM_STATE_DIR_NAME);
    std::fs::create_dir_all(&ss).unwrap();
    assert_eq!(refuse_folder(&ss), Some(FolderRefusal::InsideDaemonStorage));
}

#[test]
fn refuse_folder_allows_user_folder_inside_data_dir() {
    // Every E2E watches `<data-dir>/files`.
    let base = visible_tempdir();
    let dd = base.path().join("vdata");
    fake_data_dir(&dd);
    let files = dd.join("files");
    std::fs::create_dir_all(&files).unwrap();
    assert_eq!(refuse_folder(&files), None);
    // A folder that merely CONTAINS a data dir (the friend watching `~`) is allowed.
    assert_eq!(refuse_folder(base.path()), None);
}

#[test]
fn refuse_folder_through_symlink_into_holdings() {
    let base = visible_tempdir();
    let dd = base.path().join("vdata");
    fake_data_dir(&dd);
    let link = base.path().join("innocent");
    std::os::unix::fs::symlink(dd.join(HOLDINGS_DIR_NAME), &link).unwrap();
    assert_eq!(
        refuse_folder(&link),
        Some(FolderRefusal::InsideDaemonStorage)
    );
}

#[test]
fn data_dir_between_includes_root_and_stops_there() {
    let base = visible_tempdir();
    let root = base.path().join("home");
    let dd = root.join("vdata");
    fake_data_dir(&dd);
    let mut cache = HashMap::new();
    assert!(data_dir_between(
        &root,
        &dd.join("holdings/ab/0.bin"),
        &mut cache
    ));
    assert!(data_dir_between(&root, &dd.join(DB_FILE_NAME), &mut cache));
    assert!(!data_dir_between(
        &root,
        &root.join("docs/a.txt"),
        &mut cache
    ));
    // The root itself is checked...
    assert!(data_dir_between(&dd, &dd.join("x.txt"), &mut cache));
    // ...but nothing above it: `<data-dir>/files` is a normal folder.
    let files = dd.join("files");
    assert!(!data_dir_between(&files, &files.join("a.txt"), &mut cache));
}

// ─── scan ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn scan_prunes_viaticum_data_dir_inside_folder() {
    let root = visible_tempdir();
    let dd = root.path().join("vdata");
    fake_data_dir(&dd);
    write(
        &dd.join("files/user.txt"),
        b"under the data dir: pruned with it",
    );
    let keep = root.path().join("docs/a.txt");
    write(&keep, b"a");

    let seen = scan_paths(root.path()).await;

    assert_eq!(seen, vec![keep.to_string_lossy().into_owned()], "{seen:?}");
}

#[tokio::test]
async fn scan_prunes_fresh_init_data_dir_inside_folder() {
    // N6: identity.key only (init done, daemon never started).
    let root = visible_tempdir();
    let dd = root.path().join("vdata");
    crate::daemon::identity::init_identity(&dd).unwrap();
    let keep = root.path().join("a.txt");
    write(&keep, b"a");

    let seen = scan_paths(root.path()).await;

    assert_eq!(seen, vec![keep.to_string_lossy().into_owned()], "{seen:?}");
}

#[tokio::test]
async fn scan_of_refused_root_emits_nothing() {
    let base = visible_tempdir();
    let dd = base.path().join("vdata");
    fake_data_dir(&dd);
    assert!(scan_paths(&dd).await.is_empty());
    assert!(scan_paths(&dd.join(HOLDINGS_DIR_NAME)).await.is_empty());
}

#[tokio::test]
async fn scan_does_not_follow_symlink_to_data_dir() {
    let base = visible_tempdir();
    let dd = base.path().join("vdata");
    fake_data_dir(&dd);
    let root = base.path().join("home");
    let keep = root.join("a.txt");
    write(&keep, b"a");
    std::os::unix::fs::symlink(&dd, root.join("state")).unwrap();

    let seen = scan_paths(&root).await;

    assert_eq!(seen, vec![keep.to_string_lossy().into_owned()], "{seen:?}");
}

#[tokio::test]
async fn scan_does_not_follow_symlink_to_directory_outside_folder() {
    // W4 (Wine `z: -> /`): a link to another part of the disk is not walked.
    let base = visible_tempdir();
    let foreign = base.path().join("foreign");
    write(&foreign.join("secret.txt"), b"s");
    let root = base.path().join("home");
    let keep = root.join("a.txt");
    write(&keep, b"a");
    std::os::unix::fs::symlink(&foreign, root.join("z")).unwrap();

    let seen = scan_paths(&root).await;

    assert_eq!(seen, vec![keep.to_string_lossy().into_owned()], "{seen:?}");
}

#[tokio::test]
async fn scan_terminates_on_symlink_loop_and_emits_each_file_once() {
    let root = visible_tempdir();
    let a = root.path().join("docs/a.txt");
    write(&a, b"a");
    std::os::unix::fs::symlink("..", root.path().join("docs/loop")).unwrap();
    std::os::unix::fs::symlink(root.path().join("x"), root.path().join("y")).unwrap();
    std::os::unix::fs::symlink(root.path().join("y"), root.path().join("x")).unwrap();

    let seen = tokio::time::timeout(Duration::from_secs(10), scan_paths(root.path()))
        .await
        .expect("scan terminates");

    let a = a.to_string_lossy().into_owned();
    assert_eq!(seen.iter().filter(|p| **p == a).count(), 1, "{seen:?}");
    assert!(!seen.iter().any(|p| p.contains("/loop/")), "{seen:?}");
    let unique: HashSet<&String> = seen.iter().collect();
    assert_eq!(unique.len(), seen.len(), "each file once: {seen:?}");
}

// ─── live events ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn watcher_does_not_emit_live_event_from_hidden_subdir() {
    let root = visible_tempdir();
    std::fs::create_dir_all(root.path().join(".hidden")).unwrap();
    std::fs::create_dir_all(root.path().join("docs")).unwrap();
    let (cfg, _dd) = config(vec![root.path().to_path_buf()], false, None);
    let (tx, mut rx) = mpsc::channel(64);
    let cancel = CancellationToken::new();
    tokio::spawn(start_watcher(cfg, tx, mpsc::channel(1).1, cancel.clone()));
    tokio::time::sleep(Duration::from_millis(150)).await;

    let hidden = root.path().join(".hidden/live.txt");
    std::fs::write(&hidden, b"x").unwrap();
    std::fs::write(&hidden, b"xy").unwrap();
    let control = root.path().join("docs/y.txt");
    std::fs::write(&control, b"c").unwrap();

    let seen = events_until(&mut rx, &control).await;
    assert!(!seen.iter().any(|p| p.contains("/.hidden/")), "{seen:?}");
    cancel.cancel();
}

#[tokio::test]
async fn flush_drops_live_event_inside_data_dir() {
    let root = visible_tempdir();
    let dd = root.path().join("vd");
    fake_data_dir(&dd);
    std::fs::create_dir_all(root.path().join("docs")).unwrap();
    let (cfg, _dd) = config(vec![root.path().to_path_buf()], false, None);
    let (tx, mut rx) = mpsc::channel(64);
    let cancel = CancellationToken::new();
    tokio::spawn(start_watcher(cfg, tx, mpsc::channel(1).1, cancel.clone()));
    tokio::time::sleep(Duration::from_millis(150)).await;

    // What a running daemon writes: symbols it holds for friends, its catalog.
    std::fs::write(dd.join("holdings/ab/1.bin"), b"symbol").unwrap();
    std::fs::write(dd.join(DB_FILE_NAME), b"db page").unwrap();
    let control = root.path().join("docs/y.txt");
    std::fs::write(&control, b"c").unwrap();

    let seen = events_until(&mut rx, &control).await;
    assert!(
        !seen
            .iter()
            .any(|p| p.starts_with(dd.to_string_lossy().as_ref())),
        "{seen:?}"
    );
    cancel.cancel();
}

#[tokio::test]
async fn watcher_does_not_emit_live_event_through_symlinked_directory() {
    // W4 for notify: with follow_symlinks the target would get a watch and its
    // files would be reported under the link.
    let base = visible_tempdir();
    let foreign = base.path().join("foreign");
    std::fs::create_dir_all(&foreign).unwrap();
    let root = base.path().join("home");
    std::fs::create_dir_all(&root).unwrap();
    std::os::unix::fs::symlink(&foreign, root.join("z")).unwrap();
    let (cfg, _dd) = config(vec![root.clone()], false, None);
    let (tx, mut rx) = mpsc::channel(64);
    let cancel = CancellationToken::new();
    tokio::spawn(start_watcher(cfg, tx, mpsc::channel(1).1, cancel.clone()));
    tokio::time::sleep(Duration::from_millis(150)).await;

    std::fs::write(foreign.join("through_link.txt"), b"x").unwrap();
    let control = root.join("y.txt");
    std::fs::write(&control, b"c").unwrap();

    let seen = events_until(&mut rx, &control).await;
    assert!(!seen.iter().any(|p| p.contains("through_link")), "{seen:?}");
    cancel.cancel();
}

#[tokio::test]
async fn watcher_marks_refused_config_folder_error_and_never_scans_it() {
    let base = visible_tempdir();
    let dd = base.path().join("vdata");
    fake_data_dir(&dd);
    let ok = base.path().join("photos");
    let keep = ok.join("p.jpg");
    write(&keep, b"p");
    let states: Arc<RwLock<HashMap<PathBuf, WatchEntryState>>> = Arc::default();
    // Initial scan on: the refused folder must not be part of it.
    let (cfg, _dd) = config(vec![dd.clone(), ok.clone()], true, Some(states.clone()));
    let (tx, mut rx) = mpsc::channel(64);
    let (ctl_tx, ctl_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    tokio::spawn(start_watcher(cfg, tx, ctl_rx, cancel.clone()));

    // Live writes into the refused folder are not watched either.
    tokio::time::sleep(Duration::from_millis(150)).await;
    std::fs::write(dd.join("holdings/ab/2.bin"), b"s").unwrap();
    // A manual Scan of it keeps the error and scans nothing (W2).
    ctl_tx
        .send(WatcherCommand::Scan { path: dd.clone() })
        .await
        .unwrap();
    let control = ok.join("q.jpg");
    std::fs::write(&control, b"q").unwrap();

    let seen = events_until(&mut rx, &control).await;
    assert!(
        seen.contains(&keep.to_string_lossy().into_owned()),
        "{seen:?}"
    );
    assert!(
        !seen
            .iter()
            .any(|p| p.starts_with(dd.to_string_lossy().as_ref())),
        "{seen:?}"
    );
    let map = states.read().unwrap();
    let st = map.get(&dd).expect("status for the refused folder");
    assert_eq!(st.status, WatcherStatusSignal::Error);
    assert!(
        st.error
            .as_deref()
            .is_some_and(|e| e.contains("Viaticum data directory")),
        "{:?}",
        st.error
    );
    assert_ne!(
        map.get(&ok).map(|s| &s.status),
        Some(&WatcherStatusSignal::Error)
    );
    drop(map);
    cancel.cancel();
}

#[tokio::test]
async fn watcher_add_command_refuses_folder_inside_holdings() {
    let base = visible_tempdir();
    let dd = base.path().join("vdata");
    fake_data_dir(&dd);
    let holdings = dd.join(HOLDINGS_DIR_NAME);
    let states: Arc<RwLock<HashMap<PathBuf, WatchEntryState>>> = Arc::default();
    let (cfg, _dd) = config(vec![], false, Some(states.clone()));
    let (tx, mut rx) = mpsc::channel(64);
    let (ctl_tx, ctl_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    tokio::spawn(start_watcher(cfg, tx, ctl_rx, cancel.clone()));

    ctl_tx
        .send(WatcherCommand::Add {
            path: holdings.clone(),
            importance: 1.0,
        })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    std::fs::write(holdings.join("ab/3.bin"), b"s").unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;

    assert!(rx.try_recv().is_err(), "nothing from daemon storage");
    let map = states.read().unwrap();
    let st = map.get(&holdings).expect("status for the refused folder");
    assert_eq!(st.status, WatcherStatusSignal::Error);
    assert!(
        st.error
            .as_deref()
            .is_some_and(|e| e.contains("own storage")),
        "{:?}",
        st.error
    );
    drop(map);
    cancel.cancel();
}

// ─── backup-i16: symlink to a file inside a data dir ─────────────────────────

#[tokio::test]
async fn scan_skips_file_symlink_into_data_dir() {
    let base = visible_tempdir();
    let dd = base.path().join("vdata");
    fake_data_dir(&dd);
    let outside = base.path().join("outside.txt");
    write(&outside, b"o");
    let root = base.path().join("home");
    write(&root.join("a.txt"), b"a");
    std::os::unix::fs::symlink(dd.join(KEYFILE_NAME), root.join("k")).unwrap();
    std::os::unix::fs::symlink(dd.join(DB_FILE_NAME), root.join("db")).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("o_link")).unwrap();

    let got: HashSet<String> = scan_paths(&root).await.into_iter().collect();
    let want: HashSet<String> = [root.join("a.txt"), root.join("o_link")]
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    assert_eq!(got, want);
}

#[tokio::test]
async fn watcher_drops_live_event_of_file_symlink_into_data_dir() {
    let base = visible_tempdir();
    let dd = base.path().join("vdata");
    fake_data_dir(&dd);
    let root = base.path().join("home");
    std::fs::create_dir_all(&root).unwrap();
    let (cfg, _dd) = config(vec![root.clone()], false, None);
    let (tx, mut rx) = mpsc::channel(64);
    let cancel = CancellationToken::new();
    tokio::spawn(start_watcher(cfg, tx, mpsc::channel(1).1, cancel.clone()));
    tokio::time::sleep(Duration::from_millis(150)).await;

    std::os::unix::fs::symlink(dd.join(KEYFILE_NAME), root.join("k")).unwrap();
    let control = root.join("y.txt");
    std::fs::write(&control, b"c").unwrap();

    let seen = events_until(&mut rx, &control).await;
    let link = root.join("k").to_string_lossy().into_owned();
    assert!(!seen.contains(&link), "{seen:?}");
    cancel.cancel();
}

// ─── backup-i17: a folder whose watch() failed is still backed up ────────────

/// Restores `locked` to 0755 on drop, so a failed test leaves a removable temp dir.
struct Unlock(PathBuf);

impl Drop for Unlock {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}

/// `home/docs/a.txt` readable, `home/locked/` mode 000: a recursive `watch()` of
/// `home` fails on `locked` (the test runs unprivileged; root would read it).
fn folder_with_locked_subdir(base: &Path) -> (PathBuf, PathBuf, Unlock) {
    use std::os::unix::fs::PermissionsExt;
    let home = base.join("home");
    let file = home.join("docs/a.txt");
    write(&file, b"a");
    let locked = home.join("locked");
    write(&locked.join("secret.txt"), b"s");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    (home, file, Unlock(locked))
}

fn assert_error_status(states: &Arc<RwLock<HashMap<PathBuf, WatchEntryState>>>, dir: &Path) {
    let map = states.read().unwrap();
    let st = map.get(dir).expect("status for the folder");
    assert_eq!(st.status, WatcherStatusSignal::Error, "{:?}", st.error);
}

#[tokio::test]
async fn watcher_scans_added_folder_whose_watch_failed() {
    let base = visible_tempdir();
    let (home, file, _unlock) = folder_with_locked_subdir(base.path());
    let states: Arc<RwLock<HashMap<PathBuf, WatchEntryState>>> = Arc::default();
    let (cfg, _dd) = config(vec![], false, Some(states.clone()));
    let (tx, mut rx) = mpsc::channel(64);
    let (ctl_tx, ctl_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    tokio::spawn(start_watcher(cfg, tx, ctl_rx, cancel.clone()));

    ctl_tx
        .send(WatcherCommand::Add {
            path: home.clone(),
            importance: 1.0,
        })
        .await
        .unwrap();
    // The Add scan brings the readable file; the root itself got its watch before
    // the walk reached `locked`, so a live change at the root passes too.
    let first = events_until(&mut rx, &file).await;
    assert!(!first.iter().any(|p| p.contains("secret")), "{first:?}");
    assert_error_status(&states, &home);
    let live = home.join("live.txt");
    std::fs::write(&live, b"l").unwrap();
    events_until(&mut rx, &live).await;

    ctl_tx
        .send(WatcherCommand::Scan { path: home.clone() })
        .await
        .unwrap();
    let rescanned = events_until(&mut rx, &file).await;
    assert!(
        rescanned.contains(&file.to_string_lossy().into_owned()),
        "{rescanned:?}"
    );
    assert_error_status(&states, &home);
    cancel.cancel();
}

#[tokio::test]
async fn watcher_scans_config_folder_whose_watch_failed_and_keeps_error() {
    let base = visible_tempdir();
    let (home, file, _unlock) = folder_with_locked_subdir(base.path());
    let states: Arc<RwLock<HashMap<PathBuf, WatchEntryState>>> = Arc::default();
    let (cfg, _dd) = config(vec![home.clone()], true, Some(states.clone()));
    let (tx, mut rx) = mpsc::channel(64);
    let cancel = CancellationToken::new();
    tokio::spawn(start_watcher(cfg, tx, mpsc::channel(1).1, cancel.clone()));

    events_until(&mut rx, &file).await;
    assert_error_status(&states, &home);
    cancel.cancel();
}
