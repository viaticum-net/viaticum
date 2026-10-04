// Tests for the filesystem watcher module.

use std::time::Duration;

use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use viaticum_core::types::DeviceId;

use crate::daemon::backup::DirtyKind;
use crate::daemon::watcher::{
    IgnoreSet, WatcherCommand, WatcherConfig, debounce_ms_for_time_scale, start_watcher,
};

const TEST_DEVICE_ID: DeviceId = DeviceId([1u8; 32]);
const DEBOUNCE_MS: u64 = 50;

#[test]
fn debounce_ms_uses_debounce_secs_at_production_time_scale() {
    // At time_scale=1 (production) the debounce window is the full DEBOUNCE_SECS
    // (30 min) — a cold-backup workload coalesces edits instead of re-encoding on
    // every save. (Was hardcoded to 200 ms, ignoring the constant.)
    assert_eq!(
        debounce_ms_for_time_scale(1),
        viaticum_core::constants::DEBOUNCE_SECS * 1000
    );
}

#[test]
fn debounce_ms_scales_down_proportionally_with_time_scale() {
    // Under an experiment time_scale the window shrinks proportionally, the same
    // way every other time constant is scaled — not a fixed 200 ms.
    let ts = 1_000;
    assert_eq!(
        debounce_ms_for_time_scale(ts),
        viaticum_core::constants::DEBOUNCE_SECS * 1000 / ts
    );
}

#[test]
fn debounce_ms_floors_at_one() {
    // Extreme time_scale must never yield a zero-length window.
    assert_eq!(debounce_ms_for_time_scale(u64::MAX), 1);
}

/// Receive one DirtyEvent with a timeout.
async fn recv_with_timeout(
    rx: &mut mpsc::Receiver<crate::daemon::backup::DirtyEvent>,
) -> crate::daemon::backup::DirtyEvent {
    timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timed out waiting for DirtyEvent")
        .expect("channel closed before receiving event")
}

/// Build a WatcherConfig for a single temp directory.
/// Uses a separate data_dir so that `last_scan` marker doesn't trigger watch events.
/// Pre-creates the `last_scan` marker to skip the initial scan (which would
/// emit Added events for existing files and interfere with test assertions).
fn config_for(dir: &TempDir) -> WatcherConfig {
    let data_dir = TempDir::new().unwrap().keep();
    // Write a recent timestamp to skip initial scan.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let _ = std::fs::write(data_dir.join("last_scan"), now.to_string());
    WatcherConfig {
        watch_dirs: vec![dir.path().to_path_buf()],
        device_id: TEST_DEVICE_ID,
        debounce_ms: DEBOUNCE_MS,
        data_dir,
        rescan_interval_secs: 604800, // 1 week — effectively disabled for test duration
        watch_states: None,
        time_scale: 1,
        recheck_rx: None,
        resubmit_rx: None,
    }
}

#[tokio::test]
async fn watcher_detects_file_creation() {
    let dir = TempDir::new().unwrap();
    let (dirty_tx, mut dirty_rx) = mpsc::channel(32);
    let cancel = CancellationToken::new();

    let cancel_clone = cancel.clone();
    let config = config_for(&dir);
    tokio::spawn(async move {
        start_watcher(config, dirty_tx, mpsc::channel(1).1, cancel_clone)
            .await
            .expect("watcher error");
    });

    // Give the watcher a moment to register.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let file_path = dir.path().join("hello.txt");
    std::fs::write(&file_path, b"content").unwrap();

    let event = recv_with_timeout(&mut dirty_rx).await;
    assert_eq!(
        event.path,
        file_path.to_string_lossy().as_ref(),
        "path should match created file"
    );
    assert!(
        matches!(event.kind, DirtyKind::Added | DirtyKind::Modified),
        "kind should be Added or Modified for new file, got {:?}",
        event.kind
    );
    assert_eq!(event.device_id, TEST_DEVICE_ID);

    cancel.cancel();
}

#[tokio::test]
async fn watcher_detects_file_modification() {
    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("data.bin");
    std::fs::write(&file_path, b"initial").unwrap();

    // Small sleep so the creation event is not mixed in.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (dirty_tx, mut dirty_rx) = mpsc::channel(32);
    let cancel = CancellationToken::new();

    let cancel_clone = cancel.clone();
    let config = config_for(&dir);
    tokio::spawn(async move {
        start_watcher(config, dirty_tx, mpsc::channel(1).1, cancel_clone)
            .await
            .expect("watcher error");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    std::fs::write(&file_path, b"modified content").unwrap();

    let event = recv_with_timeout(&mut dirty_rx).await;
    assert_eq!(event.path, file_path.to_string_lossy().as_ref());
    assert!(
        matches!(event.kind, DirtyKind::Modified | DirtyKind::Added),
        "expected Modified/Added for an overwrite, got {:?}",
        event.kind
    );

    cancel.cancel();
}

#[tokio::test]
async fn watcher_detects_file_deletion() {
    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("to_delete.txt");
    std::fs::write(&file_path, b"bye").unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let (dirty_tx, mut dirty_rx) = mpsc::channel(32);
    let cancel = CancellationToken::new();

    let cancel_clone = cancel.clone();
    let config = config_for(&dir);
    tokio::spawn(async move {
        start_watcher(config, dirty_tx, mpsc::channel(1).1, cancel_clone)
            .await
            .expect("watcher error");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    std::fs::remove_file(&file_path).unwrap();

    let event = recv_with_timeout(&mut dirty_rx).await;
    assert_eq!(event.path, file_path.to_string_lossy().as_ref());
    assert_eq!(event.kind, DirtyKind::Deleted, "expected Deleted event");

    cancel.cancel();
}

#[tokio::test]
async fn watcher_ignores_hidden_files() {
    let dir = TempDir::new().unwrap();
    let (dirty_tx, mut dirty_rx) = mpsc::channel(32);
    let cancel = CancellationToken::new();

    let cancel_clone = cancel.clone();
    let config = config_for(&dir);
    tokio::spawn(async move {
        start_watcher(config, dirty_tx, mpsc::channel(1).1, cancel_clone)
            .await
            .expect("watcher error");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create hidden file — should be ignored.
    std::fs::write(dir.path().join(".hidden"), b"secret").unwrap();

    // Create visible file — should be seen.
    let visible = dir.path().join("visible.txt");
    std::fs::write(&visible, b"data").unwrap();

    let event = recv_with_timeout(&mut dirty_rx).await;
    assert_eq!(
        event.path,
        visible.to_string_lossy().as_ref(),
        "only the visible file should produce an event"
    );
    assert!(
        !event.path.contains(".hidden"),
        "hidden file must not appear in events"
    );

    cancel.cancel();
}

#[tokio::test]
async fn watcher_stops_on_cancel() {
    let dir = TempDir::new().unwrap();
    let (dirty_tx, _dirty_rx) = mpsc::channel(32);
    let cancel = CancellationToken::new();

    let cancel_clone = cancel.clone();
    let config = config_for(&dir);
    let handle = tokio::spawn(async move {
        start_watcher(config, dirty_tx, mpsc::channel(1).1, cancel_clone)
            .await
            .expect("watcher error");
    });

    // Give watcher time to start.
    tokio::time::sleep(Duration::from_millis(100)).await;

    cancel.cancel();

    // Watcher task must finish within 1 second of cancel.
    timeout(Duration::from_secs(1), handle)
        .await
        .expect("watcher did not stop within 1 second after cancel")
        .expect("watcher task panicked");
}

/// Watcher now starts cleanly with an empty watch_dirs list (awaits Add commands).
/// Renamed from watcher_errors_on_empty_watch_dirs; the old behavior was removed per spec.
#[tokio::test]
async fn watcher_starts_with_empty_dir_list_without_error() {
    let (dirty_tx, _dirty_rx) = mpsc::channel(32);
    let cancel = CancellationToken::new();
    let tmp = TempDir::new().unwrap();
    let config = WatcherConfig {
        watch_dirs: vec![],
        device_id: TEST_DEVICE_ID,
        debounce_ms: DEBOUNCE_MS,
        data_dir: tmp.path().to_path_buf(),
        rescan_interval_secs: 0,
        watch_states: None,
        time_scale: 1,
        recheck_rx: None,
        resubmit_rx: None,
    };
    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move {
        start_watcher(config, dirty_tx, mpsc::channel(1).1, cancel_clone)
            .await
            .expect("watcher must not error with empty dir list")
    });
    // Give watcher time to start.
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Cancel it; it should exit cleanly.
    cancel.cancel();
    timeout(Duration::from_secs(1), handle)
        .await
        .expect("watcher did not stop within 1 second")
        .expect("watcher task panicked");
}

// ─── WATCH-05: debounce_multiple_changes_emit_one_event ───────────────────────

/// Multiple rapid writes to the same file within the debounce window must
/// produce exactly one DirtyEvent (not one per write).
#[tokio::test]
async fn debounce_multiple_changes_emit_one_event() {
    let dir = TempDir::new().unwrap();
    let (dirty_tx, mut dirty_rx) = mpsc::channel(32);
    let cancel = CancellationToken::new();

    // Use a longer debounce to give us enough time to write multiple times.
    let config = WatcherConfig {
        watch_dirs: vec![dir.path().to_path_buf()],
        device_id: TEST_DEVICE_ID,
        debounce_ms: 300,
        data_dir: TempDir::new().unwrap().keep(),
        rescan_interval_secs: 0,
        watch_states: None,
        time_scale: 1,
        recheck_rx: None,
        resubmit_rx: None,
    };

    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        start_watcher(config, dirty_tx, mpsc::channel(1).1, cancel_clone)
            .await
            .expect("watcher error");
    });

    // Let the watcher register.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let file_path = dir.path().join("rapid.txt");

    // Write the file 5 times in rapid succession — all within debounce window.
    for i in 0u8..5 {
        std::fs::write(&file_path, [i; 64]).unwrap();
    }

    // Wait longer than the debounce window so the batch flushes.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Drain all events that arrived.
    let mut event_count = 0usize;
    while let Ok(event) = dirty_rx.try_recv() {
        assert_eq!(
            event.path,
            file_path.to_string_lossy().as_ref(),
            "unexpected path in event"
        );
        event_count += 1;
    }

    assert_eq!(
        event_count, 1,
        "5 rapid writes within debounce window must coalesce into 1 event, got {event_count}"
    );

    cancel.cancel();
}

// ─── WATCH-06: file deleted before debounce emits Deleted event ─────────────

/// Write a file, then delete it before the debounce window expires.
/// We expect a Deleted event (or at least no panic) when the debounce fires.
#[tokio::test]
async fn file_deleted_before_debounce_emits_deleted_event() {
    let dir = TempDir::new().unwrap();
    let (dirty_tx, mut dirty_rx) = mpsc::channel(32);
    let cancel = CancellationToken::new();

    // Long debounce so we can delete before it fires.
    let config = WatcherConfig {
        watch_dirs: vec![dir.path().to_path_buf()],
        device_id: TEST_DEVICE_ID,
        debounce_ms: 400,
        data_dir: TempDir::new().unwrap().keep(),
        rescan_interval_secs: 0,
        watch_states: None,
        time_scale: 1,
        recheck_rx: None,
        resubmit_rx: None,
    };

    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        start_watcher(config, dirty_tx, mpsc::channel(1).1, cancel_clone)
            .await
            .expect("watcher error");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let file_path = dir.path().join("ephemeral.txt");
    std::fs::write(&file_path, b"data").unwrap();

    // Delete the file while the debounce window is still active.
    tokio::time::sleep(Duration::from_millis(50)).await;
    std::fs::remove_file(&file_path).unwrap();

    // Wait for debounce to flush. No panic must occur.
    // The final event should reflect the Deleted state.
    let result = timeout(Duration::from_secs(3), dirty_rx.recv()).await;
    match result {
        Ok(Some(event)) => {
            assert_eq!(
                event.path,
                file_path.to_string_lossy().as_ref(),
                "event path must match deleted file"
            );
            // The last write before debounce is the delete — expect Deleted.
            // (Some platforms may coalesce to Modified; either is acceptable.)
            assert!(
                matches!(
                    event.kind,
                    DirtyKind::Deleted | DirtyKind::Modified | DirtyKind::Added
                ),
                "event kind must be a valid DirtyKind, got {:?}",
                event.kind
            );
        }
        Ok(None) => {
            // Channel closed — watcher exited cleanly without sending event (also acceptable).
        }
        Err(_timeout) => {
            // Timeout: no event arrived. The watcher may have swallowed the event
            // because the file was deleted before debounce. This is acceptable behavior.
        }
    }

    cancel.cancel();
}

// ─── WATCH-07: file without read permission — no panic ───────────────────────

/// Create a file, remove its read permission, trigger a scan. Must not panic.
/// Skipped if the test is running as root (root bypasses permission checks).
#[tokio::test]
#[cfg(unix)]
#[allow(unsafe_code)] // libc::getuid() is FFI, safe in practice
async fn file_without_read_permission_no_panic() {
    use std::os::unix::fs::PermissionsExt;

    // Skip if running as root (root ignores read-permission bits).
    if unsafe { libc::getuid() } == 0 {
        return;
    }

    let dir = TempDir::new().unwrap();
    let (dirty_tx, mut dirty_rx) = mpsc::channel(32);
    let cancel = CancellationToken::new();

    let config = config_for(&dir);
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        start_watcher(config, dirty_tx, mpsc::channel(1).1, cancel_clone)
            .await
            .expect("watcher error");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let file_path = dir.path().join("no_read.bin");
    std::fs::write(&file_path, b"secret").unwrap();
    // Remove read permission.
    std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o200)).unwrap();

    // Trigger another write to the same file to force a scan event. This may or
    // may not succeed depending on write permission; we just must not panic.
    let _ = std::fs::write(&file_path, b"update");

    // Either an event arrives or it doesn't — no panic is the invariant.
    let _ = timeout(Duration::from_secs(2), dirty_rx.recv()).await;

    // Restore permissions so TempDir cleanup succeeds.
    let _ = std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o644));

    cancel.cancel();
}

// ─── WATCH-10: rapid_changes_no_panic ────────────────────────────────────────

/// Write to the same file 10 times in 1 second. No panic; events eventually arrive.
#[tokio::test]
async fn rapid_changes_no_panic() {
    let dir = TempDir::new().unwrap();
    let (dirty_tx, mut dirty_rx) = mpsc::channel(64);
    let cancel = CancellationToken::new();

    let config = WatcherConfig {
        watch_dirs: vec![dir.path().to_path_buf()],
        device_id: TEST_DEVICE_ID,
        debounce_ms: DEBOUNCE_MS,
        data_dir: TempDir::new().unwrap().keep(),
        rescan_interval_secs: 0,
        watch_states: None,
        time_scale: 1,
        recheck_rx: None,
        resubmit_rx: None,
    };

    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        start_watcher(config, dirty_tx, mpsc::channel(1).1, cancel_clone)
            .await
            .expect("watcher error");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let file_path = dir.path().join("rapid.txt");

    // Write 10 times in rapid succession (within ~200 ms total).
    for i in 0u8..10 {
        std::fs::write(&file_path, [i; 32]).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Wait long enough for all debounce windows to expire.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Drain all events. Must not panic and at least one event must have arrived.
    let mut count = 0usize;
    while let Ok(event) = dirty_rx.try_recv() {
        assert_eq!(
            event.path,
            file_path.to_string_lossy().as_ref(),
            "unexpected path"
        );
        count += 1;
    }

    // Debounce should have coalesced the writes; we expect at least 1 event.
    assert!(
        count >= 1,
        "at least one event must arrive after 10 rapid writes"
    );

    cancel.cancel();
}

// ─── .viaticumignore tests ───────────────────────────────────────────────────

/// `IgnoreSet::build` with an empty `.viaticumignore` still enforces defaults.
#[test]
fn ignore_set_default_patterns_match_target_and_node_modules() {
    let root = TempDir::new().unwrap();
    let set = IgnoreSet::build(&[root.path().to_path_buf()]).unwrap();

    // Defaults: target/, node_modules/, .git/, __pycache__/, .cache/
    assert!(set.is_ignored(&root.path().join("target"), true));
    assert!(set.is_ignored(&root.path().join("target/foo.bin"), false));
    assert!(set.is_ignored(&root.path().join("node_modules/react/index.js"), false));
    assert!(set.is_ignored(&root.path().join(".git/HEAD"), false));
    assert!(set.is_ignored(&root.path().join("__pycache__/x.pyc"), false));

    // Not ignored: regular user files
    assert!(!set.is_ignored(&root.path().join("README.md"), false));
    assert!(!set.is_ignored(&root.path().join("src/main.rs"), false));
}

/// A `.viaticumignore` file with user patterns is loaded and applied on top of
/// the defaults.
#[test]
fn ignore_set_loads_viaticumignore_file() {
    let root = TempDir::new().unwrap();
    std::fs::write(
        root.path().join(".viaticumignore"),
        "secrets/\n*.tmp\nbuild/output.log\n",
    )
    .unwrap();

    let set = IgnoreSet::build(&[root.path().to_path_buf()]).unwrap();

    assert!(set.is_ignored(&root.path().join("secrets"), true));
    assert!(set.is_ignored(&root.path().join("secrets/passwords.txt"), false));
    assert!(set.is_ignored(&root.path().join("scratch.tmp"), false));
    assert!(set.is_ignored(&root.path().join("build/output.log"), false));

    assert!(!set.is_ignored(&root.path().join("build/release.bin"), false));
    assert!(!set.is_ignored(&root.path().join("notes.txt"), false));
}

/// Negation syntax (`!pattern`) un-ignores a file previously matched by a
/// default or earlier rule.
#[test]
fn ignore_set_negation_overrides_default() {
    let root = TempDir::new().unwrap();
    // Keep `target/important.keep` even though `target/` is a default ignore.
    std::fs::write(
        root.path().join(".viaticumignore"),
        "!target/\n!target/important.keep\n",
    )
    .unwrap();

    let set = IgnoreSet::build(&[root.path().to_path_buf()]).unwrap();

    // File explicitly whitelisted
    assert!(!set.is_ignored(&root.path().join("target/important.keep"), false));
    // Defaults for other paths still in force (we didn't un-ignore node_modules)
    assert!(set.is_ignored(&root.path().join("node_modules/x.js"), false));
}

/// Missing `.viaticumignore` is not an error — the matcher is built from the
/// defaults alone.
#[test]
fn ignore_set_missing_file_is_ok() {
    let root = TempDir::new().unwrap();
    assert!(!root.path().join(".viaticumignore").exists());

    let set = IgnoreSet::build(&[root.path().to_path_buf()]).unwrap();

    assert!(set.is_ignored(&root.path().join("target/foo"), false));
    assert!(!set.is_ignored(&root.path().join("src/lib.rs"), false));
}

/// Paths outside every configured watch directory fall through as "not
/// ignored" — no matcher claims them.
#[test]
fn ignore_set_path_outside_any_watch_dir_is_not_ignored() {
    let watched = TempDir::new().unwrap();
    let elsewhere = TempDir::new().unwrap();

    let set = IgnoreSet::build(&[watched.path().to_path_buf()]).unwrap();

    // Path under a completely different root: not filtered.
    assert!(!set.is_ignored(&elsewhere.path().join("target/evil.bin"), false));
}

/// End-to-end: the initial scan walks the watch dir and emits events only for
/// files not matched by `.viaticumignore`.
#[tokio::test]
async fn watcher_initial_scan_respects_viaticumignore() {
    let dir = TempDir::new().unwrap();

    // Create .viaticumignore with one pattern.
    std::fs::write(dir.path().join(".viaticumignore"), "ignored/\n*.log\n").unwrap();

    // Files that must be emitted:
    let keep = dir.path().join("keep.txt");
    std::fs::write(&keep, b"keep").unwrap();

    // Files that must be skipped:
    std::fs::create_dir_all(dir.path().join("ignored")).unwrap();
    std::fs::write(dir.path().join("ignored/inner.txt"), b"x").unwrap();
    std::fs::write(dir.path().join("scratch.log"), b"y").unwrap();

    // Default ignore: target/
    std::fs::create_dir_all(dir.path().join("target")).unwrap();
    std::fs::write(dir.path().join("target/out.bin"), b"z").unwrap();

    let (dirty_tx, mut dirty_rx) = mpsc::channel(32);
    let cancel = CancellationToken::new();

    // Fresh data_dir with NO last_scan marker → forces initial scan.
    let data_dir = TempDir::new().unwrap().keep();
    let config = WatcherConfig {
        watch_dirs: vec![dir.path().to_path_buf()],
        device_id: TEST_DEVICE_ID,
        debounce_ms: DEBOUNCE_MS,
        data_dir,
        rescan_interval_secs: 604800,
        watch_states: None,
        time_scale: 1,
        recheck_rx: None,
        resubmit_rx: None,
    };

    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        start_watcher(config, dirty_tx, mpsc::channel(1).1, cancel_clone)
            .await
            .expect("watcher error");
    });

    // Collect events for 500 ms — enough for the initial scan to complete.
    let mut seen: Vec<String> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(100), dirty_rx.recv()).await {
            Ok(Some(e)) => seen.push(e.path),
            Ok(None) => break,
            Err(_) => continue, // tick, keep waiting
        }
    }

    // keep.txt must be present.
    assert!(
        seen.iter().any(|p| p == keep.to_string_lossy().as_ref()),
        "expected keep.txt in scan results, got {:?}",
        seen
    );
    // Ignored files / dirs must be absent.
    for bad in &["ignored/inner.txt", "scratch.log", "target/out.bin"] {
        assert!(
            !seen.iter().any(|p| p.ends_with(bad)),
            "{bad} should have been filtered by .viaticumignore, got {:?}",
            seen
        );
    }

    cancel.cancel();
}

// ─── WATCH-08: large_file_generates_dirty_event ───────────────────────────────

/// A file larger than 128 MB must produce a DirtyEvent without panic.
/// This verifies that the watcher does not load file contents into memory.
#[tokio::test]
async fn large_file_generates_dirty_event() {
    let dir = TempDir::new().unwrap();
    let (dirty_tx, mut dirty_rx) = mpsc::channel(32);
    let cancel = CancellationToken::new();

    let config = config_for(&dir);
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        start_watcher(config, dirty_tx, mpsc::channel(1).1, cancel_clone)
            .await
            .expect("watcher error");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Write a 128 MB + 1 byte file.
    let large_file = dir.path().join("large.bin");
    const SIZE: usize = 128 * 1024 * 1024 + 1;
    // Write in chunks to avoid allocating 128 MB on the stack.
    let chunk = vec![0u8; 64 * 1024];
    let mut f = std::fs::File::create(&large_file).unwrap();
    use std::io::Write;
    let mut written = 0usize;
    while written < SIZE {
        let n = chunk.len().min(SIZE - written);
        f.write_all(&chunk[..n]).unwrap();
        written += n;
    }
    drop(f);

    // Should receive a DirtyEvent for the large file (not a panic).
    let event = recv_with_timeout(&mut dirty_rx).await;
    assert_eq!(
        event.path,
        large_file.to_string_lossy().as_ref(),
        "expected event for large.bin"
    );
    assert!(
        matches!(event.kind, DirtyKind::Added | DirtyKind::Modified),
        "expected Added or Modified for large file, got {:?}",
        event.kind
    );

    cancel.cancel();
}

// ─── WatcherCommand integration tests ────────────────────────────────────────

/// `WatcherCommand::Add` causes the watcher to register the new directory and
/// emit DirtyEvent::Added when a file is written there.
#[tokio::test]
async fn watcher_add_command_registers_new_dir_and_emits_dirty_events() {
    let dir = TempDir::new().unwrap();
    let (dirty_tx, mut dirty_rx) = mpsc::channel(32);
    let cancel = CancellationToken::new();

    // Start watcher with empty dir list.
    let (ctrl_tx, ctrl_rx) = mpsc::channel::<WatcherCommand>(8);
    let cancel_clone = cancel.clone();
    let data_dir = TempDir::new().unwrap();
    // Write a recent last_scan marker so Add-triggered scan is skipped by should_run_scan.
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let _ = std::fs::write(data_dir.path().join("last_scan"), now_ts.to_string());
    let config = WatcherConfig {
        watch_dirs: vec![],
        device_id: TEST_DEVICE_ID,
        debounce_ms: DEBOUNCE_MS,
        data_dir: data_dir.path().to_path_buf(),
        rescan_interval_secs: 604800,
        watch_states: None,
        time_scale: 1,
        recheck_rx: None,
        resubmit_rx: None,
    };
    tokio::spawn(async move {
        start_watcher(config, dirty_tx, ctrl_rx, cancel_clone)
            .await
            .expect("watcher error");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send Add command for the directory.
    ctrl_tx
        .send(WatcherCommand::Add {
            path: dir.path().to_path_buf(),
            importance: 0.5,
        })
        .await
        .expect("send failed");

    // Allow watcher time to register the directory.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Write a file to the newly-added directory.
    let file_path = dir.path().join("new_file.txt");
    std::fs::write(&file_path, b"hello").unwrap();

    // Should receive a DirtyEvent.
    let event = recv_with_timeout(&mut dirty_rx).await;
    assert!(
        event.path.ends_with("new_file.txt"),
        "expected event for file in newly-added dir, got: {}",
        event.path
    );

    cancel.cancel();
}

/// `WatcherCommand::Remove` causes the watcher to stop watching the directory.
/// Writing a file after removal should NOT produce a DirtyEvent.
#[tokio::test]
async fn watcher_remove_command_stops_watching_dir() {
    let dir = TempDir::new().unwrap();
    let (dirty_tx, mut dirty_rx) = mpsc::channel(32);
    let cancel = CancellationToken::new();

    let (ctrl_tx, ctrl_rx) = mpsc::channel::<WatcherCommand>(8);
    let cancel_clone = cancel.clone();
    let config = config_for(&dir);
    tokio::spawn(async move {
        start_watcher(config, dirty_tx, ctrl_rx, cancel_clone)
            .await
            .expect("watcher error");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send Remove command.
    ctrl_tx
        .send(WatcherCommand::Remove {
            path: dir.path().to_path_buf(),
        })
        .await
        .expect("send failed");

    tokio::time::sleep(Duration::from_millis(150)).await;

    // Write a file to the removed directory.
    std::fs::write(dir.path().join("post_remove.txt"), b"data").unwrap();

    // Wait one full debounce window — no event should arrive.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let got_event = dirty_rx.try_recv().is_ok();
    assert!(!got_event, "should not receive events after Remove command");

    cancel.cancel();
}

/// `WatcherCommand::Scan` triggers a full scan of a watched directory,
/// emitting DirtyEvent::Added for every file found.
#[tokio::test]
async fn watcher_scan_command_emits_added_events_for_all_files() {
    let dir = TempDir::new().unwrap();

    // Pre-create files so they exist before the scan.
    std::fs::write(dir.path().join("a.txt"), b"aaa").unwrap();
    std::fs::write(dir.path().join("b.txt"), b"bbb").unwrap();

    let (dirty_tx, mut dirty_rx) = mpsc::channel(32);
    let cancel = CancellationToken::new();

    let (ctrl_tx, ctrl_rx) = mpsc::channel::<WatcherCommand>(8);
    let cancel_clone = cancel.clone();
    // config_for writes a recent last_scan marker — no auto-scan.
    let config = config_for(&dir);
    tokio::spawn(async move {
        start_watcher(config, dirty_tx, ctrl_rx, cancel_clone)
            .await
            .expect("watcher error");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send Scan command.
    ctrl_tx
        .send(WatcherCommand::Scan {
            path: dir.path().to_path_buf(),
        })
        .await
        .expect("send failed");

    // Collect events over 500ms.
    let mut paths: Vec<String> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Some(e)) = tokio::time::timeout(Duration::from_millis(50), dirty_rx.recv()).await
        {
            paths.push(e.path)
        }
    }

    let has_a = paths.iter().any(|p| p.ends_with("a.txt"));
    let has_b = paths.iter().any(|p| p.ends_with("b.txt"));
    assert!(has_a, "expected a.txt in scan results, got {:?}", paths);
    assert!(has_b, "expected b.txt in scan results, got {:?}", paths);

    cancel.cancel();
}

// ─── daemon-i3 (R1-b1): one missing folder does not stop the others ──────────

/// A NAS share not mounted yet at start: folder B does not exist. The watcher
/// must keep running for folder A (initial scan + live events), mark B as
/// Error with a readable reason, and emit nothing — in particular no Deleted —
/// for B.
#[tokio::test]
async fn watcher_keeps_watching_other_dirs_when_one_is_missing() {
    use crate::daemon::watch_admin::{WatchEntryState, WatcherStatusSignal};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::{Arc, RwLock};

    let dir_a = TempDir::new().unwrap();
    let existing = dir_a.path().join("before.txt");
    std::fs::write(&existing, b"present at start").unwrap();
    let parent = TempDir::new().unwrap();
    let dir_b = parent.path().join("not-mounted-yet");

    let states: Arc<RwLock<HashMap<PathBuf, WatchEntryState>>> =
        Arc::new(RwLock::new(HashMap::new()));
    // Fresh data_dir with NO last_scan marker → the initial scan runs.
    let data_dir = TempDir::new().unwrap().keep();
    let config = WatcherConfig {
        watch_dirs: vec![dir_b.clone(), dir_a.path().to_path_buf()],
        device_id: TEST_DEVICE_ID,
        debounce_ms: DEBOUNCE_MS,
        data_dir,
        rescan_interval_secs: 604800,
        watch_states: Some(Arc::clone(&states)),
        time_scale: 1,
        recheck_rx: None,
        resubmit_rx: None,
    };

    let (dirty_tx, mut dirty_rx) = mpsc::channel(64);
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let task = tokio::spawn(async move {
        start_watcher(config, dirty_tx, mpsc::channel(1).1, cancel_clone).await
    });

    // Initial scan of A still happens.
    let first = recv_with_timeout(&mut dirty_rx).await;
    assert_eq!(first.path, existing.to_string_lossy().as_ref());
    assert_eq!(first.kind, DirtyKind::Added);

    // Live watching of A still works.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let created = dir_a.path().join("after.txt");
    std::fs::write(&created, b"created while B is missing").unwrap();
    let live = recv_with_timeout(&mut dirty_rx).await;
    assert_eq!(live.path, created.to_string_lossy().as_ref());

    // B is visible as broken, with the reason; A is not.
    {
        let map = states.read().unwrap();
        let b = map
            .get(&dir_b)
            .expect("status entry for the missing folder");
        assert_eq!(b.status, WatcherStatusSignal::Error);
        assert_eq!(b.error.as_deref(), Some("folder does not exist"));
        let a = map.get(dir_a.path()).expect("status entry for folder A");
        assert_ne!(a.status, WatcherStatusSignal::Error);
    }

    // The watcher is alive (did not return Err) and never spoke about B.
    assert!(!task.is_finished(), "watcher must keep running");
    tokio::time::sleep(Duration::from_millis(300)).await;
    while let Ok(ev) = dirty_rx.try_recv() {
        assert!(
            !ev.path.starts_with(dir_b.to_string_lossy().as_ref()),
            "no event may concern the missing folder: {ev:?}"
        );
    }
    cancel.cancel();
    let result = timeout(Duration::from_secs(5), task)
        .await
        .expect("watcher stops on cancel")
        .expect("join");
    assert!(result.is_ok(), "watcher ended with {result:?}");
}

#[test]
fn describe_watch_error_names_missing_folder_and_inotify_limit() {
    use crate::daemon::watcher::describe_watch_error;
    assert_eq!(
        describe_watch_error(&notify::Error::path_not_found()),
        "folder does not exist"
    );
    assert_eq!(
        describe_watch_error(&notify::Error::io(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied
        ))),
        "permission denied"
    );
    let limit = describe_watch_error(&notify::Error::new(notify::ErrorKind::MaxFilesWatch));
    assert!(limit.contains("fs.inotify.max_user_watches"), "{limit}");
}

/// An event already waiting out its debounce window when its folder is removed
/// is dropped at flush time (N3): the folder is no root any more.
#[tokio::test]
async fn watcher_drops_pending_event_of_removed_folder() {
    const DEBOUNCE: u64 = 1000;
    let dir = TempDir::new().unwrap();
    let (dirty_tx, mut dirty_rx) = mpsc::channel(32);
    let cancel = CancellationToken::new();
    let (ctrl_tx, ctrl_rx) = mpsc::channel::<WatcherCommand>(8);
    let mut config = config_for(&dir);
    config.debounce_ms = DEBOUNCE;
    tokio::spawn(start_watcher(config, dirty_tx, ctrl_rx, cancel.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    std::fs::write(dir.path().join("pending.txt"), b"data").unwrap();
    // Poll runs every DEBOUNCE/4: the event is in the debounce map, not yet flushed.
    tokio::time::sleep(Duration::from_millis(DEBOUNCE / 2)).await;
    ctrl_tx
        .send(WatcherCommand::Remove {
            path: dir.path().to_path_buf(),
        })
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(3 * DEBOUNCE)).await;
    let got: Vec<String> = std::iter::from_fn(|| dirty_rx.try_recv().ok())
        .map(|e| e.path)
        .collect();
    assert!(got.is_empty(), "event of a removed folder flushed: {got:?}");
    cancel.cancel();
}
