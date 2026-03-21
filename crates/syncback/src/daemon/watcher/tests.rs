// Tests for the filesystem watcher module.

use std::time::Duration;

use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use syncback_core::types::DeviceId;

use crate::daemon::backup::DirtyKind;
use crate::daemon::watcher::{start_watcher, WatcherConfig};

const TEST_DEVICE_ID: DeviceId = DeviceId([1u8; 16]);
const DEBOUNCE_MS: u64 = 50;

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
fn config_for(dir: &TempDir) -> WatcherConfig {
    WatcherConfig {
        watch_dirs: vec![dir.path().to_path_buf()],
        device_id: TEST_DEVICE_ID,
        debounce_ms: DEBOUNCE_MS,
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
        start_watcher(config, dirty_tx, cancel_clone)
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
        start_watcher(config, dirty_tx, cancel_clone)
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
        start_watcher(config, dirty_tx, cancel_clone)
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
        start_watcher(config, dirty_tx, cancel_clone)
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
        start_watcher(config, dirty_tx, cancel_clone)
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

#[tokio::test]
async fn watcher_errors_on_empty_watch_dirs() {
    let (dirty_tx, _dirty_rx) = mpsc::channel(32);
    let cancel = CancellationToken::new();
    let config = WatcherConfig {
        watch_dirs: vec![],
        device_id: TEST_DEVICE_ID,
        debounce_ms: DEBOUNCE_MS,
    };
    let result = start_watcher(config, dirty_tx, cancel).await;
    assert!(
        result.is_err(),
        "expected WatcherError::NoWatchDirs for empty watch_dirs"
    );
}
