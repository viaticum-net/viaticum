use tempfile::tempdir;

use super::{DaemonConfig, DaemonHandle};
use crate::daemon::identity::init_identity;

// ============================================================
// DaemonHandle integration tests
// ============================================================

/// Daemon starts cleanly with a freshly initialized identity and
/// shuts down without error when stop() + wait() are called.
///
/// Ignored by default because it starts a real iroh QUIC endpoint and
/// the tokio scheduler load causes timing-sensitive tests in other modules
/// to become flaky when run in the same binary. Run with `--ignored` for
/// manual / CI integration verification.
#[tokio::test]
#[ignore = "heavy: starts real iroh QUIC endpoint; run with --ignored"]
async fn daemon_starts_and_stops_cleanly() {
    let dir = tempdir().expect("tempdir");
    let data_dir = dir.path().to_path_buf();

    // Provision identity so load_identity() succeeds.
    init_identity(&data_dir).expect("init_identity");

    // Pick a unique socket path inside the temp dir to avoid collisions.
    let socket_path = data_dir
        .join("daemon_test.sock")
        .to_str()
        .expect("valid utf-8 path")
        .to_string();

    let cfg = DaemonConfig {
        data_dir: data_dir.clone(),
        socket_path,
        time_scale: 1,
        watch_dirs: vec![],
    };

    let handle = DaemonHandle::start(cfg)
        .await
        .expect("DaemonHandle::start should succeed");

    // Signal shutdown immediately — just verify the lifecycle works.
    handle.stop();
    handle.wait().await.expect("all subsystem tasks should exit cleanly");
}

/// Daemon returns an error when identity has not been initialized.
#[tokio::test]
async fn daemon_start_fails_without_identity() {
    let dir = tempdir().expect("tempdir");
    let data_dir = dir.path().to_path_buf();
    // Deliberately skip init_identity.

    let socket_path = data_dir
        .join("daemon_test2.sock")
        .to_str()
        .expect("valid utf-8 path")
        .to_string();

    let cfg = DaemonConfig {
        data_dir: data_dir.clone(),
        socket_path,
        time_scale: 1,
        watch_dirs: vec![],
    };

    match DaemonHandle::start(cfg).await {
        Ok(_) => panic!("start without identity.key should return Err"),
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("syncback init"),
                "error message should mention 'syncback init', got: {msg}"
            );
        }
    }
}
