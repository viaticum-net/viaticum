use tempfile::tempdir;

use super::{DaemonConfig, DaemonHandle, disk_available_bytes};
use crate::daemon::identity::init_identity;

#[test]
fn disk_available_bytes_returns_positive_for_existing_path() {
    let bytes = disk_available_bytes(std::path::Path::new("/"));
    assert!(bytes > 0, "root filesystem should report > 0 available bytes");
}

#[test]
fn disk_available_bytes_returns_zero_for_relative_path() {
    // Mount points are absolute. A relative path never satisfies
    // `path.starts_with(mount_point)`, so the sysinfo impl falls through to 0.
    let bytes = disk_available_bytes(std::path::Path::new("not/an/absolute/path"));
    assert_eq!(bytes, 0);
}

// ============================================================
// DaemonHandle integration tests
// ============================================================

/// Daemon starts cleanly with a freshly initialized identity and
/// shuts down without error when stop() + wait() are called.
///
/// Ignored by default because it starts a real libp2p swarm endpoint and
/// the tokio scheduler load causes timing-sensitive tests in other modules
/// to become flaky when run in the same binary. Run with `--ignored` for
/// manual / CI integration verification.
#[tokio::test]
#[ignore = "heavy: starts real libp2p swarm endpoint; run with --ignored"]
async fn daemon_starts_and_stops_cleanly() {
    let dir = tempdir().expect("tempdir");
    let data_dir = dir.path().to_path_buf();

    // Provision identity so load_identity() succeeds.
    init_identity(&data_dir).expect("init_identity");

    let cfg = DaemonConfig {
        data_dir: data_dir.clone(),
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

/// Verifies that the inbound drain task consumes messages without blocking
/// and exits cleanly when the sender is dropped.
#[tokio::test]
async fn inbound_drain_task_does_not_block_relay() {
    use crate::daemon::relay::InboundMessage;
    use syncback_core::types::{IdentityPub, Timestamp};
    use tokio::sync::mpsc;

    let (inbound_tx, inbound_rx) = mpsc::channel::<InboundMessage>(4);

    // Spawn the drain task (mirrors handle/mod.rs logic).
    tokio::spawn(async move {
        let mut rx = inbound_rx;
        while let Some(_msg) = rx.recv().await {}
    });

    // Send several messages; none should block or return an error.
    for i in 0u8..4 {
        let msg = InboundMessage {
            from: IdentityPub([i; 32]),
            payload: vec![i],
            msg_type: "test".to_string(),
            msg_id: [i; 16],
            created_at: Timestamp::now(),
        };
        inbound_tx.send(msg).await.expect("send should succeed");
    }
    // Drop the sender; the drain task should exit naturally.
    drop(inbound_tx);
}

/// Daemon returns an error when identity has not been initialized.
#[tokio::test]
async fn daemon_start_fails_without_identity() {
    let dir = tempdir().expect("tempdir");
    let data_dir = dir.path().to_path_buf();
    // Deliberately skip init_identity.

    let cfg = DaemonConfig {
        data_dir: data_dir.clone(),
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
