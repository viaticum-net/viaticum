use tempfile::tempdir;

use super::{DaemonConfig, DaemonHandle, disk_available_bytes, scaled_avail_decay_tick_secs};
use crate::daemon::identity::init_identity;

// CS-SCH-9: the avail-decay tick must scale with time_scale so avail_ewma
// actually decays under an accelerated clock. The full run_avail_decay_task is a
// real-timer loop (behavioural, not unit-covered), but the scaling arithmetic it
// depends on — used identically by the periodic task and the startup catch-up — is
// pure and covered here.
#[test]
fn avail_decay_tick_scales_with_time_scale() {
    const BASE: u64 = 24 * 3600; // AVAIL_DECAY_TICK_SECS

    // time_scale = 1 is identity (production path unchanged).
    assert_eq!(scaled_avail_decay_tick_secs(BASE, 1), BASE);

    // Accelerated: a 10x clock ticks 10x faster.
    assert_eq!(scaled_avail_decay_tick_secs(BASE, 10), BASE / 10);
    assert_eq!(scaled_avail_decay_tick_secs(BASE, 86_400), 1);

    // Floor at 1s: an extreme time_scale cannot collapse the tick to 0 (which
    // would decay every peer on every call).
    assert_eq!(scaled_avail_decay_tick_secs(BASE, BASE * 100), 1);

    // A zero time_scale is treated as 1 (max(1) guard) — never divides by zero.
    assert_eq!(scaled_avail_decay_tick_secs(BASE, 0), BASE);
}

#[test]
fn disk_available_bytes_returns_positive_for_existing_path() {
    let bytes = disk_available_bytes(std::path::Path::new("/"));
    assert!(
        bytes > 0,
        "root filesystem should report > 0 available bytes"
    );
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
    let outcome = handle
        .wait_with_deadline(super::shutdown::SHUTDOWN_DRAIN)
        .await;
    assert!(
        outcome.abandoned.is_empty(),
        "no task may outlive the drain: {:?}",
        outcome.abandoned
    );
    outcome
        .report()
        .expect("all subsystem tasks should exit cleanly");
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
                msg.contains("viaticum init"),
                "error message should mention 'viaticum init', got: {msg}"
            );
        }
    }
}
