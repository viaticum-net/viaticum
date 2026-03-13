use std::time::Duration;

use syncback::daemon::{BackupConfig, Config, DaemonHandle, NetworkConfig, ScheduleConfig,
                       StorageConfig, SyncFrequency, VacuumFrequency};
use syncback_core::constants::SECS_PER_WEEK;

fn make_config(syncback_dir: std::path::PathBuf, time_scale: u64) -> Config {
    Config {
        syncback_dir,
        backup: BackupConfig {
            include: vec![],
            exclude: vec![],
        },
        storage: StorageConfig { quota_gb: 10 },
        network: NetworkConfig {
            seed_nodes: vec![],
            bandwidth_limit_mbps: 0,
        },
        schedule: ScheduleConfig {
            sync: SyncFrequency::Weekly,
            vacuum: VacuumFrequency::Monthly,
        },
        time_scale,
    }
}

/// Verify that a node running with time_scale = SECS_PER_WEEK starts successfully,
/// runs for 4 real seconds (= 4 virtual weeks), and shuts down cleanly.
///
/// This is a smoke check that the clock-to-scheduler-to-processor pipeline
/// does not panic under time scaling.
#[tokio::test]
async fn four_virtual_weeks_in_four_seconds() {
    let dir = tempfile::tempdir().unwrap();
    let config = make_config(dir.path().to_path_buf(), SECS_PER_WEEK);

    let handle = DaemonHandle::start(config).await.expect("daemon start failed");

    // Wait 4 real seconds (= 4 virtual weeks at SECS_PER_WEEK scale).
    tokio::time::sleep(Duration::from_secs(4)).await;

    // Daemon must shut down cleanly without panic.
    handle.shutdown().await.expect("daemon shutdown failed");
}
