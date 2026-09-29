use tempfile::tempdir;

use super::{
    DaemonConfig, DaemonHandle, StartFailureKind, disk_available_bytes,
    scaled_avail_decay_tick_secs,
};
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
        bytes.is_some_and(|b| b > 0),
        "root filesystem should report > 0 available bytes, got {bytes:?}"
    );
}

/// holder-i2: a path that cannot be read is unknown (`None`), never "disk full" (0).
#[test]
fn disk_available_bytes_is_none_for_missing_path() {
    let dir = tempdir().unwrap();
    assert_eq!(disk_available_bytes(&dir.path().join("no/such/dir")), None);
}

/// holder-i2 / F6: statvfs of the data dir itself reads tmpfs (which the old mount-point
/// lookup through sysinfo skipped, reporting 0 = "disk full").
#[cfg(target_os = "linux")]
#[test]
fn statvfs_of_data_dir_is_some_on_tmpfs() {
    // A writable tmpfs mount of this machine (/dev/shm, /run/user/…, /tmp on the server).
    let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap();
    let dir = mounts
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let (_, mount, fstype) = (f.next()?, f.next()?, f.next()?);
            (fstype == "tmpfs").then_some(mount)
        })
        .find_map(|m| tempfile::tempdir_in(m).ok())
        .expect("no writable tmpfs mount — cannot check F6");
    let free = disk_available_bytes(dir.path());
    assert!(free.is_some_and(|b| b > 0), "tmpfs data dir: {free:?}");
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
// Multi-thread runtime: backup and staging cleanup use `block_in_place`, which
// panics on the default current-thread test runtime.
#[tokio::test(flavor = "multi_thread")]
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
            // daemon-i1: a missing key needs a person — systemd must not loop.
            assert_eq!(e.kind, StartFailureKind::NeedsUser);
            assert_eq!(e.exit_code(), 78);
        }
    }
}

// ============================================================
// daemon-i1: the start is all or nothing
// ============================================================

fn cfg_for(data_dir: &std::path::Path) -> DaemonConfig {
    DaemonConfig {
        data_dir: data_dir.to_path_buf(),
        time_scale: 1,
        watch_dirs: vec![],
    }
}

/// A config with a fixed listen port and the web API on an ephemeral port.
fn write_config_with_listen_port(data_dir: &std::path::Path, port: u16) {
    std::fs::write(
        data_dir.join("config.toml"),
        format!(
            "[network]\nlisten_port = {port}\nkademlia_disable_ipfs_bootstrap = true\n\
             [web_api]\nenabled = true\nbind = \"127.0.0.1:0\"\n"
        ),
    )
    .expect("write config");
}

/// The fixed listen port is held by another process. The start must refuse
/// (transient, 75), naming the port — and before anything is exposed: no web
/// API, no api-port file for the CLI to find (N1). The paused clock skips the
/// ~64 s handover wait.
#[tokio::test(start_paused = true)]
async fn start_fails_transient_when_listen_port_is_held() {
    let dir = tempdir().expect("tempdir");
    init_identity(dir.path()).expect("init_identity");
    let blocker = std::net::TcpListener::bind("0.0.0.0:0").expect("bind blocker");
    let port = blocker.local_addr().unwrap().port();
    write_config_with_listen_port(dir.path(), port);

    let err = match DaemonHandle::start(cfg_for(dir.path())).await {
        Ok(_) => panic!("start must refuse a held listen port"),
        Err(e) => e,
    };

    assert_eq!(err.kind, StartFailureKind::Transient);
    assert_eq!(err.exit_code(), 75);
    let msg = err.to_string();
    assert!(
        msg.contains(&format!("listen port {port} is in use")),
        "reason must name the port: {msg}"
    );
    assert!(
        !dir.path()
            .join(crate::daemon::web_auth::PORT_FILENAME)
            .exists(),
        "a refused start must not publish a web API port"
    );
    drop(blocker);
}

/// The friend's path after DR onto a fresh `init` (dr-i2): the stored cluster
/// lists only the lost device. The start enrolls this device with the master
/// key before the network comes up. The swarm is then refused (held port) so
/// the test needs no live network; the enrollment must already be persisted.
#[tokio::test(start_paused = true)]
async fn start_enrolls_own_device_missing_from_restored_cluster() {
    use viaticum_core::cluster::{ClusterState, issue_device_certificate, master_identity};
    use viaticum_core::db::Db;
    use viaticum_core::types::{DeviceId, Timestamp};

    let dir = tempdir().expect("tempdir");
    let keyfile = init_identity(dir.path()).expect("init_identity");
    let this_device = DeviceId(keyfile.device_id);
    let (master_key, _, _) =
        crate::daemon::identity::derive_keys(&keyfile, 0).expect("derive keys");
    let lost_device = DeviceId([0x42; 32]);
    {
        let db = Db::open(&dir.path().join("db.redb")).expect("db");
        let now = Timestamp::now();
        let cert = issue_device_certificate(&master_key, lost_device, now);
        ClusterState::init(db, master_identity(&master_key), cert, now, now)
            .expect("restored cluster state");
    }
    let blocker = std::net::TcpListener::bind("0.0.0.0:0").expect("bind blocker");
    write_config_with_listen_port(dir.path(), blocker.local_addr().unwrap().port());

    let err = match DaemonHandle::start(cfg_for(dir.path())).await {
        Ok(_) => panic!("held port must still refuse the start"),
        Err(e) => e,
    };
    assert_eq!(err.kind, StartFailureKind::Transient, "{err}");

    let db = Db::open(&dir.path().join("db.redb")).expect("reopen db");
    let state = ClusterState::load(db).expect("cluster state");
    assert!(state.get_device(&lost_device).is_some(), "old device stays");
    assert_eq!(
        state.get_device(&this_device).map(|d| d.device_index),
        Some(1),
        "this device must be enrolled"
    );
    drop(blocker);
}

/// db.redb next to this identity belongs to another master: this key cannot
/// sign into that cluster. Refuse with 78 and leave the state untouched.
#[tokio::test]
async fn start_fails_needs_user_when_cluster_master_differs() {
    use viaticum_core::cluster::{ClusterState, issue_device_certificate, master_identity};
    use viaticum_core::db::Db;
    use viaticum_core::types::{DeviceId, Timestamp};

    let dir = tempdir().expect("tempdir");
    init_identity(dir.path()).expect("init_identity");
    let foreign_master = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    {
        let db = Db::open(&dir.path().join("db.redb")).expect("db");
        let now = Timestamp::now();
        let cert = issue_device_certificate(&foreign_master, DeviceId([1u8; 32]), now);
        ClusterState::init(db, master_identity(&foreign_master), cert, now, now)
            .expect("foreign cluster state");
    }

    let err = match DaemonHandle::start(cfg_for(dir.path())).await {
        Ok(_) => panic!("a foreign cluster state must refuse the start"),
        Err(e) => e,
    };

    assert_eq!(err.kind, StartFailureKind::NeedsUser, "{err}");
    assert_eq!(err.exit_code(), 78);
    assert!(
        err.to_string().contains("belongs to another master"),
        "{err}"
    );
    let db = Db::open(&dir.path().join("db.redb")).expect("reopen db");
    assert_eq!(
        ClusterState::load(db).expect("state").all_devices().len(),
        1
    );
}

#[tokio::test]
async fn start_fails_needs_user_when_config_is_broken() {
    let dir = tempdir().expect("tempdir");
    init_identity(dir.path()).expect("init_identity");
    std::fs::write(
        dir.path().join("config.toml"),
        "[network\nlisten_port = = 1\n",
    )
    .unwrap();

    let err = match DaemonHandle::start(cfg_for(dir.path())).await {
        Ok(_) => panic!("a broken config must refuse the start"),
        Err(e) => e,
    };

    assert_eq!(err.kind, StartFailureKind::NeedsUser, "{err}");
    assert_eq!(err.exit_code(), 78);
    assert!(err.to_string().contains("config.toml"), "{err}");
}

/// The data dir is not there (home not mounted or not unlocked yet when a
/// `systemd --user` unit starts): the key cannot be seen yet, so the start is
/// retried (75), not parked as "run init" (78).
#[tokio::test]
async fn start_fails_transient_when_data_dir_is_missing() {
    let dir = tempdir().expect("tempdir");
    let missing = dir.path().join("not-mounted-yet");

    let err = match DaemonHandle::start(cfg_for(&missing)).await {
        Ok(_) => panic!("a missing data dir must refuse the start"),
        Err(e) => e,
    };

    assert_eq!(err.kind, StartFailureKind::Transient, "{err}");
    assert_eq!(err.exit_code(), 75);
    assert!(err.to_string().contains("not-mounted-yet"), "{err}");
    assert!(!missing.exists(), "a refused start must not create the dir");
}

/// The web API port is taken: the start refuses (75) BEFORE the swarm listens,
/// so the fixed libp2p port is still free the moment `start` returns (checked
/// synchronously, before the runtime could tear down a swarm task).
#[tokio::test]
async fn start_fails_transient_when_web_port_is_held_before_swarm_listens() {
    let dir = tempdir().expect("tempdir");
    init_identity(dir.path()).expect("init_identity");
    let listen_port = {
        let probe = std::net::TcpListener::bind("0.0.0.0:0").expect("probe");
        probe.local_addr().unwrap().port()
    };
    let web_blocker = std::net::TcpListener::bind("127.0.0.1:0").expect("bind web blocker");
    let web_port = web_blocker.local_addr().unwrap().port();
    std::fs::write(
        dir.path().join("config.toml"),
        format!(
            "[network]\nlisten_port = {listen_port}\nkademlia_disable_ipfs_bootstrap = true\n\
             [web_api]\nenabled = true\nbind = \"127.0.0.1:{web_port}\"\n"
        ),
    )
    .expect("write config");

    let err = match DaemonHandle::start(cfg_for(dir.path())).await {
        Ok(_) => panic!("start must refuse a held web port"),
        Err(e) => e,
    };

    let libp2p_free = std::net::TcpListener::bind(("0.0.0.0", listen_port)).is_ok();
    assert_eq!(err.kind, StartFailureKind::Transient, "{err}");
    assert_eq!(err.exit_code(), 75);
    assert!(err.to_string().contains("web API"), "{err}");
    assert!(
        libp2p_free,
        "libp2p port {listen_port} must not have been bound by a start refused on the web port"
    );
    assert!(
        !dir.path()
            .join(crate::daemon::web_auth::PORT_FILENAME)
            .exists(),
        "a refused start must not publish a web API port"
    );
    drop(web_blocker);
}
