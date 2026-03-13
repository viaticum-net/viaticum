use super::{Config, DaemonHandle, DirtyEvent, NetCommand, NetEvent, ProcessorMsg, StatusReply};

fn make_config() -> (Config, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().unwrap();
    let config = Config {
        syncback_dir: dir.path().to_path_buf(),
        ..Config::default()
    };
    (config, dir)
}

#[tokio::test]
async fn daemon_starts_and_cancels_cleanly() {
    let (config, _dir) = make_config();
    let handle = DaemonHandle::start(config).await.expect("start failed");
    handle.shutdown().await.expect("shutdown failed");
}

#[tokio::test]
async fn cancellation_token_propagates_to_all_stubs() {
    let (config, _dir) = make_config();
    let handle = DaemonHandle::start(config).await.expect("start failed");

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        handle.shutdown(),
    )
    .await;

    assert!(result.is_ok(), "shutdown did not complete within 2 seconds");
    assert!(result.unwrap().is_ok(), "shutdown returned error");
}

#[tokio::test]
async fn config_load_stores_given_dir_and_uses_defaults() {
    // No config.toml at this path — should fall back to defaults.
    let path = std::path::PathBuf::from("/nonexistent/path");
    let config = Config::load(path.clone()).unwrap();
    // syncback_dir must be exactly the path we provided, not HOME.
    assert_eq!(
        config.syncback_dir, path,
        "syncback_dir should be the path passed to load()"
    );
    assert!(config.storage.quota_gb > 0, "quota_gb should be > 0");
}

#[test]
fn channel_types_are_send() {
    fn assert_send<T: Send>() {}

    assert_send::<ProcessorMsg>();
    assert_send::<DirtyEvent>();
    assert_send::<NetEvent>();
    assert_send::<NetCommand>();
    assert_send::<StatusReply>();
}
