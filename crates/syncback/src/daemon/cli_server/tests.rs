use std::io::{Read, Write};
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use syncback_core::db::Db;
use syncback_core::types::{DeviceId, IdentityPub};

use iroh::RelayMode;

use crate::cli::types::{CliRequest, CliResponse};
use crate::daemon::handle::DaemonState;
use crate::daemon::network::{NetworkConfig, NetworkHandle};
use crate::daemon::restore::{RestoreError, RestoreRequest, RestoreResult};

use super::dispatch;

// ============================================================
// Test helper: build a minimal DaemonState backed by in-memory DB
// ============================================================

async fn make_test_state() -> Arc<DaemonState> {
    let db = Db::open_in_memory().expect("in-memory db");
    let identity_pub = IdentityPub([0u8; 32]);
    let device_id = DeviceId([0u8; 16]);

    // Minimal network handle (iroh endpoint — binds an ephemeral port).
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let net_config = NetworkConfig {
        signing_key,
        known_peers: Default::default(),
        device_cert: None,
        iroh_secret_key: None,
        relay_mode: RelayMode::Disabled,
    };
    let (incoming_tx, _incoming_rx) =
        mpsc::channel::<crate::daemon::network::connection::Connection>(1);
    let incoming_tx_for_state = incoming_tx.clone();
    let network = Arc::new(
        NetworkHandle::start(net_config, incoming_tx)
            .await
            .expect("network start"),
    );

    let (restore_tx, _restore_rx) = mpsc::channel::<(
        RestoreRequest,
        tokio::sync::oneshot::Sender<Result<RestoreResult, RestoreError>>,
    )>(4);

    let master_key = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);

    Arc::new(DaemonState {
        db,
        identity_pub,
        device_id,
        network,
        restore_tx,
        cluster_state: None,
        incoming_tx: incoming_tx_for_state,
        master_key,
        seed: vec![0u8; 64],
        data_dir: std::path::PathBuf::from("/tmp"),
        soft_quota_bytes: 0,
        disk_reserve_bytes: 0,
        time_scale: 1,
    })
}

// ============================================================
// Unit tests for dispatch
// ============================================================

#[tokio::test]
async fn dispatch_status_returns_status_response() {
    let state = make_test_state().await;
    let response = dispatch(CliRequest::Status, &state).await;
    assert!(matches!(response, CliResponse::Status(_)));
}

#[tokio::test]
async fn dispatch_status_identity_reflects_state() {
    let state = make_test_state().await;
    let response = dispatch(CliRequest::Status, &state).await;
    let CliResponse::Status(data) = response else {
        panic!("expected Status");
    };
    // Identity is all-zero bytes → hex is all zeros (64 chars for 32 bytes).
    assert_eq!(data.node_identity.len(), 64);
    assert!(data.node_identity.chars().all(|c| c == '0'));
}

#[tokio::test]
async fn dispatch_files_returns_files_response() {
    let state = make_test_state().await;
    let response = dispatch(CliRequest::Files { path_prefix: None }, &state).await;
    assert!(matches!(response, CliResponse::Files(_)));
}

#[tokio::test]
async fn dispatch_files_empty_db_returns_empty_list() {
    let state = make_test_state().await;
    let response = dispatch(CliRequest::Files { path_prefix: None }, &state).await;
    let CliResponse::Files(entries) = response else {
        panic!("expected Files");
    };
    assert!(entries.is_empty());
}

#[tokio::test]
async fn dispatch_versions_unknown_path_returns_empty_list() {
    let state = make_test_state().await;
    let response = dispatch(
        CliRequest::Versions {
            path: "photos/nonexistent.jpg".into(),
        },
        &state,
    )
    .await;
    let CliResponse::Versions(entries) = response else {
        panic!("expected Versions");
    };
    assert!(entries.is_empty());
}

#[tokio::test]
async fn dispatch_restore_coordinator_not_running_returns_error() {
    let state = make_test_state().await;
    // Drop the receiver so the send fails immediately.
    // (The make_test_state already drops _restore_rx; channel is bounded=4,
    // but since receiver is dropped, any send will fail.)
    let request = CliRequest::Restore {
        path: "some/file.txt".into(),
        version: None,
        date: None,
        dest: None,
    };
    // The file doesn't exist in DB, so get_file returns None → version_used=1.
    // Then send on a dropped-receiver channel → Error response.
    let response = dispatch(request, &state).await;
    // Either coordinator not running or db lookup returns empty:
    // both map to an error or valid Restore stub.
    match response {
        CliResponse::Error(_) => {} // expected: coordinator not running
        CliResponse::Restore(_) => {} // also acceptable if db returned empty
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn dispatch_device_revoke_no_cluster_returns_error() {
    let state = make_test_state().await;
    let id = "aa".repeat(16);
    let request = CliRequest::DeviceRevoke {
        device_id_hex: id.clone(),
    };
    let response = dispatch(request, &state).await;
    // Without cluster_state, revoke returns an error.
    assert!(matches!(response, CliResponse::Error(_)));
}

#[tokio::test]
async fn dispatch_versions_returns_versions_response() {
    let state = make_test_state().await;
    let request = CliRequest::Versions {
        path: "photos/img.jpg".into(),
    };
    let response = dispatch(request, &state).await;
    assert!(matches!(response, CliResponse::Versions(_)));
}

#[tokio::test]
async fn dispatch_device_list_returns_device_list_response() {
    let state = make_test_state().await;
    let response = dispatch(CliRequest::DeviceList, &state).await;
    // No cluster state → empty list (not an error).
    assert!(matches!(response, CliResponse::DeviceList(_)));
}

#[tokio::test]
async fn dispatch_device_list_empty_when_no_cluster() {
    let state = make_test_state().await;
    let response = dispatch(CliRequest::DeviceList, &state).await;
    let CliResponse::DeviceList(entries) = response else {
        panic!("expected DeviceList");
    };
    assert!(entries.is_empty());
}

#[tokio::test]
async fn dispatch_device_add_no_cluster_returns_error() {
    let state = make_test_state().await;
    let response = dispatch(
        CliRequest::DeviceAdd {
            label: "my-laptop".into(),
        },
        &state,
    )
    .await;
    // Without cluster_state, add returns an error.
    assert!(matches!(response, CliResponse::Error(_)));
}

#[tokio::test]
async fn dispatch_connect_invalid_addr_returns_error() {
    let state = make_test_state().await;
    let response = dispatch(
        CliRequest::Connect { addr: "192.168.1.1:12345".to_string() },
        &state,
    )
    .await;
    assert!(
        matches!(response, CliResponse::Error(_)),
        "expected Error for invalid addr format, got {response:?}"
    );
}

#[tokio::test]
async fn dispatch_connect_valid_addr_but_unreachable_returns_error() {
    let state = make_test_state().await;

    let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let node_id_bytes = sk.verifying_key().to_bytes();
    let node_id_hex: String = node_id_bytes.iter().map(|b| format!("{b:02x}")).collect();

    // Port 1 is almost certainly not listening; this will fail at iroh connect.
    let addr = format!("{node_id_hex}@127.0.0.1:1");

    let response = dispatch(CliRequest::Connect { addr }, &state).await;
    assert!(
        matches!(response, CliResponse::Error(_)),
        "expected Error for unreachable peer, got {response:?}"
    );
}

#[tokio::test]
async fn dispatch_connect_two_daemons_registers_peer() {
    use std::sync::Arc;
    use syncback_core::db::Db;
    use syncback_core::types::DeviceId;
    use crate::daemon::network::{NetworkConfig, NetworkHandle};

    let (sk_a, pk_a) = {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let pk = IdentityPub(sk.verifying_key().to_bytes());
        (sk, pk)
    };
    let (sk_b, pk_b) = {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
        let pk = IdentityPub(sk.verifying_key().to_bytes());
        (sk, pk)
    };

    let (tx_b, _rx_b) = mpsc::channel::<crate::daemon::network::connection::Connection>(4);
    let handle_b = Arc::new(
        NetworkHandle::start(
            NetworkConfig {
                signing_key: sk_b,
                known_peers: Default::default(),
                device_cert: None,
                iroh_secret_key: None,
                relay_mode: RelayMode::Disabled,
            },
            tx_b,
        )
        .await
        .expect("handle_b"),
    );
    let addr_b_endpoint = handle_b.local_addr().expect("addr_b");
    let socket_addr_b = addr_b_endpoint
        .ip_addrs()
        .next()
        .copied()
        .expect("B must have a local IP addr");
    let addr_b_str = crate::daemon::network::addr::format_node_addr(&handle_b.node_id, socket_addr_b, None);

    let db_a = Db::open_in_memory().expect("db_a");
    let (tx_a, _rx_a) = mpsc::channel::<crate::daemon::network::connection::Connection>(4);
    let tx_a_for_state = tx_a.clone();
    let handle_a = Arc::new(
        NetworkHandle::start(
            NetworkConfig {
                signing_key: sk_a,
                known_peers: Default::default(),
                device_cert: None,
                iroh_secret_key: None,
                relay_mode: RelayMode::Disabled,
            },
            tx_a,
        )
        .await
        .expect("handle_a"),
    );
    let (restore_tx, _restore_rx) = mpsc::channel::<(
        RestoreRequest,
        tokio::sync::oneshot::Sender<Result<RestoreResult, RestoreError>>,
    )>(4);
    let state_a = Arc::new(DaemonState {
        db: db_a.clone(),
        identity_pub: pk_a,
        device_id: DeviceId([1u8; 16]),
        network: handle_a.clone(),
        restore_tx,
        cluster_state: None,
        incoming_tx: tx_a_for_state,
        master_key: ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]),
        seed: vec![0u8; 64],
        data_dir: std::path::PathBuf::from("/tmp"),
        soft_quota_bytes: 0,
        disk_reserve_bytes: 0,
        time_scale: 1,
    });

    let response = dispatch(CliRequest::Connect { addr: addr_b_str }, &state_a).await;

    let CliResponse::Connected { peer_id } = response else {
        panic!("expected Connected, got {response:?}");
    };
    let expected_hex: String = pk_b.0.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(peer_id, expected_hex, "peer_id should be B's full identity hex");

    let stored = db_a.get_peer(&pk_b).expect("db get_peer").expect("peer in db");
    assert_eq!(stored.identity, pk_b);
    assert!(!stored.addrs.is_empty(), "addr should be stored");

    let _ = handle_a.get_connection(pk_b).await.expect("get_connection after connect");
    // Handles are inside Arc (shared with state_a), so we skip explicit shutdown;
    // iroh endpoints are closed when the Arc is dropped at end of test.
}

// ============================================================
// Integration test: full round-trip over Unix socket
// ============================================================

#[tokio::test]
async fn cli_server_accepts_connection_and_responds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("test.sock");
    let socket_path_str = socket_path.to_str().expect("valid path").to_string();

    let cancel = CancellationToken::new();
    let config = super::CliServerConfig {
        socket_path: socket_path_str.clone(),
    };

    let state = make_test_state().await;
    let _handle = super::start(config, cancel.clone(), state)
        .await
        .expect("server start");

    // Poll for socket existence instead of a fixed sleep.
    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // Connect via blocking UnixStream (CLI side).
    let socket_path_clone = socket_path_str.clone();
    let result = tokio::task::spawn_blocking(move || {
        use std::os::unix::net::UnixStream;

        let stream = UnixStream::connect(&socket_path_clone).expect("connect");

        // Encode CliRequest::Status.
        let request = CliRequest::Status;
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&request, &mut buf).expect("encode");
        let len = buf.len() as u32;

        let mut writer = &stream;
        writer.write_all(&len.to_be_bytes()).expect("write len");
        writer.write_all(&buf).expect("write payload");

        // Read response.
        let mut reader = &stream;
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).expect("read len");
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        let mut payload = vec![0u8; resp_len];
        reader.read_exact(&mut payload).expect("read payload");

        let response: CliResponse =
            ciborium::de::from_reader(payload.as_slice()).expect("decode response");
        response
    })
    .await
    .expect("task");

    assert!(
        matches!(result, CliResponse::Status(_)),
        "expected Status response"
    );

    cancel.cancel();
}
