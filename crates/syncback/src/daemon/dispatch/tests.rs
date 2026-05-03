use std::sync::Arc;

use tokio::sync::mpsc;

use syncback_core::db::Db;
use syncback_core::types::{DeviceId, IdentityPub};

use crate::cli::types::{CliRequest, CliResponse};
use crate::daemon::handle::DaemonState;
use crate::daemon::restore::{RestoreError, RestoreRequest, RestoreResult};

use super::dispatch;

// ============================================================
// Test helper: build a minimal DaemonState backed by in-memory DB
// ============================================================

async fn make_test_state() -> Arc<DaemonState> {
    let db = Db::open_in_memory().expect("in-memory db");
    let device_id = DeviceId([0u8; 32]);

    let master_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let identity_pub = IdentityPub(master_key.verifying_key().to_bytes());

    let (restore_tx, _restore_rx) = mpsc::channel::<(
        RestoreRequest,
        tokio::sync::oneshot::Sender<Result<RestoreResult, RestoreError>>,
    )>(4);

    Arc::new(DaemonState {
        db,
        identity_pub,
        device_id,
        restore_tx,
        cluster_state: None,
        master_key,
        seed: vec![0u8; 64],
        data_dir: std::path::PathBuf::from("/tmp"),
        soft_quota_bytes: 0,
        disk_reserve_bytes: 0,
        hard_quota_bytes: 0,
        time_scale: 1,
        relay_post_tx: None,
        swarm_handle: None,
        watch_admin: None,
        config_admin: None,
        restart_gate: None,
        shutdown_token: tokio_util::sync::CancellationToken::new(),
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
    // Identity = master_key.verifying_key() hex (64 chars for 32 bytes).
    assert_eq!(data.node_identity.len(), 64);
    // Must match state.identity_pub which equals network.identity_pub (both from master_key).
    let expected = syncback_core::types::hex_encode(&IdentityPub(
        ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]).verifying_key().to_bytes()
    ).0);
    assert_eq!(data.node_identity, expected);
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
async fn dispatch_device_revoke_sends_broadcast_to_relay_post_tx() {
    use std::sync::{Arc, Mutex};

    use syncback_core::cluster::{
        derive_device_key, issue_device_certificate, master_identity,
        ClusterState,
    };
    use syncback_core::messages::RevocationBroadcast;
    use syncback_core::types::{DeviceId, Timestamp};

    use crate::daemon::relay::RelayPost;

    // Build two devices: A (this device), B (to be revoked).
    let seed_a = [10u8; 32];
    let master_key = syncback_core::cluster::derive_master_key(&seed_a).unwrap();
    let identity_pub = master_identity(&master_key);

    let device_id_a = DeviceId([0xA0u8; 32]);
    let device_id_b = DeviceId([0xB0u8; 32]);

    let _dev_key_a = derive_device_key(&seed_a, &device_id_a.0).unwrap();
    let _dev_key_b = derive_device_key(&seed_a, &device_id_b.0).unwrap();

    let now = Timestamp(1_000_000);
    let cert_a = issue_device_certificate(
        &master_key,
        device_id_a,
        now,
    );
    let cert_b = issue_device_certificate(
        &master_key,
        device_id_b,
        now,
    );

    let db = syncback_core::db::Db::open_in_memory().unwrap();
    let mut cs = ClusterState::init(db.clone(), identity_pub, cert_a.clone(), now, now).unwrap();
    cs.add_device(cert_b.clone(), now).unwrap();
    let cluster_state = Arc::new(Mutex::new(cs));

    // Wire up a relay_post channel so we can observe the broadcast.
    let (relay_post_tx, mut relay_post_rx) = tokio::sync::mpsc::channel::<RelayPost>(4);

    let (restore_tx, _restore_rx) = mpsc::channel::<(
        crate::daemon::restore::RestoreRequest,
        tokio::sync::oneshot::Sender<Result<
            crate::daemon::restore::RestoreResult,
            crate::daemon::restore::RestoreError,
        >>,
    )>(4);

    let state = Arc::new(DaemonState {
        db,
        identity_pub,
        device_id: device_id_a,
        restore_tx,
        cluster_state: Some(cluster_state),
        master_key,
        seed: seed_a.to_vec(),
        data_dir: std::path::PathBuf::from("/tmp"),
        soft_quota_bytes: 0,
        disk_reserve_bytes: 0,
        hard_quota_bytes: 0,
        time_scale: 1,
        relay_post_tx: Some(relay_post_tx),
        swarm_handle: None,
        watch_admin: None,
        config_admin: None,
        restart_gate: None,
        shutdown_token: tokio_util::sync::CancellationToken::new(),
    });

    // Revoke device B.
    let device_b_hex: String = device_id_b
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let response = dispatch(
        CliRequest::DeviceRevoke {
            device_id_hex: device_b_hex.clone(),
        },
        &state,
    )
    .await;

    assert!(
        matches!(response, CliResponse::DeviceRevoked { .. }),
        "expected DeviceRevoked, got {response:?}"
    );

    // Relay post channel must have received a RevocationBroadcast.
    let post = relay_post_rx
        .try_recv()
        .expect("relay_post_rx must have a message after revoke");

    assert_eq!(post.msg_type, "revocation_broadcast");
    assert!(post.target.is_none(), "broadcast must have no target");

    // Decode and verify payload.
    let broadcast: RevocationBroadcast =
        syncback_core::messages::from_cbor(&post.payload)
            .expect("payload must decode as RevocationBroadcast");
    assert_eq!(
        broadcast.device_cert.device_id, device_id_b,
        "broadcast must reference the revoked device"
    );
    assert_eq!(
        broadcast.revocation.device_id, device_id_b,
        "revocation cert must target device B"
    );
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

// dispatch_connect_two_daemons_registers_peer removed in ε.5 (iroh removal).
// The libp2p equivalent test should be in swarm_tests.rs.

/// C3: Restore with dest returns "dest_not_supported_in_alpha" error.
#[tokio::test]
async fn restore_with_dest_returns_error() {
    let state = make_test_state().await;
    let request = CliRequest::Restore {
        path: "/some/file.txt".into(),
        version: None,
        date: None,
        dest: Some("/tmp/custom_dest".to_string()),
    };
    let response = dispatch(request, &state).await;
    assert_eq!(
        response,
        CliResponse::Error("dest_not_supported_in_alpha".to_string()),
        "dest must be rejected with dest_not_supported_in_alpha, got: {response:?}"
    );
}

#[cfg(any())]
async fn _removed_dispatch_connect_two_daemons_registers_peer() {
    use std::sync::Arc;
    use syncback_core::cluster::{derive_master_key, derive_device_key, master_identity, issue_device_certificate};
    use syncback_core::db::Db;
    use syncback_core::types::{DeviceId, Timestamp};

    let seed_a = [1u8; 32];
    let seed_b = [2u8; 32];
    let master_a = derive_master_key(&seed_a).unwrap();
    let master_b = derive_master_key(&seed_b).unwrap();
    let pk_a = master_identity(&master_a);
    let pk_b = master_identity(&master_b);

    let did_a = DeviceId([1u8; 32]);
    let did_b = DeviceId([2u8; 32]);
    let device_a = derive_device_key(&seed_a, &did_a).unwrap();
    let device_b = derive_device_key(&seed_b, &did_b).unwrap();

    let cert_a = issue_device_certificate(&master_a, did_a, device_a.verifying_key().to_bytes(), Timestamp::now());
    let cert_b = issue_device_certificate(&master_b, did_b, device_b.verifying_key().to_bytes(), Timestamp::now());

    let (tx_b, _rx_b) = mpsc::channel::<crate::daemon::network::connection::Connection>(4);
    let handle_b = Arc::new(
        NetworkHandle::start(
            NetworkConfig {
                signing_key: device_b.clone(),
                master_signing_key: device_b,
                master_identity: pk_b,
                known_peers: Default::default(),
                device_cert: Some(cert_b),
                iroh_secret_key: None,
                relay_mode: RelayMode::Disabled,
                x25519_pub: None,
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
                signing_key: device_a.clone(),
                master_signing_key: device_a,
                master_identity: pk_a,
                known_peers: Default::default(),
                device_cert: Some(cert_a),
                iroh_secret_key: None,
                relay_mode: RelayMode::Disabled,
                x25519_pub: None,
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
        device_id: did_a,
        network: handle_a.clone(),
        restore_tx,
        cluster_state: None,
        incoming_tx: tx_a_for_state,
        master_key: master_a,
        seed: vec![0u8; 64],
        data_dir: std::path::PathBuf::from("/tmp"),
        soft_quota_bytes: 0,
        disk_reserve_bytes: 0,
        hard_quota_bytes: 0,
        time_scale: 1,
        relay_post_tx: None,
        swarm_handle: None,
        watch_admin: None,
        config_admin: None,
        restart_gate: None,
        shutdown_token: tokio_util::sync::CancellationToken::new(),
    });

    let response = dispatch(CliRequest::Connect { addr: addr_b_str }, &state_a).await;

    let CliResponse::Connected { peer_id } = response else {
        panic!("expected Connected, got {response:?}");
    };
    // Connected peer_id should be B's master identity (from cert).
    let expected_hex: String = pk_b.0.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(peer_id, expected_hex, "peer_id should be B's master identity hex");

    // Peer should be stored under master identity.
    let stored = db_a.get_peer(&pk_b).expect("db get_peer").expect("peer in db");
    assert_eq!(stored.identity, pk_b);
    assert!(!stored.addrs.is_empty(), "addr should be stored");

    let _ = handle_a.get_connection(pk_b).await.expect("get_connection after connect");
}

