// Network module tests.
//
// All tests run two iroh endpoints on localhost (no relay server needed).
// Tests 1-3, 6-7: full two-node setup with NetworkHandle.
// Tests 4-5: unit tests of handshake verification (no network).

use std::collections::HashMap;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use syncback_core::cluster::{
    derive_device_key, derive_master_key, issue_device_certificate, master_identity,
};
use syncback_core::messages::{
    Message, PosChallengeMsg, StorageWarningMsg, SymbolTransferMsg, build_handshake,
    verify_handshake,
};
use syncback_core::erasure::Symbol;
use syncback_core::types::{DeviceId, IdentityPub, SourceBlockId, Timestamp};

use crate::daemon::network::{NetworkConfig, NetworkError, NetworkHandle};

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Generate a fresh signing key and matching IdentityPub.
fn keygen() -> (SigningKey, IdentityPub) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk = IdentityPub(sk.verifying_key().to_bytes());
    (sk, pk)
}

/// Create a NetworkConfig with empty known_peers.
fn make_config(signing_key: SigningKey) -> NetworkConfig {
    NetworkConfig {
        signing_key,
        known_peers: HashMap::new(),
        device_cert: None,
    }
}

// ─── Test 1: basic connection + handshake ─────────────────────────────────────

#[tokio::test]
async fn two_nodes_connect_and_handshake() {
    let (sk_a, _pk_a) = keygen();
    let (sk_b, _pk_b) = keygen();

    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(10);
    let (tx_b, mut rx_b) = tokio::sync::mpsc::channel(10);

    let handle_a = NetworkHandle::start(make_config(sk_a), tx_a)
        .await
        .expect("handle_a start");
    let handle_b = NetworkHandle::start(make_config(sk_b), tx_b)
        .await
        .expect("handle_b start");

    let addr_b = handle_b.local_addr().expect("addr_b");

    // A connects to B.
    let conn_a_to_b = handle_a
        .connect(addr_b, None)
        .await
        .expect("connect a -> b");

    // B receives the incoming connection.
    let incoming_b = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rx_b.recv(),
    )
    .await
    .expect("timeout waiting for B to receive connection")
    .expect("channel closed");

    // Verify identities.
    assert_eq!(
        conn_a_to_b.peer_identity,
        handle_b.identity_pub,
        "A sees B's identity"
    );
    assert_eq!(
        incoming_b.peer_identity,
        handle_a.identity_pub,
        "B sees A's identity"
    );

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

// ─── Test 2: send/receive message roundtrip ───────────────────────────────────

#[tokio::test]
async fn send_and_receive_message_roundtrip() {
    let (sk_a, _pk_a) = keygen();
    let (sk_b, _pk_b) = keygen();

    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(10);
    let (tx_b, mut rx_b) = tokio::sync::mpsc::channel(10);

    let handle_a = NetworkHandle::start(make_config(sk_a), tx_a)
        .await
        .expect("handle_a");
    let handle_b = NetworkHandle::start(make_config(sk_b), tx_b)
        .await
        .expect("handle_b");

    let addr_b = handle_b.local_addr().expect("addr_b");

    let mut conn_a = handle_a.connect(addr_b, None).await.expect("connect");
    let mut conn_b = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rx_b.recv(),
    )
    .await
    .expect("timeout")
    .expect("channel closed");

    // Build a PosChallenge message.
    let msg = Message::PosChallenge(PosChallengeMsg {
        v: 1,
        challenge_id: [7u8; 16],
        source_block_id: SourceBlockId([1u8; 32]),
        esi: 42,
        timestamp: Timestamp::now(),
    });

    NetworkHandle::send_message(&mut conn_a, &msg)
        .await
        .expect("send");

    let received = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        NetworkHandle::recv_message(&mut conn_b),
    )
    .await
    .expect("timeout")
    .expect("recv");

    assert_eq!(msg, received, "roundtrip message must match");

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

// ─── Test 3: symbol transfer roundtrip ───────────────────────────────────────

#[tokio::test]
async fn send_symbol_transfer_roundtrip() {
    let (sk_a, _pk_a) = keygen();
    let (sk_b, _pk_b) = keygen();

    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(10);
    let (tx_b, mut rx_b) = tokio::sync::mpsc::channel(10);

    let handle_a = NetworkHandle::start(make_config(sk_a), tx_a)
        .await
        .expect("handle_a");
    let handle_b = NetworkHandle::start(make_config(sk_b), tx_b)
        .await
        .expect("handle_b");

    let addr_b = handle_b.local_addr().expect("addr_b");

    let mut conn_a = handle_a.connect(addr_b, None).await.expect("connect");
    let mut conn_b = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rx_b.recv(),
    )
    .await
    .expect("timeout")
    .expect("channel closed");

    // Build a SymbolTransferMsg with 5 small symbols.
    // Using 64 bytes instead of 65535 to keep test fast.
    let symbols: Vec<Symbol> = (0..5)
        .map(|esi| Symbol {
            esi,
            data: vec![esi as u8; 64],
        })
        .collect();

    let msg = SymbolTransferMsg {
        v: 1,
        source_block_id: SourceBlockId([2u8; 32]),
        symbols,
        timestamp: Timestamp::now(),
    };

    NetworkHandle::send_message(&mut conn_a, &Message::SymbolTransfer(msg.clone()))
        .await
        .expect("send");

    let received = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        NetworkHandle::recv_message(&mut conn_b),
    )
    .await
    .expect("timeout")
    .expect("recv");

    assert!(
        matches!(received, Message::SymbolTransfer(ref m) if m == &msg),
        "symbol transfer must roundtrip correctly"
    );

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

// ─── Test 4: handshake rejects stale timestamp ───────────────────────────────

#[test]
fn handshake_rejects_stale_timestamp() {
    let (sk, pk) = keygen();
    let stale_ts = Timestamp(0); // Unix epoch — definitely stale.
    let hs = build_handshake(pk, stale_ts, &sk, None);

    let result = verify_handshake(&hs, Timestamp::now());
    assert!(
        matches!(result, Err(syncback_core::messages::MessageError::HandshakeStale { .. })),
        "stale timestamp must be rejected"
    );
}

// ─── Test 5: handshake rejects bad signature ──────────────────────────────────

#[test]
fn handshake_rejects_bad_signature() {
    let (sk, pk) = keygen();
    let mut hs = build_handshake(pk, Timestamp::now(), &sk, None);
    hs.sig[0] ^= 0xFF; // corrupt first byte

    let result = verify_handshake(&hs, Timestamp::now());
    assert!(
        matches!(result, Err(syncback_core::messages::MessageError::BadSignature)),
        "corrupted signature must be rejected"
    );
}

// ─── Test 6: connect with expected identity mismatch ─────────────────────────

#[tokio::test]
async fn connect_with_expected_identity_mismatch_fails() {
    let (sk_a, _pk_a) = keygen();
    let (sk_b, _pk_b) = keygen();
    let (_, wrong_pk) = keygen(); // completely different key

    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(10);
    let (tx_b, _rx_b) = tokio::sync::mpsc::channel(10);

    let handle_a = NetworkHandle::start(make_config(sk_a), tx_a)
        .await
        .expect("handle_a");
    let handle_b = NetworkHandle::start(make_config(sk_b), tx_b)
        .await
        .expect("handle_b");

    let addr_b = handle_b.local_addr().expect("addr_b");

    // A connects to B but expects the wrong identity.
    let result = handle_a.connect(addr_b, Some(wrong_pk)).await;

    assert!(
        matches!(result, Err(NetworkError::IdentityMismatch { .. })),
        "identity mismatch must fail with IdentityMismatch error"
    );

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

// ─── Test 7: multiple messages on same connection ─────────────────────────────

#[tokio::test]
async fn multiple_messages_on_same_connection() {
    let (sk_a, _pk_a) = keygen();
    let (sk_b, _pk_b) = keygen();

    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(10);
    let (tx_b, mut rx_b) = tokio::sync::mpsc::channel(10);

    let handle_a = NetworkHandle::start(make_config(sk_a), tx_a)
        .await
        .expect("handle_a");
    let handle_b = NetworkHandle::start(make_config(sk_b), tx_b)
        .await
        .expect("handle_b");

    let addr_b = handle_b.local_addr().expect("addr_b");

    let mut conn_a = handle_a.connect(addr_b, None).await.expect("connect");
    let mut conn_b = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rx_b.recv(),
    )
    .await
    .expect("timeout")
    .expect("channel closed");

    // Send 10 messages sequentially, verify all received in order.
    for i in 0u32..10 {
        let msg = Message::StorageWarning(StorageWarningMsg {
            v: 1,
            source_block_id: SourceBlockId([0u8; 32]),
            esi: i,
            details: format!("msg {i}"),
            timestamp: Timestamp::now(),
        });

        NetworkHandle::send_message(&mut conn_a, &msg)
            .await
            .unwrap_or_else(|e| panic!("send msg {i} failed: {e}"));

        let received = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            NetworkHandle::recv_message(&mut conn_b),
        )
        .await
        .unwrap_or_else(|_| panic!("timeout on recv msg {i}"))
        .unwrap_or_else(|e| panic!("recv msg {i} failed: {e}"));

        assert!(
            matches!(&received, Message::StorageWarning(m) if m.details == format!("msg {i}")),
            "message {i} must roundtrip with correct details"
        );
    }

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

// ─── Test 8: initiator with device cert — acceptor sees peer_master_identity ──

#[tokio::test]
async fn handshake_initiator_includes_device_cert() {
    // Build a cluster: master key → device key → cert.
    let master_key = derive_master_key(&[1u8; 32]).expect("master key");
    let device_id = DeviceId([2u8; 16]);
    let device_key = derive_device_key(&[1u8; 32], &device_id).expect("device key");
    let device_pub_key = device_key.verifying_key().to_bytes();
    let cert = issue_device_certificate(&master_key, device_id, device_pub_key, Timestamp(100));
    let master_pub = master_identity(&master_key);

    // Node A uses the device key + cert.
    let device_identity = IdentityPub(device_pub_key);
    let config_a = NetworkConfig {
        signing_key: device_key,
        known_peers: HashMap::new(),
        device_cert: Some(cert),
    };

    // Node B is a plain single-device node.
    let (sk_b, _pk_b) = keygen();
    let config_b = make_config(sk_b);

    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(10);
    let (tx_b, mut rx_b) = tokio::sync::mpsc::channel(10);

    let handle_a = NetworkHandle::start(config_a, tx_a)
        .await
        .expect("handle_a start");
    let handle_b = NetworkHandle::start(config_b, tx_b)
        .await
        .expect("handle_b start");

    let addr_b = handle_b.local_addr().expect("addr_b");

    // A (device) connects to B.
    let conn_a_to_b = handle_a
        .connect(addr_b, None)
        .await
        .expect("connect a -> b");

    // B receives the connection.
    let incoming_b = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rx_b.recv(),
    )
    .await
    .expect("timeout waiting for B to receive connection")
    .expect("channel closed");

    // A connected to B: A sees no master identity for B (B is single-device).
    assert_eq!(conn_a_to_b.peer_master_identity, None, "B has no cluster cert");

    // B received connection from A: B should see A's master identity.
    assert_eq!(
        incoming_b.peer_identity,
        device_identity,
        "B sees A's device identity"
    );
    assert_eq!(
        incoming_b.peer_master_identity,
        Some(master_pub),
        "B sees A's cluster master identity from device cert"
    );

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

// ─── Test 9: handshake without cert — peer_master_identity is None ────────────

#[tokio::test]
async fn handshake_without_cert_peer_master_identity_is_none() {
    let (sk_a, _pk_a) = keygen();
    let (sk_b, _pk_b) = keygen();

    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(10);
    let (tx_b, mut rx_b) = tokio::sync::mpsc::channel(10);

    let handle_a = NetworkHandle::start(make_config(sk_a), tx_a)
        .await
        .expect("handle_a");
    let handle_b = NetworkHandle::start(make_config(sk_b), tx_b)
        .await
        .expect("handle_b");

    let addr_b = handle_b.local_addr().expect("addr_b");

    let conn_a = handle_a.connect(addr_b, None).await.expect("connect");
    let conn_b = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rx_b.recv(),
    )
    .await
    .expect("timeout")
    .expect("channel closed");

    // Neither side presents a device cert.
    assert_eq!(conn_a.peer_master_identity, None, "no cert -> None");
    assert_eq!(conn_b.peer_master_identity, None, "no cert -> None");

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

// ─── Test 10: PeerRecord.is_device_revoked ────────────────────────────────────

#[test]
fn revocation_check_rejects_revoked_device_pub_key() {
    use syncback_core::types::PeerRecord;

    let revoked_pub = [3u8; 32];
    let record = PeerRecord {
        identity: IdentityPub([0u8; 32]),
        node_id: None,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        weeks_in_network: 0,
        device_id: None,
        revoked_device_pub_keys: vec![revoked_pub],
    };

    assert!(
        record.is_device_revoked(&IdentityPub(revoked_pub)),
        "revoked key must be detected"
    );
    assert!(
        !record.is_device_revoked(&IdentityPub([4u8; 32])),
        "non-revoked key must not trigger revocation"
    );
}

// ─── Test 11: PeerRecord backward compat — revoked_device_pub_keys defaults ───

#[test]
fn peer_record_revoked_device_pub_keys_default_empty() {
    use syncback_core::types::{from_cbor_bytes, to_cbor_bytes, PeerRecord};

    let record = PeerRecord {
        identity: IdentityPub([1u8; 32]),
        node_id: None,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        weeks_in_network: 0,
        device_id: None,
        revoked_device_pub_keys: vec![],
    };

    // Round-trip through CBOR.
    let bytes = to_cbor_bytes(&record);
    let decoded: PeerRecord = from_cbor_bytes(&bytes).expect("decode");
    assert_eq!(decoded.revoked_device_pub_keys, Vec::<[u8; 32]>::new());
}

