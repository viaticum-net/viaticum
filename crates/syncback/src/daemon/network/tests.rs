// Network module tests.
//
// All tests run two iroh endpoints on localhost (no relay server needed).
// Tests 1-3, 6-7: full two-node setup with NetworkHandle.
// Tests 4-5: unit tests of handshake verification (no network).

use std::collections::HashMap;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use syncback_core::messages::{
    Message, PosChallengeMsg, StorageWarningMsg, SymbolTransferMsg, build_handshake,
    verify_handshake,
};
use syncback_core::erasure::Symbol;
use syncback_core::types::{IdentityPub, SourceBlockId, Timestamp};

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
    let hs = build_handshake(pk, stale_ts, &sk);

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
    let mut hs = build_handshake(pk, Timestamp::now(), &sk);
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
