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
use syncback_core::types::{DeviceId, IdentityPub, NodeId, SourceBlockId, Timestamp};
use iroh::RelayMode;

use crate::daemon::network::{NetworkConfig, NetworkError, NetworkHandle};

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Generate a full key hierarchy (master + device + cert) from a seed byte.
/// Returns (device_signing_key, master_identity_pub, network_config).
fn make_node(seed_byte: u8) -> (IdentityPub, NetworkConfig) {
    let seed = [seed_byte; 32];
    let master_key = derive_master_key(&seed).expect("derive_master_key");
    let master_pub = master_identity(&master_key);
    let did = DeviceId([seed_byte; 16]);
    let device_key = derive_device_key(&seed, &did).expect("derive_device_key");
    let cert = issue_device_certificate(
        &master_key, did, device_key.verifying_key().to_bytes(), Timestamp::now(),
    );
    let config = NetworkConfig {
        signing_key: device_key,
        master_identity: master_pub,
        known_peers: HashMap::new(),
        device_cert: Some(cert),
        iroh_secret_key: None,
        relay_mode: RelayMode::Disabled,
        x25519_pub: None,
    };
    (master_pub, config)
}

/// Generate a fresh signing key and matching IdentityPub (device-level).
fn keygen() -> (SigningKey, IdentityPub) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk = IdentityPub(sk.verifying_key().to_bytes());
    (sk, pk)
}

/// Create a NetworkConfig with device cert from a seed byte.
fn make_config_with_cert(seed_byte: u8) -> NetworkConfig {
    make_node(seed_byte).1
}

// ─── Test 1: basic connection + handshake ─────────────────────────────────────

#[tokio::test]
async fn two_nodes_connect_and_handshake() {
    let (master_a, config_a) = make_node(1);
    let (master_b, config_b) = make_node(2);

    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(10);
    let (tx_b, mut rx_b) = tokio::sync::mpsc::channel(10);

    let handle_a = NetworkHandle::start(config_a, tx_a)
        .await
        .expect("handle_a start");
    let handle_b = NetworkHandle::start(config_b, tx_b)
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

    // Verify master identities (protocol-level identity from cert).
    assert_eq!(
        conn_a_to_b.master_identity(),
        master_b,
        "A sees B's master identity"
    );
    assert_eq!(
        incoming_b.master_identity(),
        master_a,
        "B sees A's master identity"
    );

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

// ─── Test 2: send/receive message roundtrip ───────────────────────────────────

#[tokio::test]
async fn send_and_receive_message_roundtrip() {
    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(10);
    let (tx_b, mut rx_b) = tokio::sync::mpsc::channel(10);

    let handle_a = NetworkHandle::start(make_config_with_cert(1), tx_a)
        .await
        .expect("handle_a");
    let handle_b = NetworkHandle::start(make_config_with_cert(2), tx_b)
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
    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(10);
    let (tx_b, mut rx_b) = tokio::sync::mpsc::channel(10);

    let handle_a = NetworkHandle::start(make_config_with_cert(3), tx_a)
        .await
        .expect("handle_a");
    let handle_b = NetworkHandle::start(make_config_with_cert(4), tx_b)
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
    // wrong_master is a completely different master identity (from node 99).
    let (wrong_master, _) = make_node(99);

    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(10);
    let (tx_b, _rx_b) = tokio::sync::mpsc::channel(10);

    let handle_a = NetworkHandle::start(make_config_with_cert(6), tx_a)
        .await
        .expect("handle_a");
    let handle_b = NetworkHandle::start(make_config_with_cert(7), tx_b)
        .await
        .expect("handle_b");

    let addr_b = handle_b.local_addr().expect("addr_b");

    // A connects to B but expects the wrong master identity.
    let result = handle_a.connect(addr_b, Some(wrong_master)).await;

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
    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(10);
    let (tx_b, mut rx_b) = tokio::sync::mpsc::channel(10);

    let handle_a = NetworkHandle::start(make_config_with_cert(11), tx_a)
        .await
        .expect("handle_a");
    let handle_b = NetworkHandle::start(make_config_with_cert(12), tx_b)
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
        master_identity: master_pub,
        known_peers: HashMap::new(),
        device_cert: Some(cert),
        iroh_secret_key: None,
        relay_mode: RelayMode::Disabled,
        x25519_pub: None,
    };

    // Node B also needs a cert (handshake now rejects cert-less peers).
    let (master_b, config_b) = make_node(2);

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

    // A connected to B: A sees B's master identity.
    assert_eq!(
        conn_a_to_b.master_identity(),
        master_b,
        "A sees B's master identity"
    );

    // B received connection from A: B should see A's device identity and master identity.
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

// ─── Test 9: handshake without cert — connection is rejected ──────────────────
//
// The handshake now requires a device certificate. Cert-less peers must be
// rejected with HandshakeFailed, not accepted with peer_master_identity=None.

#[tokio::test]
async fn handshake_without_cert_connection_is_rejected() {
    // Build two cert-less nodes (raw signing keys, no cert).
    let (sk_a, _) = keygen();
    let (sk_b, _) = keygen();

    let make_certless_config = |sk: ed25519_dalek::SigningKey| {
        let mi = IdentityPub(sk.verifying_key().to_bytes());
        NetworkConfig {
            signing_key: sk,
            master_identity: mi,
            known_peers: HashMap::new(),
            device_cert: None,
            iroh_secret_key: None,
            relay_mode: RelayMode::Disabled,
            x25519_pub: None,
        }
    };

    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(10);
    let (tx_b, _rx_b) = tokio::sync::mpsc::channel(10);

    let handle_a = NetworkHandle::start(make_certless_config(sk_a), tx_a)
        .await
        .expect("handle_a");
    let handle_b = NetworkHandle::start(make_certless_config(sk_b), tx_b)
        .await
        .expect("handle_b");

    let addr_b = handle_b.local_addr().expect("addr_b");

    // A connects to B: B rejects A because A sends no cert.
    // (The acceptor's recv_and_verify_handshake returns HandshakeFailed.)
    // The initiator sees the connection fail.
    let result = handle_a.connect(addr_b, None).await;
    assert!(
        result.is_err(),
        "cert-less connection must be rejected"
    );

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

// ─── Test 10a: to_endpoint_addr roundtrip with IPv4 ──────────────────────────

#[test]
fn to_endpoint_addr_roundtrip_ipv4() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use crate::daemon::network::addr::{ParsedNodeAddr, to_endpoint_addr};

    let sk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let pk_bytes = sk.verifying_key().to_bytes();
    let node_id = NodeId(pk_bytes);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 12345);

    let parsed = ParsedNodeAddr { node_id, socket_addr: addr, relay_url: None };
    let endpoint_addr = to_endpoint_addr(&parsed).expect("should succeed");
    let ip_addrs: Vec<_> = endpoint_addr.ip_addrs().collect();
    assert_eq!(ip_addrs.len(), 1);
    assert_eq!(*ip_addrs[0], addr);
}

// ─── Test 10b: to_endpoint_addr succeeds for arbitrary 32-byte node ids ───────
//
// NOTE: iroh 0.96 (ed25519-dalek 3.0.0-pre.1) accepts all 32-byte arrays as
// valid Ed25519 public keys without strict curve point validation.
// Therefore ToEndpointAddrError::InvalidNodeId is unreachable in practice with
// this iroh version. We document this here rather than assert an error.

#[test]
fn to_endpoint_addr_accepts_arbitrary_bytes_in_iroh_096() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use crate::daemon::network::addr::{ParsedNodeAddr, to_endpoint_addr};

    // iroh 0.96: all 32-byte arrays are accepted (lenient Ed25519 validation).
    let node_id = NodeId([0xFFu8; 32]);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9000);

    // This succeeds; ToEndpointAddrError path is a defensive guard for future stricter validation.
    let parsed = ParsedNodeAddr { node_id, socket_addr: addr, relay_url: None };
    let result = to_endpoint_addr(&parsed);
    assert!(result.is_ok(), "iroh 0.96 accepts all 32-byte node ids: {result:?}");
}

// ─── Test 10c: add_peer makes get_connection find peer ────────────────────────

#[tokio::test]
async fn add_peer_makes_get_connection_find_peer() {
    let (master_b, config_b) = make_node(20);

    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(10);
    let (tx_b, _rx_b) = tokio::sync::mpsc::channel(10);

    let handle_a = NetworkHandle::start(make_config_with_cert(21), tx_a)
        .await
        .expect("handle_a");
    let handle_b = NetworkHandle::start(config_b, tx_b)
        .await
        .expect("handle_b");

    let addr_b = handle_b.local_addr().expect("addr_b");

    let conn = handle_a
        .connect(addr_b.clone(), None)
        .await
        .expect("connect");
    // Protocol operations key on master identity (from cert), not device identity.
    let peer_master = conn.master_identity();
    assert_eq!(peer_master, master_b, "peer master identity from handshake matches B's master key");

    // Register peer by master identity so get_connection can find and verify it.
    handle_a.add_peer(peer_master, addr_b).await;

    let _arc = handle_a
        .get_connection(peer_master)
        .await
        .expect("get_connection should succeed after add_peer");

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

// ─── addr format tests ────────────────────────────────────────────────────────

use crate::daemon::network::addr::{AddrParseError, format_node_addr, parse_node_addr};

#[test]
fn format_and_parse_roundtrip_ipv4() {
    let node_id = NodeId([0xab; 32]);
    let addr: std::net::SocketAddr = "192.168.1.5:12345".parse().unwrap();
    let formatted = format_node_addr(&node_id, addr, None);
    let parsed = parse_node_addr(&formatted).unwrap();
    assert_eq!(parsed.node_id, node_id);
    assert_eq!(parsed.socket_addr, addr);
    assert!(parsed.relay_url.is_none());
}

#[test]
fn format_and_parse_roundtrip_ipv6() {
    let node_id = NodeId([0x01; 32]);
    let addr: std::net::SocketAddr = "[::1]:9000".parse().unwrap();
    let formatted = format_node_addr(&node_id, addr, None);
    let parsed = parse_node_addr(&formatted).unwrap();
    assert_eq!(parsed.node_id, node_id);
    assert_eq!(parsed.socket_addr, addr);
    assert!(parsed.relay_url.is_none());
}

#[test]
fn format_node_addr_produces_64_hex_prefix() {
    let node_id = NodeId([0u8; 32]);
    let addr: std::net::SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let formatted = format_node_addr(&node_id, addr, None);
    let hex_part = formatted.split('@').next().unwrap();
    assert_eq!(hex_part.len(), 64, "NodeId hex must be 64 chars");
    assert_eq!(hex_part, "0".repeat(64), "all-zero NodeId encodes as 64 zeros");
}

#[test]
fn parse_node_addr_rejects_missing_at() {
    let result = parse_node_addr("abcd1234noatsign");
    assert!(matches!(result, Err(AddrParseError::MissingAt)));
}

#[test]
fn parse_node_addr_rejects_short_node_id() {
    let result = parse_node_addr("abcd1234@127.0.0.1:1234");
    assert!(matches!(result, Err(AddrParseError::BadNodeIdLength(_))));
}

#[test]
fn parse_node_addr_rejects_non_hex_node_id() {
    let bad: String = "z".repeat(64) + "@127.0.0.1:1234";
    let result = parse_node_addr(&bad);
    assert!(matches!(result, Err(AddrParseError::BadNodeIdHex(_))));
}

#[test]
fn parse_node_addr_rejects_bad_socket_addr() {
    let node_id_hex = "ab".repeat(32);
    let s = format!("{node_id_hex}@not_a_valid_addr");
    let result = parse_node_addr(&s);
    assert!(matches!(result, Err(AddrParseError::BadSocketAddr(_))));
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
        device_id: None,
        revoked_device_pub_keys: vec![revoked_pub],
        addrs: vec![],
        x25519_pub: None,
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
        device_id: None,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    };

    // Round-trip through CBOR.
    let bytes = to_cbor_bytes(&record);
    let decoded: PeerRecord = from_cbor_bytes(&bytes).expect("decode");
    assert_eq!(decoded.revoked_device_pub_keys, Vec::<[u8; 32]>::new());
}

// ─── Phase 7.4: relay addr format tests ──────────────────────────────────────

#[test]
fn parse_node_addr_no_relay_backward_compat() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let hex: String = sk
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let s = format!("{hex}@192.168.1.5:12345");

    let parsed = parse_node_addr(&s).expect("should parse");
    assert_eq!(parsed.socket_addr, "192.168.1.5:12345".parse().unwrap());
    assert!(parsed.relay_url.is_none());
}

#[test]
fn parse_node_addr_with_relay_url() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
    let hex: String = sk
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let s = format!("{hex}@https://relay.iroh.network,10.0.0.1:9000");

    let parsed = parse_node_addr(&s).expect("should parse");
    assert_eq!(parsed.socket_addr, "10.0.0.1:9000".parse().unwrap());
    assert_eq!(
        parsed.relay_url.as_deref(),
        Some("https://relay.iroh.network")
    );
}

#[test]
fn format_node_addr_none_relay_matches_old_format() {
    let node_id = NodeId([0x42u8; 32]);
    let addr: std::net::SocketAddr = "127.0.0.1:7777".parse().unwrap();
    let s = format_node_addr(&node_id, addr, None);
    let parsed = parse_node_addr(&s).expect("must parse");
    assert_eq!(parsed.node_id, node_id);
    assert_eq!(parsed.socket_addr, addr);
    assert!(parsed.relay_url.is_none());
}

#[test]
fn format_and_parse_roundtrip_with_relay() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
    let node_id = NodeId(sk.verifying_key().to_bytes());
    let addr: std::net::SocketAddr = "10.1.2.3:4567".parse().unwrap();
    let relay = "https://relay.iroh.network";

    let s = format_node_addr(&node_id, addr, Some(relay));
    let parsed = parse_node_addr(&s).unwrap();

    assert_eq!(parsed.node_id, node_id);
    assert_eq!(parsed.socket_addr, addr);
    assert_eq!(parsed.relay_url.as_deref(), Some(relay));
}

#[test]
fn parse_node_addr_relay_url_no_addr_returns_error() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[4u8; 32]);
    let hex: String = sk
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let s = format!("{hex}@https://relay.iroh.network");
    let result = parse_node_addr(&s);
    assert!(
        matches!(result, Err(AddrParseError::BadSocketAddr(_))),
        "expected BadSocketAddr for relay-only addr"
    );
}

#[tokio::test]
#[ignore = "network"]
async fn network_handle_starts_with_relay_default() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[10u8; 32]);
    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    let handle = NetworkHandle::start(
        NetworkConfig {
            signing_key: sk.clone(),
            master_identity: IdentityPub(sk.verifying_key().to_bytes()),
            known_peers: Default::default(),
            device_cert: None,
            iroh_secret_key: None,
            relay_mode: RelayMode::Default,
            x25519_pub: None,
        },
        tx,
    )
    .await
    .expect("should start with RelayMode::Default");
    handle.shutdown().await;
}

// ─── Phase 7.8: Reconnection + backoff tests ──────────────────────────────────

// Test 12a: get_connection returns error during active backoff window.
//
// We inject a Backoff entry with retry_after = now + 3600 (far future).
// get_connection must return Err without attempting to connect.

#[tokio::test]
async fn get_connection_returns_error_during_backoff() {
    // pk_b is a phantom master identity used only as a pool key.
    let (pk_b, _) = make_node(30);

    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(10);

    let handle_a = NetworkHandle::start(make_config_with_cert(31), tx_a)
        .await
        .expect("handle_a");

    // Inject a far-future backoff for peer_b (no real node running).
    let future_retry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + 3600;
    handle_a.inject_backoff_for_test(pk_b, future_retry).await;

    // get_connection must fail immediately without trying to connect.
    let result = handle_a.get_connection(pk_b).await;
    assert!(
        matches!(result, Err(NetworkError::PeerNotFound(_))),
        "get_connection must return PeerNotFound during backoff"
    );

    // Peer must still be in backoff (not removed by the failed call).
    assert!(
        handle_a.is_peer_in_backoff(&pk_b).await,
        "peer must remain in backoff after rejected get_connection"
    );

    handle_a.shutdown().await;
}

// Test 12b: get_connection reconnects after backoff expires.
//
// We inject an already-expired Backoff entry (retry_after = unix epoch + 1),
// then call get_connection. It must fall through to a real connect.

#[tokio::test]
async fn get_connection_reconnects_after_backoff_expires() {
    let (master_b, config_b) = make_node(32);

    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(10);
    let (tx_b, _rx_b) = tokio::sync::mpsc::channel(10);

    let handle_a = NetworkHandle::start(make_config_with_cert(33), tx_a)
        .await
        .expect("handle_a");
    let handle_b = NetworkHandle::start(config_b, tx_b)
        .await
        .expect("handle_b");

    let addr_b = handle_b.local_addr().expect("addr_b");

    // Register peer_b by master identity so get_connection can resolve the address.
    handle_a.add_peer(master_b, addr_b).await;

    // Inject an expired backoff (retry_after = 1 second past epoch — always in the past).
    handle_a.inject_backoff_for_test(master_b, 1).await;
    assert!(
        handle_a.is_peer_in_backoff(&master_b).await,
        "sanity: injected backoff must be visible"
    );

    // get_connection must see the expired backoff and attempt a fresh connect.
    let result = handle_a.get_connection(master_b).await;
    assert!(
        result.is_ok(),
        "get_connection must succeed after backoff expires"
    );

    // Pool must now contain a Live entry (not Backoff).
    assert!(
        !handle_a.is_peer_in_backoff(&master_b).await,
        "pool must contain Live after successful reconnect"
    );

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

// Test 12c: evict_connection removes Live entry and replaces with Backoff.

#[tokio::test]
async fn evict_connection_removes_live_entry() {
    let (master_b, config_b) = make_node(34);

    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(10);
    let (tx_b, _rx_b) = tokio::sync::mpsc::channel(10);

    let handle_a = NetworkHandle::start(make_config_with_cert(35), tx_a)
        .await
        .expect("handle_a");
    let handle_b = NetworkHandle::start(config_b, tx_b)
        .await
        .expect("handle_b");

    let addr_b = handle_b.local_addr().expect("addr_b");

    // Establish a live connection and store it in the pool (keyed by master identity).
    handle_a.add_peer(master_b, addr_b).await;
    let _arc = handle_a
        .get_connection(master_b)
        .await
        .expect("initial get_connection");
    assert!(
        !handle_a.is_peer_in_backoff(&master_b).await,
        "after successful connect, entry must be Live (not Backoff)"
    );

    // Evict it.
    handle_a.evict_connection(master_b).await;

    // Pool must now contain Backoff.
    assert!(
        handle_a.is_peer_in_backoff(&master_b).await,
        "after evict_connection, entry must be Backoff"
    );

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

// Test 12d: send_to_peer records backoff on send failure.
//
// We establish a connection A→B, then close B's endpoint so its side goes
// away. Sending on the now-dead connection must fail and record Backoff.

#[tokio::test]
async fn send_to_peer_records_backoff_on_send_failure() {
    let (master_b, config_b) = make_node(36);

    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(10);
    let (tx_b, _rx_b) = tokio::sync::mpsc::channel(10);

    let handle_a = NetworkHandle::start(make_config_with_cert(37), tx_a)
        .await
        .expect("handle_a");
    let handle_b = NetworkHandle::start(config_b, tx_b)
        .await
        .expect("handle_b");

    let addr_b = handle_b.local_addr().expect("addr_b");
    handle_a.add_peer(master_b, addr_b).await;

    // Establish a live connection (populates pool).
    let _arc = handle_a
        .get_connection(master_b)
        .await
        .expect("initial get_connection");

    // Close B's endpoint so any send attempt will fail.
    handle_b.shutdown().await;

    // Wait briefly for the QUIC close to propagate.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Build a minimal message to send.
    use syncback_core::types::{SourceBlockId, Timestamp};
    let msg = syncback_core::messages::Message::PosChallenge(
        syncback_core::messages::PosChallengeMsg {
            v: 1,
            challenge_id: [0u8; 16],
            source_block_id: SourceBlockId([0u8; 32]),
            esi: 0,
            timestamp: Timestamp::now(),
        },
    );

    let result = handle_a.send_to_peer(master_b, &msg).await;
    assert!(
        result.is_err(),
        "send_to_peer must fail after peer closes endpoint"
    );

    // The dead entry must have been replaced with Backoff.
    assert!(
        handle_a.is_peer_in_backoff(&master_b).await,
        "send_to_peer must record Backoff after send failure"
    );

    handle_a.shutdown().await;
}

// ─── Test: HKDF-derived master key works in handshake ────────────────────────

#[tokio::test]
async fn two_nodes_hkdf_master_key_handshake() {
    // make_node uses derive_master_key + derive_device_key internally,
    // replicating the real daemon key hierarchy.
    let (master_pub_a, config_a) = make_node(1);
    let (master_pub_b, config_b) = make_node(2);

    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(10);
    let (tx_b, mut rx_b) = tokio::sync::mpsc::channel(10);

    let handle_a = NetworkHandle::start(config_a, tx_a)
        .await
        .expect("handle_a start");
    let handle_b = NetworkHandle::start(config_b, tx_b)
        .await
        .expect("handle_b start");

    let addr_b = handle_b.local_addr().expect("addr_b");

    let conn_a_to_b = handle_a
        .connect(addr_b, None)
        .await
        .expect("connect a -> b with HKDF master keys");

    let incoming_b = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rx_b.recv(),
    )
    .await
    .expect("timeout")
    .expect("channel closed");

    assert_eq!(conn_a_to_b.master_identity(), master_pub_b);
    assert_eq!(incoming_b.master_identity(), master_pub_a);

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

// ─── C3: cluster_peers tests ──────────────────────────────────────────────────

// cluster_peer_add_and_retrieve
//
// Given: NetworkHandle with no cluster peers.
// When: add_cluster_peer(device_id_A, addr_A) called.
// Then: cluster_peers() returns a vec containing (device_id_A, addr_A).

#[tokio::test]
async fn cluster_peer_add_and_retrieve() {
    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    let handle = NetworkHandle::start(make_config_with_cert(50), tx)
        .await
        .expect("start");

    let device_id = DeviceId([0xAAu8; 16]);
    let addr = handle.local_addr().expect("local_addr");

    handle.add_cluster_peer(device_id, addr.clone()).await;

    let peers = handle.cluster_peers().await;
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].0, device_id);

    handle.shutdown().await;
}

// cluster_peer_update_on_duplicate
//
// Given: NetworkHandle with device_id_A → addr_A.
// When: add_cluster_peer(device_id_A, addr_B) called.
// Then: cluster_peers() returns (device_id_A, addr_B) — address updated, not duplicated.

#[tokio::test]
async fn cluster_peer_update_on_duplicate() {
    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(4);
    let (tx_b, _rx_b) = tokio::sync::mpsc::channel(4);

    let handle_a = NetworkHandle::start(make_config_with_cert(51), tx_a)
        .await
        .expect("handle_a");
    let handle_b = NetworkHandle::start(make_config_with_cert(52), tx_b)
        .await
        .expect("handle_b");

    let device_id = DeviceId([0xBBu8; 16]);
    let addr_a = handle_a.local_addr().expect("addr_a");
    let addr_b = handle_b.local_addr().expect("addr_b");

    handle_a.add_cluster_peer(device_id, addr_a).await;
    // Overwrite with addr_b.
    handle_a.add_cluster_peer(device_id, addr_b.clone()).await;

    let peers = handle_a.cluster_peers().await;
    assert_eq!(peers.len(), 1, "must not duplicate on re-insert");
    assert_eq!(peers[0].0, device_id);
    // The stored addr should be addr_b (most recently inserted).
    assert_eq!(peers[0].1.id, addr_b.id, "address must be updated to addr_b");

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

// cluster_peer_remove
//
// Given: NetworkHandle with device_id_A registered.
// When: remove_cluster_peer(&device_id_A) called.
// Then: cluster_peers() returns empty vec.

#[tokio::test]
async fn cluster_peer_remove() {
    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    let handle = NetworkHandle::start(make_config_with_cert(53), tx)
        .await
        .expect("start");

    let device_id = DeviceId([0xCCu8; 16]);
    let addr = handle.local_addr().expect("local_addr");

    handle.add_cluster_peer(device_id, addr).await;
    assert_eq!(handle.cluster_peers().await.len(), 1);

    handle.remove_cluster_peer(&device_id).await;
    assert_eq!(
        handle.cluster_peers().await.len(),
        0,
        "cluster_peers must be empty after remove"
    );

    handle.shutdown().await;
}

// cluster_peer_remove_nonexistent_is_noop
//
// Given: empty cluster_peers.
// When: remove_cluster_peer(&device_id_X) called.
// Then: no panic, cluster_peers() still empty.

#[tokio::test]
async fn cluster_peer_remove_nonexistent_is_noop() {
    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    let handle = NetworkHandle::start(make_config_with_cert(54), tx)
        .await
        .expect("start");

    let device_id = DeviceId([0xDDu8; 16]);

    // No insert — just remove. Must not panic.
    handle.remove_cluster_peer(&device_id).await;
    assert_eq!(handle.cluster_peers().await.len(), 0);

    handle.shutdown().await;
}

// cluster_peers_independent_from_known_peers
//
// Given: add_peer(identity_A, addr_A) and add_cluster_peer(device_id_A, addr_A).
// When: remove_cluster_peer(&device_id_A) called.
// Then: has_known_peer(&identity_A) is still true, cluster_peers() is empty.

#[tokio::test]
async fn cluster_peers_independent_from_known_peers() {
    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    let handle = NetworkHandle::start(make_config_with_cert(55), tx)
        .await
        .expect("start");

    let identity_a = IdentityPub([0xEEu8; 32]);
    let device_id_a = DeviceId([0xEEu8; 16]);
    let addr = handle.local_addr().expect("local_addr");

    handle.add_peer(identity_a, addr.clone()).await;
    handle.add_cluster_peer(device_id_a, addr).await;

    // Remove from cluster_peers — known_peers must be unaffected.
    handle.remove_cluster_peer(&device_id_a).await;

    assert!(
        handle.has_known_peer(&identity_a).await,
        "known_peers must not be affected by remove_cluster_peer"
    );
    assert_eq!(
        handle.cluster_peers().await.len(),
        0,
        "cluster_peers must be empty after remove"
    );

    handle.shutdown().await;
}
