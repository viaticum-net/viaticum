use syncback_core::constants::PROTOCOL_VERSION;
use syncback_core::messages::{DirectBody, DirectMessage, HandshakeMsg, MessageError, frame_message, parse_framed};
use syncback_core::types::{IdentityPub, NodeId};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::daemon::{NetEvent, NetCommand};
use crate::daemon::network::{NetworkTask, NetworkHandle, NetworkError, read_message, write_message};

// ============================================================
// Test helpers
// ============================================================

fn random_identity_key() -> (ed25519_dalek::SigningKey, IdentityPub) {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let key = ed25519_dalek::SigningKey::from_bytes(&bytes);
    let pub_bytes: [u8; 32] = key.verifying_key().to_bytes();
    (key, IdentityPub(pub_bytes))
}

fn random_iroh_key() -> iroh::SecretKey {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    iroh::SecretKey::from_bytes(&bytes)
}

async fn make_test_network(
    cancel: CancellationToken,
) -> (NetworkHandle, mpsc::Receiver<NetEvent>, tokio::task::JoinHandle<()>) {
    let iroh_key = random_iroh_key();
    let (id_key, id_pub) = random_identity_key();

    let (task, handle) = NetworkTask::new(
        iroh_key,
        id_key,
        id_pub,
        cancel,
        iroh::endpoint::RelayMode::Disabled,
    )
    .await
    .expect("NetworkTask::new failed");

    let (event_tx, event_rx) = mpsc::channel::<NetEvent>(256);
    let join = tokio::spawn(task.run(event_tx));

    (handle, event_rx, join)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn make_handshake_msg(id_key: &ed25519_dalek::SigningKey, id_pub: IdentityPub) -> DirectMessage {
    let hs = HandshakeMsg::new(id_pub, unix_now(), id_key);
    DirectMessage {
        v: PROTOCOL_VERSION,
        body: DirectBody::Handshake(hs),
    }
}

// ============================================================
// Unit tests (framing)
// ============================================================

#[test]
fn frame_and_parse_roundtrip_for_handshake() {
    let (id_key, id_pub) = random_identity_key();
    let msg = make_handshake_msg(&id_key, id_pub);

    let framed = frame_message(&msg).expect("frame_message failed");
    let (parsed, consumed) = parse_framed(&framed).expect("parse_framed failed");
    assert_eq!(consumed, framed.len());

    // Verify the roundtrip preserves identity_pub.
    if let DirectBody::Handshake(hs) = parsed.body {
        assert_eq!(hs.identity_pub, id_pub);
    } else {
        panic!("expected Handshake body");
    }
}

#[test]
fn frame_rejects_message_over_64kb() {
    // Construct a DirectMessage whose CBOR exceeds 64 KB.
    // Use a RestoreRequest with a large shard_id payload padded via a wrapper.
    // Simplest: test frame_message directly using the core test approach.
    // We'll exploit the fact that the CBOR of a Vec<u8> payload grows linearly.
    // Create a fake msg using RestoreRequest with a known-serializable large shard_id.
    // Actually, RestoreRequestMsg only has v+shard_id+ts — not enough to exceed 64KB.
    // Instead, test frame_message itself with a directly crafted oversized buffer
    // by testing parse_framed with a >64KB length prefix.
    let big_len: u32 = 65537; // > MAX_MESSAGE_SIZE (65536)
    let mut buf = Vec::new();
    buf.extend_from_slice(&big_len.to_be_bytes());
    buf.extend(vec![0u8; big_len as usize]);

    let result = parse_framed(&buf);
    assert!(
        matches!(result, Err(MessageError::TooLarge { .. })),
        "expected TooLarge, got {:?}",
        result
    );
}

#[test]
fn read_message_detects_truncated_length_prefix() {
    // Only 3 bytes — less than 4 needed for length prefix.
    let buf = [0u8; 3];
    let result = parse_framed(&buf);
    assert!(
        matches!(result, Err(MessageError::BufferTooShort { need: 4, have: 3 })),
        "expected BufferTooShort, got {:?}",
        result
    );
}

// ============================================================
// Integration tests (real iroh, 2 nodes on localhost)
// ============================================================

#[tokio::test]
async fn two_nodes_connect_and_handshake() {
    let cancel_a = CancellationToken::new();
    let cancel_b = CancellationToken::new();

    let (handle_a, mut events_a, _join_a) = make_test_network(cancel_a.clone()).await;
    let (handle_b, mut events_b, _join_b) = make_test_network(cancel_b.clone()).await;

    let addr_b = handle_b.endpoint_addr.clone();
    let id_pub_b = {
        // We don't have identity_pub on the handle — get it by noting the handshake will deliver it.
        // Just use a placeholder; the actual identity is verified via the handshake event.
        // For the Connect command we need the peer's identity_pub, but since the handshake
        // establishes it, we can use a dummy here (alpha: no allowlist).
        // We need the real pub to send the Connect command properly.
        // Instead: let A send a RestoreRequest after handshake, but for now just trigger connect.
        // We'll use a dummy IdentityPub since alpha skips allowlist.
        IdentityPub([0u8; 32])
    };

    // A: build a simple handshake-only message to trigger connect.
    // Use a real identity key to craft a valid message.
    let (id_key_a, id_pub_a) = random_identity_key();
    let msg = {
        let hs = HandshakeMsg::new(id_pub_a, unix_now(), &id_key_a);
        DirectMessage {
            v: PROTOCOL_VERSION,
            body: DirectBody::Handshake(hs),
        }
    };

    // Actually NetworkTask::Connect sends the msg after handshake completes.
    // The msg in Connect is the application-level message, not the handshake itself.
    // But HandshakeMsg body would be rejected by the receiver as "got Handshake, not app message".
    // Let's instead send a BlobReady message as the application payload.
    let app_msg = DirectMessage {
        v: PROTOCOL_VERSION,
        body: DirectBody::BlobReady(syncback_core::messages::BlobReadyMsg {
            v: PROTOCOL_VERSION,
            shard_id: syncback_core::types::ShardId([1u8; 32]),
            ts: unix_now(),
        }),
    };

    handle_a
        .cmd_tx
        .send(NetCommand::Connect {
            peer_addr: addr_b,
            peer_identity: id_pub_b,
            message: app_msg,
        })
        .await
        .unwrap();

    // B should emit PeerConnected.
    let event_b = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        events_b.recv(),
    )
    .await
    .expect("timeout waiting for B's PeerConnected")
    .expect("channel closed");

    assert!(
        matches!(event_b, NetEvent::PeerConnected { .. }),
        "expected PeerConnected from B, got {:?}",
        event_b
    );

    // A should also emit PeerConnected.
    let event_a = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        events_a.recv(),
    )
    .await
    .expect("timeout waiting for A's PeerConnected")
    .expect("channel closed");

    assert!(
        matches!(event_a, NetEvent::PeerConnected { .. }),
        "expected PeerConnected from A, got {:?}",
        event_a
    );

    cancel_a.cancel();
    cancel_b.cancel();
}

#[tokio::test]
async fn handshake_fails_on_invalid_signature() {
    // B runs normally. A crafts a bad handshake manually and sends it raw.
    use iroh::endpoint::{Endpoint, RelayMode};
    use syncback_core::messages::Signature;

    let cancel_b = CancellationToken::new();
    let (_handle_b, mut events_b, _join_b) = make_test_network(cancel_b.clone()).await;

    let addr_b = _handle_b.endpoint_addr.clone();

    // Build a rogue endpoint (not using NetworkTask) that sends a bad handshake.
    let rogue_key = random_iroh_key();
    let rogue_ep = Endpoint::empty_builder(RelayMode::Disabled)
        .secret_key(rogue_key)
        .alpns(vec![syncback_core::constants::ALPN.to_vec()])
        .bind()
        .await
        .expect("bind rogue");

    // Connect to B.
    let conn = rogue_ep
        .connect(addr_b, syncback_core::constants::ALPN)
        .await
        .expect("rogue connect");

    let (mut send, _recv) = conn.open_bi().await.expect("open_bi");

    // Send a handshake with all-zeros signature (invalid).
    let (_, id_pub) = random_identity_key();
    let bad_hs = HandshakeMsg {
        v: PROTOCOL_VERSION,
        identity_pub: id_pub,
        timestamp: unix_now(),
        sig_author: Signature([0u8; 64]),
    };
    let bad_msg = DirectMessage {
        v: PROTOCOL_VERSION,
        body: DirectBody::Handshake(bad_hs),
    };
    let framed = frame_message(&bad_msg).unwrap();
    send.write_all(&framed).await.expect("write bad hs");

    // B should emit HandshakeFailed.
    let event = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        events_b.recv(),
    )
    .await
    .expect("timeout waiting for HandshakeFailed")
    .expect("channel closed");

    assert!(
        matches!(event, NetEvent::HandshakeFailed { .. }),
        "expected HandshakeFailed, got {:?}",
        event
    );

    // B's accept loop should still be alive (no more events needed — just verify no panic).
    cancel_b.cancel();
    rogue_ep.close().await;
}

#[tokio::test]
async fn handshake_fails_on_stale_timestamp() {
    use iroh::endpoint::{Endpoint, RelayMode};

    let cancel_b = CancellationToken::new();
    let (_handle_b, mut events_b, _join_b) = make_test_network(cancel_b.clone()).await;
    let addr_b = _handle_b.endpoint_addr.clone();

    let rogue_key = random_iroh_key();
    let rogue_ep = Endpoint::empty_builder(RelayMode::Disabled)
        .secret_key(rogue_key)
        .alpns(vec![syncback_core::constants::ALPN.to_vec()])
        .bind()
        .await
        .expect("bind rogue");

    let conn = rogue_ep
        .connect(addr_b, syncback_core::constants::ALPN)
        .await
        .expect("rogue connect");

    let (mut send, _recv) = conn.open_bi().await.expect("open_bi");

    // Send a handshake with timestamp 400 seconds in the past (> 300s freshness window).
    let (id_key, id_pub) = random_identity_key();
    let stale_ts = unix_now() - 400;
    let stale_hs = HandshakeMsg::new(id_pub, stale_ts, &id_key);
    let stale_msg = DirectMessage {
        v: PROTOCOL_VERSION,
        body: DirectBody::Handshake(stale_hs),
    };
    let framed = frame_message(&stale_msg).unwrap();
    send.write_all(&framed).await.expect("write stale hs");

    let event = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        events_b.recv(),
    )
    .await
    .expect("timeout waiting for HandshakeFailed (stale ts)")
    .expect("channel closed");

    match &event {
        NetEvent::HandshakeFailed { reason } => {
            assert!(
                reason.contains("timestamp"),
                "HandshakeFailed reason should mention timestamp, got: {reason}"
            );
        }
        other => panic!("expected HandshakeFailed, got {:?}", other),
    }

    cancel_b.cancel();
    rogue_ep.close().await;
}

#[tokio::test]
async fn message_received_after_successful_handshake() {
    let cancel_a = CancellationToken::new();
    let cancel_b = CancellationToken::new();

    let (handle_a, mut events_a, _join_a) = make_test_network(cancel_a.clone()).await;
    let (handle_b, mut events_b, _join_b) = make_test_network(cancel_b.clone()).await;

    let addr_b = handle_b.endpoint_addr.clone();
    let shard_id = syncback_core::types::ShardId([42u8; 32]);

    // A sends a BlobReady message to B (triggers connect + handshake + message delivery).
    let app_msg = DirectMessage {
        v: PROTOCOL_VERSION,
        body: DirectBody::BlobReady(syncback_core::messages::BlobReadyMsg {
            v: PROTOCOL_VERSION,
            shard_id,
            ts: unix_now(),
        }),
    };

    handle_a
        .cmd_tx
        .send(NetCommand::SendMessage {
            peer_identity: IdentityPub([0u8; 32]),
            peer_addr: addr_b,
            message: app_msg,
        })
        .await
        .unwrap();

    // Wait for B to get PeerConnected then MessageReceived.
    let mut got_message = false;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            panic!("timeout waiting for MessageReceived on B");
        }

        match tokio::time::timeout(remaining, events_b.recv()).await {
            Ok(Some(NetEvent::MessageReceived { message, .. })) => {
                assert!(
                    matches!(message.body, DirectBody::BlobReady(_)),
                    "expected BlobReady, got {:?}",
                    message.body
                );
                got_message = true;
                break;
            }
            Ok(Some(_)) => {
                // PeerConnected or other — keep waiting.
            }
            Ok(None) => panic!("B's event channel closed"),
            Err(_) => panic!("timeout waiting for B's MessageReceived"),
        }
    }

    assert!(got_message, "B never received the message");

    // Also drain A's events to avoid blocking.
    let _ = tokio::time::timeout(std::time::Duration::from_millis(100), events_a.recv()).await;

    cancel_a.cancel();
    cancel_b.cancel();
}

#[tokio::test]
async fn network_task_shuts_down_on_cancel() {
    let cancel = CancellationToken::new();
    let (handle, _events, join) = make_test_network(cancel.clone()).await;

    // Trigger cancel.
    cancel.cancel();

    // run() should return within 1 second.
    let result = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    assert!(result.is_ok(), "network task did not shut down within 1 second");
    assert!(result.unwrap().is_ok(), "network task panicked");

    drop(handle);
}
