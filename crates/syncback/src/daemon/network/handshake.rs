// Handshake helpers for SyncBack connection authentication.
//
// The SyncBack handshake runs on top of the iroh QUIC+TLS layer and provides
// protocol-level identity authentication (IdentityPub, Ed25519 signing key),
// distinct from iroh's transport identity (EndpointId).
//
// Protocol:
//   Initiator (A) sends HandshakeMsg first, then reads B's.
//   Acceptor  (B) reads A's HandshakeMsg first, then sends its own.
//
// This is separate from the iroh TLS handshake — iroh TLS uses its own keypair
// that has nothing to do with IdentityPub.

use ed25519_dalek::SigningKey;
use iroh::endpoint::Connection as IrohConnection;
use iroh::Endpoint;
use syncback_core::cluster::DeviceCertificate;
use syncback_core::constants::MAX_MESSAGE_SIZE;
use syncback_core::messages::{
    Message, MessageError, build_handshake, extract_cluster_identity, frame_message, from_cbor,
    verify_handshake,
};
use syncback_core::types::{IdentityPub, Timestamp};
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info, warn};

use crate::daemon::network::connection::{Connection, read_exact_from_stream};
use crate::daemon::network::NetworkError;

/// Perform the initiator (A) side of the SyncBack handshake.
///
/// Opens a bidirectional stream, sends our HandshakeMsg first, reads peer's,
/// verifies it, and returns an authenticated [`Connection`].
pub(super) async fn handshake_initiator(
    iroh_conn: IrohConnection,
    signing_key: &SigningKey,
    our_identity: IdentityPub,
    expected_identity: Option<IdentityPub>,
    device_cert: Option<DeviceCertificate>,
) -> Result<Connection, NetworkError> {
    let (mut send, mut recv) = iroh_conn
        .open_bi()
        .await
        .map_err(|e| NetworkError::Iroh(anyhow::anyhow!("{e}")))?;

    // Initiator sends handshake first.
    send_handshake_on_stream(&mut send, signing_key, our_identity, device_cert).await?;

    // Read peer's handshake.
    let (peer_identity, peer_master_identity) =
        recv_and_verify_handshake(&mut recv, expected_identity).await?;

    Ok(Connection {
        peer_identity,
        peer_master_identity,
        inner: iroh_conn,
        send,
        recv,
    })
}

/// Perform the acceptor (B) side of the SyncBack handshake.
///
/// Accepts a bidirectional stream, reads initiator's HandshakeMsg first,
/// verifies it, sends our HandshakeMsg, and returns an authenticated
/// [`Connection`].
pub(super) async fn handshake_acceptor(
    iroh_conn: IrohConnection,
    signing_key: &SigningKey,
    our_identity: IdentityPub,
    device_cert: Option<DeviceCertificate>,
) -> Result<Connection, NetworkError> {
    let (mut send, mut recv) = iroh_conn
        .accept_bi()
        .await
        .map_err(|e| NetworkError::Iroh(anyhow::anyhow!("{e}")))?;

    // Acceptor reads initiator's handshake first.
    let (peer_identity, peer_master_identity) =
        recv_and_verify_handshake(&mut recv, None).await?;

    // Then sends its own.
    send_handshake_on_stream(&mut send, signing_key, our_identity, device_cert).await?;

    Ok(Connection {
        peer_identity,
        peer_master_identity,
        inner: iroh_conn,
        send,
        recv,
    })
}

/// Write a HandshakeMsg to a SendStream (before [`Connection`] exists).
async fn send_handshake_on_stream(
    send: &mut iroh::endpoint::SendStream,
    signing_key: &SigningKey,
    our_identity: IdentityPub,
    device_cert: Option<DeviceCertificate>,
) -> Result<(), NetworkError> {
    let now = Timestamp::now();
    let hs = build_handshake(our_identity, now, signing_key, device_cert);
    let framed = frame_message(&Message::Handshake(hs)).map_err(NetworkError::Message)?;
    send.write_all(&framed)
        .await
        .map_err(|e| NetworkError::Io(std::io::Error::other(e.to_string())))?;
    send.flush()
        .await
        .map_err(|e| NetworkError::Io(std::io::Error::other(e.to_string())))?;
    Ok(())
}

/// Read and verify a single HandshakeMsg from a RecvStream.
///
/// Returns `(peer_identity, peer_master_identity)` on success.
/// `peer_master_identity` is `Some(master_pub)` if the peer presented a valid
/// device certificate, `None` for single-device nodes.
async fn recv_and_verify_handshake(
    recv: &mut iroh::endpoint::RecvStream,
    expected_identity: Option<IdentityPub>,
) -> Result<(IdentityPub, Option<IdentityPub>), NetworkError> {
    let msg = recv_framed_message(recv).await?;

    match msg {
        Message::Handshake(hs) => {
            verify_handshake(&hs, Timestamp::now())
                .map_err(|e| NetworkError::HandshakeFailed(e.to_string()))?;

            if let Some(expected) = expected_identity {
                if hs.identity_pub != expected {
                    return Err(NetworkError::IdentityMismatch {
                        expected,
                        got: hs.identity_pub,
                    });
                }
            }

            let peer_master_identity = extract_cluster_identity(&hs)
                .map_err(|e| NetworkError::HandshakeFailed(e.to_string()))?;

            Ok((hs.identity_pub, peer_master_identity))
        }
        other => Err(NetworkError::HandshakeFailed(format!(
            "expected Handshake variant, got {:?}",
            std::mem::discriminant(&other)
        ))),
    }
}

/// Read a single framed message from a RecvStream.
///
/// Used during handshake before a [`Connection`] object exists.
pub(super) async fn recv_framed_message(
    recv: &mut iroh::endpoint::RecvStream,
) -> Result<Message, NetworkError> {
    let mut len_buf = [0u8; 4];
    read_exact_from_stream(recv, &mut len_buf).await?;

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE as usize {
        return Err(NetworkError::Message(MessageError::TooLarge { size: len }));
    }

    let mut payload = vec![0u8; len];
    read_exact_from_stream(recv, &mut payload).await?;

    let msg: Message = from_cbor(&payload).map_err(NetworkError::Message)?;
    Ok(msg)
}

// ─── Accept loop ──────────────────────────────────────────────────────────────

/// Background task: accept incoming iroh connections, perform SyncBack
/// handshake, and forward authenticated connections to the caller.
///
/// Errors in individual connections are logged and do not stop the loop.
pub(super) async fn accept_loop(
    endpoint: Endpoint,
    signing_key: SigningKey,
    our_identity: IdentityPub,
    device_cert: Option<DeviceCertificate>,
    incoming_tx: tokio::sync::mpsc::Sender<Connection>,
) {
    info!("accept loop started");
    loop {
        let incoming = match endpoint.accept().await {
            Some(incoming) => incoming,
            None => {
                info!("accept loop: endpoint closed");
                break;
            }
        };

        let signing_key = signing_key.clone();
        let incoming_tx = incoming_tx.clone();
        let device_cert = device_cert.clone();

        tokio::spawn(async move {
            // Upgrade Incoming -> IrohConnection (QUIC + TLS).
            let iroh_conn = match incoming.await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!("incoming connection failed QUIC handshake: {e}");
                    return;
                }
            };

            // SyncBack handshake (B side).
            let conn =
                match handshake_acceptor(iroh_conn, &signing_key, our_identity, device_cert).await
                {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("SyncBack handshake failed on accept: {e}");
                        return;
                    }
                };

            debug!(peer = %conn.peer_identity, "accepted authenticated connection");

            if incoming_tx.send(conn).await.is_err() {
                error!("incoming_tx closed — dropping accepted connection");
            }
        });
    }
    info!("accept loop exited");
}
