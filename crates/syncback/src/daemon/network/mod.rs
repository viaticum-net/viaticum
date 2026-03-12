use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use iroh::EndpointAddr;
use iroh::endpoint::{Endpoint, RecvStream, RelayMode, SendStream};
use syncback_core::messages::{DirectBody, DirectMessage, HandshakeMsg, MessageError, frame_message, parse_framed};
use syncback_core::types::{IdentityPub, NodeId};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::daemon::{NetCommand, NetEvent};

const ALPN: &[u8] = syncback_core::constants::ALPN;
const MAX_MESSAGE_SIZE: usize = syncback_core::constants::MAX_MESSAGE_SIZE as usize;

// ============================================================
// Error
// ============================================================

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("iroh endpoint bind failed: {0}")]
    BindFailed(String),

    #[error("connection failed to {peer:?}: {reason}")]
    ConnectFailed { peer: IdentityPub, reason: String },

    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("framing error: {0}")]
    Framing(#[from] MessageError),

    #[error("io error: {0}")]
    Io(String),
}

// ============================================================
// NetworkHandle
// ============================================================

/// Processor-side handle to the network task.
/// Clone-able — Processor and CLI Server each hold a clone.
#[derive(Clone)]
pub struct NetworkHandle {
    pub cmd_tx: mpsc::Sender<NetCommand>,
    pub endpoint_addr: EndpointAddr,
    pub node_id: NodeId,
}

// ============================================================
// NetworkTask
// ============================================================

/// Owns the iroh Endpoint and drives all QUIC connections.
pub struct NetworkTask {
    endpoint: Endpoint,
    node_id: NodeId,
    identity_key: SigningKey,
    identity_pub: IdentityPub,
    cmd_rx: mpsc::Receiver<NetCommand>,
    cancel: CancellationToken,
}

impl NetworkTask {
    /// Create NetworkTask and return its channel handles.
    ///
    /// `iroh_secret_key` — iroh SecretKey (derived from seed phrase via
    ///     HKDF-SHA256(seed, info="syncback-iroh-ed25519")).
    /// `identity_key` — Ed25519 SigningKey (separate from iroh key).
    ///
    /// For tests: pass `RelayMode::Disabled`.
    /// For production: pass `RelayMode::Default` (N0 relay preset).
    pub async fn new(
        iroh_secret_key: iroh::SecretKey,
        identity_key: SigningKey,
        identity_pub: IdentityPub,
        cancel: CancellationToken,
        relay_mode: RelayMode,
    ) -> Result<(NetworkTask, NetworkHandle), NetworkError> {
        // Derive NodeId from the iroh secret key before binding.
        let node_id = NodeId(*iroh_secret_key.public().as_bytes());

        let endpoint = Endpoint::empty_builder(relay_mode)
            .secret_key(iroh_secret_key)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .map_err(|e| NetworkError::BindFailed(e.to_string()))?;

        let endpoint_addr = endpoint.addr();

        let (cmd_tx, cmd_rx) = mpsc::channel::<NetCommand>(64);

        let handle = NetworkHandle {
            cmd_tx,
            endpoint_addr,
            node_id,
        };

        let task = NetworkTask {
            endpoint,
            node_id,
            identity_key,
            identity_pub,
            cmd_rx,
            cancel,
        };

        Ok((task, handle))
    }

    /// Main event loop. Drive until `cancel` is triggered.
    /// Spawned by daemon main as a dedicated tokio task.
    pub async fn run(mut self, event_tx: mpsc::Sender<NetEvent>) {
        tracing::info!(node_id = %self.node_id, "network task started");
        loop {
            tokio::select! {
                incoming = self.endpoint.accept() => {
                    match incoming {
                        Some(incoming) => {
                            let event_tx = event_tx.clone();
                            let identity_key = self.identity_key.clone();
                            let identity_pub = self.identity_pub;
                            tokio::spawn(async move {
                                handle_incoming(incoming, event_tx, identity_key, identity_pub).await;
                            });
                        }
                        None => {
                            // Endpoint closed.
                            break;
                        }
                    }
                }
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(cmd) => {
                            let endpoint = self.endpoint.clone();
                            let identity_key = self.identity_key.clone();
                            let identity_pub = self.identity_pub;
                            let event_tx = event_tx.clone();
                            tokio::spawn(async move {
                                handle_command(
                                    cmd,
                                    &endpoint,
                                    &identity_key,
                                    identity_pub,
                                    event_tx,
                                ).await;
                            });
                        }
                        None => {
                            // Command channel closed — Processor gone.
                            break;
                        }
                    }
                }
                _ = self.cancel.cancelled() => {
                    tracing::info!("network task shutting down");
                    self.endpoint.close().await;
                    return;
                }
            }
        }
        tracing::info!("network task stopped");
    }
}

// ============================================================
// Incoming connection handler
// ============================================================

async fn handle_incoming(
    incoming: iroh::endpoint::Incoming,
    event_tx: mpsc::Sender<NetEvent>,
    identity_key: SigningKey,
    identity_pub: IdentityPub,
) {
    let accepting = match incoming.accept() {
        Ok(a) => a,
        Err(e) => {
            tracing::debug!(reason = %e, "incoming accept() failed");
            return;
        }
    };
    let conn = match accepting.await {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(reason = %e, "incoming connection failed");
            return;
        }
    };

    let remote_id = conn.remote_id();

    // Accept the first bidi stream (handshake stream).
    let (mut send, mut recv) = match conn.accept_bi().await {
        Ok(streams) => streams,
        Err(e) => {
            tracing::debug!(reason = %e, addr = %remote_id, "accept_bi failed");
            return;
        }
    };

    // Read their handshake.
    let their_msg = match read_message(&mut recv).await {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(reason = %e, addr = %remote_id, "read handshake failed");
            let _ = event_tx
                .send(NetEvent::HandshakeFailed {
                    reason: e.to_string(),
                })
                .await;
            return;
        }
    };

    let their_handshake = match their_msg.body {
        DirectBody::Handshake(h) => h,
        other => {
            let reason = format!("expected Handshake, got {}", other.variant_name());
            tracing::debug!(reason = %reason, addr = %remote_id, "handshake failed");
            let _ = event_tx.send(NetEvent::HandshakeFailed { reason }).await;
            return;
        }
    };

    if let Err(e) = their_handshake.verify() {
        let reason = format!("signature invalid: {e}");
        tracing::debug!(reason = %reason, addr = %remote_id, "handshake failed");
        let _ = event_tx.send(NetEvent::HandshakeFailed { reason }).await;
        return;
    }

    let now = unix_now();
    if let Err(e) = their_handshake.check_freshness(now) {
        let reason = format!("timestamp: {e}");
        tracing::debug!(reason = %reason, addr = %remote_id, "handshake failed");
        let _ = event_tx.send(NetEvent::HandshakeFailed { reason }).await;
        return;
    }

    // TODO(Phase2): enforce peer allowlist

    let peer_identity = their_handshake.identity_pub;

    // Send our handshake back on the same stream.
    let our_hs = HandshakeMsg::new(identity_pub, now, &identity_key);
    let our_msg = DirectMessage {
        v: syncback_core::constants::PROTOCOL_VERSION,
        body: DirectBody::Handshake(our_hs),
    };
    if let Err(e) = write_message(&mut send, &our_msg).await {
        tracing::debug!(reason = %e, addr = %remote_id, "write handshake failed");
        return;
    }

    let peer_node_id = NodeId(*conn.remote_id().as_bytes());

    tracing::info!(peer_id = %peer_identity, "peer connected");
    if event_tx
        .send(NetEvent::PeerConnected {
            peer_identity,
            peer_node_id,
        })
        .await
        .is_err()
    {
        return;
    }

    // Read subsequent messages from this peer on the same stream (recv side).
    // The initiator sends application messages after the handshake on the same stream.
    loop {
        let msg = match read_message(&mut recv).await {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(reason = %e, "connection closed from {}", peer_identity);
                break;
            }
        };

        tracing::debug!(msg_type = %msg.body.variant_name(), peer_id = %peer_identity, "message received");

        if event_tx
            .send(NetEvent::MessageReceived {
                from: peer_identity,
                message: msg,
            })
            .await
            .is_err()
        {
            break;
        }
    }
}

// ============================================================
// Outgoing connection handler
// ============================================================

async fn handle_command(
    cmd: NetCommand,
    endpoint: &Endpoint,
    identity_key: &SigningKey,
    identity_pub: IdentityPub,
    event_tx: mpsc::Sender<NetEvent>,
) {
    match cmd {
        NetCommand::Connect {
            peer_addr,
            peer_identity,
            message,
        } => {
            // TODO: connection pool for frequent peers
            tracing::debug!(peer_id = %peer_identity, addr = ?peer_addr, "outgoing connect");
            connect_and_send(
                endpoint,
                peer_addr,
                peer_identity,
                message,
                identity_key,
                identity_pub,
                event_tx,
            )
            .await;
        }
        NetCommand::SendMessage {
            peer_identity,
            peer_addr,
            message,
        } => {
            // Alpha: open fresh connection per command.
            // TODO: connection pool for frequent peers
            tracing::debug!(peer_id = %peer_identity, addr = ?peer_addr, "outgoing connect (send)");
            connect_and_send(
                endpoint,
                peer_addr,
                peer_identity,
                message,
                identity_key,
                identity_pub,
                event_tx,
            )
            .await;
        }
        NetCommand::PublishBoard { .. } | NetCommand::UploadShard { .. } => {
            // TODO Phase 2: iroh-docs board publish and blob upload.
            tracing::debug!("network: board/shard command not yet implemented");
        }
        NetCommand::SendPosChallenge { holder, shard_id, .. } => {
            // TODO Phase 2: send PoS challenge via board.
            tracing::debug!(holder = %holder, shard = %shard_id, "network: SendPosChallenge not yet implemented");
        }
        NetCommand::SendDirect { peer, .. } => {
            // TODO Phase 2: send direct message to peer.
            tracing::debug!(peer = %peer, "network: SendDirect not yet implemented");
        }
        NetCommand::ConnectAddr { node_addr } => {
            // TODO Phase 2: connect to peer by address string.
            tracing::debug!(addr = %node_addr, "network: ConnectAddr not yet implemented");
        }
        NetCommand::DownloadShard {
            shard_id,
            holder,
            reply,
        } => {
            // TODO Phase 3: connect to holder and download blob via iroh-blobs.
            // For now, reply with an error so the repair engine defers to next cycle.
            tracing::debug!(
                shard = %shard_id,
                holder = %holder,
                "network: DownloadShard not yet implemented"
            );
            let _ = reply.send(Err("DownloadShard not yet implemented".to_string()));
        }
    }
}

async fn connect_and_send(
    endpoint: &Endpoint,
    peer_addr: EndpointAddr,
    peer_identity: IdentityPub,
    message: DirectMessage,
    identity_key: &SigningKey,
    identity_pub: IdentityPub,
    event_tx: mpsc::Sender<NetEvent>,
) {
    let conn = match endpoint.connect(peer_addr, ALPN).await {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(peer_id = %peer_identity, reason = %e, "connection failed");
            return;
        }
    };

    // Open a bidi stream: initiator sends handshake, then application message.
    // Responder sends its handshake back on this same stream.
    let (mut send, mut recv) = match conn.open_bi().await {
        Ok(streams) => streams,
        Err(e) => {
            tracing::debug!(peer_id = %peer_identity, reason = %e, "open_bi failed");
            return;
        }
    };

    // Step 1: Send our handshake.
    let now = unix_now();
    let our_hs = HandshakeMsg::new(identity_pub, now, identity_key);
    let our_msg = DirectMessage {
        v: syncback_core::constants::PROTOCOL_VERSION,
        body: DirectBody::Handshake(our_hs),
    };
    if let Err(e) = write_message(&mut send, &our_msg).await {
        tracing::debug!(peer_id = %peer_identity, reason = %e, "write handshake failed");
        return;
    }

    // Step 2: Read their handshake.
    let their_msg = match read_message(&mut recv).await {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(peer_id = %peer_identity, reason = %e, "read handshake failed");
            return;
        }
    };

    let their_handshake = match their_msg.body {
        DirectBody::Handshake(h) => h,
        other => {
            tracing::debug!(
                peer_id = %peer_identity,
                got = %other.variant_name(),
                "handshake failed: unexpected message"
            );
            return;
        }
    };

    if let Err(e) = their_handshake.verify() {
        tracing::debug!(peer_id = %peer_identity, reason = %e, "handshake sig invalid");
        return;
    }

    let now2 = unix_now();
    if let Err(e) = their_handshake.check_freshness(now2) {
        tracing::debug!(peer_id = %peer_identity, reason = %e, "handshake stale");
        return;
    }

    // TODO(Phase2): enforce peer allowlist

    let peer_node_id = NodeId(*conn.remote_id().as_bytes());

    tracing::info!(peer_id = %peer_identity, "peer connected");
    if event_tx
        .send(NetEvent::PeerConnected {
            peer_identity,
            peer_node_id,
        })
        .await
        .is_err()
    {
        return;
    }

    // Step 3: Send the application-level message on the same stream.
    tracing::debug!(
        msg_type = %message.body.variant_name(),
        peer_id = %peer_identity,
        "sending message"
    );
    if let Err(e) = write_message(&mut send, &message).await {
        tracing::debug!(peer_id = %peer_identity, reason = %e, "write message failed");
        return;
    }

    // Finish the send side so the receiver knows no more data is coming on this stream.
    if let Err(e) = send.finish() {
        tracing::debug!(peer_id = %peer_identity, reason = %e, "finish send stream failed");
        return;
    }
    // Wait for the peer to finish their send side (stream 0 B→A direction).
    // This ensures QUIC has time to deliver our data before the conn closes.
    // If B closes gracefully we get Ok(()), if conn resets we get Err.
    let _ = recv.read_to_end(MAX_MESSAGE_SIZE).await;
}

// ============================================================
// Framing helpers
// ============================================================

/// Write one framed message to a SendStream.
/// [u32 BE length][CBOR bytes] — max 64 KB per message.
pub(crate) async fn write_message(
    send: &mut SendStream,
    msg: &DirectMessage,
) -> Result<(), NetworkError> {
    let framed = frame_message(msg)?;
    tracing::trace!(len = framed.len(), "raw frame");
    send.write_all(&framed)
        .await
        .map_err(|e| NetworkError::Io(e.to_string()))
}

/// Read one framed message from a RecvStream.
/// Reads exactly (4 + length) bytes. Returns error if > 64 KB.
pub(crate) async fn read_message(recv: &mut RecvStream) -> Result<DirectMessage, NetworkError> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| NetworkError::Io(e.to_string()))?;

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(NetworkError::Framing(MessageError::TooLarge { size: len }));
    }

    // Reconstruct the full framed buffer for parse_framed.
    let mut buf = Vec::with_capacity(4 + len);
    buf.extend_from_slice(&len_buf);
    buf.resize(4 + len, 0);
    recv.read_exact(&mut buf[4..])
        .await
        .map_err(|e| NetworkError::Io(e.to_string()))?;

    tracing::trace!(len = len, "raw frame");

    let (msg, _consumed) = parse_framed(&buf)?;
    Ok(msg)
}

// ============================================================
// Helpers
// ============================================================

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs()
}

// ============================================================
// DirectBody variant name helper (for logging)
// ============================================================

trait VariantName {
    fn variant_name(&self) -> &'static str;
}

impl VariantName for DirectBody {
    fn variant_name(&self) -> &'static str {
        match self {
            DirectBody::Handshake(_) => "Handshake",
            DirectBody::RestoreRequest(_) => "RestoreRequest",
            DirectBody::RestoreDenied(_) => "RestoreDenied",
            DirectBody::BlobReady(_) => "BlobReady",
        }
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests;
