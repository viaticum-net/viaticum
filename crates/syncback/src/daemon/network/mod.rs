// Network module: iroh QUIC transport layer for SyncBack β.
//
// Provides:
//   - NetworkHandle: one endpoint per daemon instance
//   - Outbound connections with SyncBack handshake authentication
//   - Inbound accept loop (background task)
//   - Framed CBOR message send/receive (via Connection)
//   - Connection pool (reuse per peer IdentityPub)
//   - send_symbols high-level helper
//
// iroh is used as pure transport. No iroh-blobs, no iroh-docs.
// All business logic lives in BackupCoordinator, RestoreCoordinator, etc.
//
// Identity separation:
//   IdentityPub = SyncBack protocol identity (ed25519, from signing key)
//   EndpointId  = iroh transport identity (separate ed25519 keypair)
// Both are 32-byte Ed25519 pubkeys from different key hierarchies.
// The mapping is published via peer_announce messages.

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey as IrohSecretKey};
use syncback_core::constants::ALPN;
use syncback_core::messages::{Message, SymbolTransferMsg};
use syncback_core::types::{IdentityPub, NodeId};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info};

pub mod addr;
pub mod connection;
mod handshake;

use crate::daemon::network::connection::Connection;
use crate::daemon::network::handshake::{accept_loop, handshake_initiator};

#[cfg(test)]
mod tests;

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors from network layer operations.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    /// iroh or QUIC transport error.
    #[error("iroh error: {0}")]
    Iroh(#[from] anyhow::Error),

    /// SyncBack handshake failed (bad signature or stale timestamp).
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    /// Message framing / CBOR serialization error.
    #[error("message error: {0}")]
    Message(#[from] syncback_core::messages::MessageError),

    /// Peer identity not in known_peers directory.
    #[error("peer not found in directory: {0}")]
    PeerNotFound(IdentityPub),

    /// Remote closed the connection cleanly.
    #[error("connection closed")]
    ConnectionClosed,

    /// IO error on the QUIC stream.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Peer's handshake identity differs from expected.
    #[error("peer identity mismatch: expected {expected}, got {got}")]
    IdentityMismatch {
        expected: IdentityPub,
        got: IdentityPub,
    },
}

// ─── Config ───────────────────────────────────────────────────────────────────

/// Configuration for the network layer.
///
/// `signing_key` is the SyncBack protocol identity key.
/// `known_peers` maps peer IdentityPub to their iroh EndpointAddr.
#[derive(Clone)]
pub struct NetworkConfig {
    /// Ed25519 signing key — identity_pub = signing_key.verifying_key().
    pub signing_key: SigningKey,
    /// Peer directory populated by the caller (from DB PeerRecords).
    pub known_peers: HashMap<IdentityPub, EndpointAddr>,
    /// Optional device certificate for cluster nodes.
    /// When present, included in the SyncBack handshake so partners can
    /// identify which cluster master identity this node belongs to.
    pub device_cert: Option<syncback_core::cluster::DeviceCertificate>,
    /// When Some, the iroh endpoint uses this key (stable NodeId).
    /// When None, iroh generates a random key (ephemeral NodeId — tests only).
    pub iroh_secret_key: Option<IrohSecretKey>,
    /// iroh relay mode. Use RelayMode::Default to enable NAT traversal.
    /// Use RelayMode::Disabled for direct-only setups (tests, LAN).
    pub relay_mode: RelayMode,
}

// ─── Connection pool ──────────────────────────────────────────────────────────

/// Internal live-connection entry in the pool.
enum ConnectionState {
    Live(Arc<Mutex<Connection>>),
}

// ─── NetworkHandle ────────────────────────────────────────────────────────────

/// Handle to the running network layer for one daemon instance.
///
/// Owns the iroh [`Endpoint`] and manages the connection pool.
/// Constructed via [`NetworkHandle::start`].
pub struct NetworkHandle {
    /// iroh endpoint (transport identity).
    endpoint: Endpoint,
    /// Our SyncBack protocol identity.
    pub identity_pub: IdentityPub,
    /// Our iroh transport identity as SyncBack NodeId bytes.
    pub node_id: NodeId,
    /// Signing key for building handshake messages.
    signing_key: SigningKey,
    /// Device certificate for cluster nodes. Passed in handshake if present.
    device_cert: Option<syncback_core::cluster::DeviceCertificate>,
    /// Known peers directory (for `get_connection` by IdentityPub).
    known_peers: Arc<RwLock<HashMap<IdentityPub, EndpointAddr>>>,
    /// Live authenticated connections keyed by peer IdentityPub.
    connections: Arc<Mutex<HashMap<IdentityPub, ConnectionState>>>,
}

impl NetworkHandle {
    /// Start the network layer.
    ///
    /// Creates an iroh endpoint with ALPN "syncback/1". Spawns a background
    /// accept loop that authenticates incoming connections and forwards them
    /// to `incoming_tx`.
    pub async fn start(
        config: NetworkConfig,
        incoming_tx: tokio::sync::mpsc::Sender<Connection>,
    ) -> Result<Self, NetworkError> {
        let identity_pub = IdentityPub(config.signing_key.verifying_key().to_bytes());

        let mut builder = Endpoint::builder()
            .alpns(vec![ALPN.to_vec()])
            .relay_mode(config.relay_mode.clone());

        if let Some(key) = config.iroh_secret_key {
            builder = builder.secret_key(key);
        }

        let endpoint = builder
            .bind()
            .await
            .map_err(|e| NetworkError::Iroh(anyhow::anyhow!("{e}")))?;

        let iroh_id = endpoint.id();
        let node_id = NodeId(*iroh_id.as_bytes());

        info!(
            identity_pub = %identity_pub,
            node_id = %node_id,
            "network handle started"
        );

        let connections: Arc<Mutex<HashMap<IdentityPub, ConnectionState>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Spawn accept loop.
        let accept_endpoint = endpoint.clone();
        let signing_key_clone = config.signing_key.clone();
        let identity_pub_clone = identity_pub;
        let device_cert_clone = config.device_cert.clone();
        tokio::spawn(async move {
            accept_loop(
                accept_endpoint,
                signing_key_clone,
                identity_pub_clone,
                device_cert_clone,
                incoming_tx,
            )
            .await;
        });

        Ok(Self {
            endpoint,
            identity_pub,
            node_id,
            signing_key: config.signing_key,
            device_cert: config.device_cert,
            known_peers: Arc::new(RwLock::new(config.known_peers)),
            connections,
        })
    }

    /// Return the iroh [`EndpointAddr`] for this endpoint (for peer_announce).
    pub fn local_addr(&self) -> Result<EndpointAddr, NetworkError> {
        Ok(self.endpoint.addr())
    }

    /// Connect to a peer by iroh [`EndpointAddr`].
    ///
    /// Performs the SyncBack handshake (A-side):
    /// 1. iroh connect (QUIC + TLS, ALPN "syncback/1")
    /// 2. Open bidirectional stream
    /// 3. Send our HandshakeMsg
    /// 4. Receive peer's HandshakeMsg
    /// 5. Verify peer's handshake (sig + freshness)
    /// 6. If `expected_identity` is `Some`, check peer identity matches
    ///
    /// Returns an authenticated [`Connection`] ready for protocol messages.
    pub async fn connect(
        &self,
        peer_addr: EndpointAddr,
        expected_identity: Option<IdentityPub>,
    ) -> Result<Connection, NetworkError> {
        debug!(peer = ?peer_addr.id, "connecting");

        let iroh_conn = self
            .endpoint
            .connect(peer_addr, ALPN)
            .await
            .map_err(|e| NetworkError::Iroh(anyhow::anyhow!("{e}")))?;

        let conn = handshake_initiator(
            iroh_conn,
            &self.signing_key,
            self.identity_pub,
            expected_identity,
            self.device_cert.clone(),
        )
        .await?;

        info!(peer = %conn.peer_identity, "connection established");
        Ok(conn)
    }

    /// Get or create a connection to a peer by their SyncBack `IdentityPub`.
    ///
    /// Checks the pool first; creates a new connection if none exists.
    /// Looks up the peer's `EndpointAddr` in `known_peers` if needed.
    pub async fn get_connection(
        &self,
        peer_identity: IdentityPub,
    ) -> Result<Arc<Mutex<Connection>>, NetworkError> {
        // Check pool first.
        {
            let pool = self.connections.lock().await;
            if let Some(ConnectionState::Live(arc)) = pool.get(&peer_identity) {
                return Ok(arc.clone());
            }
        }

        // Resolve address. Drop the guard before the connect await.
        let peer_addr = {
            let peers = self.known_peers.read().await;
            peers.get(&peer_identity).cloned()
        }
        .ok_or(NetworkError::PeerNotFound(peer_identity))?;

        // Connect and authenticate.
        let conn = self.connect(peer_addr, Some(peer_identity)).await?;
        let arc = Arc::new(Mutex::new(conn));

        // Store in pool.
        self.connections
            .lock()
            .await
            .insert(peer_identity, ConnectionState::Live(arc.clone()));

        Ok(arc)
    }

    /// Register a peer in the known_peers directory.
    ///
    /// After this call, `get_connection(identity)` will find the peer's address.
    /// If the peer was already present, the address is updated.
    pub async fn add_peer(&self, identity: IdentityPub, addr: EndpointAddr) {
        let mut peers = self.known_peers.write().await;
        peers.insert(identity, addr);
    }

    /// Send a [`Message`] on an established connection (static helper).
    pub async fn send_message(
        conn: &mut Connection,
        msg: &Message,
    ) -> Result<(), NetworkError> {
        conn.send_message(msg).await
    }

    /// Receive the next [`Message`] from an established connection (static helper).
    pub async fn recv_message(conn: &mut Connection) -> Result<Message, NetworkError> {
        conn.recv_message().await
    }

    /// Send symbols to a peer.
    ///
    /// Obtains or creates a pooled connection to `peer_identity`, then sends
    /// `msg` as [`Message::SymbolTransfer`].
    pub async fn send_symbols(
        &self,
        peer_identity: IdentityPub,
        msg: SymbolTransferMsg,
    ) -> Result<(), NetworkError> {
        let arc = self.get_connection(peer_identity).await?;
        let mut guard = arc.lock().await;
        guard.send_message(&Message::SymbolTransfer(msg)).await
    }

    /// Gracefully shut down the endpoint.
    pub async fn shutdown(self) {
        info!("shutting down network handle");
        self.endpoint.close().await;
    }
}
