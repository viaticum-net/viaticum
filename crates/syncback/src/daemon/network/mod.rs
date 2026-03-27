// Network module: iroh QUIC transport layer for SyncBack β.
//
// Provides:
//   - NetworkHandle: one endpoint per daemon instance
//   - Outbound connections with SyncBack handshake authentication
//   - Inbound accept loop (background task)
//   - Framed CBOR message send/receive (via Connection)
//   - Connection pool (reuse per peer IdentityPub)
//   - send_symbols / send_to_peer high-level helpers
//   - Backoff: failed connections are not retried for RECONNECT_BACKOFF_SECS
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
use syncback_core::constants::{ALPN, RECONNECT_BACKOFF_SECS};
use syncback_core::messages::{Message, SymbolTransferMsg};
use syncback_core::types::{DeviceId, IdentityPub, NodeId};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

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

    /// Peer identity not in known_peers directory, or currently in backoff window.
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
    /// Ed25519 signing key (device key) used for handshake signatures.
    pub signing_key: SigningKey,
    /// Master signing key used for PeerAnnounce signatures.
    /// In production: derived from seed via HKDF("syncback-master").
    /// In tests: may be the same as signing_key for simplicity.
    pub master_signing_key: SigningKey,
    /// Master identity (from cluster master key). This is the identity
    /// announced in PeerAnnounce and used for all protocol operations.
    /// Different from signing_key.verifying_key() which is the device identity.
    pub master_identity: IdentityPub,
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
    /// X25519 public key for directed relay board encryption.
    /// Advertised in PeerAnnounce so peers can encrypt messages to us.
    pub x25519_pub: Option<[u8; 32]>,
}

// ─── Connection pool ──────────────────────────────────────────────────────────

/// Internal pool entry.
enum ConnectionState {
    /// Live authenticated connection.
    Live(Arc<Connection>),
    /// Connection failed recently. Don't retry until `retry_after` unix timestamp (seconds).
    Backoff { retry_after: u64 },
}

// ─── NetworkHandle ────────────────────────────────────────────────────────────

/// Handle to the running network layer for one daemon instance.
///
/// Owns the iroh [`Endpoint`] and manages the connection pool.
/// Constructed via [`NetworkHandle::start`].
/// Request to spawn a read loop for an auto-reconnected connection.
pub type ReadLoopRequest = (IdentityPub, Arc<Connection>);

pub struct NetworkHandle {
    /// iroh endpoint (transport identity).
    endpoint: Endpoint,
    /// Our SyncBack master identity (from cluster master key).
    /// Used in PeerAnnounce and all protocol operations.
    pub identity_pub: IdentityPub,
    /// Device-level identity (signing_key.verifying_key()).
    /// Used in handshake — the key that actually signs the HandshakeMsg.
    device_identity: IdentityPub,
    /// Our iroh transport identity as SyncBack NodeId bytes.
    pub node_id: NodeId,
    /// Signing key for building handshake messages (device key).
    signing_key: SigningKey,
    /// Master signing key for PeerAnnounce signatures.
    master_signing_key: SigningKey,
    /// Device certificate for cluster nodes. Passed in handshake if present.
    device_cert: Option<syncback_core::cluster::DeviceCertificate>,
    /// X25519 public key for directed relay board encryption.
    x25519_pub: Option<[u8; 32]>,
    /// Known peers directory (for `get_connection` by IdentityPub).
    known_peers: Arc<RwLock<HashMap<IdentityPub, EndpointAddr>>>,
    /// Authenticated connections keyed by peer IdentityPub (Live or Backoff).
    connections: Arc<Mutex<HashMap<IdentityPub, ConnectionState>>>,
    /// Channel to request Processor to spawn read loops for auto-reconnected
    /// outbound connections. Without this, only accepted (inbound) connections
    /// get a read loop, so PoS responses on auto-reconnected connections
    /// would be silently dropped. None in tests.
    read_loop_tx: std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedSender<ReadLoopRequest>>>,
    /// Cluster peer directory: maps DeviceId → EndpointAddr for same-cluster devices.
    /// Populated when an inbound connection is auto-added to the cluster.
    /// Keyed by DeviceId (distinct from known_peers which is keyed by master IdentityPub).
    cluster_peers: Arc<RwLock<HashMap<DeviceId, EndpointAddr>>>,
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
        let identity_pub = config.master_identity;
        let device_identity = IdentityPub(config.signing_key.verifying_key().to_bytes());

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
            master_identity = %identity_pub,
            device_identity = %device_identity,
            node_id = %node_id,
            "network handle started"
        );

        let connections: Arc<Mutex<HashMap<IdentityPub, ConnectionState>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Spawn accept loop — uses device_identity for handshake signing.
        let accept_endpoint = endpoint.clone();
        let signing_key_clone = config.signing_key.clone();
        let device_identity_clone = device_identity;
        let device_cert_clone = config.device_cert.clone();
        tokio::spawn(async move {
            accept_loop(
                accept_endpoint,
                signing_key_clone,
                device_identity_clone,
                device_cert_clone,
                incoming_tx,
            )
            .await;
        });

        Ok(Self {
            endpoint,
            identity_pub,
            device_identity,
            node_id,
            signing_key: config.signing_key,
            master_signing_key: config.master_signing_key,
            device_cert: config.device_cert,
            x25519_pub: config.x25519_pub,
            known_peers: Arc::new(RwLock::new(config.known_peers)),
            connections,
            read_loop_tx: std::sync::Mutex::new(None),
            cluster_peers: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Set the read-loop channel so auto-reconnected outbound connections
    /// get a Processor read loop (enabling bidirectional communication).
    /// Called by DaemonHandle after creating the Processor channel.
    pub fn set_read_loop_tx(&self, tx: tokio::sync::mpsc::UnboundedSender<ReadLoopRequest>) {
        *self.read_loop_tx.lock().unwrap() = Some(tx);
    }

    /// Return the iroh [`EndpointAddr`] for this endpoint (for peer_announce).
    pub fn local_addr(&self) -> Result<EndpointAddr, NetworkError> {
        Ok(self.endpoint.addr())
    }

    /// Return a reference to the signing key (for building PeerAnnounce messages).
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Return the actual bound socket addresses (local listening ports).
    /// These are the real ports iroh is listening on, unlike `local_addr()`
    /// which may return STUN-discovered external ports.
    pub fn bound_sockets(&self) -> Vec<std::net::SocketAddr> {
        self.endpoint.bound_sockets()
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
        debug!(peer = ?peer_addr.id, addrs = ?peer_addr.addrs, "connecting");

        let connect_fut = async {
            let iroh_conn = self
                .endpoint
                .connect(peer_addr, ALPN)
                .await
                .map_err(|e| NetworkError::Iroh(anyhow::anyhow!("{e}")))?;

            handshake_initiator(
                iroh_conn,
                &self.signing_key,
                self.device_identity,
                expected_identity,
                self.device_cert.clone(),
            )
            .await
        };

        // 15-second timeout prevents hanging on unreachable peers.
        let conn = tokio::time::timeout(std::time::Duration::from_secs(15), connect_fut)
            .await
            .map_err(|_| NetworkError::Iroh(anyhow::anyhow!("connect timed out (15s)")))?
            ?;

        info!(peer = %conn.peer_identity, "connection established");
        Ok(conn)
    }

    /// Get or create a connection to a peer by their SyncBack `IdentityPub`.
    ///
    /// Checks the pool first; creates a new connection if none exists.
    /// Looks up the peer's `EndpointAddr` in `known_peers` if needed.
    ///
    /// Returns `Err(NetworkError::PeerNotFound)` if the peer is currently in
    /// a backoff window (recent connect failure). After the window expires the
    /// next call attempts a fresh connect automatically.
    pub async fn get_connection(
        &self,
        peer_identity: IdentityPub,
    ) -> Result<Arc<Connection>, NetworkError> {
        // ── 1. Check pool ──────────────────────────────────────────────────────
        {
            let pool = self.connections.lock().await;
            match pool.get(&peer_identity) {
                Some(ConnectionState::Live(arc)) => {
                    return Ok(arc.clone());
                }
                Some(ConnectionState::Backoff { retry_after }) => {
                    let now = unix_now();
                    if now < *retry_after {
                        // Still in backoff window — do not hammer the peer.
                        return Err(NetworkError::PeerNotFound(peer_identity));
                    }
                    // Backoff expired; fall through to reconnect.
                }
                None => {
                    // Not in pool; fall through to fresh connect.
                }
            }
        }

        // ── 2. Resolve address ─────────────────────────────────────────────────
        let peer_addr = {
            let peers = self.known_peers.read().await;
            peers.get(&peer_identity).cloned()
        }
        .ok_or(NetworkError::PeerNotFound(peer_identity))?;

        // ── 3. Connect and authenticate ────────────────────────────────────────
        match self.connect(peer_addr, Some(peer_identity)).await {
            Ok(conn) => {
                let arc = Arc::new(conn);
                self.connections
                    .lock()
                    .await
                    .insert(peer_identity, ConnectionState::Live(arc.clone()));

                // Notify Processor to spawn a read loop so we can receive
                // responses (PoS, SymbolAccept, etc.) on this connection.
                if let Some(tx) = self.read_loop_tx.lock().unwrap().as_ref() {
                    if let Err(e) = tx.send((peer_identity, arc.clone())) {
                        tracing::warn!(
                            peer = %peer_identity,
                            err = %e,
                            "get_connection: read_loop_tx closed, read loop not spawned"
                        );
                    }
                }

                Ok(arc)
            }
            Err(e) => {
                // Record backoff so we don't spam connect attempts.
                let retry_after = unix_now() + RECONNECT_BACKOFF_SECS;
                self.connections
                    .lock()
                    .await
                    .insert(peer_identity, ConnectionState::Backoff { retry_after });
                Err(e)
            }
        }
    }

    /// Send a message to a peer by identity.
    ///
    /// Obtains or creates a pooled connection, then sends `msg`. On send
    /// failure the dead pool entry is replaced with a `Backoff` entry so the
    /// next `get_connection` attempt reconnects rather than reusing the stale
    /// `Arc`.
    pub async fn send_to_peer(
        &self,
        peer_identity: IdentityPub,
        msg: &Message,
    ) -> Result<(), NetworkError> {
        let arc = self.get_connection(peer_identity).await?;
        match arc.send_message(msg).await {
            Ok(()) => Ok(()),
            Err(e) => {
                warn!(
                    peer = %peer_identity,
                    err = %e,
                    "send_to_peer: send failed, evicting from pool"
                );
                let retry_after = unix_now() + RECONNECT_BACKOFF_SECS;
                self.connections
                    .lock()
                    .await
                    .insert(peer_identity, ConnectionState::Backoff { retry_after });
                Err(e)
            }
        }
    }

    /// Remove a connection from the pool and record a backoff entry.
    ///
    /// Called by the Processor read loop when a connection dies unexpectedly.
    /// After this call, `get_connection` for this peer will return an error
    /// until the backoff window expires, then attempt a fresh connect.
    pub async fn evict_connection(&self, peer_identity: IdentityPub) {
        let retry_after = unix_now() + RECONNECT_BACKOFF_SECS;
        self.connections
            .lock()
            .await
            .insert(peer_identity, ConnectionState::Backoff { retry_after });
        debug!(peer = %peer_identity, "connection evicted, backoff recorded");
    }

    /// Store an established connection in the pool so it stays alive.
    ///
    /// Used by dispatch_connect to keep the connection from being dropped
    /// after the CLI returns.
    pub async fn store_connection(&self, peer_identity: IdentityPub, conn: Connection) {
        self.connections
            .lock()
            .await
            .insert(peer_identity, ConnectionState::Live(Arc::new(conn)));
        debug!(peer = %peer_identity, "connection stored in pool");
    }

    /// Store a pre-wrapped connection Arc in the pool.
    ///
    /// Used by the Processor to register connections it manages so that
    /// `get_connection()` and `send_to_peer()` can reuse them.
    pub async fn store_connection_arc(
        &self,
        peer_identity: IdentityPub,
        arc: Arc<Connection>,
    ) {
        self.connections
            .lock()
            .await
            .insert(peer_identity, ConnectionState::Live(arc));
        debug!(peer = %peer_identity, "connection arc stored in pool");
    }

    /// Register an already-established connection in the pool and spawn its
    /// read loop. Used by bootstrap discovery which connects without knowing
    /// the peer's master identity in advance.
    pub async fn register_connection(
        &self,
        peer_identity: IdentityPub,
        conn: Connection,
    ) {
        let arc = Arc::new(conn);
        self.connections
            .lock()
            .await
            .insert(peer_identity, ConnectionState::Live(arc.clone()));

        if let Some(tx) = self.read_loop_tx.lock().unwrap().as_ref() {
            if let Err(e) = tx.send((peer_identity, arc)) {
                tracing::warn!(
                    peer = %peer_identity,
                    err = %e,
                    "register_connection: read_loop_tx closed"
                );
            }
        }
        debug!(peer = %peer_identity, "connection registered in pool");
    }

    /// Register a peer in the known_peers directory.
    ///
    /// After this call, `get_connection(identity)` will find the peer's address.
    /// If the peer was already present, the address is updated.
    pub async fn add_peer(&self, identity: IdentityPub, addr: EndpointAddr) {
        debug!(
            peer = %identity,
            node_id = ?addr.id,
            num_addrs = addr.addrs.len(),
            addrs = ?addr.addrs,
            "add_peer: registering"
        );
        let mut peers = self.known_peers.write().await;
        peers.insert(identity, addr);
    }

    /// Build a full [`EndpointAddr`] for a remote peer using iroh's internal
    /// address book. Returns `None` if iroh has no info for this peer.
    ///
    /// This is much better than `EndpointAddr::new(pubkey)` (NodeId-only)
    /// because it includes actual IP:port and relay URLs that iroh has learned
    /// through the existing connection.
    pub async fn remote_endpoint_addr(&self, remote_id: iroh::PublicKey) -> Option<EndpointAddr> {
        let info = self.endpoint.remote_info(remote_id).await?;
        let addr = EndpointAddr::from_parts(
            info.id(),
            info.into_addrs().map(|a| a.into_addr()),
        );
        Some(addr)
    }

    /// Send a [`Message`] on an established connection (static helper).
    pub async fn send_message(
        conn: &Connection,
        msg: &Message,
    ) -> Result<(), NetworkError> {
        conn.send_message(msg).await
    }

    /// Receive the next [`Message`] from an established connection (static helper).
    pub async fn recv_message(conn: &Connection) -> Result<Message, NetworkError> {
        conn.recv_message().await
    }

    /// Send symbols to a peer.
    ///
    /// Uses `send_to_peer` so that a send failure evicts the dead connection
    /// and records a backoff entry, preventing repeated attempts on a dead
    /// socket until the backoff window expires.
    pub async fn send_symbols(
        &self,
        peer_identity: IdentityPub,
        msg: SymbolTransferMsg,
    ) -> Result<(), NetworkError> {
        self.send_to_peer(peer_identity, &Message::SymbolTransfer(msg))
            .await
    }

    /// Look up a peer's EndpointAddr from the known_peers directory.
    pub async fn get_peer_addr(&self, identity: &IdentityPub) -> Option<EndpointAddr> {
        let peers = self.known_peers.read().await;
        peers.get(identity).cloned()
    }

    /// Build a signed PeerAnnounceMsg for this node.
    ///
    /// Used to introduce ourselves when a new connection is established.
    /// The sig covers identity_pub || node_id || timestamp.
    /// x25519_pub is included as an informational field (not signed).
    pub fn build_peer_announce(
        &self,
        timestamp: syncback_core::types::Timestamp,
    ) -> syncback_core::messages::PeerAnnounceMsg {
        syncback_core::messages::build_peer_announce(
            self.identity_pub,
            self.node_id,
            timestamp,
            &self.master_signing_key,
            self.x25519_pub,
        )
    }

    /// Gracefully shut down the endpoint.
    pub async fn shutdown(self) {
        info!("shutting down network handle");
        self.endpoint.close().await;
    }

    /// Test-only: inject a `Backoff` entry for a peer.
    #[cfg(test)]
    pub async fn inject_backoff_for_test(&self, peer: IdentityPub, retry_after: u64) {
        self.connections
            .lock()
            .await
            .insert(peer, ConnectionState::Backoff { retry_after });
    }

    /// Test-only: check whether a peer's pool entry is a `Backoff`.
    #[cfg(test)]
    pub async fn is_peer_in_backoff(&self, peer: &IdentityPub) -> bool {
        matches!(
            self.connections.lock().await.get(peer),
            Some(ConnectionState::Backoff { .. })
        )
    }

    /// Test-only: check if a peer is in the known_peers directory.
    #[cfg(test)]
    pub async fn has_known_peer(&self, identity: &IdentityPub) -> bool {
        self.known_peers.read().await.contains_key(identity)
    }

    /// Register a cluster device's network address.
    ///
    /// Called by Processor after auto-adding a device to ClusterState.
    /// If the device_id is already present, the address is updated.
    pub async fn add_cluster_peer(&self, device_id: DeviceId, addr: EndpointAddr) {
        let mut peers = self.cluster_peers.write().await;
        peers.insert(device_id, addr);
        debug!(device_id = %device_id, "cluster peer registered");
    }

    /// List all known cluster peers.
    ///
    /// Returns a snapshot of the current cluster_peers map.
    pub async fn cluster_peers(&self) -> Vec<(DeviceId, EndpointAddr)> {
        let peers = self.cluster_peers.read().await;
        peers.iter().map(|(k, v)| (*k, v.clone())).collect()
    }

    /// Remove a cluster peer from the directory.
    ///
    /// Called on device revocation. Does nothing if the device_id is not present.
    pub async fn remove_cluster_peer(&self, device_id: &DeviceId) {
        let mut peers = self.cluster_peers.write().await;
        peers.remove(device_id);
        debug!(device_id = %device_id, "cluster peer removed");
    }
}

// ─── Private helpers ──────────────────────────────────────────────────────────

/// Current Unix timestamp in seconds.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
