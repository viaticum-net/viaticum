// libp2p swarm stack for Viaticum ε.1–ε.3.
//
// Provides:
//   - ViaticumCodec: framed CBOR codec for request-response (wire: [u32 BE len][CBOR])
//   - CertCodec: framed CBOR codec for DeviceCertExchange protocol
//   - ViaticumBehaviour: composed NetworkBehaviour (viaticum + cert + identify + kad)
//   - SwarmHandle: public API to the event loop
//   - EventLoopState: private state machine running in a tokio task
//   - Kademlia DHT: automatic Viaticum peer discovery via the shared IPFS DHT (ε.3)
//
// Identity model:
//   device_signing_key → Ed25519 keypair → PeerId (libp2p transport identity)
//   device_id = device_signing_key.verifying_key().to_bytes() (same key)
//   Noise IX authenticates both ends at transport level.
//   DeviceCertExchange adds protocol-level proof of cluster membership.
//
// Kademlia discovery:
//   All Viaticum nodes publish and discover via sha256("/viaticum/peers/v1")
//   on the shared /ipfs/kad/1.0.0 DHT. Discovery is passive: found peers are
//   dialed; DeviceCertExchange runs automatically after TCP+Noise connects.

use std::collections::{HashMap, HashSet};
use std::io;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use libp2p::identity::ed25519;
use libp2p::kad::QueryId;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, OutboundRequestId, ProtocolSupport, ResponseChannel};
use libp2p::swarm::SwarmEvent;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::{Multiaddr, PeerId, StreamProtocol};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};
use viaticum_core::cluster::{CertTrustPath, DeviceCertificate, verify_device_certificate};
use viaticum_core::messages::Message;
use viaticum_core::types::{DeviceId, IdentityPub};

// ─── Type aliases ────────────────────────────────────────────────────────────

/// Result type for `SwarmHandle::get_closest_peers` (T-9a).
///
/// Each entry is a `(PeerId, listen_addrs)` pair — the peer's libp2p identity
/// and the listen addresses known to the Kademlia routing table at query time.
/// Addresses may be empty for peers that are in the routing table but for
/// which the `identify` protocol has not yet run.
pub type ClosestPeersResult = Vec<(PeerId, Vec<Multiaddr>)>;

// ─── Wire protocol identifiers ────────────────────────────────────────────────

/// Protocol for all Viaticum direct protocol messages.
pub const VIATICUM_PROTOCOL: StreamProtocol = StreamProtocol::new("/viaticum/1");

/// Protocol for DeviceCertExchange (transport-level cert handshake).
pub const CERT_PROTOCOL: StreamProtocol = StreamProtocol::new("/viaticum/cert/1");

/// Kademlia protocol name. Still the shared IPFS DHT name (ε.3); identify
/// reports whether a peer announces it (C-DK Р-7 diagnostics).
const KAD_PROTOCOL: StreamProtocol = StreamProtocol::new("/ipfs/kad/1.0.0");

/// Max message size — matches viaticum_core::constants::MAX_MESSAGE_SIZE.
const MAX_MSG_SIZE: usize = viaticum_core::constants::MAX_MESSAGE_SIZE as usize;

// ─── Kademlia constants (ε.3) ─────────────────────────────────────────────────

/// Kademlia provider record republish interval: 30 minutes.
pub const KAD_REPUBLISH_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Kademlia discovery (get_providers) interval: 5 minutes.
pub const KAD_DISCOVERY_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Kademlia MemoryStore record limit (10x libp2p default of 1024).
pub const KAD_STORE_LIMIT: usize = 10240;

/// Grace period after startup before first get_providers (allow bootstrap to complete).
pub const KAD_INITIAL_DISCOVERY_DELAY: Duration = Duration::from_secs(15);

/// Scale a real-time Kademlia cadence by the daemon's `time_scale` so peer discovery keeps
/// pace under an accelerated (`time_scale>1`) test clock. Without this, the 5-minute
/// real-time discovery interval fires only ~once in a minutes-long accelerated run, so
/// non-seed nodes never discover holders and place nothing (the whole run degenerates).
/// Floored at 1s so discovery still fires (never a zero interval). `time_scale<=1`
/// (production) returns the base unchanged. Mirrors the scheduler/redial cadence scaling —
/// the project's time_scale contract.
pub fn scaled_kad_cadence(base: Duration, time_scale: u64) -> Duration {
    let ts = time_scale.max(1);
    if ts <= 1 {
        base
    } else {
        Duration::from_secs((base.as_secs() / ts).max(1))
    }
}

/// Select which discovered peers to dial this round. Mirrors the provider-path
/// gating: skip entirely once we already have TARGET_PEERS authenticated peers
/// (cold backup wants a stable small set, not unbounded growth), and cap the
/// number of concurrent dials to MAX_CONCURRENT_DISCOVERY_DIALS to avoid bursting
/// the cert-exchange pipeline. Peers with empty addrs are kept (dial_discovered_peer
/// still guards self/already-connected/dialing and falls back to peerid-only dial).
pub fn discovery_dial_candidates(
    peer_list: Vec<(PeerId, Vec<Multiaddr>)>,
    auth_count: usize,
) -> Vec<(PeerId, Vec<Multiaddr>)> {
    use viaticum_core::constants::{MAX_CONCURRENT_DISCOVERY_DIALS, TARGET_PEERS};
    if auth_count >= TARGET_PEERS {
        return Vec::new();
    }
    peer_list
        .into_iter()
        .take(MAX_CONCURRENT_DISCOVERY_DIALS)
        .collect()
}

// ─── ViaticumCodec ────────────────────────────────────────────────────────────

/// CBOR codec for libp2p request-response (main protocol).
///
/// Wire format: [u32 BE length][CBOR bytes].
/// Uses futures::AsyncRead/AsyncWrite (NOT tokio) as required by libp2p.
#[derive(Debug, Clone, Default)]
pub struct ViaticumCodec;

#[async_trait]
impl request_response::Codec for ViaticumCodec {
    type Protocol = StreamProtocol;
    type Request = Message;
    type Response = Message;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        read_framed_message(io).await
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        read_framed_message(io).await
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        write_framed_message(io, req).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        write_framed_message(io, resp).await
    }
}

// ─── DeviceCertExchange types ─────────────────────────────────────────────────

/// Payload for cert handshake on /viaticum/cert/1.
///
/// Sent as the first request-response exchange after TCP+Noise connection.
/// Contains the cluster DeviceCertificate (signed by master key) and optional
/// X25519 public key for directed relay board encryption.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceCertExchangeMsg {
    pub cert: DeviceCertificate,
    /// X25519 public key for directed board encryption.
    pub x25519_pub: Option<[u8; 32]>,
}

/// CBOR codec for DeviceCertExchange on /viaticum/cert/1.
#[derive(Debug, Clone, Default)]
pub struct CertCodec;

#[async_trait]
impl request_response::Codec for CertCodec {
    type Protocol = StreamProtocol;
    type Request = DeviceCertExchangeMsg;
    type Response = DeviceCertExchangeMsg;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        read_framed_cbor(io).await
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        read_framed_cbor(io).await
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        write_framed_cbor(io, &req).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        write_framed_cbor(io, &resp).await
    }
}

// ─── NetworkBehaviour ─────────────────────────────────────────────────────────

/// Combined libp2p NetworkBehaviour for Viaticum.
///
/// - viaticum: request-response for protocol messages (/viaticum/1)
/// - cert: request-response for DeviceCertExchange (/viaticum/cert/1)
/// - identify: publishes/receives peer info for diagnostics and Kademlia addresses
/// - kad: Kademlia DHT for peer discovery via /ipfs/kad/1.0.0 (ε.3)
/// - relay_client: Circuit Relay v2 client (ε.4) — must be before dcutr
/// - relay_server: Circuit Relay v2 server (ε.4) — all nodes accept relay requests
/// - dcutr: Direct Connection Upgrade through Relay (ε.4) — hole punching
///
/// Field order is load-bearing: relay_client must appear before dcutr because
/// DCUtR uses the relay client internally for coordination messages.
#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct ViaticumBehaviour {
    pub viaticum: request_response::Behaviour<ViaticumCodec>,
    pub cert: request_response::Behaviour<CertCodec>,
    pub identify: libp2p::identify::Behaviour,
    pub kad: libp2p::kad::Behaviour<libp2p::kad::store::MemoryStore>,
    pub relay_client: libp2p::relay::client::Behaviour,
    pub relay_server: libp2p::relay::Behaviour,
    pub dcutr: libp2p::dcutr::Behaviour,
}

// ─── Events and Commands ──────────────────────────────────────────────────────

/// Events from the SwarmHandle event loop to the consumer (Processor in ε.2).
///
/// PeerId is NOT exposed for InboundRequest / PeerAuthenticated — Processor
/// sees DeviceId only. PeerId is exposed in ConnectionClosed for diagnostics.
#[derive(Debug)]
pub enum ProtocolEvent {
    /// Peer completed DeviceCertExchange and is now authenticated.
    PeerAuthenticated {
        peer_id: PeerId,
        device_id: DeviceId,
        identity_pub: IdentityPub,
        device_cert: DeviceCertificate,
        x25519_pub: Option<[u8; 32]>,
        /// Addresses we know for this peer at the moment of authentication:
        /// the address we dialed it on (dialer side) ∪ its identify listen
        /// addrs (if identify already arrived). Normalized by
        /// [`normalize_peer_addrs`]: each ends in exactly one `/p2p/<peer_id>`.
        /// Carried here so the PeerRecord gets its addresses in the same write
        /// that creates it (network-i2) — a separate `PeerIdentified` can be
        /// processed before the record exists and would be lost.
        listen_addrs: Vec<Multiaddr>,
    },
    /// Authenticated peer sent an inbound protocol request.
    InboundRequest {
        from_device: DeviceId,
        from_master: IdentityPub,
        message: Message,
        response_channel: ResponseChannel<Message>,
    },
    /// Connection was closed (may not have been authenticated yet).
    ConnectionClosed {
        peer_id: PeerId,
        /// None if DeviceCertExchange never completed.
        device_id: Option<DeviceId>,
    },
    /// Identify protocol delivered the peer's listen addresses for an already
    /// authenticated peer. The processor persists them on the PeerRecord so the
    /// daemon can re-dial after restart (otherwise PeerRecord rows have no
    /// usable address and bootstrap breaks).
    ///
    /// Only emitted once cert exchange completed — before that we don't have a
    /// DeviceId to attach the addrs to. If identify arrives first, addrs are
    /// stashed in the swarm and re-emitted as part of `PeerAuthenticated.listen_addrs`.
    ///
    /// `listen_addrs` = identify addrs ∪ the address we dialed this peer on
    /// (network-i4: a working outbound address is not displaced by the peer's
    /// private LAN addrs), normalized like `PeerAuthenticated.listen_addrs`.
    PeerIdentified {
        device_id: DeviceId,
        listen_addrs: Vec<Multiaddr>,
    },
}

/// Commands sent from SwarmHandle to the event loop.
#[allow(clippy::large_enum_variant)] // Message is intentionally large; boxing would add alloc overhead.
enum SwarmCommand {
    SendMessage {
        peer_id: PeerId,
        message: Box<Message>,
        reply: oneshot::Sender<Result<Message, SwarmError>>,
    },
    /// Send a message to the first authenticated device belonging to a given master identity.
    SendToMaster {
        master: IdentityPub,
        message: Box<Message>,
        reply: oneshot::Sender<Result<Message, SwarmError>>,
    },
    /// One dial attempt for `peer_id` over all `addrs` (libp2p tries them in turn).
    Dial {
        peer_id: PeerId,
        addrs: Vec<Multiaddr>,
    },
    ListenAddrs {
        reply: oneshot::Sender<Vec<Multiaddr>>,
    },
    /// Snapshot of swarm peer-set: connected_count vs authenticated_count.
    /// Connected = libp2p has a live transport-level link (post-Noise+identify).
    /// Authenticated = our cert exchange has succeeded (heavy messages allowed).
    PeerCounts { reply: oneshot::Sender<(u32, u32)> },
    /// Snapshot of which DeviceIds are currently authenticated and which are
    /// only connected (post-Noise but cert exchange in flight or never started).
    PeerSets {
        reply: oneshot::Sender<(HashSet<DeviceId>, HashSet<DeviceId>)>,
    },
    /// Look up the PeerId for a DeviceId (checks authenticated map).
    LookupPeer {
        device: DeviceId,
        reply: oneshot::Sender<Result<PeerId, SwarmError>>,
    },
    /// Send a response on an inbound ResponseChannel (ε.2: Processor dispatch).
    SendResponse {
        channel: ResponseChannel<Message>,
        response: Box<Message>,
    },
    /// Initiate a Kademlia FIND_NODE query and return the closest peers found.
    ///
    /// Used by T-9 (DR walk) to discover the write-fanout candidates for a
    /// SelfPointer (closest peers to SHA256(owner_master_pub)) and to resolve
    /// dial addresses for holders whose PeerRecord addrs are empty/stale.
    GetClosestPeers {
        key: Vec<u8>,
        reply: oneshot::Sender<Result<ClosestPeersResult, SwarmError>>,
    },
    /// Return the known addrs for a DeviceId: identify listen addrs ∪ the
    /// address we dialed it on, normalized (`/p2p/<peer_id>` suffix).
    ///
    /// Used by T-12 (owner-addr propagation safety net): after receiving a
    /// SymbolStored ack, the owner queries the holder's known addrs so they can
    /// be persisted on the PeerRecord for later inclusion in HolderHint.addrs.
    ///
    /// Returns an empty Vec if the peer has not yet been identified (identify
    /// protocol not completed) — this is normal; the caller handles it gracefully.
    GetPeerAddrs {
        device: DeviceId,
        reply: oneshot::Sender<Vec<Multiaddr>>,
    },
    /// Test-only (`net-probe disconnect`, C-DK Р-16): close every connection to
    /// `peer_id`. Replies whether there was one.
    #[cfg(feature = "e2e-tools")]
    Disconnect {
        peer_id: PeerId,
        reply: oneshot::Sender<bool>,
    },
}

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors from the libp2p swarm layer.
#[derive(Debug, thiserror::Error)]
pub enum SwarmError {
    #[error("libp2p transport error: {0}")]
    Transport(String),

    #[error("peer not authenticated: {0:?}")]
    PeerNotAuthenticated(DeviceId),

    #[error("no authenticated device for master: {0:?}")]
    MasterNotAuthenticated(IdentityPub),

    #[error("device cert verification failed: {0}")]
    CertVerification(String),

    #[error("request failed: {0}")]
    RequestFailed(String),

    #[error("swarm command channel closed")]
    ChannelClosed,

    #[error("swarm command channel full (backpressure)")]
    ChannelFull,

    #[error("timeout")]
    Timeout,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The fixed listen port is held by another process (a second viaticum on
    /// the same port included: libp2p-tcp binds its listener with SO_REUSEPORT,
    /// so only a probe without it notices the other holder). daemon-i1.
    #[error("listen port {port} is in use by another process")]
    PortInUse { port: u16 },
}

// ─── Config ───────────────────────────────────────────────────────────────────

/// Configuration for the libp2p swarm.
pub struct SwarmConfig {
    /// Ed25519 signing key — IS the device key.
    /// device_id = verifying_key().to_bytes(). PeerId derived from same key.
    pub device_signing_key: ed25519_dalek::SigningKey,
    /// Master signing key. Used to sign PeerAnnounceMsg in build_peer_announce.
    pub master_signing_key: ed25519_dalek::SigningKey,
    /// This device's master identity (from cluster master key).
    ///
    /// Used for logging, board-message signing, and as the "who am I" in
    /// peer-facing metadata. For a single-device cluster this equals
    /// `cluster_master_pub`; for a multi-device cluster on a non-founder node
    /// they differ — the founder's identity is stored as `cluster_master_pub`,
    /// not as `identity_pub`.
    pub identity_pub: IdentityPub,
    /// Cluster master identity — the anchor for `DeviceCertificate` signature
    /// verification. Resolved from `ClusterState.master_pub()` at startup, NOT
    /// from this node's own seed-derived master.
    ///
    /// On a founder/single-device node `cluster_master_pub == identity_pub`;
    /// on a node that joined an existing cluster they differ (founder ≠ self).
    /// Using `identity_pub` here instead would silently break multi-device
    /// clusters — a joiner would reject legitimate certs signed by the founder.
    pub cluster_master_pub: IdentityPub,
    /// Device certificate issued by cluster master.
    pub device_cert: DeviceCertificate,
    /// X25519 public key for directed relay board encryption.
    pub x25519_pub: Option<[u8; 32]>,
    /// TCP listen port. 0 = OS assigns (recommended for tests).
    pub listen_port: u16,
    /// Timeout for receiving DeviceCertExchange after ConnectionEstablished.
    /// If not received within this duration, connection is closed.
    pub cert_timeout_secs: u64,

    // ── Kademlia (ε.3) ────────────────────────────────────────────────────────
    /// Additional Kademlia bootstrap multiaddrs from config.
    /// Already parsed and validated by AppConfig::validate().
    pub kademlia_bootstrap_peers: Vec<Multiaddr>,

    /// When true (the default, see `NetworkCfg`), skip built-in IPFS bootstrap
    /// nodes: the friends' network is closed (network-i11).
    pub kademlia_disable_ipfs_bootstrap: bool,

    /// Override for KAD_REPUBLISH_INTERVAL. None = use the constant.
    /// Used in tests to speed up the republish cycle.
    pub kad_republish_interval_override: Option<Duration>,

    /// Override for KAD_DISCOVERY_INTERVAL and initial discovery delay.
    /// None = use the constants. Used in tests to speed up discovery.
    pub kad_discovery_interval_override: Option<Duration>,

    /// Whether this node acts as a circuit relay server for other peers.
    /// When false, relay server is created with `max_reservations: 0` and
    /// `max_circuits: 0` so no peer can use us as a relay. Default config
    /// flag is false (opt-in) — home NAS / laptop shouldn't relay traffic
    /// for strangers without explicit consent.
    pub enable_relay_server: bool,
}

// ─── SwarmHandle ──────────────────────────────────────────────────────────────

/// Handle to the running libp2p swarm event loop.
///
/// Owns the libp2p swarm event loop.
pub struct SwarmHandle {
    cmd_tx: mpsc::Sender<SwarmCommand>,
    /// Our libp2p PeerId (stable, derived from device signing key).
    pub peer_id: PeerId,
    /// Our Viaticum DeviceId (= Ed25519 pubkey bytes of device signing key).
    pub device_id: DeviceId,
    /// Our master identity.
    pub identity_pub: IdentityPub,
    /// Master signing key for building PeerAnnounceMsg.
    master_signing_key: ed25519_dalek::SigningKey,
    /// X25519 public key for directed relay board encryption.
    pub x25519_pub: Option<[u8; 32]>,
    /// ARCH-5: count of RR responses dropped because the cmd channel was
    /// full/closed. `respond` (try_send) can silently fail under burst; this
    /// makes those drops observable via `respond_logged` + `dropped_responses()`.
    dropped_responses: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for SwarmHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SwarmHandle")
            .field("peer_id", &self.peer_id)
            .field("device_id", &self.device_id)
            .field("identity_pub", &self.identity_pub)
            .finish_non_exhaustive()
    }
}

impl SwarmHandle {
    /// Start the libp2p swarm.
    ///
    /// Derives libp2p identity from device_signing_key (same Ed25519 key).
    /// Spawns event loop as a tokio task.
    /// Returns (handle, event_receiver). The event_receiver has capacity 256.
    pub async fn start(
        config: SwarmConfig,
    ) -> Result<(Self, mpsc::Receiver<ProtocolEvent>), SwarmError> {
        // ── 1. Build libp2p keypair from device signing key ───────────────────
        // device_signing_key is Ed25519; libp2p uses the same key material.
        // PeerId = multihash(Ed25519 pubkey) — deterministic.
        let mut key_bytes = config.device_signing_key.to_bytes();
        let secret = ed25519::SecretKey::try_from_bytes(&mut key_bytes)
            .map_err(|e| SwarmError::Transport(e.to_string()))?;
        let ed_pair = ed25519::Keypair::from(secret);
        let keypair = libp2p::identity::Keypair::from(ed_pair);
        let peer_id = keypair.public().to_peer_id();
        let device_id = DeviceId(config.device_signing_key.verifying_key().to_bytes());

        info!(
            peer_id = %peer_id,
            device_id = %device_id,
            identity_pub = %config.identity_pub,
            "swarm starting"
        );

        // ── 2. Build Kademlia behaviour ───────────────────────────────────────
        let kad_cfg = libp2p::kad::Config::new(KAD_PROTOCOL);
        let kad_store = libp2p::kad::store::MemoryStore::with_config(
            peer_id,
            libp2p::kad::store::MemoryStoreConfig {
                max_records: KAD_STORE_LIMIT,
                max_provided_keys: KAD_STORE_LIMIT,
                ..Default::default()
            },
        );
        let mut kademlia = libp2p::kad::Behaviour::with_config(peer_id, kad_store, kad_cfg);
        kademlia.set_mode(Some(libp2p::kad::Mode::Server));

        // Add IPFS bootstrap peers unless disabled (e.g. in tests).
        if !config.kademlia_disable_ipfs_bootstrap {
            for (bs_peer_id, addr) in ipfs_bootstrap_peers() {
                kademlia.add_address(&bs_peer_id, addr);
            }
        }
        // Add config-provided bootstrap peers.
        for addr in &config.kademlia_bootstrap_peers {
            if let Some(bs_peer_id) = peer_id_from_multiaddr(addr) {
                kademlia.add_address(&bs_peer_id, addr.clone());
            } else {
                warn!(addr = %addr, "kademlia bootstrap peer has no /p2p component, skipping");
            }
        }

        // ── 3. Build Swarm (relay client comes from builder step) ─────────────
        // relay::client::Behaviour is produced by with_relay_client() and passed
        // as the second argument to with_behaviour(). relay_server and dcutr are
        // constructed inline. Field order in ViaticumBehaviour is load-bearing:
        // relay_client must precede dcutr for DCUtR to work correctly.
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            // Wrap TCP in NoPortReuse so libp2p's port-reuse trick (binding
            // outgoing sockets to the listener port via SO_REUSEPORT) never
            // fires. Some tun-based VPN stacks (sing-box + hysteria2) silently
            // drop TCP flows whose source port matches a local listener; cold
            // backup doesn't need NAT hole-punching enough to keep that risk.
            // Replicates `with_tcp`'s internal upgrade chain (noise + yamux,
            // wrapped in `StreamMuxerBox`) on top of the wrapped transport.
            .with_other_transport(|key| {
                use libp2p::Transport as _;
                use libp2p::core::muxing::StreamMuxerBox;
                use libp2p::core::upgrade::Version;
                let noise = libp2p::noise::Config::new(key)?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                    super::no_port_reuse::NoPortReuse::new(libp2p::tcp::tokio::Transport::new(
                        libp2p::tcp::Config::default(),
                    ))
                    .upgrade(Version::V1Lazy)
                    .authenticate(noise)
                    .multiplex(libp2p::yamux::Config::default())
                    .map(|(p, c), _| (p, StreamMuxerBox::new(c))),
                )
            })
            .map_err(|e| SwarmError::Transport(e.to_string()))?
            .with_relay_client(libp2p::noise::Config::new, libp2p::yamux::Config::default)
            .map_err(|e| SwarmError::Transport(e.to_string()))?
            .with_behaviour(|key, relay_client| ViaticumBehaviour {
                viaticum: request_response::Behaviour::new(
                    [(VIATICUM_PROTOCOL, ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(std::time::Duration::from_secs(30)),
                ),
                cert: request_response::Behaviour::new(
                    [(CERT_PROTOCOL, ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(std::time::Duration::from_secs(30)),
                ),
                identify: libp2p::identify::Behaviour::new(libp2p::identify::Config::new(
                    "/viaticum/identify/1".to_string(),
                    key.public(),
                )),
                kad: kademlia,
                relay_client,
                relay_server: {
                    let relay_cfg = if config.enable_relay_server {
                        libp2p::relay::Config::default()
                    } else {
                        // Opt-out: refuse any relay reservation/circuit.
                        // Behaviour is still instantiated to keep the type
                        // unchanged; capacity zero prevents service.
                        libp2p::relay::Config {
                            max_reservations: 0,
                            max_circuits: 0,
                            ..libp2p::relay::Config::default()
                        }
                    };
                    libp2p::relay::Behaviour::new(peer_id, relay_cfg)
                },
                dcutr: libp2p::dcutr::Behaviour::new(peer_id),
            })
            .map_err(|e| SwarmError::Transport(e.to_string()))?
            .with_swarm_config(|cfg| {
                cfg.with_idle_connection_timeout(std::time::Duration::from_secs(600))
            })
            .build();

        // Listen-port check (daemon-i1). libp2p-tcp sets SO_REUSEPORT on its
        // listening socket, so a second viaticum of the same user binds the same
        // fixed port without an error and the two silently share incoming
        // connections. A probe WITHOUT SO_REUSEPORT gets EADDRINUSE while anyone
        // listens there: it is the authoritative check. It also waits out the
        // listen-port handover when the daemon self-rexecs (Settings UI "Save &
        // restart": the child races the parent for the port).
        if config.listen_port != 0
            && !wait_for_tcp_port_free(
                "0.0.0.0",
                config.listen_port,
                LISTEN_PORT_HANDOVER_BACKOFFS_MS,
            )
            .await
        {
            return Err(SwarmError::PortInUse {
                port: config.listen_port,
            });
        }
        swarm
            .listen_on(
                format!("/ip4/0.0.0.0/tcp/{}", config.listen_port)
                    .parse()
                    .expect("valid multiaddr"),
            )
            .map_err(|e| SwarmError::Transport(e.to_string()))?;

        // IPv6 dual-stack listen. Best-effort: log warn but don't fail startup
        // if IPv6 unavailable (Windows without IPv6, sandboxes, etc.).
        match format!("/ip6/::/tcp/{}", config.listen_port).parse() {
            Ok(addr) => {
                if let Err(e) = swarm.listen_on(addr) {
                    tracing::warn!(
                        port = config.listen_port,
                        err = %e,
                        "swarm: IPv6 listen failed, continuing IPv4-only"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    err = %e,
                    "swarm: failed to parse IPv6 multiaddr, continuing IPv4-only"
                );
            }
        }

        // ── 5. Channels ───────────────────────────────────────────────────────
        // Capacity 4096: sized for burst of connections (e.g. 20-node cluster
        // reconnecting simultaneously). Overflow drops the event with a warn —
        // acceptable for non-critical events (ConnectionClosed, KadDiscovered).
        // PeerAuthenticated is also best-effort; the processor re-queries state
        // if needed rather than relying on event delivery guarantees.
        let (cmd_tx, cmd_rx) = mpsc::channel(4096);
        let (event_tx, event_rx) = mpsc::channel(4096);

        // ── 6. Compute Kademlia namespace key ─────────────────────────────────
        // sha2::Sha256::digest(b"/viaticum/peers/v1") — computed once, never hardcoded.
        let viaticum_namespace_key = {
            let hash = Sha256::digest(b"/viaticum/peers/v1");
            libp2p::kad::RecordKey::new(&hash)
        };

        // ── 7. Build Kademlia timers ──────────────────────────────────────────
        let republish_interval = config
            .kad_republish_interval_override
            .unwrap_or(KAD_REPUBLISH_INTERVAL);
        let discovery_interval = config
            .kad_discovery_interval_override
            .unwrap_or(KAD_DISCOVERY_INTERVAL);
        let initial_delay = config
            .kad_discovery_interval_override
            .unwrap_or(KAD_INITIAL_DISCOVERY_DELAY);

        let kad_republish_timer = {
            let mut t = tokio::time::interval(republish_interval);
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            t
        };
        let kad_discovery_timer = {
            let start = tokio::time::Instant::now() + initial_delay;
            let mut t = tokio::time::interval_at(start, discovery_interval);
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            t
        };

        // Test-only record-size amplifier (C-DK Р-10): read once, applied on the
        // first IPv4 TCP listen address.
        #[cfg(feature = "e2e-tools")]
        let e2e_loopback_aliases = match super::e2e_amp::alias_count_from_env() {
            Ok(n) => n,
            Err(e) => {
                warn!(err = %e, "e2e: loopback alias amplifier disabled");
                0
            }
        };

        // ── 8. Spawn event loop ───────────────────────────────────────────────
        let loop_state = EventLoopState {
            swarm,
            cmd_rx,
            event_tx,
            authenticated: HashMap::new(),
            device_to_peer: HashMap::new(),
            pending_cert: HashMap::new(),
            peer_addrs: HashMap::new(),
            dialed_addrs: HashMap::new(),
            pending_requests: HashMap::new(),
            pending_closest_peers: HashMap::new(),
            discovery_queries: HashSet::new(),
            our_cert: config.device_cert,
            our_x25519_pub: config.x25519_pub,
            cluster_master_pub: config.cluster_master_pub,
            cert_timeout: Duration::from_secs(config.cert_timeout_secs),
            kad_republish_timer,
            kad_discovery_timer,
            viaticum_namespace_key,
            dialing: HashSet::new(),
            bootstrap_called: false,
            relay_reservations: HashSet::new(),
            last_empty_lookup_warn: None,
            #[cfg(feature = "e2e-tools")]
            e2e_loopback_aliases,
        };
        tokio::spawn(loop_state.run());

        let handle = SwarmHandle {
            cmd_tx,
            peer_id,
            device_id,
            identity_pub: config.identity_pub,
            master_signing_key: config.master_signing_key,
            x25519_pub: config.x25519_pub,
            dropped_responses: std::sync::atomic::AtomicU64::new(0),
        };
        Ok((handle, event_rx))
    }

    /// Send a protocol Message to a device by DeviceId.
    ///
    /// Looks up the authenticated PeerId for the given DeviceId.
    /// Blocks until a response is received or the 30s timeout expires.
    /// Returns Err(SwarmError::PeerNotAuthenticated) if device is unknown.
    pub async fn send_to_device(
        &self,
        device: DeviceId,
        msg: Message,
    ) -> Result<Message, SwarmError> {
        let peer_id = self.find_peer_id_for_device(device).await?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::SendMessage {
                peer_id,
                message: Box::new(msg),
                reply: reply_tx,
            })
            .await
            .map_err(|_| SwarmError::ChannelClosed)?;

        tokio::time::timeout(Duration::from_secs(30), reply_rx)
            .await
            .map_err(|_| SwarmError::Timeout)?
            .map_err(|_| SwarmError::ChannelClosed)?
    }

    /// Initiate a connection to a peer by PeerId + Multiaddr.
    ///
    /// DeviceCertExchange happens automatically after TCP+Noise connects.
    /// The caller should watch event_rx for ProtocolEvent::PeerAuthenticated.
    pub async fn dial(&self, peer_id: PeerId, addr: Multiaddr) -> Result<(), SwarmError> {
        self.dial_addrs(peer_id, vec![addr]).await
    }

    /// Initiate ONE dial to `peer_id` over all of `addrs` (network-i2, I4).
    ///
    /// libp2p tries the addresses of a single dial in turn; issuing one dial per
    /// address instead would have every dial after the first rejected as
    /// "already dialing". Addresses may carry a `/p2p/<peer_id>` suffix or not.
    pub async fn dial_addrs(
        &self,
        peer_id: PeerId,
        addrs: Vec<Multiaddr>,
    ) -> Result<(), SwarmError> {
        self.cmd_tx
            .send(SwarmCommand::Dial { peer_id, addrs })
            .await
            .map_err(|_| SwarmError::ChannelClosed)
    }

    /// Return current listen addresses.
    pub async fn listen_addrs(&self) -> Result<Vec<Multiaddr>, SwarmError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::ListenAddrs { reply: reply_tx })
            .await
            .map_err(|_| SwarmError::ChannelClosed)?;
        reply_rx.await.map_err(|_| SwarmError::ChannelClosed)
    }

    /// Snapshot of peer counts: (connected, authenticated).
    pub async fn peer_counts(&self) -> Result<(u32, u32), SwarmError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::PeerCounts { reply: reply_tx })
            .await
            .map_err(|_| SwarmError::ChannelClosed)?;
        reply_rx.await.map_err(|_| SwarmError::ChannelClosed)
    }

    /// Snapshot of authenticated and connected DeviceId sets.
    /// authenticated ⊆ connected (cert exchange done implies live connection).
    pub async fn peer_sets(&self) -> Result<(HashSet<DeviceId>, HashSet<DeviceId>), SwarmError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::PeerSets { reply: reply_tx })
            .await
            .map_err(|_| SwarmError::ChannelClosed)?;
        reply_rx.await.map_err(|_| SwarmError::ChannelClosed)
    }

    /// Send a protocol Message to a peer by master IdentityPub.
    ///
    /// Scans the authenticated map for any device whose master identity matches.
    /// Returns Err(SwarmError::MasterNotAuthenticated) if no such device is connected.
    /// Blocks until a response is received or the 30s timeout expires.
    #[deprecated(note = "use send_to_device with DeviceId instead")]
    pub async fn send_to_master(
        &self,
        master: IdentityPub,
        msg: Message,
    ) -> Result<Message, SwarmError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::SendToMaster {
                master,
                message: Box::new(msg),
                reply: reply_tx,
            })
            .await
            .map_err(|_| SwarmError::ChannelClosed)?;

        tokio::time::timeout(Duration::from_secs(30), reply_rx)
            .await
            .map_err(|_| SwarmError::Timeout)?
            .map_err(|_| SwarmError::ChannelClosed)?
    }

    /// Build a signed PeerAnnounceMsg for broadcasting to the relay board.
    ///
    /// Sig covers identity_pub || timestamp (ε.5: node_id removed).
    pub fn build_peer_announce(
        &self,
        timestamp: viaticum_core::types::Timestamp,
    ) -> viaticum_core::messages::PeerAnnounceMsg {
        use viaticum_core::messages::build_peer_announce;

        build_peer_announce(
            self.identity_pub,
            timestamp,
            &self.master_signing_key,
            self.x25519_pub,
        )
    }

    /// Send a response on a libp2p ResponseChannel (fire-and-forget).
    ///
    /// Called by Processor dispatch_libp2p to complete each inbound request.
    /// Returns `Err(ChannelFull)` under backpressure (caller may retry or drop),
    /// `Err(ChannelClosed)` when the daemon is shutting down.
    pub fn respond(
        &self,
        channel: ResponseChannel<Message>,
        response: Message,
    ) -> Result<(), SwarmError> {
        self.cmd_tx
            .try_send(SwarmCommand::SendResponse {
                channel,
                response: Box::new(response),
            })
            .map_err(|e| match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => SwarmError::ChannelFull,
                tokio::sync::mpsc::error::TrySendError::Closed(_) => SwarmError::ChannelClosed,
            })
    }

    /// Send an RR response, making a dropped response observable (ARCH-5).
    ///
    /// The bare `let _ = swarm.respond(..)` pattern discarded `Err(ChannelFull)`
    /// silently: under burst (cmd channel, cap 4096, saturated by inbound
    /// SymbolTransfers) our own backpressure became the partner's 30s RR timeout
    /// with no log trail — and potentially a hit to our availability score at their
    /// end. This wrapper warns and bumps `dropped_responses` so the drop is visible.
    pub fn respond_logged(&self, channel: ResponseChannel<Message>, response: Message) {
        let outcome = self.respond(channel, response);
        self.record_respond_outcome(outcome);
    }

    /// Account for a `respond` outcome: on error, warn and increment the drop
    /// counter; on success, no-op. Split from `respond_logged` so the
    /// drop-accounting is unit-testable without a libp2p `ResponseChannel`
    /// (which has no public constructor).
    pub(crate) fn record_respond_outcome(&self, outcome: Result<(), SwarmError>) {
        use std::sync::atomic::Ordering;
        if let Err(e) = outcome {
            let dropped = self.dropped_responses.fetch_add(1, Ordering::Relaxed) + 1;
            warn!(
                error = %e,
                dropped_responses = dropped,
                "swarm: RR response dropped (cmd channel full/closed) — partner will see a timeout"
            );
        }
    }

    /// Total RR responses dropped due to a full/closed cmd channel (ARCH-5).
    pub fn dropped_responses(&self) -> u64 {
        self.dropped_responses
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Helper: find PeerId for a DeviceId via the event loop's device_to_peer map.
    async fn find_peer_id_for_device(&self, device: DeviceId) -> Result<PeerId, SwarmError> {
        let (reply_tx, reply_rx) = oneshot::channel::<Result<PeerId, SwarmError>>();
        self.cmd_tx
            .send(SwarmCommand::LookupPeer {
                device,
                reply: reply_tx,
            })
            .await
            .map_err(|_| SwarmError::ChannelClosed)?;
        reply_rx.await.map_err(|_| SwarmError::ChannelClosed)?
    }

    /// Test-only (`net-probe disconnect`, C-DK Р-16): close every connection to
    /// `device` (the PeerId is derived from the device key, so a peer that never
    /// authenticated can be named too). `Ok(false)` when there was none. The
    /// usual `ConnectionClosed` handling drops the peer from `authenticated`.
    #[cfg(feature = "e2e-tools")]
    pub async fn disconnect_device(&self, device: DeviceId) -> Result<bool, SwarmError> {
        let peer_id = device_id_to_peer_id(&device)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::Disconnect {
                peer_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| SwarmError::ChannelClosed)?;
        reply_rx.await.map_err(|_| SwarmError::ChannelClosed)
    }

    /// Query the Kademlia DHT for the peers closest to `key`.
    ///
    /// Issues a FIND_NODE query and returns the K closest peers found, each
    /// paired with their known listen addresses (from the kad routing table).
    ///
    /// Used by T-9 (DR walk) to discover SelfPointer write-fanout candidates
    /// (closest peers to SHA256(owner_master_pub)) and to resolve dial
    /// addresses for holders whose PeerRecord addrs are empty or stale.
    ///
    /// # Timeout
    /// The query times out after 30 seconds (matching the request-response
    /// timeout). On timeout the method returns an error; callers should treat
    /// an empty or error result as "fall back to known peer list".
    ///
    /// # Return type
    /// `Vec<(PeerId, Vec<Multiaddr>)>` — each element is a peer known to the
    /// routing table. Addrs come from the Kademlia routing table directly
    /// (populated via identify events); they may be empty for peers that are
    /// in the routing table but for which identify has not yet run.
    pub async fn get_closest_peers(&self, key: Vec<u8>) -> Result<ClosestPeersResult, SwarmError> {
        let (reply_tx, reply_rx) = oneshot::channel::<Result<ClosestPeersResult, SwarmError>>();
        self.cmd_tx
            .send(SwarmCommand::GetClosestPeers {
                key,
                reply: reply_tx,
            })
            .await
            .map_err(|_| SwarmError::ChannelClosed)?;

        tokio::time::timeout(Duration::from_secs(30), reply_rx)
            .await
            .map_err(|_| SwarmError::Timeout)?
            .map_err(|_| SwarmError::ChannelClosed)?
    }

    /// Return the known addrs for a DeviceId (identify listen addrs ∪ the address
    /// we dialed it on), each ending in exactly one `/p2p/<peer_id>`.
    ///
    /// T-12 (owner-addr propagation safety net): called after receiving a
    /// SymbolStored ack so the owner can persist the holder's dialable addrs.
    ///
    /// Returns an empty Vec if the device is not authenticated or the identify
    /// protocol has not yet completed for that peer — the caller handles this
    /// gracefully (empty addrs → skip DB write, DR falls back to Kademlia).
    pub async fn get_peer_addrs(&self, device: DeviceId) -> Vec<Multiaddr> {
        let (reply_tx, reply_rx) = oneshot::channel::<Vec<Multiaddr>>();
        if self
            .cmd_tx
            .send(SwarmCommand::GetPeerAddrs {
                device,
                reply: reply_tx,
            })
            .await
            .is_err()
        {
            return vec![];
        }
        reply_rx.await.unwrap_or_default()
    }
}

// ─── Event Loop ───────────────────────────────────────────────────────────────

/// Internal state of the swarm event loop task.
struct EventLoopState {
    swarm: libp2p::Swarm<ViaticumBehaviour>,
    cmd_rx: mpsc::Receiver<SwarmCommand>,
    event_tx: mpsc::Sender<ProtocolEvent>,

    /// PeerId → (DeviceId, IdentityPub, DeviceCertificate) for authenticated peers.
    authenticated: HashMap<PeerId, (DeviceId, IdentityPub, DeviceCertificate)>,

    /// DeviceId → PeerId reverse lookup (for send_to_device).
    device_to_peer: HashMap<DeviceId, PeerId>,

    /// PeerId → deadline for DeviceCertExchange timeout.
    /// peer_id → (deadline, attempts_so_far). Dialer side only — listener
    /// just waits for inbound cert request.
    pending_cert: HashMap<PeerId, (Instant, u8)>,

    /// PeerId → most recently identified listen_addrs. Updated on every
    /// Identify::Received; consumed when emitting PeerAuthenticated, and used
    /// to surface PeerIdentified events for already-authenticated peers so the
    /// processor can persist addresses on the PeerRecord.
    peer_addrs: HashMap<PeerId, Vec<Multiaddr>>,

    /// PeerId → address of the last outbound connection we successfully
    /// established to it (dialer side, relay circuits excluded). Never cleared
    /// on disconnect: it is the "last working" address (network-i4). Merged
    /// with `peer_addrs` by `peer_known_addrs`.
    dialed_addrs: HashMap<PeerId, Multiaddr>,

    /// OutboundRequestId → oneshot sender for send_to_device responses.
    pending_requests: HashMap<OutboundRequestId, oneshot::Sender<Result<Message, SwarmError>>>,

    /// QueryId → oneshot sender for get_closest_peers responses (T-9a).
    ///
    /// Populated when a GetClosestPeers command is received; fulfilled (and
    /// removed) when the corresponding OutboundQueryProgressed{GetClosestPeers}
    /// event fires with step.last == true. Stale entries (query completed or
    /// timed out before the command arrived) are harmlessly absent.
    pending_closest_peers:
        HashMap<QueryId, oneshot::Sender<Result<ClosestPeersResult, SwarmError>>>,

    /// QueryId set for get_closest_peers queries issued by DISCOVERY (do_kad_discovery),
    /// as opposed to the SwarmHandle API (pending_closest_peers). A discovery query's
    /// result is dialed (with addresses) rather than returned to a caller.
    discovery_queries: HashSet<QueryId>,

    our_cert: DeviceCertificate,
    our_x25519_pub: Option<[u8; 32]>,

    /// Trusted cluster master identity — the anchor for `DeviceCertificate`
    /// signature verification. Loaded from `ClusterState.master_pub()` at
    /// startup (a multi-device joiner stores the founder's identity here).
    /// MUST NOT be confused with this node's own seed-derived master pub —
    /// for any non-founder node those values differ.
    cluster_master_pub: IdentityPub,

    cert_timeout: Duration,

    // ── Kademlia (ε.3) ────────────────────────────────────────────────────────
    /// Interval for re-publishing our provider record to the DHT.
    kad_republish_timer: tokio::time::Interval,

    /// Interval for querying the DHT for new Viaticum peers.
    kad_discovery_timer: tokio::time::Interval,

    /// SHA-256 of b"/viaticum/peers/v1" — computed once at startup.
    viaticum_namespace_key: libp2p::kad::RecordKey,

    /// PeerIds currently being dialed (to avoid duplicate dials).
    /// Cleared when connection succeeds or fails.
    dialing: HashSet<PeerId>,

    /// True once bootstrap has been called at least once.
    bootstrap_called: bool,

    // ── Relay (ε.4) ───────────────────────────────────────────────────────────
    /// PeerIds of relay servers for which we have an active reservation.
    /// Used for logging and diagnostics only; not required for correctness.
    relay_reservations: HashSet<PeerId>,

    /// When the last WARN "kademlia lookup found no peers" was logged
    /// (rate limit, see `kad_stats`).
    last_empty_lookup_warn: Option<Instant>,

    /// Loopback aliases still to advertise on the first IPv4 TCP listen address
    /// (test-only amplifier, C-DK Р-10); 0 once done or when off.
    #[cfg(feature = "e2e-tools")]
    e2e_loopback_aliases: usize,
}

impl EventLoopState {
    async fn run(mut self) {
        use futures::StreamExt;
        let mut cert_check = tokio::time::interval(Duration::from_secs(1));
        // Periodic re-auth: every 10 minutes, re-issue cert request to every
        // connected peer that is not authenticated yet. Catches: cert request
        // exhausted retries (peer kept dropping requests) but the connection is
        // still alive, OR new connection arrived as listener side and the
        // dialer never sent their request.
        let mut cert_sweep = tokio::time::interval(Duration::from_secs(600));
        cert_sweep.tick().await; // skip immediate

        // Trigger Kademlia bootstrap on first iteration.
        self.do_bootstrap();

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await;
                }
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(cmd) => self.handle_command(cmd),
                        None => {
                            debug!("swarm command channel closed, event loop exiting");
                            break;
                        }
                    }
                }
                _ = cert_check.tick() => {
                    self.check_cert_timeouts().await;
                }
                _ = cert_sweep.tick() => {
                    self.sweep_unauthenticated_connected().await;
                }
                _ = self.kad_republish_timer.tick() => {
                    self.do_kad_republish();
                }
                _ = self.kad_discovery_timer.tick() => {
                    self.do_kad_discovery();
                }
            }
        }
    }

    async fn handle_swarm_event(&mut self, event: SwarmEvent<ViaticumBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!(addr = %address, "swarm listening on new address");
                #[cfg(feature = "e2e-tools")]
                self.e2e_advertise_loopback_aliases(&address);
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                debug!(peer_id = %peer_id, "connection established");
                // Clear dialing set entry now that connection is established.
                self.dialing.remove(&peer_id);

                // Dialer sends the cert first; listener waits for inbound request.
                // pending_cert is tracked only for the dialer side so the timeout
                // task can retry the request — listener has nothing to retry.
                if endpoint.is_dialer() {
                    // Remember the address that worked (network-i4). Relay circuits
                    // are not stored: they name the relay, not a route to the peer.
                    let remote = endpoint.get_remote_address();
                    if !remote.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
                        self.dialed_addrs.insert(peer_id, remote.clone());
                    }
                    let deadline = Instant::now() + self.cert_timeout;
                    self.pending_cert.insert(peer_id, (deadline, 1));
                    let msg = DeviceCertExchangeMsg {
                        cert: self.our_cert.clone(),
                        x25519_pub: self.our_x25519_pub,
                    };
                    let _req_id = self.swarm.behaviour_mut().cert.send_request(&peer_id, msg);
                    debug!(peer_id = %peer_id, "sent DeviceCertExchange as dialer (attempt 1)");
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                cause,
                ..
            } => {
                // `cause` = KeepAliveTimeout would mean libp2p's idle timeout closed a
                // link between live nodes (C-DK v3-C expects none).
                debug!(peer_id = %peer_id, num_established, cause = ?cause, "connection closed");
                let device_id = self.authenticated.remove(&peer_id).map(|(did, _, _)| did);
                if let Some(did) = device_id {
                    self.device_to_peer.remove(&did);
                }
                self.pending_cert.remove(&peer_id);
                let event = ProtocolEvent::ConnectionClosed { peer_id, device_id };
                emit_event(&self.event_tx, event);
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                warn!(peer_id = ?peer_id, error = %error, "outgoing connection error");
                // Clear dialing set so we can retry on next discovery cycle.
                if let Some(pid) = peer_id {
                    self.dialing.remove(&pid);
                }
            }
            SwarmEvent::ExternalAddrConfirmed { address } => {
                info!(addr = %address, "external address confirmed (may be relay circuit)");
            }
            SwarmEvent::ExternalAddrExpired { address } => {
                debug!(addr = %address, "external address expired");
            }
            SwarmEvent::Behaviour(behaviour_event) => {
                self.handle_behaviour_event(behaviour_event).await;
            }
            _ => {}
        }
    }

    async fn handle_behaviour_event(&mut self, event: ViaticumBehaviourEvent) {
        match event {
            ViaticumBehaviourEvent::Cert(cert_event) => {
                self.handle_cert_event(cert_event).await;
            }
            ViaticumBehaviourEvent::Viaticum(viaticum_event) => {
                self.handle_viaticum_event(viaticum_event).await;
            }
            ViaticumBehaviourEvent::Identify(identify_event) => {
                self.handle_identify_event(identify_event);
            }
            ViaticumBehaviourEvent::Kad(kad_event) => {
                self.handle_kad_event(kad_event);
            }
            ViaticumBehaviourEvent::RelayClient(relay_event) => {
                self.handle_relay_client_event(relay_event);
            }
            ViaticumBehaviourEvent::RelayServer(relay_event) => {
                self.handle_relay_server_event(relay_event);
            }
            ViaticumBehaviourEvent::Dcutr(dcutr_event) => {
                self.handle_dcutr_event(dcutr_event);
            }
        }
    }

    fn handle_identify_event(&mut self, event: libp2p::identify::Event) {
        if let libp2p::identify::Event::Received { peer_id, info, .. } = event {
            // Р-7: how many addresses the peer announced and how many went into
            // the Kademlia table (all of them, for now), and whether the peer
            // speaks our Kademlia protocol.
            debug!(
                peer_id = %peer_id,
                addrs = info.listen_addrs.len(),
                fed_to_kad = info.listen_addrs.len(),
                kad_protocol = info.protocols.contains(&KAD_PROTOCOL),
                protocols = ?info.protocols,
                "identify received"
            );
            // Feed identified addresses into Kademlia routing table.
            for addr in &info.listen_addrs {
                self.swarm
                    .behaviour_mut()
                    .kad
                    .add_address(&peer_id, addr.clone());
            }
            // Stash addresses for use when cert exchange completes.
            if !info.listen_addrs.is_empty() {
                self.peer_addrs.insert(peer_id, info.listen_addrs.clone());
                // If peer is already authenticated, surface the (possibly
                // refreshed) addrs to the processor so it can persist them —
                // together with the address we dialed it on (network-i4).
                if let Some((device_id, _, _)) = self.authenticated.get(&peer_id) {
                    emit_event(
                        &self.event_tx,
                        ProtocolEvent::PeerIdentified {
                            device_id: *device_id,
                            listen_addrs: self.peer_known_addrs(&peer_id),
                        },
                    );
                }
            }
        }
    }

    fn handle_relay_client_event(&mut self, event: libp2p::relay::client::Event) {
        use libp2p::relay::client::Event;
        match event {
            Event::ReservationReqAccepted {
                relay_peer_id,
                renewal,
                limit: _,
            } => {
                info!(
                    relay_peer_id = %relay_peer_id,
                    renewal,
                    "relay reservation accepted"
                );
                self.relay_reservations.insert(relay_peer_id);
            }
            Event::OutboundCircuitEstablished {
                relay_peer_id,
                limit: _,
            } => {
                debug!(relay_peer_id = %relay_peer_id, "outbound relay circuit established");
            }
            Event::InboundCircuitEstablished {
                src_peer_id,
                limit: _,
            } => {
                debug!(src_peer_id = %src_peer_id, "inbound relay circuit established (we are relay)");
            }
        }
    }

    fn handle_relay_server_event(&mut self, event: libp2p::relay::Event) {
        use libp2p::relay::Event;
        match event {
            Event::ReservationReqAccepted {
                src_peer_id,
                renewed,
            } => {
                info!(
                    src_peer_id = %src_peer_id,
                    renewed,
                    "relay server: accepted reservation from peer"
                );
            }
            Event::ReservationReqDenied { src_peer_id, .. } => {
                debug!(src_peer_id = %src_peer_id, "relay server: denied reservation (limits)");
            }
            Event::CircuitReqAccepted {
                src_peer_id,
                dst_peer_id,
            } => {
                debug!(
                    src_peer_id = %src_peer_id,
                    dst_peer_id = %dst_peer_id,
                    "relay server: circuit request accepted"
                );
            }
            Event::CircuitReqDenied {
                src_peer_id,
                dst_peer_id,
                ..
            } => {
                debug!(
                    src_peer_id = %src_peer_id,
                    dst_peer_id = %dst_peer_id,
                    "relay server: circuit request denied"
                );
            }
            Event::CircuitClosed {
                src_peer_id,
                dst_peer_id,
                ..
            } => {
                debug!(
                    src_peer_id = %src_peer_id,
                    dst_peer_id = %dst_peer_id,
                    "relay server: circuit closed"
                );
            }
            _ => {}
        }
    }

    fn handle_dcutr_event(&mut self, event: libp2p::dcutr::Event) {
        // dcutr::Event is a struct with remote_peer_id and result fields.
        match event.result {
            Ok(connection_id) => {
                info!(
                    peer_id = %event.remote_peer_id,
                    connection_id = ?connection_id,
                    "dcutr: hole punch succeeded, direct connection established"
                );
            }
            Err(ref e) => {
                debug!(
                    peer_id = %event.remote_peer_id,
                    error = %e,
                    "dcutr: hole punch failed, keeping relay connection"
                );
            }
        }
    }

    async fn handle_cert_event(
        &mut self,
        event: request_response::Event<DeviceCertExchangeMsg, DeviceCertExchangeMsg>,
    ) {
        match event {
            // Listener side: receives dialer's cert request.
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                self.on_cert_request(peer, request, channel).await;
            }
            // Dialer side: receives listener's cert response.
            request_response::Event::Message {
                peer,
                message: request_response::Message::Response { response, .. },
                ..
            } => {
                self.on_cert_response(peer, response).await;
            }
            request_response::Event::OutboundFailure { peer, error, .. } => {
                warn!(peer_id = %peer, error = %error, "cert outbound failure");
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                warn!(peer_id = %peer, error = %error, "cert inbound failure");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    async fn on_cert_request(
        &mut self,
        peer_id: PeerId,
        request: DeviceCertExchangeMsg,
        channel: ResponseChannel<DeviceCertExchangeMsg>,
    ) {
        debug!(peer_id = %peer_id, "received cert request (listener side)");

        let path = match verify_cert_for_peer(&peer_id, &request.cert, &self.cluster_master_pub) {
            Ok(p) => p,
            Err(reason) => {
                warn!(
                    peer_id = %peer_id,
                    reason = %reason,
                    "cert verification failed, closing connection"
                );
                self.swarm.disconnect_peer_id(peer_id).ok();
                return;
            }
        };

        // Send our own cert as response.
        let response = DeviceCertExchangeMsg {
            cert: self.our_cert.clone(),
            x25519_pub: self.our_x25519_pub,
        };
        if self
            .swarm
            .behaviour_mut()
            .cert
            .send_response(channel, response)
            .is_err()
        {
            warn!(peer_id = %peer_id, "failed to send cert response (connection closed?)");
            return;
        }

        self.record_authenticated(peer_id, request, path).await;
    }

    async fn on_cert_response(&mut self, peer_id: PeerId, response: DeviceCertExchangeMsg) {
        debug!(peer_id = %peer_id, "received cert response (dialer side)");

        let path = match verify_cert_for_peer(&peer_id, &response.cert, &self.cluster_master_pub) {
            Ok(p) => p,
            Err(reason) => {
                warn!(
                    peer_id = %peer_id,
                    reason = %reason,
                    "cert response verification failed, closing connection"
                );
                self.swarm.disconnect_peer_id(peer_id).ok();
                return;
            }
        };

        self.record_authenticated(peer_id, response, path).await;
    }

    /// Record a successfully verified peer in the authenticated maps.
    async fn record_authenticated(
        &mut self,
        peer_id: PeerId,
        msg: DeviceCertExchangeMsg,
        path: CertTrustPath,
    ) {
        let device_id = msg.cert.device_id;
        let identity_pub = msg.cert.master_pub_key;

        self.authenticated
            .insert(peer_id, (device_id, identity_pub, msg.cert.clone()));
        self.device_to_peer.insert(device_id, peer_id);
        self.pending_cert.remove(&peer_id);

        info!(
            peer_id = %peer_id,
            device_id = %device_id,
            identity_pub = %identity_pub,
            path = ?path,
            "peer authenticated"
        );

        let known_addrs = self.peer_known_addrs(&peer_id);
        let event = ProtocolEvent::PeerAuthenticated {
            peer_id,
            device_id,
            identity_pub,
            device_cert: msg.cert,
            x25519_pub: msg.x25519_pub,
            listen_addrs: known_addrs,
        };
        emit_event(&self.event_tx, event);

        // If we already saw this peer's identify before cert exchange, surface
        // those addrs now as well. The processor no longer depends on this (the
        // addrs ride on PeerAuthenticated above), but the DR event loops persist
        // addresses only from PeerIdentified.
        if self.peer_addrs.get(&peer_id).is_some_and(|a| !a.is_empty()) {
            emit_event(
                &self.event_tx,
                ProtocolEvent::PeerIdentified {
                    device_id,
                    listen_addrs: self.peer_known_addrs(&peer_id),
                },
            );
        }
    }

    /// All addresses we know for `peer_id`: the address we last dialed it on
    /// (first — it is known to work) ∪ its identify listen addrs. Normalized by
    /// [`normalize_peer_addrs`]. Used for every address set the swarm hands out
    /// (PeerAuthenticated, PeerIdentified, GetPeerAddrs); Kademlia is fed the raw
    /// identify addrs separately.
    fn peer_known_addrs(&self, peer_id: &PeerId) -> Vec<Multiaddr> {
        let dialed = self.dialed_addrs.get(peer_id).into_iter();
        let identified = self.peer_addrs.get(peer_id).into_iter().flatten();
        normalize_peer_addrs(*peer_id, dialed.chain(identified))
    }

    async fn handle_viaticum_event(&mut self, event: request_response::Event<Message, Message>) {
        match event {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                // Only deliver if peer is authenticated.
                if let Some((from_device, from_master, _)) = self.authenticated.get(&peer) {
                    let from_device = *from_device;
                    let from_master = *from_master;
                    let ev = ProtocolEvent::InboundRequest {
                        from_device,
                        from_master,
                        message: request,
                        response_channel: channel,
                    };
                    emit_event(&self.event_tx, ev);
                } else {
                    warn!(
                        peer_id = %peer,
                        "dropping inbound request from unauthenticated peer"
                    );
                    // Drop channel — closes the request stream cleanly.
                }
            }
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(reply) = self.pending_requests.remove(&request_id) {
                    let _ = reply.send(Ok(response));
                } else {
                    warn!(
                        peer_id = %peer,
                        request_id = ?request_id,
                        "received response for unknown request_id"
                    );
                }
            }
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                warn!(peer_id = %peer, error = %error, "viaticum outbound failure");
                if let Some(reply) = self.pending_requests.remove(&request_id) {
                    let _ = reply.send(Err(SwarmError::RequestFailed(error.to_string())));
                }
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                warn!(peer_id = %peer, error = %error, "viaticum inbound failure");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    // ── Kademlia methods (ε.3) ────────────────────────────────────────────────

    /// Initiate Kademlia bootstrap (FIND_NODE queries to fill the routing table).
    ///
    /// Called once at startup. If routing table is empty (no bootstrap peers),
    /// bootstrap returns NoKnownPeers; we log a warning and retry on the next
    /// republish tick.
    fn do_bootstrap(&mut self) {
        if !self.bootstrap_called {
            match self.swarm.behaviour_mut().kad.bootstrap() {
                Ok(query_id) => {
                    debug!(query_id = ?query_id, "kademlia bootstrap started");
                    self.bootstrap_called = true;
                }
                Err(e) => {
                    warn!(error = ?e, "kademlia bootstrap failed (no known peers?)");
                }
            }
        }
    }

    /// Publish our provider record: "I am a Viaticum node."
    ///
    /// Called after successful bootstrap and every KAD_REPUBLISH_INTERVAL.
    fn do_kad_republish(&mut self) {
        let key = self.viaticum_namespace_key.clone();
        match self.swarm.behaviour_mut().kad.start_providing(key) {
            Ok(query_id) => {
                debug!(query_id = ?query_id, "kademlia start_providing issued");
            }
            Err(e) => {
                warn!(error = %e, "kademlia start_providing failed");
            }
        }
    }

    /// Query DHT for other Viaticum nodes.
    ///
    /// Called every KAD_DISCOVERY_INTERVAL, first time after KAD_INITIAL_DISCOVERY_DELAY.
    fn do_kad_discovery(&mut self) {
        let key = self.viaticum_namespace_key.clone();
        let query_id = self.swarm.behaviour_mut().kad.get_providers(key);
        debug!(query_id = ?query_id, "kademlia get_providers issued");

        // Address-carrying discovery: get_closest_peers returns PeerInfo{peer_id, addrs},
        // unlike get_providers (PeerIds only). Querying our OWN id fills our DHT
        // neighborhood with addresses learned from the bootstrap seed, so a star-spoke
        // that only knows the seed can reach siblings. The seed answers with the closest
        // peers to our id INCLUDING their addresses (it knows everyone who dialed it).
        let self_key = self.swarm.local_peer_id().to_bytes();
        let qid = self.swarm.behaviour_mut().kad.get_closest_peers(self_key);
        self.discovery_queries.insert(qid);
        debug!(query_id = ?qid, "kademlia get_closest_peers (discovery) issued");
    }

    /// Dial a peer discovered via DHT if not already connected or dialing.
    fn dial_discovered_peer(&mut self, peer_id: PeerId, addrs: Vec<Multiaddr>) {
        // Skip self.
        if peer_id == *self.swarm.local_peer_id() {
            return;
        }
        // Skip already authenticated.
        if self.authenticated.contains_key(&peer_id) {
            return;
        }
        // Skip already dialing.
        if self.dialing.contains(&peer_id) {
            return;
        }
        // Skip already connected (cert exchange may be pending).
        if self.swarm.is_connected(&peer_id) {
            return;
        }

        let opts = if addrs.is_empty() {
            DialOpts::peer_id(peer_id).build()
        } else {
            DialOpts::peer_id(peer_id).addresses(addrs).build()
        };

        match self.swarm.dial(opts) {
            Ok(_) => {
                info!(peer_id = %peer_id, "dht: dialing discovered peer");
                self.dialing.insert(peer_id);
            }
            Err(e) => {
                debug!(peer_id = %peer_id, error = %e, "dht: dial failed");
            }
        }
    }

    /// Handle Kademlia behaviour events.
    fn handle_kad_event(&mut self, event: libp2p::kad::Event) {
        use libp2p::kad::{Event, QueryResult};

        match event {
            Event::OutboundQueryProgressed {
                id,
                result,
                step,
                stats,
            } => match result {
                QueryResult::Bootstrap(Ok(bootstrap_ok)) if bootstrap_ok.num_remaining == 0 => {
                    info!("kademlia bootstrap complete");
                    // Immediately start providing after successful bootstrap.
                    self.do_kad_republish();
                }
                QueryResult::Bootstrap(Err(e)) => {
                    warn!(error = ?e, "kademlia bootstrap failed");
                }
                QueryResult::StartProviding(Ok(ok)) => {
                    debug!(key = ?ok.key, "kademlia: provider record published");
                }
                QueryResult::StartProviding(Err(e)) => {
                    warn!(error = ?e, "kademlia: start_providing failed");
                }
                QueryResult::GetProviders(Ok(ok)) => {
                    use libp2p::kad::GetProvidersOk;
                    use viaticum_core::constants::{MAX_CONCURRENT_DISCOVERY_DIALS, TARGET_PEERS};
                    match ok {
                        GetProvidersOk::FoundProviders { providers, .. } => {
                            let count = providers.len();
                            // Skip discovery if we already have enough authenticated peers.
                            // Cold backup needs a stable small set, not unbounded growth.
                            let auth_count = self.authenticated.len();
                            if auth_count >= TARGET_PEERS {
                                debug!(
                                    count,
                                    auth_count,
                                    target = TARGET_PEERS,
                                    "dht: skipping discovery — target peer count reached"
                                );
                            } else {
                                debug!(count, "dht: found providers");
                                // Cap concurrent dials to avoid burst saturating
                                // pending_cert / check_cert_timeouts under heavy DHT.
                                let provider_list: Vec<PeerId> = providers
                                    .into_iter()
                                    .take(MAX_CONCURRENT_DISCOVERY_DIALS)
                                    .collect();
                                for peer_id in provider_list {
                                    self.dial_discovered_peer(peer_id, vec![]);
                                }
                            }
                        }
                        GetProvidersOk::FinishedWithNoAdditionalRecord { .. } => {
                            debug!("dht: get_providers query complete");
                        }
                    }
                }
                QueryResult::GetProviders(Err(e)) => {
                    warn!(error = ?e, "dht: get_providers failed");
                }
                // T-9a: GetClosestPeers result — fulfill the pending oneshot.
                //
                // libp2p-kad emits GetClosestPeers with step.last == true in a
                // single final event. We check step.last defensively; if a
                // future library version emits intermediate steps, we skip them
                // (only fulfill on final step to avoid double-send on the oneshot).
                //
                // Both Ok and Err(Timeout) variants include a peer list. On
                // Timeout we return whatever peers the query collected, so
                // callers get the best-effort result (DR callers treat a small
                // list gracefully). If no pending oneshot exists for this id
                // (e.g. the caller already timed out its own await), we simply
                // drop the result.
                QueryResult::GetClosestPeers(result) => {
                    if !step.last {
                        // Intermediate step — not expected for GetClosestPeers,
                        // but skip rather than double-send just in case.
                        return;
                    }
                    // Extract the peer list once (shared by both routes). Both Ok and
                    // Err(Timeout) carry a peer list; on Timeout we keep whatever the
                    // query collected (best-effort).
                    let peer_list: Vec<(PeerId, Vec<Multiaddr>)> = match result {
                        Ok(ok) => ok
                            .peers
                            .into_iter()
                            .map(|pi| (pi.peer_id, pi.addrs))
                            .collect(),
                        Err(e) => {
                            debug!(
                                query_id = ?id,
                                error = ?e,
                                "dht: get_closest_peers timeout, returning partial result"
                            );
                            match e {
                                libp2p::kad::GetClosestPeersError::Timeout { peers, .. } => {
                                    peers.into_iter().map(|pi| (pi.peer_id, pi.addrs)).collect()
                                }
                            }
                        }
                    };
                    self.log_lookup_stats(id, &stats, peer_list.len());

                    // Route by query origin: SwarmHandle API vs DISCOVERY.
                    if let Some(reply) = self.pending_closest_peers.remove(&id) {
                        // SwarmHandle API path (unchanged behavior — DR walk depends
                        // on the oneshot receiving exactly this list).
                        let _ = reply.send(Ok(peer_list));
                    } else if self.discovery_queries.remove(&id) {
                        // Discovery path: dial the discovered peers WITH their addresses.
                        let dials = discovery_dial_candidates(peer_list, self.authenticated.len());
                        debug!(
                            query_id = ?id,
                            count = dials.len(),
                            "dht: dialing discovered peers (address-carrying)"
                        );
                        for (peer_id, addrs) in dials {
                            self.dial_discovered_peer(peer_id, addrs);
                        }
                    } else {
                        debug!(
                            query_id = ?id,
                            "dht: get_closest_peers result with no pending caller"
                        );
                    }
                }
                _ => {} // GetRecord, PutRecord, RepublishProvider — ignore
            },
            Event::RoutingUpdated {
                peer,
                is_new_peer,
                addresses,
                ..
            } => {
                debug!(
                    peer_id = %peer,
                    is_new_peer,
                    addrs = addresses.len(),
                    "kademlia routing table updated"
                );
            }
            Event::UnroutablePeer { peer } => {
                debug!(peer_id = %peer, "kademlia: peer is unroutable");
            }
            _ => {}
        }
    }

    /// Р-7 (spec §2.4): the counters of every finished get_closest_peers
    /// (DEBUG), and a rate-limited WARN when a non-empty table gave nothing —
    /// the signature that tells an oversized answer (H1) from an overloaded seed
    /// (H2) or an empty table (H4).
    fn log_lookup_stats(&mut self, id: QueryId, stats: &libp2p::kad::QueryStats, found: usize) {
        use super::kad_stats::{LookupStats, empty_lookup_warn_due};
        let s = LookupStats::from_query(stats);
        let table_entries: usize = self
            .swarm
            .behaviour_mut()
            .kad
            .kbuckets()
            .map(|b| b.num_entries())
            .sum();
        debug!(
            query_id = ?id,
            count = found,
            requests = s.requests,
            successes = s.successes,
            failures = s.failures,
            duration_ms = s.duration_ms,
            table_entries,
            "dht: get_closest_peers complete"
        );
        let now = Instant::now();
        if empty_lookup_warn_due(self.last_empty_lookup_warn, now, table_entries, found) {
            self.last_empty_lookup_warn = Some(now);
            warn!(
                requests = s.requests,
                successes = s.successes,
                failures = s.failures,
                duration_ms = s.duration_ms,
                table_entries,
                "kademlia lookup found no peers"
            );
        }
    }

    /// Test-only amplifier (C-DK Р-10): on the first IPv4 TCP listen address,
    /// advertise the loopback aliases of its port as external addresses.
    #[cfg(feature = "e2e-tools")]
    fn e2e_advertise_loopback_aliases(&mut self, listen: &Multiaddr) {
        if self.e2e_loopback_aliases == 0 {
            return;
        }
        let aliases = super::e2e_amp::loopback_alias_addrs(listen, self.e2e_loopback_aliases);
        if aliases.is_empty() {
            return;
        }
        let n = aliases.len();
        for alias in aliases {
            self.swarm.add_external_address(alias);
        }
        self.e2e_loopback_aliases = 0;
        info!(listen = %listen, "e2e: advertising {n} loopback aliases");
    }

    fn handle_command(&mut self, cmd: SwarmCommand) {
        match cmd {
            SwarmCommand::SendMessage {
                peer_id,
                message,
                reply,
            } => {
                if !self.authenticated.contains_key(&peer_id) {
                    // Find device_id for error reporting (best-effort).
                    let device_id = self
                        .device_to_peer
                        .iter()
                        .find(|(_, pid)| **pid == peer_id)
                        .map(|(did, _)| *did)
                        .unwrap_or(DeviceId([0u8; 32]));
                    let _ = reply.send(Err(SwarmError::PeerNotAuthenticated(device_id)));
                    return;
                }
                let req_id = self
                    .swarm
                    .behaviour_mut()
                    .viaticum
                    .send_request(&peer_id, *message);
                self.pending_requests.insert(req_id, reply);
            }
            SwarmCommand::SendToMaster {
                master,
                message,
                reply,
            } => {
                // Scan authenticated map for first device with matching master identity.
                let peer_id = self
                    .authenticated
                    .iter()
                    .find(|(_, (_, identity_pub, _))| *identity_pub == master)
                    .map(|(pid, _)| *pid);

                match peer_id {
                    None => {
                        let _ = reply.send(Err(SwarmError::MasterNotAuthenticated(master)));
                    }
                    Some(pid) => {
                        let req_id = self
                            .swarm
                            .behaviour_mut()
                            .viaticum
                            .send_request(&pid, *message);
                        self.pending_requests.insert(req_id, reply);
                    }
                }
            }
            SwarmCommand::Dial { peer_id, addrs } => {
                let dial_opts = DialOpts::peer_id(peer_id).addresses(addrs).build();
                if let Err(e) = self.swarm.dial(dial_opts) {
                    // "Already connected" is expected when DR re-dials bootstrap peers
                    // before the already_auth skip check catches them all (race between
                    // peer_sets snapshot and event-loop cert-exchange completion).
                    // Log at DEBUG to avoid noise; other errors stay at WARN.
                    let is_already_connected = e.to_string().contains("already connected");
                    if is_already_connected {
                        debug!(peer_id = %peer_id, error = %e, "dial skipped — already connected");
                    } else {
                        warn!(peer_id = %peer_id, error = %e, "dial failed");
                    }
                }
            }
            SwarmCommand::ListenAddrs { reply } => {
                let addrs: Vec<Multiaddr> = self.swarm.listeners().cloned().collect();
                let _ = reply.send(addrs);
            }
            SwarmCommand::PeerCounts { reply } => {
                let connected = self.swarm.connected_peers().count() as u32;
                let authenticated = self.authenticated.len() as u32;
                let _ = reply.send((connected, authenticated));
            }
            SwarmCommand::PeerSets { reply } => {
                let auth_devices: HashSet<DeviceId> = self
                    .authenticated
                    .values()
                    .map(|(did, _, _)| *did)
                    .collect();
                let mut conn_devices: HashSet<DeviceId> = HashSet::new();
                for peer_id in self.swarm.connected_peers() {
                    if let Some((did, _, _)) = self.authenticated.get(peer_id) {
                        conn_devices.insert(*did);
                    }
                }
                // conn_devices currently only includes auth ones (we don't keep
                // a peer_id → device_id map for unauthenticated). That's fine —
                // `auth ⊆ conn` is preserved; "conn but not auth" simply isn't
                // attributable to a specific master and so isn't shown per-row.
                let _ = reply.send((auth_devices, conn_devices));
            }
            SwarmCommand::LookupPeer { device, reply } => {
                let result = self
                    .device_to_peer
                    .get(&device)
                    .copied()
                    .ok_or(SwarmError::PeerNotAuthenticated(device));
                let _ = reply.send(result);
            }
            SwarmCommand::SendResponse { channel, response } => {
                if self
                    .swarm
                    .behaviour_mut()
                    .viaticum
                    .send_response(channel, *response)
                    .is_err()
                {
                    warn!("send_response failed: channel already closed");
                }
            }
            // T-9a: Issue a Kademlia FIND_NODE query and register the pending reply.
            //
            // get_closest_peers accepts any K where K: Into<kbucket::Key<K>> + Into<Vec<u8>>
            // + Clone. Vec<u8> satisfies this via the libp2p-kad blanket impl.
            // The result arrives as Event::OutboundQueryProgressed{GetClosestPeers}
            // and is handled in handle_kad_event.
            SwarmCommand::GetClosestPeers { key, reply } => {
                let query_id = self.swarm.behaviour_mut().kad.get_closest_peers(key);
                debug!(query_id = ?query_id, "dht: get_closest_peers query issued");
                self.pending_closest_peers.insert(query_id, reply);
            }
            // T-12: Return known addrs for a DeviceId.
            //
            // Looks up the PeerId for the device via device_to_peer, then returns
            // identify addrs ∪ dialed addr (normalized, see peer_known_addrs).
            // Returns empty Vec if the device is not authenticated or we have no
            // address for it yet — callers handle this gracefully.
            SwarmCommand::GetPeerAddrs { device, reply } => {
                let addrs = self
                    .device_to_peer
                    .get(&device)
                    .map(|peer_id| self.peer_known_addrs(peer_id))
                    .unwrap_or_default();
                let _ = reply.send(addrs);
            }
            #[cfg(feature = "e2e-tools")]
            SwarmCommand::Disconnect { peer_id, reply } => {
                let was_connected = self.swarm.disconnect_peer_id(peer_id).is_ok();
                info!(peer_id = %peer_id, was_connected, "e2e: disconnect peer");
                let _ = reply.send(was_connected);
            }
        }
    }

    /// Periodic sweep: every connected peer that is not yet authenticated
    /// gets a fresh cert request. Resets retry count to 1. Idempotent on the
    /// listener side (it just responds with its own cert).
    async fn sweep_unauthenticated_connected(&mut self) {
        let connected: Vec<PeerId> = self.swarm.connected_peers().copied().collect();
        let mut sent = 0u32;
        for peer_id in connected {
            if self.authenticated.contains_key(&peer_id) {
                continue;
            }
            let new_deadline = Instant::now() + self.cert_timeout;
            self.pending_cert.insert(peer_id, (new_deadline, 1));
            let msg = DeviceCertExchangeMsg {
                cert: self.our_cert.clone(),
                x25519_pub: self.our_x25519_pub,
            };
            let _req_id = self.swarm.behaviour_mut().cert.send_request(&peer_id, msg);
            sent += 1;
        }
        if sent > 0 {
            info!(
                unauthenticated_connected = sent,
                "cert sweep: re-issued cert requests"
            );
        }
    }

    async fn check_cert_timeouts(&mut self) {
        // Cert request can be lost on flaky links (proxies, NAT-traversal,
        // tunnel jitter). Retry up to MAX_CERT_RETRIES before tearing down
        // the connection — a fresh dial would have to come from peer
        // discovery, which may not happen for hours.
        const MAX_CERT_RETRIES: u8 = 10;

        let now = Instant::now();
        let timed_out: Vec<(PeerId, u8)> = self
            .pending_cert
            .iter()
            .filter(|(_, (deadline, _))| *deadline < now)
            .map(|(pid, (_, attempts))| (*pid, *attempts))
            .collect();

        for (peer_id, attempts) in timed_out {
            // pending_cert only contains dialer-side entries (see ConnectionEstablished),
            // so we always retry until the cap.
            if attempts < MAX_CERT_RETRIES {
                let new_deadline = Instant::now() + self.cert_timeout;
                self.pending_cert
                    .insert(peer_id, (new_deadline, attempts + 1));
                let msg = DeviceCertExchangeMsg {
                    cert: self.our_cert.clone(),
                    x25519_pub: self.our_x25519_pub,
                };
                let _req_id = self.swarm.behaviour_mut().cert.send_request(&peer_id, msg);
                warn!(
                    peer_id = %peer_id,
                    attempt = attempts + 1,
                    max = MAX_CERT_RETRIES,
                    "cert exchange timed out — retrying"
                );
                continue;
            }

            warn!(
                peer_id = %peer_id,
                attempts,
                "cert exchange exhausted retries, closing connection"
            );
            self.pending_cert.remove(&peer_id);
            self.swarm.disconnect_peer_id(peer_id).ok();
            let ev = ProtocolEvent::ConnectionClosed {
                peer_id,
                device_id: None,
            };
            emit_event(&self.event_tx, ev);
        }
    }
}

/// Verify that a DeviceCertificate belongs to the given PeerId and was
/// signed by the trusted cluster master.
///
/// Two checks:
/// 1. cert.device_id → expected PeerId matches the Noise-authenticated PeerId.
/// 2. cert signature is valid under `cluster_master_pub`.
///
/// SECURITY: `cluster_master_pub` MUST be the cluster master pub stored in
/// our local `ClusterState` (set when this node joined or founded the
/// cluster), NOT the per-node seed-derived master and NOT `cert.master_pub_key`.
///
/// - Using `cert.master_pub_key` is tautological — any self-signed cert passes.
/// - Using this node's own seed-derived master is correct for a single-device
///   cluster (where founder = self) but rejects every legitimate cert in a
///   multi-device cluster (founder ≠ self → signature fails to verify).
pub(crate) fn verify_cert_for_peer(
    peer_id: &PeerId,
    cert: &DeviceCertificate,
    own_cluster_master_pub: &IdentityPub,
) -> Result<CertTrustPath, String> {
    // Check 1: does cert.device_id match the Noise-authenticated PeerId?
    let expected_peer_id = device_id_to_peer_id(&cert.device_id)
        .map_err(|e| format!("cannot derive PeerId from cert.device_id: {e}"))?;
    if *peer_id != expected_peer_id {
        return Err(format!(
            "cert.device_id mismatch: expected peer_id {expected_peer_id}, got {peer_id}"
        ));
    }

    // Check 2: split by master match.
    //
    // Intra path: cert is from our own cluster. Verify under own cluster master
    // (HIGH-1 strict anchor — no impersonation possible).
    //
    // Cross path: cert is from a different cluster. Verify under cert.master_pub_key
    // (self-signed). Peer is authenticated as a stranger; trust formula starts
    // them at effective trust ≈ 0 (no MasterTrustRecord for their master).
    if cert.master_pub_key == *own_cluster_master_pub {
        verify_device_certificate(cert, own_cluster_master_pub)
            .map_err(|e| format!("intra-cluster cert: {e}"))?;
        Ok(CertTrustPath::Intra)
    } else {
        verify_device_certificate(cert, &cert.master_pub_key)
            .map_err(|e| format!("cross-cluster cert self-signature: {e}"))?;
        Ok(CertTrustPath::Cross)
    }
}

/// Emit a ProtocolEvent to the consumer channel (best-effort, non-blocking).
///
/// If the channel is full (backpressure from slow consumer) or closed (daemon
/// shutting down), the event is dropped with a warning. The 4096-capacity channel
/// absorbs connection bursts; overflow only occurs if the processor stalls for
/// an extended period, which is a symptom of a larger problem worth logging.
fn emit_event(tx: &mpsc::Sender<ProtocolEvent>, event: ProtocolEvent) {
    if tx.try_send(event).is_err() {
        warn!("event_tx full or closed, dropping protocol event");
    }
}

/// Backoff schedule of the listen-port probe: ~63.5 s in total. Matches the
/// DB-open retry envelope: on a self-rexec the parent releases the port during
/// the same shutdown that releases the DB lock.
pub(crate) const LISTEN_PORT_HANDOVER_BACKOFFS_MS: &[u64] =
    &[0, 500, 1000, 2000, 4000, 8000, 16000, 16000, 16000];

/// Probe the given TCP port with a plain bind (no SO_REUSEPORT). If another
/// process holds it (the previous daemon during a self-rexec, a second
/// viaticum, an unrelated service), retry along `backoffs_ms`. Returns true as
/// soon as the port is free, false if it is still held after the last attempt.
pub(crate) async fn wait_for_tcp_port_free(host: &str, port: u16, backoffs_ms: &[u64]) -> bool {
    use std::net::TcpListener;
    let addr = format!("{host}:{port}");
    for (i, ms) in backoffs_ms.iter().enumerate() {
        if *ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(*ms)).await;
        }
        match TcpListener::bind(&addr) {
            Ok(l) => {
                drop(l); // release immediately so libp2p can rebind
                if i > 0 {
                    info!(port, attempts = i + 1, "listen port became available");
                }
                return true;
            }
            Err(e) => {
                warn!(port, attempt = i + 1, error = %e, "listen port not free yet, retrying");
            }
        }
    }
    warn!(
        port,
        "listen port still held after retries; refusing to start"
    );
    false
}

// ─── Helper functions ─────────────────────────────────────────────────────────

/// Strip the terminal `/p2p/<id>` component(s) of an address of `peer_id`.
///
/// Returns the transport part (what to dial), or `Err(found)` when the
/// terminal `/p2p/` names a different peer — such an address is not a route to
/// `peer_id` and must not be dialed under its id (network-i2, I3). Only the
/// TERMINAL component identifies the target: a relay-circuit address
/// (`…/p2p/<relay>/p2p-circuit`) carries the relay's id in the middle and is
/// left intact.
pub fn strip_peer_suffix(addr: &Multiaddr, peer_id: PeerId) -> Result<Multiaddr, PeerId> {
    let mut transport = addr.clone();
    while let Some(Protocol::P2p(found)) = transport.iter().last() {
        if found != peer_id {
            return Err(found);
        }
        transport.pop();
    }
    Ok(transport)
}

/// Normalize a set of addresses of `peer_id`: each result ends in exactly one
/// `/p2p/<peer_id>`, duplicates (after normalization) removed, first-seen order
/// kept. Addresses whose terminal `/p2p/` names another peer are dropped.
///
/// This is the stored form of `PeerRecord.addrs` (`processor/peer.rs`) and the
/// form DR's `parse_multiaddr_with_peer_id` expects for `HolderHint.addrs`.
pub fn normalize_peer_addrs<'a>(
    peer_id: PeerId,
    addrs: impl IntoIterator<Item = &'a Multiaddr>,
) -> Vec<Multiaddr> {
    let mut out: Vec<Multiaddr> = Vec::new();
    for addr in addrs {
        match strip_peer_suffix(addr, peer_id) {
            Ok(transport) => {
                let full = transport.with(Protocol::P2p(peer_id));
                if !out.contains(&full) {
                    out.push(full);
                }
            }
            Err(found) => {
                debug!(peer_id = %peer_id, addr = %addr, found = %found,
                    "dropping peer address with a foreign /p2p/ suffix");
            }
        }
    }
    out
}

/// Extract PeerId from a Multiaddr that ends in /p2p/<base58>.
///
/// Returns None if no /p2p component is present.
pub fn peer_id_from_multiaddr(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|proto| {
        if let libp2p::multiaddr::Protocol::P2p(peer_id) = proto {
            PeerId::from_multihash(peer_id.into()).ok()
        } else {
            None
        }
    })
}

/// Return the hardcoded IPFS DHT bootstrap nodes (PeerId + Multiaddr pairs).
///
/// Source: https://github.com/ipfs/go-ipfs-config/blob/master/bootstrap_peers.go
/// These are the canonical IPFS bootstrap nodes for the /ipfs/kad/1.0.0 DHT.
pub fn ipfs_bootstrap_peers() -> Vec<(PeerId, Multiaddr)> {
    const BOOTSTRAP_ADDRS: &[&str] = &[
        "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
        "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
        "/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
        "/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
        "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
        "/ip4/104.236.179.241/tcp/4001/p2p/QmSoLPppuBtQSGwKDZT2M73ULpjvfd3aZ6ha4oFGL1KrGM",
        "/ip4/128.199.219.111/tcp/4001/p2p/QmSoLSafTMBsPKadTEgaXctDQVcqN88CNLHXMkTNwMKPnu",
        "/ip4/104.236.76.40/tcp/4001/p2p/QmSoLV4Bbm51jM9C4gDYZQ9Cy3U6aXMJDAbzgu2fzaDs64",
    ];

    BOOTSTRAP_ADDRS
        .iter()
        .filter_map(|addr_str| {
            let addr: Multiaddr = addr_str.parse().ok()?;
            let peer_id = peer_id_from_multiaddr(&addr)?;
            Some((peer_id, addr))
        })
        .collect()
}

/// Convert a Viaticum DeviceId (Ed25519 pubkey bytes) to a libp2p PeerId.
///
/// This is the canonical mapping. device_id.0 are raw Ed25519 public key bytes
/// (same format as ed25519-dalek VerifyingKey::to_bytes()).
/// PeerId = multihash(Ed25519 pubkey) — deterministic, no secret needed.
pub fn device_id_to_peer_id(device_id: &DeviceId) -> Result<PeerId, SwarmError> {
    let pub_key = ed25519::PublicKey::try_from_bytes(&device_id.0)
        .map_err(|e| SwarmError::Transport(e.to_string()))?;
    Ok(PeerId::from_public_key(&libp2p::identity::PublicKey::from(
        pub_key,
    )))
}

/// Read a [u32 BE len][CBOR] framed Message from a futures::AsyncRead stream.
async fn read_framed_message<T>(io: &mut T) -> io::Result<Message>
where
    T: futures::AsyncRead + Unpin,
{
    use futures::AsyncReadExt;

    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MSG_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {len}"),
        ));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    viaticum_core::messages::from_cbor(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// Write a [u32 BE len][CBOR] framed Message to a futures::AsyncWrite stream.
async fn write_framed_message<T>(io: &mut T, msg: Message) -> io::Result<()>
where
    T: futures::AsyncWrite + Unpin,
{
    use futures::AsyncWriteExt;

    let framed = viaticum_core::messages::frame_message(&msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    io.write_all(&framed).await?;
    io.flush().await?;
    Ok(())
}

/// Read a [u32 BE len][CBOR] framed value of type T from a futures::AsyncRead stream.
async fn read_framed_cbor<T, R>(io: &mut R) -> io::Result<T>
where
    T: serde::de::DeserializeOwned,
    R: futures::AsyncRead + Unpin,
{
    use futures::AsyncReadExt;

    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MSG_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {len}"),
        ));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    viaticum_core::messages::from_cbor(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// Write a [u32 BE len][CBOR] framed value of type T to a futures::AsyncWrite stream.
async fn write_framed_cbor<T, W>(io: &mut W, value: &T) -> io::Result<()>
where
    T: serde::Serialize,
    W: futures::AsyncWrite + Unpin,
{
    use futures::AsyncWriteExt;

    let cbor = viaticum_core::messages::to_cbor(value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let len = cbor.len() as u32;
    let mut framed = Vec::with_capacity(4 + cbor.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&cbor);
    io.write_all(&framed).await?;
    io.flush().await?;
    Ok(())
}
