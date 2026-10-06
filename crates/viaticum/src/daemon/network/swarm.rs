// libp2p swarm stack for Viaticum ε.1–ε.3.
//
// Provides:
//   - ViaticumCodec: framed CBOR codec for request-response (wire: [u32 BE len][CBOR])
//   - CertCodec: framed CBOR codec for DeviceCertExchange protocol
//   - ViaticumBehaviour: composed NetworkBehaviour (viaticum + cert + identify + kad)
//   - SwarmHandle: public API to the event loop
//   - EventLoopState: private state machine running in a tokio task
//   - Kademlia DHT: automatic Viaticum peer discovery over FIND_NODE (ε.3, C-DK)
//     on our own DHT, `/viaticum/kad/1.0.0` — no IPFS (network-i17, ADR-003)
//
// Identity model:
//   device_signing_key → Ed25519 keypair → PeerId (libp2p transport identity)
//   device_id = device_signing_key.verifying_key().to_bytes() (same key)
//   Noise IX authenticates both ends at transport level.
//   DeviceCertExchange adds protocol-level proof of cluster membership.
//
// Kademlia discovery (C-DK C2, C3):
//   Our own DHT: the protocol is KAD_PROTOCOL, the only way in is the circle's
//   `kademlia_bootstrap_peers`, and identify feeds Kademlia only peers that
//   announce KAD_PROTOCOL — so an IPFS (or any other) Kademlia node never
//   enters our table and is never handed out by our lookups (network-i17). A
//   foreign address a user put into the bootstrap list gets one dial at start
//   and is dropped from the table after its identify.
//   FIND_NODE only — the Kademlia bootstrap plus a periodic get_closest_peers
//   of our own id; found peers we do not know yet are dialed, and
//   DeviceCertExchange runs automatically after TCP+Noise connects. There is no
//   provider namespace any more and incoming PUT_VALUE / ADD_PROVIDER are not
//   stored, so no answer of ours carries more than ≤ 20 closer peers with a
//   bounded address set each (network-i18, i20).
//   Our own timer runs the discovery lookup and the Kademlia bootstrap; it slows
//   down once the node knows enough peers (`kad_cadence`, Р-17, network-i43).
//
// Connections (C-DK C4):
//   - the connection cache (`conn_lru`, network-i41) is the single owner of
//     voluntary closes: at most `cap` peers neither busy nor infrastructure;
//   - `send_to_device` dials a known peer it has no connection to, waits for its
//     cert and sends (`on_demand`, SendOrDial, network-i42); `send_if_connected`
//     never dials (the processor's PeerAnnounce);
//   - the event-loop side of both lives in `swarm/conn_loop.rs`.

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
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};
use viaticum_core::cluster::{CertTrustPath, DeviceCertificate, verify_device_certificate};
use viaticum_core::messages::Message;
use viaticum_core::types::{DeviceId, IdentityPub};

use super::address_book::AddressBook;
use super::conn_lru::{ConnLru, DialOrigin};
use super::kad_cadence::{BootstrapOrigin, KadCadence, SettleReason, bootstrap_origin};
use super::kad_feed::{kad_dialed_addr, kad_feed_addrs, kad_replace_plan};
use super::on_demand::OnDemand;

mod conn_loop;
#[cfg(feature = "e2e-tools")]
mod e2e_hold_loop;
mod policy;

pub use policy::{ConnPolicy, ConnStats};

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

/// Kademlia protocol name: our own DHT, separate from IPFS by construction
/// (network-i17, ADR-003). A node speaking another Kademlia (IPFS's
/// `/ipfs/kad/1.0.0`) cannot query us, is not answered by us, and is not fed
/// into our table by identify (`handle_identify_event`).
pub(crate) const KAD_PROTOCOL: StreamProtocol = StreamProtocol::new("/viaticum/kad/1.0.0");

/// Max message size — matches viaticum_core::constants::MAX_MESSAGE_SIZE.
const MAX_MSG_SIZE: usize = viaticum_core::constants::MAX_MESSAGE_SIZE as usize;

// ─── Kademlia constants (ε.3) ─────────────────────────────────────────────────

/// Kademlia discovery (get_closest_peers of our own id) interval: 5 minutes.
pub const KAD_DISCOVERY_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Grace period after startup before the first discovery lookup (allow the
/// bootstrap to complete).
pub const KAD_INITIAL_DISCOVERY_DELAY: Duration = Duration::from_secs(15);

/// Kademlia frame limit, stated explicitly: the libp2p default, NOT raised
/// (network-i20). Our largest answer is FIND_NODE (GET_PROVIDERS / GET_VALUE
/// carry only closer peers here: nothing is provided or stored) with ≤ 20
/// closer peers × (≈45 B + ≤ 640 B of addresses + tags) ≈ 14 KB — the address
/// bytes per peer are bounded by `kad_feed` (network-i18, i20,
/// `MAX_KAD_ADDR_BYTES_PER_PEER`). Raising the limit would hide a regression of
/// that bound instead of fixing it.
pub const KAD_MAX_PACKET_SIZE: usize = 16 * 1024;

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

/// Discovered peers worth dialing this round (C-DK Р-5′, network-i43): those
/// `skip` does not reject — the caller skips self, connected, being dialed,
/// authenticated and already KNOWN peers (a PeerRecord, or met since start) —
/// at most MAX_CONCURRENT_DISCOVERY_DIALS of them, skipped ones not counted.
/// No gate on how many peers we already have: knowing everyone is cheap, and a
/// known peer is reached when there is something to say, not kept connected.
/// Peers with empty addrs are kept (`dial_discovered_peer` falls back to a
/// peer-id-only dial).
pub fn discovery_dial_candidates(
    peer_list: Vec<(PeerId, Vec<Multiaddr>)>,
    skip: impl Fn(&PeerId) -> bool,
) -> Vec<(PeerId, Vec<Multiaddr>)> {
    use viaticum_core::constants::MAX_CONCURRENT_DISCOVERY_DIALS;
    peer_list
        .into_iter()
        .filter(|(peer_id, _)| !skip(peer_id))
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
/// - kad: Kademlia DHT for peer discovery, FIND_NODE only (ε.3, C-DK C2)
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
    /// v3.1 W1 (г): look the device up, send — or (`dial`, network-i42) dial
    /// it, wait for its cert and send — in ONE event-loop turn. `addrs` are the
    /// PeerRecord's transport addresses (read on the handle's side).
    SendOrDial {
        device: DeviceId,
        addrs: Vec<Multiaddr>,
        message: Box<Message>,
        reply: oneshot::Sender<Result<Message, SwarmError>>,
        dial: bool,
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
        origin: DialOrigin,
    },
    /// One snapshot of the connection cache after an eviction pass (network-i41).
    ConnStats { reply: oneshot::Sender<ConnStats> },
    ListenAddrs {
        reply: oneshot::Sender<Vec<Multiaddr>>,
    },
    /// The confirmed external addresses (`status` node_addr, network-i27).
    ExternalAddrs {
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
    /// `peer_id`, then (`hold`) refuse every new one but our on-demand dial for
    /// that long. Replies whether there was a connection.
    #[cfg(feature = "e2e-tools")]
    Disconnect {
        peer_id: PeerId,
        hold: Option<Duration>,
        reply: oneshot::Sender<bool>,
    },
    /// Unit tests only: feed `peer_id`'s identify addresses to Kademlia by the
    /// identify path (`feed_kad`) and reply with what the table holds after.
    #[cfg(test)]
    TestFeedKad {
        peer_id: PeerId,
        addrs: Vec<Multiaddr>,
        reply: oneshot::Sender<Vec<Multiaddr>>,
    },
    /// Unit tests only: the addresses our Kademlia table holds for `peer_id`
    /// (empty when the peer is not in the table).
    #[cfg(test)]
    TestKadAddrs {
        peer_id: PeerId,
        reply: oneshot::Sender<Vec<Multiaddr>>,
    },
    /// Unit tests only: how many times Kademlia reported `peer_id` as a NEW
    /// entry of its table (`RoutingUpdated { is_new_peer: true }`) so far.
    #[cfg(test)]
    TestKadNewPeerCount {
        peer_id: PeerId,
        reply: oneshot::Sender<usize>,
    },
    /// Unit tests only: one discovery pass over `peers` as if a discovery
    /// lookup had found them (`dial_discovery_result`, the timer's path);
    /// replies with the peers it chose to dial.
    #[cfg(test)]
    TestDiscoveryPass {
        peers: Vec<(PeerId, Vec<Multiaddr>)>,
        reply: oneshot::Sender<Vec<PeerId>>,
    },
    /// Unit tests only: open one more connection to `addr` whatever is already
    /// connected (no dial condition) and reply with its id.
    #[cfg(test)]
    TestDialNewConnection {
        addr: Multiaddr,
        reply: oneshot::Sender<Result<libp2p::swarm::ConnectionId, SwarmError>>,
    },
    /// Unit tests only: close one connection by id; replies whether it existed.
    #[cfg(test)]
    TestCloseConnection {
        connection_id: libp2p::swarm::ConnectionId,
        reply: oneshot::Sender<bool>,
    },
    /// Unit tests only: evict `peer_id` as the cache's pass would (it moves to
    /// `closing`); replies whether it had an entry.
    #[cfg(test)]
    TestEvict {
        peer_id: PeerId,
        reply: oneshot::Sender<bool>,
    },
    /// Unit tests only: evict `peer_id`, then deliver its cert again in the
    /// same turn (a late cert on a second connection); replies (authenticated
    /// before, authenticated right after the late cert — same turn).
    #[cfg(test)]
    TestEvictLateCert {
        peer_id: PeerId,
        reply: oneshot::Sender<(bool, bool)>,
    },
    /// Unit tests only: (peer, origin) of every `lru: re-dial of evicted peer`.
    #[cfg(test)]
    TestRedialOrigins {
        reply: oneshot::Sender<Vec<(PeerId, &'static str)>>,
    },
    /// Unit tests only: (cert_done, has app activity, in_flight + waiters) of
    /// the cache entry of `peer_id`.
    #[cfg(test)]
    TestLruEntry {
        peer_id: PeerId,
        reply: oneshot::Sender<Option<(bool, bool, u32)>>,
    },
    /// Unit tests only: the Kademlia lookups started so far, in order
    /// ("discovery", "bootstrap:<origin>"), and the cadence's settle reason.
    #[cfg(test)]
    TestKadLookups {
        reply: oneshot::Sender<(Vec<String>, Option<&'static str>)>,
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

    /// An on-demand dial to a known peer failed, its cert exchange did not
    /// finish in time, or the peer is in the negative cache (network-i42).
    #[error("peer unreachable: {0:?}: {1}")]
    Unreachable(DeviceId, String),

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

    /// Override for KAD_DISCOVERY_INTERVAL and initial discovery delay.
    /// None = use the constants. Used in tests to speed up discovery.
    pub kad_discovery_interval_override: Option<Duration>,

    /// Whether this node acts as a circuit relay server for other peers.
    /// When false, relay server is created with `max_reservations: 0` and
    /// `max_circuits: 0` so no peer can use us as a relay. Default config
    /// flag is false (opt-in) — home NAS / laptop shouldn't relay traffic
    /// for strangers without explicit consent.
    pub enable_relay_server: bool,

    /// How this node treats connections (C-DK Р-15).
    pub conn_policy: ConnPolicy,
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
    /// network-i42: `send_to_device` dials a known peer it has no connection to.
    dial_on_demand: bool,
    /// The PeerRecord table the on-demand dial reads addresses from (on this
    /// side, not in the event loop: A15).
    address_book: Option<AddressBook>,
    /// The policy's time_scale (None: tests, the DR swap).
    time_scale: Option<u64>,
    /// C-DK Р-18: work-pipeline wakes the processor suppressed. Kept here
    /// because the handle is the one object both the processor and status share.
    work_wakes_suppressed: std::sync::atomic::AtomicU64,
    /// PeerRecord events dropped at the writer's queue cap (C-DK C4 fix round 4, N8).
    peer_record_dropped: std::sync::atomic::AtomicU64,
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
        let mut kad_cfg = libp2p::kad::Config::new(KAD_PROTOCOL);
        kad_cfg.set_max_packet_size(KAD_MAX_PACKET_SIZE);
        // network-i20: incoming PUT_VALUE / ADD_PROVIDER become events we ignore,
        // never records in the store. In an open network a stranger could
        // otherwise fill it and inflate our GET_PROVIDERS / GET_VALUE answers
        // past the frame. We provide nothing ourselves, so the store stays empty
        // (the behaviour still needs one).
        kad_cfg.set_record_filtering(libp2p::kad::StoreInserts::FilterBoth);
        // Р-17 (network-i43): our own timer runs the bootstrap (it slows down
        // once the cadence settles); libp2p's periodic one would keep 5 min.
        kad_cfg.set_periodic_bootstrap_interval(None);
        let kad_store = libp2p::kad::store::MemoryStore::new(peer_id);
        let mut kademlia = libp2p::kad::Behaviour::with_config(peer_id, kad_store, kad_cfg);
        kademlia.set_mode(Some(libp2p::kad::Mode::Server));

        // The circle's bootstrap peers are the only way into our DHT: there are
        // no built-in bootstrap nodes (network-i17).
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
                let tcp = super::no_port_reuse::NoPortReuse::new(
                    libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default()),
                )
                .upgrade(Version::V1Lazy)
                .authenticate(noise)
                .multiplex(libp2p::yamux::Config::default())
                .map(|(p, c), _| (p, StreamMuxerBox::new(c)));
                // network-i28: a seed is named by DNS (`/dns4/<name>/tcp/…`).
                // network-i46: the OS resolver configuration is re-read after a
                // failed lookup, so a node that started before DHCP or changed
                // networks resolves the seed without a restart.
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                    super::reloading_dns::ReloadingDns::system(tcp),
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
            // network-i42: establishing a connection (TCP + Noise + yamux) gives
            // up after 20 s — the builder's default is 10 s — so a black hole that
            // accepts TCP and never answers ends the dial (and an inbound upgrade);
            // the same number as R2's TCP timeout.
            .with_connection_timeout(Duration::from_secs(
                viaticum_core::constants::TRANSPORT_TIMEOUT_SECS,
            ))
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

        // ── 6. Known peers (C-DK Р-5′) ────────────────────────────────────────
        // Discovery does not dial a peer we already know. Seeded once from the
        // PeerRecord table; record_authenticated adds every peer of another
        // master met from now on.
        let known: HashSet<PeerId> = config
            .conn_policy
            .address_book
            .as_ref()
            .map(|book| book.known_peer_ids().into_iter().collect())
            .unwrap_or_default();
        info!(known = known.len(), "swarm: known peers loaded");
        let mut kad_cadence = KadCadence::new(config.conn_policy.time_scale);
        if let Some(reason) = kad_cadence.on_known(known.len()) {
            log_cadence_settled(reason, known.len(), &kad_cadence);
        }

        // ── 7. Build the Kademlia lookup timer (Р-17) ─────────────────────────
        // Discovery lookup + bootstrap on every tick; the period until the
        // cadence settles is the override (tests, time_scale > 1) or 5 min.
        let discovery_interval = config
            .kad_discovery_interval_override
            .unwrap_or(KAD_DISCOVERY_INTERVAL);
        let initial_delay = config
            .kad_discovery_interval_override
            .unwrap_or(KAD_INITIAL_DISCOVERY_DELAY);

        let kad_lookup_timer = {
            let start = tokio::time::Instant::now() + initial_delay;
            let mut t = tokio::time::interval_at(start, discovery_interval);
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            t
        };

        // ── 7b. Connection cache and on-demand dial (C-DK C4) ─────────────────
        #[allow(unused_mut)]
        let mut cap = config.conn_policy.cap;
        #[cfg(feature = "e2e-tools")]
        if let Some(n) = e2e_conn_cap_from_env(cap) {
            cap = Some(n);
            info!("e2e: connection cap {n}");
        }
        let lru = cap.map(|cap| {
            ConnLru::new(
                cap,
                config.conn_policy.infra.clone(),
                config.conn_policy.handshake_grace,
                viaticum_core::constants::MAX_HANDSHAKE_PROTECTED,
                // A connection without a cert is busy until the cert timeout.
                Duration::from_secs(config.cert_timeout_secs),
            )
        });
        let seed_role = config.conn_policy.is_seed();
        let infra_peers = match &config.conn_policy.infra {
            super::conn_lru::InfraRule::Peers(p) => p.clone(),
            _ => Vec::new(),
        };
        let on_demand = OnDemand::new(config.conn_policy.time_scale);

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
            kad_lookup_timer,
            kad_timer_slow: false,
            kad_cadence,
            our_bootstraps: HashSet::new(),
            #[cfg(test)]
            test_kad_lookups: Vec::new(),
            met: known.clone(),
            known,
            lru,
            closing: HashMap::new(),
            pending_close: HashMap::new(),
            on_demand,
            dial_on_demand: config.conn_policy.dial_on_demand,
            dial_origin: HashMap::new(),
            evicted_at: HashMap::new(),
            lru_out: HashMap::new(),
            lru_in: HashMap::new(),
            over_cap_since: None,
            all_busy_since: None,
            last_all_busy_warn: None,
            last_lru_tick: Instant::now(),
            seed_role,
            infra_peers,
            dialing: HashSet::new(),
            bootstrap_called: false,
            #[cfg(test)]
            test_kad_new_peer: HashMap::new(),
            #[cfg(test)]
            test_redial_origins: Vec::new(),
            relay_reservations: HashSet::new(),
            last_empty_lookup_warn: None,
            #[cfg(feature = "e2e-tools")]
            e2e_loopback_aliases,
            #[cfg(feature = "e2e-tools")]
            e2e_hold: super::e2e_hold::E2eHold::new(),
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
            dial_on_demand: config.conn_policy.dial_on_demand,
            address_book: config.conn_policy.address_book,
            time_scale: config.conn_policy.time_scale,
            work_wakes_suppressed: std::sync::atomic::AtomicU64::new(0),
            peer_record_dropped: std::sync::atomic::AtomicU64::new(0),
        };
        Ok((handle, event_rx))
    }

    /// Send a protocol Message to a device by DeviceId and wait for its answer
    /// (≤ 30 s).
    ///
    /// network-i42: when the device is known but not authenticated and the
    /// policy dials on demand, the swarm dials it (PeerRecord addresses ∪ what
    /// it knows ∪ Kademlia), waits ≤ 10 s for its cert and then sends — one
    /// command of the event loop (`SendOrDial`). `PeerNotAuthenticated` when
    /// there is nothing to dial (or the policy does not dial); `Unreachable`
    /// when the dial fails, the cert does not come in time or the peer is in
    /// the negative cache.
    pub async fn send_to_device(
        &self,
        device: DeviceId,
        msg: Message,
    ) -> Result<Message, SwarmError> {
        let addrs = match (&self.address_book, self.dial_on_demand) {
            (Some(book), true) => book.addrs_of(&device),
            _ => Vec::new(),
        };
        self.send_or_dial(device, addrs, msg, self.dial_on_demand)
            .await
    }

    /// `send_to_device` with extra addresses to dial (dr-i63): a peer found by a
    /// Kademlia lookup may have no PeerRecord yet, so the address book knows
    /// nothing of it. The given addresses (terminal `/p2p/` stripped; one naming
    /// another peer is dropped) come first, then the book's.
    pub async fn send_to_device_via(
        &self,
        device: DeviceId,
        given: Vec<Multiaddr>,
        msg: Message,
    ) -> Result<Message, SwarmError> {
        let mut addrs = Vec::new();
        if self.dial_on_demand
            && let Ok(peer) = device_id_to_peer_id(&device)
        {
            let book = match &self.address_book {
                Some(book) => book.addrs_of(&device),
                None => Vec::new(),
            };
            for a in given.iter().filter_map(|a| strip_peer_suffix(a, peer).ok()) {
                if !addrs.contains(&a) {
                    addrs.push(a);
                }
            }
            for a in book {
                if !addrs.contains(&a) {
                    addrs.push(a);
                }
            }
        }
        self.send_or_dial(device, addrs, msg, self.dial_on_demand)
            .await
    }

    /// Send only over an existing authenticated connection — never dials
    /// (`send_to_device` before C4). The processor's PeerAnnounce goes this way:
    /// it follows an authentication, and must not dial a peer the cache closed.
    pub async fn send_if_connected(
        &self,
        device: DeviceId,
        msg: Message,
    ) -> Result<Message, SwarmError> {
        self.send_or_dial(device, Vec::new(), msg, false).await
    }

    async fn send_or_dial(
        &self,
        device: DeviceId,
        addrs: Vec<Multiaddr>,
        msg: Message,
        dial: bool,
    ) -> Result<Message, SwarmError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::SendOrDial {
                device,
                addrs,
                message: Box::new(msg),
                reply: reply_tx,
                dial,
            })
            .await
            .map_err(|_| SwarmError::ChannelClosed)?;

        tokio::time::timeout(Duration::from_secs(30), reply_rx)
            .await
            .map_err(|_| SwarmError::Timeout)?
            .map_err(|_| SwarmError::ChannelClosed)?
    }

    /// One snapshot of the connection cache, taken right after an eviction
    /// pass (network-i41).
    pub async fn conn_stats(&self) -> Result<ConnStats, SwarmError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::ConnStats { reply: reply_tx })
            .await
            .map_err(|_| SwarmError::ChannelClosed)?;
        reply_rx.await.map_err(|_| SwarmError::ChannelClosed)
    }

    /// The policy's time_scale (None: tests, the DR swap).
    pub fn time_scale(&self) -> Option<u64> {
        self.time_scale
    }

    /// C-DK Р-18: the processor suppressed one work-pipeline wake.
    pub(crate) fn note_work_wake_suppressed(&self) {
        self.work_wakes_suppressed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// C-DK Р-18: work-pipeline wakes suppressed so far (status).
    pub fn work_wakes_suppressed(&self) -> u64 {
        self.work_wakes_suppressed
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The processor dropped one PeerRecord event at the writer's queue cap
    /// (C-DK C4 fix round 4, N8).
    pub(crate) fn note_peer_record_dropped(&self) {
        self.peer_record_dropped
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// PeerRecord events dropped at the writer's queue cap so far (status).
    pub fn peer_record_dropped(&self) -> u64 {
        self.peer_record_dropped
            .load(std::sync::atomic::Ordering::Relaxed)
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
        self.dial_addrs_from(peer_id, addrs, DialOrigin::Manual)
            .await
    }

    /// [`SwarmHandle::dial_addrs`] with the origin the log of the connection
    /// cache names (`lru: re-dial of evicted peer origin=…`, network-i43).
    pub(crate) async fn dial_addrs_from(
        &self,
        peer_id: PeerId,
        addrs: Vec<Multiaddr>,
        origin: DialOrigin,
    ) -> Result<(), SwarmError> {
        self.cmd_tx
            .send(SwarmCommand::Dial {
                peer_id,
                addrs,
                origin,
            })
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

    /// Return the confirmed external addresses.
    pub async fn external_addrs(&self) -> Result<Vec<Multiaddr>, SwarmError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::ExternalAddrs { reply: reply_tx })
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

    /// Test-only (`net-probe disconnect`, C-DK Р-16): close every connection to
    /// `device` (the PeerId is derived from the device key, so a peer that never
    /// authenticated can be named too). `Ok(false)` when there was none. The
    /// usual `ConnectionClosed` handling drops the peer from `authenticated`.
    /// `hold`: for that long every new connection with the peer — Kademlia's,
    /// the redial pass's, its own inbound — is closed before the cert exchange;
    /// only our on-demand dial (`send_to_device`) reconnects it. A zero `hold`
    /// only ends the peer's hold: nothing is closed, `Ok(connected now)`.
    #[cfg(feature = "e2e-tools")]
    pub async fn disconnect_device(
        &self,
        device: DeviceId,
        hold: Option<Duration>,
    ) -> Result<bool, SwarmError> {
        let peer_id = device_id_to_peer_id(&device)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::Disconnect {
                peer_id,
                hold,
                reply: reply_tx,
            })
            .await
            .map_err(|_| SwarmError::ChannelClosed)?;
        reply_rx.await.map_err(|_| SwarmError::ChannelClosed)
    }

    /// Unit tests only: feed `peer` to Kademlia exactly as an identify carrying
    /// `addrs` would, and return the addresses the table holds for it after.
    #[cfg(test)]
    pub(crate) async fn test_feed_kad(
        &self,
        peer: PeerId,
        addrs: Vec<Multiaddr>,
    ) -> Vec<Multiaddr> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::TestFeedKad {
                peer_id: peer,
                addrs,
                reply,
            })
            .await
            .expect("swarm loop alive");
        rx.await.expect("swarm loop replied")
    }

    /// Unit tests only: the addresses our Kademlia table holds for `peer`
    /// (empty when it is not in the table).
    #[cfg(test)]
    pub(crate) async fn test_kad_addrs(&self, peer: PeerId) -> Vec<Multiaddr> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::TestKadAddrs {
                peer_id: peer,
                reply,
            })
            .await
            .expect("swarm loop alive");
        rx.await.expect("swarm loop replied")
    }

    /// Unit tests only: how many times Kademlia reported `peer` as a new entry
    /// of its table so far (`RoutingUpdated { is_new_peer: true }`). Events
    /// reach the loop after the command that caused them: wait on another
    /// peer's later event before trusting a count.
    #[cfg(test)]
    pub(crate) async fn test_kad_new_peer_count(&self, peer: PeerId) -> usize {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::TestKadNewPeerCount {
                peer_id: peer,
                reply,
            })
            .await
            .expect("swarm loop alive");
        rx.await.expect("swarm loop replied")
    }

    /// Unit tests only: run one discovery pass over `peers` (what a discovery
    /// lookup found) and return the peers it chose to dial (C-DK Р-5′).
    #[cfg(test)]
    pub(crate) async fn test_discovery_pass(
        &self,
        peers: Vec<(PeerId, Vec<Multiaddr>)>,
    ) -> Vec<PeerId> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::TestDiscoveryPass { peers, reply })
            .await
            .expect("swarm loop alive");
        rx.await.expect("swarm loop replied")
    }

    /// Unit tests only: open an extra connection to `addr` (a duplicate when
    /// already connected) and return its id.
    #[cfg(test)]
    pub(crate) async fn test_dial_new_connection(
        &self,
        addr: Multiaddr,
    ) -> Result<libp2p::swarm::ConnectionId, SwarmError> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::TestDialNewConnection { addr, reply })
            .await
            .map_err(|_| SwarmError::ChannelClosed)?;
        rx.await.map_err(|_| SwarmError::ChannelClosed)?
    }

    /// Unit tests only: close the connection `connection_id`; false when unknown.
    #[cfg(test)]
    pub(crate) async fn test_close_connection(
        &self,
        connection_id: libp2p::swarm::ConnectionId,
    ) -> bool {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::TestCloseConnection {
                connection_id,
                reply,
            })
            .await
            .expect("swarm loop alive");
        rx.await.expect("swarm loop replied")
    }

    /// Unit tests only: evict `peer` as the cache's pass would.
    #[cfg(test)]
    pub(crate) async fn test_evict(&self, peer: PeerId) -> bool {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::TestEvict {
                peer_id: peer,
                reply,
            })
            .await
            .expect("swarm loop alive");
        rx.await.expect("swarm loop replied")
    }

    /// Unit tests only: (cert_done, has app activity, in_flight) of `peer`'s
    /// cache entry; None without an entry (or without a cache).
    #[cfg(test)]
    pub(crate) async fn test_lru_entry(&self, peer: PeerId) -> Option<(bool, bool, u32)> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::TestLruEntry {
                peer_id: peer,
                reply,
            })
            .await
            .expect("swarm loop alive");
        rx.await.expect("swarm loop replied")
    }

    /// Unit tests only: evict `peer` and deliver its cert again (late cert).
    #[cfg(test)]
    pub(crate) async fn test_evict_late_cert(&self, peer: PeerId) -> (bool, bool) {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::TestEvictLateCert {
                peer_id: peer,
                reply,
            })
            .await
            .expect("swarm loop alive");
        rx.await.expect("swarm loop replied")
    }

    /// Unit tests only: (peer, origin) of every re-dial of an evicted peer.
    #[cfg(test)]
    pub(crate) async fn test_redial_origins(&self) -> Vec<(PeerId, &'static str)> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::TestRedialOrigins { reply })
            .await
            .expect("swarm loop alive");
        rx.await.expect("swarm loop replied")
    }

    /// Unit tests only: the Kademlia lookups started so far and the cadence's
    /// settle reason.
    #[cfg(test)]
    pub(crate) async fn test_kad_lookups(&self) -> (Vec<String>, Option<&'static str>) {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::TestKadLookups { reply })
            .await
            .expect("swarm loop alive");
        rx.await.expect("swarm loop replied")
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

    // ── Kademlia (ε.3, Р-17) ──────────────────────────────────────────────────
    /// Our lookup timer: discovery lookup + bootstrap on every tick.
    kad_lookup_timer: tokio::time::Interval,
    /// The timer runs at the settled (slow) period already.
    kad_timer_slow: bool,
    /// When the lookups slow down (network-i43).
    kad_cadence: KadCadence,
    /// Bootstraps we started (start, timer); any other is libp2p's own (auto).
    our_bootstraps: HashSet<QueryId>,
    /// Unit tests only: the lookups started, in order.
    #[cfg(test)]
    test_kad_lookups: Vec<String>,

    /// Peers we KNOW (C-DK Р-5′): PeerRecords of other masters at start plus
    /// every peer of another master authenticated since. Discovery never dials
    /// them — a known peer is reached when there is something to say — so a
    /// peer the connection cache closes (C4) is not dialed back by discovery.
    /// Only grows.
    known: HashSet<PeerId>,

    /// Peers met by a cert exchange on ANY path (siblings too) plus `known` at
    /// start: discovery never dials them and they never make a discovery round
    /// "not quiet" (fix round 1, WARN-3). `known` stays "other masters" for the
    /// status and the settle threshold.
    met: HashSet<PeerId>,

    // ── Connection cache and on-demand dial (C-DK C4) ─────────────────────────
    /// The connection cache (network-i41); None = no cache (ConnPolicy cap None).
    lru: Option<ConnLru>,
    /// Peers the cache evicted whose connection has not closed yet → their
    /// device (for the processor's ConnectionClosed). Not authenticated any
    /// more; a send to one dials after the close.
    closing: HashMap<PeerId, Option<DeviceId>>,
    /// Evicted peers whose connection is closed only after the linger of our
    /// last answer → when (deferred close, fix round 2). A subset of `closing`.
    pending_close: HashMap<PeerId, Instant>,
    /// Waiters of `send_to_device` for peers being dialed on demand (network-i42).
    on_demand: OnDemand,
    /// The policy dials on demand.
    dial_on_demand: bool,
    /// Our outbound dials by ConnectionId → (peer, origin, start): the `origin=`
    /// of `lru: re-dial of evicted peer`. Everything else is Kademlia's own.
    dial_origin: HashMap<libp2p::swarm::ConnectionId, (PeerId, DialOrigin, Instant)>,
    /// When the cache evicted a peer (kept LRU_REDIAL_WINDOW_SECS).
    evicted_at: HashMap<PeerId, Instant>,
    /// /viaticum/1 requests the cache counts as in flight → (peer, app traffic).
    lru_out: HashMap<OutboundRequestId, (PeerId, bool)>,
    lru_in: HashMap<request_response::InboundRequestId, (PeerId, bool)>,
    /// Since when non-infra peers exceed the cap (`lru: over cap` / `under cap`).
    over_cap_since: Option<Instant>,
    /// Since when the overshoot has no protected / cert-pending peer behind it.
    all_busy_since: Option<Instant>,
    last_all_busy_warn: Option<Instant>,
    /// The previous cache tick (`lru: tick late`).
    last_lru_tick: Instant,
    /// The seed role (redial floor = ∞) and a friend's infrastructure peers,
    /// reported by ConnStats for redial.
    seed_role: bool,
    infra_peers: Vec<PeerId>,

    /// PeerIds currently being dialed (to avoid duplicate dials).
    /// Cleared when connection succeeds or fails.
    dialing: HashSet<PeerId>,

    /// True once bootstrap has been called at least once.
    bootstrap_called: bool,

    /// Unit tests only: `RoutingUpdated { is_new_peer: true }` per peer.
    #[cfg(test)]
    test_kad_new_peer: HashMap<PeerId, usize>,

    /// Unit tests only: (peer, origin) of every `lru: re-dial of evicted peer`.
    #[cfg(test)]
    test_redial_origins: Vec<(PeerId, &'static str)>,

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

    /// Peers `net-probe disconnect --hold-secs` holds: only our on-demand dial
    /// reconnects them until the hold ends (test-only, step 8b).
    #[cfg(feature = "e2e-tools")]
    e2e_hold: super::e2e_hold::E2eHold,
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

        // The connection cache's tick (network-i41): ends the handshake grace
        // between events and notices a stalled loop (`lru: tick late`).
        let mut lru_tick = tokio::time::interval(Duration::from_secs(
            viaticum_core::constants::CONN_LRU_TICK_SECS,
        ));
        lru_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        lru_tick.tick().await; // skip immediate
        self.last_lru_tick = Instant::now();

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
                    self.on_demand_expire();
                    self.close_due();
                }
                _ = cert_sweep.tick() => {
                    self.sweep_unauthenticated_connected().await;
                }
                _ = lru_tick.tick() => {
                    self.lru_tick();
                }
                _ = self.kad_lookup_timer.tick() => {
                    self.kad_lookup_tick();
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
                peer_id,
                endpoint,
                connection_id,
                ..
            } => {
                debug!(peer_id = %peer_id, "connection established");
                // Clear dialing set entry now that connection is established.
                self.dialing.remove(&peer_id);
                // Test-only hold (step 8b): closed before any bookkeeping or cert.
                #[cfg(feature = "e2e-tools")]
                if self.e2e_hold_refuses(peer_id, connection_id, endpoint.is_dialer()) {
                    return;
                }
                self.conn_established(peer_id, connection_id, endpoint.is_dialer(), Instant::now());

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
                connection_id,
                num_established,
                cause,
                ..
            } => {
                // `cause` = KeepAliveTimeout would mean libp2p's idle timeout closed a
                // link between live nodes (C-DK v3-C expects none).
                debug!(peer_id = %peer_id, num_established, cause = ?cause, "connection closed");
                self.e2e_forget_closed(connection_id);
                if num_established > 0 {
                    // network-i19: another connection to this peer lives (a
                    // duplicate from simultaneous dials, closed by one side), so
                    // the peer stays authenticated and the processor hears
                    // nothing. A cert request that left on the closed channel is
                    // re-sent on the live one by check_cert_timeouts.
                    return;
                }
                // An evicted peer left `authenticated` already; its device waits
                // in `closing` for this event (v3.1 W1 в).
                let closing_device = self.closing.remove(&peer_id).flatten();
                let device_id = self
                    .authenticated
                    .remove(&peer_id)
                    .map(|(did, _, _)| did)
                    .or(closing_device);
                if let Some(did) = device_id {
                    self.device_to_peer.remove(&did);
                }
                self.pending_cert.remove(&peer_id);
                let event = ProtocolEvent::ConnectionClosed { peer_id, device_id };
                emit_event(&self.event_tx, event);
                self.conn_closed(peer_id, Instant::now());
            }
            SwarmEvent::OutgoingConnectionError {
                peer_id,
                error,
                connection_id,
                ..
            } => {
                // Clear dialing set so we can retry on next discovery cycle.
                if let Some(pid) = peer_id {
                    self.dialing.remove(&pid);
                }
                let on_demand =
                    self.outgoing_conn_error(peer_id, connection_id, &error, Instant::now());
                if on_demand {
                    // One INFO `swarm: on-demand dial failed` says it (v3.1 N5).
                    debug!(peer_id = ?peer_id, error = %error, "outgoing connection error");
                } else {
                    warn!(peer_id = ?peer_id, error = %error, "outgoing connection error");
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
            // network-i17: only a peer that announces OUR Kademlia is in the
            // table. `add_address` would put any peer there, and a protocol the
            // peer then fails to confirm only marks it, never removes it — an
            // IPFS node connecting to us would stay in the table and be handed
            // out by our FIND_NODE answers. A peer that got in before its
            // identify (a foreign address in `kademlia_bootstrap_peers`: added at
            // start, dialed once by the bootstrap) is taken out here.
            let kad_protocol = info.protocols.contains(&KAD_PROTOCOL);
            let kad_addrs = if kad_protocol {
                self.feed_kad(peer_id, &info.listen_addrs)
            } else {
                let removed = self.swarm.behaviour_mut().kad.remove_peer(&peer_id);
                if removed.is_some() {
                    warn!(
                        peer_id = %peer_id,
                        "kad peer {peer_id} does not speak {KAD_PROTOCOL} — removed from the routing table"
                    );
                }
                0
            };
            // Р-7 / network-i18: how many addresses the peer announced, how many
            // its Kademlia record holds now, and whether it speaks our Kademlia.
            debug!(
                peer_id = %peer_id,
                addrs = info.listen_addrs.len(),
                fed_to_kad = kad_addrs,
                kad_protocol,
                protocols = ?info.protocols,
                "identify received"
            );
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

    /// network-i18, i20 (C-DK Р-3): replace `peer_id`'s Kademlia record with
    /// the bounded set [`kad_feed_addrs`] picks from its identify addresses
    /// (plus the address we dialed it on). New addresses are added BEFORE stale
    /// ones are removed, and the dialed address is never removed (unless it is
    /// oversized, see [`kad_dialed_addr`]), so the peer never drops out of the
    /// table on the way. Returns how many addresses the record holds afterwards.
    fn feed_kad(&mut self, peer_id: PeerId, identify_addrs: &[Multiaddr]) -> usize {
        let dialed = self.dialed_addrs.get(&peer_id);
        let want = kad_feed_addrs(peer_id, identify_addrs, dialed);
        let keep = kad_dialed_addr(peer_id, dialed);
        let current = self.kad_addrs_of(&peer_id);
        let (add, remove) = kad_replace_plan(peer_id, &current, &want, keep.as_ref());
        let kad = &mut self.swarm.behaviour_mut().kad;
        for addr in add {
            kad.add_address(&peer_id, addr);
        }
        for addr in &remove {
            kad.remove_address(&peer_id, addr);
        }
        self.kad_addrs_of(&peer_id).len()
    }

    /// The addresses our Kademlia table holds for `peer_id` (empty when absent).
    fn kad_addrs_of(&mut self, peer_id: &PeerId) -> Vec<Multiaddr> {
        let Some(bucket) = self.swarm.behaviour_mut().kad.kbucket(*peer_id) else {
            return Vec::new();
        };
        bucket
            .iter()
            .find(|e| e.node.key.preimage() == peer_id)
            .map(|e| e.node.value.iter().cloned().collect())
            .unwrap_or_default()
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
                connection_id,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
            } => {
                if self.e2e_is_refused(connection_id) {
                    debug!(peer_id = %peer, "e2e: cert request on a held connection ignored");
                    return;
                }
                self.on_cert_request(peer, request, channel).await;
            }
            // Dialer side: receives listener's cert response.
            request_response::Event::Message {
                peer,
                connection_id,
                message: request_response::Message::Response { response, .. },
            } => {
                if self.e2e_is_refused(connection_id) {
                    debug!(peer_id = %peer, "e2e: cert response on a held connection ignored");
                    return;
                }
                self.on_cert_response(peer, response).await;
            }
            request_response::Event::OutboundFailure { peer, error, .. } => {
                warn!(peer_id = %peer, error = %error, "cert outbound failure");
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                warn!(peer_id = %peer, error = %error, "cert inbound failure");
            }
            request_response::Event::ResponseSent { peer, .. } => {
                // Listener side: our cert answer left (fix round 1, N-1).
                self.cert_answer_sent(peer, Instant::now());
            }
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

        self.record_authenticated(peer_id, request, path, true);
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

        self.record_authenticated(peer_id, response, path, false);
    }

    /// Record a successfully verified peer in the authenticated maps.
    /// `listener`: we answered the peer's cert request; the cache counts the
    /// exchange as finished only once that answer is sent (`ResponseSent` of
    /// the cert protocol), so an eviction cannot cut the answer off and leave
    /// the knowledge one-sided (fix round 1, N-1).
    fn record_authenticated(
        &mut self,
        peer_id: PeerId,
        msg: DeviceCertExchangeMsg,
        path: CertTrustPath,
        listener: bool,
    ) {
        let device_id = msg.cert.device_id;
        let identity_pub = msg.cert.master_pub_key;

        // Met by cert on any path (siblings too): discovery leaves it alone.
        self.met.insert(peer_id);
        self.pending_cert.remove(&peer_id);
        if self.closing.contains_key(&peer_id) {
            // A late cert on a second connection of a peer the cache just
            // evicted: it stays closing, not authenticated (fix round 1, WARN-1).
            debug!(peer_id = %peer_id, "cert of a closing peer ignored");
            return;
        }
        self.authenticated
            .insert(peer_id, (device_id, identity_pub, msg.cert.clone()));
        self.device_to_peer.insert(device_id, peer_id);
        if matches!(path, CertTrustPath::Cross) {
            // Another master: known from now on, discovery leaves it alone (Р-5′).
            if self.known.insert(peer_id)
                && let Some(reason) = self.kad_cadence.on_known(self.known.len())
            {
                log_cadence_settled(reason, self.known.len(), &self.kad_cadence);
            }
        }

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

        // network-i42: requests waiting for this peer go out; network-i41: the
        // cert exchange is done (the dialer's now, the listener's when its
        // answer is sent), the cache's pass runs.
        self.conn_authenticated(peer_id, Instant::now(), !listener);
    }

    /// All addresses we know for `peer_id`: the address we last dialed it on
    /// (first — it is known to work) ∪ its identify listen addrs. Normalized by
    /// [`normalize_peer_addrs`]. Used for every address set the swarm hands out
    /// (PeerAuthenticated, PeerIdentified, GetPeerAddrs). Kademlia gets a
    /// different, bounded set: `feed_kad` filters, ranks and caps the identify
    /// addrs (network-i18, i20); this one is not bounded (R2, network-i2/i4).
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
                        request_id,
                        request,
                        channel,
                    },
                ..
            } => {
                // Only deliver if peer is authenticated.
                if let Some((from_device, from_master, _)) = self.authenticated.get(&peer) {
                    let from_device = *from_device;
                    let from_master = *from_master;
                    self.inbound_request_started(peer, request_id, &request);
                    let ev = ProtocolEvent::InboundRequest {
                        from_device,
                        from_master,
                        message: request,
                        response_channel: channel,
                    };
                    emit_event(&self.event_tx, ev);
                } else if self.closing.contains_key(&peer) {
                    // Evicted, its close deferred: not answered (fix round 2).
                    debug!(peer_id = %peer, "dropping inbound request from a closing peer");
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
                self.outbound_request_ended(request_id);
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
                self.outbound_request_ended(request_id);
                if let Some(reply) = self.pending_requests.remove(&request_id) {
                    // A request the peer did not answer in time is a `Timeout`; a dropped
                    // connection (EOF, closed) stays a failed request (restore-i44).
                    let err = match error {
                        request_response::OutboundFailure::Timeout => SwarmError::Timeout,
                        other => SwarmError::RequestFailed(other.to_string()),
                    };
                    let _ = reply.send(Err(err));
                }
            }
            request_response::Event::InboundFailure {
                peer,
                error,
                request_id,
                ..
            } => {
                warn!(peer_id = %peer, error = %error, "viaticum inbound failure");
                self.inbound_request_ended(request_id);
            }
            request_response::Event::ResponseSent { request_id, .. } => {
                self.inbound_request_ended(request_id);
            }
        }
    }

    // ── Kademlia methods (ε.3) ────────────────────────────────────────────────

    /// Initiate Kademlia bootstrap (FIND_NODE queries to fill the routing table).
    ///
    /// Called once at startup. If the routing table is empty (no bootstrap
    /// peers), bootstrap returns NoKnownPeers and we log a warning; our lookup
    /// timer (and libp2p's bootstrap on a low table) retries later.
    fn do_bootstrap(&mut self) {
        if !self.bootstrap_called {
            match self.start_bootstrap(BootstrapOrigin::Start) {
                Ok(()) => self.bootstrap_called = true,
                Err(e) => {
                    warn!(error = ?e, "kademlia bootstrap failed (no known peers?)");
                }
            }
        }
    }

    /// Start a Kademlia bootstrap of ours and log it (`origin=start|timer`).
    fn start_bootstrap(
        &mut self,
        origin: BootstrapOrigin,
    ) -> Result<(), libp2p::kad::NoKnownPeers> {
        let query_id = self.swarm.behaviour_mut().kad.bootstrap()?;
        self.our_bootstraps.insert(query_id);
        info!(query_id = ?query_id, origin = %origin.as_str(), "kademlia bootstrap started");
        #[cfg(test)]
        self.test_kad_lookups
            .push(format!("bootstrap:{}", origin.as_str()));
        Ok(())
    }

    /// The lookup timer's tick (Р-17 v3.3, network-i43): the discovery lookup,
    /// then the bootstrap; once the cadence has settled, the timer slows down
    /// (a tick already scheduled is kept, the next ones come at the slow period).
    fn kad_lookup_tick(&mut self) {
        self.do_kad_discovery();
        if let Err(e) = self.start_bootstrap(BootstrapOrigin::Timer) {
            debug!(error = ?e, "kademlia bootstrap skipped (no known peers)");
        }
        if let Some(period) = self.kad_cadence.slow_down(self.kad_timer_slow) {
            let start = tokio::time::Instant::now() + period;
            let mut t = tokio::time::interval_at(start, period);
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            self.kad_lookup_timer = t;
            self.kad_timer_slow = true;
            info!(
                interval_secs = period.as_secs(),
                "kademlia lookups slowed down"
            );
        }
    }

    /// Look for peers near our own id (C-DK: the only discovery lookup).
    ///
    /// get_closest_peers returns PeerInfo{peer_id, addrs}: querying our OWN id
    /// fills our DHT neighborhood with addresses learned from the bootstrap
    /// seed, so a star-spoke that only knows the seed can reach siblings. The
    /// seed answers with the closest peers to our id INCLUDING their addresses
    /// (it knows everyone who dialed it).
    fn do_kad_discovery(&mut self) {
        let self_key = self.swarm.local_peer_id().to_bytes();
        let qid = self.swarm.behaviour_mut().kad.get_closest_peers(self_key);
        self.discovery_queries.insert(qid);
        info!(query_id = ?qid, "kademlia discovery lookup started");
        #[cfg(test)]
        self.test_kad_lookups.push("discovery".to_string());
    }

    /// Discovery path (C-DK Р-5′, network-i43): dial the peers a discovery
    /// lookup (`query`) found that we do not know yet, WITH their addresses.
    /// Returns the peers it chose to dial (`dial_discovered_peer` may still
    /// find a dial already under way).
    fn dial_discovery_result(
        &mut self,
        query: Option<QueryId>,
        peer_list: Vec<(PeerId, Vec<Multiaddr>)>,
    ) -> Vec<PeerId> {
        let found = peer_list.len();
        let local = *self.swarm.local_peer_id();
        let dials = discovery_dial_candidates(peer_list, |p| {
            *p == local
                || self.known.contains(p)
                || self.met.contains(p)
                || self.authenticated.contains_key(p)
                || self.dialing.contains(p)
                || self.swarm.is_connected(p)
        });
        debug!(
            query_id = ?query,
            found,
            count = dials.len(),
            known = self.known.len(),
            "dht: dialing discovered peers (address-carrying)"
        );
        let chosen = dials.iter().map(|(peer_id, _)| *peer_id).collect();
        for (peer_id, addrs) in dials {
            self.dial_discovered_peer(peer_id, addrs);
        }
        chosen
    }

    /// Р-17 (network-i43): a discovery round of the timer ended — a quiet one
    /// (found peers, none unknown) counts towards settling the cadence. A
    /// sibling met by cert is not "unknown" either.
    fn discovery_round_done(&mut self, peer_list: &[(PeerId, Vec<Multiaddr>)]) {
        let local = *self.swarm.local_peer_id();
        let found_any = peer_list.iter().any(|(p, _)| *p != local);
        let found_unknown = peer_list
            .iter()
            .any(|(p, _)| *p != local && !self.known.contains(p) && !self.met.contains(p));
        if let Some(reason) = self
            .kad_cadence
            .on_discovery_round(found_any, found_unknown)
        {
            log_cadence_settled(reason, self.known.len(), &self.kad_cadence);
        }
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
        let cid = opts.connection_id();

        match self.swarm.dial(opts) {
            Ok(_) => {
                info!(peer_id = %peer_id, "dht: dialing discovered peer");
                self.dialing.insert(peer_id);
                self.note_dial(cid, peer_id, DialOrigin::Discovery);
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
                QueryResult::Bootstrap(res) => {
                    // Р-17 (NOTE д): libp2p's own bootstrap shows up only as its
                    // first progress step; ours were logged when started.
                    let ours = self.our_bootstraps.contains(&id);
                    if let Some(origin) = bootstrap_origin(ours, step.count.get()) {
                        info!(query_id = ?id, origin = %origin.as_str(), "kademlia bootstrap started");
                        #[cfg(test)]
                        self.test_kad_lookups
                            .push(format!("bootstrap:{}", origin.as_str()));
                    }
                    if step.last {
                        self.our_bootstraps.remove(&id);
                    }
                    match res {
                        Ok(ok) if ok.num_remaining == 0 => info!("kademlia bootstrap complete"),
                        Ok(_) => {}
                        Err(e) => warn!(error = ?e, "kademlia bootstrap failed"),
                    }
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
                        self.discovery_round_done(&peer_list);
                        self.dial_discovery_result(Some(id), peer_list);
                    } else {
                        debug!(
                            query_id = ?id,
                            "dht: get_closest_peers result with no pending caller"
                        );
                    }
                }
                // GetProviders, GetRecord, PutRecord, … — we issue none.
                _ => {}
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
                #[cfg(test)]
                if is_new_peer {
                    *self.test_kad_new_peer.entry(peer).or_default() += 1;
                }
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

    /// A user build has no e2e hold: no connection is ever refused.
    #[cfg(not(feature = "e2e-tools"))]
    fn e2e_is_refused(&self, _cid: libp2p::swarm::ConnectionId) -> bool {
        false
    }

    /// A user build has no e2e hold: there is no refused connection to forget.
    #[cfg(not(feature = "e2e-tools"))]
    fn e2e_forget_closed(&mut self, _cid: libp2p::swarm::ConnectionId) {}

    fn handle_command(&mut self, cmd: SwarmCommand) {
        match cmd {
            SwarmCommand::SendOrDial {
                device,
                addrs,
                message,
                reply,
                dial,
            } => {
                self.send_or_dial(device, addrs, message, reply, dial);
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
                        self.send_app_request(pid, message, reply);
                    }
                }
            }
            SwarmCommand::Dial {
                peer_id,
                addrs,
                origin,
            } => {
                let dial_opts = DialOpts::peer_id(peer_id).addresses(addrs).build();
                let cid = dial_opts.connection_id();
                match self.swarm.dial(dial_opts) {
                    Ok(()) => self.note_dial(cid, peer_id, origin),
                    Err(e) => {
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
            }
            SwarmCommand::ConnStats { reply } => {
                let _ = reply.send(self.conn_stats_snapshot());
            }
            SwarmCommand::ListenAddrs { reply } => {
                let addrs: Vec<Multiaddr> = self.swarm.listeners().cloned().collect();
                let _ = reply.send(addrs);
            }
            SwarmCommand::ExternalAddrs { reply } => {
                let _ = reply.send(self.swarm.external_addresses().cloned().collect());
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
            SwarmCommand::Disconnect {
                peer_id,
                hold,
                reply,
            } => {
                let _ = reply.send(self.e2e_disconnect(peer_id, hold));
            }
            #[cfg(test)]
            SwarmCommand::TestFeedKad {
                peer_id,
                addrs,
                reply,
            } => {
                self.feed_kad(peer_id, &addrs);
                let _ = reply.send(self.kad_addrs_of(&peer_id));
            }
            #[cfg(test)]
            SwarmCommand::TestKadAddrs { peer_id, reply } => {
                let _ = reply.send(self.kad_addrs_of(&peer_id));
            }
            #[cfg(test)]
            SwarmCommand::TestKadNewPeerCount { peer_id, reply } => {
                let n = self.test_kad_new_peer.get(&peer_id).copied().unwrap_or(0);
                let _ = reply.send(n);
            }
            #[cfg(test)]
            SwarmCommand::TestDiscoveryPass { peers, reply } => {
                let _ = reply.send(self.dial_discovery_result(None, peers));
            }
            #[cfg(test)]
            SwarmCommand::TestDialNewConnection { addr, reply } => {
                let opts = DialOpts::unknown_peer_id().address(addr).build();
                let connection_id = opts.connection_id();
                let result = self
                    .swarm
                    .dial(opts)
                    .map(|()| connection_id)
                    .map_err(|e| SwarmError::Transport(e.to_string()));
                let _ = reply.send(result);
            }
            #[cfg(test)]
            SwarmCommand::TestCloseConnection {
                connection_id,
                reply,
            } => {
                let _ = reply.send(self.swarm.close_connection(connection_id));
            }
            #[cfg(test)]
            SwarmCommand::TestEvict { peer_id, reply } => {
                let _ = reply.send(self.test_evict(peer_id));
            }
            #[cfg(test)]
            SwarmCommand::TestEvictLateCert { peer_id, reply } => {
                let Some((_, _, cert)) = self.authenticated.get(&peer_id).cloned() else {
                    let _ = reply.send((false, false));
                    return;
                };
                self.test_evict(peer_id);
                let path = verify_cert_for_peer(&peer_id, &cert, &self.cluster_master_pub)
                    .expect("a cert that authenticated before verifies again");
                let msg = DeviceCertExchangeMsg {
                    cert,
                    x25519_pub: None,
                };
                self.record_authenticated(peer_id, msg, path, false);
                let _ = reply.send((true, self.authenticated.contains_key(&peer_id)));
            }
            #[cfg(test)]
            SwarmCommand::TestRedialOrigins { reply } => {
                let _ = reply.send(self.test_redial_origins.clone());
            }
            #[cfg(test)]
            SwarmCommand::TestLruEntry { peer_id, reply } => {
                let _ = reply.send(self.lru.as_ref().and_then(|l| l.entry_state(&peer_id)));
            }
            #[cfg(test)]
            SwarmCommand::TestKadLookups { reply } => {
                let settled = self.kad_cadence.settled().map(|r| r.as_str());
                let _ = reply.send((self.test_kad_lookups.clone(), settled));
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

/// INFO `kademlia lookup cadence settled` (Р-17, network-i43).
fn log_cadence_settled(reason: SettleReason, known: usize, cadence: &KadCadence) {
    info!(
        reason = %reason.as_str(),
        known,
        interval_secs = cadence.settled_period().map(|d| d.as_secs()).unwrap_or(0),
        "kademlia lookup cadence settled"
    );
}

/// Test-only connection cap (C-DK Р-15): `VIATICUM_E2E_CONN_CAP=N` replaces the
/// policy's cap when it has one (the DR swap stays without a cache).
#[cfg(feature = "e2e-tools")]
fn e2e_conn_cap_from_env(cap: Option<usize>) -> Option<usize> {
    // Only a policy with a cache gets the test cap.
    cap?;
    let raw = std::env::var("VIATICUM_E2E_CONN_CAP").ok()?;
    match raw.trim().parse::<usize>() {
        Ok(n) => Some(n),
        Err(e) => {
            warn!(value = %raw, err = %e, "e2e: VIATICUM_E2E_CONN_CAP is not a number, ignored");
            None
        }
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
