mod cli_server;
pub(crate) mod merkle;
mod network;
mod processor;
mod scheduler;
pub(crate) mod shard_manager;
pub mod storage;
mod watcher;

#[cfg(test)]
mod tests;

use std::path::PathBuf;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

// ============================================================
// Channel capacity constants
// ============================================================

const PROCESSOR_CHANNEL_CAPACITY: usize = 256;
const DIRTY_CHANNEL_CAPACITY: usize = 1024;
const NET_EVENT_CHANNEL_CAPACITY: usize = 256;
const NET_CMD_CHANNEL_CAPACITY: usize = 64;

// ============================================================
// Config
// ============================================================

#[derive(Debug, Clone)]
pub struct Config {
    pub syncback_dir: PathBuf,
    pub backup: BackupConfig,
    pub storage: StorageConfig,
    pub network: NetworkConfig,
    pub schedule: ScheduleConfig,
}

#[derive(Debug, Clone)]
pub struct BackupConfig {
    pub include: Vec<IncludeEntry>,
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct IncludeEntry {
    pub path: PathBuf,
    pub importance: f64,
}

#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub quota_gb: u64,
}

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub seed_nodes: Vec<String>,
    pub bandwidth_limit_mbps: u64,
}

#[derive(Debug, Clone)]
pub struct ScheduleConfig {
    pub sync: SyncFrequency,
    pub vacuum: VacuumFrequency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncFrequency {
    Weekly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VacuumFrequency {
    Monthly,
}

impl Config {
    pub fn load(_syncback_dir: PathBuf) -> anyhow::Result<Self> {
        tracing::debug!("config load: using defaults");
        Ok(Self::default())
    }
}

impl Default for Config {
    fn default() -> Self {
        let home = std::env::var("HOME").expect("HOME env var not set");
        let syncback_dir = PathBuf::from(home).join(".syncback");
        Config {
            syncback_dir,
            backup: BackupConfig {
                include: Vec::new(),
                exclude: Vec::new(),
            },
            storage: StorageConfig { quota_gb: 100 },
            network: NetworkConfig {
                seed_nodes: Vec::new(),
                bandwidth_limit_mbps: 0,
            },
            schedule: ScheduleConfig {
                sync: SyncFrequency::Weekly,
                vacuum: VacuumFrequency::Monthly,
            },
        }
    }
}

// ============================================================
// Channel message types
// ============================================================

pub enum ProcessorMsg {
    Scheduled(ScheduledCmd),
    Cli(CliCmd),
}

#[derive(Debug, Clone)]
pub enum ScheduledCmd {
    WeeklySync,
    PosRound,
    Vacuum,
    RepairCheck,
}

#[derive(Debug)]
pub enum CliCmd {
    Status {
        reply: tokio::sync::oneshot::Sender<StatusReply>,
    },
    BackupNow {
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    RestoreFile {
        path: PathBuf,
        dest: PathBuf,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    Shutdown,
}

#[derive(Debug, Clone)]
pub struct DirtyEvent {
    pub path: PathBuf,
    pub kind: DirtyKind,
    pub detected_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirtyKind {
    Created,
    Modified,
    Deleted,
}

/// Events emitted by NetworkTask to Processor.
#[derive(Debug)]
pub enum NetEvent {
    /// Handshake completed successfully on an incoming connection.
    PeerConnected {
        peer_identity: syncback_core::types::IdentityPub,
        peer_node_id: syncback_core::types::NodeId,
    },
    /// A DirectMessage was received from an authenticated peer.
    MessageReceived {
        from: syncback_core::types::IdentityPub,
        message: syncback_core::messages::DirectMessage,
    },
    /// A board-style message received (gossip/board sync).
    BoardMessage {
        from: syncback_core::types::IdentityPub,
        msg_type: String,
        payload: Vec<u8>,
    },
    /// Shard blob successfully uploaded to a holder.
    ShardUploaded {
        shard_id: syncback_core::types::ShardId,
        holder: syncback_core::types::IdentityPub,
        bytes: u64,
    },
    /// Shard blob successfully downloaded/served to a requester.
    ShardDownloaded {
        shard_id: syncback_core::types::ShardId,
        peer: syncback_core::types::IdentityPub,
        bytes: u64,
    },
    /// Network task encountered a fatal, unrecoverable error.
    FatalError(String),
    /// Handshake failed (log and ignore).
    HandshakeFailed {
        reason: String,
    },
}

/// Commands from Processor to NetworkTask.
#[derive(Debug)]
pub enum NetCommand {
    /// Open an outgoing connection to a peer and send a DirectMessage.
    Connect {
        peer_addr: iroh::EndpointAddr,
        peer_identity: syncback_core::types::IdentityPub,
        message: syncback_core::messages::DirectMessage,
    },
    /// Send a DirectMessage to a peer, opening a connection if needed.
    SendMessage {
        peer_identity: syncback_core::types::IdentityPub,
        peer_addr: iroh::EndpointAddr,
        message: syncback_core::messages::DirectMessage,
    },
    /// Publish a message to our iroh-docs board.
    /// msg_type is used as the board key prefix (e.g. "shard_offer").
    /// directed_to: if Some, the message is targeted at a specific peer.
    PublishBoard {
        msg_type: String,
        payload: Vec<u8>,
        directed_to: Option<syncback_core::types::IdentityPub>,
    },
    /// Upload a shard blob to a holder peer via iroh-blobs.
    UploadShard {
        shard_id: syncback_core::types::ShardId,
        holder: syncback_core::types::IdentityPub,
        data: Vec<u8>,
    },
    /// Send a PoS challenge to a holder via board message.
    SendPosChallenge {
        holder: syncback_core::types::IdentityPub,
        shard_id: syncback_core::types::ShardId,
        block_index: u32,
        nonce: [u8; 32],
        challenge_id: [u8; 32],
    },
    /// Send a direct (non-board) message payload to a peer.
    /// Payload is already CBOR-encoded DirectMessage.
    SendDirect {
        peer: syncback_core::types::IdentityPub,
        payload: Vec<u8>,
    },
    /// Connect to a peer by node address string (discovery/bootstrap).
    ConnectAddr {
        node_addr: String,
    },
}

#[derive(Debug, serde::Serialize)]
pub struct StatusReply {
    pub uptime_secs: u64,
    pub peer_count: usize,
    pub shards_held: usize,
    pub shards_placed: usize,
    pub budget_gb: f64,
    pub dirty_files: usize,
}

// ============================================================
// DaemonError
// ============================================================

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("task '{task}' panicked: {msg}")]
    TaskPanicked { task: &'static str, msg: String },

    #[error("cannot open database at {path}: {source}")]
    DbOpen {
        path: PathBuf,
        #[source]
        source: redb::Error,
    },

    #[error("cli socket error: {0}")]
    CliSocket(#[from] std::io::Error),

    #[error("config error: {0}")]
    Config(String),

    #[error("network error: {0}")]
    Network(#[from] network::NetworkError),
}

// ============================================================
// DaemonHandle
// ============================================================

pub struct DaemonHandle {
    cancel: CancellationToken,

    processor_handle: tokio::task::JoinHandle<()>,
    network_handle: tokio::task::JoinHandle<()>,
    scheduler_handle: tokio::task::JoinHandle<()>,
    cli_server_handle: tokio::task::JoinHandle<()>,

    // Keep senders alive so receivers don't close prematurely.
    _dirty_tx: mpsc::Sender<DirtyEvent>,
    _processor_tx: mpsc::Sender<ProcessorMsg>,

    started_at: std::time::Instant,
}

impl DaemonHandle {
    pub async fn start(config: Config) -> Result<Self, DaemonError> {
        let syncback_dir = config.syncback_dir.clone();
        let db_path = syncback_dir.join("syncback.redb");
        let db = syncback_core::db::Db::open(&db_path)
            .unwrap_or_else(|e| panic!("fatal: cannot open DB at {db_path:?}: {e}"));

        let cancel = CancellationToken::new();

        let (processor_tx, processor_rx) = mpsc::channel::<ProcessorMsg>(PROCESSOR_CHANNEL_CAPACITY);
        let (dirty_tx, dirty_rx) = mpsc::channel::<DirtyEvent>(DIRTY_CHANNEL_CAPACITY);
        let (net_event_tx, net_event_rx) = mpsc::channel::<NetEvent>(NET_EVENT_CHANNEL_CAPACITY);

        let cli_socket_path = syncback_dir.join("syncback.sock");
        if cli_socket_path.exists() {
            std::fs::remove_file(&cli_socket_path)?;
        }

        // Generate ephemeral keys for this daemon instance.
        // In production these would be derived from the seed phrase.
        let iroh_secret_key = {
            use rand::RngCore;
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            iroh::SecretKey::from_bytes(&bytes)
        };
        let identity_signing_key = {
            use rand::RngCore;
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            ed25519_dalek::SigningKey::from_bytes(&bytes)
        };
        let identity_pub_bytes: [u8; 32] = identity_signing_key.verifying_key().to_bytes();
        let identity_pub = syncback_core::types::IdentityPub(identity_pub_bytes);

        // Clone identity key so both NetworkTask and Processor can own a copy.
        // ed25519_dalek::SigningKey doesn't impl Clone — use from_bytes.
        let net_identity_key =
            ed25519_dalek::SigningKey::from_bytes(&identity_signing_key.to_bytes());

        let (net_task, net_handle) = network::NetworkTask::new(
            iroh_secret_key,
            net_identity_key,
            identity_pub,
            cancel.clone(),
            iroh::endpoint::RelayMode::Disabled,
        )
        .await?;

        let net_cmd_tx = net_handle.cmd_tx.clone();

        let processor_handle = tokio::spawn(processor::run(
            db,
            cancel.clone(),
            processor_rx,
            dirty_rx,
            net_event_rx,
            net_cmd_tx,
            config.clone(),
            identity_signing_key,
            identity_pub,
        ));

        let network_handle = tokio::spawn({
            let net_event_tx = net_event_tx;
            async move {
                net_task.run(net_event_tx).await;
            }
        });

        let scheduler_handle = tokio::spawn(scheduler::run(
            cancel.clone(),
            processor_tx.clone(),
        ));

        let cli_server_handle = tokio::spawn(cli_server::run(
            cancel.clone(),
            processor_tx.clone(),
            cli_socket_path.clone(),
        ));

        tokio::spawn(watcher::run(cancel.clone(), dirty_tx.clone()));

        tracing::info!(socket = ?cli_socket_path, "daemon started");

        Ok(DaemonHandle {
            cancel,
            processor_handle,
            network_handle,
            scheduler_handle,
            cli_server_handle,
            _dirty_tx: dirty_tx,
            _processor_tx: processor_tx,
            started_at: std::time::Instant::now(),
        })
    }

    pub async fn join(self) -> Result<(), DaemonError> {
        tokio::select! {
            r = self.processor_handle => {
                r.map_err(|e| DaemonError::TaskPanicked { task: "processor", msg: e.to_string() })?;
            }
            r = self.network_handle => {
                r.map_err(|e| DaemonError::TaskPanicked { task: "network", msg: e.to_string() })?;
            }
            r = self.scheduler_handle => {
                r.map_err(|e| DaemonError::TaskPanicked { task: "scheduler", msg: e.to_string() })?;
            }
            r = self.cli_server_handle => {
                r.map_err(|e| DaemonError::TaskPanicked { task: "cli_server", msg: e.to_string() })?;
            }
        }
        Ok(())
    }

    pub async fn shutdown(self) -> Result<(), DaemonError> {
        tracing::info!("shutdown: cancelling all tasks");
        self.cancel.cancel();
        let results = tokio::join!(
            self.processor_handle,
            self.network_handle,
            self.scheduler_handle,
            self.cli_server_handle,
        );
        for (name, r) in [
            ("processor", results.0),
            ("network", results.1),
            ("scheduler", results.2),
            ("cli_server", results.3),
        ] {
            r.map_err(|e| DaemonError::TaskPanicked { task: name, msg: e.to_string() })?;
        }
        tracing::info!("shutdown: complete");
        Ok(())
    }
}
