// DaemonHandle: wires all subsystems and manages their lifecycle.
//
// All subsystems are started here: BackupCoordinator, RestoreCoordinator,
// RepairAgent, RelayManager, NetworkHandle, Processor, Watcher, Scheduler,
// and CliServer.

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use hkdf::Hkdf;
use sha2::Sha256;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use syncback_core::cluster::{
    issue_device_certificate, master_identity, ClusterState, DeviceCertificate,
};
use syncback_core::config::AppConfig;
use syncback_core::db::Db;
use syncback_core::erasure::{ErasureEncoder, RaptorQEncoder};
use syncback_core::types::{hex_encode, DeviceId, IdentityPub, Timestamp};

use iroh::RelayMode;

use crate::daemon::backup::{BackupConfig, BackupCoordinator, DirtyEvent};
use crate::daemon::cli_server::{self, CliServerConfig};
use crate::daemon::cluster_sync::{ClusterSyncConfig, ClusterSyncManager};
use crate::daemon::identity::{derive_keys, load_identity, IdentityError};
use crate::daemon::network::{NetworkConfig, NetworkHandle};
use crate::daemon::processor::Processor;
use crate::daemon::relay::{RelayConfig, RelayManager};
use crate::daemon::repair::{RepairAgent, RepairConfig, RepairTrigger};
use crate::daemon::restore::{RestoreConfig, RestoreCoordinator, RestoreError, RestoreRequest, RestoreResult};
use crate::daemon::scheduler::{PendingChallenges, Scheduler, SchedulerConfig};
use crate::daemon::watcher::{WatcherConfig, WatcherError};

// ─── Public config ────────────────────────────────────────────────────────────

/// Top-level daemon configuration passed from main().
pub struct DaemonConfig {
    /// Directory holding identity.key, config.toml, db.redb, symbols/, relay.board.
    pub data_dir: PathBuf,
    /// Expanded (tilde-resolved) Unix socket path.
    pub socket_path: String,
    /// Time acceleration factor. 1 = real time; 604800 = 1 second equals 1 week.
    /// Used to scale periodic intervals in tests and demos.
    pub time_scale: u64,
    /// Directories the watcher will monitor for backup.
    /// Used in Phase 6.4 (Watcher); stored here for future reference.
    pub watch_dirs: Vec<PathBuf>,
}

// ─── DaemonState ──────────────────────────────────────────────────────────────

/// Shared live state threaded from DaemonHandle to subsystems (e.g. CliServer).
///
/// Cheap to clone (Arc internals). Passed as `Arc<DaemonState>` to cli_server.
pub struct DaemonState {
    /// Open database handle.
    pub db: Db,
    /// This node's master identity public key.
    pub identity_pub: IdentityPub,
    /// This device's ID.
    pub device_id: DeviceId,
    /// Network handle for outbound connections (e.g. Connect request).
    pub network: Arc<NetworkHandle>,
    /// Channel to send restore requests to RestoreCoordinator.
    pub restore_tx: mpsc::Sender<(
        RestoreRequest,
        tokio::sync::oneshot::Sender<Result<RestoreResult, RestoreError>>,
    )>,
    /// Cluster state (optional — None before first device registration).
    pub cluster_state: Option<Arc<Mutex<ClusterState>>>,
}

// ─── DaemonHandle ─────────────────────────────────────────────────────────────

/// Owns all subsystem task handles and the cancellation token.
///
/// Call `stop()` to signal shutdown; await `wait()` to join all tasks.
pub struct DaemonHandle {
    cancel: CancellationToken,
    tasks: Vec<tokio::task::JoinHandle<anyhow::Result<()>>>,
}

impl DaemonHandle {
    /// Start the daemon: load identity, open DB, build subsystems, spawn tasks.
    pub async fn start(cfg: DaemonConfig) -> Result<Self, anyhow::Error> {
        // ── 1. Load identity ──────────────────────────────────────────────────
        let keyfile = load_identity(&cfg.data_dir).map_err(|e| match e {
            IdentityError::NotInitialized => {
                anyhow::anyhow!("identity not initialized — run 'syncback init' first")
            }
            other => anyhow::anyhow!("identity load error: {other}"),
        })?;

        // ── 2. Load or create AppConfig ───────────────────────────────────────
        let config_path = cfg.data_dir.join("config.toml");
        let app_config = if config_path.exists() {
            AppConfig::load(&config_path)?
        } else {
            AppConfig::defaults()
        };
        // validate() already called by load(); call it here for the defaults path.
        app_config.validate()?;

        // ── 3. Open DB ────────────────────────────────────────────────────────
        let db = Db::open(&cfg.data_dir.join("db.redb"))?;

        // ── 4. Derive keys ────────────────────────────────────────────────────
        // Epoch 0 is the initial epoch; epoch rotation happens on device revocation.
        let (master_key, device_key, epoch_key_bytes, iroh_key_bytes) = derive_keys(&keyfile, 0)?;
        let identity_pub: IdentityPub = master_identity(&master_key);
        let device_id = DeviceId(keyfile.device_id);

        // ── 5. Initialize or load ClusterState ────────────────────────────────
        let cluster_state: Option<Arc<Mutex<ClusterState>>> =
            match ClusterState::load(db.clone()) {
                Ok(state) => Some(Arc::new(Mutex::new(state))),
                Err(syncback_core::cluster::ClusterStateError::NotInitialized) => {
                    // First-time startup: register this device as the sole cluster member.
                    let device_pub_key = device_key.verifying_key().to_bytes();
                    let now = Timestamp::now();
                    let cert: DeviceCertificate = issue_device_certificate(
                        &master_key,
                        device_id,
                        device_pub_key,
                        now,
                    );
                    match ClusterState::init(db.clone(), identity_pub, cert, now, now) {
                        Ok(state) => {
                            tracing::info!("cluster state initialized (first device)");
                            Some(Arc::new(Mutex::new(state)))
                        }
                        Err(e) => {
                            tracing::error!("failed to init cluster state: {e}");
                            None
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("failed to load cluster state: {e}");
                    None
                }
            };

        // ── 6. Create inter-subsystem channels ────────────────────────────────
        let (dirty_tx, dirty_rx) = mpsc::channel::<DirtyEvent>(256);
        let (restore_tx, restore_rx) = mpsc::channel::<(
            RestoreRequest,
            tokio::sync::oneshot::Sender<Result<RestoreResult, crate::daemon::restore::RestoreError>>,
        )>(16);
        let (repair_tx, repair_rx) = mpsc::channel::<RepairTrigger>(64);
        let (relay_sync_tx, relay_sync_rx) =
            mpsc::channel::<crate::daemon::relay::SyncTrigger>(64);
        let (incoming_tx, incoming_rx) =
            mpsc::channel::<crate::daemon::network::connection::Connection>(64);
        // relay inbound messages → Processor dispatch_relay
        let (inbound_tx, inbound_rx) =
            mpsc::channel::<crate::daemon::relay::InboundMessage>(128);

        // ── 7. Build erasure encoder ──────────────────────────────────────────
        let encoder: Arc<dyn ErasureEncoder> = Arc::new(RaptorQEncoder::new());

        // ── 7a. Load known peers from DB → populate known_peers map ──────────
        // This lets get_connection() find existing peers immediately after restart.
        let known_peers = {
            use crate::daemon::network::addr::{parse_node_addr, to_endpoint_addr};
            let peers = db.list_all_peers().unwrap_or_default();
            let mut map = HashMap::new();
            for peer in peers {
                for addr_str in &peer.addrs {
                    match parse_node_addr(addr_str) {
                        Ok(parsed) => {
                            match to_endpoint_addr(&parsed) {
                                Ok(ea) => {
                                    map.insert(peer.identity, ea);
                                    break;
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        peer = %peer.identity,
                                        addr = %addr_str,
                                        error = %e,
                                        "startup: skipping unparseable peer addr"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                peer = %peer.identity,
                                addr = %addr_str,
                                error = %e,
                                "startup: skipping malformed peer addr"
                            );
                        }
                    }
                }
            }
            tracing::info!(count = map.len(), "loaded peers from db");

            // ── 7b. Inject bootstrap peers from config ────────────────────────
            // Bootstrap peers are added to known_peers so get_connection() can
            // reach them on first contact without a prior peer exchange.
            // Errors are logged and skipped — a bad bootstrap address should not
            // prevent the daemon from starting.
            {
                use crate::daemon::network::addr::{parse_node_addr, to_endpoint_addr};
                let mut bootstrap_added = 0usize;
                for addr_str in &app_config.network.bootstrap_peers {
                    match parse_node_addr(addr_str) {
                        Ok(parsed) => {
                            match to_endpoint_addr(&parsed) {
                                Ok(ea) => {
                                    // Convert NodeId → IdentityPub (both are 32-byte pubkeys).
                                    let identity = syncback_core::types::IdentityPub(parsed.node_id.0);
                                    map.insert(identity, ea);
                                    bootstrap_added += 1;
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        addr = %addr_str,
                                        error = %e,
                                        "startup: skipping bootstrap peer with unparseable addr"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                addr = %addr_str,
                                error = %e,
                                "startup: skipping malformed bootstrap peer addr"
                            );
                        }
                    }
                }
                if bootstrap_added > 0 {
                    tracing::info!(count = bootstrap_added, "loaded bootstrap peers from config");
                }
            }

            map
        };

        // ── 8. Start network ──────────────────────────────────────────────────
        let device_cert_for_network = cluster_state.as_ref().and_then(|cs| {
            let state = cs.lock().expect("cluster_state lock poisoned");
            state
                .get_device(&device_id)
                .map(|entry| entry.certificate.clone())
        });

        let relay_mode = if app_config.network.enable_relay {
            RelayMode::Default
        } else {
            RelayMode::Disabled
        };

        let net_config = NetworkConfig {
            signing_key: device_key.clone(),
            known_peers,
            device_cert: device_cert_for_network,
            iroh_secret_key: Some(iroh::SecretKey::from_bytes(&iroh_key_bytes)),
            relay_mode,
        };
        let network = Arc::new(NetworkHandle::start(net_config, incoming_tx).await?);

        // ── 9. Ensure symbols and holdings directories exist ──────────────────
        let symbols_dir = cfg.data_dir.join("symbols");
        std::fs::create_dir_all(&symbols_dir)?;
        let holdings_dir = cfg.data_dir.join("holdings");
        std::fs::create_dir_all(&holdings_dir)?;

        // ── 10. Build subsystems ──────────────────────────────────────────────
        let source_block_size =
            syncback_core::config::source_block_size_bytes(&app_config);

        let backup = BackupCoordinator::new(
            db.clone(),
            BackupConfig {
                source_block_size,
                symbols_dir: symbols_dir.clone(),
                epoch_key: epoch_key_bytes,
                device_id,
                mock_holders: vec![],
                cluster_state: cluster_state.clone(),
                network: Some(network.clone()),
                watch_configs: app_config.watch.clone(),
            },
            encoder.clone(),
        );

        let restore = RestoreCoordinator::new(
            db.clone(),
            RestoreConfig {
                epoch_key: epoch_key_bytes,
                parallel_holders: 5,
                identity: identity_pub,
                device_id,
                symbols_dir: symbols_dir.clone(),
            },
            encoder.clone(),
            network.clone(),
        );

        let repair = RepairAgent::new(
            db.clone(),
            RepairConfig {
                source_blocks_dir: symbols_dir.clone(),
                symbols_dir: symbols_dir.clone(),
                epoch_key: epoch_key_bytes,
                own_identity: identity_pub,
            },
            encoder.clone(),
        );

        // Derive a stable x25519 private key from seed for relay encryption.
        // HKDF-SHA256(ikm=seed, salt=b"", info=b"syncback-x25519") → 32 bytes.
        let x25519_priv = {
            let hk = Hkdf::<Sha256>::new(Some(b""), &keyfile.seed);
            let mut okm = [0u8; 32];
            hk.expand(b"syncback-x25519", &mut okm)
                .expect("HKDF expand for x25519 cannot fail with valid length");
            x25519_dalek::StaticSecret::from(okm)
        };

        let board_path = cfg.data_dir.join("relay.board");
        let relay = RelayManager::new(RelayConfig {
            board_path,
            identity_pub,
            x25519_priv,
            signing_key: device_key.clone(),
            max_entries: app_config.network.relay_max_entries,
            max_size_bytes: app_config.network.relay_max_size_mb * 1_048_576,
            prune_interval_secs: 3600,
        })?;

        // ── 11. CancellationToken ─────────────────────────────────────────────
        let cancel = CancellationToken::new();

        // ── 12. Build DaemonState (shared with CliServer) ─────────────────────
        // Clone restore_tx so CliServer can forward requests to RestoreCoordinator.
        // The original is held by the cancel task (dropped on shutdown to close channel).
        let state = Arc::new(DaemonState {
            db: db.clone(),
            identity_pub,
            device_id,
            network: network.clone(),
            restore_tx: restore_tx.clone(),
            cluster_state: cluster_state.clone(),
        });

        // ── 13. Start CLI server ──────────────────────────────────────────────
        let cli_config = CliServerConfig {
            socket_path: cfg.socket_path.clone(),
        };
        // The returned handle is a JoinHandle<()>; wrap it so it fits our Vec.
        let cli_handle = cli_server::start(cli_config, cancel.clone(), state).await?;

        // ── 14. Compute scan interval (scaled by time_scale) ──────────────────
        let time_scale = cfg.time_scale.max(1);
        let repair_interval_secs = (3600 / time_scale).max(1);

        // ── 15. Spawn subsystem tasks ─────────────────────────────────────────
        let mut tasks: Vec<tokio::task::JoinHandle<anyhow::Result<()>>> = Vec::new();

        tasks.push(tokio::spawn(backup.run(dirty_rx)));
        tasks.push(tokio::spawn(restore.run(restore_rx)));
        tasks.push(tokio::spawn(repair.run(repair_interval_secs, repair_rx)));
        tasks.push(tokio::spawn(relay.run(relay_sync_rx, inbound_tx)));

        // Wrap the cli server JoinHandle<()> into JoinHandle<anyhow::Result<()>>.
        tasks.push(tokio::spawn(async move {
            cli_handle.await.map_err(|e| anyhow::anyhow!("cli_server task panicked: {e}"))?;
            Ok(())
        }));

        // ── Phase 7.2: spawn Processor ────────────────────────────────────────
        let repair_tx_for_processor = repair_tx.clone();
        let soft_quota_bytes = syncback_core::config::soft_quota_bytes(&app_config);
        let hard_quota_bytes = syncback_core::config::hard_quota_bytes(&app_config);
        // Treat 0 (unlimited sentinel from config) as u64::MAX for Processor.
        let soft_quota_bytes = if soft_quota_bytes == 0 { u64::MAX } else { soft_quota_bytes };
        let hard_quota_bytes = if hard_quota_bytes == 0 { u64::MAX } else { hard_quota_bytes };
        if let Some(cs) = cluster_state.as_ref() {
            let cluster_sync = Arc::new(ClusterSyncManager::new(
                db.clone(),
                ClusterSyncConfig {
                    our_device_id: device_id,
                    batch_size: 1000,
                },
                cs.clone(),
            ));
            let processor = Processor::new(
                db.clone(),
                identity_pub,
                repair_tx_for_processor,
                cluster_sync,
                encoder.clone(),
                holdings_dir.clone(),
                symbols_dir.clone(), // source_blocks_dir: owner's blocks for PoS verification
                network.clone(),
                relay_sync_tx.clone(),
                soft_quota_bytes,
                hard_quota_bytes,
            );
            let cancel_processor = cancel.clone();
            tasks.push(tokio::spawn(async move {
                processor.run(incoming_rx, inbound_rx, cancel_processor).await
            }));
        } else {
            tracing::warn!("cluster state unavailable — Processor not started, incoming connections will be dropped");
            // Drop incoming_rx so the network accept loop's incoming_tx send() will
            // eventually get channel-full backpressure rather than silent discard.
            drop(incoming_rx);
            drop(inbound_rx);
            drop(repair_tx_for_processor);
        }

        // Phase 6.4: spawn Watcher when watch_dirs are configured.
        if !cfg.watch_dirs.is_empty() {
            let watcher_config = WatcherConfig {
                watch_dirs: cfg.watch_dirs.clone(),
                device_id,
                // Debounce 200 ms by default; scale by time_scale for testing.
                debounce_ms: 200 / time_scale.max(1),
            };
            let dirty_tx_watcher = dirty_tx.clone();
            let cancel_watcher = cancel.clone();
            tasks.push(tokio::spawn(async move {
                match crate::daemon::watcher::start_watcher(
                    watcher_config,
                    dirty_tx_watcher,
                    cancel_watcher,
                )
                .await
                {
                    Ok(()) => Ok(()),
                    Err(WatcherError::NoWatchDirs) => {
                        // Shouldn't happen — we checked above.
                        Ok(())
                    }
                    Err(WatcherError::Notify(e)) => {
                        Err(anyhow::anyhow!("watcher error: {e}"))
                    }
                }
            }));
        }
        // ── Phase 6.5: Scheduler ──────────────────────────────────────────────
        // Create the shared PendingChallenges map. The Scheduler writes to it.
        // TODO: wire to Processor so PosResponse can be matched without ESI scan.
        let pending_challenges: PendingChallenges =
            std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

        let scheduler = Scheduler::new(
            db.clone(),
            SchedulerConfig {
                pos_interval_secs: 3600,
                timeout_check_secs: 3600,
                time_scale,
            },
            network.clone(),
            repair_tx.clone(),
            pending_challenges,
        );
        let cancel_scheduler = cancel.clone();
        tasks.push(tokio::spawn(async move {
            scheduler.run(cancel_scheduler).await
        }));

        // Keep channel senders alive so receivers don't immediately close.
        // They are moved into a background task that holds them until cancel fires.
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            cancel_clone.cancelled().await;
            // Dropping senders here closes the channels, which signals subsystems to exit.
            drop(dirty_tx);
            drop(restore_tx);
            drop(repair_tx);
            drop(relay_sync_tx);
        });

        // ── 16. Log startup ───────────────────────────────────────────────────
        let identity_hex = hex_encode(&identity_pub.0);
        tracing::info!(
            identity = %identity_hex,
            data_dir = %cfg.data_dir.display(),
            "daemon started"
        );

        Ok(DaemonHandle { cancel, tasks })
    }

    /// Signal all subsystems to stop.
    pub fn stop(&self) {
        self.cancel.cancel();
    }

    /// Wait for all subsystem tasks to complete.
    ///
    /// Returns the first error encountered, or Ok(()) if all tasks exit cleanly.
    pub async fn wait(self) -> anyhow::Result<()> {
        for task in self.tasks {
            task.await??;
        }
        Ok(())
    }
}
