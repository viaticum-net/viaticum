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
    /// Channel to send connections to the Processor for read-loop spawning.
    /// Used by dispatch_connect for outbound connections.
    pub incoming_tx: mpsc::Sender<crate::daemon::network::connection::Connection>,
    /// Master signing key (for issuing device certs, revocations).
    pub master_key: ed25519_dalek::SigningKey,
    /// Raw seed bytes (for deriving new device keys).
    pub seed: Vec<u8>,
    /// Data directory path (for disk space queries).
    pub data_dir: PathBuf,
    /// Raw soft quota in bytes from config (0 = use disk-based limit).
    pub soft_quota_bytes: u64,
    /// Disk reserve in bytes.
    pub disk_reserve_bytes: u64,
    /// Raw hard quota in bytes from config (0 = no eviction floor).
    pub hard_quota_bytes: u64,
    /// Time acceleration factor (1 = real time).
    pub time_scale: u64,
    /// Channel to post messages to the relay board (e.g. RevocationBroadcast).
    /// None in tests that do not wire up a RelayManager.
    pub relay_post_tx: Option<mpsc::Sender<crate::daemon::relay::RelayPost>>,
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
        let (backup_event_tx, backup_event_rx) =
            mpsc::channel::<crate::daemon::backup::BackupEvent>(64);
        let (relay_sync_tx, relay_sync_rx) =
            mpsc::channel::<crate::daemon::relay::SyncTrigger>(64);
        let (relay_post_tx, relay_post_rx) =
            mpsc::channel::<crate::daemon::relay::RelayPost>(256);
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

            // ── 7b. Bootstrap peers ──────────────────────────────────────────
            // Bootstrap peers are NOT added to known_peers here because the
            // address contains the iroh NodeId, not the SyncBack master identity.
            // Actual connection + identity resolution happens in
            // run_bootstrap_discovery (spawned later), which calls
            // network.connect(None) → gets master identity from handshake →
            // network.add_peer(master_id, addr).

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
            if let Some(url_str) = &app_config.network.relay_url {
                let relay_url: iroh::RelayUrl = url_str
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid relay_url '{url_str}': {e}"))?;
                RelayMode::custom([relay_url])
            } else {
                RelayMode::Default
            }
        } else {
            RelayMode::Disabled
        };

        // Derive a stable x25519 private key from seed for relay encryption.
        // HKDF-SHA256(ikm=seed, salt=b"", info=b"syncback-x25519") → 32 bytes.
        let x25519_priv = {
            let hk = Hkdf::<Sha256>::new(Some(b""), &keyfile.seed);
            let mut okm = [0u8; 32];
            hk.expand(b"syncback-x25519", &mut okm)
                .expect("HKDF expand for x25519 cannot fail with valid length");
            x25519_dalek::StaticSecret::from(okm)
        };
        let x25519_pub_key = x25519_dalek::PublicKey::from(&x25519_priv);

        let net_config = NetworkConfig {
            signing_key: device_key.clone(),
            master_signing_key: master_key.clone(),
            master_identity: identity_pub,
            known_peers,
            device_cert: device_cert_for_network,
            iroh_secret_key: Some(iroh::SecretKey::from_bytes(&iroh_key_bytes)),
            relay_mode,
            x25519_pub: Some(x25519_pub_key.to_bytes()),
        };
        // Clone incoming_tx before it's moved into NetworkHandle::start.
        // The clone goes into DaemonState so dispatch_connect can send outbound
        // connections to the Processor for read-loop spawning.
        let incoming_tx_for_state = incoming_tx.clone();
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
                time_scale: cfg.time_scale.max(1),
                mock_offer_budget_gb: None,
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

        let board_path = cfg.data_dir.join("relay.board");
        let relay = RelayManager::new(RelayConfig {
            board_path,
            identity_pub,
            x25519_priv,
            signing_key: master_key.clone(),
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
            incoming_tx: incoming_tx_for_state.clone(),
            master_key: master_key.clone(),
            seed: keyfile.seed.clone(),
            data_dir: cfg.data_dir.clone(),
            soft_quota_bytes: syncback_core::config::soft_quota_bytes(&app_config),
            disk_reserve_bytes: syncback_core::config::disk_reserve_bytes(&app_config),
            hard_quota_bytes: syncback_core::config::hard_quota_bytes(&app_config),
            time_scale: cfg.time_scale.max(1),
            relay_post_tx: Some(relay_post_tx.clone()),
        });

        // Clone state for web API and metrics pusher before cli_server consumes it.
        let state_for_web_api = if app_config.web_api.enabled {
            Some(state.clone())
        } else {
            None
        };
        let state_for_metrics = if app_config.metrics.enabled {
            Some(state.clone())
        } else {
            None
        };

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

        tasks.push(tokio::spawn(backup.run(dirty_rx, backup_event_rx)));
        tasks.push(tokio::spawn(restore.run(restore_rx)));
        tasks.push(tokio::spawn(repair.run(repair_interval_secs, repair_rx)));
        // Board sync must be faster than PoS timeout so challenges
        // arrive before they expire. POS_TIMEOUT_SECS/time_scale gives
        // the effective timeout; sync at ~1/3 of that, floor 2s.
        let pos_timeout_scaled = (syncback_core::constants::POS_TIMEOUT_SECS / time_scale).max(1);
        let board_sync_interval = (pos_timeout_scaled / 3).max(2);
        tasks.push(tokio::spawn(relay.run(
            relay_sync_rx,
            inbound_tx,
            relay_post_rx,
            db.clone(),
            network.clone(),
            board_sync_interval,
        )));

        // Wrap the cli server JoinHandle<()> into JoinHandle<anyhow::Result<()>>.
        tasks.push(tokio::spawn(async move {
            cli_handle.await.map_err(|e| anyhow::anyhow!("cli_server task panicked: {e}"))?;
            Ok(())
        }));

        // ── Web API server (optional) ─────────────────────────────────────────
        if let Some(web_state) = state_for_web_api {
            let static_dir = if app_config.web_api.static_dir.is_empty() {
                None
            } else {
                let p = std::path::PathBuf::from(&app_config.web_api.static_dir);
                Some(if p.is_absolute() { p } else { cfg.data_dir.join(p) })
            };
            let web_config = crate::daemon::web_api::WebApiConfig {
                port: app_config.web_api.port,
                static_dir,
            };
            let web_handle = crate::daemon::web_api::start(
                web_config,
                cancel.clone(),
                web_state,
            )
            .await?;
            tasks.push(web_handle);
        }

        // ── Phase 7.2: spawn Processor ────────────────────────────────────────
        // Create the PendingChallenges map here so both Processor and Scheduler
        // share the same Arc. Scheduler is wired below; Processor consumes its clone.
        let pending_challenges: PendingChallenges =
            std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

        let repair_tx_for_processor = repair_tx.clone();
        // Raw quota values from config. 0 = "not configured" (use disk-based limit).
        // Processor and holder_cleanup compute effective_quota from disk_free at runtime.
        let soft_quota_bytes = syncback_core::config::soft_quota_bytes(&app_config);
        let hard_quota_bytes = syncback_core::config::hard_quota_bytes(&app_config);
        let disk_reserve_bytes = syncback_core::config::disk_reserve_bytes(&app_config);
        if let Some(cs) = cluster_state.as_ref() {
            let cluster_sync = Arc::new(ClusterSyncManager::new(
                db.clone(),
                ClusterSyncConfig {
                    our_device_id: device_id,
                    batch_size: 1000,
                },
                cs.clone(),
            ));
            // Clone for periodic sync task before cluster_sync is moved into Processor.
            let cluster_sync_for_sync_loop = cluster_sync.clone();

            // Create channel for auto-reconnect read loops and wire to network.
            let (read_loop_tx, read_loop_rx) =
                mpsc::unbounded_channel::<crate::daemon::network::ReadLoopRequest>();
            network.set_read_loop_tx(read_loop_tx);

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
                cfg.data_dir.clone(),
                disk_reserve_bytes,
                backup_event_tx,
                time_scale,
                pending_challenges.clone(),
                relay_post_tx.clone(),
                Some(cs.clone()),
                app_config.escrow.clone(),
            );
            let cancel_processor = cancel.clone();
            tasks.push(tokio::spawn(async move {
                processor.run(incoming_rx, inbound_rx, read_loop_rx, cancel_processor).await
            }));

            // ── Populate cluster_peers from stored addresses (reconnect after restart) ──
            {
                // Collect addrs under lock, then use them without holding guard across .await.
                let stored: Vec<_> = {
                    let guard = cs.lock().unwrap();
                    guard.cluster_addrs()
                        .iter()
                        .filter(|(did, _)| **did != device_id)
                        .map(|(did, hex)| (*did, hex.clone()))
                        .collect()
                };
                for (dev_id, node_id_hex) in stored {
                    // Stored as hex NodeId — parse back to EndpointAddr (relay-assisted).
                    if node_id_hex.len() == 64 {
                        let fake_addr = format!("{node_id_hex}@0.0.0.0:1");
                        if let Ok(parsed) = crate::daemon::network::addr::parse_node_addr(&fake_addr) {
                            if let Ok(ea) = crate::daemon::network::addr::to_endpoint_addr(&parsed) {
                                network.add_cluster_peer(dev_id, ea).await;
                                tracing::info!(?dev_id, "restored cluster peer addr from DB");
                            }
                        }
                    }
                }
            }

            // ── Cluster periodic sync ──────────────────────────────────────────
            {
                let cs_sync = cluster_sync_for_sync_loop;
                let cs_state = cs.clone();
                let cs_network = network.clone();
                let cs_incoming = incoming_tx_for_state.clone();
                let cs_interval = (300 / time_scale).max(10);
                let cancel_cs = cancel.clone();
                tasks.push(tokio::spawn(async move {
                    if let Err(e) = crate::daemon::cluster_sync::run_periodic_sync(
                        cs_sync,
                        cs_state,
                        cs_network,
                        device_id,
                        cs_interval,
                        cancel_cs,
                        cs_incoming,
                    )
                    .await
                    {
                        tracing::error!(error = %e, "cluster periodic sync failed");
                    }
                    Ok(())
                }));
            }
        } else {
            tracing::warn!("cluster state unavailable — Processor not started, incoming connections will be dropped");
            // Drop incoming_rx so the network accept loop's incoming_tx send() will
            // eventually get channel-full backpressure rather than silent discard.
            drop(incoming_rx);
            drop(inbound_rx);
            drop(repair_tx_for_processor);
        }

        // Phase 6.4: spawn Watcher when watch_dirs are configured.
        // Merge CLI --watch-dir with [[watch]] paths from config.
        let mut all_watch_dirs = cfg.watch_dirs.clone();
        for wc in &app_config.watch {
            let p = syncback_core::config::expand_watch_path(&wc.path);
            if !all_watch_dirs.contains(&p) {
                all_watch_dirs.push(p);
            }
        }
        if !all_watch_dirs.is_empty() {
            let watcher_config = WatcherConfig {
                watch_dirs: all_watch_dirs,
                device_id,
                // Debounce 200 ms by default; scale by time_scale for testing.
                debounce_ms: 200 / time_scale.max(1),
                data_dir: cfg.data_dir.clone(),
                // Rescan weekly; scale by time_scale for testing.
                rescan_interval_secs: (604800 / time_scale).max(60),
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
        // Pass the same PendingChallenges Arc created for Processor above.
        // Scheduler writes to it; Processor reads it when verifying PosResponse.
        let scheduler = Scheduler::new(
            db.clone(),
            SchedulerConfig {
                pos_interval_secs: 3600,
                timeout_check_secs: 3600,
                time_scale,
            },
            repair_tx.clone(),
            pending_challenges,
            relay_post_tx.clone(),
            master_key.clone(),
        );
        let cancel_scheduler = cancel.clone();
        tasks.push(tokio::spawn(async move {
            scheduler.run(cancel_scheduler).await
        }));

        // ── Metrics pusher (optional) ──────────────────────────────────────
        if let Some(state_m) = state_for_metrics {
            let metrics_cfg = app_config.metrics.clone();
            let cancel_m = cancel.clone();
            tasks.push(tokio::spawn(async move {
                crate::daemon::metrics::run(metrics_cfg, state_m, cancel_m).await
            }));
        }

        // ── System state periodic push ──────────────────────────────────────
        {
            let ss_db = db.clone();
            let ss_network = network.clone();
            let ss_seed = keyfile.seed.clone();
            let ss_interval = (6 * 3600 / time_scale).max(60);
            let cancel_ss = cancel.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) = crate::daemon::system_state::run_periodic_push(
                    ss_db, ss_network, ss_seed, ss_interval, cancel_ss,
                ).await {
                    tracing::error!(error = %e, "system_state periodic push failed");
                }
                Ok(())
            }));
        }

        // ── Periodic peer discovery ──────────────────────────────────────────
        {
            let disc_db = db.clone();
            let disc_network = network.clone();
            let disc_interval = (300 / time_scale).max(10);
            let cancel_disc = cancel.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) = crate::daemon::system_state::run_periodic_discovery(
                    disc_db, disc_network, disc_interval, cancel_disc,
                ).await {
                    tracing::error!(error = %e, "periodic discovery failed");
                }
                Ok(())
            }));
        }

        // ── Bootstrap auto-connect ──────────────────────────────────────────
        if !app_config.network.bootstrap_peers.is_empty() {
            let net_bs = network.clone();
            let db_bs = db.clone();
            let bootstrap_peers = app_config.network.bootstrap_peers.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::daemon::system_state::run_bootstrap_discovery(
                    net_bs, db_bs, bootstrap_peers,
                ).await {
                    tracing::error!(error = %e, "bootstrap discovery failed");
                }
            });
        }

        // ── Holder cleanup task ────────────────────────────────────────────
        {
            let cleanup_db = db.clone();
            let cleanup_holdings = holdings_dir.clone();
            let cleanup_relay = relay_post_tx.clone();
            let cleanup_cancel = cancel.clone();
            let cleanup_data_dir = cfg.data_dir.clone();
            let cleanup_interval = (3600 / time_scale).max(1);
            let pressure_interval = (3600 / time_scale).max(60);
            tasks.push(tokio::spawn(async move {
                crate::daemon::holder_cleanup::run(
                    cleanup_db,
                    cleanup_holdings,
                    cleanup_relay,
                    soft_quota_bytes,
                    hard_quota_bytes,
                    cleanup_data_dir,
                    disk_reserve_bytes,
                    cleanup_interval,
                    pressure_interval,
                    time_scale,
                    cleanup_cancel,
                ).await
            }));
        }

        // ── Holdings integrity scan task ───────────────────────────────────
        {
            let integrity_db = db.clone();
            let integrity_holdings = holdings_dir.clone();
            let integrity_relay = relay_post_tx.clone();
            let integrity_cancel = cancel.clone();
            let integrity_interval = syncback_core::constants::DEFAULT_HOLDINGS_INTEGRITY_INTERVAL_SECS;
            tasks.push(tokio::spawn(async move {
                crate::daemon::holdings_integrity::run(
                    integrity_db,
                    integrity_holdings,
                    integrity_relay,
                    identity_pub,
                    integrity_interval,
                    time_scale,
                    integrity_cancel,
                )
                .await
            }));
        }

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
            drop(relay_post_tx);
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

// ── Disk space ────────────────────────────────────────────────────────────────

/// Query available bytes on the filesystem containing `path` via statvfs(2).
/// Returns 0 on error (conservative — treats as "disk full").
pub(crate) fn disk_available_bytes(path: &std::path::Path) -> u64 {
    let path_str = match path.to_str() {
        Some(s) => s,
        None => return 0,
    };
    let c_path = match std::ffi::CString::new(path_str) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
            stat.f_bavail * stat.f_frsize
        } else {
            0
        }
    }
}
