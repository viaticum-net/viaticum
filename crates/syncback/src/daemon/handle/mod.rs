// DaemonHandle: wires all subsystems and manages their lifecycle.
//
// All subsystems are started here: BackupCoordinator, RestoreCoordinator,
// RepairAgent, RelayManager, SwarmHandle, Processor, Watcher, Scheduler,
// and CliServer.

#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

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

use crate::daemon::backup::{BackupConfig, BackupCoordinator, DirtyEvent};
use crate::daemon::cluster_sync::{ClusterSyncConfig, ClusterSyncManager};
use crate::daemon::identity::{derive_keys, load_identity, IdentityError};
use crate::daemon::processor::Processor;
use crate::daemon::relay::{RelayConfig, RelayManager};
use crate::daemon::repair::RepairTrigger;
use crate::daemon::restore::{RestoreConfig, RestoreCoordinator, RestoreError, RestoreRequest, RestoreResult};
use crate::daemon::scheduler::{PendingChallenges, Scheduler, SchedulerConfig};
use crate::daemon::watcher::{WatcherCommand, WatcherConfig};

// ─── Public config ────────────────────────────────────────────────────────────

/// Top-level daemon configuration passed from main().
pub struct DaemonConfig {
    /// Directory holding identity.key, config.toml, db.redb, symbols/, relay.board.
    pub data_dir: PathBuf,
    /// Time acceleration factor. 1 = real time; 604800 = 1 second equals 1 week.
    /// Used to scale periodic intervals in tests and demos.
    pub time_scale: u64,
    /// Directories the watcher will monitor for backup.
    /// Used in Phase 6.4 (Watcher); stored here for future reference.
    pub watch_dirs: Vec<PathBuf>,
}

// ─── DaemonState ──────────────────────────────────────────────────────────────

/// Shared live state threaded from DaemonHandle to subsystems.
///
/// Cheap to clone (Arc internals). Passed as `Arc<DaemonState>` to dispatch/web_api.
pub struct DaemonState {
    /// Open database handle.
    pub db: Db,
    /// This node's master identity public key.
    pub identity_pub: IdentityPub,
    /// This device's ID.
    pub device_id: DeviceId,
    /// Channel to send restore requests to RestoreCoordinator.
    pub restore_tx: mpsc::Sender<(
        RestoreRequest,
        tokio::sync::oneshot::Sender<Result<RestoreResult, RestoreError>>,
    )>,
    /// Cluster state (optional — None before first device registration).
    pub cluster_state: Option<Arc<Mutex<ClusterState>>>,
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
    /// libp2p swarm handle.
    pub swarm_handle: Option<std::sync::Arc<crate::daemon::network::swarm::SwarmHandle>>,
    /// Watch admin — manages dynamic folder add/remove/status.
    /// None if web API is disabled.
    pub watch_admin: Option<std::sync::Arc<crate::daemon::watch_admin::WatchAdmin>>,
    /// Config admin — read/write the editable subset of config.toml.
    /// None if web API is disabled.
    pub config_admin: Option<std::sync::Arc<crate::daemon::config_admin::ConfigAdmin>>,
    /// Restart gate — guards POST /api/restart so it only fires once.
    /// None if web API is disabled.
    pub restart_gate: Option<std::sync::Arc<crate::daemon::restart::RestartGate>>,
    /// Cancellation token shared with the daemon runtime; the restart handler
    /// cancels it after spawning the child to drain the current process.
    pub shutdown_token: CancellationToken,
    /// Per-peer rejection backoff. Shared by repair + backup pipelines so a
    /// QuotaFull from peer X in one path is also visible to the other.
    pub peer_backoff: std::sync::Arc<crate::daemon::peer_backoff::PeerBackoff>,
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
    /// Returns a clone of the internal cancellation token. Caller can `cancelled()`
    /// it from main() to wake up on either Ctrl-C or an in-process restart trigger.
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Start the daemon: load identity, open DB, build subsystems, spawn tasks.
    pub async fn start(cfg: DaemonConfig) -> Result<Self, anyhow::Error> {
        // Legacy data directory migration hint (one-shot WARN).
        if let Some(home) = dirs::home_dir() {
            let legacy = home.join(".syncback");
            if legacy.exists() && cfg.data_dir != legacy {
                tracing::warn!(
                    legacy_path = %legacy.display(),
                    current_path = %cfg.data_dir.display(),
                    "legacy data directory detected at ~/.syncback; migrate to new platform-native path or set --data-dir explicitly"
                );
            }
        }

        // ── 1. Load identity ──────────────────────────────────────────────────
        let keyfile = load_identity(&cfg.data_dir).map_err(|e| match e {
            IdentityError::NotInitialized => {
                anyhow::anyhow!("identity not initialized — run 'syncback init' first")
            }
            IdentityError::Corrupt(p, msg) => anyhow::anyhow!(
                "identity file at {} is corrupt or from an incompatible binary version ({}). \
                 Delete the file and re-run 'syncback init', or restore from backup.",
                p.display(),
                msg
            ),
            other => anyhow::anyhow!(
                "identity load error from {}: {}",
                cfg.data_dir.join("identity.key").display(),
                other
            ),
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
        // Retry on lock contention: when the daemon self-rexecs (Settings UI
        // restart), the child briefly races the parent for the redb file lock.
        // Total wait ≤ 11 s — same envelope as the libp2p listen-port retry.
        let db_path = cfg.data_dir.join("db.redb");
        let db = open_db_with_retry(&db_path).await?;

        // ── 3.5. Migrate trust_p prior for evidence-less peers ────────────────
        // INITIAL_TRUST_P was raised from 0.1 to 0.5 (neutral Bayesian prior)
        // to give fresh peers a real shot at being chosen as a holder. That
        // value is only applied when a PeerRecord is created — existing rows
        // were sitting at the old prior, indistinguishable from a peer that
        // failed every challenge. One-time bump: any peer with no observed
        // PoS evidence (trust_i == 0.0) and a stored trust_p strictly below
        // the new prior gets bumped. Never lowers an existing trust_p, so
        // there's no risk of softening a deserved penalty.
        {
            use syncback_core::constants::INITIAL_TRUST_P;
            match db.list_all_peers() {
                Ok(peers) => {
                    let mut migrated = 0u32;
                    for mut record in peers {
                        if record.trust_i == 0.0 && record.trust_p < INITIAL_TRUST_P {
                            record.trust_p = INITIAL_TRUST_P;
                            if let Err(e) = db.upsert_peer(&record) {
                                tracing::warn!(device = %record.device_id, err = %e,
                                    "trust_p migration: upsert failed");
                            } else {
                                migrated += 1;
                            }
                        }
                    }
                    if migrated > 0 {
                        tracing::info!(
                            migrated,
                            new_prior = INITIAL_TRUST_P,
                            "trust_p prior migration: bumped evidence-less peers"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(err = %e, "trust_p migration: list_all_peers failed");
                }
            }
        }

        // ── 3.7. Migrate Wave-8 cached reliability fields ─────────────────────
        // Unconditionally populates importance, current_alive, current_reliability,
        // target_reliability on every SourceBlockRecord. Idempotent. Runs before
        // workers and scheduler start so the cached fields are consistent from boot.
        match syncback_core::migration::migrate_block_records(&db) {
            Ok(count) => {
                if count > 0 {
                    tracing::info!(count, "block record cached fields migration complete");
                }
            }
            Err(e) => {
                // Spec wording said `list_all_source_blocks` failure is fatal, but we
                // downgrade to WARN intentionally: daemon should boot even with stale
                // cached fields. Trade-off: Wave 10's priority queue will treat all
                // blocks as "needing work" (current_reliability defaults to 0.0 < target),
                // resulting in O(N) spurious repair attempts on next worker tick. This is
                // safe (over-send, not under-send) — and the worker self-recovers as it
                // re-reads each block. Better than refusing to start the daemon entirely.
                tracing::warn!(err = %e, "block record cached fields migration failed (non-fatal)");
            }
        }

        // ── 4. Derive keys ────────────────────────────────────────────────────
        // Epoch 0 is the initial epoch; epoch rotation happens on device revocation.
        let (master_key, device_key, epoch_key_bytes) = derive_keys(&keyfile, 0)?;
        let identity_pub: IdentityPub = master_identity(&master_key);
        let device_id = DeviceId(keyfile.device_id);

        // ── 5. Initialize or load ClusterState ────────────────────────────────
        let cluster_state: Option<Arc<Mutex<ClusterState>>> =
            match ClusterState::load(db.clone()) {
                Ok(state) => Some(Arc::new(Mutex::new(state))),
                Err(syncback_core::cluster::ClusterStateError::NotInitialized) => {
                    // First-time startup: register this device as the sole cluster member.
                    let now = Timestamp::now();
                    let cert: DeviceCertificate = issue_device_certificate(
                        &master_key,
                        device_id,
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
        // relay inbound messages → Processor dispatch_relay
        let (inbound_tx, inbound_rx) =
            mpsc::channel::<crate::daemon::relay::InboundMessage>(128);

        // ── 7. Build erasure encoder ──────────────────────────────────────────
        let encoder: Arc<dyn ErasureEncoder> = Arc::new(RaptorQEncoder::new());

        // ── 8. Derive x25519 key for relay encryption ────────────────────────
        // HKDF-SHA256(ikm=seed, salt=b"", info=b"syncback-x25519") → 32 bytes.
        let x25519_priv = {
            let hk = Hkdf::<Sha256>::new(Some(b""), &keyfile.seed);
            let mut okm = [0u8; 32];
            hk.expand(b"syncback-x25519", &mut okm)
                .expect("HKDF expand for x25519 cannot fail with valid length");
            x25519_dalek::StaticSecret::from(okm)
        };

        // ── 9. Ensure symbols and holdings directories exist ──────────────────
        let symbols_dir = cfg.data_dir.join("symbols");
        std::fs::create_dir_all(&symbols_dir)?;

        // ── 9.0. Wave 2 migration: remove legacy flat {esi}.bin files (pre-Wave 2) ──
        // These are bound-per-holder symbol files written by the old backup pipeline.
        // After Wave 2, all symbols are raw and live in {block_hex}/raw/{esi}.bin.
        // This cleanup is fast (metadata-only scan) and idempotent.
        if let Err(e) = crate::daemon::backup::pipeline::cleanup_legacy_bound_symbol_files(&symbols_dir) {
            tracing::warn!("startup: cleanup_legacy_bound_symbol_files failed: {e}");
        }

        let holdings_dir = cfg.data_dir.join("holdings");
        std::fs::create_dir_all(&holdings_dir)?;

        // ── 9.1. Ensure restore staging directory exists ──────────────────────
        let staging_root = cfg.data_dir.join("restore");
        std::fs::create_dir_all(&staging_root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&staging_root, std::fs::Permissions::from_mode(0o700))?;
        }

        // ── 9.5. Start libp2p swarm (before subsystems so they can receive swarm handle) ──
        // swarm_event_rx is consumed by Processor::run below.
        let (swarm_handle_arc, swarm_event_rx) = {
            // Pull both the per-device cert and the cluster master pub from
            // ClusterState. master_pub is the anchor for cert verification
            // (see `verify_cert_for_peer`); it's the FOUNDER's identity, not
            // necessarily this node's own derived master.
            let cert_and_master = cluster_state.as_ref().and_then(|cs| {
                let state = cs.lock().expect("cluster_state lock poisoned");
                let cert = state
                    .get_device(&device_id)
                    .map(|entry| entry.certificate.clone())?;
                Some((cert, state.master_pub()))
            });
            if let Some((device_cert, cluster_master_pub)) = cert_and_master {
                let x25519_pub = {
                    let hk = Hkdf::<Sha256>::new(Some(b""), &keyfile.seed);
                    let mut okm = [0u8; 32];
                    hk.expand(b"syncback-x25519", &mut okm)
                        .expect("HKDF expand cannot fail with valid length");
                    let secret = x25519_dalek::StaticSecret::from(okm);
                    let pub_key = x25519_dalek::PublicKey::from(&secret);
                    Some(pub_key.to_bytes())
                };
                // Parse kademlia_bootstrap_peers from config strings → Multiaddr.
                // AppConfig::validate() already checked basic syntax; full parse here.
                let kademlia_bootstrap_peers: Vec<libp2p::Multiaddr> = app_config
                    .network
                    .kademlia_bootstrap_peers
                    .iter()
                    .filter_map(|s| {
                        s.parse::<libp2p::Multiaddr>().map_err(|e| {
                            tracing::warn!(addr = %s, error = %e, "skipping unparseable kademlia bootstrap peer");
                        }).ok()
                    })
                    .collect();

                let swarm_cfg = crate::daemon::network::swarm::SwarmConfig {
                    device_signing_key: device_key.clone(),
                    master_signing_key: master_key.clone(),
                    identity_pub,
                    cluster_master_pub,
                    device_cert,
                    x25519_pub,
                    listen_port: app_config.network.listen_port,
                    cert_timeout_secs: 10,
                    kademlia_bootstrap_peers,
                    kademlia_disable_ipfs_bootstrap: app_config
                        .network
                        .kademlia_disable_ipfs_bootstrap,
                    kad_republish_interval_override: None,
                    kad_discovery_interval_override: None,
                };
                match crate::daemon::network::swarm::SwarmHandle::start(swarm_cfg).await {
                    Ok((handle, events)) => {
                        tracing::info!(
                            peer_id = %handle.peer_id,
                            "libp2p swarm started (ε.2, wired to processor)"
                        );
                        (Some(Arc::new(handle)), Some(events))
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "libp2p swarm start failed, continuing without it");
                        (None, None)
                    }
                }
            } else {
                tracing::debug!("no device cert available, skipping libp2p swarm start");
                (None, None)
            }
        };

        // ── 10. Build subsystems ──────────────────────────────────────────────
        let source_block_size =
            syncback_core::config::source_block_size_bytes(&app_config);

        // ── Step A: Build live_configs Arc ────────────────────────────────────
        // Merge CLI watch_dirs with [[watch]] entries from config.
        let mut initial_watch_configs: Vec<syncback_core::config::WatchConfig> =
            app_config.watch.clone();
        for dir in &cfg.watch_dirs {
            let dir_str = dir.to_string_lossy().to_string();
            if !initial_watch_configs.iter().any(|wc| {
                syncback_core::config::expand_watch_path(&wc.path) == *dir
            }) {
                initial_watch_configs.push(syncback_core::config::WatchConfig {
                    path: dir_str,
                    importance_multiplier: syncback_core::config::DEFAULT_IMPORTANCE_MULTIPLIER,
                    was_legacy_importance: false,
                    classification: None,
                    bursts: None,
                });
            }
        }

        // Compute FolderClassification for each configured watch directory.
        // This is a one-time synchronous scan (capped at CLASSIFY_SCAN_CAP paths).
        // Must run BEFORE live_configs is published to BackupCoordinator.
        for wc in &mut initial_watch_configs {
            wc.populate_classification();
            wc.populate_bursts(); // Wave 7: detect time-clustered media bursts
        }
        // Emit legacy field deprecation warnings once per legacy watch entry.
        for wc in &initial_watch_configs {
            if wc.was_legacy_importance {
                let expanded = syncback_core::config::expand_watch_path(&wc.path);
                tracing::warn!(
                    target: "config",
                    "watch[{}].importance is deprecated; field now interpreted as \
                     importance_multiplier (range [0, 2], default 1.0). If you intended \
                     this as a multiplier no action needed; otherwise update your config.",
                    expanded.display()
                );
            }
        }

        let live_configs: Arc<RwLock<Vec<syncback_core::config::WatchConfig>>> =
            Arc::new(RwLock::new(initial_watch_configs.clone()));

        // ── Step B: Create watcher command channel ────────────────────────────
        let (watcher_cmd_tx, watcher_cmd_rx) = mpsc::channel::<WatcherCommand>(64);

        // Create accepted_offers map shared between BackupCoordinator and Processor.
        let accepted_offers = crate::daemon::processor::make_empty_accepted_offers();

        // Per-peer rejection backoff. 6h cooldown in production, scaled by
        // time_scale so demos and tests see proportionally shorter cooldowns.
        let peer_backoff_secs =
            (crate::daemon::peer_backoff::DEFAULT_COOLDOWN_SECS / cfg.time_scale.max(1)).max(1);
        let peer_backoff = Arc::new(crate::daemon::peer_backoff::PeerBackoff::new(
            peer_backoff_secs,
        ));

        let backup = BackupCoordinator::new(
            db.clone(),
            BackupConfig {
                source_block_size,
                symbols_dir: symbols_dir.clone(),
                epoch_key: epoch_key_bytes,
                device_id,
                mock_holders: vec![],
                cluster_state: cluster_state.clone(),
                watch_configs: initial_watch_configs.clone(),
                time_scale: cfg.time_scale.max(1),
                mock_offer_budget_gb: None,
                master_signing_key: Some(master_key.clone()),
                swarm: swarm_handle_arc.clone(),
                // ── Step C: Pass live_watch_configs ──────────────────────────
                live_watch_configs: Some(Arc::clone(&live_configs)),
                peer_backoff: Some(Arc::clone(&peer_backoff)),
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
                swarm: swarm_handle_arc.clone(),
                staging_root: staging_root.clone(),
                data_dir: cfg.data_dir.clone(),
                fetch_timeout: std::time::Duration::from_secs(
                    app_config.restore.fetch_timeout_secs,
                ),
            },
            encoder.clone(),
        );

        // RepairAgent is now only used for periodic reliability_scan (Wave 11b).
        // The repair instance is created in the reliability_scan task below.
        // The old repair.run() task is replaced by the WorkPipeline worker.

        let board_path = cfg.data_dir.join("relay.board");
        let relay = RelayManager::new(RelayConfig {
            board_path,
            identity_pub,
            x25519_priv,
            signing_key: master_key.clone(),
            max_entries: app_config.network.relay_max_entries,
            max_size_bytes: app_config.network.relay_max_size_mb * 1_048_576,
            prune_interval_secs: (3600 / cfg.time_scale.max(1)).max(5),
            ttl_secs: (syncback_core::constants::RELAY_TTL_SECS / cfg.time_scale.max(1)).max(60),
        })?;

        // ── 11. CancellationToken ─────────────────────────────────────────────
        let cancel = CancellationToken::new();

        // ── Step D: Create WatchAdmin ──────────────────────────────────────────
        let watch_admin = Arc::new(crate::daemon::watch_admin::WatchAdmin::new(
            config_path.clone(),
            Arc::clone(&live_configs),
            watcher_cmd_tx.clone(),
            db.clone(),
        ));

        // ── Step D.1: Create ConfigAdmin and RestartGate ──────────────────────
        let config_admin =
            Arc::new(crate::daemon::config_admin::ConfigAdmin::new(config_path.clone()));
        let restart_gate = Arc::new(crate::daemon::restart::RestartGate::new());

        // ── 12. Build DaemonState (shared with CliServer) ─────────────────────
        // Clone restore_tx so CliServer can forward requests to RestoreCoordinator.
        // The original is held by the cancel task (dropped on shutdown to close channel).
        let state = Arc::new(DaemonState {
            db: db.clone(),
            identity_pub,
            device_id,
            restore_tx: restore_tx.clone(),
            cluster_state: cluster_state.clone(),
            master_key: master_key.clone(),
            seed: keyfile.seed.clone(),
            data_dir: cfg.data_dir.clone(),
            soft_quota_bytes: syncback_core::config::soft_quota_bytes(&app_config),
            disk_reserve_bytes: syncback_core::config::disk_reserve_bytes(&app_config),
            hard_quota_bytes: syncback_core::config::hard_quota_bytes(&app_config),
            time_scale: cfg.time_scale.max(1),
            relay_post_tx: Some(relay_post_tx.clone()),
            swarm_handle: swarm_handle_arc.clone(),
            // ── Step E: Add watch_admin to DaemonState ────────────────────────
            watch_admin: if app_config.web_api.enabled {
                Some(Arc::clone(&watch_admin))
            } else {
                None
            },
            config_admin: if app_config.web_api.enabled {
                Some(Arc::clone(&config_admin))
            } else {
                None
            },
            restart_gate: if app_config.web_api.enabled {
                Some(Arc::clone(&restart_gate))
            } else {
                None
            },
            shutdown_token: cancel.clone(),
            peer_backoff: Arc::clone(&peer_backoff),
        });

        // Clone state for web API and metrics pusher.
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

        // ── 13. (removed) Unix socket CLI server — CLI now speaks HTTP ───────

        // ── 14. Compute scan interval (scaled by time_scale) ──────────────────
        let time_scale = cfg.time_scale.max(1);
        let reliability_scan_interval_secs = (3600 / time_scale).max(1);

        // ── 14.5. Create WorkPipeline channel ────────────────────────────────
        let (work_event_tx, work_event_rx) =
            tokio::sync::mpsc::channel::<crate::daemon::work_pipeline::WorkEvent>(64);

        // ── 15. Spawn subsystem tasks ─────────────────────────────────────────
        let mut tasks: Vec<tokio::task::JoinHandle<anyhow::Result<()>>> = Vec::new();

        tasks.push(tokio::spawn(backup.run(dirty_rx, backup_event_rx)));
        tasks.push(tokio::spawn(restore.run(restore_rx)));

        // Wave 11b: RepairAgent::run() replaced by WorkPipeline worker + periodic reliability_scan.
        // RepairTrigger channel (repair_rx) is forwarded to work_event_tx to wake the worker.
        {
            let work_event_tx_relay = work_event_tx.clone();
            let cancel_relay = cancel.clone();
            tasks.push(tokio::spawn(async move {
                let mut repair_rx = repair_rx;
                loop {
                    tokio::select! {
                        _ = cancel_relay.cancelled() => break,
                        maybe_trigger = repair_rx.recv() => {
                            match maybe_trigger {
                                None => break,
                                Some(_trigger) => {
                                    // Wake the worker: a PoS failure or explicit trigger
                                    // means a placement is now Lost — worker will pick it up.
                                    let _ = work_event_tx_relay.try_send(
                                        crate::daemon::work_pipeline::WorkEvent::DirtyFileEnqueued,
                                    );
                                }
                            }
                        }
                    }
                }
                Ok(())
            }));
        }

        // Periodic reliability scan (keeps cached fields consistent as a safety net).
        {
            let repair_for_scan = crate::daemon::repair::RepairAgent::new(
                db.clone(),
                crate::daemon::repair::RepairConfig {
                    source_blocks_dir: symbols_dir.clone(),
                    symbols_dir: symbols_dir.clone(),
                    epoch_key: epoch_key_bytes,
                    own_identity: identity_pub,
                    master_signing_key: Some(master_key.clone()),
                    swarm: swarm_handle_arc.clone(),
                    peer_backoff: Some(Arc::clone(&peer_backoff)),
                },
                encoder.clone(),
            );
            let cancel_scan = cancel.clone();
            tasks.push(tokio::spawn(async move {
                let mut ticker = tokio::time::interval(
                    tokio::time::Duration::from_secs(reliability_scan_interval_secs),
                );
                ticker.tick().await; // skip immediate tick
                loop {
                    tokio::select! {
                        _ = cancel_scan.cancelled() => break Ok(()),
                        _ = ticker.tick() => {
                            let updated = repair_for_scan.reliability_scan().await;
                            if updated > 0 {
                                tracing::info!(updated, "reliability_scan: background pass complete");
                            }
                        }
                    }
                }
            }));
        }

        // ── 9.2. Spawn staging cleanup checker (warn if staging dir is large) ──
        {
            let staging_root_for_warn = staging_root.clone();
            let warn_bytes = (app_config.restore.staging_warn_gb * 1_073_741_824.0) as u64;
            let cancel_for_warn = cancel.clone();
            tasks.push(tokio::spawn(async move {
                // Check immediately at startup.
                tokio::task::block_in_place(|| {
                    crate::daemon::restore::cleanup::check_staging_warn(&staging_root_for_warn, warn_bytes);
                });
                // Then check every hour.
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
                interval.tick().await; // skip immediate tick (already checked above)
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            tokio::task::block_in_place(|| {
                                crate::daemon::restore::cleanup::check_staging_warn(&staging_root_for_warn, warn_bytes);
                            });
                        }
                        _ = cancel_for_warn.cancelled() => break,
                    }
                }
                Ok(())
            }));
        }
        // ── 9.3. Peer auto-dial: bootstrap from PeerRecord on startup,
        //         periodic re-dial of known peers we are not currently connected to.
        //         Without this, every daemon restart leaves the swarm isolated:
        //         libp2p doesn't dial saved peers on its own, and PeerRecord rows
        //         are useless until something issues a dial. Identify-driven persist
        //         (processor::on_peer_identified) keeps `addrs` fresh on every
        //         identify Received, so this loop always sees the latest endpoints.
        if let Some(swarm_for_redial) = state.swarm_handle.clone() {
            let db_for_redial = db.clone();
            let cancel_for_redial = cancel.clone();
            // 5 min real time, scaled (30 s on time_scale=10); floor 30 s so we
            // don't re-dial-storm a single offline peer.
            let redial_interval = std::time::Duration::from_secs(
                (300 / time_scale).max(30),
            );
            tasks.push(tokio::spawn(async move {
                use libp2p::{multiaddr::Protocol, Multiaddr};
                use std::str::FromStr;

                async fn redial_known_peers(
                    db: &Db,
                    swarm: &crate::daemon::network::swarm::SwarmHandle,
                ) {
                    // peer_sets returns DeviceIds: (connected_devices, auth_devices).
                    // A device is "connected" only after cert exchange, which
                    // implies a live transport — exactly what we want to skip
                    // re-dialing. (Pre-cert connections are transient enough that
                    // re-dialing them is harmless.)
                    let connected_devices: std::collections::HashSet<_> =
                        match swarm.peer_sets().await {
                            Ok((conn, _auth)) => conn.into_iter().collect(),
                            Err(_) => return,
                        };
                    let peers = match db.list_all_peers() {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    let mut dialed = 0u32;
                    let mut skipped_already = 0u32;
                    for record in &peers {
                        if connected_devices.contains(&record.device_id) {
                            skipped_already += 1;
                            continue;
                        }
                        for addr_str in &record.addrs {
                            let addr = match Multiaddr::from_str(addr_str) {
                                Ok(a) => a,
                                Err(_) => continue,
                            };
                            let peer_id = addr.iter().find_map(|p| match p {
                                Protocol::P2p(pid) => Some(pid),
                                _ => None,
                            });
                            let peer_id = match peer_id {
                                Some(p) => p,
                                None => continue,
                            };
                            if let Err(e) = swarm.dial(peer_id, addr).await {
                                tracing::debug!(peer = %peer_id, err = %e,
                                    "auto-dial failed (will retry next tick)");
                            } else {
                                dialed += 1;
                            }
                        }
                    }
                    if dialed > 0 || skipped_already > 0 {
                        tracing::info!(
                            dialed,
                            already_connected = skipped_already,
                            known_peers = peers.len(),
                            "auto-dial pass"
                        );
                    }
                }

                // Initial bootstrap: dial everything we know about as soon as we
                // come up. This is what makes restart actually re-establish links.
                redial_known_peers(&db_for_redial, &swarm_for_redial).await;

                let mut ticker = tokio::time::interval(redial_interval);
                ticker.tick().await; // skip the immediate tick
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {
                            redial_known_peers(&db_for_redial, &swarm_for_redial).await;
                        }
                        _ = cancel_for_redial.cancelled() => break,
                    }
                }
                Ok(())
            }));
        }

        // Board sync must be faster than PoS timeout so challenges arrive before
        // they expire (POS_TIMEOUT_SECS/time_scale → sync at ~1/3 of that), AND
        // it must be fast enough to propagate SymbolDropped notices so owners
        // can repair freed-up placements promptly. We cap at 10 min (scaled by
        // time_scale, so 1 min at scale=10), floor 2s.
        let pos_timeout_scaled = (syncback_core::constants::POS_TIMEOUT_SECS / time_scale).max(1);
        let drop_notice_cap = (600 / time_scale).max(2);
        let board_sync_interval = (pos_timeout_scaled / 3).min(drop_notice_cap).max(2);
        let swarm_for_relay = state.swarm_handle.clone();
        tasks.push(tokio::spawn(relay.run(
            relay_sync_rx,
            inbound_tx,
            relay_post_rx,
            db.clone(),
            board_sync_interval,
            swarm_for_relay,
        )));

        // ── Step E.5: Background rollup refresh task (every 5 min) ────────────
        if let Some(admin) = state.watch_admin.as_ref() {
            let admin_for_refresh = Arc::clone(admin);
            let cancel_refresh = cancel.clone();
            tasks.push(tokio::spawn(async move {
                let mut ticker =
                    tokio::time::interval(std::time::Duration::from_secs(300));
                ticker.tick().await; // skip immediate tick (done in WatchAdmin::new)
                loop {
                    tokio::select! {
                        _ = cancel_refresh.cancelled() => break Ok(()),
                        _ = ticker.tick() => {
                            if let Err(e) = admin_for_refresh.recompute_all_rollups() {
                                tracing::warn!(error = %e, "rollup refresh failed");
                            }
                        }
                    }
                }
            }));
        }

        // ── Web API server (optional) ─────────────────────────────────────────
        if let Some(web_state) = state_for_web_api {
            let static_dir = if app_config.web_api.static_dir.is_empty() {
                None
            } else {
                let p = std::path::PathBuf::from(&app_config.web_api.static_dir);
                Some(if p.is_absolute() { p } else { cfg.data_dir.join(p) })
            };
            let web_config = crate::daemon::web_api::WebApiConfig {
                bind: app_config.web_api.bind.clone(),
                static_dir,
            };
            // Load (or create) the bearer token; wrap in AuthState.
            let token = crate::daemon::web_auth::load_or_create_token(&cfg.data_dir)?;
            let auth = crate::daemon::web_auth::AuthState::new(token);
            // Bind now to capture the actual OS-chosen port, then persist it for the CLI.
            let listener = tokio::net::TcpListener::bind(&web_config.bind).await?;
            let actual_port = listener.local_addr()?.port();
            crate::daemon::web_auth::write_port_file(&cfg.data_dir, actual_port)?;
            let web_handle = crate::daemon::web_api::start_with_listener(
                web_config,
                listener,
                cancel.clone(),
                web_state,
                auth,
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

            // Require a SwarmHandle to start Processor. If swarm failed to start,
            // skip Processor (same degraded behavior as before).
            let swarm_for_processor = match swarm_handle_arc.clone() {
                Some(s) => s,
                None => {
                    tracing::warn!("swarm unavailable — Processor not started");
                    drop(inbound_rx);
                    drop(repair_tx_for_processor);
                    return Ok(DaemonHandle { cancel, tasks });
                }
            };
            let swarm_event_rx_for_processor = match swarm_event_rx {
                Some(rx) => rx,
                None => {
                    tracing::warn!("swarm events unavailable — Processor not started");
                    drop(inbound_rx);
                    drop(repair_tx_for_processor);
                    return Ok(DaemonHandle { cancel, tasks });
                }
            };

            let mut processor = Processor::new(
                db.clone(),
                identity_pub,
                repair_tx_for_processor,
                cluster_sync,
                holdings_dir.clone(),
                swarm_for_processor,
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
                accepted_offers.clone(),
                master_key.clone(),
            );
            // Wire WorkPipeline event channel to Processor so on_peer_authenticated
            // sends WorkEvent::PeerAuthenticated to wake the worker.
            processor.set_work_event_tx(work_event_tx.clone());

            // ── Spawn WorkPipeline worker ──────────────────────────────────────
            {
                let work_pipeline_config = crate::daemon::work_pipeline::WorkPipelineConfig {
                    // Cooldown: 30s in production. Scale with time_scale for demos/tests.
                    cooldown: std::time::Duration::from_secs(
                        (30 / time_scale).max(1),
                    ),
                    // Tick interval: 60s in production. Scale with time_scale.
                    tick_interval: std::time::Duration::from_secs(
                        (60 / time_scale).max(1),
                    ),
                    completion_bonus_coef: app_config.reliability.completion_bonus_coefficient,
                    device_id,
                    epoch_key: epoch_key_bytes,
                    min_pool_size: 2,
                    time_scale,
                };
                let worker = crate::daemon::work_pipeline::WorkPipeline::new(
                    db.clone(),
                    work_pipeline_config,
                    encoder.clone(),
                    swarm_handle_arc.clone(),
                    Some(master_key.clone()),
                    Some(Arc::clone(&peer_backoff)),
                    cluster_state.clone(),
                    work_event_rx,
                );
                tasks.push(tokio::spawn(async move {
                    worker.run().await
                }));
            }

            let cancel_processor = cancel.clone();
            tasks.push(tokio::spawn(async move {
                processor.run(swarm_event_rx_for_processor, inbound_rx, cancel_processor).await
            }));

            // ── Cluster periodic sync ──────────────────────────────────────────
            {
                let cs_sync = cluster_sync_for_sync_loop;
                let cs_state = cs.clone();
                let cs_swarm = swarm_handle_arc.clone();
                let cs_interval = (300 / time_scale).max(10);
                let cancel_cs = cancel.clone();
                tasks.push(tokio::spawn(async move {
                    // Only run if swarm is available; otherwise skip (no libp2p cluster sync).
                    if let Some(swarm) = cs_swarm {
                        if let Err(e) = crate::daemon::cluster_sync::run_periodic_sync(
                            cs_sync,
                            cs_state,
                            swarm,
                            device_id,
                            cs_interval,
                            cancel_cs,
                        )
                        .await
                        {
                            tracing::error!(error = %e, "cluster periodic sync failed");
                        }
                    } else {
                        tracing::warn!("swarm unavailable — cluster periodic sync not started");
                    }
                    Ok(())
                }));
            }
        } else {
            tracing::warn!("cluster state unavailable — Processor not started");
            drop(inbound_rx);
            drop(repair_tx_for_processor);
        }

        // ── Step F: Spawn watcher — ALWAYS (even with empty dir list) ────────
        // Merge CLI --watch-dir with [[watch]] paths from config (same as initial_watch_configs).
        let mut all_watch_dirs = cfg.watch_dirs.clone();
        for wc in &app_config.watch {
            let p = syncback_core::config::expand_watch_path(&wc.path);
            if !all_watch_dirs.contains(&p) {
                all_watch_dirs.push(p);
            }
        }
        {
            let watcher_config = WatcherConfig {
                watch_dirs: all_watch_dirs,
                device_id,
                // Debounce 200 ms by default; scale by time_scale for testing.
                debounce_ms: 200 / time_scale.max(1),
                data_dir: cfg.data_dir.clone(),
                // Rescan weekly; scale by time_scale for testing.
                rescan_interval_secs: (604800 / time_scale).max(60),
                watch_states: state
                    .watch_admin
                    .as_ref()
                    .map(|a| Arc::clone(&a.watch_states)),
            };
            let dirty_tx_watcher = dirty_tx.clone();
            let cancel_watcher = cancel.clone();
            tasks.push(tokio::spawn(async move {
                crate::daemon::watcher::start_watcher(
                    watcher_config,
                    dirty_tx_watcher,
                    watcher_cmd_rx,
                    cancel_watcher,
                )
                .await
                .map_err(|e| anyhow::anyhow!("watcher error: {e}"))
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
                event_log_retain_rows: 100_000,
                pos_weekly_retain_weeks: syncback_core::constants::P_WINDOW_WEEKS * 2,
            },
            repair_tx.clone(),
            pending_challenges,
            relay_post_tx.clone(),
            master_key.clone(),
            symbols_dir.clone(),
            accepted_offers,
            encoder.clone(),
            epoch_key_bytes,
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
        // Uses SwarmHandle (ε.2+). Only started if swarm is available.
        {
            let ss_db = db.clone();
            let ss_swarm = swarm_handle_arc.clone();
            let ss_seed = keyfile.seed.clone();
            let ss_interval = (6 * 3600 / time_scale).max(60);
            let cancel_ss = cancel.clone();
            tasks.push(tokio::spawn(async move {
                if let Some(swarm) = ss_swarm {
                    if let Err(e) = crate::daemon::system_state::run_periodic_push(
                        ss_db, swarm, ss_seed, ss_interval, cancel_ss,
                    ).await {
                        tracing::error!(error = %e, "system_state periodic push failed");
                    }
                } else {
                    tracing::warn!("swarm unavailable — system_state periodic push not started");
                }
                Ok(())
            }));
        }

        // ── Holder cleanup task ────────────────────────────────────────────
        {
            let cleanup_db = db.clone();
            let cleanup_holdings = holdings_dir.clone();
            let cleanup_relay = relay_post_tx.clone();
            let cleanup_cancel = cancel.clone();
            let cleanup_data_dir = cfg.data_dir.clone();
            let cleanup_master_key = master_key.clone();
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
                    cleanup_master_key,
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
            let integrity_master_key = master_key.clone();
            let integrity_interval = syncback_core::constants::DEFAULT_HOLDINGS_INTEGRITY_INTERVAL_SECS;
            tasks.push(tokio::spawn(async move {
                crate::daemon::holdings_integrity::run(
                    integrity_db,
                    integrity_holdings,
                    integrity_relay,
                    identity_pub,
                    integrity_interval,
                    time_scale,
                    integrity_master_key,
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
            drop(work_event_tx);
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

// ── DB open retry ────────────────────────────────────────────────────────────

/// Wrap `Db::open` in an exponential backoff (≤ ~60s total) so a freshly
/// rexec'd child can wait for the parent to release the redb file lock.
///
/// Parent shutdown can be slow — `DaemonHandle::wait` joins every task
/// sequentially, and a BackupCoordinator with an in-flight symbol-write
/// cycle can hold the DB Arc for tens of seconds before exiting. The
/// envelope must outlast the slowest realistic parent drain; 11s was
/// observed to lose races under active backup load.
async fn open_db_with_retry(path: &std::path::Path) -> Result<Db, anyhow::Error> {
    let backoffs_ms = [0u64, 500, 1000, 2000, 4000, 8000, 16000, 16000, 16000];
    let mut last_err: Option<anyhow::Error> = None;
    for (i, ms) in backoffs_ms.iter().enumerate() {
        if *ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(*ms)).await;
        }
        match Db::open(path) {
            Ok(db) => {
                if i > 0 {
                    tracing::info!(attempts = i + 1, "db open succeeded after retry");
                }
                return Ok(db);
            }
            Err(e) => {
                let msg = e.to_string();
                let is_lock = msg.contains("Database already open")
                    || msg.contains("Cannot acquire lock");
                if !is_lock {
                    return Err(e.into());
                }
                tracing::warn!(attempt = i + 1, error = %msg, "db locked, retrying");
                last_err = Some(e.into());
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("db open failed after retries")))
}

// ── Disk space ────────────────────────────────────────────────────────────────

/// Query available bytes on the filesystem containing `path` via `sysinfo`.
/// Returns 0 if no mount point matches (conservative — treats as "disk full").
pub(crate) fn disk_available_bytes(path: &std::path::Path) -> u64 {
    use sysinfo::Disks;
    let disks = Disks::new_with_refreshed_list();
    disks
        .list()
        .iter()
        .filter(|d| path.starts_with(d.mount_point()))
        .max_by_key(|d| d.mount_point().as_os_str().len())
        .map(|d| d.available_space())
        .unwrap_or(0)
}
