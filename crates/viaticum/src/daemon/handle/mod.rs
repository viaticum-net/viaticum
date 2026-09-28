// DaemonHandle: wires all subsystems and manages their lifecycle.
//
// All subsystems are started here: BackupCoordinator, RestoreCoordinator,
// RepairAgent, SwarmHandle, Processor, Watcher, Scheduler, the mailbox poll/sweep
// tasks, and CliServer.

pub(crate) mod redial;
pub mod shutdown;
pub mod startup;
#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use viaticum_core::cluster::{
    ClusterState, ClusterStateError, DeviceCertificate, issue_device_certificate, master_identity,
};
use viaticum_core::config::AppConfig;
use viaticum_core::db::{Db, DbError};
use viaticum_core::erasure::{ErasureEncoder, RaptorQEncoder};
use viaticum_core::types::{DeviceId, IdentityPub, Timestamp, hex_encode};

use crate::daemon::backup::{BackupConfig, BackupCoordinator, DirtyEvent};
use crate::daemon::cluster_sync::{ClusterSyncConfig, ClusterSyncManager};
use crate::daemon::identity::{
    IdentityError, corrupt_key_hint, derive_keys, load_identity, not_initialized_hint,
};
use crate::daemon::processor::Processor;
use crate::daemon::repair::RepairTrigger;
use crate::daemon::restore::{RestoreConfig, RestoreCoordinator, RestoreRequest};
use crate::daemon::scheduler::{PendingChallenges, Scheduler, SchedulerConfig};
use crate::daemon::watcher::{WatcherCommand, WatcherConfig};

use shutdown::{NamedTask, ShutdownOutcome};
pub use startup::{StartError, StartFailureKind};
use startup::{
    classify_cluster_error, classify_config_error, classify_db_error, classify_identity_error,
};

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
    /// Queue of restore jobs for the RestoreCoordinator (restore-i4: submit and
    /// answer at once; the job runs in the coordinator).
    pub restore_tx: mpsc::Sender<RestoreRequest>,
    /// Restore job registry, seeded from staging before the web API starts
    /// (restore-i14); shared with the coordinator.
    pub restore_jobs: crate::daemon::restore::jobs::RestoreJobs,
    /// Restore staging status (job dirs, bytes, publish probe), set before the web
    /// API starts, refreshed by the staging monitor and by the restore coordinator
    /// after each job; read by `status` (restore-i8, i18, i19).
    pub restore_staging: Arc<Mutex<crate::daemon::restore::cleanup::StagingStatus>>,
    /// Cluster state. Always `Some` in a running daemon (`start` refuses
    /// otherwise); `None` only in dispatch tests that do not build one.
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
    /// libp2p swarm handle. Always `Some` in a running daemon (`start` refuses
    /// otherwise); `None` only in tests.
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
    /// Mailbox router — used by dispatch_device_revoke (T-13b-2) to publish directed
    /// revocation entries to storage-relationship peers instead of relay broadcast.
    /// None in tests that do not wire up a MailboxRouter.
    pub mailbox_router: Option<std::sync::Arc<crate::daemon::mailbox::routing::MailboxRouter>>,
    /// dr-i11: background-counted "files without a local source" for `status`.
    pub missing_sources:
        std::sync::Arc<crate::daemon::dispatch::missing_sources::MissingSourceCache>,
}

/// Web API pieces prepared before the swarm starts (see step 9.4 of `start`).
struct WebPrepared {
    config: crate::daemon::web_api::WebApiConfig,
    listener: tokio::net::TcpListener,
    auth: crate::daemon::web_auth::AuthState,
    port: u16,
}

// ─── DaemonHandle ─────────────────────────────────────────────────────────────

/// Owns all subsystem task handles and the cancellation token.
///
/// Call `stop()` to signal shutdown; await `wait_with_deadline()` to join all
/// tasks (see `shutdown` for the whole stop path).
pub struct DaemonHandle {
    cancel: CancellationToken,
    tasks: Vec<NamedTask>,
}

impl DaemonHandle {
    /// Returns a clone of the internal cancellation token. Caller can `cancelled()`
    /// it from main() to wake up on either Ctrl-C or an in-process restart trigger.
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Start the daemon: load identity, open DB, build subsystems, spawn tasks.
    ///
    /// All or nothing (daemon-i1): every way this can fail returns `Err` before
    /// the first subsystem task is spawned and before the web API serves, so
    /// `Ok` means the whole node runs — there is no "started without the
    /// network" mode. Each failure carries its class (see `startup`), which
    /// `main` turns into exit status 78 (needs a person) or 75 (retry later).
    pub async fn start(cfg: DaemonConfig) -> Result<Self, StartError> {
        // Legacy data directory migration hint (one-shot WARN).
        if let Some(home) = dirs::home_dir() {
            let legacy = home.join(".viaticum");
            if legacy.exists() && cfg.data_dir != legacy {
                tracing::warn!(
                    legacy_path = %legacy.display(),
                    current_path = %cfg.data_dir.display(),
                    "legacy data directory detected at ~/.viaticum; migrate to new platform-native path or set --data-dir explicitly"
                );
            }
        }

        // ── 1. Load identity ──────────────────────────────────────────────────
        let keyfile = load_identity(&cfg.data_dir).map_err(|e| {
            let kind = classify_identity_error(&e, &cfg.data_dir);
            let key_path = cfg.data_dir.join("identity.key");
            StartError::new(
                kind,
                match e {
                    IdentityError::NotInitialized if kind == StartFailureKind::NeedsUser => {
                        anyhow::anyhow!(not_initialized_hint(&cfg.data_dir))
                    }
                    IdentityError::NotInitialized => anyhow::anyhow!(
                        "data directory {} is missing or not readable (not mounted or \
                         not unlocked yet?); will retry",
                        cfg.data_dir.display()
                    ),
                    IdentityError::Corrupt(p, msg) => anyhow::anyhow!(corrupt_key_hint(&p, &msg)),
                    other => anyhow::anyhow!(
                        "identity load error from {}: {}",
                        key_path.display(),
                        other
                    ),
                },
            )
        })?;

        // ── 2. Load or create AppConfig ───────────────────────────────────────
        let config_path = cfg.data_dir.join("config.toml");
        let config_error = |e: viaticum_core::config::ConfigError| {
            StartError::new(
                classify_config_error(&e),
                anyhow::Error::new(e).context(format!("config {}", config_path.display())),
            )
        };
        let app_config = if config_path.exists() {
            AppConfig::load(&config_path).map_err(config_error)?
        } else {
            AppConfig::defaults()
        };
        // validate() already called by load(); call it here for the defaults path.
        app_config.validate().map_err(config_error)?;

        // ── 3. Open DB ────────────────────────────────────────────────────────
        // Retry on lock contention: when the daemon self-rexecs (Settings UI
        // restart), the child briefly races the parent for the redb file lock.
        // Total wait ≈ 63.5 s (see `open_db_with_retry`).
        let db_path = cfg.data_dir.join("db.redb");
        let db = open_db_with_retry(&db_path).await.map_err(|e| {
            StartError::new(
                classify_db_error(&e),
                anyhow::Error::new(e)
                    .context(format!("cannot open database {}", db_path.display())),
            )
        })?;

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
            use viaticum_core::constants::INITIAL_TRUST_P;
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
        match viaticum_core::migration::migrate_block_records(&db) {
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

        // ── 3.8. EWMA availability startup catch-up ───────────────────────────
        // Apply any ticks missed while the daemon was offline, then reset
        // last_avail_sample = now so the periodic decay task starts from a clean clock.
        {
            use viaticum_core::constants::{AVAIL_DECAY_TICK_SECS, AVAIL_EWMA_ALPHA};
            let now_secs = Timestamp::now().0;
            // CS-SCH-9: use the same scaled tick as the periodic decay task
            // (scaled_avail_decay_tick_secs). If the catch-up used the raw 24h tick
            // while the running task uses the scaled one, a restart under acceleration
            // would under-count missed ticks and leave avail_ewma stale — the exact
            // desync this fix closes. At time_scale=1 this is AVAIL_DECAY_TICK_SECS.
            let tick_secs = scaled_avail_decay_tick_secs(AVAIL_DECAY_TICK_SECS, cfg.time_scale);
            match db.apply_avail_decay_startup_catchup(AVAIL_EWMA_ALPHA, now_secs, tick_secs) {
                Ok(n) if n > 0 => tracing::info!(peers = n, "avail_ewma startup catch-up applied"),
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(err = %e, "avail_ewma startup catch-up failed (non-fatal)")
                }
            }
        }

        // ── 4. Derive keys ────────────────────────────────────────────────────
        // Epoch 0 is the initial epoch; epoch rotation happens on device revocation.
        let (master_key, device_key, epoch_key_bytes) = derive_keys(&keyfile, 0).map_err(|e| {
            StartError::needs_user(
                anyhow::Error::new(e).context("cannot derive keys from identity.key"),
            )
        })?;
        let identity_pub: IdentityPub = master_identity(&master_key);
        let device_id = DeviceId(keyfile.device_id);

        // ── 5. Initialize or load ClusterState ────────────────────────────────
        // The node cannot join the network without its own certificate in the
        // cluster state, so any failure here refuses the start (daemon-i1).
        let mut cluster = match ClusterState::load(db.clone()) {
            Ok(state) => state,
            Err(ClusterStateError::NotInitialized) => {
                // First-time startup: register this device as the sole cluster member.
                let now = Timestamp::now();
                let cert: DeviceCertificate = issue_device_certificate(&master_key, device_id, now);
                let state =
                    ClusterState::init(db.clone(), identity_pub, cert, now, now).map_err(|e| {
                        StartError::new(
                            classify_cluster_error(&e),
                            anyhow::Error::new(e).context("cannot initialize the cluster state"),
                        )
                    })?;
                tracing::info!("cluster state initialized (first device)");
                state
            }
            Err(e) => {
                return Err(StartError::new(
                    classify_cluster_error(&e),
                    anyhow::Error::new(e)
                        .context("cannot load the cluster state from the database"),
                ));
            }
        };
        // A device missing from the stored state (fresh `init` + `dr`) enrolls
        // itself with the master key; a foreign master or a full cluster refuses.
        let own_membership = startup::ensure_own_device_enrolled(
            &mut cluster,
            &master_key,
            device_id,
            Timestamp::now(),
        )?;
        let cluster_state: Arc<Mutex<ClusterState>> = Arc::new(Mutex::new(cluster));

        // ── 6. Create inter-subsystem channels ────────────────────────────────
        let (dirty_tx, dirty_rx) = mpsc::channel::<DirtyEvent>(256);
        // Queue of restore jobs; a full queue answers `busy` (try_send, A14).
        let (restore_tx, restore_rx) = mpsc::channel::<RestoreRequest>(16);
        let (repair_tx, repair_rx) = mpsc::channel::<RepairTrigger>(64);
        let (backup_event_tx, backup_event_rx) =
            mpsc::channel::<crate::daemon::backup::BackupEvent>(64);
        // ── 7. Build erasure encoder ──────────────────────────────────────────
        let encoder: Arc<dyn ErasureEncoder> = Arc::new(RaptorQEncoder::new());

        // ── 9. Ensure symbols and holdings directories exist ──────────────────
        let dir_error = |path: &std::path::Path, e: std::io::Error| {
            StartError::transient(
                anyhow::Error::new(e).context(format!("cannot prepare {}", path.display())),
            )
        };
        let symbols_dir = cfg.data_dir.join("symbols");
        std::fs::create_dir_all(&symbols_dir).map_err(|e| dir_error(&symbols_dir, e))?;

        // ── 9.0. Wave 2 migration: remove legacy flat {esi}.bin files (pre-Wave 2) ──
        // These are bound-per-holder symbol files written by the old backup pipeline.
        // After Wave 2, all symbols are raw and live in {block_hex}/raw/{esi}.bin.
        // This cleanup is fast (metadata-only scan) and idempotent.
        if let Err(e) =
            crate::daemon::backup::pipeline::cleanup_legacy_bound_symbol_files(&symbols_dir)
        {
            tracing::warn!("startup: cleanup_legacy_bound_symbol_files failed: {e}");
        }

        let holdings_dir = cfg.data_dir.join("holdings");
        std::fs::create_dir_all(&holdings_dir).map_err(|e| dir_error(&holdings_dir, e))?;

        // ── 9.1. Ensure restore staging directory exists ──────────────────────
        let staging_root = cfg.data_dir.join("restore");
        std::fs::create_dir_all(&staging_root).map_err(|e| dir_error(&staging_root, e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&staging_root, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| dir_error(&staging_root, e))?;
        }
        // Staging status for `status`, known before the web API starts (job-dir count,
        // publish probe); bytes come from the staging monitor (9.2).
        let restore_staging = Arc::new(Mutex::new(
            crate::daemon::restore::cleanup::initial_staging_status(&staging_root),
        ));
        // restore-i14: every job dir in staging is a known job before the web API
        // answers `--status <id>`; leftover temp files of jobs the previous run did
        // not finish are removed (nothing runs yet, restore-i24).
        let restore_jobs = crate::daemon::restore::jobs::RestoreJobs::new(staging_root.clone());
        let seeded = restore_jobs.seed_from_staging();
        if seeded > 0 {
            tracing::info!(jobs = seeded, "restore: job dirs registered from staging");
        }

        // ── 9.4. Bind the web API listener (optional) ─────────────────────────
        // Bound BEFORE the swarm listens and before any task is spawned: a web
        // port that is taken refuses the start (daemon-i1, transient) while the
        // libp2p port is still free and nothing else runs. The server itself
        // is started after DaemonState exists (below).
        let web_error = |what: &str, e: anyhow::Error| {
            StartError::transient(e.context(format!("web API {what}")))
        };
        let web_prepared = if app_config.web_api.enabled {
            let static_dir = if app_config.web_api.static_dir.is_empty() {
                None
            } else {
                let p = std::path::PathBuf::from(&app_config.web_api.static_dir);
                Some(if p.is_absolute() {
                    p
                } else {
                    cfg.data_dir.join(p)
                })
            };
            let config = crate::daemon::web_api::WebApiConfig {
                bind: app_config.web_api.bind.clone(),
                static_dir,
            };
            let token = crate::daemon::web_auth::load_or_create_token(&cfg.data_dir)
                .map_err(|e| web_error("token", e.into()))?;
            let auth = crate::daemon::web_auth::AuthState::new(token);
            let listener = tokio::net::TcpListener::bind(&config.bind)
                .await
                .map_err(|e| web_error(&format!("cannot bind {}", config.bind), e.into()))?;
            let port = listener
                .local_addr()
                .map_err(|e| web_error("listener address", e.into()))?
                .port();
            Some(WebPrepared {
                config,
                listener,
                auth,
                port,
            })
        } else {
            None
        };

        // ── 9.5. Start libp2p swarm (before subsystems so they can receive swarm handle) ──
        // swarm_event_rx is consumed by Processor::run below. A node without a
        // swarm neither backs up nor holds anything for others, so a swarm that
        // does not start (the fixed listen port is taken, …) refuses the start
        // (daemon-i1) instead of running the rest half-wired.
        let (swarm_handle_arc, swarm_event_rx) = {
            // The per-device cert and the cluster master pub come from the
            // membership check above. master_pub is the anchor for cert
            // verification (see `verify_cert_for_peer`); it's the FOUNDER's
            // identity, not necessarily this node's own derived master.
            let device_cert = own_membership.device_cert.clone();
            let cluster_master_pub = own_membership.cluster_master_pub;
            // The x25519 key of this phrase (the same one DR announces, F11).
            let x25519_pub = Some(
                x25519_dalek::PublicKey::from(&viaticum_core::cluster::derive_x25519_secret(
                    &keyfile.seed,
                ))
                .to_bytes(),
            );
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
                // Must exceed libp2p request_response::Config.request_timeout (30s in
                // swarm.rs) so our retry layer fires AFTER RR's own timeout reports the
                // failure — otherwise both clocks race and a still-in-flight RR request
                // gets cancelled by the duplicate send, surfacing as
                // "Connection was closed before a response was received".
                cert_timeout_secs: 35,
                kademlia_bootstrap_peers,
                kademlia_disable_ipfs_bootstrap: app_config.network.kademlia_disable_ipfs_bootstrap,
                kad_republish_interval_override: None,
                // Under an accelerated test clock (time_scale>1) the 5-min real-time
                // discovery interval fires only ~once in a minutes-long run, so non-seed
                // nodes never discover holders and place nothing. Scale it with time_scale
                // so discovery keeps pace (the time_scale contract; this override also
                // shortens the initial discovery delay). Production (time_scale=1) = None,
                // unchanged.
                kad_discovery_interval_override: if cfg.time_scale > 1 {
                    Some(crate::daemon::network::swarm::scaled_kad_cadence(
                        crate::daemon::network::swarm::KAD_DISCOVERY_INTERVAL,
                        cfg.time_scale,
                    ))
                } else {
                    None
                },
                enable_relay_server: app_config.network.enable_relay_server,
            };
            let (handle, events) = crate::daemon::network::swarm::SwarmHandle::start(swarm_cfg)
                .await
                .map_err(|e| {
                    StartError::transient(
                        anyhow::Error::new(e).context("libp2p swarm did not start"),
                    )
                })?;
            tracing::info!(
                peer_id = %handle.peer_id,
                "libp2p swarm started (ε.2, wired to processor)"
            );
            (Arc::new(handle), events)
        };

        // ── 10. Build subsystems ──────────────────────────────────────────────
        let source_block_size = viaticum_core::config::source_block_size_bytes(&app_config);

        // ── Step A: Build live_configs Arc ────────────────────────────────────
        // Merge CLI watch_dirs with [[watch]] entries from config.
        let mut initial_watch_configs: Vec<viaticum_core::config::WatchConfig> =
            app_config.watch.clone();
        for dir in &cfg.watch_dirs {
            let dir_str = dir.to_string_lossy().to_string();
            if !initial_watch_configs
                .iter()
                .any(|wc| viaticum_core::config::expand_watch_path(&wc.path) == *dir)
            {
                initial_watch_configs.push(viaticum_core::config::WatchConfig {
                    path: dir_str,
                    importance_multiplier: viaticum_core::config::DEFAULT_IMPORTANCE_MULTIPLIER,
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
                let expanded = viaticum_core::config::expand_watch_path(&wc.path);
                tracing::warn!(
                    target: "config",
                    "watch[{}].importance is deprecated; field now interpreted as \
                     importance_multiplier (range [0, 2], default 1.0). If you intended \
                     this as a multiplier no action needed; otherwise update your config.",
                    expanded.display()
                );
            }
        }

        let live_configs: Arc<RwLock<Vec<viaticum_core::config::WatchConfig>>> =
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

        // WorkPipeline event channel. Created here (earlier than the spawn site
        // below) so BackupConfig can hold a sender to wake worker after flush.
        let (work_event_tx, work_event_rx) =
            tokio::sync::mpsc::channel::<crate::daemon::work_pipeline::WorkEvent>(64);

        let backup = BackupCoordinator::new(
            db.clone(),
            BackupConfig {
                source_block_size,
                symbols_dir: symbols_dir.clone(),
                epoch_key: epoch_key_bytes,
                device_id,
                mock_holders: vec![],
                cluster_state: Some(cluster_state.clone()),
                watch_configs: initial_watch_configs.clone(),
                time_scale: cfg.time_scale.max(1),
                mock_offer_budget_gb: None,
                master_signing_key: Some(master_key.clone()),
                swarm: Some(swarm_handle_arc.clone()),
                // ── Step C: Pass live_watch_configs ──────────────────────────
                live_watch_configs: Some(Arc::clone(&live_configs)),
                peer_backoff: Some(Arc::clone(&peer_backoff)),
                work_event_tx: Some(work_event_tx.clone()),
            },
            encoder.clone(),
        );

        // ── 11. CancellationToken ─────────────────────────────────────────────
        // Created before the restore coordinator: a running restore job stops on it
        // and is recorded `interrupted` within the drain (T10).
        let cancel = CancellationToken::new();

        let restore = RestoreCoordinator::new(
            db.clone(),
            RestoreConfig {
                epoch_key: epoch_key_bytes,
                // Requests over the swarm; redial of holders that did not answer
                // before a retry (restore-i26).
                symbols: Some(Arc::new(crate::daemon::symbol_fetch::SwarmSymbols::new(
                    swarm_handle_arc.clone(),
                    db.clone(),
                ))),
                staging_root: staging_root.clone(),
                data_dir: cfg.data_dir.clone(),
                jobs: restore_jobs.clone(),
                cancel: cancel.clone(),
                staging_status: Arc::clone(&restore_staging),
                pressure: Some(crate::daemon::restore::cleanup::HoldingsPressure {
                    db: db.clone(),
                    data_dir: cfg.data_dir.clone(),
                    soft_quota_bytes: viaticum_core::config::soft_quota_bytes(&app_config),
                    disk_reserve_bytes: viaticum_core::config::disk_reserve_bytes(&app_config),
                }),
                time_scale: cfg.time_scale.max(1),
            },
            encoder.clone(),
        );

        // RepairAgent is now only used for periodic reliability_scan (Wave 11b).
        // The repair instance is created in the reliability_scan task below.
        // The old repair.run() task is replaced by the WorkPipeline worker.

        // ── Step D: Create WatchAdmin ──────────────────────────────────────────
        let watch_admin = Arc::new(crate::daemon::watch_admin::WatchAdmin::new(
            config_path.clone(),
            Arc::clone(&live_configs),
            watcher_cmd_tx.clone(),
            db.clone(),
        ));

        // ── Step D.1: Create ConfigAdmin and RestartGate ──────────────────────
        let config_admin = Arc::new(crate::daemon::config_admin::ConfigAdmin::new(
            config_path.clone(),
        ));
        let restart_gate = Arc::new(crate::daemon::restart::RestartGate::new());

        // ── 11.5. Build MailboxRouter (needed by DaemonState for dispatch_device_revoke) ──
        // Built here (before DaemonState) because DaemonState carries mailbox_router for
        // dispatch_device_revoke (T-13b-2). The same Arc is reused below in Phase 6.5
        // (scheduler + mailbox poll wiring) — no double-construction. The swarm is
        // always up here (start refuses otherwise), so there is no offline sender.
        let early_mailbox_router: std::sync::Arc<crate::daemon::mailbox::routing::MailboxRouter> =
            std::sync::Arc::new(crate::daemon::mailbox::routing::MailboxRouter::new(
                swarm_handle_arc.clone(),
                db.clone(),
            ));

        // ── 12. Build DaemonState (shared with CliServer) ─────────────────────
        // Clone restore_tx so CliServer can forward requests to RestoreCoordinator.
        // The original is held by the cancel task (dropped on shutdown to close channel).
        let state = Arc::new(DaemonState {
            db: db.clone(),
            identity_pub,
            device_id,
            restore_tx: restore_tx.clone(),
            restore_jobs: restore_jobs.clone(),
            restore_staging: Arc::clone(&restore_staging),
            cluster_state: Some(cluster_state.clone()),
            master_key: master_key.clone(),
            seed: keyfile.seed.clone(),
            data_dir: cfg.data_dir.clone(),
            soft_quota_bytes: viaticum_core::config::soft_quota_bytes(&app_config),
            disk_reserve_bytes: viaticum_core::config::disk_reserve_bytes(&app_config),
            hard_quota_bytes: viaticum_core::config::hard_quota_bytes(&app_config),
            time_scale: cfg.time_scale.max(1),
            swarm_handle: Some(swarm_handle_arc.clone()),
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
            // T-13b-2: router shared with dispatch_device_revoke for directed revocation publish.
            mailbox_router: Some(std::sync::Arc::clone(&early_mailbox_router)),
            missing_sources: Default::default(),
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

        // ── 14.5. WorkPipeline channel created earlier (above BackupCoordinator). ──

        // ── Web API server (optional) ─────────────────────────────────────────
        // The listener was bound before the swarm (9.4). The api-port file is
        // written only here, once the swarm is up and nothing that depends on
        // outside state (ports, lock, keys) can still refuse the start, so the
        // CLI does not find the port of a start that was refused.
        let web_api_task = match (state_for_web_api, web_prepared) {
            (Some(web_state), Some(prepared)) => {
                crate::daemon::web_auth::write_port_file(&cfg.data_dir, prepared.port)
                    .map_err(|e| web_error("port file", e.into()))?;
                let web_handle = crate::daemon::web_api::start_with_listener(
                    prepared.config,
                    prepared.listener,
                    cancel.clone(),
                    web_state,
                    prepared.auth,
                )
                .await
                .map_err(|e| web_error("server", e))?;
                Some(web_handle)
            }
            _ => None,
        };

        // ── 15. Spawn subsystem tasks ─────────────────────────────────────────
        let mut tasks: Vec<NamedTask> = Vec::new();
        if let Some(web_handle) = web_api_task {
            tasks.push(("web_api", web_handle));
        }

        tasks.push((
            "backup",
            tokio::spawn(backup.run(dirty_rx, backup_event_rx)),
        ));
        tasks.push(("restore", tokio::spawn(restore.run(restore_rx))));

        // Wave 11b: RepairAgent::run() replaced by WorkPipeline worker + periodic reliability_scan.
        // RepairTrigger channel (repair_rx) is forwarded to work_event_tx to wake the worker.
        // PL-8c: RepairTrigger is a unit `Wake` — every trigger means "some placement
        // became Lost; rescan the DB and re-encode". We forward each one to a single
        // generic worker wake; there is no per-placement addressing to preserve.
        {
            let work_event_tx_relay = work_event_tx.clone();
            let cancel_relay = cancel.clone();
            tasks.push(("repair_relay", tokio::spawn(async move {
                let mut repair_rx = repair_rx;
                loop {
                    tokio::select! {
                        _ = cancel_relay.cancelled() => break,
                        maybe_trigger = repair_rx.recv() => {
                            match maybe_trigger {
                                None => break,
                                Some(crate::daemon::repair::RepairTrigger::Wake) => {
                                    // A placement is now Lost — worker will pick it up.
                                    let _ = work_event_tx_relay.try_send(
                                        crate::daemon::work_pipeline::WorkEvent::DirtyFileEnqueued,
                                    );
                                }
                            }
                        }
                    }
                }
                Ok(())
            })));
        }

        // Periodic reliability scan (keeps cached fields consistent as a safety net).
        {
            let repair_for_scan = crate::daemon::repair::RepairAgent::new(db.clone());
            let cancel_scan = cancel.clone();
            tasks.push(("reliability_scan", tokio::spawn(async move {
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
            })));
        }

        // ── 9.2. Restore staging report (restore-i8: report, never delete) ──
        {
            let monitor = crate::daemon::restore::cleanup::run_staging_monitor(
                staging_root.clone(),
                (app_config.restore.staging_warn_gb * 1_073_741_824.0) as u64,
                crate::daemon::restore::cleanup::STAGING_CHECK_INTERVAL,
                Arc::clone(&restore_staging),
                Some(crate::daemon::restore::cleanup::HoldingsPressure {
                    db: db.clone(),
                    data_dir: cfg.data_dir.clone(),
                    soft_quota_bytes: viaticum_core::config::soft_quota_bytes(&app_config),
                    disk_reserve_bytes: viaticum_core::config::disk_reserve_bytes(&app_config),
                }),
                cancel.clone(),
            );
            tasks.push((
                "staging_monitor",
                tokio::spawn(async move {
                    monitor.await;
                    Ok(())
                }),
            ));
        }
        // ── 9.25. EWMA availability decay task (daily) ────────────────────────
        {
            use viaticum_core::constants::{AVAIL_DECAY_TICK_SECS, AVAIL_EWMA_ALPHA};
            let avail_db = db.clone();
            let avail_cancel = cancel.clone();
            // CS-SCH-9: scale the tick by time_scale. run_avail_decay_task uses this
            // single value BOTH as the timer cadence AND as the `tick_secs` threshold
            // fed to apply_avail_decay_batch, so one scaled value keeps cadence and
            // decay math in sync. Without this the task fired every real 24h while the
            // batch demanded 24h of real elapsed → avail_ewma never decayed under
            // acceleration. At time_scale=1 this is exactly AVAIL_DECAY_TICK_SECS.
            let avail_tick_secs = scaled_avail_decay_tick_secs(AVAIL_DECAY_TICK_SECS, time_scale);
            tasks.push((
                "avail_decay",
                tokio::spawn(async move {
                    run_avail_decay_task(avail_db, avail_cancel, AVAIL_EWMA_ALPHA, avail_tick_secs)
                        .await;
                    Ok(())
                }),
            ));
        }

        // ── 9.3. Peer auto-dial (network-i2): dial known peers at start and then
        //         periodically, so a restart / DR rejoins the network without a
        //         manual `connect`. See redial/mod.rs.
        {
            let swarm_for_redial = swarm_handle_arc.clone();
            // 5 min real time, scaled (30 s on time_scale=10); floor 30 s so we
            // don't re-dial-storm a single offline peer.
            let redial_interval = std::time::Duration::from_secs((300 / time_scale).max(30));
            let db_for_redial = db.clone();
            let cancel_for_redial = cancel.clone();
            tasks.push((
                "redial",
                tokio::spawn(async move {
                    redial::run_redial_loop(
                        db_for_redial,
                        swarm_for_redial,
                        redial_interval,
                        cancel_for_redial,
                    )
                    .await;
                    Ok(())
                }),
            ));
        }

        // ── Step E.5: Background rollup refresh task (every 5 min) ────────────
        if let Some(admin) = state.watch_admin.as_ref() {
            let admin_for_refresh = Arc::clone(admin);
            let cancel_refresh = cancel.clone();
            tasks.push((
                "rollup_refresh",
                tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(300));
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
                }),
            ));
        }

        // ── Phase 7.2: spawn Processor ────────────────────────────────────────
        // PendingChallenges map: owned by the Scheduler (it both writes challenges
        // and resolves mailbox PoS responses against them). Wired below.
        let pending_challenges: PendingChallenges =
            std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

        // Raw quota values from config. 0 = "not configured" (use disk-based limit).
        // Processor and holder_cleanup compute effective_quota from disk_free at runtime.
        let soft_quota_bytes = viaticum_core::config::soft_quota_bytes(&app_config);
        let hard_quota_bytes = viaticum_core::config::hard_quota_bytes(&app_config);
        let disk_reserve_bytes = viaticum_core::config::disk_reserve_bytes(&app_config);
        // Processor, worker and cluster sync always start: the swarm and the
        // cluster state are guaranteed by the start checks above (no early
        // return that leaves the node half-started, daemon-i1).
        {
            let cluster_sync = Arc::new(ClusterSyncManager::new(
                db.clone(),
                ClusterSyncConfig {
                    our_device_id: device_id,
                    batch_size: 1000,
                },
                cluster_state.clone(),
            ));
            // Clone for periodic sync task before cluster_sync is moved into Processor.
            let cluster_sync_for_sync_loop = cluster_sync.clone();

            let mut processor = Processor::new(
                db.clone(),
                identity_pub,
                cluster_sync,
                holdings_dir.clone(),
                swarm_handle_arc.clone(),
                soft_quota_bytes,
                hard_quota_bytes,
                cfg.data_dir.clone(),
                disk_reserve_bytes,
                backup_event_tx,
                Some(cluster_state.clone()),
                accepted_offers.clone(),
                master_key.clone(),
            );
            // Wire WorkPipeline event channel to Processor so on_peer_authenticated
            // sends WorkEvent::PeerAuthenticated to wake the worker.
            processor.set_work_event_tx(work_event_tx.clone());
            // В-0b: the [four_r] dials drive the 4R offer shadow (logs only, off the reply path).
            processor.set_four_r(viaticum_core::four_r_holder::FourRParams::from_cfg(
                &app_config.four_r,
            ));

            // ── Spawn WorkPipeline worker ──────────────────────────────────────
            {
                let work_pipeline_config = crate::daemon::work_pipeline::WorkPipelineConfig {
                    // Cooldown: 30s in production. Scale with time_scale for demos/tests.
                    cooldown: std::time::Duration::from_secs((30 / time_scale).max(1)),
                    // Tick interval: 60s in production. Scale with time_scale.
                    tick_interval: std::time::Duration::from_secs((60 / time_scale).max(1)),
                    completion_bonus_coef: app_config.reliability.completion_bonus_coefficient,
                    device_id,
                    own_master_pub_key: identity_pub,
                    epoch_key: epoch_key_bytes,
                    data_dir: cfg.data_dir.clone(),
                    min_pool_size: 2,
                };
                let worker = crate::daemon::work_pipeline::WorkPipeline::new(
                    db.clone(),
                    work_pipeline_config,
                    encoder.clone(),
                    Some(swarm_handle_arc.clone()),
                    Some(master_key.clone()),
                    Some(Arc::clone(&peer_backoff)),
                    Some(cluster_state.clone()),
                    work_event_rx,
                );
                tasks.push((
                    "work_pipeline",
                    tokio::spawn(async move { worker.run().await }),
                ));
            }

            let cancel_processor = cancel.clone();
            tasks.push((
                "processor",
                tokio::spawn(async move { processor.run(swarm_event_rx, cancel_processor).await }),
            ));

            // ── Cluster periodic sync ──────────────────────────────────────────
            {
                let cs_sync = cluster_sync_for_sync_loop;
                let cs_state = cluster_state.clone();
                let cs_swarm = swarm_handle_arc.clone();
                let cs_interval = (300 / time_scale).max(10);
                let cancel_cs = cancel.clone();
                tasks.push((
                    "cluster_sync",
                    tokio::spawn(async move {
                        if let Err(e) = crate::daemon::cluster_sync::run_periodic_sync(
                            cs_sync,
                            cs_state,
                            cs_swarm,
                            device_id,
                            cs_interval,
                            cancel_cs,
                        )
                        .await
                        {
                            tracing::error!(error = %e, "cluster periodic sync failed");
                        }
                        Ok(())
                    }),
                ));
            }
        }

        // ── Step F: Spawn watcher — ALWAYS (even with empty dir list) ────────
        // Merge CLI --watch-dir with [[watch]] paths from config (same as initial_watch_configs).
        let mut all_watch_dirs = cfg.watch_dirs.clone();
        for wc in &app_config.watch {
            let p = viaticum_core::config::expand_watch_path(&wc.path);
            if !all_watch_dirs.contains(&p) {
                all_watch_dirs.push(p);
            }
        }
        {
            let watcher_config = WatcherConfig {
                watch_dirs: all_watch_dirs,
                device_id,
                // Coalesce rapid edits over the cold-backup debounce window
                // (DEBOUNCE_SECS, 30 min), scaled by time_scale for experiments/tests.
                debounce_ms: crate::daemon::watcher::debounce_ms_for_time_scale(time_scale),
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
            tasks.push((
                "watcher",
                tokio::spawn(async move {
                    crate::daemon::watcher::start_watcher(
                        watcher_config,
                        dirty_tx_watcher,
                        watcher_cmd_rx,
                        cancel_watcher,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("watcher error: {e}"))
                }),
            ));
        }
        // ── Phase 6.5: Scheduler + Mailbox poll (T-6) ────────────────────────
        // Pass the same PendingChallenges Arc created for Processor above.
        // Scheduler writes to it; Processor reads it when verifying PosResponse.

        // T-6: MailboxRouter already built in step 11.5 (early_mailbox_router).
        // Reuse the same Arc here for scheduler + mailbox poll wiring.
        // pos_response_tx: poll loop → scheduler (bounded 256, try_send + WARN on full).
        let (pos_response_tx, pos_response_rx) =
            mpsc::channel::<viaticum_core::messages::PosHashResponseMsg>(256);

        // Reuse early_mailbox_router built above (step 11.5). Same instance used in
        // DaemonState.mailbox_router (for dispatch_device_revoke / T-13b-2).
        let mailbox_router = std::sync::Arc::clone(&early_mailbox_router);

        let scheduler = Scheduler::new(
            db.clone(),
            SchedulerConfig {
                pos_interval_secs: 3600,
                timeout_check_secs: 3600,
                time_scale,
                event_log_retain_rows: 100_000,
                pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
            },
            repair_tx.clone(),
            pending_challenges,
            std::sync::Arc::clone(&mailbox_router),
            identity_pub,
            master_key.clone(),
            accepted_offers,
            encoder.clone(),
            epoch_key_bytes,
            cfg.data_dir.clone(),
        );
        let cancel_scheduler = cancel.clone();
        tasks.push((
            "scheduler",
            tokio::spawn(async move { scheduler.run(pos_response_rx, cancel_scheduler).await }),
        ));

        // ── T-6/T-7/T-13b-1: Mailbox poll task ─────────────────────────────
        // Polls this node's mailbox every MAILBOX_POLL_INTERVAL_SECS.
        // Started alongside other periodic tasks (T-9 will add explicit Kademlia stabilize wait).
        //
        // T-6:     PosResponder handles PosChallenge entries from mailbox.
        // T-7:     ProcessorDropHandler handles DropNotice batch entries (db only).
        // CROWN-1 C3a: pointers live in the rendezvous box, which only DR reads (РС3.1).
        // T-13b-1: ProcessorDeleteHandler handles DeleteRequest entries (Delete/CancelDelete).
        // T-13b-2: ProcessorRevocationHandler handles Revocation entries (device revocation).
        // No Arc<Processor> wrap needed: all handlers are standalone structs built from clones.
        {
            use crate::daemon::mailbox::poll::run_mailbox_poll;
            use crate::daemon::processor::{
                PosResponder, ProcessorDeleteHandler, ProcessorDropHandler, ProcessorPosHandler,
                ProcessorRevocationHandler,
            };

            let pos_handler = ProcessorPosHandler::new(PosResponder::new(
                db.clone(),
                holdings_dir.clone(),
                master_key.clone(),
            ));

            // T-13a: pass repair_tx so ProcessorDropHandler can wake the repair worker
            // for immediate-drop DropNotice entries (deadline ≈ now).
            let drop_handler = ProcessorDropHandler::new(db.clone(), repair_tx.clone())
                .with_time_scale(time_scale);

            // T-13b-1: ProcessorDeleteHandler handles Delete/CancelDelete via mailbox.
            // Only requires db — same as SymbolDropHandler.
            let delete_handler = ProcessorDeleteHandler::new(db.clone());

            // T-13b-2: ProcessorRevocationHandler handles Revocation entries via mailbox.
            // Only requires db — mirrors the relay-board revocation_broadcast handler.
            let revocation_handler = ProcessorRevocationHandler::new(db.clone());

            let poll_router = std::sync::Arc::clone(&mailbox_router);
            let poll_pos_tx = pos_response_tx.clone();
            let poll_identity = identity_pub;
            let poll_cancel = cancel.clone();
            tasks.push((
                "mailbox_poll",
                tokio::spawn(async move {
                    run_mailbox_poll(
                        poll_router,
                        poll_pos_tx,
                        std::sync::Arc::new(pos_handler),
                        std::sync::Arc::new(drop_handler),
                        std::sync::Arc::new(delete_handler),
                        std::sync::Arc::new(revocation_handler),
                        poll_identity,
                        time_scale,
                        poll_cancel,
                    )
                    .await;
                    Ok(())
                }),
            ));
        }

        // ── T-11: Mailbox TTL sweep + membership-based self-cleanup ──────────
        // Two housekeeping tasks running at MAILBOX_SWEEP_INTERVAL_SECS (6 hours):
        //
        // (a) run_mailbox_ttl_sweep — remove TTL-expired entries of ALL classes.
        //     SelfPointers leave only by this sweep or by the monotone per-address
        //     pointer budget at store time (CROWN-1 Q5/N5); without the sweep
        //     they would accumulate until that budget.
        //
        // (b) run_mailbox_self_cleanup — for each target stored in our mailbox,
        //     check membership (should_store). If we are no longer in the candidate set,
        //     delete all non-high-trust entries for that target. SelfPointers are exempt
        //     from membership eviction (AC-6 / Bug-D).
        //
        // Both tasks are unconditional (no swarm required for TTL sweep; self-cleanup
        // builds routing view from DB on each tick).
        {
            use crate::daemon::mailbox::cleanup::{
                run_mailbox_self_cleanup, run_mailbox_ttl_sweep,
            };

            // Own PeerId for the membership view (the swarm is always up here).
            let my_peer_id_for_cleanup = swarm_handle_arc.peer_id;

            // (a) TTL sweep. Cadence scaled by time_scale (same as scheduler / poll).
            let sweep_db = db.clone();
            let sweep_cancel = cancel.clone();
            tasks.push((
                "mailbox_ttl_sweep",
                tokio::spawn(async move {
                    run_mailbox_ttl_sweep(sweep_db, time_scale, sweep_cancel).await;
                    Ok(())
                }),
            ));

            // (b) Membership-based self-cleanup. Cadence scaled by time_scale.
            let cleanup_db = db.clone();
            let cleanup_cancel = cancel.clone();
            tasks.push((
                "mailbox_self_cleanup",
                tokio::spawn(async move {
                    run_mailbox_self_cleanup(
                        cleanup_db,
                        my_peer_id_for_cleanup,
                        time_scale,
                        cleanup_cancel,
                    )
                    .await;
                    Ok(())
                }),
            ));
        }

        // ── Metrics pusher (optional) ──────────────────────────────────────
        if let Some(state_m) = state_for_metrics {
            let metrics_cfg = app_config.metrics.clone();
            let cancel_m = cancel.clone();
            tasks.push((
                "metrics",
                tokio::spawn(async move {
                    crate::daemon::metrics::run(metrics_cfg, state_m, cancel_m).await
                }),
            ));
        }

        // ── System state periodic push (T-8) ────────────────────────────────
        // T-8: pointer is published via mailbox instead of push-to-all.
        // The pointer is sealed with keys derived from the seed inside the task
        // (RendezvousKeys); its place state lives in META (CROWN-1 C3a).
        // Uses SwarmHandle (ε.2+); the swarm is always up here.
        {
            let ss_db = db.clone();
            let ss_swarm = swarm_handle_arc.clone();
            let ss_seed = keyfile.seed.clone();
            let ss_master_key = master_key.clone();
            let ss_data_dir = cfg.data_dir.clone();
            let ss_interval = (6 * 3600 / time_scale).max(60);
            let ss_mailbox_router = std::sync::Arc::clone(&mailbox_router);
            // Spec B2 (dr-i19): pointers name the device that published them.
            let ss_publisher = device_id;
            let cancel_ss = cancel.clone();
            tasks.push((
                "system_state_push",
                tokio::spawn(async move {
                    if let Err(e) = crate::daemon::system_state::run_periodic_push(
                        ss_db,
                        ss_swarm,
                        ss_seed,
                        ss_master_key,
                        ss_data_dir,
                        ss_interval,
                        time_scale,
                        cancel_ss,
                        ss_mailbox_router,
                        ss_publisher,
                    )
                    .await
                    {
                        tracing::error!(error = %e, "system_state periodic push failed");
                    }
                    Ok(())
                }),
            ));
        }

        // ── Holder cleanup task ────────────────────────────────────────────
        {
            let cleanup_db = db.clone();
            let cleanup_holdings = holdings_dir.clone();
            let cleanup_router = std::sync::Arc::clone(&mailbox_router);
            let cleanup_cancel = cancel.clone();
            let cleanup_data_dir = cfg.data_dir.clone();
            let cleanup_master_key = master_key.clone();
            let cleanup_interval = (3600 / time_scale).max(1);
            let pressure_interval = (3600 / time_scale).max(60);
            // В-0: the [four_r] dials drive the 4R shadow of the pressure tick (logs only).
            let cleanup_four_r =
                viaticum_core::four_r_holder::FourRParams::from_cfg(&app_config.four_r);
            tasks.push((
                "holder_cleanup",
                tokio::spawn(async move {
                    crate::daemon::holder_cleanup::run(
                        cleanup_db,
                        cleanup_holdings,
                        cleanup_router,
                        soft_quota_bytes,
                        hard_quota_bytes,
                        cleanup_data_dir,
                        disk_reserve_bytes,
                        cleanup_interval,
                        pressure_interval,
                        time_scale,
                        cleanup_master_key,
                        cleanup_four_r,
                        cleanup_cancel,
                    )
                    .await
                }),
            ));
        }

        // ── Holdings integrity scan task ───────────────────────────────────
        // Publishes immediate-drop DropNotice via mailbox when a held symbol
        // directory has vanished from disk (T-13a).
        {
            let integrity_db = db.clone();
            let integrity_holdings = holdings_dir.clone();
            let integrity_router = std::sync::Arc::clone(&mailbox_router);
            let integrity_cancel = cancel.clone();
            let integrity_master_key = master_key.clone();
            let integrity_interval =
                viaticum_core::constants::DEFAULT_HOLDINGS_INTEGRITY_INTERVAL_SECS;
            tasks.push((
                "holdings_integrity",
                tokio::spawn(async move {
                    crate::daemon::holdings_integrity::run(
                        integrity_db,
                        integrity_holdings,
                        integrity_router,
                        identity_pub,
                        integrity_interval,
                        time_scale,
                        integrity_master_key,
                        integrity_cancel,
                    )
                    .await
                }),
            ));
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

    /// Wait for all subsystem tasks to finish, at most `deadline`.
    ///
    /// Call after `stop()`. Tasks still running at the deadline are reported
    /// as abandoned (not aborted here: they are cancelled when the runtime is
    /// dropped after `main` returns). See `shutdown::ShutdownOutcome::report`.
    pub async fn wait_with_deadline(self, deadline: std::time::Duration) -> ShutdownOutcome {
        shutdown::wait_tasks_with_deadline(self.tasks, deadline).await
    }
}

// ── EWMA availability decay task ─────────────────────────────────────────────

/// Scale the avail-decay tick interval by `time_scale` (CS-SCH-9).
///
/// `run_avail_decay_task` uses the returned value BOTH as its timer cadence and
/// as the `tick_secs` threshold it hands to `apply_avail_decay_batch`, so scaling
/// one value keeps the firing cadence and the decay math in lockstep. The startup
/// catch-up uses the same helper for the same reason. Floors at 1s so an extreme
/// `time_scale` cannot collapse the tick to 0 (which would decay every peer on
/// every call). At `time_scale = 1` this is identity: `base_tick_secs`.
fn scaled_avail_decay_tick_secs(base_tick_secs: u64, time_scale: u64) -> u64 {
    (base_tick_secs / time_scale.max(1)).max(1)
}

/// Run alongside other periodic tasks. Applies EWMA decay for all peers that
/// haven't been contacted in > tick_secs. Fires once per tick_secs interval.
async fn run_avail_decay_task(
    db: viaticum_core::db::Db,
    cancel: tokio_util::sync::CancellationToken,
    alpha: f64,
    tick_secs: u64,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(tick_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let now_secs = Timestamp::now().0;
                if let Err(e) = db.apply_avail_decay_batch(alpha, now_secs, tick_secs) {
                    tracing::warn!("avail_decay_batch failed: {e}");
                }
            }
            _ = cancel.cancelled() => break,
        }
    }
}

// ── DB open retry ────────────────────────────────────────────────────────────

/// Wrap `Db::open` in an exponential backoff (≤ ~60s total) so a freshly
/// rexec'd child can wait for the parent to release the redb file lock.
///
/// Backoffs sum to ≈ 63.5 s. The parent drains its tasks through
/// `wait_with_deadline` (up to `SHUTDOWN_DRAIN`) and only then exits and
/// releases the lock, so the envelope must outlast that drain plus a slow
/// exit under load; an 11 s envelope was observed to lose races under
/// active backup load.
async fn open_db_with_retry(path: &std::path::Path) -> Result<Db, DbError> {
    let backoffs_ms = [0u64, 500, 1000, 2000, 4000, 8000, 16000, 16000, 16000];
    let mut last_err: Option<DbError> = None;
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
                let is_lock =
                    msg.contains("Database already open") || msg.contains("Cannot acquire lock");
                if !is_lock {
                    return Err(e);
                }
                tracing::warn!(attempt = i + 1, error = %msg, "db locked, retrying");
                last_err = Some(e);
            }
        }
    }
    // The loop runs at least once and only falls through after a lock error.
    Err(last_err.unwrap_or(DbError::Database(redb::DatabaseError::DatabaseAlreadyOpen)))
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
