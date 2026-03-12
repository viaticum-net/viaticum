use std::collections::HashMap;
use std::path::{Path, PathBuf};

use syncback_core::budget::BudgetPlanner;
use syncback_core::constants::SECS_PER_WEEK;
use syncback_core::db::Db;
use syncback_core::escrow::EscrowChecker;
use syncback_core::messages::{
    frame_message, from_cbor, to_cbor, CancelDeleteMsg, DeleteMsg, DenyReason, DirectBody,
    DirectMessage, MsgId, PeerAnnounceMsg, PosChallengeMsg, PosResponseMsg, RejectReason,
    RestoreDeniedMsg, RestoreRequestMsg, ShardAcceptMsg, ShardDropNoticeMsg, ShardDroppedMsg,
    ShardOfferMsg, ShardRejectMsg, ShardStoredMsg, StorageWarningMsg, SystemStateAckMsg,
    SystemStateBackupMsg, SystemStateRequestMsg, SystemStateResponseMsg,
};
use syncback_core::placement::PlacementEngine;
use syncback_core::trust::{TransferEvent, TrustEngine};
use syncback_core::types::{FileId, FileRecord, IdentityPub, ScheduleRecord, ShardStatus, Timestamp};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::daemon::packer::Packer;
use crate::daemon::repair::RepairEngine;
use crate::daemon::shard_manager::{PosResponse, PosResult, ShardManager, ShardManagerError};
use crate::daemon::storage::{OfferDecision, Storage, StorageError};
use crate::daemon::{
    CliCmd, Config, DirtyEvent, DirtyKind, IncludeEntry, NetCommand, NetEvent, ProcessorMsg,
    ScheduledCmd, StatusReply,
};

#[cfg(test)]
mod tests;

// ============================================================
// Internal state for pending PoS challenges
// ============================================================

#[derive(Clone)]
struct PendingPosChallenge {
    shard_id: syncback_core::types::ShardId,
    block_index: u32,
    nonce: [u8; 32],
    sent_at: Timestamp,
}

// ============================================================
// Processor struct
// ============================================================

/// State for a restore operation in progress.
/// Accumulates k shard blobs and completes when all k shards arrive.
struct PendingRestore {
    /// Destination file path.
    dest: std::path::PathBuf,
    /// Original file path (used to find the file in the pack unit's index).
    original_path: String,
    /// Unit ID being restored.
    unit_id: syncback_core::types::UnitId,
    /// Unit type (Pack or Chunk).
    unit_type: syncback_core::types::UnitType,
    /// RS parameters.
    k: usize,
    n: usize,
    /// Accumulated shard blobs indexed by shard_index.
    /// None = not yet received.
    shard_blobs: Vec<Option<Vec<u8>>>,
    /// Number of blobs received so far.
    received: usize,
    /// CLI reply channel. Consumed on completion.
    reply: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
}

struct Processor {
    db: Db,
    config: Config,
    cancel: CancellationToken,

    processor_rx: mpsc::Receiver<ProcessorMsg>,
    dirty_rx: mpsc::Receiver<DirtyEvent>,
    net_event_rx: mpsc::Receiver<NetEvent>,
    net_cmd_tx: mpsc::Sender<NetCommand>,

    /// Stored as raw bytes so we can reconstruct SigningKey per-operation
    /// (ed25519_dalek::SigningKey does not impl Clone).
    identity_key_bytes: [u8; 32],
    identity_pub: IdentityPub,

    trust: TrustEngine,
    #[allow(dead_code)]
    escrow: EscrowChecker,
    #[allow(dead_code)]
    placement: PlacementEngine,
    budget: BudgetPlanner,
    shard_manager: ShardManager,
    storage: Storage,
    repair_engine: RepairEngine,

    /// JSON-encoded EndpointAddr of our iroh endpoint (for Status responses).
    own_node_id: String,

    started_at: std::time::Instant,
    pending_pos_challenges: HashMap<[u8; 32], PendingPosChallenge>,
    /// Active restore operations, keyed by restore ID (u64 counter).
    pending_restores: HashMap<u64, PendingRestore>,
    /// Maps each awaited ShardId to (restore_id, shard_index).
    pending_shard_to_restore: HashMap<syncback_core::types::ShardId, (u64, usize)>,
    /// Counter for restore IDs.
    next_restore_id: u64,

    // ---- DR boot state machine ----
    /// Set during DR restore; cleared when PeerConnected fires and request is sent.
    pending_dr_peer_addr: Option<String>,
    /// CLI reply sender for DR restore; cleared when SystemStateResponse arrives or fails.
    pending_dr_cli_reply: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
    /// Set when DR request is sent; cleared when SystemStateResponse arrives.
    /// (Unused in current single-step flow but kept for future retry logic.)
    #[allow(dead_code)]
    pending_dr_reply: Option<tokio::sync::oneshot::Sender<Result<SystemStateResponseMsg, String>>>,
}

// ============================================================
// Public entry point
// ============================================================

/// Run the processor task until `cancel` is signalled or a channel closes.
/// Owns all logic modules. Sole DB writer.
pub async fn run(
    db: Db,
    cancel: CancellationToken,
    processor_rx: mpsc::Receiver<ProcessorMsg>,
    dirty_rx: mpsc::Receiver<DirtyEvent>,
    net_event_rx: mpsc::Receiver<NetEvent>,
    net_cmd_tx: mpsc::Sender<NetCommand>,
    config: Config,
    identity_key: ed25519_dalek::SigningKey,
    identity_pub: IdentityPub,
    own_node_id: String,
) {
    let trust = TrustEngine::new(db.clone());
    let escrow = EscrowChecker::new(db.clone());
    let placement = PlacementEngine::new(db.clone(), TrustEngine::new(db.clone()));
    let budget = BudgetPlanner::new(db.clone(), TrustEngine::new(db.clone()));

    let shards_dir = config.syncback_dir.join("shards");
    let storage = Storage::new(
        db.clone(),
        shards_dir,
        config.storage.quota_gb as f64,
        TrustEngine::new(db.clone()),
    )
    .expect("storage init: shards dir creation failed");

    // Clone identity key for ShardManager (ed25519_dalek::SigningKey may not impl Clone).
    let sm_key = ed25519_dalek::SigningKey::from_bytes(&identity_key.to_bytes());

    let shard_manager = ShardManager::new(
        db.clone(),
        PlacementEngine::new(db.clone(), TrustEngine::new(db.clone())),
        BudgetPlanner::new(db.clone(), TrustEngine::new(db.clone())),
        sm_key,
        identity_pub,
        net_cmd_tx.clone(),
    );

    let repair_engine = RepairEngine::new(db.clone());

    let identity_key_bytes = identity_key.to_bytes();

    let mut proc = Processor {
        db,
        config,
        cancel,
        processor_rx,
        dirty_rx,
        net_event_rx,
        net_cmd_tx,
        identity_key_bytes,
        identity_pub,
        trust,
        escrow,
        placement,
        budget,
        shard_manager,
        storage,
        repair_engine,
        own_node_id,
        started_at: std::time::Instant::now(),
        pending_pos_challenges: HashMap::new(),
        pending_restores: HashMap::new(),
        pending_shard_to_restore: HashMap::new(),
        next_restore_id: 0,
        pending_dr_peer_addr: None,
        pending_dr_cli_reply: None,
        pending_dr_reply: None,
    };

    tracing::info!("processor: started");
    proc.run_loop().await;
    tracing::info!("processor: stopped");
}

// ============================================================
// Main event loop
// ============================================================

impl Processor {
    async fn run_loop(&mut self) {
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    tracing::debug!("processor: cancelled");
                    break;
                }

                msg = self.processor_rx.recv() => {
                    match msg {
                        Some(ProcessorMsg::Scheduled(cmd)) => self.handle_scheduled(cmd).await,
                        Some(ProcessorMsg::Cli(cmd)) => self.handle_cli(cmd).await,
                        None => {
                            tracing::debug!("processor: processor_rx closed");
                            break;
                        }
                    }
                }

                event = self.dirty_rx.recv() => {
                    match event {
                        Some(ev) => self.handle_dirty(ev).await,
                        None => {
                            tracing::debug!("processor: dirty_rx closed");
                            break;
                        }
                    }
                }

                event = self.net_event_rx.recv() => {
                    match event {
                        Some(ev) => self.handle_net_event(ev).await,
                        None => {
                            tracing::debug!("processor: net_event_rx closed");
                            break;
                        }
                    }
                }
            }
        }
    }
}

// ============================================================
// Scheduled command handlers
// ============================================================

impl Processor {
    async fn handle_scheduled(&mut self, cmd: ScheduledCmd) {
        match cmd {
            ScheduledCmd::WeeklySync => {
                self.run_weekly_sync().await;
                // After weekly sync, trigger system state backup inline.
                self.handle_system_state_backup().await;
            }
            ScheduledCmd::PosRound => self.run_pos_round().await,
            ScheduledCmd::Vacuum => self.run_vacuum().await,
            ScheduledCmd::RepairCheck => self.run_repair_check().await,
            // Safety-net: also fired weekly by scheduler if WeeklySync was skipped.
            ScheduledCmd::SystemStateBackup => self.handle_system_state_backup().await,
        }
    }

    async fn run_weekly_sync(&mut self) {
        let now = Timestamp::now();
        tracing::info!("weekly sync: starting");

        // 1. Estimate budget.
        let estimate = self
            .budget
            .estimate_budget()
            .expect("budget estimation: db error is fatal");
        let budget_gb = estimate.total_gb;

        // 2. Select dirty files to back up.
        let batch = self
            .budget
            .select_backup_batch(budget_gb)
            .expect("backup batch selection: db error is fatal");
        tracing::info!(
            files = batch.candidates.len(),
            deferred = batch.deferred_count,
            total_gb = batch.total_required_gb,
            "weekly sync: backup batch selected"
        );

        // 3. Pack dirty files into units and upload via ShardManager.
        let packer = Packer::new(
            self.db.clone(),
            ed25519_dalek::SigningKey::from_bytes(&self.identity_key_bytes),
            self.identity_pub,
            crate::daemon::packer::DEFAULT_UNIT_SIZE_BYTES,
        );
        let pack_results = packer.pack_batch(&batch.candidates, now);
        tracing::info!(units = pack_results.len(), "weekly sync: pack_batch complete");

        for result in pack_results {
            // Write unit record to DB.
            self.db
                .upsert_unit(&result.unit_record)
                .expect("upsert_unit: db error is fatal");

            // Upload shards via ShardManager.
            match self
                .shard_manager
                .upload_unit(
                    result.unit_record.unit_id,
                    &result.unit_record,
                    &result.plaintext,
                    result.importance,
                    syncback_core::types::FileType::User,
                    now,
                )
                .await
            {
                Ok(placements) => {
                    tracing::info!(
                        unit_id = %result.unit_record.unit_id,
                        shards = placements.len(),
                        "weekly sync: unit uploaded"
                    );
                    // Mark each member file as backed-up.
                    for file_record in &result.file_records {
                        self.db
                            .mark_file_clean(&file_record.path, now, result.unit_record.unit_id)
                            .expect("mark_file_clean: db error is fatal");
                    }
                }
                Err(ShardManagerError::NotEnoughPeers { need, have }) => {
                    tracing::info!(
                        need,
                        have,
                        unit_id = %result.unit_record.unit_id,
                        "weekly sync: not enough peers for upload, retry next week"
                    );
                    // Files remain dirty — will be retried next cycle.
                }
                Err(e) => panic!("upload_unit unexpected error: {e}"),
            }
        }

        // 4. Trust update: recalculate trust for all peers.
        let current_week = (now.0 / SECS_PER_WEEK) as u32;
        let count = self
            .trust
            .recalculate_all(now, current_week)
            .expect("trust recalculation: db error is fatal");
        tracing::info!(peers = count, "weekly sync: trust recalculated");

        // 5. Update weeks_in_network for all known peers.
        let peers = self
            .db
            .list_all_peers()
            .expect("list_all_peers: db error is fatal");
        for peer in &peers {
            self.db
                .increment_peer_weeks(&peer.identity)
                .expect("increment_peer_weeks: db error is fatal");
        }

        // 6. Process expired cooldowns (holder side).
        let deleted = self
            .storage
            .process_expired_cooldowns(now)
            .expect("process_expired_cooldowns: db error is fatal");
        if !deleted.is_empty() {
            tracing::info!(
                count = deleted.len(),
                "weekly sync: expired cooldowns processed"
            );
        }

        // 7. Process expired drop notices (holder side).
        let dropped = self
            .storage
            .process_expired_drop_notices(now)
            .expect("process_expired_drop_notices: db error is fatal");
        for shard_id in &dropped {
            tracing::debug!(shard = %shard_id, "drop notice expired: shard deleted");
        }

        // 8. Check disk pressure.
        self.check_disk_pressure(now).await;

        // 9. Clean up stale pending PoS challenges (older than 7 days).
        let cutoff = now.0.saturating_sub(7 * 86_400);
        self.pending_pos_challenges
            .retain(|_, v| v.sent_at.0 >= cutoff);

        // 10. Update schedule record.
        self.db
            .set_schedule(&ScheduleRecord {
                task_name: "weekly_sync".to_string(),
                last_run: Some(now),
                next_run: Timestamp(now.0 + 7 * 604_800),
            })
            .expect("set_schedule failed");

        tracing::info!("weekly sync: complete");
    }

    async fn run_pos_round(&mut self) {
        let now = Timestamp::now();

        let challenges = self
            .shard_manager
            .sample_pos_challenges(now)
            .expect("sample_pos_challenges: db error is fatal");
        tracing::info!(count = challenges.len(), "pos round: sending challenges");

        for challenge in &challenges {
            let challenge_id = compute_challenge_id(challenge);

            self.net_cmd_tx
                .send(NetCommand::SendPosChallenge {
                    holder: challenge.holder,
                    shard_id: challenge.shard_id,
                    block_index: challenge.block_index,
                    nonce: challenge.nonce,
                    challenge_id,
                })
                .await
                .expect("net channel closed");

            self.pending_pos_challenges.insert(
                challenge_id,
                PendingPosChallenge {
                    shard_id: challenge.shard_id,
                    block_index: challenge.block_index,
                    nonce: challenge.nonce,
                    sent_at: now,
                },
            );
        }

        self.db
            .set_schedule(&ScheduleRecord {
                task_name: "pos_round".to_string(),
                last_run: Some(now),
                next_run: Timestamp(now.0 + 7 * 604_800),
            })
            .expect("set_schedule failed");

        tracing::info!(sent = challenges.len(), "pos round: complete");
    }

    async fn run_vacuum(&mut self) {
        let now = Timestamp::now();
        tracing::info!("vacuum: running (stub — full vacuum in Phase 3)");

        let stale_units = self
            .db
            .list_stale_units()
            .expect("list_stale_units failed");
        tracing::info!(stale = stale_units.len(), "vacuum: found stale units");

        let units = self
            .db
            .list_units_by_status(syncback_core::types::UnitStatus::Deleting)
            .expect("list units failed");
        for unit in units {
            tracing::debug!(unit = %unit.unit_id, "vacuum: deleting unit (stub)");
        }

        self.db
            .set_schedule(&ScheduleRecord {
                task_name: "vacuum".to_string(),
                last_run: Some(now),
                next_run: Timestamp(now.0 + 30 * 86_400),
            })
            .expect("set_schedule failed");
    }

    async fn run_repair_check(&mut self) {
        let now = Timestamp::now();

        self.repair_engine.reset_cycle();

        let under_replicated = self
            .shard_manager
            .find_under_replicated_units()
            .expect("find_under_replicated_units failed");
        tracing::info!(
            count = under_replicated.len(),
            "repair check: under-replicated units"
        );

        for unit_id in under_replicated {
            match self
                .shard_manager
                .repair_unit(unit_id, None, now)
                .await
            {
                Ok(n) => {
                    tracing::info!(unit = %unit_id, shards = n, "repair: repaired from local plaintext");
                }
                Err(ShardManagerError::PlaintextNotAvailable) => {
                    self.repair_engine.queue_for_restore(unit_id);
                }
                Err(ShardManagerError::NotEnoughPeers { need, have }) => {
                    tracing::info!(
                        unit = %unit_id,
                        need,
                        have,
                        "repair: not enough peers, retry next week"
                    );
                }
                Err(e) => panic!("repair_unit unexpected error: {e}"),
            }
        }

        let net_cmd_tx = self.net_cmd_tx.clone();
        let summary = self
            .repair_engine
            .run_pending(&self.shard_manager, now, &net_cmd_tx)
            .await;

        tracing::info!(
            repaired = summary.units_repaired,
            skipped_shards = summary.units_skipped_not_enough_shards,
            skipped_peers = summary.units_skipped_no_peers,
            rate_limited = summary.units_skipped_rate_limited,
            offers_sent = summary.shards_offered,
            "repair check: complete"
        );

        self.db
            .set_schedule(&ScheduleRecord {
                task_name: "repair_check".to_string(),
                last_run: Some(now),
                next_run: Timestamp(now.0 + SECS_PER_WEEK),
            })
            .expect("set_schedule failed");
    }
}

// ============================================================
// CLI command handlers
// ============================================================

impl Processor {
    async fn handle_cli(&mut self, cmd: CliCmd) {
        match cmd {
            CliCmd::Status { reply } => self.handle_cli_status(reply).await,
            CliCmd::BackupNow { reply } => self.handle_cli_backup_now(reply).await,
            CliCmd::RestoreFile { path, dest, reply } => {
                self.handle_cli_restore(path, dest, reply).await;
            }
            CliCmd::Peers { reply } => self.handle_cli_peers(reply).await,
            CliCmd::Shutdown => {
                tracing::info!("processor: shutdown requested via CLI");
                self.cancel.cancel();
            }
            CliCmd::ConnectPeer { node_addr, reply } => {
                self.handle_cli_connect_peer(node_addr, reply).await;
            }
            CliCmd::DrRestore {
                seed_phrase,
                peer_addr,
                reply,
            } => {
                self.handle_dr_restore(seed_phrase, peer_addr, reply).await;
            }
        }
    }

    async fn handle_cli_status(&self, reply: tokio::sync::oneshot::Sender<StatusReply>) {
        let peers = self
            .db
            .list_all_peers()
            .expect("list_all_peers failed");
        let shards_held = self
            .db
            .list_all_holding()
            .expect("list_all_holding failed")
            .len();
        let shards_placed = self
            .db
            .list_all_shards()
            .expect("list_all_shards failed")
            .iter()
            .filter(|s| s.status == ShardStatus::Stored)
            .count();
        let budget_record = self.db.get_budget().expect("get_budget failed");
        let budget_gb = budget_record.map(|b| b.estimated_gb).unwrap_or(0.0);
        let dirty_files = self
            .db
            .list_dirty_files()
            .expect("list_dirty_files failed")
            .len();

        let reply_value = StatusReply {
            uptime_secs: self.started_at.elapsed().as_secs(),
            peer_count: peers.len(),
            shards_held,
            shards_placed,
            budget_gb,
            dirty_files,
            own_node_id: self.own_node_id.clone(),
        };

        let _ = reply.send(reply_value);
    }

    async fn handle_cli_backup_now(
        &mut self,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    ) {
        tracing::info!("backup now: triggered by CLI");
        self.run_weekly_sync().await;
        self.handle_system_state_backup().await;
        let _ = reply.send(Ok(()));
    }

    async fn handle_cli_connect_peer(
        &self,
        node_addr: String,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    ) {
        tracing::info!(addr = %node_addr, "cli: connect peer requested");
        let result = self
            .net_cmd_tx
            .send(NetCommand::ConnectAddr { node_addr })
            .await;
        match result {
            Ok(()) => {
                let _ = reply.send(Ok(()));
            }
            Err(_) => {
                let _ = reply.send(Err("network channel closed".to_string()));
            }
        }
    }

    /// Start a restore operation.
    ///
    /// This method does NOT block the event loop. It:
    /// 1. Validates the file/unit in DB.
    /// 2. Registers a PendingRestore state machine.
    /// 3. Sends RestoreRequest NetCommands to holders.
    /// 4. Returns immediately — ShardData responses arrive later via handle_direct_message.
    async fn handle_cli_restore(
        &mut self,
        path: PathBuf,
        dest: PathBuf,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    ) {
        use syncback_core::types::ShardStatus;

        tracing::info!(?path, ?dest, "restore: requested");
        let path_str = path.to_string_lossy().to_string();

        // 1. Look up file record.
        let file_record = match self.db.get_file(&path_str) {
            Ok(Some(r)) => r,
            Ok(None) => {
                let _ = reply.send(Err(format!("file not found in DB: {path_str}")));
                return;
            }
            Err(e) => {
                let _ = reply.send(Err(format!("db error looking up file: {e}")));
                return;
            }
        };

        let unit_id = match file_record.current_unit_id {
            Some(id) => id,
            None => {
                let _ = reply.send(Err(format!(
                    "file has no current unit (not backed up): {path_str}"
                )));
                return;
            }
        };

        // 2. Look up unit record.
        let unit_record = match self.db.get_unit(&unit_id) {
            Ok(Some(r)) => r,
            Ok(None) => {
                let _ = reply.send(Err(format!("unit not found in DB: {unit_id}")));
                return;
            }
            Err(e) => {
                let _ = reply.send(Err(format!("db error looking up unit: {e}")));
                return;
            }
        };

        let k = unit_record.rs_k as usize;
        let n = unit_record.rs_n as usize;

        // 3. Get shard records — select k shards with status Stored.
        let all_shards = match self.db.list_shards_for_unit(&unit_id) {
            Ok(s) => s,
            Err(e) => {
                let _ = reply.send(Err(format!("db error listing shards: {e}")));
                return;
            }
        };

        let stored: Vec<_> = all_shards
            .iter()
            .filter(|s| s.status == ShardStatus::Stored)
            .collect();

        if stored.len() < k {
            let _ = reply.send(Err(format!(
                "not enough stored shards: need {k}, have {} (status=Stored) out of {}",
                stored.len(),
                all_shards.len()
            )));
            return;
        }

        let selected = &stored[..k];

        // 4. Register the PendingRestore state machine.
        let restore_id = self.next_restore_id;
        self.next_restore_id += 1;

        // Register each shard we'll be waiting for.
        // pending_shard_to_restore maps ShardId → (restore_id, shard_index).
        for shard_rec in selected {
            self.pending_shard_to_restore.insert(
                shard_rec.shard_id,
                (restore_id, shard_rec.shard_index as usize),
            );
        }

        self.pending_restores.insert(
            restore_id,
            PendingRestore {
                dest: dest.clone(),
                original_path: path_str.clone(),
                unit_id,
                unit_type: unit_record.unit_type,
                k,
                n,
                shard_blobs: vec![None; n],
                received: 0,
                reply: Some(reply),
            },
        );

        // 5. Send RestoreRequest to each holder.
        for shard_rec in selected {
            let shard_id = shard_rec.shard_id;
            let holder = shard_rec.holder_id;

            let peer_record = match self.db.get_peer(&holder) {
                Ok(Some(r)) => r,
                Ok(None) => {
                    tracing::debug!(holder = %holder, "restore: holder not in DB, skipping shard");
                    continue;
                }
                Err(e) => {
                    tracing::debug!(holder = %holder, error = %e, "restore: db error");
                    continue;
                }
            };

            let holder_addr = match peer_record.node_id {
                Some(node_id) => match iroh::PublicKey::from_bytes(&node_id.0) {
                    Ok(pk) => iroh::EndpointAddr::new(pk),
                    Err(e) => {
                        tracing::debug!(holder = %holder, error = %e, "restore: invalid node_id");
                        continue;
                    }
                },
                None => {
                    tracing::debug!(holder = %holder, "restore: holder has no known node_id");
                    continue;
                }
            };

            let restore_msg = syncback_core::messages::DirectMessage {
                v: syncback_core::constants::PROTOCOL_VERSION,
                body: syncback_core::messages::DirectBody::RestoreRequest(
                    syncback_core::messages::RestoreRequestMsg {
                        v: 1,
                        shard_id,
                        ts: syncback_core::types::Timestamp::now().0,
                    },
                ),
            };

            if self.net_cmd_tx
                .send(NetCommand::Connect {
                    peer_addr: holder_addr,
                    peer_identity: holder,
                    message: restore_msg,
                })
                .await
                .is_err()
            {
                tracing::debug!("restore: net channel closed");
                break;
            }
        }
    }

    /// Advance a pending restore when a ShardData message arrives.
    ///
    /// If all k shards are now available, performs RS decode + decrypt + file write.
    /// The reply sender is consumed on completion.
    async fn on_shard_data_received(
        &mut self,
        shard_id: syncback_core::types::ShardId,
        data: Vec<u8>,
    ) {
        use syncback_core::types::UnitType;

        let (restore_id, shard_index) = match self.pending_shard_to_restore.remove(&shard_id) {
            Some(pair) => pair,
            None => {
                tracing::debug!(shard = %shard_id, "shard_data: no pending restore, ignoring");
                return;
            }
        };

        let pending = match self.pending_restores.get_mut(&restore_id) {
            Some(p) => p,
            None => return,
        };

        if shard_index < pending.n && pending.shard_blobs[shard_index].is_none() {
            pending.shard_blobs[shard_index] = Some(data);
            pending.received += 1;
        }

        tracing::debug!(
            shard = %shard_id,
            received = pending.received,
            k = pending.k,
            "restore: shard received"
        );

        if pending.received < pending.k {
            // Still waiting for more shards.
            return;
        }

        // All k shards received — perform RS decode + decrypt + write.
        let pending = self.pending_restores.remove(&restore_id).expect("just checked");

        let identity_key = ed25519_dalek::SigningKey::from_bytes(&self.identity_key_bytes);
        let packer = crate::daemon::packer::Packer::new(
            self.db.clone(),
            identity_key,
            self.identity_pub,
            crate::daemon::packer::DEFAULT_UNIT_SIZE_BYTES,
        );

        let result = match packer.unpack_unit(
            pending.unit_id,
            pending.unit_type,
            pending.shard_blobs,
            pending.k,
            pending.n,
        ) {
            Ok(unpack) => {
                let path_str = &pending.original_path;
                let dest = &pending.dest;
                match pending.unit_type {
                    UnitType::Pack => {
                        match unpack.files.into_iter().find(|f| f.path.as_deref() == Some(path_str)) {
                            Some(unpacked) => {
                                if let Some(parent) = dest.parent() {
                                    let _ = std::fs::create_dir_all(parent);
                                }
                                std::fs::write(dest, &unpacked.bytes)
                                    .map_err(|e| format!("write file failed: {e}"))
                            }
                            None => Err(format!("file not found in pack unit: {path_str}")),
                        }
                    }
                    UnitType::Chunk => {
                        match unpack.files.into_iter().next() {
                            Some(unpacked) => {
                                if let Some(parent) = dest.parent() {
                                    let _ = std::fs::create_dir_all(parent);
                                }
                                std::fs::write(dest, &unpacked.bytes)
                                    .map_err(|e| format!("write file failed: {e}"))
                            }
                            None => Err("empty chunk unpack result".to_string()),
                        }
                    }
                }
            }
            Err(e) => Err(format!("unpack failed: {e}")),
        };

        if let Some(reply) = pending.reply {
            let _ = reply.send(result.clone());
        }

        match result {
            Ok(()) => tracing::info!(
                path = %pending.original_path,
                dest = ?pending.dest,
                "restore: complete"
            ),
            Err(ref e) => tracing::info!(
                path = %pending.original_path,
                error = %e,
                "restore: failed"
            ),
        }
    }

    async fn handle_cli_peers(
        &self,
        reply: tokio::sync::oneshot::Sender<Vec<crate::daemon::cli_server::PeerInfo>>,
    ) {
        let now = syncback_core::types::Timestamp::now();
        let peers = self
            .db
            .list_all_peers()
            .expect("list_all_peers: db error is fatal");

        let peer_infos = peers
            .into_iter()
            .map(|rec| {
                let trust_score = self.trust.combined_score(&rec.identity).unwrap_or(0.0);
                let shards_held_for_us = self
                    .db
                    .count_stored_shards_for_holder(&rec.identity)
                    .unwrap_or(0);
                let last_seen_secs_ago = rec.last_seen.secs_elapsed(now);
                crate::daemon::cli_server::PeerInfo {
                    identity: hex::encode(&rec.identity.0[..8]),
                    trust_p: rec.trust_p,
                    trust_i: rec.trust_i,
                    trust_s: rec.trust_s,
                    trust_score,
                    weeks_in_network: rec.weeks_in_network,
                    shards_held_for_us,
                    last_seen_secs_ago,
                }
            })
            .collect();

        let _ = reply.send(peer_infos);
    }
}

// ============================================================
// System state handlers
// ============================================================

impl Processor {
    /// Owner-side: snapshot, encrypt, and push system state blob to top-15 peers.
    async fn handle_system_state_backup(&mut self) {
        let now = Timestamp::now();

        // 1. Snapshot DB.
        let state = match crate::daemon::system_state::snapshot_db(&self.db) {
            Ok(s) => s,
            Err(e) => {
                tracing::info!(error = %e, "system_state_backup: snapshot_db failed, skipping");
                return;
            }
        };

        // 2. Pack (encrypt + compress).
        let blob = match crate::daemon::system_state::pack_system_state(&state, &self.identity_key_bytes) {
            Ok(b) => b,
            Err(e) => {
                tracing::info!(error = %e, "system_state_backup: pack_system_state failed, skipping");
                return;
            }
        };

        // 3. Select up to 15 peers by trust score. Skip peers without a known node_addr.
        let all_peers = self
            .db
            .list_all_peers()
            .expect("list_all_peers: db error is fatal");

        let mut scored: Vec<(f64, syncback_core::types::PeerRecord)> = all_peers
            .into_iter()
            .filter(|p| p.node_id.is_some())
            .map(|p| {
                let score = self.trust.combined_score(&p.identity).unwrap_or(0.0);
                (score, p)
            })
            .collect();

        // Sort descending by trust score.
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        let selected: Vec<_> = scored.into_iter().take(15).collect();

        if selected.len() < 3 {
            tracing::info!(
                peers = selected.len(),
                "system_state_backup: too few peers for system state backup, skipping"
            );
            return;
        }

        let blob_bytes = blob.len();
        let mut sent_count = 0usize;

        // 4. Send to each selected peer (fire and forget).
        for (_, peer_record) in &selected {
            let node_id = match peer_record.node_id {
                Some(ref n) => n,
                None => continue,
            };

            let peer_pub_key = match iroh::PublicKey::from_bytes(&node_id.0) {
                Ok(pk) => pk,
                Err(e) => {
                    tracing::debug!(peer = %peer_record.identity, error = %e, "system_state_backup: invalid node_id");
                    continue;
                }
            };
            let peer_addr = iroh::EndpointAddr::new(peer_pub_key);

            let msg = DirectMessage {
                v: syncback_core::constants::PROTOCOL_VERSION,
                body: DirectBody::SystemStateBackup(SystemStateBackupMsg {
                    blob: blob.clone(),
                    created_at: now.0,
                }),
            };

            let result = self
                .net_cmd_tx
                .send(NetCommand::SendMessage {
                    peer_identity: peer_record.identity,
                    peer_addr,
                    message: msg,
                })
                .await;

            if result.is_err() {
                tracing::debug!("system_state_backup: net channel closed");
                break;
            }
            sent_count += 1;
        }

        tracing::info!(
            sent = sent_count,
            blob_bytes = blob_bytes,
            "system_state_backup: sent to peers"
        );
    }

    /// Holder-side: receive and store a system state blob pushed by an owner.
    async fn handle_system_state_backup_received(
        &mut self,
        from: IdentityPub,
        msg: SystemStateBackupMsg,
    ) {
        // 1. Validate.
        if msg.blob.is_empty() || msg.created_at == 0 {
            tracing::debug!(peer = %from, "system_state_backup_received: invalid (empty blob or zero created_at)");
            self.send_system_state_ack(from, false).await;
            return;
        }

        // 2. Only accept from known peers.
        match self.db.get_peer(&from).expect("get_peer failed") {
            Some(_) => {}
            None => {
                tracing::debug!(peer = %from, "system_state_backup_received: unknown peer, rejecting");
                self.send_system_state_ack(from, false).await;
                return;
            }
        }

        // 3. Store (overwrites any previous blob for this owner).
        let now = Timestamp::now();
        let record = syncback_core::types::SystemStateBlobRecord {
            blob: msg.blob,
            created_at: Timestamp(msg.created_at),
            received_at: now,
        };

        self.db
            .store_system_state_blob(&from, &record)
            .expect("store_system_state_blob: db error is fatal");

        tracing::info!(
            peer = %from,
            bytes = record.blob.len(),
            "system_state_backup_received: stored blob"
        );

        // 4. Send ack.
        self.send_system_state_ack(from, true).await;
    }

    /// Holder-side: respond to a system state request from the owner.
    async fn handle_system_state_request(&self, from: IdentityPub, msg: SystemStateRequestMsg) {
        // 1. Verify requester matches the handshake identity.
        if msg.requester != from {
            tracing::debug!(
                peer = %from,
                requested = %msg.requester,
                "system_state_request: requester mismatch, ignoring"
            );
            return;
        }

        // 2. Look up blob.
        let response_msg = match self
            .db
            .get_system_state_blob(&msg.requester)
            .expect("get_system_state_blob: db error is fatal")
        {
            Some(record) => SystemStateResponseMsg {
                blob: record.blob,
                created_at: record.created_at.0,
            },
            None => SystemStateResponseMsg {
                blob: vec![],
                created_at: 0,
            },
        };

        let found = !response_msg.blob.is_empty();

        // 3. Send response via SendDirect.
        let dm = DirectMessage {
            v: syncback_core::constants::PROTOCOL_VERSION,
            body: DirectBody::SystemStateResponse(response_msg),
        };
        let framed = frame_message(&dm).expect("SystemStateResponse frames cleanly");
        self.net_cmd_tx
            .send(NetCommand::SendDirect {
                peer: from,
                payload: framed,
            })
            .await
            .expect("net channel closed");

        tracing::debug!(peer = %from, found = found, "system_state_request: responded");
    }

    /// Owner-side (DR boot): receive the system state blob from a holder, decrypt, restore DB.
    async fn handle_system_state_response(&mut self, from: IdentityPub, msg: SystemStateResponseMsg) {
        let cli_reply = match self.pending_dr_cli_reply.take() {
            Some(r) => r,
            None => {
                tracing::debug!(peer = %from, "system_state_response: unexpected, no pending DR, ignoring");
                return;
            }
        };

        if msg.blob.is_empty() {
            let _ = cli_reply.send(Err(format!(
                "peer {from} does not have a system state backup for this identity"
            )));
            return;
        }

        // Decrypt and deserialize.
        let state =
            match crate::daemon::system_state::unpack_system_state(&msg.blob, &self.identity_key_bytes) {
                Ok(s) => s,
                Err(e) => {
                    let _ = cli_reply.send(Err(format!("failed to unpack system state: {e}")));
                    return;
                }
            };

        // Populate DB. Use force variant since the DR connection may have already
        // registered the holder as a peer in the local DB.
        if let Err(e) = crate::daemon::system_state::restore_db_force(&self.db, &state) {
            let _ = cli_reply.send(Err(format!("failed to restore DB: {e}")));
            return;
        }

        tracing::info!(
            peer = %from,
            files = state.files.len(),
            shards = state.shards.len(),
            peers = state.peers.len(),
            "DR restore: DB populated from system state"
        );

        let _ = cli_reply.send(Ok(()));
    }

    /// Owner-side: receive ack from holder that it stored/rejected the backup.
    async fn handle_system_state_ack(&self, from: IdentityPub, msg: SystemStateAckMsg) {
        if msg.stored {
            tracing::info!(peer = %from, "system_state_ack: holder stored backup");
        } else {
            tracing::info!(peer = %from, "system_state_ack: holder rejected backup");
        }
    }

    /// Helper: send a SystemStateAck to a peer via SendDirect.
    async fn send_system_state_ack(&self, to: IdentityPub, stored: bool) {
        let dm = DirectMessage {
            v: syncback_core::constants::PROTOCOL_VERSION,
            body: DirectBody::SystemStateAck(SystemStateAckMsg { stored }),
        };
        let framed = frame_message(&dm).expect("SystemStateAck frames cleanly");
        let _ = self
            .net_cmd_tx
            .send(NetCommand::SendDirect {
                peer: to,
                payload: framed,
            })
            .await;
    }
}

// ============================================================
// DR boot handlers
// ============================================================

impl Processor {
    /// CLI handler for CliCmd::DrRestore.
    /// Verifies seed phrase matches daemon identity, then initiates connection to peer.
    async fn handle_dr_restore(
        &mut self,
        seed_phrase: Vec<String>,
        peer_addr: String,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    ) {
        // Step 1: Verify seed phrase matches our identity.
        let derived_identity = match derive_identity_from_seed(&seed_phrase) {
            Ok(id) => id,
            Err(e) => {
                let _ = reply.send(Err(format!("invalid seed phrase: {e}")));
                return;
            }
        };
        if derived_identity != self.identity_pub {
            let _ = reply.send(Err(
                "seed phrase does not match daemon identity. \
                 Re-run 'syncback init' with your seed phrase first."
                    .to_string(),
            ));
            return;
        }

        // Step 2: Connect to the peer (fire and forget — PeerConnected event follows).
        let result = self
            .net_cmd_tx
            .send(NetCommand::ConnectAddr {
                node_addr: peer_addr.clone(),
            })
            .await;
        if result.is_err() {
            let _ = reply.send(Err("network channel closed".to_string()));
            return;
        }

        // Step 3: Set pending state so handle_peer_connected_for_dr sends the request.
        self.pending_dr_peer_addr = Some(peer_addr);
        self.pending_dr_cli_reply = Some(reply);
    }

    /// Called from handle_peer_connected. If a DR restore is pending, sends the request.
    async fn handle_peer_connected_for_dr(&mut self, peer_identity: IdentityPub) {
        // Clean up stale reply if CLI timed out (sender closed).
        if let Some(ref reply) = self.pending_dr_cli_reply {
            if reply.is_closed() {
                self.pending_dr_peer_addr = None;
                self.pending_dr_cli_reply = None;
                return;
            }
        }

        if self.pending_dr_peer_addr.take().is_none() {
            return; // Not a DR connect.
        }

        // Send SystemStateRequest.
        let msg = DirectMessage {
            v: syncback_core::constants::PROTOCOL_VERSION,
            body: DirectBody::SystemStateRequest(SystemStateRequestMsg {
                requester: self.identity_pub,
            }),
        };
        let framed = frame_message(&msg).expect("SystemStateRequest frames cleanly");
        let _ = self
            .net_cmd_tx
            .try_send(NetCommand::SendDirect {
                peer: peer_identity,
                payload: framed,
            });

        tracing::debug!(peer = %peer_identity, "DR restore: SystemStateRequest sent");
        // pending_dr_cli_reply stays set until SystemStateResponse arrives.
    }
}

// ============================================================
// Helper: derive identity from BIP39 seed phrase
// ============================================================

fn derive_identity_from_seed(words: &[String]) -> Result<IdentityPub, String> {
    let phrase = words.join(" ");
    let mnemonic =
        bip39::Mnemonic::parse(&phrase).map_err(|e| format!("invalid mnemonic: {e}"))?;
    let seed_bytes = mnemonic.to_seed("");
    let (signing_key, _iroh_priv) = crate::cli::init::derive_keys(&seed_bytes);
    let pub_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    Ok(IdentityPub(pub_bytes))
}

// ============================================================
// DirtyEvent handler
// ============================================================

impl Processor {
    async fn handle_dirty(&self, event: DirtyEvent) {
        tracing::debug!(path = ?event.path, kind = ?event.kind, "dirty event");
        let path_str = event.path.to_string_lossy().to_string();
        let now = Timestamp(event.detected_at);

        match event.kind {
            DirtyKind::Created | DirtyKind::Modified => {
                match self
                    .db
                    .get_file(&path_str)
                    .expect("get_file failed")
                {
                    Some(_) => {
                        self.db
                            .mark_file_dirty(&path_str, now)
                            .expect("mark_file_dirty failed");
                    }
                    None => {
                        let importance = self.config_importance_for_path(&event.path);
                        if importance < 0.1 {
                            tracing::debug!(
                                path = ?event.path,
                                "dirty: importance too low, skipping"
                            );
                            return;
                        }
                        let file_id = self.next_file_id();
                        let record = FileRecord {
                            file_id,
                            path: path_str.clone(),
                            content_hash: [0u8; 32],
                            size_bytes: 0,
                            importance,
                            dirty: true,
                            current_unit_id: None,
                            last_backed_up: None,
                            backed_up: false,
                            first_seen: now,
                        };
                        self.db.upsert_file(&record).expect("upsert_file failed");
                    }
                }
            }
            DirtyKind::Deleted => {
                tracing::debug!(
                    path = ?event.path,
                    "dirty: file deleted (delete flow in Phase 3)"
                );
            }
        }
    }

    /// Return the importance for a path based on config include patterns.
    /// Prefix match, longest match wins. Returns 0.0 if no match or excluded.
    fn config_importance_for_path(&self, path: &Path) -> f64 {
        let path_str = path.to_string_lossy();

        // Check exclude patterns first (simple prefix match for Phase 2).
        for exclude in &self.config.backup.exclude {
            if path_str.starts_with(exclude.as_str()) {
                return 0.0;
            }
        }

        // Find best (longest) include prefix match.
        let mut best: Option<&IncludeEntry> = None;
        for entry in &self.config.backup.include {
            let entry_str = entry.path.to_string_lossy();
            if path_str.starts_with(entry_str.as_ref()) {
                match best {
                    None => best = Some(entry),
                    Some(prev) => {
                        if entry.path.as_os_str().len() > prev.path.as_os_str().len() {
                            best = Some(entry);
                        }
                    }
                }
            }
        }

        best.map(|e| e.importance).unwrap_or(0.0)
    }

    /// Read-then-increment FileId counter from config table.
    fn next_file_id(&self) -> FileId {
        let current: u64 = self
            .db
            .get_config("next_file_id")
            .expect("get_config failed")
            .unwrap_or(0u64);
        let next = current + 1;
        self.db
            .set_config("next_file_id", &next)
            .expect("set_config failed");
        FileId(next)
    }
}

// ============================================================
// NetEvent handlers
// ============================================================

impl Processor {
    async fn handle_net_event(&mut self, event: NetEvent) {
        match event {
            NetEvent::PeerConnected {
                peer_identity,
                peer_node_id,
            } => {
                self.handle_peer_connected(peer_identity, peer_node_id).await;
            }
            NetEvent::MessageReceived { from, message } => {
                self.handle_direct_message(from, message).await;
            }
            NetEvent::BoardMessage {
                from,
                msg_type,
                payload,
            } => {
                self.handle_board_message(from, msg_type, payload).await;
            }
            NetEvent::ShardUploaded {
                shard_id,
                holder,
                bytes,
            } => {
                self.handle_shard_uploaded(shard_id, holder, bytes).await;
            }
            NetEvent::ShardDownloaded {
                shard_id,
                peer,
                bytes,
            } => {
                self.handle_shard_downloaded(shard_id, peer, bytes).await;
            }
            NetEvent::FatalError(msg) => {
                tracing::error!("network fatal error: {msg}");
                self.cancel.cancel();
            }
            NetEvent::HandshakeFailed { reason } => {
                tracing::debug!("handshake failed: {reason}");
            }
        }
    }

    async fn handle_peer_connected(
        &mut self,
        peer: IdentityPub,
        node_id: syncback_core::types::NodeId,
    ) {
        tracing::info!(peer = %peer, "peer connected");
        let now = Timestamp::now();
        match self.db.get_peer(&peer).expect("get_peer failed") {
            Some(mut record) => {
                record.last_seen = now;
                record.node_id = Some(node_id);
                self.db.upsert_peer(&record).expect("upsert_peer failed");
            }
            None => {
                // New peer: create record with node_id set.
                self.trust
                    .upsert_peer(&peer, now)
                    .expect("upsert_peer failed");
                // Update node_id on the freshly created record.
                if let Some(mut record) = self
                    .db
                    .get_peer(&peer)
                    .expect("get_peer failed")
                {
                    record.node_id = Some(node_id);
                    self.db.upsert_peer(&record).expect("upsert_peer failed");
                }
            }
        }

        // If this connection was initiated for DR restore, send the request.
        self.handle_peer_connected_for_dr(peer).await;
    }

    async fn handle_direct_message(&mut self, from: IdentityPub, message: syncback_core::messages::DirectMessage) {
        let now = Timestamp::now();
        match message.body {
            DirectBody::Handshake(_) => {
                tracing::debug!(peer = %from, "direct: unexpected handshake in processor");
            }
            DirectBody::RestoreRequest(req) => {
                self.handle_restore_request(from, req, now).await;
            }
            DirectBody::RestoreDenied(denied) => {
                tracing::info!(
                    peer = %from,
                    shard = %denied.shard_id,
                    required_weeks = denied.required_weeks,
                    current_weeks = denied.current_weeks,
                    "restore denied by holder (escrow)"
                );
                // Remove from pending map — this shard won't arrive.
                self.pending_shard_to_restore.remove(&denied.shard_id);
            }
            DirectBody::BlobReady(ready) => {
                tracing::debug!(
                    peer = %from,
                    shard = %ready.shard_id,
                    "blob ready from holder (pull in Phase 3)"
                );
            }
            DirectBody::ShardData(shard_data) => {
                tracing::debug!(
                    peer = %from,
                    shard = %shard_data.shard_id,
                    bytes = shard_data.data.len(),
                    "shard data received inline"
                );
                self.on_shard_data_received(shard_data.shard_id, shard_data.data).await;
            }
            DirectBody::SystemStateBackup(msg) => {
                self.handle_system_state_backup_received(from, msg).await;
            }
            DirectBody::SystemStateRequest(msg) => {
                self.handle_system_state_request(from, msg).await;
            }
            DirectBody::SystemStateResponse(msg) => {
                self.handle_system_state_response(from, msg).await;
            }
            DirectBody::SystemStateAck(msg) => {
                self.handle_system_state_ack(from, msg).await;
            }
        }
    }

    async fn handle_board_message(
        &mut self,
        from: IdentityPub,
        msg_type: String,
        payload: Vec<u8>,
    ) {
        tracing::debug!(peer = %from, msg_type = %msg_type, "board message received");

        // Only process from known peers.
        if self.db.get_peer(&from).expect("get_peer failed").is_none() {
            tracing::debug!(peer = %from, "board message from unknown peer, dropping");
            return;
        }

        let now = Timestamp::now();

        match msg_type.as_str() {
            "shard_offer" => {
                let msg: ShardOfferMsg = match from_cbor(&payload) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::debug!(peer = %from, error = %e, "shard_offer: parse error");
                        return;
                    }
                };
                self.handle_shard_offer(from, msg, now).await;
            }
            "shard_accept" => {
                let msg: ShardAcceptMsg = match from_cbor(&payload) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::debug!(peer = %from, error = %e, "shard_accept: parse error");
                        return;
                    }
                };
                self.handle_shard_accept(from, msg, now).await;
            }
            "shard_stored" => {
                let msg: ShardStoredMsg = match from_cbor(&payload) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::debug!("shard_stored: parse error: {e}");
                        return;
                    }
                };
                self.shard_manager
                    .handle_shard_stored(msg.shard_id, now)
                    .expect("handle_shard_stored failed");
                tracing::info!(shard = %msg.shard_id, holder = %from, "shard stored confirmed");
            }
            "shard_reject" => {
                let msg: ShardRejectMsg = match from_cbor(&payload) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::debug!("shard_reject: parse error: {e}");
                        return;
                    }
                };
                self.shard_manager
                    .handle_shard_reject(msg.shard_id, now)
                    .unwrap_or_else(|e| {
                        tracing::debug!(error = %e, "shard_reject: shard not found (ok)");
                    });
            }
            "shard_dropped" => {
                let msg: ShardDroppedMsg = match from_cbor(&payload) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::debug!("shard_dropped: parse error: {e}");
                        return;
                    }
                };
                self.shard_manager
                    .handle_shard_dropped(msg.shard_id, now)
                    .unwrap_or_else(|e| {
                        tracing::debug!(error = %e, "shard_dropped: shard not found (ok)");
                    });
                tracing::info!(shard = %msg.shard_id, holder = %from, "shard dropped by holder");
            }
            "shard_drop_notice" => {
                let msg: ShardDropNoticeMsg = match from_cbor(&payload) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::debug!("shard_drop_notice: parse error: {e}");
                        return;
                    }
                };
                tracing::info!(
                    shard = %msg.shard_id,
                    deadline = msg.deadline,
                    "shard drop notice from holder (repair in Phase 3)"
                );
            }
            "pos_challenge" => {
                let msg: PosChallengeMsg = match from_cbor(&payload) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::debug!("pos_challenge: parse error: {e}");
                        return;
                    }
                };
                self.handle_pos_challenge_incoming(from, msg, now).await;
            }
            "pos_response" => {
                let msg: PosResponseMsg = match from_cbor(&payload) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::debug!("pos_response: parse error: {e}");
                        return;
                    }
                };
                self.handle_pos_response_incoming(from, msg, now).await;
            }
            "delete" => {
                let msg: DeleteMsg = match from_cbor(&payload) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::debug!("delete: parse error: {e}");
                        return;
                    }
                };
                match self.storage.handle_delete_request(msg.shard_id, &from, now) {
                    Ok(()) => {
                        tracing::debug!(shard = %msg.shard_id, "delete request recorded");
                    }
                    Err(StorageError::ShardNotFound(_)) => {
                        tracing::debug!(
                            shard = %msg.shard_id,
                            "delete for unknown shard, ignoring"
                        );
                    }
                    Err(e) => panic!("handle_delete_request unexpected error: {e}"),
                }
            }
            "cancel_delete" => {
                let msg: CancelDeleteMsg = match from_cbor(&payload) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::debug!("cancel_delete: parse error: {e}");
                        return;
                    }
                };
                match self.storage.handle_cancel_delete(msg.shard_id, &from) {
                    Ok(()) => {
                        tracing::debug!(shard = %msg.shard_id, "cancel_delete processed");
                    }
                    Err(StorageError::ShardNotFound(_)) => {
                        tracing::debug!(
                            shard = %msg.shard_id,
                            "cancel_delete for unknown shard, ignoring"
                        );
                    }
                    Err(e) => panic!("handle_cancel_delete unexpected error: {e}"),
                }
            }
            "storage_warning" => {
                let msg: StorageWarningMsg = match from_cbor(&payload) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::debug!("storage_warning: parse error: {e}");
                        return;
                    }
                };
                match self.storage.handle_storage_warning(msg.shard_id) {
                    Ok(true) => {
                        tracing::debug!(shard = %msg.shard_id, "storage warning: shard intact");
                    }
                    Ok(false) => {
                        tracing::error!(
                            shard = %msg.shard_id,
                            "storage warning: shard CORRUPTED"
                        );
                    }
                    Err(StorageError::ShardNotFound(_)) => {
                        tracing::debug!(
                            shard = %msg.shard_id,
                            "storage warning for shard we don't hold"
                        );
                    }
                    Err(e) => panic!("handle_storage_warning unexpected error: {e}"),
                }
            }
            "peer_announce" => {
                let msg: PeerAnnounceMsg = match from_cbor(&payload) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::debug!("peer_announce: parse error: {e}");
                        return;
                    }
                };
                self.handle_peer_announce(from, msg, now).await;
            }
            _ => {
                tracing::debug!(
                    peer = %from,
                    msg_type = %msg_type,
                    "unknown board message type, ignoring"
                );
            }
        }
    }

    // ----------------------------------------------------------------
    // Shard offer flow (we are the holder)
    // ----------------------------------------------------------------

    async fn handle_shard_offer(
        &mut self,
        from: IdentityPub,
        msg: ShardOfferMsg,
        now: Timestamp,
    ) {
        let descriptor = &msg.descriptor;
        tracing::debug!(shard = %descriptor.shard_id, owner = %from, "shard offer received");

        if let Err(e) = descriptor.verify_sig() {
            tracing::debug!(shard = %descriptor.shard_id, error = %e, "shard offer: invalid sig");
            return;
        }

        if descriptor.owner_pub != from {
            tracing::debug!(
                shard = %descriptor.shard_id,
                "shard offer: owner_pub mismatch"
            );
            return;
        }

        match self
            .storage
            .should_accept_offer(descriptor)
            .expect("should_accept_offer failed")
        {
            OfferDecision::Accept => {
                tracing::debug!(shard = %descriptor.shard_id, "shard offer: accepting");
                let accept_msg = ShardAcceptMsg {
                    v: 1,
                    shard_id: descriptor.shard_id,
                    offer_msg_id: MsgId::derive(&descriptor.shard_id.0, now.0),
                    ts: now.0,
                };
                let accept_payload = to_cbor(&accept_msg).expect("cbor failed");
                self.net_cmd_tx
                    .send(NetCommand::PublishBoard {
                        msg_type: "shard_accept".to_string(),
                        payload: accept_payload,
                        directed_to: Some(from),
                    })
                    .await
                    .expect("net channel closed");
            }
            OfferDecision::RejectFull => {
                tracing::debug!(shard = %descriptor.shard_id, "shard offer: rejecting (full)");
                self.send_shard_reject(from, descriptor.shard_id, RejectReason::Full, now)
                    .await;
            }
            OfferDecision::RejectUnknown | OfferDecision::RejectNotAllowed => {
                tracing::debug!(
                    shard = %descriptor.shard_id,
                    "shard offer: rejecting (not allowed)"
                );
                self.send_shard_reject(
                    from,
                    descriptor.shard_id,
                    RejectReason::NotAllowed,
                    now,
                )
                .await;
            }
        }
    }

    // ----------------------------------------------------------------
    // Shard accept flow (we are the owner, holder accepted our offer)
    // ----------------------------------------------------------------

    async fn handle_shard_accept(
        &mut self,
        from: IdentityPub,
        msg: ShardAcceptMsg,
        now: Timestamp,
    ) {
        tracing::debug!(shard = %msg.shard_id, holder = %from, "shard accept received");
        match self
            .shard_manager
            .handle_shard_accept(msg.shard_id, from, msg.offer_msg_id, now)
            .await
        {
            Ok(()) => {}
            Err(ShardManagerError::ShardNotFound(_)) => {
                tracing::debug!(
                    shard = %msg.shard_id,
                    "shard accept for unknown shard (TTL expired?)"
                );
            }
            Err(e) => panic!("handle_shard_accept unexpected error: {e}"),
        }
    }

    // ----------------------------------------------------------------
    // PoS challenge (we are the holder)
    // ----------------------------------------------------------------

    async fn handle_pos_challenge_incoming(
        &self,
        from: IdentityPub,
        msg: PosChallengeMsg,
        now: Timestamp,
    ) {
        tracing::debug!(shard = %msg.shard_id, challenger = %from, "pos challenge received");

        match self
            .storage
            .answer_pos_challenge(msg.shard_id, msg.block_range.0, &msg.nonce)
        {
            Ok(answer) => {
                let response = PosResponseMsg {
                    v: 1,
                    challenge_id: msg.challenge_id,
                    block_data_hash: answer.block_data_hash,
                    merkle_proof: answer.merkle_proof,
                    ts: now.0,
                };
                let payload = to_cbor(&response).expect("cbor failed");
                self.net_cmd_tx
                    .send(NetCommand::PublishBoard {
                        msg_type: "pos_response".to_string(),
                        payload,
                        directed_to: Some(from),
                    })
                    .await
                    .expect("net channel closed");
                tracing::debug!(shard = %msg.shard_id, "pos challenge: response sent");
            }
            Err(StorageError::ShardNotFound(_)) => {
                tracing::debug!(
                    shard = %msg.shard_id,
                    "pos challenge: shard not held, no response"
                );
            }
            Err(StorageError::BlobMissing(path)) => {
                tracing::error!(
                    shard = %msg.shard_id,
                    ?path,
                    "pos challenge: blob missing on disk"
                );
            }
            Err(e) => panic!("answer_pos_challenge unexpected error: {e}"),
        }
    }

    // ----------------------------------------------------------------
    // PoS response (we are the challenger/owner)
    // ----------------------------------------------------------------

    async fn handle_pos_response_incoming(
        &mut self,
        from: IdentityPub,
        msg: PosResponseMsg,
        now: Timestamp,
    ) {
        tracing::debug!(
            peer = %from,
            challenge = ?msg.challenge_id,
            "pos response received"
        );

        let challenge_info = match self.pending_pos_challenges.get(&msg.challenge_id) {
            Some(info) => info.clone(),
            None => {
                tracing::debug!("pos response for unknown challenge_id, ignoring");
                return;
            }
        };

        let current_week = (now.0 / SECS_PER_WEEK) as u32;

        let pos_response = PosResponse {
            from,
            shard_id: challenge_info.shard_id,
            block_index: challenge_info.block_index,
            block_data_hash: msg.block_data_hash,
            merkle_proof: msg.merkle_proof,
            nonce: challenge_info.nonce,
        };

        let result = self
            .shard_manager
            .handle_pos_response(pos_response, now, current_week)
            .expect("handle_pos_response: unexpected error");

        match result {
            PosResult::Pass => {
                tracing::debug!(
                    peer = %from,
                    shard = %challenge_info.shard_id,
                    "pos: PASS"
                );
                // Record PoS pass in trust.
                let outcome = syncback_core::trust::PosOutcome {
                    week_number: current_week,
                    challenged: 1,
                    passed: 1,
                };
                self.trust
                    .record_pos_result(&from, outcome)
                    .unwrap_or_else(|e| {
                        tracing::debug!(error = %e, "trust record_pos_result error");
                    });
            }
            PosResult::Fail => {
                tracing::info!(
                    peer = %from,
                    shard = %challenge_info.shard_id,
                    "pos: FAIL"
                );
                // Record PoS fail in trust.
                let outcome = syncback_core::trust::PosOutcome {
                    week_number: current_week,
                    challenged: 1,
                    passed: 0,
                };
                self.trust
                    .record_pos_result(&from, outcome)
                    .unwrap_or_else(|e| {
                        tracing::debug!(error = %e, "trust record_pos_result error");
                    });

                // Send storage_warning to holder.
                let warning = StorageWarningMsg {
                    v: 1,
                    shard_id: challenge_info.shard_id,
                    details: "PoS verification failed".to_string(),
                    ts: now.0,
                };
                let payload = to_cbor(&warning).expect("cbor failed");
                self.net_cmd_tx
                    .send(NetCommand::PublishBoard {
                        msg_type: "storage_warning".to_string(),
                        payload,
                        directed_to: Some(from),
                    })
                    .await
                    .expect("net channel closed");
            }
        }

        self.pending_pos_challenges.remove(&msg.challenge_id);
    }

    // ----------------------------------------------------------------
    // Peer announce (bootstrap/discovery)
    // ----------------------------------------------------------------

    async fn handle_peer_announce(
        &self,
        from: IdentityPub,
        msg: PeerAnnounceMsg,
        now: Timestamp,
    ) {
        tracing::debug!(
            announced = %msg.identity_pub,
            from = %from,
            "peer announce"
        );
        self.trust
            .upsert_peer(&msg.identity_pub, now)
            .expect("upsert_peer failed");

        let node_addr = String::from_utf8_lossy(&msg.node_addr).to_string();
        self.net_cmd_tx
            .send(NetCommand::ConnectAddr { node_addr })
            .await
            .expect("net channel closed");
    }

    // ----------------------------------------------------------------
    // Restore request (we are the holder)
    // ----------------------------------------------------------------

    async fn handle_restore_request(
        &self,
        from: IdentityPub,
        req: RestoreRequestMsg,
        now: Timestamp,
    ) {
        tracing::debug!(shard = %req.shard_id, owner = %from, "restore request");

        match self.storage.read_shard_for_restore(req.shard_id, &from, now) {
            Ok(blob) => {
                // Send shard data inline via ShardData message (Phase 3 approach).
                // The owner sent a RestoreRequest via NetCommand::Connect and is waiting
                // on the same connection for a response.
                let shard_data_msg = syncback_core::messages::DirectMessage {
                    v: syncback_core::constants::PROTOCOL_VERSION,
                    body: syncback_core::messages::DirectBody::ShardData(
                        syncback_core::messages::ShardDataMsg {
                            shard_id: req.shard_id,
                            data: blob,
                        },
                    ),
                };
                // Encode and send via SendDirect. The peer identity is `from` (the owner).
                // Note: SendDirect opens a new outgoing connection to `from`.
                // This is necessary because the holder cannot send back on the same incoming conn
                // in the current architecture (handle_incoming processes messages but doesn't
                // hold a reference to the connection for sending back).
                let cbor = syncback_core::messages::frame_message(&shard_data_msg)
                    .expect("ShardData serializes cleanly");
                self.net_cmd_tx
                    .send(NetCommand::SendDirect { peer: from, payload: cbor })
                    .await
                    .expect("net channel closed");
                tracing::info!(shard = %req.shard_id, owner = %from, "restore: shard data sent inline");
            }
            Err(StorageError::EscrowDenied(denial)) => {
                tracing::info!(
                    shard = %req.shard_id,
                    owner = %from,
                    required_weeks = denial.required_weeks,
                    current_weeks = denial.current_weeks,
                    "restore: denied by escrow"
                );
                let denied_msg = RestoreDeniedMsg {
                    v: 1,
                    shard_id: req.shard_id,
                    reason: DenyReason::EscrowNotMet,
                    required_weeks: denial.required_weeks,
                    current_weeks: denial.current_weeks,
                    ts: now.0,
                };
                let payload = to_cbor(&denied_msg).expect("cbor failed");
                self.net_cmd_tx
                    .send(NetCommand::SendDirect { peer: from, payload })
                    .await
                    .expect("net channel closed");
            }
            Err(StorageError::ShardNotFound(_)) => {
                tracing::debug!(shard = %req.shard_id, "restore: shard not held");
                let denied_msg = RestoreDeniedMsg {
                    v: 1,
                    shard_id: req.shard_id,
                    reason: DenyReason::NotFound,
                    required_weeks: 0,
                    current_weeks: 0,
                    ts: now.0,
                };
                let payload = to_cbor(&denied_msg).expect("cbor failed");
                self.net_cmd_tx
                    .send(NetCommand::SendDirect { peer: from, payload })
                    .await
                    .expect("net channel closed");
            }
            Err(e) => panic!("read_shard_for_restore unexpected error: {e}"),
        }
    }

    // ----------------------------------------------------------------
    // Transfer events
    // ----------------------------------------------------------------

    async fn handle_shard_uploaded(
        &self,
        shard_id: syncback_core::types::ShardId,
        holder: IdentityPub,
        bytes: u64,
    ) {
        tracing::debug!(shard = %shard_id, holder = %holder, bytes, "shard uploaded to holder");
        let now = Timestamp::now();
        let event = TransferEvent {
            peer: holder,
            bytes_sent_to_peer: bytes,
            bytes_received_from_peer: 0,
        };
        self.trust
            .record_transfer(&event, now)
            .unwrap_or_else(|e| {
                tracing::debug!(error = %e, "trust update for unknown peer (uploaded)");
            });
    }

    async fn handle_shard_downloaded(
        &self,
        shard_id: syncback_core::types::ShardId,
        peer: IdentityPub,
        bytes: u64,
    ) {
        tracing::debug!(shard = %shard_id, peer = %peer, bytes, "shard downloaded/served");
        let now = Timestamp::now();
        let event = TransferEvent {
            peer,
            bytes_sent_to_peer: bytes,
            bytes_received_from_peer: 0,
        };
        self.trust
            .record_transfer(&event, now)
            .unwrap_or_else(|e| {
                tracing::debug!(error = %e, "trust update for unknown peer (downloaded)");
            });
    }
}

// ============================================================
// Disk pressure helper
// ============================================================

impl Processor {
    async fn check_disk_pressure(&mut self, now: Timestamp) {
        use syncback_core::budget::DiskPressure;

        let result = self
            .storage
            .check_pressure(now)
            .expect("check_pressure failed");

        match result.pressure {
            DiskPressure::Normal => {}
            DiskPressure::Soft => {
                tracing::info!("disk pressure: SOFT — rejecting new shard offers");
            }
            DiskPressure::Hard => {
                tracing::info!(
                    evictions = result.immediate_evictions.len(),
                    drop_notices = result.drop_notices.len(),
                    freed_gb = result.freed_gb,
                    "disk pressure: HARD — evicting shards"
                );

                // Phase 1: immediate evictions.
                for target in &result.immediate_evictions {
                    match self.storage.evict_shard(target.shard_id, now) {
                        Ok(owner_pub) => {
                            let msg = syncback_core::messages::ShardDroppedMsg {
                                v: 1,
                                shard_id: target.shard_id,
                                ts: now.0,
                            };
                            let payload = to_cbor(&msg).expect("cbor failed");
                            self.net_cmd_tx
                                .send(NetCommand::PublishBoard {
                                    msg_type: "shard_dropped".to_string(),
                                    payload,
                                    directed_to: Some(owner_pub),
                                })
                                .await
                                .expect("net channel closed");
                        }
                        Err(StorageError::ShardNotFound(_)) => {} // already gone
                        Err(e) => panic!("evict_shard unexpected error: {e}"),
                    }
                }

                // Phase 2: drop notices.
                for notice in &result.drop_notices {
                    self.storage
                        .record_drop_notice(notice.shard_id, now)
                        .unwrap_or_else(|e| {
                            tracing::debug!(error = %e, "record_drop_notice: shard not found");
                        });

                    let msg = syncback_core::messages::ShardDropNoticeMsg {
                        v: 1,
                        shard_id: notice.shard_id,
                        deadline: notice.deadline,
                        ts: now.0,
                    };
                    let payload = to_cbor(&msg).expect("cbor failed");

                    if let Ok(Some(record)) = self.db.get_holding(&notice.shard_id) {
                        self.net_cmd_tx
                            .send(NetCommand::PublishBoard {
                                msg_type: "shard_drop_notice".to_string(),
                                payload,
                                directed_to: Some(record.owner_pub),
                            })
                            .await
                            .expect("net channel closed");
                    }
                }
            }
        }
    }
}

// ============================================================
// Helper: send_shard_reject
// ============================================================

impl Processor {
    async fn send_shard_reject(
        &self,
        to: IdentityPub,
        shard_id: syncback_core::types::ShardId,
        reason: RejectReason,
        now: Timestamp,
    ) {
        let msg = ShardRejectMsg {
            v: 1,
            shard_id,
            offer_msg_id: MsgId::derive(&shard_id.0, now.0),
            reason,
            ts: now.0,
        };
        let payload = to_cbor(&msg).expect("cbor failed");
        self.net_cmd_tx
            .send(NetCommand::PublishBoard {
                msg_type: "shard_reject".to_string(),
                payload,
                directed_to: Some(to),
            })
            .await
            .expect("net channel closed");
    }
}

// ============================================================
// Helper: challenge_id derivation
// ============================================================

fn compute_challenge_id(c: &crate::daemon::shard_manager::PosChallenge) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&c.shard_id.0);
    hasher.update(&c.block_index.to_be_bytes());
    hasher.update(&c.nonce);
    *hasher.finalize().as_bytes()
}
