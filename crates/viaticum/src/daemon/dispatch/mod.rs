//! Shared CLI-command dispatch.
//!
//! Maps a `CliRequest` to a `CliResponse` by calling into `DaemonState`.
//! Consumed by `web_api` handlers. Previously also consumed by `cli_server`
//! (Unix socket) — removed in the macOS port HTTP-unification work.

use viaticum_core::system_state::catalog::{RefusalKind, WaitingReason};
use viaticum_core::trust::compute_combined;
use viaticum_core::types::{
    FileRecord, FileVersion, LocalState, PlacementStatus, SourceBlockStatus, Timestamp, hex_encode,
};

use crate::cli::types::{
    CliRequest, CliResponse, DeviceEntry, EffectiveStatus, FileEntry, PeerSummary, RestoreBlocker,
    RestoreRejection, StatusData, VersionEntry,
};
use crate::daemon::handle::DaemonState;
use crate::daemon::restore::staging::JobId;
use crate::daemon::restore::{RestoreCoordinator, RestoreRequest, VersionSelector};

pub mod missing_sources;

#[cfg(test)]
mod tests;

// ============================================================
// Dispatch — wired to real DaemonState
// ============================================================

/// Dispatch a CliRequest and produce a CliResponse.
pub(crate) async fn dispatch(request: CliRequest, state: &DaemonState) -> CliResponse {
    match request {
        CliRequest::Status => dispatch_status(state).await,

        CliRequest::Files { path_prefix } => dispatch_files(state, path_prefix),

        CliRequest::Versions { path } => dispatch_versions(state, &path),

        CliRequest::Restore {
            path,
            version,
            date,
            dest,
        } => dispatch_restore(state, path, version, date, dest).await,

        CliRequest::RestoreJobStatus { job_id } => dispatch_restore_job(state, &job_id).await,

        CliRequest::RestoreJobList => CliResponse::RestoreJobs(state.restore_jobs.list()),

        CliRequest::DeviceList => dispatch_device_list(state),

        CliRequest::DeviceAdd { label } => dispatch_device_add(state, label),

        CliRequest::DeviceRevoke { device_id_hex } => {
            dispatch_device_revoke(state, device_id_hex).await
        }

        CliRequest::Connect { addr } => dispatch_connect(state, addr).await,
    }
}

// ── Status ────────────────────────────────────────────────────────────────────

pub(crate) async fn dispatch_status(state: &DaemonState) -> CliResponse {
    let peers = match state.db.list_all_peers() {
        Ok(p) => p,
        Err(e) => {
            return CliResponse::Error(format!("db error listing peers: {e}"));
        }
    };
    let files = match state.db.list_all_files() {
        Ok(f) => f,
        Err(e) => {
            return CliResponse::Error(format!("db error listing files: {e}"));
        }
    };
    let holdings_bytes = match state.db.total_holding_bytes() {
        Ok(b) => b,
        Err(e) => {
            return CliResponse::Error(format!("db error reading holdings: {e}"));
        }
    };
    let source_blocks = match state.db.list_all_source_blocks() {
        Ok(b) => b,
        Err(e) => {
            return CliResponse::Error(format!("db error reading source blocks: {e}"));
        }
    };
    let placements = match state.db.list_all_placements() {
        Ok(p) => p,
        Err(e) => {
            return CliResponse::Error(format!("db error reading placements: {e}"));
        }
    };

    // PoS totals across all peers.
    let (pos_total_challenges, pos_total_passes) = state.db.total_pos_stats().unwrap_or((0, 0));

    // Current week for recent PoS window (last 4 weeks), scaled by time_scale.
    let now_week = crate::daemon::processor::current_week_number_scaled(state.time_scale);
    let recent_window_start = now_week.saturating_sub(3); // last 4 weeks inclusive

    // Snapshot of authenticated DeviceIds (heavy traffic allowed). conn-only
    // (post-Noise but pre-cert) is not attributable to a specific master, so
    // peers list shows just `auth` vs `known`.
    let auth_devices: std::collections::HashSet<viaticum_core::types::DeviceId> =
        match state.swarm_handle.as_ref() {
            Some(s) => s.peer_sets().await.map(|(a, _)| a).unwrap_or_default(),
            None => std::collections::HashSet::new(),
        };

    // Compute peer summaries, sorted by combined trust descending (top 20).
    let mut peer_summaries: Vec<PeerSummary> = peers
        .iter()
        .map(|p| {
            let combined = compute_combined(p.trust_p, p.trust_i, p.trust_s);
            let identity_hex = bytes_to_hex_8(&p.device_id.0);
            let last_seen = timestamp_to_iso(p.last_seen);

            // Recent PoS stats for this peer.
            let (ch, pa) = state
                .db
                .list_pos_weekly_for_peer(&p.device_id)
                .unwrap_or_default()
                .into_iter()
                .filter(|(week, _)| *week >= recent_window_start)
                .fold((0u32, 0u32), |(c, p), (_, e)| {
                    (c.saturating_add(e.challenged), p.saturating_add(e.passed))
                });

            PeerSummary {
                identity_hex,
                trust: combined,
                bytes_we_store: p.bytes_we_store_for_peer,
                bytes_peer_stores: p.bytes_peer_stores_for_us,
                last_seen,
                trust_p: p.trust_p,
                trust_i: p.trust_i,
                trust_s: p.trust_s,
                pos_challenges_recent: ch,
                pos_passes_recent: pa,
                link: if auth_devices.contains(&p.device_id) {
                    "auth".to_string()
                } else {
                    "known".to_string()
                },
            }
        })
        .collect();
    peer_summaries.sort_by(|a, b| {
        b.trust
            .partial_cmp(&a.trust)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    peer_summaries.truncate(20);

    // avg_trust across all peers.
    let avg_trust = if peers.is_empty() {
        0.0
    } else {
        let sum: f64 = peers
            .iter()
            .map(|p| compute_combined(p.trust_p, p.trust_i, p.trust_s))
            .sum();
        sum / peers.len() as f64
    };

    // backed_up_bytes: sum of k*t for files that have been backed up (backed_up_at set).
    let backed_up_bytes: u64 = files
        .iter()
        .filter_map(|f| f.versions.last())
        .filter(|v| v.backed_up_at.is_some())
        .map(|v| v.k as u64 * v.t as u64)
        .sum();

    // blocks_needing_repair: source blocks with NeedsRepair-like status.
    let blocks_needing_repair = source_blocks
        .iter()
        .filter(|b| b.status == SourceBlockStatus::Stale)
        .count() as u32;

    // Placement stats.
    use viaticum_core::types::PlacementStatus;
    let placement_count = placements.len() as u32;
    let placement_alive = placements
        .iter()
        .filter(|p| {
            matches!(
                p.status,
                PlacementStatus::Alive | PlacementStatus::Uncertain
            )
        })
        .count() as u32;
    let placement_lost = placements
        .iter()
        .filter(|p| {
            matches!(
                p.status,
                PlacementStatus::Lost | PlacementStatus::PresumedLost
            )
        })
        .count() as u32;

    // Block health: per source block, count alive symbols vs k_eff (k + 3).
    use std::collections::HashMap;
    let mut alive_symbols_per_block: HashMap<[u8; 32], u32> = HashMap::new();
    for pl in &placements {
        if matches!(
            pl.status,
            PlacementStatus::Alive | PlacementStatus::Uncertain
        ) {
            *alive_symbols_per_block
                .entry(pl.source_block_id.0)
                .or_default() += pl.symbol_count();
        }
    }
    let mut blocks_ok = 0u32;
    let mut blocks_at_risk = 0u32;
    for sb in &source_blocks {
        let alive = alive_symbols_per_block
            .get(&sb.block_id.0)
            .copied()
            .unwrap_or(0);
        let k_eff = sb.k + 3;
        if alive >= k_eff {
            blocks_ok += 1;
        } else {
            blocks_at_risk += 1;
        }
    }

    let node_identity = hex_encode(&state.identity_pub.0);
    let device_id = bytes_to_hex_8(&state.device_id.0);

    let node_addr = match state.swarm_handle.as_ref() {
        Some(swarm) => {
            let addrs = swarm.listen_addrs().await.unwrap_or_default();
            // Prefer a routable IPv4 address, then any routable, then anything.
            // Excludes both IPv4 (127.0.0.1) and IPv6 (::1) loopback.
            let addr_strings: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();
            let base = crate::daemon::network::addr::select_display_base_addr(&addr_strings)
                .unwrap_or_default();
            if base.is_empty() {
                swarm.peer_id.to_string()
            } else {
                format!("{}/p2p/{}", base, swarm.peer_id)
            }
        }
        None => hex_encode(&state.identity_pub.0),
    };

    let (peer_count_connected, peer_count_authenticated) = match state.swarm_handle.as_ref() {
        Some(s) => s.peer_counts().await.unwrap_or((0, 0)),
        None => (0, 0),
    };

    let by_importance = compute_importance_buckets(&source_blocks);
    // restore-i8/i18/i19: cached staging status (set before the web API started,
    // refreshed hourly and by the restore coordinator after each job); no disk walk.
    let staging = *state
        .restore_staging
        .lock()
        .expect("restore staging status lock poisoned");
    // holder-i1..i3: one disk read and one holdings number for the quota, its state and the
    // staging squeeze flag.
    let disk_free = crate::daemon::handle::disk_available_bytes(&state.data_dir);
    let quota = viaticum_core::budget::compute_effective_quota(
        state.soft_quota_bytes,
        disk_free,
        holdings_bytes,
        state.disk_reserve_bytes,
    );
    let (effective_quota_bytes, quota_state) = match quota {
        viaticum_core::budget::Quota::Bytes(n) => (n, "bytes"),
        viaticum_core::budget::Quota::Unknown => (0, "unknown"),
        // Never produced by compute_effective_quota (tests only).
        viaticum_core::budget::Quota::Unlimited => (0, "unlimited"),
    };
    let quota_note = if disk_free.is_none() {
        crate::daemon::holder_cleanup::unreadable_disk_note(&state.data_dir, state.soft_quota_bytes)
    } else {
        String::new()
    };
    // holder-i4: below the reserve (at any quota), say so and what the pressure tick gives
    // back — the Hard deficit, bounded by the hard floor.
    let below_reserve_giving_back_bytes = match (disk_free, quota) {
        (Some(free), viaticum_core::budget::Quota::Bytes(q)) if free < state.disk_reserve_bytes => {
            let above_floor = holdings_bytes.saturating_sub(state.hard_quota_bytes);
            Some(viaticum_core::budget::hard_eviction_deficit(q, holdings_bytes).min(above_floor))
        }
        _ => None,
    };
    let staging_squeezes_holdings = crate::daemon::restore::cleanup::staging_squeezes_holdings(
        crate::daemon::restore::cleanup::holder_stops_taking_data(
            state.soft_quota_bytes,
            disk_free,
            state.disk_reserve_bytes,
            holdings_bytes,
        ),
        staging.bytes,
    );
    let mut dr = dr_readiness(&state.db, Timestamp::now().0, state.time_scale);
    dr.files_without_source = state.missing_sources.get(&state.db).await;

    CliResponse::Status(Box::new(StatusData {
        node_identity,
        device_id,
        node_addr,
        peer_count: peers.len() as u32,
        peer_count_connected,
        peer_count_authenticated,
        avg_trust,
        holding_bytes: holdings_bytes,
        backed_up_files: files.len() as u32,
        backed_up_bytes,
        blocks_needing_repair,
        peers: peer_summaries,
        effective_quota_bytes,
        quota_state: quota_state.to_string(),
        quota_note,
        below_reserve_giving_back_bytes,
        used_bytes: holdings_bytes,
        pos_total_challenges,
        pos_total_passes,
        placement_count,
        placement_alive,
        placement_lost,
        blocks_ok,
        blocks_at_risk,
        table_stats: state.db.table_stats().ok(),
        by_importance,
        restore_staging_jobs: staging.job_dirs,
        restore_staging_bytes: staging.bytes,
        restore_staging_path: state
            .data_dir
            .join("restore")
            .to_string_lossy()
            .into_owned(),
        restore_publish: staging.publish.as_str().to_string(),
        restore_staging_squeezes_holdings: staging_squeezes_holdings,
        dr_pointer_published_at: dr.published_at,
        dr_pointer_files: dr.files,
        dr_pointer_acks: dr.acks,
        catalog_lineage: dr.lineage,
        files_without_source: dr.files_without_source,
        dr_ready: dr.ready,
        dr_pointer_ack_threshold: dr.threshold,
        dr_ss_blocks_placed: dr.blocks_placed,
        dr_ss_blocks_total: dr.blocks_total,
        dr_pointer_refusal: dr.refusal,
        dr_waiting_since: dr.waiting_since,
        dr_waiting: dr.waiting,
        dr_restores_state_of: dr.restores_state_of,
        files_too_large: count_too_large_under_watches(state),
        max_file_size_bytes: state.max_file_size_bytes,
        block_work_budget_bytes: state.block_work_budget_bytes,
        dr_lease: state
            .dr_leases
            .as_ref()
            .and_then(|leases| leases.status())
            .map(|s| crate::cli::types::DrLeaseStatus {
                holds_mib: s.holds_mib,
                age_s: s.age_s,
            }),
    }))
}

/// backup-i4: the too-large marks of files under the watch directories now. A mark left
/// by a folder that was unwatched since is not counted (the start pass drops it). Without a
/// watch admin (web API off; tests) every mark counts. A DB error counts none.
fn count_too_large_under_watches(state: &DaemonState) -> u32 {
    let marks = match state.db.list_too_large() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(err = %e, "status: cannot list the too-large marks");
            return 0;
        }
    };
    let Some(admin) = state.watch_admin.as_ref() else {
        return marks.len() as u32;
    };
    let roots: Vec<std::path::PathBuf> = admin
        .live_configs
        .read()
        .expect("live_configs lock poisoned")
        .iter()
        .map(|wc| viaticum_core::config::expand_watch_path(&wc.path))
        .collect();
    marks
        .iter()
        .filter(|(path, _)| {
            roots
                .iter()
                .any(|root| std::path::Path::new(path).starts_with(root))
        })
        .count() as u32
}

/// Status fields about DR readiness (dr-i9, dr-i39, dr-i41, dr-i49; mailbox-i49, i54)
/// and missing sources (dr-i11).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct DrReadiness {
    pub(crate) published_at: u64,
    pub(crate) files: u32,
    pub(crate) acks: u32,
    pub(crate) lineage: String,
    pub(crate) files_without_source: u32,
    pub(crate) ready: bool,
    pub(crate) threshold: u32,
    pub(crate) blocks_placed: u32,
    pub(crate) blocks_total: u32,
    /// Words: why friends refused the pointer of the newest base ("" = no refusal).
    pub(crate) refusal: String,
    pub(crate) waiting_since: u64,
    /// Words: why the newest changes are not in the network yet ("" = they are).
    pub(crate) waiting: String,
    /// dr-i53: `created_at` of the catalog state DR restores; 0 = not ready.
    pub(crate) restores_state_of: u64,
}

/// Read-only: the pointer places in META (never a pointer only built, dr-i9) and this
/// DB's history id (not minted here). A DB read error leaves the corresponding fields at
/// their "unknown" zero. `files_without_source` is filled by the caller from the
/// background-counted `MissingSourceCache` (one stat per file is too slow inline).
pub(crate) fn dr_readiness(
    db: &viaticum_core::db::Db,
    now_secs: u64,
    time_scale: u64,
) -> DrReadiness {
    let mut r = DrReadiness::default();
    let known_peers = db.list_all_peers().map(|p| p.len()).unwrap_or(0);
    match crate::daemon::system_state::strength::pointer_readiness(
        db,
        known_peers,
        now_secs,
        time_scale,
    ) {
        Ok(p) => {
            if let Some((at, files, acks)) = p.accepted {
                r.published_at = at;
                r.files = files;
                r.acks = acks;
            }
            r.ready = p.ready;
            r.restores_state_of = p.restores_state_of.unwrap_or(0);
            r.threshold = p.threshold;
            r.blocks_placed = p.blocks_placed;
            r.blocks_total = p.blocks_total;
            r.refusal = p.refusal.map(refusal_words).unwrap_or_default();
            if let Some(w) = p.waiting {
                r.waiting_since = w.since;
                r.waiting = waiting_words(w.reason).to_string();
            }
        }
        Err(e) => tracing::warn!(error = %e, "status: cannot read the pointer places"),
    }
    match db.catalog_lineage() {
        Ok(Some(l)) => r.lineage = l.to_hex(),
        Ok(None) => {}
        Err(e) => tracing::warn!(error = %e, "status: cannot read the catalog history id"),
    }
    r
}

/// The refusal of the pointer in words (CROWN-1 V.15.3, V.16.4 п.9 / NOTE-C).
pub(crate) fn refusal_words(kind: RefusalKind) -> String {
    match kind {
        RefusalKind::ClockSkew => {
            "DR: not ready — friends refused the recovery pointer: this computer's clock looks wrong"
                .to_string()
        }
        RefusalKind::SlotsFull => "DR: not ready — this recovery phrase already has 64 installations \
             stored at friends; there is no room for this one"
            .to_string(),
        RefusalKind::Superseded => {
            "DR: friends hold a pointer newer than this computer's clock — the clock went back"
                .to_string()
        }
        RefusalKind::Mixed {
            clock,
            superseded,
            slots_full,
            other,
        } => {
            let mut s = format!(
                "DR: not ready — friends refused the pointer ({clock} clock, {superseded} newer \
                 pointer held, {slots_full} full"
            );
            if other > 0 {
                s.push_str(&format!(", {other} other"));
            }
            s.push(')');
            s
        }
        RefusalKind::NoAck => "DR: not ready — no friend answered the last pointer publication".to_string(),
    }
}

/// Why the newest catalog changes wait (mailbox-i54).
pub(crate) fn waiting_words(reason: WaitingReason) -> &'static str {
    match reason {
        WaitingReason::BlocksNotPlaced => "catalog blocks not placed",
        WaitingReason::Refused => "friends refused",
        WaitingReason::NoAck => "no friend answered",
    }
}

// ── Files ─────────────────────────────────────────────────────────────────────

/// Owner-side estimate of a version's lifecycle state from placement counts.
///
/// `live` / `target` / `lost` are SYMBOL counts (not holder counts): we need
/// k_eff symbols to decode, and each holder typically carries many symbols
/// (an ESI range). Counting holders would give nonsensical "6/1195" displays.
/// Whether the file's local copy is safe to delete: the latest version is backed
/// up and its source block has reached its reliability target, so the network can
/// reconstruct it without the local source. Conservative — returns false when the
/// version is not backed up, the block record is missing, or it is below target
/// (a target of 0.0 is the pre-migration sentinel and never counts as safe).
/// "At target" is `reliability::meets_target` — the one tolerance-aware definition
/// (repair-i3). A block not in service (being released, in the window, missing) is never
/// safe, whatever its cached reliability says (backup-i8, backup-i21: the cache is not
/// recomputed when the block turns `Deleting`).
fn compute_is_safe_to_delete(state: &DaemonState, file: &FileRecord) -> bool {
    // backup-i4: a file whose current content is above the limit is not protected, whatever
    // its older version says. A DB error answers "no".
    if !matches!(state.db.get_too_large(&file.path), Ok(None)) {
        return false;
    }
    let Some(version) = file.versions.last() else {
        return false;
    };
    if version.backed_up_at.is_none() {
        return false;
    }
    if !block_in_service(state, &version.source_block_id) {
        return false;
    }
    match state.db.get_source_block(&version.source_block_id) {
        Ok(Some(block)) => {
            block.target_reliability > 0.0
                && viaticum_core::reliability::meets_target(
                    block.current_reliability,
                    block.target_reliability,
                )
        }
        _ => false,
    }
}

/// The block is in service (`Serviceability::Serviceable`, backup-i21). A DB error answers
/// "no": the conservative side for both readers.
fn block_in_service(state: &DaemonState, block: &viaticum_core::types::SourceBlockId) -> bool {
    state
        .db
        .block_serviceability(block)
        .is_ok_and(|s| s.is_serviceable())
}

fn compute_effective_status(state: &DaemonState, version: &FileVersion) -> EffectiveStatus {
    // backed_up_at == None means the encoder pipeline hasn't produced a block yet.
    if version.backed_up_at.is_none() {
        return EffectiveStatus::Queued;
    }
    // A block not in service is never "restorable / on target", whatever its placements
    // count (backup-i8): the network is releasing it; the file is backed up again.
    match state.db.block_serviceability(&version.source_block_id) {
        Ok(s) if s.is_serviceable() => {}
        Ok(_) => return EffectiveStatus::Releasing,
        Err(_) => return EffectiveStatus::Queued, // Conservative on DB error.
    }

    let target = version.k + viaticum_core::constants::DECODE_OVERHEAD;
    let placements = match state.db.list_placements_for_block(&version.source_block_id) {
        Ok(ps) => ps,
        Err(_) => return EffectiveStatus::Queued, // Conservative on DB error.
    };

    let mut live_symbols = 0u32;
    let mut lost_symbols = 0u32;
    let mut known_symbols = 0u32; // anything not Lost/Deleting
    for p in &placements {
        let n = p.symbol_count();
        match p.status {
            PlacementStatus::Alive => {
                live_symbols = live_symbols.saturating_add(n);
                known_symbols = known_symbols.saturating_add(n);
            }
            PlacementStatus::Lost | PlacementStatus::Deleting => {
                lost_symbols = lost_symbols.saturating_add(n);
            }
            // Offered/Accepted/Uncertain/PresumedLost — placed but not confirmed.
            _ => {
                known_symbols = known_symbols.saturating_add(n);
            }
        }
    }

    if live_symbols >= target {
        EffectiveStatus::Restorable {
            live: live_symbols,
            target,
        }
    } else if known_symbols >= target && lost_symbols > 0 {
        EffectiveStatus::Degraded {
            live: live_symbols,
            lost: lost_symbols,
            target,
        }
    } else {
        EffectiveStatus::Replicating {
            live: live_symbols,
            target,
        }
    }
}

fn too_large_info(mark: &viaticum_core::types::TooLargeMark) -> crate::cli::types::TooLargeInfo {
    crate::cli::types::TooLargeInfo {
        size_bytes: mark.size_bytes,
        limit_bytes: mark.limit_bytes,
        since: timestamp_to_iso_date(mark.first_seen),
    }
}

fn dispatch_files(state: &DaemonState, path_prefix: Option<String>) -> CliResponse {
    let records = match path_prefix {
        Some(ref prefix) => state.db.list_files_with_prefix(prefix),
        None => state.db.list_all_files(),
    };
    let records = match records {
        Ok(r) => r,
        Err(e) => {
            return CliResponse::Error(format!("db error listing files: {e}"));
        }
    };

    let marks: std::collections::HashMap<String, viaticum_core::types::TooLargeMark> =
        match state.db.list_too_large() {
            Ok(m) => m.into_iter().collect(),
            Err(e) => {
                return CliResponse::Error(format!("db error listing too-large marks: {e}"));
            }
        };

    let mut entries: Vec<FileEntry> = records
        .iter()
        .map(|f| {
            let latest = f.versions.last();
            let last_backed_up = latest
                .and_then(|v| v.backed_up_at)
                .map(timestamp_to_iso)
                .unwrap_or_else(|| "pending".to_string());
            let size_bytes = latest.map(|v| v.k as u64 * v.t as u64).unwrap_or(0);
            let local_state = f
                .devices
                .iter()
                .map(|(_, ls)| match ls {
                    LocalState::Present => "present",
                    LocalState::Deleted(_) => "deleted",
                })
                .next()
                .unwrap_or("unknown")
                .to_string();
            let effective_status = latest.map(|v| compute_effective_status(state, v));
            let is_safe_to_delete = compute_is_safe_to_delete(state, f);
            FileEntry {
                path: f.path.clone(),
                versions: f.versions.len() as u32,
                last_backed_up,
                size_bytes,
                local_state,
                effective_status,
                is_safe_to_delete,
                too_large: marks.get(&f.path).map(too_large_info),
            }
        })
        .collect();

    // A marked file with no catalog record was never backed up: the mark is all there is.
    let listed: std::collections::HashSet<&str> = records.iter().map(|f| f.path.as_str()).collect();
    let mut synthetic: Vec<FileEntry> = marks
        .iter()
        .filter(|(path, _)| {
            !listed.contains(path.as_str())
                && path_prefix.as_ref().is_none_or(|p| path.starts_with(p))
        })
        .map(|(path, mark)| FileEntry {
            path: path.clone(),
            versions: 0,
            last_backed_up: "never".to_string(),
            size_bytes: 0,
            local_state: "present".to_string(),
            effective_status: None,
            is_safe_to_delete: false,
            too_large: Some(too_large_info(mark)),
        })
        .collect();
    if !synthetic.is_empty() {
        entries.append(&mut synthetic);
        entries.sort_by(|a, b| a.path.cmp(&b.path));
    }

    CliResponse::Files(entries)
}

// ── Versions ──────────────────────────────────────────────────────────────────

fn dispatch_versions(state: &DaemonState, path: &str) -> CliResponse {
    let record = match state.db.get_file(path) {
        Ok(Some(r)) => r,
        Ok(None) => return CliResponse::Versions(vec![]),
        Err(e) => return CliResponse::Error(format!("db error: {e}")),
    };

    let entries: Vec<VersionEntry> = record
        .versions
        .iter()
        .enumerate()
        .map(|(idx, v)| {
            let backed_up_at = v
                .backed_up_at
                .map(timestamp_to_iso)
                .unwrap_or_else(|| "pending".to_string());
            let content_hash_hex = hex_encode(&v.content_hash);
            let source_block_id_hex = hex_encode(&v.source_block_id.0);
            let effective_status = compute_effective_status(state, v);
            // restore_blocker is the count-side of effective_status (owner's estimate);
            // what a restore actually got is in its job's failures (restore-i3).
            let restore_blocker = match &effective_status {
                EffectiveStatus::Replicating { live, target }
                | EffectiveStatus::Degraded { live, target, .. } => {
                    // Estimate offline holders: placements not Alive that we
                    // expected to count toward `target`.
                    let holders_offline = target.saturating_sub(*live);
                    Some(RestoreBlocker::InsufficientPlacements {
                        have: *live,
                        need: *target,
                        holders_offline,
                    })
                }
                // restore-i3 (2026-09-30): holders that got the block's Delete no longer
                // serve it; never shown as restorable.
                EffectiveStatus::Releasing => Some(RestoreBlocker::BeingReleased),
                _ => None,
            };
            VersionEntry {
                version: (idx + 1) as u32,
                created_at: timestamp_to_iso(v.created_at),
                backed_up_at,
                content_hash_hex,
                size_bytes: v.k as u64 * v.t as u64,
                source_block_id_hex,
                effective_status,
                restore_blocker,
            }
        })
        .collect();

    CliResponse::Versions(entries)
}

// ── Restore ───────────────────────────────────────────────────────────────────

/// Submit a restore job (restore-i3, i4). Answers at once: the job (`queued`), or a
/// rejection when no job can do anything — the path is not in the catalog, nothing
/// under it has a backed-up version, a bad argument, or the queue is full / closed.
/// A rejected request creates no job and no staging dir.
async fn dispatch_restore(
    state: &DaemonState,
    path: String,
    version: Option<u32>,
    date: Option<String>,
    dest: Option<String>,
) -> CliResponse {
    if dest.is_some() {
        return CliResponse::RestoreRejected(RestoreRejection::DestNotSupported);
    }

    // version is 1-based from the CLI; the selector index is 0-based.
    let version_selector = if let Some(v) = version {
        VersionSelector::Index(v.saturating_sub(1) as usize)
    } else if let Some(ref d) = date {
        match parse_iso_date(d) {
            Some(ts) => VersionSelector::BeforeDate(ts),
            None => {
                return CliResponse::RestoreRejected(RestoreRejection::InvalidDate {
                    date: d.clone(),
                });
            }
        }
    } else {
        VersionSelector::Latest
    };

    // A range scan of the catalog (A12): cheap enough for the request path.
    let records = match crate::daemon::restore::resolve_path(&state.db, &path) {
        Ok(r) => r,
        Err(e) => return CliResponse::Error(format!("db error resolving {path}: {e}")),
    };
    if records.is_empty() {
        return CliResponse::RestoreRejected(RestoreRejection::NotInCatalog { path });
    }
    // `--version 0` names nothing (versions are 1-based), not version 1.
    let selectable = version != Some(0)
        && records
            .iter()
            .any(|r| RestoreCoordinator::select_version(r, &version_selector).is_some());
    if !selectable {
        let available = backed_up_version_numbers(&records);
        return CliResponse::RestoreRejected(match version {
            Some(version) if !available.is_empty() => RestoreRejection::VersionNotFound {
                path,
                version,
                available,
            },
            _ => RestoreRejection::NotBackedUp { path },
        });
    }

    let job_id = JobId::new();
    let job = state
        .restore_jobs
        .submit(job_id, &path, records.len() as u32);
    let request = RestoreRequest {
        path,
        version_selector,
        job_id,
    };
    match state.restore_tx.try_send(request) {
        Ok(()) => CliResponse::RestoreJob(job),
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            state.restore_jobs.remove(job_id);
            CliResponse::RestoreRejected(RestoreRejection::Busy {
                active: state.restore_jobs.active_count(),
            })
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            state.restore_jobs.remove(job_id);
            CliResponse::RestoreRejected(RestoreRejection::Unavailable)
        }
    }
}

/// The 1-based version numbers backed up in any of `records`, ascending.
fn backed_up_version_numbers(records: &[FileRecord]) -> Vec<u32> {
    let numbers: std::collections::BTreeSet<u32> = records
        .iter()
        .flat_map(|r| {
            r.versions
                .iter()
                .enumerate()
                .filter(|(_, v)| v.backed_up_at.is_some())
                .map(|(i, _)| i as u32 + 1)
        })
        .collect();
    numbers.into_iter().collect()
}

/// One restore job by id: from memory, else from its job dir (never "unknown" for
/// an existing job dir, restore-i14).
async fn dispatch_restore_job(state: &DaemonState, job_id: &str) -> CliResponse {
    let unknown = || {
        CliResponse::RestoreRejected(RestoreRejection::UnknownJob {
            job_id: job_id.to_string(),
        })
    };
    let Some(id) = JobId::parse(job_id) else {
        return unknown();
    };
    // The disk fallback may walk a job dir: off the async workers.
    let jobs = state.restore_jobs.clone();
    match tokio::task::spawn_blocking(move || jobs.get(id)).await {
        Ok(Some(job)) => CliResponse::RestoreJob(job),
        Ok(None) => unknown(),
        Err(e) => CliResponse::Error(format!("restore job lookup failed: {e}")),
    }
}

// ── Device list ───────────────────────────────────────────────────────────────

fn dispatch_device_list(state: &DaemonState) -> CliResponse {
    let cluster = match &state.cluster_state {
        Some(c) => c,
        None => return CliResponse::DeviceList(vec![]),
    };

    let cs = cluster.lock().expect("cluster_state lock poisoned");
    let revoked: std::collections::HashSet<viaticum_core::types::DeviceId> = cs
        .all_devices()
        .iter()
        .filter(|d| cs.is_device_revoked(&d.device_id))
        .map(|d| d.device_id)
        .collect();

    let entries: Vec<DeviceEntry> = cs
        .all_devices()
        .iter()
        .map(|d| {
            let device_id_hex = hex_encode(&d.device_id.0);
            let is_current = d.device_id == state.device_id;
            let added_at = timestamp_to_iso_date(d.certificate.issued_at);
            let is_revoked = revoked.contains(&d.device_id);
            DeviceEntry {
                device_id_hex,
                label: format!("device-{}", d.device_index),
                is_current,
                added_at,
                revoked: is_revoked,
            }
        })
        .collect();

    CliResponse::DeviceList(entries)
}

// ── Device add ────────────────────────────────────────────────────────────────

fn dispatch_device_add(state: &DaemonState, label: String) -> CliResponse {
    use viaticum_core::cluster::{derive_device_key, issue_device_certificate};
    use viaticum_core::types::DeviceId;

    let cluster_state = match &state.cluster_state {
        Some(cs) => cs,
        None => return CliResponse::Error("cluster state not initialized".to_string()),
    };

    // Derive a deterministic device_seed from identity + label (blake3 → 32 bytes).
    let device_seed: [u8; 32] = {
        let mut h = blake3::Hasher::new();
        h.update(&state.identity_pub.0);
        h.update(label.as_bytes());
        h.finalize().into()
    };

    // Derive the new device's signing key; device_id.0 = verifying_key().to_bytes()
    let device_key = match derive_device_key(&state.seed, &device_seed) {
        Ok(k) => k,
        Err(e) => return CliResponse::Error(format!("key derivation failed: {e}")),
    };
    let device_id = DeviceId(device_key.verifying_key().to_bytes());

    let now = Timestamp::now();
    let cert = issue_device_certificate(&state.master_key, device_id, now);

    // Register in ClusterState.
    let mut cs = cluster_state.lock().expect("cluster_state lock");
    if let Err(e) = cs.add_device(cert, now) {
        return CliResponse::Error(format!("device registration failed: {e}"));
    }
    drop(cs);

    tracing::info!(
        label = %label,
        device_id = %hex_encode(&device_id.0),
        "device registered"
    );

    let added_at = timestamp_to_iso_date(now);
    CliResponse::DeviceAdded(DeviceEntry {
        device_id_hex: hex_encode(&device_id.0),
        label,
        is_current: false,
        added_at,
        revoked: false,
    })
}

// ── Device revoke ─────────────────────────────────────────────────────────────

async fn dispatch_device_revoke(state: &DaemonState, device_id_hex: String) -> CliResponse {
    use viaticum_core::cluster::{EpochCounter, issue_revocation};
    use viaticum_core::messages::to_cbor;
    use viaticum_core::types::DeviceId;

    use crate::daemon::cluster_sync::ClusterSyncManager;

    let cluster_state = match &state.cluster_state {
        Some(cs) => cs,
        None => return CliResponse::Error("cluster state not initialized".to_string()),
    };

    // Parse hex device_id (32 bytes = 64 hex chars).
    if device_id_hex.len() != 64 {
        return CliResponse::Error(format!(
            "device_id must be 64 hex chars (32 bytes), got {}",
            device_id_hex.len()
        ));
    }
    let mut device_id_bytes = [0u8; 32];
    for (i, chunk) in device_id_hex.as_bytes().chunks(2).enumerate() {
        let hi = match chunk[0] {
            b'0'..=b'9' => chunk[0] - b'0',
            b'a'..=b'f' => chunk[0] - b'a' + 10,
            _ => {
                return CliResponse::Error(format!(
                    "invalid hex char in device_id: {}",
                    chunk[0] as char
                ));
            }
        };
        let lo = match chunk[1] {
            b'0'..=b'9' => chunk[1] - b'0',
            b'a'..=b'f' => chunk[1] - b'a' + 10,
            _ => {
                return CliResponse::Error(format!(
                    "invalid hex char in device_id: {}",
                    chunk[1] as char
                ));
            }
        };
        device_id_bytes[i] = (hi << 4) | lo;
    }
    let device_id = DeviceId(device_id_bytes);

    // Prevent revoking our own device.
    if device_id == state.device_id {
        return CliResponse::Error("cannot revoke the current device".to_string());
    }

    // Lock scope: extract data and revoke. Drop guard before any await.
    let (revocation, device_cert, new_epoch) = {
        let mut cs = cluster_state.lock().expect("cluster_state lock");
        let new_epoch = EpochCounter(cs.current_epoch().0 + 1);
        let now = Timestamp::now();

        // Capture the device certificate before revoking (needed for broadcast).
        let device_cert = cs.get_device(&device_id).map(|e| e.certificate.clone());

        let revocation = issue_revocation(&state.master_key, device_id, now, new_epoch);
        if let Err(e) = cs.revoke_device(revocation.clone(), now, now) {
            return CliResponse::Error(format!("revocation failed: {e}"));
        }
        // Guard dropped here — no MutexGuard crosses the await boundary below.
        (revocation, device_cert, new_epoch)
    };

    tracing::info!(
        device_id = %device_id_hex,
        new_epoch = new_epoch.0,
        "device revoked, epoch rotated"
    );

    // T-13b-2: Publish directed Revocation entries to storage-relationship peers only.
    //
    // Target-master set = { get_master_for_device(p.holder_id) ∀ our placements }
    //                   ∪ { h.owner_id ∀ our holdings }
    // deduplicated, excluding our own master (cluster siblings learn via cluster_sync epoch path).
    if let (Some(cert), Some(mailbox_router)) = (device_cert, state.mailbox_router.as_ref()) {
        let broadcast = ClusterSyncManager::build_revocation_broadcast(&revocation, &cert);
        match to_cbor(&broadcast) {
            Ok(payload) => {
                // Build storage-relationship target-master set.
                use std::collections::HashSet;
                use viaticum_core::mailbox::{MailboxAddress, MailboxClass, MailboxEntry};
                use viaticum_core::types::IdentityPub;

                let my_master: IdentityPub =
                    IdentityPub(state.master_key.verifying_key().to_bytes());

                let mut target_masters: HashSet<IdentityPub> = HashSet::new();

                // (1) Holders of our data: placements → holder_id → holder master.
                match state.db.list_all_placements() {
                    Ok(placements) => {
                        for placement in &placements {
                            match state.db.get_master_for_device(&placement.holder_id) {
                                Ok(Some(master)) => {
                                    if master != my_master {
                                        target_masters.insert(master);
                                    }
                                }
                                Ok(None) => {
                                    tracing::debug!(
                                        holder = %placement.holder_id,
                                        "dispatch_device_revoke: no master for holder device, skipping"
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        holder = %placement.holder_id,
                                        err = %e,
                                        "dispatch_device_revoke: db error resolving holder master"
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            err = %e,
                            "dispatch_device_revoke: list_all_placements failed, skipping holder targets"
                        );
                    }
                }

                // (2) Owners we hold for: holdings → owner_id (already a master IdentityPub).
                match state.db.list_all_holdings() {
                    Ok(holdings) => {
                        for holding in &holdings {
                            if holding.owner_id != my_master {
                                target_masters.insert(holding.owner_id);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            err = %e,
                            "dispatch_device_revoke: list_all_holdings failed, skipping owner targets"
                        );
                    }
                }

                let target_count = target_masters.len();
                if target_count == 0 {
                    tracing::info!(
                        device_id = %device_id_hex,
                        "dispatch_device_revoke: no storage-relationship peers — revocation not published (no targets)"
                    );
                } else {
                    tracing::info!(
                        device_id = %device_id_hex,
                        target_masters = target_count,
                        "dispatch_device_revoke: publishing directed revocation to storage-relationship peers"
                    );

                    let ttl_secs = viaticum_core::mailbox::scaled_ttl_secs(
                        viaticum_core::mailbox::class_config::REVOCATION_TTL.as_secs(),
                        state.time_scale,
                    );
                    let now_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let mut total_acks: usize = 0;
                    let mut zero_ack_targets: usize = 0;

                    for target_master in &target_masters {
                        let msg_id: [u8; 16] = rand::random();
                        let entry = MailboxEntry {
                            target: MailboxAddress::for_master(target_master),
                            msg_id,
                            class: MailboxClass::Revocation,
                            payload_version: 1,
                            payload: payload.clone(),
                            expires_at: now_secs + ttl_secs,
                            stored_at: now_secs,
                            sender: Some(my_master),
                        };
                        match mailbox_router.publish(entry, None).await {
                            Ok(0) => {
                                zero_ack_targets += 1;
                                tracing::warn!(
                                    device_id = %device_id_hex,
                                    target = %target_master,
                                    "dispatch_device_revoke: 0 acks for revocation target (best-effort)"
                                );
                            }
                            Ok(acks) => {
                                total_acks += acks;
                            }
                            Err(e) => {
                                zero_ack_targets += 1;
                                tracing::warn!(
                                    device_id = %device_id_hex,
                                    target = %target_master,
                                    err = %e,
                                    "dispatch_device_revoke: revocation publish failed for target"
                                );
                            }
                        }
                    }

                    tracing::info!(
                        device_id = %device_id_hex,
                        targets = target_count,
                        total_acks,
                        zero_ack_targets,
                        "dispatch_device_revoke: directed revocation publish complete (best-effort)"
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    device_id = %device_id_hex,
                    err = %e,
                    "dispatch_device_revoke: failed to CBOR-encode RevocationBroadcast"
                );
            }
        }
    }

    CliResponse::DeviceRevoked { device_id_hex }
}

// ── Connect ───────────────────────────────────────────────────────────────────

async fn dispatch_connect(state: &DaemonState, addr: String) -> CliResponse {
    // addr is a libp2p Multiaddr string, e.g.:
    //   /ip4/1.2.3.4/tcp/4001/p2p/12D3KooW...
    let multiaddr: libp2p::Multiaddr = match addr.parse() {
        Ok(ma) => ma,
        Err(e) => {
            return CliResponse::Error(format!("invalid multiaddr '{addr}': {e}"));
        }
    };

    let swarm = match state.swarm_handle.as_ref() {
        Some(s) => s,
        None => return CliResponse::Error("swarm not available".to_string()),
    };

    // Extract PeerId from the /p2p/... component of the multiaddr.
    use libp2p::multiaddr::Protocol;
    let peer_id = multiaddr.iter().find_map(|p| {
        if let Protocol::P2p(peer_id) = p {
            Some(peer_id)
        } else {
            None
        }
    });

    let peer_id = match peer_id {
        Some(id) => id,
        None => {
            return CliResponse::Error(format!(
                "multiaddr '{addr}' has no /p2p component — cannot identify peer"
            ));
        }
    };

    if let Err(e) = swarm.dial(peer_id, multiaddr.clone()).await {
        tracing::warn!(addr = %addr, error = %e, "connect failed");
        return CliResponse::Error(format!("connect failed: {e}"));
    }

    tracing::info!(addr = %addr, "dial initiated — peer will be registered on connection");
    CliResponse::Connected {
        peer_id: peer_id.to_string(),
    }
}

// ============================================================
// Importance bucket aggregation
// ============================================================

/// Bucket definition: name, inclusive lower bound, exclusive upper bound, midpoint.
struct BucketDef {
    name: &'static str,
    lo: f64,
    hi: f64,
    midpoint: f64,
}

const BUCKET_DEFS: [BucketDef; 5] = [
    BucketDef {
        name: "critical",
        lo: 0.90,
        hi: f64::INFINITY,
        midpoint: 0.95,
    },
    BucketDef {
        name: "high",
        lo: 0.70,
        hi: 0.90,
        midpoint: 0.80,
    },
    BucketDef {
        name: "medium",
        lo: 0.40,
        hi: 0.70,
        midpoint: 0.55,
    },
    BucketDef {
        name: "low",
        lo: 0.10,
        hi: 0.40,
        midpoint: 0.25,
    },
    BucketDef {
        name: "trivial",
        lo: f64::NEG_INFINITY,
        hi: 0.10,
        midpoint: 0.05,
    },
];

/// Compute per-importance-bucket reliability aggregates over all Active source blocks.
///
/// Returns exactly 5 entries in order: critical, high, medium, low, trivial.
/// If a bucket has zero blocks, returns that bucket with block_count=0 and status="empty".
///
/// Receives the already-loaded source_blocks slice from dispatch_status — no second DB call.
pub(crate) fn compute_importance_buckets(
    source_blocks: &[viaticum_core::types::SourceBlockRecord],
) -> Vec<viaticum_core::types::ImportanceBucketStats> {
    use viaticum_core::reliability::{meets_target, target_reliability};
    use viaticum_core::types::{ImportanceBucketStats, SourceBlockStatus};

    // Accumulators: (count, sum_of_current_reliability)
    let mut accum: [(u32, f64); 5] = [(0, 0.0); 5];

    for block in source_blocks {
        if block.status != SourceBlockStatus::Active {
            continue;
        }
        let imp = block.importance;
        // Assign to the FIRST matching bucket (critical first, trivial last).
        // Boundary rules: >= lo (inclusive) AND < hi (exclusive).
        for (i, def) in BUCKET_DEFS.iter().enumerate() {
            if imp >= def.lo && imp < def.hi {
                accum[i].0 += 1;
                accum[i].1 += block.current_reliability;
                break;
            }
        }
    }

    BUCKET_DEFS
        .iter()
        .enumerate()
        .map(|(i, def)| {
            let target_p = target_reliability(def.midpoint);
            let (count, sum) = accum[i];
            if count == 0 {
                ImportanceBucketStats {
                    bucket: def.name.to_string(),
                    block_count: 0,
                    mean_p_recoverable: 0.0,
                    target_p,
                    status: "empty".to_string(),
                }
            } else {
                let mean = sum / count as f64;
                ImportanceBucketStats {
                    bucket: def.name.to_string(),
                    block_count: count,
                    mean_p_recoverable: mean,
                    target_p,
                    status: if meets_target(mean, target_p) {
                        "healthy".to_string()
                    } else {
                        "degraded".to_string()
                    },
                }
            }
        })
        .collect()
}

// ============================================================
// Formatting helpers
// ============================================================

/// First 8 bytes as lowercase hex (16 chars). Used for peer identity display.
fn bytes_to_hex_8(bytes: &[u8]) -> String {
    hex_encode(&bytes[..8.min(bytes.len())])
}

/// Unix timestamp → "YYYY-MM-DD HH:MM:SS" (UTC, approximate).
fn timestamp_to_iso(ts: Timestamp) -> String {
    unix_secs_to_iso(ts.0, true)
}

/// Unix timestamp → "YYYY-MM-DD" (UTC, date only).
fn timestamp_to_iso_date(ts: Timestamp) -> String {
    unix_secs_to_iso(ts.0, false)
}

/// Minimal ISO-8601-ish formatter without chrono dependency.
/// Computes year/month/day/hour/min/sec from a Unix timestamp using
/// the proleptic Gregorian calendar.
pub(crate) fn unix_secs_to_iso(secs: u64, include_time: bool) -> String {
    // Days since epoch.
    let days = (secs / 86400) as u32;
    let time_secs = secs % 86400;

    // Gregorian calendar calculation (civil date from days since 1970-01-01).
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html (civil_from_days).
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    if include_time {
        let h = time_secs / 3600;
        let min = (time_secs % 3600) / 60;
        let sec = time_secs % 60;
        // RFC 3339 with explicit UTC marker so JS Date / chrono parse cleanly.
        format!("{y:04}-{m:02}-{d:02}T{h:02}:{min:02}:{sec:02}Z")
    } else {
        format!("{y:04}-{m:02}-{d:02}")
    }
}

/// Parse "YYYY-MM-DD" to a Timestamp (start of day UTC). Returns None on parse error.
fn parse_iso_date(s: &str) -> Option<Timestamp> {
    let parts: Vec<&str> = s.splitn(3, '-').collect();
    if parts.len() != 3 {
        return None;
    }
    let year: u64 = parts[0].parse().ok()?;
    let month: u64 = parts[1].parse().ok()?;
    let day: u64 = parts[2].parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Days from 1970-01-01 to year-month-day.
    // Algorithm: days_from_civil from Hinnant.
    let y = if month <= 2 {
        year as i64 - 1
    } else {
        year as i64
    };
    let m = month as i64;
    let d = day as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    if days < 0 {
        return None;
    }
    Some(Timestamp(days as u64 * 86400))
}
