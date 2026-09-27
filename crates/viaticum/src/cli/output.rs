use crate::cli::types::{
    DeviceEntry, FileEntry, RestoreFailureKind, RestoreJob, RestoreJobState, RestoreOutcome,
    RestoreRejection, StatusData, VersionEntry,
};

/// Format bytes as human-readable size string.
/// < 1 KB  → "N B"
/// < 1 MB  → "N KB"  (integer)
/// < 1 GB  → "N.N MB" (one decimal)
/// >= 1 GB → "N.NN GB" (two decimals)
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1_024;
    const MB: u64 = 1_048_576;
    const GB: u64 = 1_073_741_824;
    if bytes < KB {
        format!("{bytes} B")
    } else if bytes < MB {
        format!("{} KB", bytes / KB)
    } else if bytes < GB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    }
}

/// Render StatusData to a String.
pub fn render_status(data: &StatusData) -> String {
    let mut out = String::new();
    out.push_str("viaticum status\n");
    out.push_str(&format!("  identity:       {}\n", data.node_identity));
    if !data.node_addr.is_empty() {
        out.push_str(&format!("  addr:           {}\n", data.node_addr));
    }
    out.push_str(&format!(
        "  peers:          {}  (avg trust: {:.2})\n",
        data.peer_count, data.avg_trust
    ));
    out.push_str(&format!(
        "  holding:        {} for {} peers\n",
        format_bytes(data.holding_bytes),
        data.peer_count
    ));
    out.push_str(&format!(
        "  backed up:      {} files, {}\n",
        data.backed_up_files,
        format_bytes(data.backed_up_bytes)
    ));
    out.push_str(&format!(
        "  repair needed:  {} blocks\n",
        data.blocks_needing_repair
    ));
    out.push_str(&render_dr_readiness(data));
    let quota_str = if data.effective_quota_bytes == 0 {
        "unlimited".to_string()
    } else {
        format_bytes(data.effective_quota_bytes)
    };
    out.push_str(&format!(
        "  quota:          {}  (used: {})\n",
        quota_str,
        format_bytes(data.used_bytes)
    ));
    // restore-i8: restored files stay until the user moves them out.
    let staging_size = match data.restore_staging_bytes {
        Some(b) => format_bytes(b),
        None => "size still counting".to_string(),
    };
    if data.restore_staging_jobs > 0 {
        out.push_str(&format!(
            "  restore staging: {} job dir(s), {} in {} — move files out, then delete the directories\n",
            data.restore_staging_jobs, staging_size, data.restore_staging_path
        ));
    }
    // restore-i18
    if data.restore_staging_squeezes_holdings {
        out.push_str(&format!(
            "  WARNING: restore staging {staging_size} is taking space from your friends' data; move files out and delete it\n"
        ));
    }
    // restore-i19
    if data.restore_publish == "unavailable" {
        out.push_str(
            "  ERROR: restore cannot write files into staging on this filesystem (see the daemon log)\n",
        );
    }
    if data.peer_count == 0 {
        out.push_str("  no peers yet\n");
        out.push_str("  WARNING: backup requires >= 2 peers for erasure coding\n");
    } else if data.peer_count == 1 {
        out.push_str("  WARNING: only 1 peer, backup requires >= 2 for erasure coding\n");
        out.push('\n');
        out.push_str("top peers:\n");
        for peer in &data.peers {
            let short_id = if peer.identity_hex.len() >= 8 {
                &peer.identity_hex[..8]
            } else {
                &peer.identity_hex
            };
            out.push_str(&format!(
                "  {}  trust={:.2}  stores={}/{} last={}\n",
                short_id,
                peer.trust,
                format_bytes(peer.bytes_we_store),
                format_bytes(peer.bytes_peer_stores),
                peer.last_seen
            ));
        }
    } else {
        out.push('\n');
        out.push_str("top peers:\n");
        for peer in &data.peers {
            let short_id = if peer.identity_hex.len() >= 8 {
                &peer.identity_hex[..8]
            } else {
                &peer.identity_hex
            };
            out.push_str(&format!(
                "  {}  trust={:.2}  stores={}/{} last={}\n",
                short_id,
                peer.trust,
                format_bytes(peer.bytes_we_store),
                format_bytes(peer.bytes_peer_stores),
                peer.last_seen
            ));
        }
    }
    out
}

/// The DR readiness (dr-i9) and missing-source (dr-i11) lines of `status`.
pub fn render_dr_readiness(data: &StatusData) -> String {
    let mut out = String::new();
    if data.dr_pointer_published_at > 0 {
        out.push_str(&format!(
            "  DR:             ready: recovery pointer published {}, {} files, accepted by {} peer(s)\n",
            crate::daemon::dispatch::unix_secs_to_iso(data.dr_pointer_published_at, true),
            data.dr_pointer_files,
            data.dr_pointer_acks
        ));
    } else {
        out.push_str(
            "  DR:             NOT READY: this node has not published its recovery pointer yet \
             (first one ~12 h after install)\n",
        );
    }
    if data.files_without_source > 0 {
        out.push_str(&format!(
            "  files without local source: {} (not re-protected until they are back at their \
             original paths)\n",
            data.files_without_source
        ));
    }
    out
}

/// Format and print StatusData to stdout.
pub fn format_status(data: &StatusData) {
    print!("{}", render_status(data));
}

// ─── restore (restore-i3, i4, i15) ───────────────────────────────────────────

/// Right after the daemon accepted the job (printed before any waiting).
pub fn render_restore_submitted(job: &RestoreJob) -> String {
    let mut out = format!(
        "restore job {} submitted: {} file(s) under {}\n",
        job.job_id, job.files_total, job.path
    );
    out.push_str(&format!("  staging: {}\n", job.staging_path));
    out.push_str(
        "  This is a cold backup: restore can take hours. Ctrl-C stops watching, not the restore.\n",
    );
    out.push_str(&format!(
        "  Check later with: viaticum restore --status {}\n",
        job.job_id
    ));
    out
}

/// A progress line while the job is queued or running.
pub fn render_restore_progress(job: &RestoreJob) -> String {
    match job.state {
        RestoreJobState::Queued => format!(
            "queued: waiting for an earlier restore job to finish ({} file(s))\n",
            job.files_total
        ),
        _ => {
            let mut line = format!(
                "running: {}/{} restored, {} failed",
                job.files_restored,
                job.files_total,
                job.failures.len()
            );
            // restore-i26: no holder answered; redialed, retried at this time.
            if let Some(until) = &job.waiting_for_holders_until {
                line.push_str(&format!(
                    "; no holder answered, reconnecting, retry at {until}"
                ));
            }
            line.push('\n');
            line
        }
    }
}

/// Why a file was not restored, in words.
pub fn restore_failure_reason(kind: RestoreFailureKind) -> &'static str {
    match kind {
        RestoreFailureKind::HoldersUnavailable => "not enough holders answered; retry later",
        RestoreFailureKind::NotBackedUp => "no backed-up version",
        RestoreFailureKind::BlockMissing => "its block record is missing from the catalog",
        RestoreFailureKind::Corrupt => "the data did not decode",
        RestoreFailureKind::PathUnsafe => "unsafe path in the catalog",
        RestoreFailureKind::WriteFailed => "could not write it into staging",
        RestoreFailureKind::Interrupted => "the daemon stopped before it was restored",
        RestoreFailureKind::Internal => "internal error",
    }
}

/// The final report of a finished job. Never says "started": the job is over.
pub fn render_restore_finished(job: &RestoreJob) -> String {
    let (restored, total) = (job.files_restored, job.files_total);
    let mut out = match job.outcome {
        Some(RestoreOutcome::Complete) => {
            format!("restore complete: {restored} of {total} file(s) restored\n")
        }
        Some(RestoreOutcome::Partial) => {
            format!("restore partial: {restored} of {total} file(s) restored\n")
        }
        Some(RestoreOutcome::NothingRestored) => {
            format!("restore failed: nothing restored (0 of {total} file(s))\n")
        }
        Some(RestoreOutcome::Interrupted) => format!(
            "restore interrupted: the daemon stopped before the job finished; {restored} of {total} file(s) restored\n"
        ),
        None => format!("restore job state unknown: {restored} of {total} file(s) restored\n"),
    };
    out.push_str(&format!("  staging: {}\n", job.staging_path));
    if !job.failures.is_empty() {
        out.push_str(&format!("  not restored ({}):\n", job.failures.len()));
        for f in &job.failures {
            out.push_str(&format!(
                "    {} — {} ({})\n",
                f.path,
                restore_failure_reason(f.kind),
                f.detail
            ));
        }
    }
    let retry = job.failures.iter().any(|f| {
        matches!(
            f.kind,
            RestoreFailureKind::HoldersUnavailable | RestoreFailureKind::Interrupted
        )
    });
    if retry {
        out.push_str(&format!(
            "  Retry: viaticum restore {}   (restored files are downloaded again)\n",
            job.path
        ));
    }
    if restored > 0 {
        out.push_str(
            "  The files are in staging and NOT protected there. Move them into a watched folder \
             (the original one or any other) within ~4 weeks of the deletion to protect them again.\n",
        );
    }
    out
}

/// A refused request (nothing was started) or an unknown job id.
pub fn render_restore_rejection(r: &RestoreRejection) -> String {
    let line = match r {
        RestoreRejection::NotInCatalog { path } => {
            format!("{path} is not in the backup catalog (no file there and none under it)")
        }
        RestoreRejection::NotBackedUp { path } => {
            format!("nothing under {path} has a backed-up version yet")
        }
        RestoreRejection::VersionNotFound {
            path,
            version,
            available,
        } => {
            let list: Vec<String> = available.iter().map(u32::to_string).collect();
            format!(
                "version {version} not found for {path} (available: {})",
                list.join(", ")
            )
        }
        RestoreRejection::DestNotSupported => {
            "--dest is not supported: restored files go to the staging directory".to_string()
        }
        RestoreRejection::InvalidDate { date } => {
            format!("invalid date {date} (expected YYYY-MM-DD)")
        }
        RestoreRejection::Busy { active } => {
            format!(
                "the restore queue is full ({active} job(s) queued or running); try again later"
            )
        }
        RestoreRejection::Unavailable => {
            "the daemon is not taking restore jobs (shutting down?)".to_string()
        }
        RestoreRejection::UnknownJob { job_id } => format!(
            "unknown restore job {job_id} (its staging directory does not exist, or the id is wrong)"
        ),
    };
    format!("restore: {line}\n")
}

/// `viaticum restore --status`: recent jobs, newest first.
pub fn render_restore_jobs(jobs: &[RestoreJob]) -> String {
    if jobs.is_empty() {
        return "no restore jobs\n".to_string();
    }
    let mut out = format!("restore jobs ({}), newest first:\n", jobs.len());
    for j in jobs {
        let state = match (j.state, j.outcome) {
            (RestoreJobState::Finished, Some(o)) => o.as_str(),
            (RestoreJobState::Queued, _) => "queued",
            (RestoreJobState::Running, _) => "running",
            (RestoreJobState::Finished, None) => "finished",
        };
        out.push_str(&format!(
            "  {}  {:<16} {}/{}  {}\n",
            j.job_id, state, j.files_restored, j.files_total, j.path
        ));
    }
    out
}

/// The CLI could not reach the daemon for too long, or the daemon no longer knows
/// the job.
pub fn render_restore_lost_contact(job_id: &str, staging_path: &str) -> String {
    format!(
        "restore: lost contact with the daemon; the restore may have been interrupted. \
         Files restored so far: {staging_path}. Check `viaticum restore --status {job_id}` \
         after the daemon is back, or run the restore again.\n"
    )
}

/// Render a list of DeviceEntry to a String.
pub fn render_device_list(devices: &[DeviceEntry]) -> String {
    let mut out = String::new();
    out.push_str(&format!("cluster devices ({}):\n", devices.len()));
    for device in devices {
        let marker = if device.revoked {
            "[R]"
        } else if device.is_current {
            "[*]"
        } else {
            "   "
        };
        let short_id = if device.device_id_hex.len() >= 16 {
            &device.device_id_hex[..16]
        } else {
            &device.device_id_hex
        };
        out.push_str(&format!(
            "  {} {}  {}  added {}\n",
            marker, short_id, device.label, device.added_at
        ));
    }
    out
}

/// Format and print a list of DeviceEntry to stdout.
pub fn format_device_list(devices: &[DeviceEntry]) {
    print!("{}", render_device_list(devices));
}

/// Render a newly-added DeviceEntry to a String.
pub fn render_device_added(device: &DeviceEntry) -> String {
    let mut out = String::new();
    out.push_str("device added\n");
    let id_display = if device.device_id_hex.len() > 16 {
        format!("{}...", &device.device_id_hex[..16])
    } else {
        device.device_id_hex.clone()
    };
    out.push_str(&format!("  id:    {}\n", id_display));
    out.push_str(&format!("  label: {}\n", device.label));
    out
}

/// Format and print a newly-added DeviceEntry to stdout.
pub fn format_device_added(device: &DeviceEntry) {
    print!("{}", render_device_added(device));
}

/// Render a device revocation confirmation to a String.
pub fn render_device_revoked(device_id_hex: &str) -> String {
    let short = if device_id_hex.len() > 16 {
        format!("{}...", &device_id_hex[..16])
    } else {
        device_id_hex.to_string()
    };
    format!("device revoked: {short}\n")
}

/// Format and print a device revocation confirmation to stdout.
pub fn format_device_revoked(device_id_hex: &str) {
    print!("{}", render_device_revoked(device_id_hex));
}

/// Render a list of FileEntry to a String.
pub fn render_files(files: &[FileEntry]) -> String {
    let mut out = String::new();
    if files.is_empty() {
        out.push_str("no files backed up\n");
        return out;
    }
    out.push_str(&format!("backed-up files ({}):\n", files.len()));
    for file in files {
        let version_label = if file.versions == 1 {
            "1 version".to_string()
        } else {
            format!("{} versions", file.versions)
        };
        out.push_str(&format!(
            "  {}   {}   {}   {}   {}\n",
            file.path,
            version_label,
            file.last_backed_up,
            format_bytes(file.size_bytes),
            file.local_state
        ));
    }
    out
}

/// Format and print a list of FileEntry to stdout.
pub fn format_files(files: &[FileEntry]) {
    print!("{}", render_files(files));
}

/// Render a list of VersionEntry for one path to a String.
pub fn render_versions(path: &str, versions: &[VersionEntry]) -> String {
    let mut out = String::new();
    if versions.is_empty() {
        out.push_str(&format!("no versions found for {path}\n"));
        return out;
    }
    out.push_str(&format!("versions of {} ({}):\n", path, versions.len()));
    for entry in versions {
        let hash_short = if entry.content_hash_hex.len() > 8 {
            format!("{}...", &entry.content_hash_hex[..8])
        } else {
            entry.content_hash_hex.clone()
        };
        let block_short = if entry.source_block_id_hex.len() >= 8 {
            entry.source_block_id_hex[..8].to_string()
        } else {
            entry.source_block_id_hex.clone()
        };
        out.push_str(&format!(
            "  v{}  {}  backed {}  {}  {}  [block: {}]\n",
            entry.version,
            entry.created_at,
            entry.backed_up_at,
            hash_short,
            format_bytes(entry.size_bytes),
            block_short
        ));
    }
    out
}

/// Format and print a list of VersionEntry for one path to stdout.
pub fn format_versions(path: &str, versions: &[VersionEntry]) {
    print!("{}", render_versions(path, versions));
}

/// Render a Connect success response to a String.
pub fn render_connected(peer_id: &str) -> String {
    let short = if peer_id.len() > 16 {
        format!("{}...", &peer_id[..16])
    } else {
        peer_id.to_string()
    };
    format!("connected to peer: {short}\n")
}

/// Format and print a Connect success response to stdout.
pub fn format_connected(peer_id: &str) {
    print!("{}", render_connected(peer_id));
}

/// Render a daemon error message to a String.
pub fn render_error(msg: &str) -> String {
    format!("error: {msg}\n")
}

/// Format and print a daemon error message to stderr.
pub fn format_error(msg: &str) {
    eprint!("{}", render_error(msg));
}
