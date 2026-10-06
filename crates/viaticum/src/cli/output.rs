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
    if !data.daemon_version.is_empty() {
        out.push_str(&format!("  version:        {}\n", data.daemon_version));
    }
    out.push_str(&format!("  identity:       {}\n", data.node_identity));
    if !data.node_addr.is_empty() {
        // The mark goes before the address: the address stays the last thing on
        // the line, so copying the line's tail gives a `connect` argument.
        let label = if data.node_addr_lan_only {
            "addr (LAN only):"
        } else {
            "addr:"
        };
        out.push_str(&format!("  {label:<15} {}\n", data.node_addr));
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
    // repair-i8 ceiling: shown only when it happens.
    if data.blocks_esi_exhausted > 0 {
        out.push_str(&format!(
            "  not repairable: {} blocks (ESI numbers used up)\n",
            data.blocks_esi_exhausted
        ));
    }
    // backup-i4
    if data.max_file_size_bytes > 0 {
        out.push_str(&format!(
            "  size limit:     {} per file on this machine\n",
            format_bytes(data.max_file_size_bytes)
        ));
    }
    if data.files_too_large > 0 {
        out.push_str(&format!(
            "  too large:      {} file(s) above the limit: not supported yet, not backed up\n",
            data.files_too_large
        ));
    }
    // К-b3 (spec v3.9a): a `viaticum dr` on this machine borrows this node's memory.
    if let Some(lease) = &data.dr_lease {
        out.push_str(&format!(
            "  dr_lease:       {}holds_mib={} age_s={}\n",
            if lease.revoked { "revoked " } else { "" },
            lease.holds_mib,
            lease.age_s
        ));
    }
    // Q-V9 (a): the node's memory goes to the restore first.
    if data.backup_paused_while_restoring {
        out.push_str("  backup:         paused while restoring\n");
    }
    if data.backup_pause_overlong {
        out.push_str(&format!(
            "  backup:         paused for over {} h: a restore job may be stuck\n",
            crate::daemon::work_pipeline::BACKUP_PAUSE_WARN_AFTER.as_secs() / 3600
        ));
    }
    out.push_str(&render_dr_readiness(data));
    // holder-i1/i2: 0 is "no room", never "unlimited"; an unread disk says so.
    let quota_str = match data.quota_state.as_str() {
        "unknown" => "unknown".to_string(),
        _ if data.effective_quota_bytes == 0 => {
            "0 B — free disk at or below the reserve: not taking friends' data, giving space back"
                .to_string()
        }
        _ => format_bytes(data.effective_quota_bytes),
    };
    out.push_str(&format!(
        "  quota:          {}  (used: {})\n",
        quota_str,
        format_bytes(data.used_bytes)
    ));
    if !data.quota_note.is_empty() {
        out.push_str(&format!("  WARNING: {}\n", data.quota_note));
    }
    // holder-i4
    match data.below_reserve_giving_back_bytes {
        Some(0) => out
            .push_str("  disk below reserve: holding nothing for friends, not taking their data\n"),
        Some(b) => out.push_str(&format!(
            "  disk below reserve: giving back {} of friends' data\n",
            format_bytes(b)
        )),
        None => {}
    }
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

/// The DR readiness (dr-i9, dr-i39, dr-i41; mailbox-i49, i54) and missing-source
/// (dr-i11) lines of `status`.
pub fn render_dr_readiness(data: &StatusData) -> String {
    let iso = |t| crate::daemon::dispatch::unix_secs_to_iso(t, true);
    let mut out = String::new();
    if data.dr_pointer_published_at == 0 {
        out.push_str(
            "  DR:             NOT READY: this node has not published its recovery pointer yet \
             (first one ~12 h after install)\n",
        );
    } else if data.dr_ready {
        out.push_str(&format!(
            "  DR:             ready: recovery pointer published {}, {} files, accepted by {} of the {} \
             nodes DR will ask\n",
            iso(data.dr_pointer_published_at),
            data.dr_pointer_files,
            data.dr_pointer_acks,
            data.dr_pointer_near_set
        ));
        if data.dr_restores_state_of > 0 {
            out.push_str(&format!(
                "                  DR would restore the catalog as of {} or newer\n",
                iso(data.dr_restores_state_of)
            ));
        }
    } else {
        out.push_str(&format!(
            "  DR:             NOT READY: recovery pointer published {}, {} files, accepted by {} of \
             the {} nodes DR will ask ({} needed; held by {} in all)\n",
            iso(data.dr_pointer_published_at),
            data.dr_pointer_files,
            data.dr_pointer_acks,
            data.dr_pointer_near_set,
            data.dr_pointer_ack_threshold,
            data.dr_pointer_held
        ));
        if data.dr_ss_blocks_placed < data.dr_ss_blocks_total {
            out.push_str(&format!(
                "                  the catalog blocks are not stored at friends yet ({} of {}): \
                 friends have no room yet; a newcomer enters the network gradually\n",
                data.dr_ss_blocks_placed, data.dr_ss_blocks_total
            ));
        }
    }
    if !data.dr_pointer_refusal.is_empty() {
        out.push_str(&format!("  {}\n", data.dr_pointer_refusal));
    }
    if data.dr_waiting_since > 0 {
        out.push_str(&format!(
            "  DR: the newest catalog changes are not in the network yet (waiting since {}: {})\n",
            iso(data.dr_waiting_since),
            data.dr_waiting
        ));
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

/// A progress line while the job is queued or running. `now_unix` (seconds) turns a
/// wait for holders into "retry in …".
pub fn render_restore_progress(job: &RestoreJob, now_unix: u64) -> String {
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
            // restore-i26: holders did not answer; redialed, retried after a pause.
            if let Some(until) = &job.waiting_for_holders_until {
                line.push_str(&format!(
                    "; holders did not answer, reconnecting, {}",
                    retry_in(until, now_unix)
                ));
            }
            // restore-i39: a big block of this node holds the memory this one needs.
            if job.waiting_for_memory {
                line.push_str("; waiting for memory (another big block is being worked on)");
            }
            line.push('\n');
            line
        }
    }
}

/// "retry in 4 min" for an ISO-8601 UTC time (`YYYY-MM-DDTHH:MM:SSZ`) relative to
/// `now_unix`; "retry at <raw>" if it does not parse.
pub(crate) fn retry_in(until_iso: &str, now_unix: u64) -> String {
    let Some(until) = parse_iso_utc(until_iso) else {
        return format!("retry at {until_iso}");
    };
    let left = until.saturating_sub(now_unix);
    match left {
        0 => "retrying now".to_string(),
        1..60 => format!("retry in {left} s"),
        60..3600 => format!("retry in {} min", left.div_ceil(60)),
        _ => format!(
            "retry in {} h {} min",
            left / 3600,
            (left % 3600).div_ceil(60)
        ),
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` → Unix seconds (days_from_civil, Hinnant). `None` on
/// any other shape.
fn parse_iso_utc(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, min, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || h > 23 || min > 59 || sec > 60 {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + h * 3600 + min * 60 + sec).ok()
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
pub fn render_device_revoked(device_id_hex: &str, holders_skipped: u32) -> String {
    let short = if device_id_hex.len() > 16 {
        format!("{}...", &device_id_hex[..16])
    } else {
        device_id_hex.to_string()
    };
    let mut out = format!("device revoked: {short}\n");
    if holders_skipped > 0 {
        out.push_str(&format!(
            "revocation not sent to {holders_skipped} holder device(s): master unknown until they reconnect\n"
        ));
    }
    out
}

/// Format and print a device revocation confirmation to stdout.
pub fn format_device_revoked(device_id_hex: &str, holders_skipped: u32) {
    print!("{}", render_device_revoked(device_id_hex, holders_skipped));
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
        // backup-i4, backup-i7: a too-large file says so instead of a backup date; an earlier
        // version, if there is one, is named as kept but no longer checked; when the file
        // is deleted (the deletion window runs) the copies are being released instead.
        if let Some(tl) = &file.too_large {
            let limits = format!(
                "too large for this machine ({} > {}): not supported yet, not backed up",
                format_bytes(tl.size_bytes),
                format_bytes(tl.limit_bytes)
            );
            if file.last_backed_up == "never" {
                out.push_str(&format!("  {}   {}\n", file.path, limits));
            } else if file.local_state == "deleted" {
                out.push_str(&format!(
                    "  {}   {}   {}; deleted; its copies are released after the deletion window\n",
                    file.path, version_label, limits
                ));
            } else {
                out.push_str(&format!(
                    "  {}   {}   {}; the version of {} is kept in the network but no longer checked\n",
                    file.path, version_label, limits, file.last_backed_up
                ));
            }
            continue;
        }
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
