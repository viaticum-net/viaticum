use crate::cli::types::{
    DeviceEntry, FileEntry, RestoreBlocker, RestoreData, StatusData, VersionEntry,
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

/// Format and print StatusData to stdout.
pub fn format_status(data: &StatusData) {
    print!("{}", render_status(data));
}

/// Render RestoreData to a String.
pub fn render_restore(data: &RestoreData) -> String {
    let mut out = String::new();
    out.push_str("restore started\n");
    out.push_str(&format!("  path:     {}\n", data.path));
    out.push_str(&format!("  version:  {}\n", data.version_used));
    let hash_display = if data.content_hash_hex.len() > 16 {
        format!("{}...", &data.content_hash_hex[..16])
    } else {
        data.content_hash_hex.clone()
    };
    out.push_str(&format!("  hash:     {}\n", hash_display));
    out.push_str(&format!("  status:   {}\n", data.status));
    if !data.staging_path.is_empty() {
        out.push_str(&format!("  staging:  {}\n", data.staging_path));
    }
    out
}

/// Format and print RestoreData to stdout.
pub fn format_restore(data: &RestoreData) {
    print!("{}", render_restore(data));
}

/// Render a structured RestoreBlocker to stderr-suitable text.
pub fn format_restore_blocked(b: &RestoreBlocker) {
    eprintln!("restore blocked:");
    match b {
        RestoreBlocker::InsufficientPlacements {
            have,
            need,
            holders_offline,
        } => {
            eprintln!(
                "  reason: not enough live holders ({have}/{need} symbols, ~{holders_offline} offline)"
            );
            eprintln!("  hint:   wait for offline peers to come back, or trigger repair");
        }
        RestoreBlocker::AllHoldersOffline { last_seen_secs_ago } => {
            eprintln!("  reason: all holders offline (last seen {last_seen_secs_ago}s ago)");
        }
    }
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
