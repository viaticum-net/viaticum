use crate::cli::types::{
    DeviceEntry, FileEntry, RestoreData, StatusData, VersionEntry,
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

/// Format and print StatusData to stdout.
pub fn format_status(data: &StatusData) {
    println!("syncback status");
    println!("  identity:       {}", data.node_identity);
    println!(
        "  peers:          {}  (avg trust: {:.2})",
        data.peer_count, data.avg_trust
    );
    println!(
        "  holding:        {} for {} peers",
        format_bytes(data.holding_bytes),
        data.peer_count
    );
    println!(
        "  backed up:      {} files, {}",
        data.backed_up_files,
        format_bytes(data.backed_up_bytes)
    );
    println!("  repair needed:  {} blocks", data.blocks_needing_repair);

    let quota_str = if data.effective_quota_bytes == 0 {
        "unlimited".to_string()
    } else {
        format_bytes(data.effective_quota_bytes)
    };
    println!(
        "  quota:          {}  (used: {})",
        quota_str,
        format_bytes(data.used_bytes)
    );

    if data.peer_count == 0 {
        println!("  no peers yet");
    } else {
        println!();
        println!("top peers:");
        for peer in &data.peers {
            let short_id = if peer.identity_hex.len() >= 8 {
                &peer.identity_hex[..8]
            } else {
                &peer.identity_hex
            };
            println!(
                "  {}  trust={:.2}  stores={}/{} last={}",
                short_id,
                peer.trust,
                format_bytes(peer.bytes_we_store),
                format_bytes(peer.bytes_peer_stores),
                peer.last_seen
            );
        }
    }
}

/// Format and print RestoreData to stdout.
pub fn format_restore(data: &RestoreData) {
    println!("restore started");
    println!("  path:     {}", data.path);
    println!("  version:  {}", data.version_used);
    // Show first 16 chars of hash + ellipsis
    let hash_display = if data.content_hash_hex.len() > 16 {
        format!("{}...", &data.content_hash_hex[..16])
    } else {
        data.content_hash_hex.clone()
    };
    println!("  hash:     {}", hash_display);
    println!("  status:   {}", data.status);
}

/// Format and print a list of DeviceEntry to stdout.
pub fn format_device_list(devices: &[DeviceEntry]) {
    println!("cluster devices ({}):", devices.len());
    for device in devices {
        let marker = if device.revoked {
            "[R]"
        } else if device.is_current {
            "[*]"
        } else {
            "   "
        };
        // Show first 16 chars of device_id_hex
        let short_id = if device.device_id_hex.len() >= 16 {
            &device.device_id_hex[..16]
        } else {
            &device.device_id_hex
        };
        println!(
            "  {} {}  {}  added {}",
            marker, short_id, device.label, device.added_at
        );
    }
}

/// Format and print a newly-added DeviceEntry to stdout.
pub fn format_device_added(device: &DeviceEntry) {
    println!("device added");
    // Show first 16 chars + ellipsis
    let id_display = if device.device_id_hex.len() > 16 {
        format!("{}...", &device.device_id_hex[..16])
    } else {
        device.device_id_hex.clone()
    };
    println!("  id:    {}", id_display);
    println!("  label: {}", device.label);
}

/// Format and print a device revocation confirmation to stdout.
pub fn format_device_revoked(device_id_hex: &str) {
    let short = if device_id_hex.len() > 16 {
        format!("{}...", &device_id_hex[..16])
    } else {
        device_id_hex.to_string()
    };
    println!("device revoked: {short}");
}

/// Format and print a list of FileEntry to stdout.
pub fn format_files(files: &[FileEntry]) {
    if files.is_empty() {
        println!("no files backed up");
        return;
    }
    println!("backed-up files ({}):", files.len());
    for file in files {
        let version_label = if file.versions == 1 {
            "1 version".to_string()
        } else {
            format!("{} versions", file.versions)
        };
        println!(
            "  {}   {}   {}   {}   {}",
            file.path,
            version_label,
            file.last_backed_up,
            format_bytes(file.size_bytes),
            file.local_state
        );
    }
}

/// Format and print a list of VersionEntry for one path.
pub fn format_versions(path: &str, versions: &[VersionEntry]) {
    if versions.is_empty() {
        println!("no versions found for {path}");
        return;
    }
    println!("versions of {} ({}):", path, versions.len());
    for entry in versions {
        // Show first 8 chars of hash + "..."
        let hash_short = if entry.content_hash_hex.len() > 8 {
            format!("{}...", &entry.content_hash_hex[..8])
        } else {
            entry.content_hash_hex.clone()
        };
        // Show first 8 chars of block id
        let block_short = if entry.source_block_id_hex.len() >= 8 {
            entry.source_block_id_hex[..8].to_string()
        } else {
            entry.source_block_id_hex.clone()
        };
        let backed_str = &entry.backed_up_at;
        println!(
            "  v{}  {}  backed {}  {}  {}  [block: {}]",
            entry.version,
            entry.created_at,
            backed_str,
            hash_short,
            format_bytes(entry.size_bytes),
            block_short
        );
    }
}

/// Format and print a daemon error message to stderr.
pub fn format_error(msg: &str) {
    eprintln!("error: {msg}");
}
