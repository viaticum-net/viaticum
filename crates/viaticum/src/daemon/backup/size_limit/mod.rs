// The size limit of this machine (backup-i4, backup-i5): the largest file the daemon backs
// up, derived from the RAM the daemon may use, and the pack size that follows from it.
//
// `M = min(MemTotal, cgroup v2 memory.max)`. Heavy block work (encode, PoS re-encode, decode)
// holds up to `BLOCK_WORK_PEAK_FACTOR` block volumes, a backup `BACKUP_PEAK_FACTOR`; the
// daemon may take half of the RAM: `RAM_DIVISOR = 2·(14 + 2) = 32`, `N = clamp(M / 32,
// 32 MiB, 1 GiB)` (7.6 GiB → 243 MiB). The factor 14 holds only with the memory budget of
// R1-d-b; without it the divisor would be 76 (spec r1_bigfile_refusal.md §1.2, frozen).
//
// The machine's RAM is read from `/proc/meminfo` and the cgroup files directly (a few lines
// of parsing), not through a crate: only the total is needed, and the parsers are pure
// functions the unit tests feed with text.

use std::path::PathBuf;

use viaticum_core::constants::MAX_FILE_SIZE_CEILING_BYTES;

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

/// Volumes of one block that heavy block work holds at its peak: 3.1 + R with R <= 10,
/// plus a 7 % margin (frozen, spec §1.3).
pub const BLOCK_WORK_PEAK_FACTOR: u64 = 14;
/// Volumes of a file that a backup holds: the file and its compressed copy.
pub const BACKUP_PEAK_FACTOR: u64 = 2;
/// Backup and block work together may take half of the RAM.
pub const RAM_DIVISOR: u64 = 2 * (BLOCK_WORK_PEAK_FACTOR + BACKUP_PEAK_FACTOR);
const _: () = assert!(RAM_DIVISOR == 32);

/// The automatic limit is never below this ...
pub const AUTO_FILE_SIZE_FLOOR: u64 = 32 * MIB;
/// ... and never above this.
pub const AUTO_FILE_SIZE_CAP: u64 = GIB;
/// RAM assumed when neither `/proc/meminfo` nor a cgroup limit can be read.
pub const UNKNOWN_RAM_ASSUMED: u64 = 4 * GIB;

/// The automatic limit for `ram` bytes; `0` (unknown) counts as [`UNKNOWN_RAM_ASSUMED`].
pub fn auto_max_file_size(ram: u64) -> u64 {
    let ram = if ram == 0 { UNKNOWN_RAM_ASSUMED } else { ram };
    (ram / RAM_DIVISOR).clamp(AUTO_FILE_SIZE_FLOOR, AUTO_FILE_SIZE_CAP)
}

/// The limit in force: `override_mb` MiB when the config sets it (`> 0`; the config
/// validation keeps it within the RaptorQ ceiling), else the automatic one.
pub fn effective_max_file_size(override_mb: u64, ram: u64) -> u64 {
    if override_mb > 0 {
        override_mb
            .saturating_mul(MIB)
            .min(MAX_FILE_SIZE_CEILING_BYTES)
    } else {
        auto_max_file_size(ram)
    }
}

/// The pack size in force: the configured one, but at most half the file limit, so a pack
/// never costs more memory than the largest accepted file (J9).
pub fn effective_pack_size(configured: u64, max_file: u64) -> u64 {
    configured.min(max_file / 2)
}

/// `MemTotal` of `/proc/meminfo` text, in bytes.
pub(crate) fn parse_meminfo_total(text: &str) -> Option<u64> {
    let line = text.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    kib.checked_mul(1024)
}

/// The content of a cgroup v2 `memory.max`: a number of bytes, or `max` (no limit).
pub(crate) fn parse_cgroup_memory_max(text: &str) -> Option<u64> {
    text.trim().parse().ok()
}

/// The cgroup v2 path of `/proc/self/cgroup` text (the `0::<path>` line).
pub(crate) fn parse_cgroup_v2_path(text: &str) -> Option<&str> {
    text.lines().find_map(|l| l.strip_prefix("0::"))
}

/// The lesser of the two known values.
pub(crate) fn combine_ram(meminfo: Option<u64>, cgroup: Option<u64>) -> Option<u64> {
    match (meminfo, cgroup) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The lowest `memory.max` from this process's cgroup up to the cgroup root (a limit of
/// a parent binds the child too).
fn read_cgroup_limit() -> Option<u64> {
    let root = PathBuf::from("/sys/fs/cgroup");
    let own = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = parse_cgroup_v2_path(&own)?.trim_start_matches('/');
    let mut dir = root.join(rel);
    let mut lowest: Option<u64> = None;
    loop {
        if let Ok(text) = std::fs::read_to_string(dir.join("memory.max"))
            && let Some(v) = parse_cgroup_memory_max(&text)
        {
            lowest = Some(lowest.map_or(v, |l| l.min(v)));
        }
        if dir == root || !dir.pop() {
            break;
        }
    }
    lowest
}

/// `M`: the RAM the daemon may use, `None` when it cannot be read.
fn read_machine_ram() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|t| parse_meminfo_total(&t));
    combine_ram(meminfo, read_cgroup_limit())
}

/// `M = min(MemTotal, cgroup memory.max)`; unknown → [`UNKNOWN_RAM_ASSUMED`] and a WARN.
pub fn machine_ram_limit_bytes() -> u64 {
    match read_machine_ram() {
        Some(m) if m > 0 => m,
        _ => {
            tracing::warn!(
                assumed_bytes = UNKNOWN_RAM_ASSUMED,
                "memory: cannot read this machine's RAM; assuming 4 GiB for the size limits"
            );
            UNKNOWN_RAM_ASSUMED
        }
    }
}

/// The limits of this daemon run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeLimits {
    /// `M`.
    pub ram_bytes: u64,
    /// `N` in force.
    pub max_file_size: u64,
    /// `N` the machine would get without the override.
    pub auto_max_file_size: u64,
    /// The config sets `max_file_size_mb`.
    pub overridden: bool,
    /// `B_eff`.
    pub pack_size: u64,
}

impl SizeLimits {
    /// Pure: the limits for `ram` bytes, the config override and the configured pack size.
    pub fn compute(override_mb: u64, configured_pack: u64, ram: u64) -> Self {
        let max_file_size = effective_max_file_size(override_mb, ram);
        SizeLimits {
            ram_bytes: ram,
            max_file_size,
            auto_max_file_size: auto_max_file_size(ram),
            overridden: override_mb > 0,
            pack_size: effective_pack_size(configured_pack, max_file_size),
        }
    }

    /// Reads this machine's RAM.
    pub fn resolve(override_mb: u64, configured_pack: u64) -> Self {
        Self::compute(override_mb, configured_pack, machine_ram_limit_bytes())
    }

    /// The start line, and a WARN when the override is above the automatic limit.
    /// The block work budget belongs to R1-d-b: until then it is "not set".
    pub fn log_start(&self) {
        let source = if self.overridden { "config" } else { "auto" };
        tracing::info!(
            "memory: max file size {} ({source}, RAM {}), block work budget not set, pack size {}",
            format_size(self.max_file_size),
            format_size(self.ram_bytes),
            format_size(self.pack_size),
        );
        if self.overridden && self.max_file_size > self.auto_max_file_size {
            tracing::warn!(
                configured = %format_size(self.max_file_size),
                automatic = %format_size(self.auto_max_file_size),
                "memory: backup.max_file_size_mb is above the automatic limit for this machine; \
                 a big file may use more memory than the machine can spare"
            );
        }
    }
}

/// `243 MiB`, `7.6 GiB`.
pub(crate) fn format_size(bytes: u64) -> String {
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else {
        format!("{} MiB", bytes / MIB)
    }
}

#[cfg(test)]
mod tests;
