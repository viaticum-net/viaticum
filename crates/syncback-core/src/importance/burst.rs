// Burst detection and downweighting for photo bursts.
//
// Detects time-clustered groups of media files (e.g., camera burst shots)
// and applies a 70% downweight to reduce their backup priority relative to
// individually important files.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use super::extensions::MEDIA_EXTENSIONS;

// ============================================================
// Constants
// ============================================================

/// Default burst window: files within this duration count toward a burst.
pub const BURST_WINDOW: Duration = Duration::from_secs(60);

/// Minimum number of media files within the burst window to qualify as a burst.
pub const BURST_MIN_COUNT: usize = 8;

// ============================================================
// Public API
// ============================================================

/// Detect time-clustered groups of media files (bursts) from a list of
/// (path, mtime) pairs.
///
/// # Algorithm
///
/// Sorts the input by mtime ascending (ties broken by path for determinism),
/// then performs a non-overlapping greedy forward scan:
/// - At each position `i`, find the largest `j` such that
///   `files[j].mtime - files[i].mtime <= window`.
/// - If `j - i + 1 >= min_count`, emit the range `files[i..=j]` as a burst and
///   advance past `j` (non-overlapping).
/// - Otherwise advance `i` by one and try the next starting position.
///
/// # Properties
///
/// - Each file appears in at most one burst (non-overlapping).
/// - Deterministic: same input -> same output, regardless of call order.
/// - If `files` is empty or fewer than `min_count` in any window, returns `[]`.
///
/// # Parameters
///
/// - `files`: (path, mtime) pairs. Need not be pre-sorted; the function sorts internally.
/// - `window`: maximum duration between the first and last file in a burst.
/// - `min_count`: minimum number of files to qualify as a burst.
pub fn detect_bursts(
    files: &[(PathBuf, SystemTime)],
    window: Duration,
    min_count: usize,
) -> Vec<HashSet<PathBuf>> {
    if files.is_empty() || min_count == 0 {
        return vec![];
    }

    // Sort by mtime ascending; break ties by path for determinism.
    let mut sorted: Vec<&(PathBuf, SystemTime)> = files.iter().collect();
    sorted.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));

    let mut bursts: Vec<HashSet<PathBuf>> = vec![];
    let mut i = 0;
    while i < sorted.len() {
        let t_i = sorted[i].1;
        // Find largest j such that sorted[j].mtime - sorted[i].mtime <= window.
        let mut j = i;
        while j + 1 < sorted.len() {
            let span = sorted[j + 1].1.duration_since(t_i).unwrap_or(Duration::MAX);
            if span <= window {
                j += 1;
            } else {
                break;
            }
        }
        let count = j - i + 1;
        if count >= min_count {
            let set: HashSet<PathBuf> = sorted[i..=j].iter().map(|p| p.0.clone()).collect();
            bursts.push(set);
            i = j + 1; // advance past the entire burst (non-overlapping)
        } else {
            i += 1; // no burst at this start; advance one step
        }
    }
    bursts
}

/// Returns true if `path` appears in any of the given burst sets.
///
/// Iterates the burst sets in order. O(sets * 1) average per HashSet lookup.
pub fn is_in_any_burst(path: &Path, bursts: &[HashSet<PathBuf>]) -> bool {
    bursts.iter().any(|set| set.contains(path))
}

/// Deterministically select 70% of paths for burst downweighting.
///
/// Uses `blake3(path_bytes + b"burst-downweight")` as a stable hash.
/// Returns true if `(u64::from_le_bytes(hash[0..8]) % 100) < 70`.
///
/// # Determinism
///
/// Pure function of `path`. Same path -> same result, always.
/// Stable across daemon restarts and crate version upgrades (blake3 is
/// content-addressed and version-stable).
///
/// # Note on probability
///
/// Earlier drafts used `hash[0] % 100`, but `u8 % 100` is biased
/// (256 mod 100 = 56 → residues 0..55 are over-represented, giving ~76.6%
/// selection instead of 70%). Using the first 8 bytes as a `u64` reduces
/// the bias to ~5×10⁻¹⁸, indistinguishable from a perfect 70% rate.
pub fn burst_downweight_selects(path: &Path) -> bool {
    let mut hasher = blake3::Hasher::new();
    hasher.update(path.to_string_lossy().as_bytes());
    hasher.update(b"burst-downweight");
    let hash = hasher.finalize();
    let bytes = hash.as_bytes();
    let head = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    (head % 100) < 70
}

/// Returns true if the (already lowercased) extension is a media extension.
///
/// Used by `populate_bursts` in `config/mod.rs` to filter files before
/// building the `(path, mtime)` input for `detect_bursts`. Delegates to the
/// single source of truth in `extensions::MEDIA_EXTENSIONS`.
pub(crate) fn is_media_ext(ext_lower: &str) -> bool {
    MEDIA_EXTENSIONS.contains(&ext_lower)
}

/// Apply the burst downweight: halve the importance, floor at 0.05.
///
/// Formula: `(importance * 0.5).max(0.05)`
///
/// # Invariant
///
/// Input range: any `f64`. Output range: `[0.05, ...]` (floor applies).
/// For valid importance values in `[0.0, 1.0]`, output is in `[0.05, 0.5]`.
pub fn apply_burst_downweight(importance: f64) -> f64 {
    (importance * 0.5).max(0.05)
}
