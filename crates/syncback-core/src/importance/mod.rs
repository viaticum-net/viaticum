// Importance classification: pure, infallible, no I/O.
// Assigns an ImportanceClass to each file based on its extension and
// the folder's detected media fraction.

use std::path::{Path, PathBuf};

mod extensions;
use extensions::{MEDIA_EXTENSIONS, TEXT_OR_CODE_EXTENSIONS};

pub mod burst;
pub use burst::{
    BURST_MIN_COUNT, BURST_WINDOW, apply_burst_downweight, burst_downweight_selects, detect_bursts,
    is_in_any_burst,
};

#[cfg(test)]
mod tests;

// ============================================================
// Types
// ============================================================

/// Classification of a file for backup importance.
///
/// Values returned by `importance_value()` are the base importance scores
/// before applying the folder multiplier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportanceClass {
    /// Plain text, source code, config files — extension whitelist.
    /// Base importance: 1.0
    TextOrCode,
    /// Media file in a media folder, top 5% bucket (deterministic hash).
    /// Base importance: 0.95
    MediaHigh,
    /// Media file in a media folder, middle 25% bucket.
    /// Base importance: 0.65
    MediaMedium,
    /// Media file in a media folder, bottom 70% bucket.
    /// Base importance: 0.20
    MediaLow,
    /// Unknown file type, or media file outside a media folder.
    /// Base importance: 0.05
    Unknown,
}

/// Classification metadata for a watched folder.
///
/// Produced by `classify_folder` from a sample of the folder's paths.
/// Passed to `classify_file` for per-file classification decisions.
///
/// # Stability
///
/// `is_media_folder` is a snapshot property. If the file mix in the folder
/// changes such that the media fraction crosses the 50% threshold, the value
/// will change on the next call to `classify_folder`, causing all media files
/// in the folder to be reclassified. This is expected behavior.
#[derive(Debug, Clone, PartialEq)]
pub struct FolderClassification {
    /// True if more than or equal to 50% of the sampled files in this folder have
    /// media extensions (image, video, or audio).
    pub is_media_folder: bool,
    /// Scaling factor applied to all files in this folder.
    ///
    /// Range: [0.0, 2.0]. Default: 1.0.
    /// Source: `[[watch]] importance_multiplier` config field.
    /// Values outside [0.0, 2.0] are accepted; `effective_importance` clamps
    /// the final result to [0.0, 1.0] regardless.
    pub importance_multiplier: f64,
}

impl Default for FolderClassification {
    fn default() -> Self {
        Self {
            is_media_folder: false,
            importance_multiplier: 1.0,
        }
    }
}

// ============================================================
// Private helpers
// ============================================================

/// Hash the full path to a bucket in [0, 100).
///
/// Uses blake3 for version-stable determinism (unlike DefaultHasher).
/// A folder rename changes the full path and may change the bucket — this is
/// a documented trade-off (D2 in spec).
fn path_bucket(path: &Path) -> u8 {
    let hash = blake3::hash(path.to_string_lossy().as_bytes());
    let bytes = hash.as_bytes();
    let n = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    (n % 100) as u8
}

/// Returns true for known special filenames that have no extension but are
/// clearly text/code: Dockerfile, Makefile, .gitignore, etc.
///
/// Only called when `path.extension() == None`.
fn is_special_text_filename(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    matches!(
        name,
        "Dockerfile"
            | "Makefile"
            | "Procfile"
            | "Vagrantfile"
            | ".gitignore"
            | ".dockerignore"
            | ".eslintignore"
            | ".gitattributes"
            | ".editorconfig"
            | ".npmignore"
    )
}

// ============================================================
// Public API
// ============================================================

/// Classify a file by its path and the folder's classification.
///
/// # Rules (evaluated in order)
///
/// 1. If the file's extension (final component, ASCII-lowercased) is in
///    `TEXT_OR_CODE_EXTENSIONS` → `TextOrCode`.
/// 2. If the file has no extension and the filename matches a known special
///    filename (Dockerfile, Makefile, .gitignore, etc.) → `TextOrCode`.
/// 3. If `folder.is_media_folder` AND the extension is in `MEDIA_EXTENSIONS`
///    → hash-bucket the full path: `[0,5)` → `MediaHigh`, `[5,30)` → `MediaMedium`,
///    `[30,100)` → `MediaLow`.
/// 4. Otherwise → `Unknown`.
///
/// Note: a media-extension file OUTSIDE a media folder returns `Unknown`.
/// This is intentional: stray photos in a documents folder should not compete
/// with the actual documents.
///
/// # I/O
///
/// Pure function — no filesystem access. Classification is based solely on
/// the path string and the folder classification struct.
///
/// # Extension matching
///
/// Uses only the final extension component (`path.extension()`).
/// `archive.tar.gz` → extension `.gz` → `Unknown`.
/// Files with no extension → `Unknown` unless they match a special filename.
///
/// # Hash determinism
///
/// The full path byte string is hashed via blake3. The bucket is stable across
/// daemon restarts and crate version upgrades. A folder rename changes the full
/// path → may change the bucket; this is a documented trade-off.
pub fn classify_file(path: &Path, folder: &FolderClassification) -> ImportanceClass {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => {
            let ext_lower = ext.to_ascii_lowercase();
            if TEXT_OR_CODE_EXTENSIONS.contains(&ext_lower.as_str()) {
                return ImportanceClass::TextOrCode;
            }
            if folder.is_media_folder && MEDIA_EXTENSIONS.contains(&ext_lower.as_str()) {
                return match path_bucket(path) {
                    0..=4 => ImportanceClass::MediaHigh,
                    5..=29 => ImportanceClass::MediaMedium,
                    _ => ImportanceClass::MediaLow,
                };
            }
            ImportanceClass::Unknown
        }
        None => {
            if is_special_text_filename(path) {
                ImportanceClass::TextOrCode
            } else {
                ImportanceClass::Unknown
            }
        }
    }
}

/// Determine the classification of a folder from a sample of its file paths.
///
/// A folder is considered a media folder when at least 50% of the sampled
/// paths have a media extension (image, video, or audio — see `MEDIA_EXTENSIONS`).
///
/// # Sampling
///
/// The caller may pass a representative sample rather than all files for very
/// large folders. The 50% threshold is applied to the sample. For small folders
/// (< 1000 files), pass all paths. For larger folders, a random sample of
/// 1000–2000 paths is sufficient.
///
/// # Empty input
///
/// Returns `FolderClassification { is_media_folder: false, importance_multiplier: 1.0 }`.
/// The caller is responsible for setting `importance_multiplier` from config after
/// calling this function.
///
/// # Note on multiplier
///
/// This function does NOT set `importance_multiplier` (it has no access to config).
/// The returned struct always has `importance_multiplier = 1.0`. The caller
/// (watcher, Wave 6) must set it from the `[[watch]] importance_multiplier` config
/// field before using the struct.
pub fn classify_folder(paths: &[PathBuf]) -> FolderClassification {
    if paths.is_empty() {
        return FolderClassification::default();
    }
    let media_count = paths
        .iter()
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .map(|e| MEDIA_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
                .unwrap_or(false)
        })
        .count();
    let is_media_folder = (media_count as f64 / paths.len() as f64) >= 0.50;
    FolderClassification {
        is_media_folder,
        importance_multiplier: 1.0,
    }
}

/// Map an `ImportanceClass` to its base f64 importance score.
///
/// | Class       | Value |
/// |-------------|-------|
/// | TextOrCode  | 1.00  |
/// | MediaHigh   | 0.95  |
/// | MediaMedium | 0.65  |
/// | MediaLow    | 0.20  |
/// | Unknown     | 0.05  |
pub fn importance_value(class: ImportanceClass) -> f64 {
    match class {
        ImportanceClass::TextOrCode => 1.00,
        ImportanceClass::MediaHigh => 0.95,
        ImportanceClass::MediaMedium => 0.65,
        ImportanceClass::MediaLow => 0.20,
        ImportanceClass::Unknown => 0.05,
    }
}

/// Compute the effective importance of a file after applying the folder multiplier.
///
/// Formula: `(importance_value(class) * multiplier).clamp(0.0, 1.0)`
///
/// # Multiplier semantics
///
/// - 1.0 (default): no change
/// - 0.5: halve the base importance
/// - 2.0: double (clamped to 1.0 for TextOrCode and MediaHigh)
/// - 0.0: effectively exclude (effective importance = 0.0)
/// - Negative or > 2.0: accepted defensively; clamping ensures output stays in [0.0, 1.0]
///
/// # Output
///
/// Always in `[0.0, 1.0]`.
pub fn effective_importance(class: ImportanceClass, multiplier: f64) -> f64 {
    (importance_value(class) * multiplier).clamp(0.0, 1.0)
}
