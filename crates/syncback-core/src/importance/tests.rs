use super::*;
use std::path::{Path, PathBuf};

fn non_media_folder() -> FolderClassification {
    FolderClassification {
        is_media_folder: false,
        importance_multiplier: 1.0,
    }
}

fn media_folder() -> FolderClassification {
    FolderClassification {
        is_media_folder: true,
        importance_multiplier: 1.0,
    }
}

// ============================================================
// Extension classification — TextOrCode
// ============================================================

#[test]
fn classify_file_rs_returns_text_or_code() {
    let result = classify_file(Path::new("src/main.rs"), &non_media_folder());
    assert_eq!(result, ImportanceClass::TextOrCode);
}

#[test]
fn classify_file_md_returns_text_or_code() {
    let result = classify_file(Path::new("README.md"), &non_media_folder());
    assert_eq!(result, ImportanceClass::TextOrCode);
}

#[test]
fn classify_file_py_returns_text_or_code() {
    let result = classify_file(Path::new("script.py"), &non_media_folder());
    assert_eq!(result, ImportanceClass::TextOrCode);
}

#[test]
fn classify_file_json_returns_text_or_code() {
    let result = classify_file(Path::new("config.json"), &non_media_folder());
    assert_eq!(result, ImportanceClass::TextOrCode);
}

#[test]
fn classify_file_toml_returns_text_or_code() {
    let result = classify_file(Path::new("Cargo.toml"), &non_media_folder());
    assert_eq!(result, ImportanceClass::TextOrCode);
}

#[test]
fn classify_file_sh_returns_text_or_code() {
    let result = classify_file(Path::new("deploy.sh"), &non_media_folder());
    assert_eq!(result, ImportanceClass::TextOrCode);
}

// ============================================================
// Unknown classification
// ============================================================

#[test]
fn classify_file_unknown_extension_returns_unknown() {
    let result = classify_file(Path::new("mystery.xyz"), &non_media_folder());
    assert_eq!(result, ImportanceClass::Unknown);
}

#[test]
fn classify_file_no_extension_returns_unknown() {
    // "Binaryfile" does not match special filenames
    let result = classify_file(Path::new("Binaryfile"), &non_media_folder());
    assert_eq!(result, ImportanceClass::Unknown);
}

#[test]
fn classify_file_gz_extension_returns_unknown() {
    // .extension() on "archive.tar.gz" returns "gz" — not in either set
    let result = classify_file(Path::new("archive.tar.gz"), &non_media_folder());
    assert_eq!(result, ImportanceClass::Unknown);
}

// ============================================================
// Special filenames (no extension)
// ============================================================

#[test]
fn classify_file_dockerfile_returns_text_or_code() {
    let result = classify_file(Path::new("Dockerfile"), &non_media_folder());
    assert_eq!(result, ImportanceClass::TextOrCode);
}

#[test]
fn classify_file_makefile_returns_text_or_code() {
    let result = classify_file(Path::new("Makefile"), &non_media_folder());
    assert_eq!(result, ImportanceClass::TextOrCode);
}

#[test]
fn classify_file_gitignore_returns_text_or_code() {
    let result = classify_file(Path::new(".gitignore"), &non_media_folder());
    assert_eq!(result, ImportanceClass::TextOrCode);
}

#[test]
fn special_filename_procfile_returns_text_or_code() {
    let result = classify_file(Path::new("Procfile"), &non_media_folder());
    assert_eq!(result, ImportanceClass::TextOrCode);
}

#[test]
fn special_filename_vagrantfile_returns_text_or_code() {
    let result = classify_file(Path::new("Vagrantfile"), &non_media_folder());
    assert_eq!(result, ImportanceClass::TextOrCode);
}

#[test]
fn special_filename_dockerignore_returns_text_or_code() {
    let result = classify_file(Path::new(".dockerignore"), &non_media_folder());
    assert_eq!(result, ImportanceClass::TextOrCode);
}

// ============================================================
// Case insensitivity
// ============================================================

#[test]
fn classify_file_uppercase_extension_treated_same_as_lowercase() {
    let result = classify_file(Path::new("IMAGE.JPG"), &media_folder());
    assert!(
        matches!(
            result,
            ImportanceClass::MediaHigh | ImportanceClass::MediaMedium | ImportanceClass::MediaLow
        ),
        "expected a media bucket, got {:?}",
        result
    );
}

#[test]
fn classify_file_mixed_case_rs_is_text_or_code() {
    let result = classify_file(Path::new("main.RS"), &non_media_folder());
    assert_eq!(result, ImportanceClass::TextOrCode);
}

// ============================================================
// Multiple extension
// ============================================================

#[test]
fn classify_file_tar_gz_uses_final_extension() {
    // extension() returns "gz" for "backup.tar.gz" — not in either set
    let result = classify_file(Path::new("backup.tar.gz"), &non_media_folder());
    assert_eq!(result, ImportanceClass::Unknown);
}

#[test]
fn classify_file_min_js_uses_js() {
    // extension() returns "js" for "app.min.js" → TextOrCode
    let result = classify_file(Path::new("app.min.js"), &non_media_folder());
    assert_eq!(result, ImportanceClass::TextOrCode);
}

// ============================================================
// Media file in / outside media folder
// ============================================================

#[test]
fn classify_file_jpg_in_media_folder_returns_one_of_three_buckets() {
    let result = classify_file(
        Path::new("/home/alice/Photos/IMG_001.jpg"),
        &media_folder(),
    );
    assert!(
        matches!(
            result,
            ImportanceClass::MediaHigh | ImportanceClass::MediaMedium | ImportanceClass::MediaLow
        ),
        "expected a media bucket, got {:?}",
        result
    );
}

#[test]
fn classify_file_jpg_outside_media_folder_returns_unknown() {
    let result = classify_file(
        Path::new("/home/alice/Documents/stray.jpg"),
        &non_media_folder(),
    );
    assert_eq!(result, ImportanceClass::Unknown);
}

#[test]
fn classify_file_mp4_in_media_folder_returns_bucket() {
    let result = classify_file(
        Path::new("/home/alice/Videos/vacation.mp4"),
        &media_folder(),
    );
    assert!(
        matches!(
            result,
            ImportanceClass::MediaHigh | ImportanceClass::MediaMedium | ImportanceClass::MediaLow
        ),
        "expected a media bucket, got {:?}",
        result
    );
}

#[test]
fn classify_file_mp3_outside_media_folder_returns_unknown() {
    let result = classify_file(
        Path::new("/home/alice/Downloads/song.mp3"),
        &non_media_folder(),
    );
    assert_eq!(result, ImportanceClass::Unknown);
}

// ============================================================
// Determinism
// ============================================================

#[test]
fn classify_file_deterministic_across_calls() {
    let path = Path::new("/home/alice/Photos/IMG_001.jpg");
    let folder = media_folder();
    let result_1 = classify_file(path, &folder);
    let result_2 = classify_file(path, &folder);
    assert_eq!(result_1, result_2);
}

#[test]
fn classify_file_same_name_different_folder_may_differ() {
    let path_a = PathBuf::from("/photos/IMG_001.jpg");
    let path_b = PathBuf::from("/archive/IMG_001.jpg");
    let folder = media_folder();
    let result_a = classify_file(&path_a, &folder);
    let result_b = classify_file(&path_b, &folder);
    // Both must be media buckets — no assertion about them being equal or unequal
    assert!(matches!(
        result_a,
        ImportanceClass::MediaHigh | ImportanceClass::MediaMedium | ImportanceClass::MediaLow
    ));
    assert!(matches!(
        result_b,
        ImportanceClass::MediaHigh | ImportanceClass::MediaMedium | ImportanceClass::MediaLow
    ));
}

// ============================================================
// Bucket distribution
// ============================================================

#[test]
fn classify_file_bucket_distribution_in_media_folder() {
    let folder = FolderClassification {
        is_media_folder: true,
        importance_multiplier: 1.0,
    };
    let mut high = 0usize;
    let mut med = 0usize;
    let mut low = 0usize;
    for i in 0..1000u32 {
        let path = PathBuf::from(format!("/photos/file_{}.jpg", i));
        match classify_file(&path, &folder) {
            ImportanceClass::MediaHigh => high += 1,
            ImportanceClass::MediaMedium => med += 1,
            ImportanceClass::MediaLow => low += 1,
            other => panic!("unexpected class {:?} for media file in media folder", other),
        }
    }
    assert!(
        high >= 20 && high <= 80,
        "MediaHigh out of expected range [20,80]: {}",
        high
    );
    assert!(
        med >= 220 && med <= 280,
        "MediaMedium out of expected range [220,280]: {}",
        med
    );
    assert!(
        low >= 670 && low <= 730,
        "MediaLow out of expected range [670,730]: {}",
        low
    );
}

// ============================================================
// classify_folder heuristic
// ============================================================

#[test]
fn classify_folder_detects_media_folder_at_50_percent() {
    let mut paths: Vec<PathBuf> = (0..50).map(|i| PathBuf::from(format!("img_{}.jpg", i))).collect();
    paths.extend((0..50).map(|i| PathBuf::from(format!("doc_{}.txt", i))));
    let result = classify_folder(&paths);
    assert!(result.is_media_folder, "50% media fraction should be a media folder");
}

#[test]
fn classify_folder_does_not_flag_below_threshold() {
    let mut paths: Vec<PathBuf> = (0..49).map(|i| PathBuf::from(format!("img_{}.jpg", i))).collect();
    paths.extend((0..51).map(|i| PathBuf::from(format!("doc_{}.txt", i))));
    let result = classify_folder(&paths);
    assert!(!result.is_media_folder, "49% media fraction should not be a media folder");
}

#[test]
fn classify_folder_detects_pure_media_folder() {
    let paths: Vec<PathBuf> = (0..200).map(|i| PathBuf::from(format!("img_{}.jpg", i))).collect();
    let result = classify_folder(&paths);
    assert!(result.is_media_folder);
}

#[test]
fn classify_folder_mixed_below_half_is_not_media() {
    let mut paths: Vec<PathBuf> = (0..30).map(|i| PathBuf::from(format!("img_{}.jpg", i))).collect();
    paths.extend((0..70).map(|i| PathBuf::from(format!("src_{}.rs", i))));
    let result = classify_folder(&paths);
    assert!(!result.is_media_folder);
}

#[test]
fn classify_folder_empty_input_returns_non_media_default() {
    let result = classify_folder(&[]);
    assert!(!result.is_media_folder);
    assert_eq!(result.importance_multiplier, 1.0);
}

#[test]
fn classify_folder_multiplier_is_always_1_0() {
    let paths: Vec<PathBuf> = (0..100).map(|i| PathBuf::from(format!("img_{}.jpg", i))).collect();
    let result = classify_folder(&paths);
    assert_eq!(result.importance_multiplier, 1.0);
}

#[test]
fn classify_folder_counts_all_media_types() {
    // 30 mp4 + 20 mp3 + 50 rs = 100 total → 50% media → is_media_folder = true
    let mut paths: Vec<PathBuf> = (0..30).map(|i| PathBuf::from(format!("video_{}.mp4", i))).collect();
    paths.extend((0..20).map(|i| PathBuf::from(format!("audio_{}.mp3", i))));
    paths.extend((0..50).map(|i| PathBuf::from(format!("src_{}.rs", i))));
    let result = classify_folder(&paths);
    assert!(result.is_media_folder);
}

// ============================================================
// importance_value anchors
// ============================================================

#[test]
fn importance_value_anchors_match_spec() {
    assert_eq!(importance_value(ImportanceClass::TextOrCode), 1.00);
    assert_eq!(importance_value(ImportanceClass::MediaHigh), 0.95);
    assert_eq!(importance_value(ImportanceClass::MediaMedium), 0.65);
    assert_eq!(importance_value(ImportanceClass::MediaLow), 0.20);
    assert_eq!(importance_value(ImportanceClass::Unknown), 0.05);
}

// ============================================================
// effective_importance
// ============================================================

#[test]
fn effective_importance_applies_multiplier() {
    let result = effective_importance(ImportanceClass::TextOrCode, 0.5);
    assert!((result - 0.50).abs() < 1e-10, "expected 0.50, got {}", result);
}

#[test]
fn effective_importance_clamps_above_one() {
    assert_eq!(effective_importance(ImportanceClass::TextOrCode, 2.0), 1.0);
    assert_eq!(effective_importance(ImportanceClass::MediaHigh, 2.0), 1.0);
    assert_eq!(effective_importance(ImportanceClass::MediaMedium, 2.0), 1.0);
}

#[test]
fn effective_importance_zero_multiplier_returns_zero() {
    assert_eq!(effective_importance(ImportanceClass::TextOrCode, 0.0), 0.0);
    assert_eq!(effective_importance(ImportanceClass::MediaHigh, 0.0), 0.0);
    assert_eq!(effective_importance(ImportanceClass::Unknown, 0.0), 0.0);
}

#[test]
fn effective_importance_clamps_below_zero() {
    // negative multiplier → result < 0.0 → clamped to 0.0
    assert_eq!(effective_importance(ImportanceClass::TextOrCode, -1.0), 0.0);
}

#[test]
fn effective_importance_default_multiplier_is_identity() {
    assert_eq!(effective_importance(ImportanceClass::TextOrCode, 1.0), 1.0);
    assert!(
        (effective_importance(ImportanceClass::MediaLow, 1.0) - 0.20).abs() < 1e-10
    );
    assert!(
        (effective_importance(ImportanceClass::Unknown, 1.0) - 0.05).abs() < 1e-10
    );
}

#[test]
fn effective_importance_media_low_boosted() {
    // 0.20 * 3.0 = 0.60 → no clamp needed
    let result = effective_importance(ImportanceClass::MediaLow, 3.0);
    assert!((result - 0.60).abs() < 1e-10, "expected 0.60, got {}", result);
    // 0.20 * 6.0 = 1.20 → clamped to 1.0
    assert_eq!(effective_importance(ImportanceClass::MediaLow, 6.0), 1.0);
}
