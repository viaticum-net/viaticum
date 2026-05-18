use super::*;
use super::burst;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

// ============================================================
// ---- burst.rs tests ----
// ============================================================

/// Helper: make a SystemTime from seconds since UNIX_EPOCH.
fn t(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// Helper: make a (PathBuf, SystemTime) pair.
fn file_at(name: &str, secs: u64) -> (PathBuf, SystemTime) {
    (PathBuf::from(name), t(secs))
}

// ──────────────────────────────────────────────
// detect_bursts
// ──────────────────────────────────────────────

#[test]
fn detect_bursts_groups_eight_files_within_60s() {
    let files: Vec<(PathBuf, SystemTime)> = (0..8u64)
        .map(|i| file_at(&format!("/photos/img_{:04}.jpg", i), i * 5))
        .collect();
    let result = burst::detect_bursts(&files, Duration::from_secs(60), 8);
    assert_eq!(result.len(), 1, "expected 1 burst, got {}", result.len());
    assert_eq!(result[0].len(), 8, "burst should contain all 8 files");
    for i in 0..8u64 {
        let p = PathBuf::from(format!("/photos/img_{:04}.jpg", i));
        assert!(result[0].contains(&p), "missing {}", p.display());
    }
}

#[test]
fn detect_bursts_ignores_seven_files_within_60s() {
    let files: Vec<(PathBuf, SystemTime)> = (0..7u64)
        .map(|i| file_at(&format!("/photos/img_{:04}.jpg", i), i * 5))
        .collect();
    let result = burst::detect_bursts(&files, Duration::from_secs(60), 8);
    assert!(result.is_empty(), "7 < min_count=8, expected no burst");
}

#[test]
fn detect_bursts_separates_two_clusters_separated_by_5_min() {
    // group1: t=0,5,10,15,20,25,30,35
    let mut files: Vec<(PathBuf, SystemTime)> = (0..8u64)
        .map(|i| file_at(&format!("/photos/g1_{:04}.jpg", i), i * 5))
        .collect();
    // group2: t=360..395 (6 minutes later)
    files.extend((0..8u64).map(|i| file_at(&format!("/photos/g2_{:04}.jpg", i), 360 + i * 5)));

    let result = burst::detect_bursts(&files, Duration::from_secs(60), 8);
    assert_eq!(result.len(), 2, "expected 2 bursts, got {}", result.len());

    // Each burst should contain 8 paths.
    assert_eq!(result[0].len(), 8);
    assert_eq!(result[1].len(), 8);

    // Algorithm sorts by mtime → group1 (earlier) → result[0]; group2 → result[1].
    for i in 0..8u64 {
        let g1 = PathBuf::from(format!("/photos/g1_{:04}.jpg", i));
        assert!(result[0].contains(&g1), "g1 path {} should be in first burst", i);
        assert!(!result[1].contains(&g1), "g1 path {} must NOT leak into second burst", i);

        let g2 = PathBuf::from(format!("/photos/g2_{:04}.jpg", i));
        assert!(result[1].contains(&g2), "g2 path {} should be in second burst", i);
        assert!(!result[0].contains(&g2), "g2 path {} must NOT leak into first burst", i);
    }
}

#[test]
fn detect_bursts_empty_input_returns_empty() {
    let result = burst::detect_bursts(&[], Duration::from_secs(60), 8);
    assert!(result.is_empty());
}

#[test]
fn detect_bursts_single_file_returns_empty() {
    let files = vec![file_at("/photos/solo.jpg", 0)];
    let result = burst::detect_bursts(&files, Duration::from_secs(60), 8);
    assert!(result.is_empty(), "1 < min_count=8, expected no burst");
}

#[test]
fn detect_bursts_sorts_input_internally() {
    // Provide files in reverse mtime order.
    let files: Vec<(PathBuf, SystemTime)> = (0..8u64)
        .map(|i| file_at(&format!("/photos/img_{:04}.jpg", i), (7 - i) * 5))
        .collect();
    let result = burst::detect_bursts(&files, Duration::from_secs(60), 8);
    assert_eq!(result.len(), 1, "should sort internally and detect burst");
    assert_eq!(result[0].len(), 8);
}

#[test]
fn detect_bursts_exactly_at_window_boundary() {
    // 8 files: t=0,10,20,30,40,50,59,60 — last exactly 60s from first.
    let times = [0u64, 10, 20, 30, 40, 50, 59, 60];
    let files: Vec<(PathBuf, SystemTime)> = times
        .iter()
        .enumerate()
        .map(|(i, &s)| file_at(&format!("/photos/img_{:04}.jpg", i), s))
        .collect();
    let result = burst::detect_bursts(&files, Duration::from_secs(60), 8);
    assert_eq!(result.len(), 1, "t[7]-t[0]=60 <= 60, should form a burst");
}

#[test]
fn detect_bursts_just_outside_window() {
    // 8 files: t=0,10,20,30,40,50,59,61 — last 61s from first.
    let times = [0u64, 10, 20, 30, 40, 50, 59, 61];
    let files: Vec<(PathBuf, SystemTime)> = times
        .iter()
        .enumerate()
        .map(|(i, &s)| file_at(&format!("/photos/img_{:04}.jpg", i), s))
        .collect();
    let result = burst::detect_bursts(&files, Duration::from_secs(60), 8);
    assert!(result.is_empty(), "t[7]-t[0]=61 > 60, no 8-file window fits");
}

#[test]
fn detect_bursts_large_cluster_beyond_min_emits_full_range() {
    // 16 files at t=0,3,6,...,45
    let files: Vec<(PathBuf, SystemTime)> = (0..16u64)
        .map(|i| file_at(&format!("/photos/img_{:04}.jpg", i), i * 3))
        .collect();
    let result = burst::detect_bursts(&files, Duration::from_secs(60), 8);
    assert_eq!(result.len(), 1, "all 16 fit in window");
    assert_eq!(result[0].len(), 16, "all 16 should be in the burst");
}

#[test]
fn detect_bursts_non_overlapping_greedy() {
    // Design: first 8 files span 56s (≤ 60s window).
    // The next file is at t=62 (62-0=62 > 60) → first burst ends at j=7.
    // Then 9 more files starting at t=62 form the second burst (range 24s ≤ 60s).
    //
    // first8: t=0,8,16,24,32,40,48,56 (range=56 ≤ 60, count=8 ≥ 8 → first burst)
    // second_group: t=62,65,68,71,74,77,80,83,86 (range=24 ≤ 60, count=9 ≥ 8 → second burst)
    let first8 = [0u64, 8, 16, 24, 32, 40, 48, 56];
    let second9 = [62u64, 65, 68, 71, 74, 77, 80, 83, 86];
    let mut times: Vec<u64> = first8.to_vec();
    times.extend_from_slice(&second9);

    let files: Vec<(PathBuf, SystemTime)> = times
        .iter()
        .enumerate()
        .map(|(i, &s)| file_at(&format!("/photos/img_{:04}.jpg", i), s))
        .collect();
    let result = burst::detect_bursts(&files, Duration::from_secs(60), 8);
    assert_eq!(result.len(), 2, "non-overlapping: first 8 then 9 = 2 bursts, got {}", result.len());

    // Check sizes: order in result follows mtime order.
    let sizes: Vec<usize> = result.iter().map(|s| s.len()).collect();
    assert!(
        sizes.contains(&8) && sizes.contains(&9),
        "expected bursts of size 8 and 9, got {:?}",
        sizes
    );
}

// ──────────────────────────────────────────────
// is_in_any_burst
// ──────────────────────────────────────────────

#[test]
fn is_in_any_burst_finds_path_in_one_of_several_sets() {
    let mut set_a: HashSet<PathBuf> = HashSet::new();
    set_a.insert(PathBuf::from("/p/a"));
    set_a.insert(PathBuf::from("/p/b"));
    let mut set_b: HashSet<PathBuf> = HashSet::new();
    set_b.insert(PathBuf::from("/q/c"));
    let bursts = vec![set_a, set_b];
    assert!(burst::is_in_any_burst(Path::new("/q/c"), &bursts));
}

#[test]
fn is_in_any_burst_returns_false_for_path_not_in_any_set() {
    let mut set_a: HashSet<PathBuf> = HashSet::new();
    set_a.insert(PathBuf::from("/p/a"));
    set_a.insert(PathBuf::from("/p/b"));
    let mut set_b: HashSet<PathBuf> = HashSet::new();
    set_b.insert(PathBuf::from("/q/c"));
    let bursts = vec![set_a, set_b];
    assert!(!burst::is_in_any_burst(Path::new("/p/z"), &bursts));
}

#[test]
fn is_in_any_burst_empty_bursts_returns_false() {
    assert!(!burst::is_in_any_burst(Path::new("/anything"), &[]));
}

// ──────────────────────────────────────────────
// burst_downweight_selects
// ──────────────────────────────────────────────

#[test]
fn burst_downweight_selects_seventy_percent_of_thousand_paths() {
    let paths: Vec<PathBuf> = (0..1000u32)
        .map(|i| PathBuf::from(format!("/photos/img_{:04}.jpg", i)))
        .collect();
    let count = paths
        .iter()
        .filter(|p| burst::burst_downweight_selects(p))
        .count();
    // Using u64 % 100 (8 bytes of blake3) reduces bias to ~5×10⁻¹⁸ — effectively
    // exact 70%. Binomial(1000, 0.7): stdev ≈ 14.5; ±5σ ≈ ±73, so [627, 773] is safe.
    assert!(
        (627..=773).contains(&count),
        "expected ~70% of 1000 selected (within ±5σ of binomial), got {}",
        count
    );
}

#[test]
fn burst_downweight_deterministic_across_calls() {
    let path = Path::new("/home/alice/Photos/IMG_0042.jpg");
    let r1 = burst::burst_downweight_selects(path);
    let r2 = burst::burst_downweight_selects(path);
    assert_eq!(r1, r2, "pure function must be deterministic");
}

#[test]
fn burst_downweight_different_paths_may_differ() {
    // Assert non-constant: at least one pair of distinct paths in a small
    // sample produces different selection results. Catches a regression where
    // burst_downweight_selects starts returning the same value for all inputs.
    let results: Vec<bool> = (0..32u32)
        .map(|i| {
            let p = PathBuf::from(format!("/photos/img_{:04}.jpg", i));
            burst::burst_downweight_selects(&p)
        })
        .collect();
    let trues = results.iter().filter(|&&b| b).count();
    assert!(
        trues > 0 && trues < results.len(),
        "expected mixed true/false across 32 paths, got {} true",
        trues
    );
}

// ──────────────────────────────────────────────
// apply_burst_downweight
// ──────────────────────────────────────────────

#[test]
fn apply_burst_downweight_halves_value() {
    let result = burst::apply_burst_downweight(0.65);
    assert!((result - 0.325).abs() < 1e-9, "expected 0.325, got {}", result);
}

#[test]
fn apply_burst_downweight_floors_at_005() {
    // 0.05 * 0.5 = 0.025 → max(0.025, 0.05) = 0.05
    let r1 = burst::apply_burst_downweight(0.05);
    assert!((r1 - 0.05).abs() < 1e-9, "floor at 0.05: got {}", r1);

    // 0.01 * 0.5 = 0.005 → max(0.005, 0.05) = 0.05
    let r2 = burst::apply_burst_downweight(0.01);
    assert!((r2 - 0.05).abs() < 1e-9, "floor at 0.05: got {}", r2);

    // 0.0 * 0.5 = 0 → max(0, 0.05) = 0.05
    let r3 = burst::apply_burst_downweight(0.0);
    assert!((r3 - 0.05).abs() < 1e-9, "floor at 0.05: got {}", r3);
}

#[test]
fn apply_burst_downweight_mediahigh() {
    let result = burst::apply_burst_downweight(0.95);
    assert!((result - 0.475).abs() < 1e-9, "0.95 * 0.5 = 0.475, got {}", result);
}

#[test]
fn apply_burst_downweight_medialow() {
    let result = burst::apply_burst_downweight(0.20);
    assert!((result - 0.10).abs() < 1e-9, "0.20 * 0.5 = 0.10, got {}", result);
}
