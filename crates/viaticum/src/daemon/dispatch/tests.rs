use std::sync::{Arc, RwLock};

use tokio::sync::mpsc;

use viaticum_core::db::Db;
use viaticum_core::types::{DeviceId, IdentityPub};

use crate::cli::types::{CliRequest, CliResponse};
use crate::cli::types::{
    RestoreFailure, RestoreFailureKind, RestoreJobState, RestoreOutcome, RestoreRejection,
};
use crate::daemon::handle::DaemonState;
use crate::daemon::restore::RestoreRequest;
use crate::daemon::restore::jobs::RestoreJobs;
use crate::daemon::restore::staging::JobId;

use super::dispatch;

// ============================================================
// Test helper: build a minimal DaemonState backed by in-memory DB
// ============================================================

/// A registry over a staging root that does not exist (no job dirs).
fn test_jobs() -> RestoreJobs {
    RestoreJobs::new(std::path::PathBuf::from(
        "/nonexistent/viaticum-test/restore",
    ))
}

async fn make_test_state() -> Arc<DaemonState> {
    make_test_state_with(std::path::PathBuf::from("/tmp"), 0, 0).await
}

async fn make_test_state_with(
    data_dir: std::path::PathBuf,
    soft_quota_bytes: u64,
    disk_reserve_bytes: u64,
) -> Arc<DaemonState> {
    let db = Db::open_in_memory().expect("in-memory db");
    let device_id = DeviceId([0u8; 32]);

    let master_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let identity_pub = IdentityPub(master_key.verifying_key().to_bytes());

    let (restore_tx, _restore_rx) = mpsc::channel::<crate::daemon::restore::RestoreRequest>(4);

    Arc::new(DaemonState {
        db,
        identity_pub,
        device_id,
        restore_tx,
        restore_jobs: test_jobs(),
        restore_staging: Default::default(),
        cluster_state: None,
        master_key,
        seed: vec![0u8; 64],
        data_dir,
        soft_quota_bytes,
        disk_reserve_bytes,
        hard_quota_bytes: 0,
        time_scale: 1,
        swarm_handle: None,
        watch_admin: None,
        config_admin: None,
        restart_gate: None,
        shutdown_token: tokio_util::sync::CancellationToken::new(),
        peer_backoff: std::sync::Arc::new(crate::daemon::peer_backoff::PeerBackoff::default()),
        mailbox_router: None,
        missing_sources: Default::default(),
        max_file_size_bytes: 0,
    })
}

// ============================================================
// Unit tests for dispatch
// ============================================================

#[tokio::test]
async fn dispatch_status_returns_status_response() {
    let state = make_test_state().await;
    let response = dispatch(CliRequest::Status, &state).await;
    assert!(matches!(response, CliResponse::Status(_)));
}

#[tokio::test]
async fn dispatch_status_identity_reflects_state() {
    let state = make_test_state().await;
    let response = dispatch(CliRequest::Status, &state).await;
    let CliResponse::Status(data) = response else {
        panic!("expected Status");
    };
    // Identity = master_key.verifying_key() hex (64 chars for 32 bytes).
    assert_eq!(data.node_identity.len(), 64);
    // Must match state.identity_pub which equals network.identity_pub (both from master_key).
    let expected = viaticum_core::types::hex_encode(
        &IdentityPub(
            ed25519_dalek::SigningKey::from_bytes(&[1u8; 32])
                .verifying_key()
                .to_bytes(),
        )
        .0,
    );
    assert_eq!(data.node_identity, expected);
}

#[tokio::test]
async fn dispatch_files_returns_files_response() {
    let state = make_test_state().await;
    let response = dispatch(CliRequest::Files { path_prefix: None }, &state).await;
    assert!(matches!(response, CliResponse::Files(_)));
}

#[tokio::test]
async fn dispatch_files_empty_db_returns_empty_list() {
    let state = make_test_state().await;
    let response = dispatch(CliRequest::Files { path_prefix: None }, &state).await;
    let CliResponse::Files(entries) = response else {
        panic!("expected Files");
    };
    assert!(entries.is_empty());
}

/// Insert a single-version file backed by one source block with the given
/// reliability fields. Used by the is_safe_to_delete tests.
fn insert_file_with_block(
    state: &DaemonState,
    path: &str,
    current_reliability: f64,
    target_reliability: f64,
    backed_up: bool,
) {
    use viaticum_core::types::{
        FileId, FileRecord, FileVersion, LocalState, SourceBlockId, SourceBlockRecord,
        SourceBlockStatus, SourceBlockType, Timestamp,
    };
    let block_id = SourceBlockId([7u8; 32]);
    let block = SourceBlockRecord {
        seal_generation: 0,
        block_id,
        k: 4,
        t: 1024,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(0),
        encrypted_size: Some(4096),
        n: Some(8),
        overhead: Some(1.5),
        drop_notice_sent_at: None,
        importance: 0.5,
        current_alive: 8,
        current_reliability,
        target_reliability,
    };
    state.db.upsert_source_block(&block).unwrap();
    let file = FileRecord {
        file_id: FileId(1),
        path: path.to_string(),
        importance: 0.5,
        devices: vec![(DeviceId([0u8; 32]), LocalState::Present)],
        versions: vec![FileVersion {
            content_hash: [0u8; 32],
            source_block_id: block_id,
            k: 4,
            t: 1024,
            created_at: Timestamp(0),
            backed_up_at: if backed_up { Some(Timestamp(1)) } else { None },
        }],
        first_seen: Timestamp(0),
        on_disk_confirmed: true,
    };
    state.db.upsert_file(&file).unwrap();
}

async fn safe_to_delete_flag(state: &DaemonState, path: &str) -> bool {
    let CliResponse::Files(entries) =
        dispatch(CliRequest::Files { path_prefix: None }, state).await
    else {
        panic!("expected Files");
    };
    entries
        .iter()
        .find(|e| e.path == path)
        .expect("file entry present")
        .is_safe_to_delete
}

#[tokio::test]
async fn dispatch_files_is_safe_to_delete_when_block_at_target() {
    let state = make_test_state().await;
    insert_file_with_block(&state, "doc.pdf", 0.99, 0.95, true);
    assert!(
        safe_to_delete_flag(&state, "doc.pdf").await,
        "current_reliability >= target → safe to delete local copy"
    );
}

#[tokio::test]
async fn dispatch_files_not_safe_to_delete_when_below_target() {
    let state = make_test_state().await;
    insert_file_with_block(&state, "doc.pdf", 0.50, 0.95, true);
    assert!(
        !safe_to_delete_flag(&state, "doc.pdf").await,
        "block below reliability target → not safe"
    );
}

#[tokio::test]
async fn dispatch_files_not_safe_to_delete_when_not_backed_up() {
    let state = make_test_state().await;
    insert_file_with_block(&state, "doc.pdf", 0.99, 0.95, false);
    assert!(
        !safe_to_delete_flag(&state, "doc.pdf").await,
        "version not backed up yet → not safe"
    );
}

#[tokio::test]
async fn dispatch_versions_unknown_path_returns_empty_list() {
    let state = make_test_state().await;
    let response = dispatch(
        CliRequest::Versions {
            path: "photos/nonexistent.jpg".into(),
        },
        &state,
    )
    .await;
    let CliResponse::Versions(entries) = response else {
        panic!("expected Versions");
    };
    assert!(entries.is_empty());
}

#[tokio::test]
async fn dispatch_device_revoke_no_cluster_returns_error() {
    let state = make_test_state().await;
    let id = "aa".repeat(16);
    let request = CliRequest::DeviceRevoke {
        device_id_hex: id.clone(),
    };
    let response = dispatch(request, &state).await;
    // Without cluster_state, revoke returns an error.
    assert!(matches!(response, CliResponse::Error(_)));
}

/// Revocation via mailbox only (relay board retired in T-13b-3).
///
/// With no storage-relationship peers (no placements, no holdings) and no router,
/// revocation still succeeds but publishes to 0 mailbox targets (best-effort).
#[tokio::test]
async fn dispatch_device_revoke_returns_device_revoked_with_no_router() {
    use std::sync::{Arc, Mutex};

    use viaticum_core::cluster::{
        ClusterState, derive_device_key, issue_device_certificate, master_identity,
    };
    use viaticum_core::types::{DeviceId, Timestamp};

    // Build two devices: A (this device), B (to be revoked).
    let seed_a = [10u8; 32];
    let master_key = viaticum_core::cluster::derive_master_key(&seed_a).unwrap();
    let identity_pub = master_identity(&master_key);

    let device_id_a = DeviceId([0xA0u8; 32]);
    let device_id_b = DeviceId([0xB0u8; 32]);

    let _dev_key_a = derive_device_key(&seed_a, &device_id_a.0).unwrap();
    let _dev_key_b = derive_device_key(&seed_a, &device_id_b.0).unwrap();

    let now = Timestamp(1_000_000);
    let cert_a = issue_device_certificate(&master_key, device_id_a, now);
    let cert_b = issue_device_certificate(&master_key, device_id_b, now);

    let db = viaticum_core::db::Db::open_in_memory().unwrap();
    let mut cs = ClusterState::init(db.clone(), identity_pub, cert_a.clone(), now, now).unwrap();
    cs.add_device(cert_b.clone(), now).unwrap();
    let cluster_state = Arc::new(Mutex::new(cs));

    let (restore_tx, _restore_rx) = mpsc::channel::<crate::daemon::restore::RestoreRequest>(4);

    let state = Arc::new(DaemonState {
        db,
        identity_pub,
        device_id: device_id_a,
        restore_tx,
        restore_jobs: test_jobs(),
        restore_staging: Default::default(),
        cluster_state: Some(cluster_state),
        master_key,
        seed: seed_a.to_vec(),
        data_dir: std::path::PathBuf::from("/tmp"),
        soft_quota_bytes: 0,
        disk_reserve_bytes: 0,
        hard_quota_bytes: 0,
        time_scale: 1,
        swarm_handle: None,
        watch_admin: None,
        config_admin: None,
        restart_gate: None,
        shutdown_token: tokio_util::sync::CancellationToken::new(),
        peer_backoff: std::sync::Arc::new(crate::daemon::peer_backoff::PeerBackoff::default()),
        mailbox_router: None, // no router → revocation goes nowhere (best-effort)
        missing_sources: Default::default(),
        max_file_size_bytes: 0,
    });

    // Revoke device B.
    let device_b_hex: String = device_id_b.0.iter().map(|b| format!("{b:02x}")).collect();
    let response = dispatch(
        CliRequest::DeviceRevoke {
            device_id_hex: device_b_hex.clone(),
        },
        &state,
    )
    .await;

    assert!(
        matches!(response, CliResponse::DeviceRevoked { .. }),
        "expected DeviceRevoked, got {response:?}"
    );
}

#[tokio::test]
async fn dispatch_versions_returns_versions_response() {
    let state = make_test_state().await;
    let request = CliRequest::Versions {
        path: "photos/img.jpg".into(),
    };
    let response = dispatch(request, &state).await;
    assert!(matches!(response, CliResponse::Versions(_)));
}

#[tokio::test]
async fn dispatch_device_list_returns_device_list_response() {
    let state = make_test_state().await;
    let response = dispatch(CliRequest::DeviceList, &state).await;
    // No cluster state → empty list (not an error).
    assert!(matches!(response, CliResponse::DeviceList(_)));
}

#[tokio::test]
async fn dispatch_device_list_empty_when_no_cluster() {
    let state = make_test_state().await;
    let response = dispatch(CliRequest::DeviceList, &state).await;
    let CliResponse::DeviceList(entries) = response else {
        panic!("expected DeviceList");
    };
    assert!(entries.is_empty());
}

#[tokio::test]
async fn dispatch_device_add_no_cluster_returns_error() {
    let state = make_test_state().await;
    let response = dispatch(
        CliRequest::DeviceAdd {
            label: "my-laptop".into(),
        },
        &state,
    )
    .await;
    // Without cluster_state, add returns an error.
    assert!(matches!(response, CliResponse::Error(_)));
}

#[tokio::test]
async fn dispatch_connect_invalid_addr_returns_error() {
    let state = make_test_state().await;
    let response = dispatch(
        CliRequest::Connect {
            addr: "192.168.1.1:12345".to_string(),
        },
        &state,
    )
    .await;
    assert!(
        matches!(response, CliResponse::Error(_)),
        "expected Error for invalid addr format, got {response:?}"
    );
}

#[tokio::test]
async fn dispatch_connect_valid_addr_but_unreachable_returns_error() {
    let state = make_test_state().await;

    let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let node_id_bytes = sk.verifying_key().to_bytes();
    let node_id_hex: String = node_id_bytes.iter().map(|b| format!("{b:02x}")).collect();

    // Port 1 is almost certainly not listening; this will fail at iroh connect.
    let addr = format!("{node_id_hex}@127.0.0.1:1");

    let response = dispatch(CliRequest::Connect { addr }, &state).await;
    assert!(
        matches!(response, CliResponse::Error(_)),
        "expected Error for unreachable peer, got {response:?}"
    );
}

// dispatch_connect_two_daemons_registers_peer removed in ε.5 (iroh removal).
// The libp2p equivalent test should be in swarm_tests.rs.

// ============================================================
// Wave 12 ATDD: importance bucket tests
// ============================================================

use viaticum_core::types::{
    SourceBlockId, SourceBlockRecord, SourceBlockStatus, SourceBlockType, Timestamp as Ts,
};

fn make_block(
    id: u8,
    importance: f64,
    reliability: f64,
    status: SourceBlockStatus,
) -> SourceBlockRecord {
    SourceBlockRecord {
        seal_generation: 0,
        block_id: SourceBlockId([id; 32]),
        k: 10,
        t: 64,
        block_type: SourceBlockType::Single,
        status,
        created_at: Ts(0),
        encrypted_size: None,
        n: None,
        overhead: None,
        drop_notice_sent_at: None,
        importance,
        current_alive: 0,
        current_reliability: reliability,
        target_reliability: 0.0,
    }
}

use super::compute_importance_buckets;

#[test]
fn bucket_for_importance_critical() {
    let block = make_block(1, 0.95, 0.99, SourceBlockStatus::Active);
    let buckets = compute_importance_buckets(&[block]);
    let crit = buckets.iter().find(|b| b.bucket == "critical").unwrap();
    assert_eq!(crit.block_count, 1);
}

#[test]
fn bucket_for_importance_high() {
    let block = make_block(1, 0.75, 0.99, SourceBlockStatus::Active);
    let buckets = compute_importance_buckets(&[block]);
    let high = buckets.iter().find(|b| b.bucket == "high").unwrap();
    assert_eq!(high.block_count, 1);
    let crit = buckets.iter().find(|b| b.bucket == "critical").unwrap();
    assert_eq!(crit.block_count, 0);
}

#[test]
fn bucket_for_importance_medium() {
    let block = make_block(1, 0.50, 0.99, SourceBlockStatus::Active);
    let buckets = compute_importance_buckets(&[block]);
    let med = buckets.iter().find(|b| b.bucket == "medium").unwrap();
    assert_eq!(med.block_count, 1);
}

#[test]
fn bucket_for_importance_low() {
    let block = make_block(1, 0.20, 0.93, SourceBlockStatus::Active);
    let buckets = compute_importance_buckets(&[block]);
    let low = buckets.iter().find(|b| b.bucket == "low").unwrap();
    assert_eq!(low.block_count, 1);
}

#[test]
fn bucket_for_importance_trivial() {
    let block = make_block(1, 0.05, 0.78, SourceBlockStatus::Active);
    let buckets = compute_importance_buckets(&[block]);
    let triv = buckets.iter().find(|b| b.bucket == "trivial").unwrap();
    assert_eq!(triv.block_count, 1);
}

#[test]
fn bucket_for_importance_boundary_critical() {
    // importance = 0.90 exactly → critical (>= 0.90)
    let block = make_block(1, 0.90, 0.99, SourceBlockStatus::Active);
    let buckets = compute_importance_buckets(&[block]);
    let crit = buckets.iter().find(|b| b.bucket == "critical").unwrap();
    assert_eq!(crit.block_count, 1, "0.90 must be in critical");
    let high = buckets.iter().find(|b| b.bucket == "high").unwrap();
    assert_eq!(high.block_count, 0);
}

#[test]
fn bucket_for_importance_boundary_high() {
    // importance = 0.70 exactly → high (>= 0.70, < 0.90)
    let block = make_block(1, 0.70, 0.99, SourceBlockStatus::Active);
    let buckets = compute_importance_buckets(&[block]);
    let high = buckets.iter().find(|b| b.bucket == "high").unwrap();
    assert_eq!(high.block_count, 1, "0.70 must be in high");
    let crit = buckets.iter().find(|b| b.bucket == "critical").unwrap();
    assert_eq!(crit.block_count, 0);
}

#[test]
fn bucket_for_importance_boundary_medium() {
    // importance = 0.40 exactly → medium
    let block = make_block(1, 0.40, 0.99, SourceBlockStatus::Active);
    let buckets = compute_importance_buckets(&[block]);
    let med = buckets.iter().find(|b| b.bucket == "medium").unwrap();
    assert_eq!(med.block_count, 1, "0.40 must be in medium");
    let high = buckets.iter().find(|b| b.bucket == "high").unwrap();
    assert_eq!(high.block_count, 0);
}

#[test]
fn bucket_for_importance_boundary_low() {
    // importance = 0.10 exactly → low
    let block = make_block(1, 0.10, 0.93, SourceBlockStatus::Active);
    let buckets = compute_importance_buckets(&[block]);
    let low = buckets.iter().find(|b| b.bucket == "low").unwrap();
    assert_eq!(low.block_count, 1, "0.10 must be in low");
    let triv = buckets.iter().find(|b| b.bucket == "trivial").unwrap();
    assert_eq!(triv.block_count, 0);
}

#[test]
fn bucket_for_importance_at_zero() {
    // importance = 0.0 (pre-migration sentinel) → trivial
    let block = make_block(1, 0.0, 0.0, SourceBlockStatus::Active);
    let buckets = compute_importance_buckets(&[block]);
    let triv = buckets.iter().find(|b| b.bucket == "trivial").unwrap();
    assert_eq!(triv.block_count, 1, "0.0 must be in trivial");
}

#[test]
fn aggregate_returns_all_five_buckets_even_when_empty() {
    let buckets = compute_importance_buckets(&[]);
    assert_eq!(buckets.len(), 5, "must always return 5 buckets");
    let expected_order = ["critical", "high", "medium", "low", "trivial"];
    for (i, name) in expected_order.iter().enumerate() {
        assert_eq!(buckets[i].bucket, *name, "bucket order must be fixed");
        assert_eq!(buckets[i].block_count, 0);
        assert_eq!(buckets[i].status, "empty");
        assert!((buckets[i].mean_p_recoverable - 0.0).abs() < 1e-12);
        assert!(
            buckets[i].target_p > 0.0,
            "target_p must be non-zero even for empty bucket"
        );
    }
}

#[test]
fn aggregate_sums_block_counts_to_active_total() {
    let blocks = vec![
        // 2 per bucket (Active)
        make_block(1, 0.95, 0.99, SourceBlockStatus::Active),
        make_block(2, 0.91, 0.99, SourceBlockStatus::Active),
        make_block(3, 0.80, 0.99, SourceBlockStatus::Active),
        make_block(4, 0.72, 0.99, SourceBlockStatus::Active),
        make_block(5, 0.55, 0.99, SourceBlockStatus::Active),
        make_block(6, 0.42, 0.99, SourceBlockStatus::Active),
        make_block(7, 0.25, 0.93, SourceBlockStatus::Active),
        make_block(8, 0.15, 0.93, SourceBlockStatus::Active),
        make_block(9, 0.05, 0.78, SourceBlockStatus::Active),
        make_block(10, 0.01, 0.78, SourceBlockStatus::Active),
        // 3 Stale — should not count
        make_block(11, 0.95, 0.0, SourceBlockStatus::Stale),
        make_block(12, 0.50, 0.0, SourceBlockStatus::Stale),
        make_block(13, 0.20, 0.0, SourceBlockStatus::Stale),
    ];
    let buckets = compute_importance_buckets(&blocks);
    let total: u32 = buckets.iter().map(|b| b.block_count).sum();
    assert_eq!(
        total, 10,
        "sum of block_count must equal Active block count"
    );
}

#[test]
fn aggregate_status_healthy_when_mean_p_above_target() {
    // medium bucket: midpoint=0.55, target_p = target_reliability(0.55) ≈ 0.9987
    // Use 0.9999 to ensure clearly above target → status = "healthy".
    let blocks = vec![
        make_block(1, 0.55, 0.9999, SourceBlockStatus::Active),
        make_block(2, 0.55, 0.9999, SourceBlockStatus::Active),
    ];
    let buckets = compute_importance_buckets(&blocks);
    let med = buckets.iter().find(|b| b.bucket == "medium").unwrap();
    assert_eq!(
        med.status, "healthy",
        "mean 0.9999 should be >= target_p for medium bucket"
    );
}

#[test]
fn aggregate_status_degraded_when_mean_p_below_target() {
    // critical bucket: midpoint=0.95, target_p ≈ 0.99998
    // current_reliability=0.90 << 0.99998 → degraded
    let blocks = vec![
        make_block(1, 0.95, 0.90, SourceBlockStatus::Active),
        make_block(2, 0.95, 0.90, SourceBlockStatus::Active),
        make_block(3, 0.95, 0.90, SourceBlockStatus::Active),
    ];
    let buckets = compute_importance_buckets(&blocks);
    let crit = buckets.iter().find(|b| b.bucket == "critical").unwrap();
    assert_eq!(crit.status, "degraded");
}

#[test]
fn aggregate_handles_zero_blocks_per_bucket_gracefully() {
    // Only critical bucket has blocks
    let blocks = vec![
        make_block(1, 0.95, 0.99, SourceBlockStatus::Active),
        make_block(2, 0.91, 0.99, SourceBlockStatus::Active),
    ];
    let buckets = compute_importance_buckets(&blocks);
    let crit = buckets.iter().find(|b| b.bucket == "critical").unwrap();
    assert_eq!(crit.block_count, 2);

    for name in &["high", "medium", "low", "trivial"] {
        let b = buckets.iter().find(|b| b.bucket == *name).unwrap();
        assert_eq!(b.block_count, 0, "{name} should be empty");
        assert_eq!(b.status, "empty");
        // No NaN
        assert!(!b.mean_p_recoverable.is_nan());
        assert!(!b.target_p.is_nan());
    }
}

#[test]
fn aggregate_mean_is_arithmetic_mean_not_weighted() {
    // low bucket: 2 blocks with reliabilities 0.90 and 0.80 → mean = 0.85
    let blocks = vec![
        make_block(1, 0.20, 0.90, SourceBlockStatus::Active),
        make_block(2, 0.25, 0.80, SourceBlockStatus::Active),
    ];
    let buckets = compute_importance_buckets(&blocks);
    let low = buckets.iter().find(|b| b.bucket == "low").unwrap();
    assert!(
        (low.mean_p_recoverable - 0.85).abs() < 1e-9,
        "mean should be 0.85, got {}",
        low.mean_p_recoverable
    );
}

#[test]
fn aggregate_excludes_stale_and_deleting_blocks() {
    let blocks = vec![
        make_block(1, 0.95, 0.99, SourceBlockStatus::Active),
        make_block(2, 0.95, 0.99, SourceBlockStatus::Stale),
        make_block(3, 0.95, 0.99, SourceBlockStatus::Deleting),
    ];
    let buckets = compute_importance_buckets(&blocks);
    let crit = buckets.iter().find(|b| b.bucket == "critical").unwrap();
    assert_eq!(crit.block_count, 1, "only Active block should be counted");
}

#[tokio::test]
async fn api_status_response_includes_by_importance_field() {
    let state = make_test_state().await;

    // Insert 3 Active blocks with distinct importance values
    let blocks = vec![
        make_block(1, 0.95, 0.99, SourceBlockStatus::Active),
        make_block(2, 0.50, 0.99, SourceBlockStatus::Active),
        make_block(3, 0.20, 0.93, SourceBlockStatus::Active),
    ];
    for b in &blocks {
        state.db.upsert_source_block(b).unwrap();
    }

    let response = dispatch(CliRequest::Status, &state).await;
    let CliResponse::Status(data) = response else {
        panic!("expected Status");
    };
    assert!(
        !data.by_importance.is_empty(),
        "by_importance must be present"
    );
    assert_eq!(data.by_importance.len(), 5, "must return exactly 5 buckets");
}

#[tokio::test]
async fn api_status_backward_compat_existing_fields_preserved() {
    let state = make_test_state().await;

    let response = dispatch(CliRequest::Status, &state).await;
    let CliResponse::Status(data) = response else {
        panic!("expected Status");
    };
    // Existing fields must still be present and sensible
    assert_eq!(data.peer_count, 0);
    assert_eq!(data.backed_up_files, 0);
    assert_eq!(data.blocks_ok, 0);
    assert_eq!(data.blocks_at_risk, 0);
    // by_importance must also be present
    assert_eq!(data.by_importance.len(), 5);
}

#[tokio::test]
async fn status_response_by_importance_has_five_buckets_in_fixed_order() {
    let state = make_test_state().await;

    let response = dispatch(CliRequest::Status, &state).await;
    let CliResponse::Status(data) = response else {
        panic!("expected Status");
    };
    let names: Vec<&str> = data
        .by_importance
        .iter()
        .map(|b| b.bucket.as_str())
        .collect();
    assert_eq!(names, ["critical", "high", "medium", "low", "trivial"]);
}

// ─── T-13b-2: Revocation producer tests ──────────────────────────────────────
//
// These tests verify that dispatch_device_revoke:
//   1. Sends directed Revocation entries ONLY to storage-relationship peers
//      (our holders ∪ owners we hold for), NOT to unrelated known peers.
//   2. Deduplicates targets (peer both holder and owner → 1 publish, not 2).
//   3. Does NOT post to the relay board (relay is inert after T-13b-2).

use async_trait::async_trait;
use viaticum_core::messages::{
    MailboxFetchRequest, MailboxFetchResponse, MailboxStoreRequest, MailboxStoreResponse,
};
use viaticum_core::types::{HoldingRecord, HoldingStatus, PeerRecord, SymbolPlacement, Timestamp};

use crate::daemon::mailbox::routing::{MailboxNetworkSender, MailboxRouter};

struct RecordingMailboxSenderD {
    stored: tokio::sync::Mutex<Vec<MailboxStoreRequest>>,
}

impl RecordingMailboxSenderD {
    fn new() -> Self {
        RecordingMailboxSenderD {
            stored: tokio::sync::Mutex::new(vec![]),
        }
    }
}

#[async_trait]
impl MailboxNetworkSender for RecordingMailboxSenderD {
    async fn send_store(
        &self,
        _device: DeviceId,
        req: MailboxStoreRequest,
    ) -> anyhow::Result<MailboxStoreResponse> {
        self.stored.lock().await.push(req.clone());
        Ok(MailboxStoreResponse::Ack {
            msg_id: req.entry.msg_id,
        })
    }

    async fn send_fetch(
        &self,
        _device: DeviceId,
        _req: MailboxFetchRequest,
    ) -> anyhow::Result<MailboxFetchResponse> {
        Ok(MailboxFetchResponse {
            v: 1,
            entries: vec![],
            served_msg_ids: vec![],
        })
    }
}

fn gen_libp2p_device_id() -> DeviceId {
    use libp2p::identity::Keypair;
    let kp = Keypair::generate_ed25519();
    let ed = kp.try_into_ed25519().unwrap();
    DeviceId(ed.public().to_bytes())
}

fn make_router_for_revocation(db: &Db) -> (Arc<MailboxRouter>, Arc<RecordingMailboxSenderD>) {
    // Insert one peer with a valid libp2p DeviceId so candidate set is non-empty.
    let device_id = gen_libp2p_device_id();
    let peer = PeerRecord {
        device_id,
        master_identity: IdentityPub([0xCAu8; 32]),
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: 0.5,
        last_avail_sample: 0,
    };
    db.upsert_peer(&peer).unwrap();
    let sender = Arc::new(RecordingMailboxSenderD::new());
    let router = Arc::new(MailboxRouter::with_sender(
        Arc::clone(&sender) as Arc<dyn MailboxNetworkSender>,
        db.clone(),
    ));
    (router, sender)
}

/// revocation_published_only_to_storage_relationship_peers:
/// Set up M with: a placement on holder H1, a holding owned by O1, AND an
/// unrelated known peer U1 in the peers table with NO storage relationship.
/// Revoke a device → assert directed Revocation entries published to H1's master
/// and O1, but NOT to U1, and NOT to our own master; no relay post.
#[tokio::test]
async fn revocation_published_only_to_storage_relationship_peers() {
    use std::sync::{Arc as StdArc, Mutex};
    use viaticum_core::cluster::{ClusterState, issue_device_certificate, master_identity};
    use viaticum_core::mailbox::MailboxClass;

    // Build our master and a device to revoke.
    let seed = [0xA1u8; 32];
    let master_key = viaticum_core::cluster::derive_master_key(&seed).unwrap();
    let our_master = master_identity(&master_key);
    let our_device_id = DeviceId([0xA1u8; 32]);
    let revoked_device_id = DeviceId([0xA2u8; 32]);

    let now = Timestamp(1_000_000);
    let cert_a = issue_device_certificate(&master_key, our_device_id, now);
    let cert_r = issue_device_certificate(&master_key, revoked_device_id, now);

    let db = Db::open_in_memory().expect("db");

    let mut cs = ClusterState::init(db.clone(), our_master, cert_a.clone(), now, now).unwrap();
    cs.add_device(cert_r.clone(), now).unwrap();
    let cluster_state = StdArc::new(Mutex::new(cs));

    // H1: holder master + device. We have a placement on H1.
    let h1_key = ed25519_dalek::SigningKey::from_bytes(&[0xB1u8; 32]);
    let h1_master = IdentityPub(h1_key.verifying_key().to_bytes());
    let h1_device = gen_libp2p_device_id();
    {
        let h1_peer = PeerRecord {
            device_id: h1_device,
            master_identity: h1_master,
            trust_p: 0.5,
            trust_i: 0.0,
            trust_s: 1.0,
            bytes_we_store_for_peer: 0,
            bytes_peer_stores_for_us: 0,
            first_seen: Timestamp(0),
            last_seen: Timestamp(0),
            revoked_device_pub_keys: vec![],
            addrs: vec![],
            x25519_pub: None,
            avail_ewma: 0.5,
            last_avail_sample: 0,
        };
        db.upsert_peer(&h1_peer).unwrap();
        db.set_master_for_device(&h1_device, &h1_master).unwrap();
    }
    // Insert placement: our data held by H1.
    let placement = SymbolPlacement {
        source_block_id: SourceBlockId([0x01u8; 32]),
        holder_id: h1_device,
        file_id: viaticum_core::types::FileId(1),
        esi_ranges: vec![(0, 5)],
        binding_seed: [0u8; 32],
        status: viaticum_core::types::PlacementStatus::Alive,
        last_verified: None,
        placed_at: now,
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).unwrap();

    // O1: owner master. We hold O1's data.
    let o1_master = IdentityPub([0xC1u8; 32]);
    let o1_holding = HoldingRecord {
        source_block_id: SourceBlockId([0x02u8; 32]),
        owner_id: o1_master,
        esi_ranges: vec![(0, 5)],
        importance: 0.5,
        total_bytes: 512,
        status: HoldingStatus::Active,
        received_at: now,
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    db.upsert_holding(&o1_holding).unwrap();

    // U1: unrelated peer, NOT a holder and NOT an owner.
    // Insert it just as a known peer (no placements, no holdings).
    let u1_master = IdentityPub([0xD1u8; 32]);
    let u1_device = gen_libp2p_device_id();
    {
        let u1_peer = PeerRecord {
            device_id: u1_device,
            master_identity: u1_master,
            trust_p: 0.5,
            trust_i: 0.0,
            trust_s: 1.0,
            bytes_we_store_for_peer: 0,
            bytes_peer_stores_for_us: 0,
            first_seen: Timestamp(0),
            last_seen: Timestamp(0),
            revoked_device_pub_keys: vec![],
            addrs: vec![],
            x25519_pub: None,
            avail_ewma: 0.5,
            last_avail_sample: 0,
        };
        db.upsert_peer(&u1_peer).unwrap();
        db.set_master_for_device(&u1_device, &u1_master).unwrap();
    }

    let (restore_tx, _restore_rx) = mpsc::channel::<crate::daemon::restore::RestoreRequest>(4);

    let (router, sender) = make_router_for_revocation(&db);

    let state = Arc::new(DaemonState {
        db,
        identity_pub: our_master,
        device_id: our_device_id,
        restore_tx,
        restore_jobs: test_jobs(),
        restore_staging: Default::default(),
        cluster_state: Some(cluster_state),
        master_key,
        seed: seed.to_vec(),
        data_dir: std::path::PathBuf::from("/tmp"),
        soft_quota_bytes: 0,
        disk_reserve_bytes: 0,
        hard_quota_bytes: 0,
        time_scale: 1,
        swarm_handle: None,
        watch_admin: None,
        config_admin: None,
        restart_gate: None,
        shutdown_token: tokio_util::sync::CancellationToken::new(),
        peer_backoff: std::sync::Arc::new(crate::daemon::peer_backoff::PeerBackoff::default()),
        mailbox_router: Some(router),
        missing_sources: Default::default(),
        max_file_size_bytes: 0,
    });

    // Revoke device.
    let revoked_hex: String = revoked_device_id
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let response = dispatch(
        CliRequest::DeviceRevoke {
            device_id_hex: revoked_hex.clone(),
        },
        &state,
    )
    .await;
    assert!(
        matches!(response, CliResponse::DeviceRevoked { .. }),
        "must be DeviceRevoked"
    );

    // Drain all mailbox store requests.
    let stored = sender.stored.lock().await;
    let targets: std::collections::HashSet<_> = stored
        .iter()
        .map(|r| IdentityPub(r.entry.target.0))
        .collect();

    // Must include H1's master and O1's master.
    assert!(
        targets.contains(&h1_master),
        "H1 master must be a revocation target"
    );
    assert!(
        targets.contains(&o1_master),
        "O1 master must be a revocation target"
    );
    // Must NOT include U1 (no storage relationship).
    assert!(
        !targets.contains(&u1_master),
        "U1 must NOT be a revocation target (no storage relationship)"
    );
    // Must NOT include our own master.
    assert!(
        !targets.contains(&our_master),
        "our own master must NOT be a revocation target"
    );

    // All entries must have Revocation class.
    for req in stored.iter() {
        assert_eq!(
            req.entry.class,
            MailboxClass::Revocation,
            "all entries must be Revocation class"
        );
    }
}

/// revocation_dedup_peer_is_holder_and_owner:
/// A peer that is BOTH a holder (we have a placement) AND an owner-we-hold-for
/// must result in exactly one Revocation publish, not two.
#[tokio::test]
async fn revocation_dedup_peer_is_holder_and_owner() {
    use std::sync::{Arc as StdArc, Mutex};
    use viaticum_core::cluster::{ClusterState, issue_device_certificate, master_identity};

    let seed = [0xF1u8; 32];
    let master_key = viaticum_core::cluster::derive_master_key(&seed).unwrap();
    let our_master = master_identity(&master_key);
    let our_device_id = DeviceId([0xF1u8; 32]);
    let revoked_device_id = DeviceId([0xF2u8; 32]);

    let now = Timestamp(1_000_000);
    let cert_a = issue_device_certificate(&master_key, our_device_id, now);
    let cert_r = issue_device_certificate(&master_key, revoked_device_id, now);

    let db = Db::open_in_memory().expect("db");
    let mut cs = ClusterState::init(db.clone(), our_master, cert_a.clone(), now, now).unwrap();
    cs.add_device(cert_r.clone(), now).unwrap();
    let cluster_state = StdArc::new(Mutex::new(cs));

    // Dual peer P: BOTH a holder of our data AND an owner we hold for.
    let p_key = ed25519_dalek::SigningKey::from_bytes(&[0xE1u8; 32]);
    let p_master = IdentityPub(p_key.verifying_key().to_bytes());
    let p_device = gen_libp2p_device_id();
    {
        let p_peer = PeerRecord {
            device_id: p_device,
            master_identity: p_master,
            trust_p: 0.5,
            trust_i: 0.0,
            trust_s: 1.0,
            bytes_we_store_for_peer: 0,
            bytes_peer_stores_for_us: 0,
            first_seen: Timestamp(0),
            last_seen: Timestamp(0),
            revoked_device_pub_keys: vec![],
            addrs: vec![],
            x25519_pub: None,
            avail_ewma: 0.5,
            last_avail_sample: 0,
        };
        db.upsert_peer(&p_peer).unwrap();
        db.set_master_for_device(&p_device, &p_master).unwrap();
    }
    // Placement: our data held by P.
    let placement = SymbolPlacement {
        source_block_id: SourceBlockId([0xF3u8; 32]),
        holder_id: p_device,
        file_id: viaticum_core::types::FileId(1),
        esi_ranges: vec![(0, 5)],
        binding_seed: [0u8; 32],
        status: viaticum_core::types::PlacementStatus::Alive,
        last_verified: None,
        placed_at: now,
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).unwrap();
    // Holding: P's data held by us.
    let holding = HoldingRecord {
        source_block_id: SourceBlockId([0xF4u8; 32]),
        owner_id: p_master,
        esi_ranges: vec![(0, 5)],
        importance: 0.5,
        total_bytes: 512,
        status: HoldingStatus::Active,
        received_at: now,
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    db.upsert_holding(&holding).unwrap();

    let (restore_tx, _restore_rx) = mpsc::channel::<crate::daemon::restore::RestoreRequest>(4);

    let (router, sender) = make_router_for_revocation(&db);

    let state = Arc::new(DaemonState {
        db,
        identity_pub: our_master,
        device_id: our_device_id,
        restore_tx,
        restore_jobs: test_jobs(),
        restore_staging: Default::default(),
        cluster_state: Some(cluster_state),
        master_key,
        seed: seed.to_vec(),
        data_dir: std::path::PathBuf::from("/tmp"),
        soft_quota_bytes: 0,
        disk_reserve_bytes: 0,
        hard_quota_bytes: 0,
        time_scale: 1,
        swarm_handle: None,
        watch_admin: None,
        config_admin: None,
        restart_gate: None,
        shutdown_token: tokio_util::sync::CancellationToken::new(),
        peer_backoff: std::sync::Arc::new(crate::daemon::peer_backoff::PeerBackoff::default()),
        mailbox_router: Some(router),
        missing_sources: Default::default(),
        max_file_size_bytes: 0,
    });

    let revoked_hex: String = revoked_device_id
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let response = dispatch(
        CliRequest::DeviceRevoke {
            device_id_hex: revoked_hex,
        },
        &state,
    )
    .await;
    assert!(matches!(response, CliResponse::DeviceRevoked { .. }));

    // Collect unique targets published to.
    let stored = sender.stored.lock().await;
    let targets: Vec<_> = stored
        .iter()
        .map(|r| IdentityPub(r.entry.target.0))
        .collect();
    let target_count = targets.iter().filter(|&&t| t == p_master).count();

    // The router may send to multiple postman devices but with same target in each publish call.
    // We care that unique target masters = 1 (only p_master, not p_master twice from two source paths).
    let unique_masters: std::collections::HashSet<_> = targets.iter().copied().collect();
    assert!(
        unique_masters.contains(&p_master),
        "dual-role peer p_master must be in unique targets"
    );
    // Dedup means p_master appears as a single publish batch target, not twice.
    // The router internally fans out to N postmen per target call — we check that
    // all store requests share the same msg_id (one publish call, not two separate ones).
    let msg_ids: std::collections::HashSet<_> = stored.iter().map(|r| r.entry.msg_id).collect();
    assert_eq!(
        msg_ids.len(),
        1,
        "dedup: dual-role peer should produce exactly 1 unique msg_id publish (1 target, not 2)"
    );
    let _ = target_count; // suppress unused warning
}

#[cfg(any())]
async fn _removed_dispatch_connect_two_daemons_registers_peer() {
    use std::sync::Arc;
    use viaticum_core::cluster::{
        derive_device_key, derive_master_key, issue_device_certificate, master_identity,
    };
    use viaticum_core::db::Db;
    use viaticum_core::types::{DeviceId, Timestamp};

    let seed_a = [1u8; 32];
    let seed_b = [2u8; 32];
    let master_a = derive_master_key(&seed_a).unwrap();
    let master_b = derive_master_key(&seed_b).unwrap();
    let pk_a = master_identity(&master_a);
    let pk_b = master_identity(&master_b);

    let did_a = DeviceId([1u8; 32]);
    let did_b = DeviceId([2u8; 32]);
    let device_a = derive_device_key(&seed_a, &did_a).unwrap();
    let device_b = derive_device_key(&seed_b, &did_b).unwrap();

    let cert_a = issue_device_certificate(
        &master_a,
        did_a,
        device_a.verifying_key().to_bytes(),
        Timestamp::now(),
    );
    let cert_b = issue_device_certificate(
        &master_b,
        did_b,
        device_b.verifying_key().to_bytes(),
        Timestamp::now(),
    );

    let (tx_b, _rx_b) = mpsc::channel::<crate::daemon::network::connection::Connection>(4);
    let handle_b = Arc::new(
        NetworkHandle::start(
            NetworkConfig {
                signing_key: device_b.clone(),
                master_signing_key: device_b,
                master_identity: pk_b,
                known_peers: Default::default(),
                device_cert: Some(cert_b),
                iroh_secret_key: None,
                relay_mode: RelayMode::Disabled,
                x25519_pub: None,
            },
            tx_b,
        )
        .await
        .expect("handle_b"),
    );
    let addr_b_endpoint = handle_b.local_addr().expect("addr_b");
    let socket_addr_b = addr_b_endpoint
        .ip_addrs()
        .next()
        .copied()
        .expect("B must have a local IP addr");
    let addr_b_str =
        crate::daemon::network::addr::format_node_addr(&handle_b.node_id, socket_addr_b, None);

    let db_a = Db::open_in_memory().expect("db_a");
    let (tx_a, _rx_a) = mpsc::channel::<crate::daemon::network::connection::Connection>(4);
    let tx_a_for_state = tx_a.clone();
    let handle_a = Arc::new(
        NetworkHandle::start(
            NetworkConfig {
                signing_key: device_a.clone(),
                master_signing_key: device_a,
                master_identity: pk_a,
                known_peers: Default::default(),
                device_cert: Some(cert_a),
                iroh_secret_key: None,
                relay_mode: RelayMode::Disabled,
                x25519_pub: None,
            },
            tx_a,
        )
        .await
        .expect("handle_a"),
    );
    let (restore_tx, _restore_rx) = mpsc::channel::<crate::daemon::restore::RestoreRequest>(4);
    let state_a = Arc::new(DaemonState {
        db: db_a.clone(),
        identity_pub: pk_a,
        device_id: did_a,
        network: handle_a.clone(),
        restore_tx,
        restore_jobs: test_jobs(),
        restore_staging: Default::default(),
        cluster_state: None,
        incoming_tx: tx_a_for_state,
        master_key: master_a,
        seed: vec![0u8; 64],
        data_dir: std::path::PathBuf::from("/tmp"),
        soft_quota_bytes: 0,
        disk_reserve_bytes: 0,
        hard_quota_bytes: 0,
        time_scale: 1,
        swarm_handle: None,
        watch_admin: None,
        config_admin: None,
        restart_gate: None,
        shutdown_token: tokio_util::sync::CancellationToken::new(),
    });

    let response = dispatch(CliRequest::Connect { addr: addr_b_str }, &state_a).await;

    let CliResponse::Connected { peer_id } = response else {
        panic!("expected Connected, got {response:?}");
    };
    // Connected peer_id should be B's master identity (from cert).
    let expected_hex: String = pk_b.0.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        peer_id, expected_hex,
        "peer_id should be B's master identity hex"
    );

    // Peer should be stored under master identity.
    let stored = db_a
        .get_peer(&pk_b)
        .expect("db get_peer")
        .expect("peer in db");
    assert_eq!(stored.identity, pk_b);
    assert!(!stored.addrs.is_empty(), "addr should be stored");

    let _ = handle_a
        .get_connection(pk_b)
        .await
        .expect("get_connection after connect");
}

// ============================================================
// R1-e1 (repair-i3): one tolerance-aware "at target"
// ============================================================

#[tokio::test]
async fn dispatch_files_is_safe_to_delete_at_float_boundary_of_target() {
    // Five full copies at p = 0.9 compute to 0.9999899999999999 in f64, one ulp under
    // target_reliability(1.0): mathematically at target, and shown as such.
    let state = make_test_state().await;
    let target = viaticum_core::reliability::target_reliability(1.0);
    insert_file_with_block(&state, "notes.txt", 0.9999899999999999, target, true);
    assert!(safe_to_delete_flag(&state, "notes.txt").await);
}

#[test]
fn importance_bucket_is_healthy_at_float_boundary() {
    // The spec's example (importance 1.0 at 0.9999899999999999) is healthy even with a
    // raw `>=`: the critical bucket's target is target(0.95) ≈ 0.999982. The float
    // boundary of a bucket is its own target: one ulp below it must read "healthy".
    for (importance, bucket) in [(1.0, "critical"), (0.55, "medium")] {
        let midpoint = if bucket == "critical" { 0.95 } else { 0.55 };
        let target = viaticum_core::reliability::target_reliability(midpoint);
        let one_ulp_below = f64::from_bits(target.to_bits() - 1);
        let block = make_block(1, importance, one_ulp_below, SourceBlockStatus::Active);
        let buckets = compute_importance_buckets(&[block]);
        let b = buckets.iter().find(|b| b.bucket == bucket).unwrap();
        assert_eq!(b.status, "healthy", "{bucket}");
    }
}

// ============================================================
// restore-i8 / i18 / i19: cached restore staging status in status
// ============================================================

fn staging_test_state(
    data_dir: &std::path::Path,
    restore_tx: mpsc::Sender<RestoreRequest>,
    soft_quota_bytes: u64,
) -> Arc<DaemonState> {
    let master_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    Arc::new(DaemonState {
        db: Db::open_in_memory().unwrap(),
        identity_pub: IdentityPub(master_key.verifying_key().to_bytes()),
        device_id: DeviceId([0u8; 32]),
        restore_tx,
        restore_jobs: test_jobs(),
        restore_staging: Default::default(),
        cluster_state: None,
        master_key,
        seed: vec![0u8; 64],
        data_dir: data_dir.to_path_buf(),
        soft_quota_bytes,
        disk_reserve_bytes: 0,
        hard_quota_bytes: 0,
        time_scale: 1,
        swarm_handle: None,
        watch_admin: None,
        config_admin: None,
        restart_gate: None,
        shutdown_token: tokio_util::sync::CancellationToken::new(),
        peer_backoff: std::sync::Arc::new(crate::daemon::peer_backoff::PeerBackoff::default()),
        mailbox_router: None,
        missing_sources: Default::default(),
        max_file_size_bytes: 0,
    })
}

fn held(total_bytes: u64) -> viaticum_core::types::HoldingRecord {
    viaticum_core::types::HoldingRecord {
        source_block_id: viaticum_core::types::SourceBlockId([9u8; 32]),
        owner_id: IdentityPub([8u8; 32]),
        esi_ranges: vec![(0, 10)],
        importance: 0.5,
        total_bytes,
        status: viaticum_core::types::HoldingStatus::Active,
        received_at: viaticum_core::types::Timestamp(100),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    }
}

/// `status` reports the cached staging status (no disk walk on the request path).
#[tokio::test]
async fn dispatch_status_reports_cached_restore_staging_summary() {
    use crate::daemon::restore::cleanup::{PublishCheck, StagingStatus};
    use crate::daemon::restore::staging::publish::PublishMethod;
    let state = make_test_state().await;
    *state.restore_staging.lock().unwrap() = StagingStatus {
        job_dirs: 3,
        bytes: Some(1234),
        publish: PublishCheck::Works(PublishMethod::RenameNoReplace),
    };
    let CliResponse::Status(data) = dispatch(CliRequest::Status, &state).await else {
        panic!("expected Status");
    };
    assert_eq!(data.restore_staging_jobs, 3);
    assert_eq!(data.restore_staging_bytes, Some(1234));
    assert_eq!(data.restore_staging_path, "/tmp/restore");
    assert_eq!(data.restore_publish, "rename_noreplace");
}

/// W3: before the byte walk finished, `status` says "counting" (None), not 0.
#[tokio::test]
async fn dispatch_status_reports_counting_before_first_byte_walk() {
    use crate::daemon::restore::cleanup::StagingStatus;
    let state = make_test_state().await;
    *state.restore_staging.lock().unwrap() = StagingStatus {
        job_dirs: 2,
        bytes: None,
        ..Default::default()
    };
    let CliResponse::Status(data) = dispatch(CliRequest::Status, &state).await else {
        panic!("expected Status");
    };
    assert_eq!(data.restore_staging_jobs, 2);
    assert_eq!(data.restore_staging_bytes, None);
}

/// restore-i18: holder under disk pressure + non-empty staging → the status flag;
/// no pressure or empty staging → no flag.
#[tokio::test]
async fn dispatch_status_flags_staging_squeezing_holdings_under_pressure() {
    use crate::daemon::restore::cleanup::StagingStatus;
    let data_dir = tempfile::TempDir::new().unwrap();
    let (restore_tx, _rx) = mpsc::channel(1);
    // Quota 1000 bytes, 950 held: free ratio 5 % < 15 % → pressure.
    let state = staging_test_state(data_dir.path(), restore_tx, 1000);
    state.db.upsert_holding(&held(950)).unwrap();

    let status = |bytes: u64| StagingStatus {
        job_dirs: 1,
        bytes: Some(bytes),
        ..Default::default()
    };
    *state.restore_staging.lock().unwrap() = status(5 * 1024 * 1024);
    let CliResponse::Status(data) = dispatch(CliRequest::Status, &state).await else {
        panic!("expected Status");
    };
    assert!(data.restore_staging_squeezes_holdings);

    *state.restore_staging.lock().unwrap() = status(0);
    let CliResponse::Status(data) = dispatch(CliRequest::Status, &state).await else {
        panic!("expected Status");
    };
    assert!(
        !data.restore_staging_squeezes_holdings,
        "empty staging squeezes nothing"
    );

    let (restore_tx, _rx) = mpsc::channel(1);
    let relaxed = staging_test_state(data_dir.path(), restore_tx, 1_000_000);
    relaxed.db.upsert_holding(&held(950)).unwrap();
    *relaxed.restore_staging.lock().unwrap() = status(5 * 1024 * 1024);
    let CliResponse::Status(data) = dispatch(CliRequest::Status, &relaxed).await else {
        panic!("expected Status");
    };
    assert!(
        !data.restore_staging_squeezes_holdings,
        "no pressure, no warning"
    );
}

// ============================================================
// B1.3: restore as a job — submit answers at once (restore-i3, i4)
// ============================================================

/// A catalog record at `path` (one version, backed up or not).
fn catalog_file(path: &str, id: u64, backed_up: bool) -> viaticum_core::types::FileRecord {
    viaticum_core::types::FileRecord {
        file_id: viaticum_core::types::FileId(id),
        path: path.to_string(),
        importance: 0.5,
        devices: vec![],
        versions: vec![viaticum_core::types::FileVersion {
            content_hash: [1u8; 32],
            source_block_id: viaticum_core::types::SourceBlockId([2u8; 32]),
            k: 1,
            t: 64,
            created_at: Ts(10),
            backed_up_at: backed_up.then_some(Ts(20)),
        }],
        first_seen: Ts(0),
        on_disk_confirmed: true,
    }
}

fn restore_req(path: &str) -> CliRequest {
    CliRequest::Restore {
        path: path.into(),
        version: None,
        date: None,
        dest: None,
    }
}

/// State whose restore queue is `rx` (capacity `cap`) and whose registry is `jobs`.
fn job_state(cap: usize) -> (Arc<DaemonState>, mpsc::Receiver<RestoreRequest>) {
    let (tx, rx) = mpsc::channel::<RestoreRequest>(cap);
    let state = staging_test_state(std::path::Path::new("/tmp"), tx, 0);
    (state, rx)
}

#[tokio::test]
async fn dispatch_restore_unknown_path_is_rejected_not_in_catalog_and_creates_no_job() {
    let (state, mut rx) = job_state(4);
    state
        .db
        .upsert_file(&catalog_file("/home/kolya/files/part/b.bin", 1, true))
        .unwrap();
    for path in ["/home/kolya/files/nope.bin", "/home/kolya/files/par"] {
        let response = dispatch(restore_req(path), &state).await;
        assert_eq!(
            response,
            CliResponse::RestoreRejected(RestoreRejection::NotInCatalog { path: path.into() })
        );
    }
    assert!(state.restore_jobs.list().is_empty(), "no job was created");
    assert!(rx.try_recv().is_err(), "nothing was enqueued");
}

#[tokio::test]
async fn dispatch_restore_path_without_backed_up_version_is_rejected_not_backed_up() {
    let (state, mut rx) = job_state(4);
    state
        .db
        .upsert_file(&catalog_file("/home/kolya/new.txt", 1, false))
        .unwrap();
    let response = dispatch(restore_req("/home/kolya/new.txt"), &state).await;
    assert_eq!(
        response,
        CliResponse::RestoreRejected(RestoreRejection::NotBackedUp {
            path: "/home/kolya/new.txt".into()
        })
    );
    assert!(state.restore_jobs.list().is_empty());
    assert!(rx.try_recv().is_err());
}

/// `--version N` outside the backed-up versions is its own refusal naming the
/// versions that are there — never "nothing has a backed-up version yet".
#[tokio::test]
async fn dispatch_restore_unknown_version_is_rejected_version_not_found_with_available() {
    let (state, mut rx) = job_state(4);
    let mut record = catalog_file("/home/kolya/a.txt", 1, true);
    let mut second = record.versions[0].clone();
    second.backed_up_at = None; // version 2 exists but is not backed up
    record.versions.push(second);
    state.db.upsert_file(&record).unwrap();

    for version in [0, 2, 7] {
        let response = dispatch(
            CliRequest::Restore {
                path: "/home/kolya/a.txt".into(),
                version: Some(version),
                date: None,
                dest: None,
            },
            &state,
        )
        .await;
        assert_eq!(
            response,
            CliResponse::RestoreRejected(RestoreRejection::VersionNotFound {
                path: "/home/kolya/a.txt".into(),
                version,
                available: vec![1],
            }),
            "--version {version}"
        );
    }
    assert!(state.restore_jobs.list().is_empty(), "no job was created");
    assert!(rx.try_recv().is_err(), "nothing was enqueued");
}

#[tokio::test]
async fn dispatch_restore_version_when_nothing_backed_up_is_rejected_not_backed_up() {
    let (state, _rx) = job_state(4);
    state
        .db
        .upsert_file(&catalog_file("/home/kolya/new.txt", 1, false))
        .unwrap();
    let response = dispatch(
        CliRequest::Restore {
            path: "/home/kolya/new.txt".into(),
            version: Some(1),
            date: None,
            dest: None,
        },
        &state,
    )
    .await;
    assert_eq!(
        response,
        CliResponse::RestoreRejected(RestoreRejection::NotBackedUp {
            path: "/home/kolya/new.txt".into()
        })
    );
}

/// restore-i4: the answer is the queued job, at once — the request is in the
/// coordinator's queue, nobody waits for the restore itself.
#[tokio::test]
async fn dispatch_restore_known_path_returns_queued_job_and_enqueues_request() {
    let (state, mut rx) = job_state(4);
    state
        .db
        .upsert_file(&catalog_file("/home/kolya/photos/a.jpg", 1, true))
        .unwrap();
    state
        .db
        .upsert_file(&catalog_file("/home/kolya/photos/b.jpg", 2, true))
        .unwrap();

    let response = dispatch(restore_req("/home/kolya/photos"), &state).await;
    let CliResponse::RestoreJob(job) = response else {
        panic!("expected RestoreJob, got {response:?}");
    };
    assert_eq!(job.state, RestoreJobState::Queued);
    assert_eq!(job.files_total, 2);
    assert_eq!(job.path, "/home/kolya/photos");
    let queued = rx.try_recv().expect("request enqueued");
    assert_eq!(queued.job_id.to_string(), job.job_id);
    assert_eq!(queued.path, "/home/kolya/photos");
    assert_eq!(state.restore_jobs.get(queued.job_id), Some(job));
}

#[tokio::test]
async fn dispatch_restore_queue_full_returns_busy_and_rolls_back_job() {
    let (state, _rx) = job_state(1);
    state
        .db
        .upsert_file(&catalog_file("/a.txt", 1, true))
        .unwrap();
    assert!(matches!(
        dispatch(restore_req("/a.txt"), &state).await,
        CliResponse::RestoreJob(_)
    ));
    let response = dispatch(restore_req("/a.txt"), &state).await;
    assert_eq!(
        response,
        CliResponse::RestoreRejected(RestoreRejection::Busy { active: 1 })
    );
    assert_eq!(
        state.restore_jobs.list().len(),
        1,
        "the refused job is rolled back"
    );
}

#[tokio::test]
async fn dispatch_restore_closed_channel_returns_unavailable_and_rolls_back_job() {
    let (state, rx) = job_state(4);
    drop(rx);
    state
        .db
        .upsert_file(&catalog_file("/a.txt", 1, true))
        .unwrap();
    let response = dispatch(restore_req("/a.txt"), &state).await;
    assert_eq!(
        response,
        CliResponse::RestoreRejected(RestoreRejection::Unavailable)
    );
    assert!(state.restore_jobs.list().is_empty());
}

#[tokio::test]
async fn dispatch_restore_with_dest_or_bad_date_is_rejected() {
    let (state, _rx) = job_state(4);
    let response = dispatch(
        CliRequest::Restore {
            path: "/a.txt".into(),
            version: None,
            date: None,
            dest: Some("/tmp/out".into()),
        },
        &state,
    )
    .await;
    assert_eq!(
        response,
        CliResponse::RestoreRejected(RestoreRejection::DestNotSupported)
    );
    let response = dispatch(
        CliRequest::Restore {
            path: "/a.txt".into(),
            version: None,
            date: Some("yesterday".into()),
            dest: None,
        },
        &state,
    )
    .await;
    assert_eq!(
        response,
        CliResponse::RestoreRejected(RestoreRejection::InvalidDate {
            date: "yesterday".into()
        })
    );
}

#[tokio::test]
async fn dispatch_restore_job_status_unknown_id_returns_unknown_job() {
    let (state, _rx) = job_state(4);
    for id in [JobId::new().to_string(), "not-a-job-id".to_string()] {
        let response = dispatch(CliRequest::RestoreJobStatus { job_id: id.clone() }, &state).await;
        assert_eq!(
            response,
            CliResponse::RestoreRejected(RestoreRejection::UnknownJob { job_id: id })
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dispatch_restore_job_status_returns_finished_job_with_failures() {
    let (state, _rx) = job_state(4);
    let id = JobId::new();
    state.restore_jobs.submit(id, "/p/", 2);
    state.restore_jobs.mark_running(id, "/p/", 2);
    state.restore_jobs.record_restored(id, "/p/a");
    state.restore_jobs.record_failure(
        id,
        RestoreFailure {
            path: "/p/b".into(),
            kind: RestoreFailureKind::HoldersUnavailable,
            detail: "collected 1 of 3 symbols".into(),
        },
    );
    state.restore_jobs.finish(id, false);

    let response = dispatch(
        CliRequest::RestoreJobStatus {
            job_id: id.to_string(),
        },
        &state,
    )
    .await;
    let CliResponse::RestoreJob(job) = response else {
        panic!("expected RestoreJob, got {response:?}");
    };
    assert_eq!(job.state, RestoreJobState::Finished);
    assert_eq!(job.outcome, Some(RestoreOutcome::Partial));
    assert_eq!(job.restored_paths, vec!["/p/a".to_string()]);
    assert_eq!(job.failures[0].kind, RestoreFailureKind::HoldersUnavailable);

    let CliResponse::RestoreJobs(list) = dispatch(CliRequest::RestoreJobList, &state).await else {
        panic!("expected RestoreJobs");
    };
    assert_eq!(list, vec![job]);
}

// ============================================================
// DR readiness (dr-i9) and files without a local source (dr-i11)
// ============================================================

fn catalog_file_with_states(
    path: &std::path::Path,
    states: Vec<viaticum_core::types::LocalState>,
) -> viaticum_core::types::FileRecord {
    viaticum_core::types::FileRecord {
        file_id: viaticum_core::types::FileId(1),
        path: path.display().to_string(),
        importance: 0.5,
        devices: states
            .into_iter()
            .enumerate()
            .map(|(i, s)| (DeviceId([i as u8 + 1; 32]), s))
            .collect(),
        versions: vec![],
        first_seen: viaticum_core::types::Timestamp(1),
        on_disk_confirmed: true,
    }
}

#[tokio::test]
async fn status_counts_files_without_source() {
    use viaticum_core::types::LocalState;
    let dir = tempfile::tempdir().unwrap();
    let here = dir.path().join("here.txt");
    std::fs::write(&here, b"x").unwrap();
    let state = make_test_state().await;
    let files = [
        catalog_file_with_states(&here, vec![LocalState::Present]),
        catalog_file_with_states(&dir.path().join("gone-1.txt"), vec![LocalState::Present]),
        catalog_file_with_states(&dir.path().join("gone-2.txt"), vec![LocalState::Present]),
    ];
    for (i, mut f) in files.into_iter().enumerate() {
        f.file_id = viaticum_core::types::FileId(i as u64 + 1);
        state.db.upsert_file(&f).unwrap();
    }
    let CliResponse::Status(data) = dispatch(CliRequest::Status, &state).await else {
        panic!("expected Status");
    };
    assert_eq!(data.files_without_source, 2);
}

#[test]
fn status_ignores_files_deleted_everywhere() {
    use viaticum_core::types::{LocalState, Timestamp};
    let db = Db::open_in_memory().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let files = vec![
        // Deleted on every device: not live, not "missing".
        catalog_file_with_states(
            &dir.path().join("deleted.txt"),
            vec![LocalState::Deleted(Timestamp(5))],
        ),
        // Deleted on one device, present on another: live, missing here.
        catalog_file_with_states(
            &dir.path().join("half.txt"),
            vec![LocalState::Deleted(Timestamp(5)), LocalState::Present],
        ),
    ];
    for (i, mut f) in files.into_iter().enumerate() {
        f.file_id = viaticum_core::types::FileId(i as u64 + 1);
        db.upsert_file(&f).unwrap();
    }
    assert_eq!(
        super::missing_sources::count_files_without_source(&db).unwrap(),
        1
    );
}

#[test]
fn status_reports_not_ready_and_mints_nothing_on_a_fresh_db() {
    let db = Db::open_in_memory().unwrap();
    let r = super::dr_readiness(&db, 1_800_000_000, 1);
    assert_eq!(
        r,
        super::DrReadiness {
            threshold: 1,
            ..super::DrReadiness::default()
        }
    );
    assert_eq!(
        db.catalog_lineage().unwrap(),
        None,
        "status must only read, never mint a history"
    );
}

/// A pointer place record acked by `acks` postmen, for the status tests.
fn place_record(
    base: viaticum_core::types::SourceBlockId,
    at: u64,
    acks: usize,
) -> viaticum_core::system_state::catalog::PlacePublication {
    viaticum_core::system_state::catalog::PlacePublication {
        place: viaticum_core::mailbox::seal::PointerPlace::A,
        base,
        diffs: vec![],
        generation: 3,
        created_at: viaticum_core::types::Timestamp(at),
        files: 4,
        acks: (0..acks).map(|i| DeviceId([0xE0 + i as u8; 32])).collect(),
        entry_cbor: vec![],
        target_sig: [0; 64],
        last_refusal: None,
        to_retire: vec![],
        reached: None,
    }
}

#[tokio::test]
async fn status_reports_dr_pointer_from_last_publication() {
    use viaticum_core::system_state::catalog::PointerPublications;
    let state = make_test_state().await;
    let lineage = state.db.get_or_create_catalog_lineage().unwrap();
    let mut meta = PointerPublications::new(lineage);
    meta.current = Some(place_record(
        viaticum_core::types::SourceBlockId([7; 32]),
        1_790_000_000,
        2,
    ));
    state.db.put_pointer_publications(&meta).unwrap();
    let CliResponse::Status(data) = dispatch(CliRequest::Status, &state).await else {
        panic!("expected Status");
    };
    assert_eq!(data.dr_pointer_published_at, 1_790_000_000);
    assert_eq!(data.dr_pointer_files, 4);
    assert_eq!(data.dr_pointer_acks, 2);
    assert_eq!(data.catalog_lineage, lineage.to_hex());
    assert!(!data.dr_ready, "the catalog block has no holder");
    assert_eq!((data.dr_ss_blocks_placed, data.dr_ss_blocks_total), (0, 1));
}

/// mailbox-i49: the refusal of the newest base's place is in `status` in words; an
/// unacked record is not reported as published.
#[tokio::test]
async fn status_shows_last_refusal_reason() {
    use viaticum_core::system_state::catalog::{PointerPublications, PointerRefusal, RefusalKind};
    let state = make_test_state().await;
    let lineage = state.db.get_or_create_catalog_lineage().unwrap();
    for (kind, words) in [
        (RefusalKind::ClockSkew, "this computer's clock looks wrong"),
        (RefusalKind::SlotsFull, "already has 64 installations"),
        (
            RefusalKind::Superseded,
            "friends hold a pointer newer than this computer's clock — the clock went back",
        ),
        (
            RefusalKind::Mixed {
                clock: 1,
                superseded: 2,
                slots_full: 3,
                other: 0,
            },
            "(1 clock, 2 newer pointer held, 3 full)",
        ),
    ] {
        let mut meta = PointerPublications::new(lineage);
        let mut rec = place_record(
            viaticum_core::types::SourceBlockId([7; 32]),
            1_790_000_000,
            0,
        );
        rec.last_refusal = Some(PointerRefusal { at: 1, kind });
        meta.current = Some(rec);
        state.db.put_pointer_publications(&meta).unwrap();
        let CliResponse::Status(data) = dispatch(CliRequest::Status, &state).await else {
            panic!("expected Status");
        };
        assert!(
            data.dr_pointer_refusal.contains(words),
            "{kind:?}: {}",
            data.dr_pointer_refusal
        );
        assert_eq!(data.dr_pointer_published_at, 0, "no postman accepted it");
    }
}

/// An SS block held by `holders` peers seen now (strength = holders; k_eff = 4).
fn held_ss_block(db: &Db, id: u8, holders: u8) -> viaticum_core::types::SourceBlockId {
    use viaticum_core::types::{
        FileId, PeerRecord, PlacementStatus, SourceBlockId, SourceBlockRecord, SourceBlockStatus,
        SourceBlockType, SymbolPlacement, Timestamp,
    };
    let block_id = SourceBlockId([id; 32]);
    db.upsert_source_block(&SourceBlockRecord {
        seal_generation: 0,
        block_id,
        k: 1,
        t: 64,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(1),
        encrypted_size: Some(64),
        n: Some(12),
        overhead: Some(3.0),
        drop_notice_sent_at: None,
        importance: 1.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.99,
    })
    .unwrap();
    for h in 0..holders {
        let device = DeviceId([0xA0 + h; 32]);
        db.upsert_peer(&PeerRecord {
            device_id: device,
            master_identity: IdentityPub(device.0),
            trust_p: 0.5,
            trust_i: 0.0,
            trust_s: 1.0,
            bytes_we_store_for_peer: 0,
            bytes_peer_stores_for_us: 0,
            first_seen: Timestamp(1),
            last_seen: Timestamp::now(),
            revoked_device_pub_keys: vec![],
            addrs: vec![],
            x25519_pub: None,
            avail_ewma: 0.5,
            last_avail_sample: 0,
        })
        .unwrap();
        db.upsert_placement(&SymbolPlacement {
            source_block_id: block_id,
            holder_id: device,
            file_id: FileId(0),
            esi_ranges: vec![(u32::from(h) * 4, 4)],
            binding_seed: [0; 32],
            status: PlacementStatus::Alive,
            last_verified: None,
            placed_at: Timestamp(1),
            consecutive_misses: 0,
        })
        .unwrap();
    }
    block_id
}

/// dr-i53: a new base with 1 ack in place B does not make status "not ready" while
/// place A is restorable; status names the date of the catalog state DR restores
/// (place A's pointer), in the JSON field and in the CLI line.
#[tokio::test]
async fn status_names_the_date_dr_would_restore() {
    use viaticum_core::mailbox::seal::PointerPlace;
    use viaticum_core::system_state::catalog::PointerPublications;
    let state = make_test_state().await;
    let lineage = state.db.get_or_create_catalog_lineage().unwrap();
    let old = held_ss_block(&state.db, 7, 3); // 3 known peers → threshold 2
    let new = held_ss_block(&state.db, 8, 3);
    let mut meta = PointerPublications::new(lineage);
    meta.other = Some(place_record(old, 1_790_000_000, 3));
    let mut newer = place_record(new, 1_790_100_000, 1);
    newer.place = PointerPlace::B;
    meta.current = Some(newer);
    state.db.put_pointer_publications(&meta).unwrap();
    let CliResponse::Status(data) = dispatch(CliRequest::Status, &state).await else {
        panic!("expected Status");
    };
    assert!(data.dr_ready, "place A is restorable");
    assert_eq!(data.dr_restores_state_of, 1_790_000_000);
    assert_eq!(data.dr_pointer_published_at, 1_790_000_000);
    let rendered = crate::cli::output::render_status(&data);
    assert!(
        rendered.contains(&format!(
            "DR would restore the catalog as of {} or newer",
            super::unix_secs_to_iso(1_790_000_000, true)
        )),
        "got: {rendered}"
    );

    // Nothing restorable (the new base short of the threshold, place A gone): no date.
    meta.other = None;
    state.db.put_pointer_publications(&meta).unwrap();
    let CliResponse::Status(data) = dispatch(CliRequest::Status, &state).await else {
        panic!("expected Status");
    };
    assert!(!data.dr_ready);
    assert_eq!(data.dr_restores_state_of, 0);
    assert!(!crate::cli::output::render_status(&data).contains("DR would restore"));
}

/// mailbox-i54: the wait is in `status` with its start and reason.
#[tokio::test]
async fn status_shows_waiting_since_and_reason() {
    use viaticum_core::system_state::catalog::{PointerPublications, Waiting, WaitingReason};
    let state = make_test_state().await;
    let lineage = state.db.get_or_create_catalog_lineage().unwrap();
    let mut meta = PointerPublications::new(lineage);
    meta.waiting = Some(Waiting {
        since: 1_790_000_123,
        reason: WaitingReason::BlocksNotPlaced,
    });
    state.db.put_pointer_publications(&meta).unwrap();
    let CliResponse::Status(data) = dispatch(CliRequest::Status, &state).await else {
        panic!("expected Status");
    };
    assert_eq!(data.dr_waiting_since, 1_790_000_123);
    assert_eq!(data.dr_waiting, "catalog blocks not placed");
}

// ─── F-Q: quota fields of status (holder-i2, holder-i4) ─────────────────────────

async fn status_of(state: &Arc<DaemonState>) -> Box<crate::cli::types::StatusData> {
    let CliResponse::Status(data) = dispatch(CliRequest::Status, state).await else {
        panic!("expected Status");
    };
    data
}

/// holder-i2: an unreadable data dir without a soft quota ⇒ `quota_state: unknown` and the
/// note naming the path; with a soft quota ⇒ `bytes` (the soft quota), the note still said.
#[tokio::test]
async fn status_of_an_unreadable_disk_is_unknown_and_names_the_path() {
    let dir = tempfile::TempDir::new().unwrap();
    let missing = dir.path().join("gone");
    let data = status_of(&make_test_state_with(missing.clone(), 0, 0).await).await;
    assert_eq!(data.quota_state, "unknown");
    assert!(
        data.quota_note.contains(&format!(
            "could not read free space on {}",
            missing.display()
        )),
        "{}",
        data.quota_note
    );
    assert_eq!(data.below_reserve_giving_back_bytes, None);

    let data = status_of(&make_test_state_with(missing, 1000, 0).await).await;
    assert_eq!(data.quota_state, "bytes");
    assert_eq!(data.effective_quota_bytes, 1000);
    assert!(
        data.quota_note.contains("soft quota"),
        "{}",
        data.quota_note
    );
}

/// holder-i4: free disk below the reserve ⇒ status says what the tick gives back, also when
/// the quota is not 0 (held over the gap); a readable disk above the reserve ⇒ nothing.
#[tokio::test]
async fn status_below_reserve_says_what_is_given_back_at_any_quota() {
    let dir = tempfile::TempDir::new().unwrap();
    let free = crate::daemon::handle::disk_available_bytes(dir.path()).unwrap();
    // Held is only a DB number here; large, so the disk moving between reads (parallel
    // tests on the same filesystem) stays small against it.
    let held = 1024 * 1024 * 1024 * 1024u64;
    // reserve = free + held/2 ⇒ Q = free + held − reserve = held/2 > 0, free < reserve.
    let state = make_test_state_with(dir.path().to_path_buf(), 0, free + held / 2).await;
    state
        .db
        .upsert_holding(&viaticum_core::types::HoldingRecord {
            source_block_id: viaticum_core::types::SourceBlockId([7; 32]),
            owner_id: IdentityPub([7; 32]),
            esi_ranges: vec![(0, 1)],
            importance: 0.5,
            total_bytes: held,
            status: viaticum_core::types::HoldingStatus::Active,
            received_at: viaticum_core::types::Timestamp(0),
            delete_requested_at: None,
            drop_notice_sent_at: None,
        })
        .unwrap();
    let data = status_of(&state).await;
    assert_eq!(data.quota_state, "bytes");
    // The disk moves a little between the two reads: Q ≈ held/2, given back ≈ held − 0.85·Q.
    assert!(data.effective_quota_bytes > 0, "quota is not 0 here");
    let back = data
        .below_reserve_giving_back_bytes
        .expect("below the reserve ⇒ Some");
    assert!(
        back >= held / 4,
        "gives back about the gap and more: {back}"
    );
    assert!(back <= held, "never more than held: {back}");

    let data = status_of(&make_test_state_with(dir.path().to_path_buf(), 0, 0).await).await;
    assert_eq!(data.below_reserve_giving_back_bytes, None);
    assert!(data.quota_note.is_empty());
}

// ── L1b (backup-i8, backup-i21): a block not in service is never "safe" / "restorable" ──

/// The file entry of `path` from `dispatch_files`.
async fn file_entry(state: &DaemonState, path: &str) -> crate::cli::types::FileEntry {
    let CliResponse::Files(entries) =
        dispatch(CliRequest::Files { path_prefix: None }, state).await
    else {
        panic!("expected Files");
    };
    entries
        .into_iter()
        .find(|e| e.path == path)
        .expect("file entry present")
}

/// The block of `insert_file_with_block`, its status set to `status`.
fn set_block_status(state: &DaemonState, status: viaticum_core::types::SourceBlockStatus) {
    let id = viaticum_core::types::SourceBlockId([7u8; 32]);
    let mut block = state.db.get_source_block(&id).unwrap().unwrap();
    block.status = status;
    state.db.upsert_source_block(&block).unwrap();
}

/// A placement of the `insert_file_with_block` block at holder `holder` with `count` symbols.
fn block_placement(
    state: &DaemonState,
    holder: u8,
    count: u32,
    status: viaticum_core::types::PlacementStatus,
) {
    use viaticum_core::types::{FileId, SourceBlockId, SymbolPlacement, Timestamp};
    state
        .db
        .upsert_placement(&SymbolPlacement {
            source_block_id: SourceBlockId([7u8; 32]),
            holder_id: DeviceId([holder; 32]),
            file_id: FileId(1),
            esi_ranges: vec![(u32::from(holder) * 100, count)],
            binding_seed: [0; 32],
            status,
            last_verified: None,
            placed_at: Timestamp(1),
            consecutive_misses: 0,
        })
        .unwrap();
}

/// M8: the cache says "at target" (it is not recomputed when the block turns `Deleting`),
/// but the network is releasing the block.
#[tokio::test]
async fn is_safe_to_delete_false_when_block_is_deleting_even_if_cached_reliability_high() {
    let state = make_test_state().await;
    insert_file_with_block(&state, "doc.pdf", 0.99, 0.95, true);
    assert!(
        safe_to_delete_flag(&state, "doc.pdf").await,
        "control: in service"
    );

    set_block_status(&state, viaticum_core::types::SourceBlockStatus::Deleting);

    assert!(!safe_to_delete_flag(&state, "doc.pdf").await);
}

#[tokio::test]
async fn is_safe_to_delete_false_when_a_placement_is_deleting() {
    use viaticum_core::types::PlacementStatus;
    let state = make_test_state().await;
    insert_file_with_block(&state, "doc.pdf", 0.99, 0.95, true);
    block_placement(&state, 0x51, 20, PlacementStatus::Alive);
    assert!(safe_to_delete_flag(&state, "doc.pdf").await, "control");

    block_placement(&state, 0x52, 20, PlacementStatus::Deleting);

    assert!(!safe_to_delete_flag(&state, "doc.pdf").await);
}

/// M8: `effective_status` counts placements; a block being released is `Releasing` even
/// with enough `Alive` symbols to decode.
#[tokio::test]
async fn effective_status_is_releasing_when_block_is_deleting_even_with_alive_placements() {
    use crate::cli::types::EffectiveStatus;
    use viaticum_core::types::{PlacementStatus, SourceBlockStatus};
    let state = make_test_state().await;
    insert_file_with_block(&state, "doc.pdf", 0.99, 0.95, true);
    block_placement(&state, 0x51, 50, PlacementStatus::Alive);
    assert!(
        matches!(
            file_entry(&state, "doc.pdf").await.effective_status,
            Some(EffectiveStatus::Restorable { .. })
        ),
        "control: restorable in service"
    );

    set_block_status(&state, SourceBlockStatus::Deleting);
    assert_eq!(
        file_entry(&state, "doc.pdf").await.effective_status,
        Some(EffectiveStatus::Releasing)
    );

    // A Deleting placement alone (status still Active) is the same answer.
    set_block_status(&state, SourceBlockStatus::Active);
    block_placement(&state, 0x52, 1, PlacementStatus::Deleting);
    assert_eq!(
        file_entry(&state, "doc.pdf").await.effective_status,
        Some(EffectiveStatus::Releasing)
    );
}

async fn doc_versions(state: &DaemonState) -> Vec<crate::cli::types::VersionEntry> {
    let CliResponse::Versions(v) = dispatch(
        CliRequest::Versions {
            path: "doc.pdf".into(),
        },
        state,
    )
    .await
    else {
        panic!("expected Versions");
    };
    v
}

/// restore-i3 (2026-09-30): a version whose block is being released shows the restore
/// blocker "being released", not "restorable" with no blocker, although its `Alive`
/// placements could decode it.
#[tokio::test]
async fn restore_blocker_is_being_released_when_block_is_deleting() {
    use crate::cli::types::{EffectiveStatus, RestoreBlocker};
    use viaticum_core::types::{PlacementStatus, SourceBlockStatus};
    let state = make_test_state().await;
    insert_file_with_block(&state, "doc.pdf", 0.99, 0.95, true);
    block_placement(&state, 0x51, 50, PlacementStatus::Alive);
    let before = doc_versions(&state).await;
    assert!(matches!(
        before[0].effective_status,
        EffectiveStatus::Restorable { .. }
    ));
    assert_eq!(before[0].restore_blocker, None, "control: in service");

    set_block_status(&state, SourceBlockStatus::Deleting);

    let after = doc_versions(&state).await;
    assert_eq!(after[0].effective_status, EffectiveStatus::Releasing);
    assert_eq!(
        after[0].restore_blocker,
        Some(RestoreBlocker::BeingReleased)
    );
}

// ── R1-d-a (backup-i4, backup-i7): a file above the size limit is shown, never "safe" ──

fn too_large_mark(size_bytes: u64) -> viaticum_core::types::TooLargeMark {
    viaticum_core::types::TooLargeMark {
        size_bytes,
        limit_bytes: 268_435_456,
        first_seen: viaticum_core::types::Timestamp(86_400 * 365),
        last_seen: viaticum_core::types::Timestamp(86_400 * 366),
    }
}

async fn files_of(state: &DaemonState) -> Vec<crate::cli::types::FileEntry> {
    let CliResponse::Files(entries) =
        dispatch(CliRequest::Files { path_prefix: None }, state).await
    else {
        panic!("expected Files");
    };
    entries
}

#[tokio::test]
async fn files_lists_marked_file_without_record_as_never_backed_up() {
    let state = make_test_state().await;
    insert_file_with_block(&state, "doc.pdf", 0.99, 0.95, true);
    state
        .db
        .put_too_large("huge.mkv", &too_large_mark(4_294_967_296))
        .unwrap();

    let entries = files_of(&state).await;
    assert_eq!(entries.len(), 2, "the catalog file and the marked one");

    let huge = entries.iter().find(|e| e.path == "huge.mkv").unwrap();
    assert_eq!(huge.last_backed_up, "never");
    assert!(!huge.is_safe_to_delete);
    assert_eq!(huge.versions, 0);
    assert_eq!(huge.effective_status, None);
    let info = huge.too_large.as_ref().expect("too_large is set");
    assert_eq!(info.size_bytes, 4_294_967_296);
    assert_eq!(info.limit_bytes, 268_435_456);
    assert_eq!(info.since, "1971-01-01");

    let doc = entries.iter().find(|e| e.path == "doc.pdf").unwrap();
    assert_eq!(doc.too_large, None, "an unmarked file has no too_large");

    // The JSON path the E2E reads: `.too_large.size_bytes` on the file entry itself.
    let json = serde_json::to_value(huge).unwrap();
    assert_eq!(json["too_large"]["size_bytes"], 4_294_967_296u64);
    assert_eq!(json["last_backed_up"], "never");
}

#[tokio::test]
async fn files_prefix_filters_marked_files_without_record() {
    let state = make_test_state().await;
    state
        .db
        .put_too_large("/a/huge.mkv", &too_large_mark(1 << 32))
        .unwrap();
    state
        .db
        .put_too_large("/b/huge.mkv", &too_large_mark(1 << 32))
        .unwrap();
    let CliResponse::Files(entries) = dispatch(
        CliRequest::Files {
            path_prefix: Some("/a/".to_string()),
        },
        &state,
    )
    .await
    else {
        panic!("expected Files");
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "/a/huge.mkv");
}

#[tokio::test]
async fn is_safe_to_delete_false_when_mark_present() {
    let state = make_test_state().await;
    insert_file_with_block(&state, "grow.bin", 0.99, 0.95, true);
    assert!(
        safe_to_delete_flag(&state, "grow.bin").await,
        "control: no mark, at target"
    );

    state
        .db
        .put_too_large("grow.bin", &too_large_mark(300 << 20))
        .unwrap();

    let entry = file_entry(&state, "grow.bin").await;
    assert!(!entry.is_safe_to_delete, "a mark makes it unsafe");
    assert!(entry.too_large.is_some());
    assert_ne!(
        entry.last_backed_up, "never",
        "the earlier version's date stays"
    );
    assert_eq!(entry.versions, 1);
}

#[tokio::test]
async fn status_counts_too_large_files_under_watch_dirs() {
    let dir = tempfile::TempDir::new().unwrap();
    let watch = dir.path().join("watched");
    let mut state = make_test_state().await;
    let live = Arc::new(RwLock::new(vec![viaticum_core::config::WatchConfig {
        path: watch.to_string_lossy().into_owned(),
        importance_multiplier: 1.0,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    }]));
    let (tx, _rx) = mpsc::channel(4);
    let admin = crate::daemon::watch_admin::WatchAdmin::new(
        dir.path().join("config.toml"),
        live,
        tx,
        state.db.clone(),
    );
    let inner = Arc::get_mut(&mut state).expect("state is not shared yet");
    inner.watch_admin = Some(Arc::new(admin));
    inner.max_file_size_bytes = 268_435_456;

    let inside = watch.join("huge.mkv").to_string_lossy().into_owned();
    let nested = watch.join("sub/big.bin").to_string_lossy().into_owned();
    let outside = dir.path().join("elsewhere/x.bin");
    state
        .db
        .put_too_large(&inside, &too_large_mark(1 << 32))
        .unwrap();
    state
        .db
        .put_too_large(&nested, &too_large_mark(1 << 30))
        .unwrap();
    state
        .db
        .put_too_large(&outside.to_string_lossy(), &too_large_mark(1 << 30))
        .unwrap();

    let data = status_of(&state).await;
    assert_eq!(
        data.files_too_large, 2,
        "the mark outside the watched folder is not counted"
    );
    assert_eq!(data.max_file_size_bytes, 268_435_456);
    assert_eq!(data.block_work_budget_bytes, 0, "R1-d-b sets it");

    let json = serde_json::to_value(&*data).unwrap();
    assert_eq!(json["files_too_large"], 2, "the name the E2E reads");
}

/// network-i14 (C-DK Р-7): status counts as known only the PeerRecords of another
/// master with a dialable address; without a swarm there is no authenticated list.
#[tokio::test]
async fn dispatch_status_reports_known_devices_from_peer_records() {
    use viaticum_core::constants::{AVAIL_EWMA_INITIAL, INITIAL_TRUST_P};
    use viaticum_core::types::{PeerRecord, Timestamp};

    let state = make_test_state().await;
    let rec = |device_id: DeviceId, master: IdentityPub, addrs: Vec<String>| PeerRecord {
        device_id,
        master_identity: master,
        trust_p: INITIAL_TRUST_P,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp::now(),
        last_seen: Timestamp::now(),
        revoked_device_pub_keys: vec![],
        addrs,
        x25519_pub: None,
        avail_ewma: AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    };
    let key = |seed: u8| {
        DeviceId(
            ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )
    };
    let addr = vec!["/ip4/127.0.0.1/tcp/4001".to_string()];
    let stranger = IdentityPub([0x42; 32]);
    let known = key(50);
    for r in [
        rec(known, stranger, addr.clone()),
        rec(key(51), state.identity_pub, addr.clone()),
        rec(key(52), stranger, vec![]),
    ] {
        state.db.upsert_peer(&r).unwrap();
    }

    let CliResponse::Status(data) = dispatch(CliRequest::Status, &state).await else {
        panic!("expected Status");
    };
    assert_eq!(data.peer_count, 3, "every PeerRecord row");
    assert_eq!(data.peer_count_known, 1);
    assert_eq!(
        data.known_devices,
        Some(vec![viaticum_core::types::hex_encode(&known.0[..8])])
    );
    assert_eq!(
        data.authenticated_devices, None,
        "no swarm: no list, not an empty one"
    );
}
