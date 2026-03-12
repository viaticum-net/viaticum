//! Phase 3 GATE tests.
//!
//! Three smoke/integration tests proving the full system works end-to-end.
//! Slow (seconds) — not #[ignore] — they are part of the mandatory GATE.
//!
//! Run: cargo test -p syncback phase3 -- --test-threads=1 --nocapture

use std::time::Duration;

use syncback::daemon::cli_server::{CliRequest, CliResponse};
use syncback::daemon::{BackupConfig, Config, DaemonHandle, IncludeEntry, NetworkConfig,
                       ScheduleConfig, StorageConfig, SyncFrequency, VacuumFrequency};

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Wait for the Unix socket to appear.
/// Retries up to 20 times with 100 ms intervals (2 s total).
async fn wait_for_socket(path: &std::path::Path) {
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if tokio::net::UnixStream::connect(path).await.is_ok() {
            return;
        }
    }
    panic!("socket not ready after 2s: {path:?}");
}

/// Send one JSON CLI request and return the parsed response.
async fn send_cli_request_raw(
    path: &std::path::Path,
    request: &CliRequest,
) -> CliResponse {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let stream = tokio::net::UnixStream::connect(path)
        .await
        .unwrap_or_else(|e| panic!("connect to {path:?}: {e}"));
    let json = serde_json::to_string(request).expect("serialize request");
    let (read_half, mut write_half) = stream.into_split();
    write_half
        .write_all(format!("{json}\n").as_bytes())
        .await
        .expect("write request");
    write_half.flush().await.expect("flush");
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read response");
    serde_json::from_str(line.trim()).expect("parse CliResponse")
}

/// Wait until a file exists at `path`. Returns Err on timeout.
async fn wait_for_file(
    path: &std::path::Path,
    timeout: Duration,
) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if std::time::Instant::now() > deadline {
            anyhow::bail!("timeout waiting for file: {path:?}");
        }
        if path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Tell daemon at `socket` to connect to the peer at `node_addr`.
async fn connect_peers(socket: &std::path::Path, node_addr: &str) -> anyhow::Result<()> {
    let resp = send_cli_request_raw(
        socket,
        &CliRequest::ConnectPeer { node_addr: node_addr.to_string() },
    )
    .await;
    match resp {
        CliResponse::Ok { .. } | CliResponse::Accepted { .. } => Ok(()),
        CliResponse::Error { message } => anyhow::bail!("connect failed: {message}"),
        other => anyhow::bail!("unexpected: {other:?}"),
    }
}

/// Get the `own_node_id` (EndpointAddr as JSON string) from the daemon's Status.
async fn get_node_addr(socket: &std::path::Path) -> String {
    let resp = send_cli_request_raw(socket, &CliRequest::Status).await;
    match resp {
        CliResponse::StatusOk(s) => s.own_node_id,
        other => panic!("expected StatusOk, got {other:?}"),
    }
}

/// Build a minimal Config with the given syncback_dir and include entries.
fn make_config(syncback_dir: std::path::PathBuf, include: Vec<IncludeEntry>) -> Config {
    Config {
        syncback_dir,
        backup: BackupConfig { include, exclude: vec![] },
        storage: StorageConfig { quota_gb: 10 },
        network: NetworkConfig { seed_nodes: vec![], bandwidth_limit_mbps: 0 },
        schedule: ScheduleConfig {
            sync: SyncFrequency::Weekly,
            vacuum: VacuumFrequency::Monthly,
        },
    }
}

/// Deterministic BIP39 mnemonic derived from entropy `[seed; 32]`.
fn fixed_mnemonic(seed: u8) -> Vec<String> {
    use bip39::Mnemonic;
    let entropy = [seed; 32];
    let m = Mnemonic::from_entropy(&entropy).expect("valid entropy");
    m.words().map(|s| s.to_string()).collect()
}

/// Recursively copy `src` directory to `dst`.
fn copy_dir_recursive(
    src: &std::path::Path,
    dst: &std::path::Path,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

// ── Test 1: daemon starts and responds to Status ──────────────────────────────

#[tokio::test]
async fn phase3_daemon_starts_and_responds_to_status() {
    let dir = tempfile::TempDir::new().expect("tempdir");

    let mnemonic_owned = fixed_mnemonic(0);
    let mnemonic_refs: Vec<&str> = mnemonic_owned.iter().map(|s| s.as_str()).collect();
    syncback::cli::init::init_with_mnemonic(dir.path(), &mnemonic_refs)
        .expect("init_with_mnemonic");

    let config = make_config(dir.path().to_path_buf(), vec![]);
    let handle = DaemonHandle::start(config).await.expect("daemon start");

    let sock = dir.path().join("syncback.sock");
    wait_for_socket(&sock).await;

    let resp = send_cli_request_raw(&sock, &CliRequest::Status).await;
    match resp {
        CliResponse::StatusOk(s) => {
            assert!(s.uptime_secs < 10, "uptime_secs should be <10, got {}", s.uptime_secs);
            assert_eq!(s.peer_count, 0, "no seed nodes configured");
            assert_eq!(s.dirty_files, 0, "no include dirs configured");
            assert!(!s.own_node_id.is_empty(), "own_node_id must be non-empty");
        }
        other => panic!("expected StatusOk, got: {other:?}"),
    }

    handle.shutdown().await.expect("shutdown");
}

// ── Test 2: two daemons connect to each other ─────────────────────────────────

#[tokio::test]
async fn phase3_two_daemons_connect_and_see_each_other() {
    let dir_a = tempfile::TempDir::new().expect("tempdir a");
    let dir_b = tempfile::TempDir::new().expect("tempdir b");

    let mnemonic_a = fixed_mnemonic(10);
    let mnemonic_b = fixed_mnemonic(11);
    let refs_a: Vec<&str> = mnemonic_a.iter().map(|s| s.as_str()).collect();
    let refs_b: Vec<&str> = mnemonic_b.iter().map(|s| s.as_str()).collect();
    syncback::cli::init::init_with_mnemonic(dir_a.path(), &refs_a).expect("init a");
    syncback::cli::init::init_with_mnemonic(dir_b.path(), &refs_b).expect("init b");

    let config_a = make_config(dir_a.path().to_path_buf(), vec![]);
    let config_b = make_config(dir_b.path().to_path_buf(), vec![]);

    let handle_a = DaemonHandle::start(config_a).await.expect("start a");
    let handle_b = DaemonHandle::start(config_b).await.expect("start b");

    let sock_a = dir_a.path().join("syncback.sock");
    let sock_b = dir_b.path().join("syncback.sock");
    wait_for_socket(&sock_a).await;
    wait_for_socket(&sock_b).await;

    let node_addr_b = get_node_addr(&sock_b).await;
    assert!(!node_addr_b.is_empty(), "node_addr_b must be non-empty");

    connect_peers(&sock_a, &node_addr_b).await.expect("connect A->B");
    tokio::time::sleep(Duration::from_millis(1000)).await;

    let resp = send_cli_request_raw(&sock_a, &CliRequest::Status).await;
    match resp {
        CliResponse::StatusOk(s) => {
            assert!(
                s.peer_count >= 1,
                "A should see at least 1 peer after connecting to B, got {}",
                s.peer_count
            );
        }
        other => panic!("expected StatusOk, got: {other:?}"),
    }

    handle_a.shutdown().await.expect("shutdown a");
    handle_b.shutdown().await.expect("shutdown b");
}

// ── Test 3: full backup → restore from seed (in-process) ─────────────────────

const TEST_FILE_CONTENT: &[u8] = b"hello from syncback phase3 gate test\n";

#[tokio::test]
async fn phase3_full_backup_restore_from_seed_inprocess() {
    tokio::time::timeout(
        Duration::from_secs(120),
        run_full_backup_restore(),
    )
    .await
    .expect("test timed out after 120s")
    .expect("test failed");
}

async fn run_full_backup_restore() -> anyhow::Result<()> {
    use syncback_core::db::Db;
    use syncback_core::messages::{
        FileType as MsgFileType, SignedShardDescriptor, SignedShardDescriptorUnsigned,
    };
    use syncback_core::types::{
        FileId, FileRecord, IdentityPub, NodeId, PeerRecord,
        ShardRecord, ShardStatus, Timestamp, UnitId,
    };

    // ── Step 1: Create directories ────────────────────────────────────────────
    let root = tempfile::TempDir::new()?;
    let files_dir = root.path().join("files");
    let dir_a = root.path().join("node_a");
    let dir_b = root.path().join("node_b");
    let dir_c = root.path().join("node_c");
    let restore_dir = root.path().join("restored");
    std::fs::create_dir_all(&files_dir)?;
    std::fs::create_dir_all(&restore_dir)?;

    // ── Step 2: Write test file ───────────────────────────────────────────────
    let test_file = files_dir.join("notes.txt");
    std::fs::write(&test_file, TEST_FILE_CONTENT)?;
    let file_path_str = test_file.to_string_lossy().to_string();

    // ── Step 3: Init node A and B ─────────────────────────────────────────────
    let mnemonic_a = fixed_mnemonic(20);
    let mnemonic_b = fixed_mnemonic(21);
    let refs_a: Vec<&str> = mnemonic_a.iter().map(|s| s.as_str()).collect();
    let refs_b: Vec<&str> = mnemonic_b.iter().map(|s| s.as_str()).collect();

    std::fs::create_dir_all(&dir_a)?;
    std::fs::create_dir_all(&dir_b)?;

    let key_file_a = syncback::cli::init::init_with_mnemonic(&dir_a, &refs_a)?;
    let key_file_b = syncback::cli::init::init_with_mnemonic(&dir_b, &refs_b)?;

    let identity_pub_a = IdentityPub(key_file_a.identity_pub);
    let identity_pub_b = IdentityPub(key_file_b.identity_pub);

    // B's iroh node_id (iroh PublicKey bytes), needed for PeerRecord.
    let iroh_key_b = iroh::SecretKey::from_bytes(&key_file_b.iroh_priv);
    let node_id_b = NodeId(*iroh_key_b.public().as_bytes());

    // ── Step 4: Open A's DB, create FileRecord ────────────────────────────────
    let db_a = Db::open(&dir_a.join("syncback.redb"))?;
    let now = Timestamp::now();

    db_a.upsert_file(&FileRecord {
        file_id: FileId(1),
        path: file_path_str.clone(),
        content_hash: [0u8; 32],
        size_bytes: TEST_FILE_CONTENT.len() as u64,
        importance: 0.9,
        dirty: true,
        current_unit_id: None,
        last_backed_up: None,
        backed_up: false,
        first_seen: now,
    })?;

    // Insert B as a trusted peer in A's DB (needed for shard placement + restore lookup).
    db_a.upsert_peer(&PeerRecord {
        identity: identity_pub_b,
        node_id: Some(node_id_b),
        trust_p: 0.8,
        trust_i: 0.8,
        trust_s: 1.0,
        bytes_sent_to_peer: 0,
        bytes_received_from_peer: 0,
        first_seen: now,
        last_seen: now,
        weeks_in_network: 26,
        subnet_prefix: None,
        allowlisted: false,
    })?;

    // ── Step 5: Pack the test file and get shard blobs ────────────────────────
    let identity_key_a = ed25519_dalek::SigningKey::from_bytes(&key_file_a.identity_priv);
    let packer = syncback::daemon::packer::Packer::new(
        db_a.clone(),
        ed25519_dalek::SigningKey::from_bytes(&key_file_a.identity_priv),
        identity_pub_a,
        syncback::daemon::packer::DEFAULT_UNIT_SIZE_BYTES,
    );

    let candidate = syncback_core::budget::BackupCandidate {
        path: file_path_str.clone(),
        importance: 0.9,
        required_gb: 0.0, // not used by pack_batch
    };
    let pack_results = packer.pack_batch(&[candidate], now);
    anyhow::ensure!(!pack_results.is_empty(), "pack_batch returned no results");
    let pack_result = &pack_results[0];

    db_a.upsert_unit(&pack_result.unit_record)?;
    let unit_id: UnitId = pack_result.unit_record.unit_id;
    let k = pack_result.unit_record.rs_k as usize;
    let n = pack_result.unit_record.rs_n as usize;

    // Encrypt + erasure-code to get the shard blobs.
    // pack_result.plaintext holds zstd-compressed bytes; plaintext_to_shards expects
    // uncompressed input (it compresses before encrypting). Decompress first so the
    // round-trip through unpack_unit works correctly.
    let uncompressed_plaintext = zstd::decode_all(pack_result.plaintext.as_slice())
        .map_err(|e| anyhow::anyhow!("zstd decompress failed: {e}"))?;
    let shard_blobs = packer.plaintext_to_shards(unit_id, &uncompressed_plaintext, k, n)
        .map_err(|e| anyhow::anyhow!("plaintext_to_shards failed: {e}"))?;
    anyhow::ensure!(shard_blobs.len() == n, "expected {n} shards, got {}", shard_blobs.len());

    // ── Step 6: Populate B's storage with the shard blobs ────────────────────
    let db_b = Db::open(&dir_b.join("syncback.redb"))?;

    // Insert A as a known peer in B's DB (escrow reads the peer record).
    db_b.upsert_peer(&PeerRecord {
        identity: identity_pub_a,
        node_id: None,
        trust_p: 0.8,
        trust_i: 0.8,
        trust_s: 1.0,
        bytes_sent_to_peer: 0,
        bytes_received_from_peer: 0,
        first_seen: now,
        last_seen: now,
        weeks_in_network: 26,
        subnet_prefix: None,
        allowlisted: false,
    })?;

    let trust_b = syncback_core::trust::TrustEngine::new(db_b.clone());
    let storage_b = syncback::daemon::storage::Storage::new(
        db_b.clone(),
        dir_b.join("shards"),
        10.0,
        trust_b,
    )?;

    for (shard_index, blob) in shard_blobs.iter().enumerate() {
        let shard_id = syncback_core::types::ShardId(*blake3::hash(blob).as_bytes());

        let tree = syncback::daemon::storage::build_merkle_tree(blob);
        let merkle_root = *tree.last().unwrap_or(&[0u8; 32]);

        let unsigned = SignedShardDescriptorUnsigned {
            shard_id,
            unit_id,
            shard_index: shard_index as u8,
            k: k as u8,
            n: n as u8,
            merkle_root,
            owner_pub: identity_pub_a,
            importance: 0.9,
            file_type: MsgFileType::User,
            created_at: now.0,
        };
        let descriptor = SignedShardDescriptor::sign(unsigned, &identity_key_a)?;

        storage_b.store_shard(&descriptor, blob).await?;

        // Record in A's DB: shard is Stored at holder B.
        db_a.upsert_shard(&ShardRecord {
            shard_id,
            unit_id,
            shard_index: shard_index as u8,
            holder_id: identity_pub_b,
            status: ShardStatus::Stored,
            last_verified: None,
            offered_at: now,
            stored_at: Some(now),
            merkle_root,
        })?;
    }

    // Mark file as backed up in A's DB so C can find it via RestoreFile.
    db_a.mark_file_clean(&file_path_str, now, unit_id)?;

    // Drop DB handles — redb requires exclusive writer access.
    drop(packer);
    drop(storage_b);
    drop(db_b);
    drop(db_a);

    // ── Step 7: Start daemon B (holder) ──────────────────────────────────────
    let config_b = make_config(dir_b.clone(), vec![]);
    let handle_b = DaemonHandle::start(config_b).await?;
    let sock_b = dir_b.join("syncback.sock");
    wait_for_socket(&sock_b).await;
    let node_addr_b = get_node_addr(&sock_b).await;

    // ── Step 8: Copy A's dir to C (same identity + same DB = knows shard map) ─
    copy_dir_recursive(&dir_a, &dir_c)?;

    // ── Step 9: Start daemon C (recovery node — same identity as A) ──────────
    let config_c = make_config(dir_c.clone(), vec![]);
    let handle_c = DaemonHandle::start(config_c).await?;
    let sock_c = dir_c.join("syncback.sock");
    wait_for_socket(&sock_c).await;

    // ── Step 10: Connect C to B and wait for PeerConnected ───────────────────
    connect_peers(&sock_c, &node_addr_b).await?;
    // Wait for handshake + PeerConnected event to arrive at C's processor
    // and update the PeerRecord with B's node_id (needed by do_restore).
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // ── Step 11: Restore file on C ────────────────────────────────────────────
    let dest_path = restore_dir.join("notes_restored.txt");
    let restore_resp = send_cli_request_raw(
        &sock_c,
        &CliRequest::RestoreFile {
            path: file_path_str.clone(),
            dest: dest_path.to_string_lossy().to_string(),
        },
    )
    .await;

    match &restore_resp {
        CliResponse::Ok { .. } | CliResponse::Accepted { .. } => {}
        other => anyhow::bail!("RestoreFile returned unexpected response: {other:?}"),
    }

    // ── Step 12: Wait for the restored file to appear ────────────────────────
    wait_for_file(&dest_path, Duration::from_secs(30)).await?;

    // ── Step 13: Verify content byte-for-byte ────────────────────────────────
    let restored = std::fs::read(&dest_path)?;
    anyhow::ensure!(
        restored == TEST_FILE_CONTENT,
        "restored content mismatch:\n  expected ({} bytes): {:?}\n  got ({} bytes): {:?}",
        TEST_FILE_CONTENT.len(),
        TEST_FILE_CONTENT,
        restored.len(),
        &restored[..restored.len().min(64)],
    );

    // ── Step 14: Shutdown ─────────────────────────────────────────────────────
    handle_b.shutdown().await?;
    handle_c.shutdown().await?;

    Ok(())
}
