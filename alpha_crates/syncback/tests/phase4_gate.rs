//! Phase 4 GATE test: full DR (Disaster Recovery) from seed phrase only.
//!
//! Tests the complete DR flow:
//!   1. Owner A backs up files to holder B.
//!   2. A pushes its system state (encrypted DB snapshot) to B.
//!   3. A's directory is deleted (simulating device loss).
//!   4. A' starts fresh with the same seed phrase.
//!   5. A' sends DrRestore to retrieve system state from B.
//!   6. A' verifies it can see its original files and restore them.
//!
//! Run: cargo test -p syncback phase4 -- --test-threads=1 --nocapture

use std::time::Duration;

use syncback::daemon::cli_server::{CliRequest, CliResponse};
use syncback::daemon::{
    BackupConfig, Config, DaemonHandle, IncludeEntry, NetworkConfig, ScheduleConfig, StorageConfig,
    SyncFrequency, VacuumFrequency,
};

// ── Shared test helpers (copied from phase3_gate.rs to avoid cross-file deps) ─

async fn wait_for_socket(path: &std::path::Path) {
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if tokio::net::UnixStream::connect(path).await.is_ok() {
            return;
        }
    }
    panic!("socket not ready after 4s: {path:?}");
}

async fn send_cli_request_raw(path: &std::path::Path, request: &CliRequest) -> CliResponse {
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

async fn wait_for_file(path: &std::path::Path, timeout: Duration) -> anyhow::Result<()> {
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

async fn connect_peers(socket: &std::path::Path, node_addr: &str) -> anyhow::Result<()> {
    let resp = send_cli_request_raw(
        socket,
        &CliRequest::ConnectPeer {
            node_addr: node_addr.to_string(),
        },
    )
    .await;
    match resp {
        CliResponse::Ok { .. } | CliResponse::Accepted { .. } => Ok(()),
        CliResponse::Error { message } => anyhow::bail!("connect failed: {message}"),
        other => anyhow::bail!("unexpected: {other:?}"),
    }
}

async fn get_node_addr(socket: &std::path::Path) -> String {
    let resp = send_cli_request_raw(socket, &CliRequest::Status).await;
    match resp {
        CliResponse::StatusOk(s) => s.own_node_id,
        other => panic!("expected StatusOk, got {other:?}"),
    }
}

fn make_config(syncback_dir: std::path::PathBuf, include: Vec<IncludeEntry>) -> Config {
    Config {
        syncback_dir,
        backup: BackupConfig {
            include,
            exclude: vec![],
        },
        storage: StorageConfig { quota_gb: 10 },
        network: NetworkConfig {
            seed_nodes: vec![],
            bandwidth_limit_mbps: 0,
        },
        schedule: ScheduleConfig {
            sync: SyncFrequency::Weekly,
            vacuum: VacuumFrequency::Monthly,
        },
        time_scale: 1,
    }
}

fn fixed_mnemonic(seed: u8) -> Vec<String> {
    use bip39::Mnemonic;
    let entropy = [seed; 32];
    let m = Mnemonic::from_entropy(&entropy).expect("valid entropy");
    m.words().map(|s| s.to_string()).collect()
}

// ── Phase 4 gate test ─────────────────────────────────────────────────────────

#[tokio::test]
async fn phase4_full_dr_from_seed_only() {
    tokio::time::timeout(Duration::from_secs(120), run_full_dr())
        .await
        .expect("test timed out after 120s")
        .expect("test failed");
}

async fn run_full_dr() -> anyhow::Result<()> {
    use syncback_core::db::Db;
    use syncback_core::messages::{
        FileType as MsgFileType, SignedShardDescriptor, SignedShardDescriptorUnsigned,
    };
    use syncback_core::types::{
        FileId, FileRecord, IdentityPub, NodeId, PeerRecord, ShardRecord, ShardStatus, Timestamp,
        UnitId,
    };

    // ── Step 1: Create directories ────────────────────────────────────────────
    let root = tempfile::TempDir::new()?;
    let files_dir = root.path().join("files");
    let dir_a = root.path().join("node_a");
    let dir_b = root.path().join("node_b");
    let restore_dir = root.path().join("restored");
    std::fs::create_dir_all(&files_dir)?;
    std::fs::create_dir_all(&restore_dir)?;

    const TEST_CONTENT: &[u8] = b"phase4 DR gate test: hello from the original owner\n";

    // ── Step 2: Write test file ───────────────────────────────────────────────
    let test_file = files_dir.join("notes.txt");
    std::fs::write(&test_file, TEST_CONTENT)?;
    let file_path_str = test_file.to_string_lossy().to_string();

    // ── Step 3: Init node A and B with known seeds ────────────────────────────
    let mnemonic_a = fixed_mnemonic(40);
    let mnemonic_b = fixed_mnemonic(41);
    let refs_a: Vec<&str> = mnemonic_a.iter().map(|s| s.as_str()).collect();
    let refs_b: Vec<&str> = mnemonic_b.iter().map(|s| s.as_str()).collect();

    std::fs::create_dir_all(&dir_a)?;
    std::fs::create_dir_all(&dir_b)?;

    let key_file_a = syncback::cli::init::init_with_mnemonic(&dir_a, &refs_a)?;
    let key_file_b = syncback::cli::init::init_with_mnemonic(&dir_b, &refs_b)?;

    let identity_pub_a = IdentityPub(key_file_a.identity_pub);
    let identity_pub_b = IdentityPub(key_file_b.identity_pub);

    // B's iroh NodeId (used in PeerRecord).
    let iroh_key_b = iroh::SecretKey::from_bytes(&key_file_b.iroh_priv);
    let node_id_b = NodeId(*iroh_key_b.public().as_bytes());

    // ── Step 4: Populate A's DB directly ─────────────────────────────────────
    let db_a = Db::open(&dir_a.join("syncback.redb"))?;
    let now = Timestamp::now();

    // Insert file record.
    db_a.upsert_file(&FileRecord {
        file_id: FileId(1),
        path: file_path_str.clone(),
        content_hash: [0u8; 32],
        size_bytes: TEST_CONTENT.len() as u64,
        importance: 0.9,
        dirty: true,
        current_unit_id: None,
        last_backed_up: None,
        backed_up: false,
        first_seen: now,
    })?;

    // Insert B as trusted peer in A's DB.
    db_a.upsert_peer(&PeerRecord {
        identity: identity_pub_b,
        node_id: Some(node_id_b),
        trust_p: 0.9,
        trust_i: 0.9,
        trust_s: 1.0,
        bytes_sent_to_peer: 0,
        bytes_received_from_peer: 0,
        first_seen: now,
        last_seen: now,
        weeks_in_network: 26,
        subnet_prefix: None,
        allowlisted: false,
    })?;

    // ── Step 5: Pack file and scatter shards to B ─────────────────────────────
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
        required_gb: 0.0,
    };
    let pack_results = packer.pack_batch(&[candidate], now);
    anyhow::ensure!(!pack_results.is_empty(), "pack_batch returned no results");
    let pack_result = &pack_results[0];

    db_a.upsert_unit(&pack_result.unit_record)?;
    let unit_id: UnitId = pack_result.unit_record.unit_id;
    let k = pack_result.unit_record.rs_k as usize;
    let n = pack_result.unit_record.rs_n as usize;

    // Decompress before re-encoding.
    let uncompressed = zstd::decode_all(pack_result.plaintext.as_slice())
        .map_err(|e| anyhow::anyhow!("zstd decompress failed: {e}"))?;
    let shard_blobs = packer
        .plaintext_to_shards(unit_id, &uncompressed, k, n)
        .map_err(|e| anyhow::anyhow!("plaintext_to_shards: {e}"))?;

    // Populate B's storage with shards.
    let db_b = Db::open(&dir_b.join("syncback.redb"))?;
    db_b.upsert_peer(&PeerRecord {
        identity: identity_pub_a,
        node_id: None,
        trust_p: 0.9,
        trust_i: 0.9,
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

    db_a.mark_file_clean(&file_path_str, now, unit_id)?;

    // ── Step 6: Pack A's system state and store in B's DB ────────────────────
    // Snapshot A's DB and push the encrypted blob directly to B's DB (simulating
    // a successful SystemStateBackup message received by B).
    let sys_state = syncback::daemon::system_state::snapshot_db(&db_a)?;
    let blob = syncback::daemon::system_state::pack_system_state(
        &sys_state,
        &key_file_a.identity_priv,
    )?;

    let blob_record = syncback_core::types::SystemStateBlobRecord {
        blob,
        created_at: now,
        received_at: now,
    };
    db_b.store_system_state_blob(&identity_pub_a, &blob_record)?;

    // Drop DB handles before starting daemons.
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

    // ── Step 8: Simulate device loss — delete A's entire directory ────────────
    std::fs::remove_dir_all(&dir_a)?;

    // ── Step 9: Start fresh daemon A' (same seed, empty DB) ──────────────────
    let dir_a_prime = root.path().join("node_a_prime");
    std::fs::create_dir_all(&dir_a_prime)?;
    let refs_a_prime: Vec<&str> = mnemonic_a.iter().map(|s| s.as_str()).collect();
    syncback::cli::init::init_with_mnemonic(&dir_a_prime, &refs_a_prime)?;

    let config_a_prime = make_config(
        dir_a_prime.clone(),
        vec![IncludeEntry {
            path: files_dir.clone(),
            importance: 0.9,
        }],
    );
    let handle_a_prime = DaemonHandle::start(config_a_prime).await?;
    let sock_a_prime = dir_a_prime.join("syncback.sock");
    wait_for_socket(&sock_a_prime).await;

    // ── Step 10: Send DrRestore from A' — retrieves system state from B ───────
    // DR restore sends the seed phrase + peer addr to the running daemon.
    let dr_resp = send_cli_request_raw(
        &sock_a_prime,
        &CliRequest::DrRestore {
            seed_phrase: mnemonic_a.join(" "),
            peer_addr: node_addr_b.clone(),
        },
    )
    .await;

    match &dr_resp {
        CliResponse::Ok { message } => {
            tracing::info!("DR restore OK: {message}");
        }
        CliResponse::Error { message } => {
            anyhow::bail!("DR restore failed: {message}");
        }
        other => anyhow::bail!("unexpected DR restore response: {other:?}"),
    }

    // Give A' a moment to process the restored DB.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // ── Step 11: Verify A' knows its shards (Status check) ───────────────────
    let status_resp = send_cli_request_raw(&sock_a_prime, &CliRequest::Status).await;
    match status_resp {
        CliResponse::StatusOk(s) => {
            assert!(
                s.shards_placed >= 1,
                "A' should see shards_placed >= 1 after DR restore, got {}",
                s.shards_placed
            );
        }
        other => anyhow::bail!("expected StatusOk, got: {other:?}"),
    }

    // ── Step 12: Connect A' to B and restore original file ───────────────────
    connect_peers(&sock_a_prime, &node_addr_b).await?;
    tokio::time::sleep(Duration::from_millis(1000)).await;

    let dest_path = restore_dir.join("notes_dr_restored.txt");
    let restore_resp = send_cli_request_raw(
        &sock_a_prime,
        &CliRequest::RestoreFile {
            path: file_path_str.clone(),
            dest: dest_path.to_string_lossy().to_string(),
        },
    )
    .await;

    match &restore_resp {
        CliResponse::Ok { .. } | CliResponse::Accepted { .. } => {}
        other => anyhow::bail!("RestoreFile returned: {other:?}"),
    }

    // ── Step 13: Wait and verify file content ────────────────────────────────
    wait_for_file(&dest_path, Duration::from_secs(30)).await?;

    let restored = std::fs::read(&dest_path)?;
    anyhow::ensure!(
        restored == TEST_CONTENT,
        "restored content mismatch:\n  expected ({} bytes): {:?}\n  got ({} bytes): {:?}",
        TEST_CONTENT.len(),
        TEST_CONTENT,
        restored.len(),
        &restored[..restored.len().min(64)],
    );

    // ── Step 14: Shutdown ─────────────────────────────────────────────────────
    handle_b.shutdown().await?;
    handle_a_prime.shutdown().await?;

    Ok(())
}
