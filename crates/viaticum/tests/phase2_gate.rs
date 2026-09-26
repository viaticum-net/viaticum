// Phase 2 Gate: two nodes, backup → restore end-to-end.
//
// Tests in this file exercise ALL cross-module flows from Phase 2:
//   1. full_backup_restore_roundtrip            — single file, byte-for-byte verify
//   2. backup_restore_pack_multiple_files        — multi-file pack, byte-for-byte verify
//   3. network_symbol_transfer_between_nodes     — removed in ε.5 (iroh removed)
//   4. placement_produces_valid_allocation_for_pipeline — placement + erasure integration
//   5. (removed) relay_three_hop_message_delivery — relay board retired in A2 / T-13b-3
//   6. full_pipeline_backup_encode_decode_decrypt — pure data path, no file I/O
//
// GATE CRITERIA: tests 1, 2, 4, 6 pass → Phase 2 is complete.
// Test 3 (QUIC symbol transfer) was iroh-era; libp2p equivalent in swarm_tests.rs.
// Test 5 (relay board) removed: the relay board was retired by the A2 mailbox bus.

use std::sync::Arc;

use tempfile::TempDir;
use viaticum::daemon::backup::pipeline::{compress_and_encrypt, decrypt_and_decompress};
use viaticum::daemon::backup::{BackupConfig, BackupCoordinator, DirtyEvent, DirtyKind};
use viaticum::daemon::restore::staging::JobId;
use viaticum::daemon::restore::{
    RestoreConfig, RestoreCoordinator, RestoreRequest, VersionSelector,
};
use viaticum_core::db::Db;
use viaticum_core::erasure::{ErasureEncoder, RaptorQEncoder, Symbol};
use viaticum_core::placement::{HolderCandidate, compute_allocation};
use viaticum_core::types::{DeviceId, ErasureParams, SourceBlockId};

// ─── Shared helpers ───────────────────────────────────────────────────────────

/// Small block size for fast tests.
const SMALL_BLOCK_SIZE: u64 = 65_535 * 2;
const EPOCH_KEY: [u8; 32] = [77u8; 32];
const DEVICE_A: DeviceId = DeviceId([1u8; 32]);

/// 5 mock holders with varying trust — for backup/restore tests with real files.
fn test_holders() -> Vec<HolderCandidate> {
    (0..5)
        .map(|i| HolderCandidate {
            device_id: DeviceId([(i + 1) as u8; 32]),
            trust: 0.3 + (i as f64) * 0.1, // 0.3, 0.4, 0.5, 0.6, 0.7
        })
        .collect()
}

/// 2 holders for small-blob pure pipeline tests (avoids MIN_SYMBOLS_PER_HOLDER trimming).
fn test_holders_small() -> Vec<HolderCandidate> {
    vec![
        HolderCandidate {
            device_id: DeviceId([1u8; 32]),
            trust: 0.8,
        },
        HolderCandidate {
            device_id: DeviceId([2u8; 32]),
            trust: 0.6,
        },
    ]
}

/// Backup config pointing at a symbols_dir TempDir.
fn backup_config(symbols_dir: &TempDir) -> BackupConfig {
    BackupConfig {
        source_block_size: SMALL_BLOCK_SIZE,
        symbols_dir: symbols_dir.path().to_path_buf(),
        epoch_key: EPOCH_KEY,
        device_id: DEVICE_A,
        mock_holders: test_holders(),
        cluster_state: None,
        watch_configs: vec![],
        time_scale: 1,
        mock_offer_budget_gb: None,
        master_signing_key: None,
        swarm: None,
        live_watch_configs: None,
        peer_backoff: None,
        work_event_tx: None,
    }
}

/// Restore config pointing at the same symbols_dir.
/// `staging_dir` is used as both data_dir and parent for restore/.
fn restore_config(_symbols_dir: &TempDir, staging_dir: &TempDir) -> RestoreConfig {
    let staging_root = staging_dir.path().join("restore");
    std::fs::create_dir_all(&staging_root).expect("create staging_root");
    RestoreConfig {
        epoch_key: EPOCH_KEY,
        parallel_holders: 5,
        swarm: None,
        staging_root,
        data_dir: staging_dir.path().to_path_buf(),
        fetch_timeout: std::time::Duration::from_secs(60),
    }
}

/// Write bytes to a file in a TempDir, return absolute path string.
fn write_file(dir: &TempDir, name: &str, content: &[u8]) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, content).expect("write test file");
    path.to_string_lossy().into_owned()
}

// ─── Test 1: full_backup_restore_roundtrip ────────────────────────────────────
//
// End-to-end: one file → backup → restore → byte-for-byte match.
// Cross-module flow: BackupCoordinator → DB → symbols_dir → RestoreCoordinator.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_backup_restore_roundtrip() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let staging_dir = TempDir::new().unwrap();

    // Backup phase
    let content: Vec<u8> = (0..8192u32).map(|i| (i * 7 + 13) as u8).collect();
    let path = write_file(&files_dir, "data.bin", &content);

    let mut backup = BackupCoordinator::new(
        db.clone(),
        backup_config(&symbols_dir),
        Arc::new(RaptorQEncoder::new()),
    );
    backup
        .process_event(DirtyEvent {
            path: path.clone(),
            kind: DirtyKind::Added,
            device_id: DEVICE_A,
        })
        .unwrap();
    let results = backup.flush_all(true, &Default::default()).unwrap();
    assert!(
        !results.is_empty(),
        "backup should produce at least one block"
    );

    // Restore phase
    let restore = RestoreCoordinator::new(
        db.clone(),
        restore_config(&symbols_dir, &staging_dir),
        Arc::new(RaptorQEncoder::new()),
    );
    let result = restore
        .restore(RestoreRequest {
            path: path.clone(),
            version_selector: VersionSelector::Latest,
            job_id: JobId::new(),
        })
        .await
        .unwrap();

    assert_eq!(result.files_restored, 1, "failures: {:?}", result.failures);
    assert!(result.failures.is_empty());

    // Byte-for-byte verify — file is in staging_path
    let rel = path.trim_start_matches('/');
    let restored = std::fs::read(result.staging_path.join(rel)).unwrap();
    assert_eq!(
        restored, content,
        "restored content must match original byte-for-byte"
    );
}

// ─── Test 2: backup_restore_pack_multiple_files ───────────────────────────────
//
// Multiple small files packed into one source block, all restore correctly.
// Validates Pack index serialization and per-file extraction in RestoreCoordinator.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_restore_pack_multiple_files() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let staging_dir = TempDir::new().unwrap();

    let test_files: Vec<(&str, Vec<u8>)> = vec![
        (
            "alpha.txt",
            b"alpha content --- first file in the pack".to_vec(),
        ),
        (
            "beta.txt",
            b"beta content --- second file in the pack".to_vec(),
        ),
        (
            "gamma.txt",
            b"gamma content --- third file in the pack".to_vec(),
        ),
    ];

    let mut backup = BackupCoordinator::new(
        db.clone(),
        backup_config(&symbols_dir),
        Arc::new(RaptorQEncoder::new()),
    );
    let mut paths = Vec::new();
    for (name, content) in &test_files {
        let path = write_file(&files_dir, name, content);
        backup
            .process_event(DirtyEvent {
                path: path.clone(),
                kind: DirtyKind::Added,
                device_id: DEVICE_A,
            })
            .unwrap();
        paths.push(path);
    }
    let results = backup.flush_all(true, &Default::default()).unwrap();
    // All 3 small files fit in one block (total << SMALL_BLOCK_SIZE)
    assert_eq!(
        results.len(),
        1,
        "all files should pack into one source block"
    );

    // Restore by prefix (the files_dir path)
    let restore = RestoreCoordinator::new(
        db.clone(),
        restore_config(&symbols_dir, &staging_dir),
        Arc::new(RaptorQEncoder::new()),
    );
    let prefix = files_dir.path().to_string_lossy().to_string() + "/";
    let result = restore
        .restore(RestoreRequest {
            path: prefix,
            version_selector: VersionSelector::Latest,
            job_id: JobId::new(),
        })
        .await
        .unwrap();

    assert_eq!(result.files_restored, 3, "failures: {:?}", result.failures);
    assert_eq!(result.blocks_fetched, 1, "all files are in one block");
    assert!(result.failures.is_empty());

    // Byte-for-byte verify each file — files are in staging_path
    for (name, expected) in &test_files {
        let full_path = files_dir.path().join(name);
        let rel = full_path.to_string_lossy();
        let rel = rel.trim_start_matches('/');
        let restored = std::fs::read(result.staging_path.join(rel)).unwrap();
        assert_eq!(&restored, expected, "content mismatch for {}", name);
    }
}

// ─── Test 3: network_symbol_transfer_between_nodes ───────────────────────────
//
// Disabled in ε.5: used iroh QUIC NetworkHandle.
// Network transfer is tested in swarm_tests.rs (libp2p) and E2E suite.

#[cfg(any())]
async fn network_symbol_transfer_between_nodes() {
    // Node A
    let seed_a = [0xA1u8; 32];
    let master_key_a = derive_master_key(&seed_a).unwrap();
    let did_a = DeviceId([0xA1u8; 16]);
    let device_key_a = derive_device_key(&seed_a, &did_a).unwrap();
    let cert_a = issue_device_certificate(
        &master_key_a,
        did_a,
        device_key_a.verifying_key().to_bytes(),
        Timestamp::now(),
    );

    // Node B
    let seed_b = [0xB1u8; 32];
    let master_key_b = derive_master_key(&seed_b).unwrap();
    let did_b = DeviceId([0xB1u8; 16]);
    let device_key_b = derive_device_key(&seed_b, &did_b).unwrap();
    let cert_b = issue_device_certificate(
        &master_key_b,
        did_b,
        device_key_b.verifying_key().to_bytes(),
        Timestamp::now(),
    );

    let pk_a = master_identity(&master_key_a);
    let pk_b = master_identity(&master_key_b);

    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(64);
    let (tx_b, mut rx_b) = tokio::sync::mpsc::channel(64);

    let handle_a = NetworkHandle::start(
        NetworkConfig {
            signing_key: device_key_a,
            master_signing_key: master_key_a,
            master_identity: pk_a,
            known_peers: HashMap::new(),
            device_cert: Some(cert_a),
            iroh_secret_key: None,
            relay_mode: iroh::RelayMode::Disabled,
            x25519_pub: None,
        },
        tx_a,
    )
    .await
    .unwrap();
    let handle_b = NetworkHandle::start(
        NetworkConfig {
            signing_key: device_key_b,
            master_signing_key: master_key_b,
            master_identity: pk_b,
            known_peers: HashMap::new(),
            device_cert: Some(cert_b),
            iroh_secret_key: None,
            relay_mode: iroh::RelayMode::Disabled,
            x25519_pub: None,
        },
        tx_b,
    )
    .await
    .unwrap();

    let addr_b = handle_b.local_addr().unwrap();

    // A connects to B and sends symbols
    let mut conn_a = handle_a.connect(addr_b, None).await.unwrap();
    let mut conn_b = tokio::time::timeout(std::time::Duration::from_secs(5), rx_b.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    // Build a SymbolTransferMsg with 3 real symbols (small data for speed)
    let block_id = SourceBlockId([42u8; 32]);
    let symbols: Vec<Symbol> = (0u32..3)
        .map(|esi| Symbol {
            esi,
            data: vec![(esi as u8).wrapping_mul(7); 128],
        })
        .collect();

    let transfer_msg = SymbolTransferMsg {
        v: 1,
        source_block_id: block_id,
        symbols: symbols.clone(),
        timestamp: Timestamp::now(),
    };

    NetworkHandle::send_message(&mut conn_a, &Message::SymbolTransfer(transfer_msg.clone()))
        .await
        .unwrap();

    let received = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        NetworkHandle::recv_message(&mut conn_b),
    )
    .await
    .expect("timeout")
    .unwrap();

    // Verify the received message matches exactly
    match received {
        Message::SymbolTransfer(m) => {
            assert_eq!(m.source_block_id, block_id);
            assert_eq!(m.symbols.len(), 3);
            for (got, want) in m.symbols.iter().zip(symbols.iter()) {
                assert_eq!(got.esi, want.esi);
                assert_eq!(got.data, want.data);
            }
        }
        other => panic!("expected SymbolTransfer, got {:?}", other),
    }

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

// ─── Test 4: placement_produces_valid_allocation_for_pipeline ─────────────────
//
// Placement allocates symbols → encoder encodes each holder's range with binding
// → collect and unbind → decode → verify matches original stored blob.
// Validates that placement ESI ranges + binding is consistent end-to-end.

#[test]
fn placement_produces_valid_allocation_for_pipeline() {
    let encoder = RaptorQEncoder::new();

    // Create a stored blob (compress+encrypt a small payload)
    let plaintext = b"placement integration test payload";
    let stored = compress_and_encrypt(plaintext, &EPOCH_KEY).unwrap();

    let params = ErasureParams::compute(stored.len() as u64, 0.5).unwrap();
    let holders = test_holders_small();
    let allocations = compute_allocation(&holders, &params, 0).unwrap();
    assert!(
        !allocations.is_empty(),
        "should allocate to at least one holder"
    );

    let block_id = SourceBlockId(*blake3::hash(&stored).as_bytes());

    // Encode symbols for each holder (binding applied)
    let mut all_bound: Vec<(Symbol, DeviceId)> = Vec::new();
    for alloc in &allocations {
        let symbols = encoder
            .encode(
                &stored,
                &params,
                alloc.start_esi,
                alloc.symbol_count,
                &block_id,
                &alloc.device_id,
            )
            .unwrap();
        assert_eq!(symbols.len(), alloc.symbol_count as usize);
        for sym in symbols {
            all_bound.push((sym, alloc.device_id));
        }
    }

    // Unbind and collect k_eff symbols for decoding
    let k_eff = params.k_eff as usize;
    let mut unbound: Vec<Symbol> = all_bound
        .into_iter()
        .take(k_eff)
        .map(|(sym, holder_id)| encoder.unbind(sym, &block_id, &holder_id))
        .collect();
    assert_eq!(unbound.len(), k_eff);

    // Sort by ESI for decoder (some decoders are order-sensitive)
    unbound.sort_by_key(|s| s.esi);

    // Decode
    let padded = encoder.decode(&unbound, &params).unwrap();
    assert!(padded.len() >= stored.len());
    let decoded_stored = &padded[..stored.len()];

    // Decrypt and decompress
    let recovered = decrypt_and_decompress(decoded_stored, &EPOCH_KEY).unwrap();
    assert_eq!(
        recovered, plaintext,
        "recovered plaintext must match original"
    );
}

// ─── Test 6: full_pipeline_backup_encode_decode_decrypt ──────────────────────
//
// Pure data-flow: no file I/O, no DB writes. Validates the cryptographic
// and erasure pipeline from raw bytes through all transformations and back.
// Cross-module: backup/pipeline (encrypt) + placement + erasure + backup/pipeline (decrypt).

#[test]
fn full_pipeline_backup_encode_decode_decrypt() {
    let encoder = RaptorQEncoder::new();

    // Step 1: arbitrary plaintext data
    let plaintext: Vec<u8> = (0..4096u32).map(|i| ((i * 31 + 17) % 256) as u8).collect();

    // Step 2: compress + encrypt → stored blob [nonce][ciphertext]
    let stored = compress_and_encrypt(&plaintext, &EPOCH_KEY).unwrap();
    assert!(stored.len() > 12, "stored must be longer than nonce");

    // Step 3: compute ErasureParams and placement allocation
    let params = ErasureParams::compute(stored.len() as u64, 0.5).unwrap();
    let holders = test_holders_small();
    let allocations = compute_allocation(&holders, &params, 0).unwrap();

    // source_block_id = blake3(stored)
    let block_id = SourceBlockId(*blake3::hash(&stored).as_bytes());

    // Step 4: for each holder, encode their ESI range with binding
    let mut all_unbound: Vec<Symbol> = Vec::new();
    for alloc in &allocations {
        let bound_symbols = encoder
            .encode(
                &stored,
                &params,
                alloc.start_esi,
                alloc.symbol_count,
                &block_id,
                &alloc.device_id,
            )
            .unwrap();

        // Unbind immediately (simulating the restore path)
        for sym in bound_symbols {
            let unbound = encoder.unbind(sym, &block_id, &alloc.device_id);
            all_unbound.push(unbound);

            // Stop once we have enough symbols (k_eff)
            if all_unbound.len() >= params.k_eff as usize {
                break;
            }
        }

        if all_unbound.len() >= params.k_eff as usize {
            break;
        }
    }

    assert!(
        all_unbound.len() >= params.k_eff as usize,
        "must collect at least k_eff={} symbols, got {}",
        params.k_eff,
        all_unbound.len()
    );

    // Step 5: decode → padded block of k*t bytes
    all_unbound.sort_by_key(|s| s.esi);
    let padded = encoder.decode(&all_unbound, &params).unwrap();
    assert!(padded.len() >= stored.len());

    // Trim to stored_size
    let stored_recovered = &padded[..stored.len()];
    assert_eq!(
        stored_recovered,
        stored.as_slice(),
        "decoded stored blob must match original before decrypt"
    );

    // Step 6: decrypt + decompress → original plaintext
    let recovered = decrypt_and_decompress(stored_recovered, &EPOCH_KEY).unwrap();
    assert_eq!(
        recovered, plaintext,
        "recovered plaintext must match original byte-for-byte"
    );

    // Verify all params are internally consistent
    assert_eq!(
        params.k_eff,
        params.k + 3,
        "k_eff must be k+3 (decode overhead)"
    );
    assert!(params.n >= params.k_eff, "n must be at least k_eff");
}
