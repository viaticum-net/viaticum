// Phase 2 Gate: two nodes, backup → restore end-to-end.
//
// Tests in this file exercise ALL cross-module flows from Phase 2:
//   1. full_backup_restore_roundtrip            — single file, byte-for-byte verify
//   2. backup_restore_pack_multiple_files        — multi-file pack, byte-for-byte verify
//   3. network_symbol_transfer_between_nodes     — two iroh nodes, SymbolTransferMsg
//   4. placement_produces_valid_allocation_for_pipeline — placement + erasure integration
//   5. relay_three_hop_message_delivery          — A→B(hop1)→C(hop2) directed message
//   6. full_pipeline_backup_encode_decode_decrypt — pure data path, no file I/O
//
// GATE CRITERIA: all 6 tests pass → Phase 2 is complete.

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use syncback::daemon::backup::{BackupConfig, BackupCoordinator, DirtyEvent, DirtyKind};
use syncback::daemon::backup::pipeline::{compress_and_encrypt, decrypt_and_decompress};
use syncback::daemon::network::{NetworkConfig, NetworkHandle};
use syncback::daemon::relay::{RelayConfig, RelayManager};
use syncback::daemon::restore::{RestoreConfig, RestoreCoordinator, RestoreRequest, VersionSelector};
use syncback_core::constants::MAX_BOARD_ENTRIES;
use syncback_core::db::Db;
use syncback_core::erasure::{ErasureEncoder, RaptorQEncoder, Symbol};
use syncback_core::messages::{Message, SymbolTransferMsg};
use syncback_core::placement::{compute_allocation, HolderCandidate};
use syncback_core::types::{DeviceId, ErasureParams, IdentityPub, SourceBlockId, Timestamp};
use tempfile::TempDir;

// ─── Shared helpers ───────────────────────────────────────────────────────────

/// Small block size for fast tests.
const SMALL_BLOCK_SIZE: u64 = 65_535 * 2;
const EPOCH_KEY: [u8; 32] = [77u8; 32];
const DEVICE_A: DeviceId = DeviceId([1u8; 16]);
const DEVICE_B: DeviceId = DeviceId([2u8; 16]);

/// 5 mock holders with varying trust — for backup/restore tests with real files.
fn test_holders() -> Vec<HolderCandidate> {
    (0..5)
        .map(|i| HolderCandidate {
            identity: IdentityPub([(i + 1) as u8; 32]),
            trust: 0.3 + (i as f64) * 0.1, // 0.3, 0.4, 0.5, 0.6, 0.7
        })
        .collect()
}

/// 2 holders for small-blob pure pipeline tests (avoids MIN_SYMBOLS_PER_HOLDER trimming).
fn test_holders_small() -> Vec<HolderCandidate> {
    vec![
        HolderCandidate { identity: IdentityPub([1u8; 32]), trust: 0.8 },
        HolderCandidate { identity: IdentityPub([2u8; 32]), trust: 0.6 },
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
        network: None,
        watch_configs: vec![],
        time_scale: 1,
    }
}

/// Restore config pointing at the same symbols_dir.
fn restore_config(symbols_dir: &TempDir) -> RestoreConfig {
    RestoreConfig {
        epoch_key: EPOCH_KEY,
        parallel_holders: 5,
        identity: IdentityPub([9u8; 32]),
        device_id: DEVICE_B,
        symbols_dir: symbols_dir.path().to_path_buf(),
    }
}

/// Write bytes to a file in a TempDir, return absolute path string.
fn write_file(dir: &TempDir, name: &str, content: &[u8]) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, content).expect("write test file");
    path.to_string_lossy().into_owned()
}

/// Create a NetworkHandle with a fresh signing key and empty peer directory.
async fn make_network_handle() -> NetworkHandle {
    let sk = SigningKey::generate(&mut OsRng);
    let (tx, _rx) = tokio::sync::mpsc::channel(64);
    NetworkHandle::start(
        NetworkConfig {
            signing_key: sk,
            known_peers: HashMap::new(),
            device_cert: None,
            iroh_secret_key: None,
            relay_mode: iroh::RelayMode::Disabled,
        },
        tx,
    )
    .await
    .expect("NetworkHandle::start")
}

// ─── Test 1: full_backup_restore_roundtrip ────────────────────────────────────
//
// End-to-end: one file → backup → restore → byte-for-byte match.
// Cross-module flow: BackupCoordinator → DB → symbols_dir → RestoreCoordinator.

#[tokio::test]
async fn full_backup_restore_roundtrip() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let out_dir = TempDir::new().unwrap();

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
    let results = backup.flush_all(true).unwrap();
    assert!(!results.is_empty(), "backup should produce at least one block");

    // Restore phase
    let network = Arc::new(make_network_handle().await);
    let restore = RestoreCoordinator::new(
        db.clone(),
        restore_config(&symbols_dir),
        Arc::new(RaptorQEncoder::new()),
        network,
    );
    let result = restore
        .restore(RestoreRequest {
            path: path.clone(),
            version_selector: VersionSelector::Latest,
            output_dir: out_dir.path().to_path_buf(),
            device_id: DEVICE_B,
        })
        .await
        .unwrap();

    assert_eq!(result.files_restored, 1, "failures: {:?}", result.failures);
    assert!(result.failures.is_empty());

    // Byte-for-byte verify
    let rel = path.trim_start_matches('/');
    let restored = std::fs::read(out_dir.path().join(rel)).unwrap();
    assert_eq!(restored, content, "restored content must match original byte-for-byte");
}

// ─── Test 2: backup_restore_pack_multiple_files ───────────────────────────────
//
// Multiple small files packed into one source block, all restore correctly.
// Validates Pack index serialization and per-file extraction in RestoreCoordinator.

#[tokio::test]
async fn backup_restore_pack_multiple_files() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let out_dir = TempDir::new().unwrap();

    let test_files: Vec<(&str, Vec<u8>)> = vec![
        ("alpha.txt", b"alpha content --- first file in the pack".to_vec()),
        ("beta.txt",  b"beta content --- second file in the pack".to_vec()),
        ("gamma.txt", b"gamma content --- third file in the pack".to_vec()),
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
    let results = backup.flush_all(true).unwrap();
    // All 3 small files fit in one block (total << SMALL_BLOCK_SIZE)
    assert_eq!(results.len(), 1, "all files should pack into one source block");

    // Restore by prefix (the files_dir path)
    let network = Arc::new(make_network_handle().await);
    let restore = RestoreCoordinator::new(
        db.clone(),
        restore_config(&symbols_dir),
        Arc::new(RaptorQEncoder::new()),
        network,
    );
    let prefix = files_dir.path().to_string_lossy().to_string() + "/";
    let result = restore
        .restore(RestoreRequest {
            path: prefix,
            version_selector: VersionSelector::Latest,
            output_dir: out_dir.path().to_path_buf(),
            device_id: DEVICE_B,
        })
        .await
        .unwrap();

    assert_eq!(result.files_restored, 3, "failures: {:?}", result.failures);
    assert_eq!(result.blocks_fetched, 1, "all files are in one block");
    assert!(result.failures.is_empty());

    // Byte-for-byte verify each file
    for (name, expected) in &test_files {
        let full_path = files_dir.path().join(name);
        let rel = full_path.to_string_lossy();
        let rel = rel.trim_start_matches('/');
        let restored = std::fs::read(out_dir.path().join(rel)).unwrap();
        assert_eq!(&restored, expected, "content mismatch for {}", name);
    }
}

// ─── Test 3: network_symbol_transfer_between_nodes ───────────────────────────
//
// Node A sends a SymbolTransferMsg with real symbol data to Node B.
// Verifies QUIC handshake + framed CBOR send/recv across two iroh endpoints.

#[tokio::test]
async fn network_symbol_transfer_between_nodes() {
    let sk_a = SigningKey::generate(&mut OsRng);
    let sk_b = SigningKey::generate(&mut OsRng);

    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(64);
    let (tx_b, mut rx_b) = tokio::sync::mpsc::channel(64);

    let handle_a = NetworkHandle::start(
        NetworkConfig { signing_key: sk_a, known_peers: HashMap::new(), device_cert: None, iroh_secret_key: None, relay_mode: iroh::RelayMode::Disabled },
        tx_a,
    )
    .await
    .unwrap();
    let handle_b = NetworkHandle::start(
        NetworkConfig { signing_key: sk_b, known_peers: HashMap::new(), device_cert: None, iroh_secret_key: None, relay_mode: iroh::RelayMode::Disabled },
        tx_b,
    )
    .await
    .unwrap();

    let addr_b = handle_b.local_addr().unwrap();

    // A connects to B and sends symbols
    let mut conn_a = handle_a.connect(addr_b, None).await.unwrap();
    let mut conn_b = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rx_b.recv(),
    )
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

    let params = ErasureParams::compute(stored.len() as u64, 0.5);
    let holders = test_holders_small();
    let allocations = compute_allocation(&holders, &params).unwrap();
    assert!(!allocations.is_empty(), "should allocate to at least one holder");

    let block_id = SourceBlockId(*blake3::hash(&stored).as_bytes());

    // Encode symbols for each holder (binding applied)
    let mut all_bound: Vec<(Symbol, IdentityPub)> = Vec::new();
    for alloc in &allocations {
        let symbols = encoder
            .encode(
                &stored,
                &params,
                alloc.start_esi,
                alloc.symbol_count,
                &block_id,
                &alloc.identity,
            )
            .unwrap();
        assert_eq!(symbols.len(), alloc.symbol_count as usize);
        for sym in symbols {
            all_bound.push((sym, alloc.identity));
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
    assert_eq!(recovered, plaintext, "recovered plaintext must match original");
}

// ─── Test 5: relay_three_hop_message_delivery ────────────────────────────────
//
// A posts directed message to C → B relays (hop 0→1) → C syncs from B (hop 1→2).
// C decrypts and reads the payload. Validates full epidemic relay chain.

#[test]
fn relay_three_hop_message_delivery() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let dir_c = TempDir::new().unwrap();

    // Use timestamps far in the future to avoid TTL expiry during the test.
    let future = Timestamp(Timestamp::now().0 + 10_000_000);

    // ── C: generate identity and X25519 keypair ──────────────────────────
    let c_signing_key = SigningKey::generate(&mut OsRng);
    let c_identity = IdentityPub(c_signing_key.verifying_key().to_bytes());
    let c_x25519_priv = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let c_x25519_pub = x25519_dalek::PublicKey::from(&c_x25519_priv);

    // ── A: post a directed message to C ─────────────────────────────────
    let config_a = RelayConfig::defaults_for_test(dir_a.path().join("board_a.bin"));
    let a_identity = config_a.identity_pub;
    let a_signing_key = SigningKey::from_bytes(&config_a.signing_key.to_bytes());
    let mut manager_a = RelayManager::new(config_a).unwrap();

    let msg_id = [0xABu8; 16];
    let payload = b"phase2 gate: relay message payload";
    manager_a
        .post_directed_with_key(
            "pos_challenge",
            msg_id,
            c_identity,
            &c_x25519_pub,
            payload,
            future,
        )
        .unwrap();

    assert_eq!(manager_a.entries.len(), 1);
    assert_eq!(manager_a.entries[0].entry.hop, 0);

    // ── B: sync from A (hop 0 → 1) ───────────────────────────────────────
    let config_b = RelayConfig::defaults_for_test(dir_b.path().join("board_b.bin"));
    let mut manager_b = RelayManager::new(config_b).unwrap();

    let a_entries = manager_a.entries_for_sync(future);
    assert_eq!(a_entries.len(), 1);

    let accepted = manager_b
        .process_remote_entries(&a_entries, future)
        .unwrap();
    assert_eq!(accepted, 1, "B must accept A's entry");
    assert_eq!(manager_b.entries[0].entry.hop, 1);

    // ── C: sync from B (hop 1 → 2) and decrypt ───────────────────────────
    let config_c = RelayConfig {
        board_path: dir_c.path().join("board_c.bin"),
        identity_pub: c_identity,
        x25519_priv: c_x25519_priv,
        signing_key: c_signing_key,
        max_entries: MAX_BOARD_ENTRIES,
        max_size_bytes: syncback_core::constants::MAX_BOARD_SIZE_BYTES,
        prune_interval_secs: 3600,
    };
    let mut manager_c = RelayManager::new(config_c).unwrap();

    let b_entries = manager_b.entries_for_sync(future);
    assert_eq!(b_entries.len(), 1);
    assert_eq!(b_entries[0].entry.hop, 1);

    let accepted = manager_c
        .process_remote_entries(&b_entries, future)
        .unwrap();
    assert_eq!(accepted, 1, "C must accept B's relayed entry");
    assert_eq!(manager_c.entries[0].entry.hop, 2);

    // C scans board and decrypts the directed message
    let (inbound_tx, mut inbound_rx) = tokio::sync::mpsc::channel(16);
    let delivered = manager_c.scan_for_self(&inbound_tx, future);
    assert_eq!(delivered, 1, "C should receive exactly one directed message");

    let msg = inbound_rx.try_recv().unwrap();
    assert_eq!(msg.payload, payload, "decrypted payload must match");
    assert_eq!(msg.from, a_identity, "author must be A");
    assert_eq!(msg.msg_id, msg_id);

    // Verify hop=2 entry is not relayed further (gate: hop limit enforced)
    let dir_d = TempDir::new().unwrap();
    let config_d = RelayConfig::defaults_for_test(dir_d.path().join("board_d.bin"));
    let mut manager_d = RelayManager::new(config_d).unwrap();

    let c_entries = manager_c.entries_for_sync(future);
    assert_eq!(c_entries[0].entry.hop, 2);

    let accepted_d = manager_d
        .process_remote_entries(&c_entries, future)
        .unwrap();
    assert_eq!(accepted_d, 0, "hop=2 must not propagate further");
    assert_eq!(manager_d.stats().0, 0);

    // Suppress unused-variable warnings from the captures above
    let _ = a_signing_key;
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
    let plaintext: Vec<u8> = (0..4096u32)
        .map(|i| ((i * 31 + 17) % 256) as u8)
        .collect();

    // Step 2: compress + encrypt → stored blob [nonce][ciphertext]
    let stored = compress_and_encrypt(&plaintext, &EPOCH_KEY).unwrap();
    assert!(stored.len() > 12, "stored must be longer than nonce");

    // Step 3: compute ErasureParams and placement allocation
    let params = ErasureParams::compute(stored.len() as u64, 0.5);
    let holders = test_holders_small();
    let allocations = compute_allocation(&holders, &params).unwrap();

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
                &alloc.identity,
            )
            .unwrap();

        // Unbind immediately (simulating the restore path)
        for sym in bound_symbols {
            let unbound = encoder.unbind(sym, &block_id, &alloc.identity);
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
        stored_recovered, stored.as_slice(),
        "decoded stored blob must match original before decrypt"
    );

    // Step 6: decrypt + decompress → original plaintext
    let recovered = decrypt_and_decompress(stored_recovered, &EPOCH_KEY).unwrap();
    assert_eq!(recovered, plaintext, "recovered plaintext must match original byte-for-byte");

    // Verify all params are internally consistent
    assert_eq!(params.k_eff, params.k + 3, "k_eff must be k+3 (decode overhead)");
    assert!(params.n >= params.k_eff, "n must be at least k_eff");
}
