//! Unit tests for the packer module.
//!
//! All tests use real filesystem (tempfile::TempDir) and real DB where needed.

use std::io::Write as _;

use syncback_core::types::{FileId, FileRecord, Timestamp, UnitId, UnitType};

use crate::daemon::crypto;

use super::*;

// ============================================================
// Test helpers
// ============================================================

fn test_identity_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[1u8; 32])
}

fn test_identity_pub() -> syncback_core::types::IdentityPub {
    syncback_core::types::IdentityPub(
        test_identity_key().verifying_key().to_bytes(),
    )
}

fn make_packer() -> Packer {
    // Use a real tempfile-based DB; Packer only reads files from DB in pack_batch.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db = syncback_core::db::Db::open(tmp.path()).unwrap();
    Packer::new(db, test_identity_key(), test_identity_pub(), DEFAULT_UNIT_SIZE_BYTES)
}

fn make_packer_with_unit_size(unit_size_bytes: u64) -> Packer {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db = syncback_core::db::Db::open(tmp.path()).unwrap();
    Packer::new(db, test_identity_key(), test_identity_pub(), unit_size_bytes)
}

fn test_timestamp() -> Timestamp {
    Timestamp(1_700_000_000)
}

/// Write content to a file in the TempDir and return a FileRecord.
fn make_file_record(
    dir: &tempfile::TempDir,
    name: &str,
    content: &[u8],
    file_id: u64,
    importance: f64,
) -> FileRecord {
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(content).unwrap();
    drop(f);

    let content_hash = *blake3::hash(content).as_bytes();
    FileRecord {
        file_id: FileId(file_id),
        path: path.to_str().unwrap().to_string(),
        content_hash,
        size_bytes: content.len() as u64,
        importance,
        dirty: true,
        current_unit_id: None,
        last_backed_up: None,
        backed_up: false,
        first_seen: test_timestamp(),
    }
}

// ============================================================
// Key derivation tests
// ============================================================

#[test]
fn derive_unit_key_is_deterministic() {
    let packer = make_packer();
    let unit_id = UnitId([2u8; 32]);
    let k1 = packer.derive_unit_key(unit_id);
    let k2 = packer.derive_unit_key(unit_id);
    assert_eq!(k1, k2);
    assert_ne!(k1, [0u8; 32]);
}

#[test]
fn derive_unit_key_differs_per_unit() {
    let packer = make_packer();
    let k1 = packer.derive_unit_key(UnitId([1u8; 32]));
    let k2 = packer.derive_unit_key(UnitId([2u8; 32]));
    assert_ne!(k1, k2);
}

// ============================================================
// Encrypt / decrypt tests
// ============================================================

#[test]
fn encrypt_decrypt_roundtrip() {
    let key = [0xabu8; 32];
    let plaintext = b"test plaintext data";
    let ciphertext = crypto::encrypt_plaintext(&key, plaintext).unwrap();
    assert_ne!(ciphertext.as_slice(), plaintext.as_slice());
    let recovered = crypto::decrypt_ciphertext(&key, &ciphertext).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn encrypt_decrypt_different_nonces() {
    let key = [0u8; 32];
    let c1 = crypto::encrypt_plaintext(&key, b"test").unwrap();
    let c2 = crypto::encrypt_plaintext(&key, b"test").unwrap();
    // Different random nonces → different ciphertext.
    assert_ne!(c1, c2);
    // Both decrypt to same plaintext.
    assert_eq!(crypto::decrypt_ciphertext(&key, &c1).unwrap(), b"test");
    assert_eq!(crypto::decrypt_ciphertext(&key, &c2).unwrap(), b"test");
}

// ============================================================
// PackIndex CBOR round-trip
// ============================================================

#[test]
fn pack_index_round_trip_cbor() {
    let index = PackIndex {
        version: 1,
        members: vec![PackMember {
            path: "/foo/bar.txt".into(),
            file_id: 42,
            offset: 0,
            length: 100,
            content_hash: [0u8; 32],
            importance: 0.5,
        }],
    };
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&index, &mut bytes).unwrap();
    let decoded: PackIndex = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    assert_eq!(decoded.version, 1);
    assert_eq!(decoded.members.len(), 1);
    assert_eq!(decoded.members[0].path, "/foo/bar.txt");
    assert_eq!(decoded.members[0].file_id, 42);
    assert_eq!(decoded.members[0].length, 100);
}

// ============================================================
// pack_unit tests
// ============================================================

#[test]
fn pack_unit_single_small_file() {
    let dir = tempfile::TempDir::new().unwrap();
    let content = b"hello world";
    let file = make_file_record(&dir, "foo.txt", content, 1, 0.9);

    let packer = make_packer();
    let now = test_timestamp();
    let result = packer.pack_unit(&[file.clone()], 0.9, now).unwrap();

    assert_eq!(result.unit_record.unit_type, UnitType::Pack);
    assert_eq!(result.unit_record.member_file_ids, vec![FileId(1)]);
    assert!((result.unit_record.importance_avg - 0.9).abs() < 1e-9);
    // Plaintext has 4-byte prefix + index bytes + file bytes.
    assert!(result.plaintext.len() > content.len());
    assert_eq!(result.file_records.len(), 1);
    assert_eq!(result.file_records[0].file_id, FileId(1));
    assert!((result.importance - 0.9).abs() < 1e-9);
    assert!(result.chunk_info.is_none());
}

#[test]
fn pack_unit_multiple_files_index_round_trip() {
    let dir = tempfile::TempDir::new().unwrap();
    let contents = [
        vec![0x01u8; 1000],
        vec![0x02u8; 2000],
        vec![0x03u8; 3000],
    ];
    let files: Vec<FileRecord> = contents
        .iter()
        .enumerate()
        .map(|(i, c)| make_file_record(&dir, &format!("f{i}.bin"), c, i as u64 + 1, 0.5))
        .collect();

    let packer = make_packer();
    let now = test_timestamp();
    let result = packer.pack_unit(&files, 0.5, now).unwrap();

    // Round-trip: unpack the plaintext.
    let unpacked = unpack_pack_plaintext(&result.plaintext).unwrap();
    assert_eq!(unpacked.len(), 3);
    for (i, uf) in unpacked.iter().enumerate() {
        assert_eq!(uf.bytes, contents[i]);
    }
}

#[test]
fn pack_unit_id_is_unique_per_call() {
    let dir = tempfile::TempDir::new().unwrap();
    let f1 = make_file_record(&dir, "a.txt", b"aaa", 1, 0.5);
    let f2 = make_file_record(&dir, "b.txt", b"bbb", 2, 0.5);

    let packer = make_packer();
    let now = test_timestamp();
    let r1 = packer.pack_unit(&[f1], 0.5, now).unwrap();
    let r2 = packer.pack_unit(&[f2], 0.5, now).unwrap();
    assert_ne!(r1.unit_record.unit_id, r2.unit_record.unit_id);
}

#[test]
fn pack_unit_importance_too_low_returns_error() {
    let dir = tempfile::TempDir::new().unwrap();
    let f = make_file_record(&dir, "x.bin", b"data", 1, 0.05);
    let packer = make_packer();
    let err = packer.pack_unit(&[f], 0.05, test_timestamp()).unwrap_err();
    assert!(matches!(err, PackerError::ImportanceTooLow(_)));
}

// ============================================================
// chunk_file tests
// ============================================================

#[test]
fn chunk_file_exact_unit_size_produces_one_chunk() {
    let unit_size: u64 = 1024;
    let dir = tempfile::TempDir::new().unwrap();
    let content = vec![0x42u8; unit_size as usize];
    let mut file = make_file_record(&dir, "exact.bin", &content, 1, 0.9);
    // chunk_file reads size from disk, not from FileRecord.size_bytes.
    // But we still set it for correctness.
    file.size_bytes = unit_size;

    let packer = make_packer_with_unit_size(unit_size);
    let now = test_timestamp();
    let results = packer.chunk_file(&file, now).unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].unit_record.unit_type, UnitType::Chunk);
    assert_eq!(results[0].unit_record.chunk_index, Some(0));
    assert_eq!(results[0].plaintext.len(), unit_size as usize);
    assert_eq!(results[0].unit_record.parent_file_id, Some(FileId(1)));
    let ci = results[0].chunk_info.as_ref().unwrap();
    assert_eq!(ci.chunk_index, 0);
    assert_eq!(ci.total_chunks, 1);
}

#[test]
fn chunk_file_splits_large_file() {
    let unit_size: u64 = 1024;
    let total = unit_size * 3 + 512; // 3.5 units → 4 chunks

    let dir = tempfile::TempDir::new().unwrap();
    let content = vec![0x77u8; total as usize];
    let mut file = make_file_record(&dir, "large.bin", &content, 1, 0.9);
    file.size_bytes = total;

    let packer = make_packer_with_unit_size(unit_size);
    let results = packer.chunk_file(&file, test_timestamp()).unwrap();

    assert_eq!(results.len(), 4);
    for (i, r) in results.iter().enumerate() {
        assert_eq!(r.unit_record.unit_type, UnitType::Chunk);
        assert_eq!(r.unit_record.chunk_index, Some(i as u32));
    }
    assert_eq!(results[0].plaintext.len(), unit_size as usize);
    assert_eq!(results[1].plaintext.len(), unit_size as usize);
    assert_eq!(results[2].plaintext.len(), unit_size as usize);
    assert_eq!(results[3].plaintext.len(), 512); // remainder
}

#[test]
fn chunk_unit_id_stable_for_same_content() {
    let unit_size: u64 = 1024;
    let dir = tempfile::TempDir::new().unwrap();
    let content = vec![0x33u8; unit_size as usize];
    let file = make_file_record(&dir, "stable.bin", &content, 1, 0.9);

    let packer = make_packer_with_unit_size(unit_size);
    let now = test_timestamp();
    let r1 = packer.chunk_file(&file, now).unwrap();
    let r2 = packer.chunk_file(&file, now).unwrap();

    // Same content_hash + chunk_index → same unit_id.
    assert_eq!(
        r1[0].unit_record.unit_id,
        r2[0].unit_record.unit_id
    );
}

// ============================================================
// unpack_unit tests
// ============================================================

/// Build shard blobs from a pack result for use in unpack_unit.
fn shards_from_pack_result(
    packer: &Packer,
    result: &PackResult,
) -> (Vec<Option<Vec<u8>>>, usize, usize) {
    let k = result.unit_record.rs_k as usize;
    let n = result.unit_record.rs_n as usize;
    let unit_id = result.unit_record.unit_id;

    let ikm: [u8; 32] = packer.identity_key.to_bytes();
    let key = crypto::derive_unit_key(&ikm, unit_id);
    let ciphertext = crypto::encrypt_plaintext(&key, &result.plaintext).unwrap();
    let shards = crypto::rs_encode(&ciphertext, k, n).unwrap();

    let blobs: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
    (blobs, k, n)
}

#[test]
fn unpack_unit_recovers_pack_from_all_shards() {
    let dir = tempfile::TempDir::new().unwrap();
    let contents = [vec![0xAAu8; 100], vec![0xBBu8; 200]];
    let files: Vec<FileRecord> = contents
        .iter()
        .enumerate()
        .map(|(i, c)| make_file_record(&dir, &format!("f{i}.bin"), c, i as u64 + 1, 0.5))
        .collect();

    let packer = make_packer();
    let result = packer.pack_unit(&files, 0.5, test_timestamp()).unwrap();
    let unit_id = result.unit_record.unit_id;
    let (blobs, k, n) = shards_from_pack_result(&packer, &result);

    let unpacked = packer
        .unpack_unit(unit_id, UnitType::Pack, blobs, k, n)
        .unwrap();
    assert_eq!(unpacked.files.len(), 2);
    assert_eq!(unpacked.files[0].bytes, contents[0]);
    assert_eq!(unpacked.files[1].bytes, contents[1]);
}

#[test]
fn unpack_unit_recovers_from_k_of_n_shards() {
    let dir = tempfile::TempDir::new().unwrap();
    let contents = [vec![1u8; 500], vec![2u8; 300], vec![3u8; 200]];
    // importance=0.1 → Low tier → k=5, n=7
    let files: Vec<FileRecord> = contents
        .iter()
        .enumerate()
        .map(|(i, c)| make_file_record(&dir, &format!("g{i}.bin"), c, i as u64 + 1, 0.1))
        .collect();

    let packer = make_packer();
    let result = packer.pack_unit(&files, 0.1, test_timestamp()).unwrap();
    let unit_id = result.unit_record.unit_id;
    let k = result.unit_record.rs_k as usize; // 5
    let n = result.unit_record.rs_n as usize; // 7

    assert_eq!(n, 7, "expected Low tier n=7 for importance=0.1");

    let (mut blobs, _k, _n) = shards_from_pack_result(&packer, &result);

    // Lose 2 shards (indices 0 and 3) — still have 5 of 7.
    blobs[0] = None;
    blobs[3] = None;

    let unpacked = packer
        .unpack_unit(unit_id, UnitType::Pack, blobs, k, n)
        .unwrap();
    assert_eq!(unpacked.files.len(), 3);
    assert_eq!(unpacked.files[0].bytes, contents[0]);
    assert_eq!(unpacked.files[1].bytes, contents[1]);
    assert_eq!(unpacked.files[2].bytes, contents[2]);
}

#[test]
fn unpack_unit_fails_below_k() {
    let dir = tempfile::TempDir::new().unwrap();
    // importance=0.1 → Low tier → k=5, n=7
    let f = make_file_record(&dir, "h.bin", &vec![0xFFu8; 100], 1, 0.1);

    let packer = make_packer();
    let result = packer.pack_unit(&[f], 0.1, test_timestamp()).unwrap();
    let unit_id = result.unit_record.unit_id;
    let k = result.unit_record.rs_k as usize; // 5
    let n = result.unit_record.rs_n as usize; // 7

    assert_eq!(n, 7, "expected Low tier n=7 for importance=0.1");

    let (mut blobs, _k, _n) = shards_from_pack_result(&packer, &result);
    // Lose 4 of 7 shards → only 3 remain (< k=5).
    blobs[0] = None;
    blobs[1] = None;
    blobs[2] = None;
    blobs[3] = None;

    let err = packer
        .unpack_unit(unit_id, UnitType::Pack, blobs, k, n)
        .unwrap_err();
    assert!(matches!(err, PackerError::NotEnoughShards { need: 5, have: 3 }), "got: {err:?}");
}

#[test]
fn unpack_unit_chunk_returns_raw_bytes() {
    let unit_size: u64 = 512;
    let dir = tempfile::TempDir::new().unwrap();
    let content = vec![0x55u8; unit_size as usize];
    let file = make_file_record(&dir, "chunk.bin", &content, 1, 0.5);

    let packer = make_packer_with_unit_size(unit_size);
    let chunks = packer.chunk_file(&file, test_timestamp()).unwrap();
    assert_eq!(chunks.len(), 1);

    let result = &chunks[0];
    let unit_id = result.unit_record.unit_id;
    let k = result.unit_record.rs_k as usize;
    let n = result.unit_record.rs_n as usize;

    let (blobs, _k, _n) = shards_from_pack_result(&packer, result);

    let unpacked = packer
        .unpack_unit(unit_id, UnitType::Chunk, blobs, k, n)
        .unwrap();
    assert_eq!(unpacked.files.len(), 1);
    assert!(unpacked.files[0].path.is_none());
    assert_eq!(unpacked.files[0].bytes, content);
}

// ============================================================
// derive_chunk_unit_id tests
// ============================================================

#[test]
fn derive_chunk_unit_id_is_deterministic() {
    let hash = [0xCAu8; 32];
    let id1 = derive_chunk_unit_id(&hash, 0);
    let id2 = derive_chunk_unit_id(&hash, 0);
    assert_eq!(id1, id2);
}

#[test]
fn derive_chunk_unit_id_differs_per_chunk_index() {
    let hash = [0xCAu8; 32];
    let id0 = derive_chunk_unit_id(&hash, 0);
    let id1 = derive_chunk_unit_id(&hash, 1);
    assert_ne!(id0, id1);
}

// ============================================================
// pack_batch tests (using fake file sizes via small unit_size)
// ============================================================

#[test]
fn pack_batch_groups_small_files() {
    // unit_size_bytes = 300 bytes. Three files of 100 bytes each.
    // Greedy: file0+file1 = 200 ≤ 300 → same pack.
    //         file2 added: 200+100=300 ≤ 300 → still same pack.
    // All three fit → 1 PackResult.
    let unit_size: u64 = 301; // slightly above 300 so 3×100=300 fits
    let dir = tempfile::TempDir::new().unwrap();

    let tmp_db = tempfile::NamedTempFile::new().unwrap();
    let db = syncback_core::db::Db::open(tmp_db.path()).unwrap();

    let mut files = Vec::new();
    for i in 0..3u64 {
        let content = vec![i as u8 + 1; 100];
        let rec = make_file_record(&dir, &format!("s{i}.bin"), &content, i + 1, 0.5);
        db.upsert_file(&rec).unwrap();
        files.push(rec);
    }

    let packer =
        Packer::new(db, test_identity_key(), test_identity_pub(), unit_size);
    let candidates: Vec<syncback_core::budget::BackupCandidate> = files
        .iter()
        .map(|f| syncback_core::budget::BackupCandidate {
            path: f.path.clone(),
            importance: f.importance,
            required_gb: 0.0,
        })
        .collect();

    let results = packer.pack_batch(&candidates, test_timestamp());
    assert_eq!(results.len(), 1, "all 3 files should fit in one pack");
    assert_eq!(results[0].unit_record.member_file_ids.len(), 3);
}

#[test]
fn pack_batch_splits_into_two_packs() {
    // unit_size_bytes = 150. Two files of 100 bytes: first pack 100, second pack 100.
    let unit_size: u64 = 150;
    let dir = tempfile::TempDir::new().unwrap();
    let tmp_db = tempfile::NamedTempFile::new().unwrap();
    let db = syncback_core::db::Db::open(tmp_db.path()).unwrap();

    let mut files = Vec::new();
    for i in 0..2u64 {
        let content = vec![i as u8 + 1; 100];
        let rec = make_file_record(&dir, &format!("t{i}.bin"), &content, i + 1, 0.5);
        db.upsert_file(&rec).unwrap();
        files.push(rec);
    }

    let packer = Packer::new(db, test_identity_key(), test_identity_pub(), unit_size);
    let candidates: Vec<syncback_core::budget::BackupCandidate> = files
        .iter()
        .map(|f| syncback_core::budget::BackupCandidate {
            path: f.path.clone(),
            importance: f.importance,
            required_gb: 0.0,
        })
        .collect();

    let results = packer.pack_batch(&candidates, test_timestamp());
    // file0 (100) fits in pack1. file1 (100): 100+100=200 > 150 → new pack.
    assert_eq!(results.len(), 2, "should create 2 packs");
}

#[test]
fn pack_batch_chunks_large_file() {
    // unit_size = 1024, file = 2.5 * unit_size → 3 chunks.
    let unit_size: u64 = 1024;
    let total = (unit_size as f64 * 2.5) as usize;
    let dir = tempfile::TempDir::new().unwrap();
    let tmp_db = tempfile::NamedTempFile::new().unwrap();
    let db = syncback_core::db::Db::open(tmp_db.path()).unwrap();

    let content = vec![0x99u8; total];
    let mut rec = make_file_record(&dir, "big.bin", &content, 1, 0.9);
    rec.size_bytes = total as u64;
    db.upsert_file(&rec).unwrap();

    let packer = Packer::new(db, test_identity_key(), test_identity_pub(), unit_size);
    let candidates = vec![syncback_core::budget::BackupCandidate {
        path: rec.path.clone(),
        importance: rec.importance,
        required_gb: 0.0,
    }];

    let results = packer.pack_batch(&candidates, test_timestamp());
    assert_eq!(results.len(), 3);
    for r in &results {
        assert_eq!(r.unit_record.unit_type, UnitType::Chunk);
    }
    assert_eq!(results[0].plaintext.len(), unit_size as usize);
    assert_eq!(results[1].plaintext.len(), unit_size as usize);
    assert_eq!(results[2].plaintext.len(), unit_size as usize / 2); // 512 bytes
}

#[test]
fn pack_batch_missing_file_skips_gracefully() {
    let tmp_db = tempfile::NamedTempFile::new().unwrap();
    let db = syncback_core::db::Db::open(tmp_db.path()).unwrap();

    // File record in DB but file deleted from disk.
    let rec = FileRecord {
        file_id: FileId(1),
        path: "/nonexistent/ghost.bin".to_string(),
        content_hash: [0u8; 32],
        size_bytes: 100,
        importance: 0.5,
        dirty: true,
        current_unit_id: None,
        last_backed_up: None,
        backed_up: false,
        first_seen: test_timestamp(),
    };
    db.upsert_file(&rec).unwrap();

    let packer = Packer::new(db, test_identity_key(), test_identity_pub(), DEFAULT_UNIT_SIZE_BYTES);
    let candidates = vec![syncback_core::budget::BackupCandidate {
        path: rec.path.clone(),
        importance: rec.importance,
        required_gb: 0.0,
    }];

    // Should not panic; skips the missing file.
    let results = packer.pack_batch(&candidates, test_timestamp());
    assert!(results.is_empty());
}
