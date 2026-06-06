use super::*;

fn key() -> [u8; 32] {
    [0x5Au8; 32]
}

#[test]
fn build_state_block_is_deterministic_and_content_addressed() {
    let plaintext = b"the quick brown fox jumps over the lazy dog".repeat(100);
    let (id1, blob1) = build_state_block(&plaintext, &key()).unwrap();
    let (id2, blob2) = build_state_block(&plaintext, &key()).unwrap();

    assert_eq!(id1, id2, "same plaintext+key must yield same block_id");
    assert_eq!(blob1, blob2, "deterministic blob");
    assert_eq!(
        id1.0,
        *blake3::hash(&blob1).as_bytes(),
        "block_id must be blake3(blob)"
    );
}

#[test]
fn different_key_yields_different_block() {
    let plaintext = b"system state payload".repeat(50);
    let (id_a, _) = build_state_block(&plaintext, &[1u8; 32]).unwrap();
    let (id_b, _) = build_state_block(&plaintext, &[2u8; 32]).unwrap();
    assert_ne!(id_a, id_b);
}

#[test]
fn retain_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let plaintext = b"snapshot bytes".repeat(200);
    let (id, blob) = build_state_block(&plaintext, &key()).unwrap();

    store_retained_block(dir.path(), &id, &blob).unwrap();
    let loaded = load_retained_block(dir.path(), &id).unwrap();
    assert_eq!(loaded, blob);
}

#[test]
fn store_rejects_mismatched_block_id() {
    let dir = tempfile::tempdir().unwrap();
    let (_id, blob) = build_state_block(b"abc", &key()).unwrap();
    let wrong = SourceBlockId([0xFFu8; 32]);
    let err = store_retained_block(dir.path(), &wrong, &blob);
    assert!(err.is_err(), "must refuse to retain under a wrong block_id");
}

#[test]
fn load_detects_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let (id, blob) = build_state_block(b"important state".repeat(10).as_slice(), &key()).unwrap();
    store_retained_block(dir.path(), &id, &blob).unwrap();

    // Corrupt the retained file in place.
    let path = retained_block_path(dir.path(), &id);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[0] ^= 0xFF;
    std::fs::write(&path, &bytes).unwrap();

    let err = load_retained_block(dir.path(), &id);
    assert!(err.is_err(), "corrupted retained block must fail to load");
}

#[test]
fn remove_retained_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let (id, blob) = build_state_block(b"x".repeat(100).as_slice(), &key()).unwrap();
    store_retained_block(dir.path(), &id, &blob).unwrap();
    remove_retained_block(dir.path(), &id).unwrap();
    // Second remove (file already gone) is not an error.
    remove_retained_block(dir.path(), &id).unwrap();
    assert!(load_retained_block(dir.path(), &id).is_err());
}

#[test]
fn ss_record_has_max_importance_and_high_overhead() {
    let (id, blob) = build_state_block(&b"state".repeat(5000), &key()).unwrap();
    let rec = ss_source_block_record(id, blob.len()).unwrap();

    assert_eq!(rec.block_id, id);
    assert!((rec.importance - 1.0).abs() < 1e-12, "MAX importance");
    // overhead = 1.5 + importance*1.5 = 3.0 at importance 1.0 (unusually high replication).
    assert!(
        (rec.overhead.unwrap() - 3.0).abs() < 1e-9,
        "overhead {:?} should be 3.0 at max importance",
        rec.overhead
    );
    assert_eq!(rec.encrypted_size, Some(blob.len() as u64));
    assert!(rec.n.unwrap() >= rec.k, "n must cover at least k symbols");
    assert!(rec.target_reliability > 0.99, "SS target reliability very high");
}
