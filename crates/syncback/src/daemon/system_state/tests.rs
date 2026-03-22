use super::*;

// ─── snapshot_and_encrypt ────────────────────────────────────────────────────

#[test]
fn snapshot_and_encrypt_produces_nonempty_blob() {
    let db = syncback_core::db::Db::open_in_memory().unwrap();
    let seed = [42u8; 64];
    let blob = snapshot_and_encrypt(&db, &seed).unwrap();
    assert!(!blob.is_empty());
    // salt(24) + nonce(12) + tag(16) = 52 bytes minimum
    assert!(blob.len() > 52, "blob too small: {} bytes", blob.len());
}

// ─── roundtrip ───────────────────────────────────────────────────────────────

#[test]
fn snapshot_encrypt_decrypt_roundtrip() {
    let db = syncback_core::db::Db::open_in_memory().unwrap();
    let seed = [42u8; 64];
    let blob = snapshot_and_encrypt(&db, &seed).unwrap();

    let db2 = syncback_core::db::Db::open_in_memory().unwrap();
    let state = decrypt_and_restore(&db2, &blob, &seed).unwrap();
    assert_eq!(state.version, SYSTEM_STATE_VERSION);
}

// ─── wrong seed ──────────────────────────────────────────────────────────────

#[test]
fn wrong_seed_fails_decrypt() {
    let db = syncback_core::db::Db::open_in_memory().unwrap();
    let seed = [42u8; 64];
    let blob = snapshot_and_encrypt(&db, &seed).unwrap();

    let db2 = syncback_core::db::Db::open_in_memory().unwrap();
    let wrong_seed = [99u8; 64];
    assert!(
        decrypt_and_restore(&db2, &blob, &wrong_seed).is_err(),
        "decryption with wrong seed must fail"
    );
}

// ─── deterministic key derivation ────────────────────────────────────────────

#[test]
fn same_seed_produces_same_key() {
    let seed = [7u8; 64];
    let key1 = identity_key_bytes_from_seed(&seed).unwrap();
    let key2 = identity_key_bytes_from_seed(&seed).unwrap();
    assert_eq!(key1, key2);
}

#[test]
fn different_seeds_produce_different_keys() {
    let key1 = identity_key_bytes_from_seed(&[1u8; 64]).unwrap();
    let key2 = identity_key_bytes_from_seed(&[2u8; 64]).unwrap();
    assert_ne!(key1, key2);
}

// ─── short blob ──────────────────────────────────────────────────────────────

#[test]
fn short_blob_fails_decrypt() {
    let db = syncback_core::db::Db::open_in_memory().unwrap();
    let seed = [1u8; 64];
    // A blob shorter than 52 bytes cannot contain salt+nonce+tag.
    let short_blob = vec![0u8; 10];
    assert!(decrypt_and_restore(&db, &short_blob, &seed).is_err());
}
