use super::*;

// ─── Pointer cadence helpers (the publisher itself: `pointer/tests.rs`) ─────────

mod cadence {
    use viaticum_core::cluster::derive_master_key;
    use viaticum_core::constants::MAILBOX_POINTER_REPUBLISH_SECS;
    use viaticum_core::db::testutil::test_db;
    use viaticum_core::mailbox::class_config;
    use viaticum_core::system_state::CatalogLineageId;
    use viaticum_core::types::{
        DeviceId, SourceBlockId, SourceBlockRecord, SourceBlockStatus, SourceBlockType, Timestamp,
    };

    use crate::daemon::system_state::pointer_refresh_interval_secs;
    use crate::daemon::system_state::publish::{PointerCatalog, build_pointer_for_placed};

    /// T-8: base not placed (no Alive holder) → no pointer to publish.
    #[test]
    fn pointer_not_published_before_base_placed() {
        let db = test_db();
        let master_key = derive_master_key(&[0xCD; 64]).unwrap();
        let block_id = SourceBlockId([0xDD; 32]);
        db.upsert_source_block(&SourceBlockRecord {
            seal_generation: 0,
            esi_high_water: 0,
            block_id,
            k: 6,
            t: 512,
            block_type: SourceBlockType::Single,
            status: SourceBlockStatus::Active,
            created_at: Timestamp(1),
            encrypted_size: Some(1024),
            n: Some(10),
            overhead: Some(1.5),
            drop_notice_sent_at: None,
            importance: 1.0,
            current_alive: 0,
            current_reliability: 0.0,
            target_reliability: 0.99,
        })
        .unwrap();
        let catalog = PointerCatalog {
            lineage: CatalogLineageId([0x4c; 16]),
            publisher: DeviceId([0xd1; 32]),
            files_after: &[3],
        };
        let result =
            build_pointer_for_placed(&db, &master_key, 1, &block_id, &[], Timestamp(5), catalog)
                .unwrap();
        assert!(
            result.is_none(),
            "no pointer while the base has no Alive holder"
        );
    }

    /// AC-24′ (mailbox-i41): the refresh interval scales like the TTL; the pointer
    /// outlives ≥ 60 refreshes at any time_scale.
    #[test]
    fn pointer_refresh_interval_scales_with_time_scale() {
        for ts in [1u64, 1000, 100_000] {
            let refresh = pointer_refresh_interval_secs(ts);
            assert_eq!(refresh, MAILBOX_POINTER_REPUBLISH_SECS / ts);
            let ttl = viaticum_core::mailbox::scaled_ttl_secs(
                class_config::SELF_POINTER_TTL.as_secs(),
                ts,
            );
            // Integer division rounds both.
            assert!(ttl >= 60 * refresh && ttl / refresh <= 64, "ts={ts}");
        }
    }
}

// ─── CRIT-1 ATDD: AEAD key must not be the Ed25519 signing scalar ─────────────

// AC-A2: key derived from seed must differ from master signing scalar
#[test]
fn system_state_aead_key_is_different_from_master_signing_scalar() {
    use viaticum_core::cluster::derive_master_key;
    let seed = [0xABu8; 64];
    let aead_key = identity_key_bytes_from_seed(&seed).unwrap();
    let signing_scalar = derive_master_key(&seed).unwrap().to_bytes();
    assert_ne!(
        aead_key, signing_scalar,
        "AEAD key must not equal Ed25519 signing scalar"
    );
}

// AC-A3: encrypt/decrypt roundtrip with new derivation
#[test]
fn system_state_encrypt_decrypt_roundtrip_with_new_derivation() {
    let db = viaticum_core::db::Db::open_in_memory().unwrap();
    let seed = [0x11u8; 64];
    let blob = snapshot_and_encrypt(&db, &seed).unwrap();
    let db2 = viaticum_core::db::Db::open_in_memory().unwrap();
    let state = decrypt_and_restore(&db2, &blob, &seed).unwrap();
    assert_eq!(state.version, SYSTEM_STATE_VERSION);
}

// AC-A4: wrong seed must fail decryption
#[test]
fn system_state_wrong_seed_fails_decrypt_after_fix() {
    let db = viaticum_core::db::Db::open_in_memory().unwrap();
    let seed = [0x11u8; 64];
    let blob = snapshot_and_encrypt(&db, &seed).unwrap();
    let db2 = viaticum_core::db::Db::open_in_memory().unwrap();
    assert!(
        decrypt_and_restore(&db2, &blob, &[0x22u8; 64]).is_err(),
        "wrong seed must fail decryption"
    );
}

// ─── snapshot_and_encrypt ────────────────────────────────────────────────────

#[test]
fn snapshot_and_encrypt_produces_nonempty_blob() {
    let db = viaticum_core::db::Db::open_in_memory().unwrap();
    let seed = [42u8; 64];
    let blob = snapshot_and_encrypt(&db, &seed).unwrap();
    assert!(!blob.is_empty());
    // salt(24) + nonce(12) + tag(16) = 52 bytes minimum
    assert!(blob.len() > 52, "blob too small: {} bytes", blob.len());
}

// ─── roundtrip ───────────────────────────────────────────────────────────────

#[test]
fn snapshot_encrypt_decrypt_roundtrip() {
    let db = viaticum_core::db::Db::open_in_memory().unwrap();
    let seed = [42u8; 64];
    let blob = snapshot_and_encrypt(&db, &seed).unwrap();

    let db2 = viaticum_core::db::Db::open_in_memory().unwrap();
    let state = decrypt_and_restore(&db2, &blob, &seed).unwrap();
    assert_eq!(state.version, SYSTEM_STATE_VERSION);
}

// ─── wrong seed ──────────────────────────────────────────────────────────────

#[test]
fn wrong_seed_fails_decrypt() {
    let db = viaticum_core::db::Db::open_in_memory().unwrap();
    let seed = [42u8; 64];
    let blob = snapshot_and_encrypt(&db, &seed).unwrap();

    let db2 = viaticum_core::db::Db::open_in_memory().unwrap();
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
    let db = viaticum_core::db::Db::open_in_memory().unwrap();
    let seed = [1u8; 64];
    // A blob shorter than 52 bytes cannot contain salt+nonce+tag.
    let short_blob = vec![0u8; 10];
    assert!(decrypt_and_restore(&db, &short_blob, &seed).is_err());
}
