// Tests for DR module: snapshot/restore roundtrip without network.
//
// Network-dependent BFS logic is exercised by integration tests only.
// Unit tests here cover the decrypt_and_restore contract.

use crate::daemon::system_state::{
    SYSTEM_STATE_VERSION, decrypt_and_restore, snapshot_and_encrypt,
};
use viaticum_core::cluster::{derive_master_key, master_identity};
use viaticum_core::system_state::{BlockRef, sign_self_pointer};
use viaticum_core::types::{SourceBlockId, Timestamp, to_cbor_bytes};

use super::select_freshest_valid_pointer;

fn pointer_blob(master: &ed25519_dalek::SigningKey, generation: u32, created_at: u64) -> Vec<u8> {
    let base = BlockRef {
        block_id: SourceBlockId([generation as u8; 32]),
        holders: vec![],
        encrypted_size: 128,
    };
    let p = sign_self_pointer(master, generation, base, vec![], Timestamp(created_at));
    to_cbor_bytes(&p)
}

#[test]
fn dr_decrypt_and_restore_roundtrip() {
    let db1 = viaticum_core::db::Db::open_in_memory().unwrap();
    let seed = [42u8; 64];
    let blob = snapshot_and_encrypt(&db1, &seed).unwrap();

    let db2 = viaticum_core::db::Db::open_in_memory().unwrap();
    let state = decrypt_and_restore(&db2, &blob, &seed).unwrap();

    assert_eq!(state.version, SYSTEM_STATE_VERSION);
}

#[test]
fn dr_fails_on_empty_blob() {
    let db = viaticum_core::db::Db::open_in_memory().unwrap();
    let seed = [42u8; 64];
    assert!(
        decrypt_and_restore(&db, &[], &seed).is_err(),
        "decryption of empty blob must fail"
    );
}

#[test]
fn dr_fails_on_wrong_seed() {
    let db1 = viaticum_core::db::Db::open_in_memory().unwrap();
    let seed = [42u8; 64];
    let blob = snapshot_and_encrypt(&db1, &seed).unwrap();

    let db2 = viaticum_core::db::Db::open_in_memory().unwrap();
    let wrong_seed = [99u8; 64];
    assert!(
        decrypt_and_restore(&db2, &blob, &wrong_seed).is_err(),
        "decryption with wrong seed must fail"
    );
}

#[test]
fn select_pointer_picks_freshest_created_at() {
    let master = derive_master_key(&[5u8; 32]).unwrap();
    let id = master_identity(&master);
    let blobs: Vec<(u64, Vec<u8>)> = vec![
        (1000, pointer_blob(&master, 1, 1000)),
        (3000, pointer_blob(&master, 2, 3000)), // freshest by created_at
        (2000, pointer_blob(&master, 3, 2000)),
    ];
    let picked = select_freshest_valid_pointer(&blobs, &id).expect("a valid pointer exists");
    assert_eq!(picked.created_at, Timestamp(3000));
    assert_eq!(picked.generation, 2);
}

#[test]
fn select_pointer_generation_breaks_created_at_tie() {
    let master = derive_master_key(&[6u8; 32]).unwrap();
    let id = master_identity(&master);
    // Same created_at; higher generation wins the tiebreak.
    let blobs: Vec<(u64, Vec<u8>)> = vec![
        (5000, pointer_blob(&master, 4, 5000)),
        (5000, pointer_blob(&master, 7, 5000)),
    ];
    let picked = select_freshest_valid_pointer(&blobs, &id).expect("a valid pointer exists");
    assert_eq!(picked.generation, 7);
}

#[test]
fn select_pointer_rejects_wrong_signer() {
    let master = derive_master_key(&[7u8; 32]).unwrap();
    let attacker = derive_master_key(&[8u8; 32]).unwrap();
    let id = master_identity(&master);
    // The only blob is a well-formed pointer signed by a DIFFERENT master → rejected.
    let blobs: Vec<(u64, Vec<u8>)> = vec![(9000, pointer_blob(&attacker, 1, 9000))];
    assert!(
        select_freshest_valid_pointer(&blobs, &id).is_none(),
        "a pointer signed by another master must not be selected"
    );
}

#[test]
fn select_pointer_none_when_empty_or_garbage() {
    let master = derive_master_key(&[9u8; 32]).unwrap();
    let id = master_identity(&master);
    assert!(
        select_freshest_valid_pointer(&[], &id).is_none(),
        "empty → None"
    );
    let garbage: Vec<(u64, Vec<u8>)> = vec![(1, vec![1, 2, 3]), (2, vec![0xFF; 20])];
    assert!(
        select_freshest_valid_pointer(&garbage, &id).is_none(),
        "non-pointer blobs → None"
    );
}

#[test]
fn select_pointer_skips_invalid_keeps_valid() {
    let master = derive_master_key(&[10u8; 32]).unwrap();
    let attacker = derive_master_key(&[11u8; 32]).unwrap();
    let id = master_identity(&master);
    // A fresher attacker-signed pointer must NOT shadow the older valid one.
    let blobs: Vec<(u64, Vec<u8>)> = vec![
        (1000, pointer_blob(&master, 1, 1000)),   // valid, older
        (9000, pointer_blob(&attacker, 9, 9000)), // invalid signer, fresher
        (3, vec![0u8; 8]),                        // garbage
    ];
    let picked = select_freshest_valid_pointer(&blobs, &id).expect("the valid pointer survives");
    assert_eq!(picked.created_at, Timestamp(1000));
    assert_eq!(picked.generation, 1);
}
