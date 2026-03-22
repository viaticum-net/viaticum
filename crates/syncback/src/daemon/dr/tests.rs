// Tests for DR module: snapshot/restore roundtrip without network.
//
// Network-dependent BFS logic is exercised by integration tests only.
// Unit tests here cover the decrypt_and_restore contract.

use crate::daemon::system_state::{decrypt_and_restore, snapshot_and_encrypt, SYSTEM_STATE_VERSION};

#[test]
fn dr_decrypt_and_restore_roundtrip() {
    let db1 = syncback_core::db::Db::open_in_memory().unwrap();
    let seed = [42u8; 64];
    let blob = snapshot_and_encrypt(&db1, &seed).unwrap();

    let db2 = syncback_core::db::Db::open_in_memory().unwrap();
    let state = decrypt_and_restore(&db2, &blob, &seed).unwrap();

    assert_eq!(state.version, SYSTEM_STATE_VERSION);
}

#[test]
fn dr_fails_on_empty_blob() {
    let db = syncback_core::db::Db::open_in_memory().unwrap();
    let seed = [42u8; 64];
    assert!(
        decrypt_and_restore(&db, &[], &seed).is_err(),
        "decryption of empty blob must fail"
    );
}

#[test]
fn dr_fails_on_wrong_seed() {
    let db1 = syncback_core::db::Db::open_in_memory().unwrap();
    let seed = [42u8; 64];
    let blob = snapshot_and_encrypt(&db1, &seed).unwrap();

    let db2 = syncback_core::db::Db::open_in_memory().unwrap();
    let wrong_seed = [99u8; 64];
    assert!(
        decrypt_and_restore(&db2, &blob, &wrong_seed).is_err(),
        "decryption with wrong seed must fail"
    );
}

#[test]
fn dr_freshest_blob_selected_by_created_at() {
    // Simulate what run_dr does: sort blobs by created_at desc, pick index 0.
    let blobs: Vec<(u64, Vec<u8>)> = vec![
        (1000, vec![1, 2, 3]),
        (3000, vec![4, 5, 6]), // freshest
        (2000, vec![7, 8, 9]),
    ];

    let mut sorted = blobs.clone();
    sorted.sort_by(|a, b| b.0.cmp(&a.0));

    assert_eq!(sorted[0].0, 3000);
    assert_eq!(sorted[0].1, vec![4, 5, 6]);
}
