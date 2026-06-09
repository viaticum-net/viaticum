// Tests for DR module.
//
// Unit tests: select_freshest_valid_pointer logic + wait_for_kad_bootstrap_stable
// seam tests (multi-swarm auth counting + DB upsert, timeout/best-effort).
//
// Full happy-path run_dr is NOT cargo-testable (no in-process multi-node DR
// harness) — covered by local_dr_test.sh E2E test instead.

use std::time::Duration;

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

// ─── wait_for_kad_bootstrap_stable tests ─────────────────────────────────────

/// Verify that wait_for_kad_bootstrap_stable correctly counts PeerAuthenticated
/// events and upserts each authenticated peer into the DB.
///
/// Scenario: spin 3 swarms (A, B, C). A dials B and C and waits for both to
/// authenticate. We simulate the DB-upserting behavior of wait_for_kad_bootstrap_stable
/// by calling it with A's event_rx and checking that:
///   - the returned count == 2 (both B and C authenticated)
///   - both peers appear in the DB after the call
#[tokio::test]
async fn wait_for_kad_bootstrap_stable_counts_authenticated_peers_and_upserts_db() {
    use crate::daemon::network::swarm::SwarmHandle;
    use crate::daemon::network::swarm_test_helpers::{get_listen_addr, make_swarm_config};

    // Build 3 swarms (A, B, C) in the same test cluster.
    let cfg_a = make_swarm_config(0x01);
    let cfg_b = make_swarm_config(0x02);
    let cfg_c = make_swarm_config(0x03);

    let device_id_b =
        viaticum_core::types::DeviceId(cfg_b.device_signing_key.verifying_key().to_bytes());
    let device_id_c =
        viaticum_core::types::DeviceId(cfg_c.device_signing_key.verifying_key().to_bytes());

    let (handle_a, mut event_rx_a) = SwarmHandle::start(cfg_a).await.unwrap();
    let (handle_b, _event_rx_b) = SwarmHandle::start(cfg_b).await.unwrap();
    let (handle_c, _event_rx_c) = SwarmHandle::start(cfg_c).await.unwrap();

    // Get B and C's listen addresses and peer_ids.
    let addr_b = get_listen_addr(&handle_b).await;
    let addr_c = get_listen_addr(&handle_c).await;
    let pid_b = handle_b.peer_id;
    let pid_c = handle_c.peer_id;

    // Dial B and C from A.
    handle_a.dial(pid_b, addr_b).await.unwrap();
    handle_a.dial(pid_c, addr_c).await.unwrap();

    // Run wait_for_kad_bootstrap_stable: should count 2 authenticated peers.
    let db = viaticum_core::db::Db::open_in_memory().unwrap();
    let count = super::wait_for_kad_bootstrap_stable(
        &handle_a,
        &mut event_rx_a,
        &db,
        10, // 10 second timeout — plenty for loopback
        2,  // stop at 2 authenticated peers
    )
    .await;

    assert_eq!(
        count, 2,
        "should have authenticated exactly 2 peers (B and C)"
    );

    // Both peers should now be in the DB.
    let peer_b = db.get_peer(&device_id_b).unwrap();
    let peer_c = db.get_peer(&device_id_c).unwrap();
    assert!(
        peer_b.is_some(),
        "peer B must be upserted into DB after authentication"
    );
    assert!(
        peer_c.is_some(),
        "peer C must be upserted into DB after authentication"
    );
}

/// Verify that wait_for_kad_bootstrap_stable returns 0 quickly when there are
/// no peers (isolated node) — must NOT hang past the timeout.
///
/// Scenario: single swarm, no other peers. Call with timeout=3s, min_peers=1.
/// Expect: returns 0 within ~3s (best-effort), no hang.
#[tokio::test]
async fn wait_for_kad_bootstrap_stable_returns_zero_on_timeout_no_hang() {
    use crate::daemon::network::swarm::SwarmHandle;
    use crate::daemon::network::swarm_test_helpers::make_swarm_config;

    let cfg = make_swarm_config(0x10);
    let (handle, mut event_rx) = SwarmHandle::start(cfg).await.unwrap();
    let db = viaticum_core::db::Db::open_in_memory().unwrap();

    let start = std::time::Instant::now();
    // Use a short 3-second timeout.
    let count = super::wait_for_kad_bootstrap_stable(
        &handle,
        &mut event_rx,
        &db,
        3, // 3 second timeout
        1, // min_peers = 1 — will never be reached since no one connects
    )
    .await;

    let elapsed = start.elapsed();
    assert_eq!(count, 0, "isolated node should authenticate 0 peers");
    assert!(
        elapsed < Duration::from_secs(5),
        "wait_for_kad_bootstrap_stable should not hang beyond timeout (elapsed={elapsed:?})"
    );
}
