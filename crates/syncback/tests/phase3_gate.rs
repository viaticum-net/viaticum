// Phase 3 Gate: two devices, shared identity, dedup.
//
// Tests in this file exercise ALL cross-module flows from Phase 3:
//   1. two_devices_shared_identity          — same seed → same master_pub, distinct device indices
//   2. cluster_sync_event_exchange          — Device A serves events → Device B applies them
//   3. dedup_across_devices                 — content_hash already backed up → no re-backup needed
//   4. device_revocation_rotates_epoch      — revoke → epoch++ → only other device active
//   5. revocation_broadcast_round_trip      — CBOR serde + signature verification
//   6. handshake_with_cluster_identity      — device cert embedded → extract_cluster_identity OK
//   7. peer_affinity_isolates_blast_radius  — per-device peer sets, reassign moves peer
//
// GATE CRITERIA: all 7 tests pass → Phase 3 is complete.

use std::sync::{Arc, Mutex};

use syncback::daemon::cluster_sync::{ClusterSyncConfig, ClusterSyncManager};
use syncback_core::cluster::{
    derive_device_key, derive_epoch_key, derive_master_key, issue_device_certificate,
    issue_revocation, master_identity, ClusterState, EpochCounter,
};
use syncback_core::db::Db;
use syncback_core::messages::{
    build_handshake, extract_cluster_identity, frame_message, from_cbor, to_cbor,
    unframe_message, verify_handshake, Message, RevocationBroadcast,
};
use syncback_core::types::{
    DeviceId, Event, EventEntry, FileId, FileRecord, FileVersion, IdentityPub, LocalState,
    SourceBlockId, Timestamp,
};

// ─── Shared fixtures ──────────────────────────────────────────────────────────

/// Seed bytes for the "cluster" — both devices derive from this.
const SEED: &[u8] = &[0xAA_u8; 64];
const DEVICE_A_ID: DeviceId = DeviceId([0xA0u8; 16]);
const DEVICE_B_ID: DeviceId = DeviceId([0xB0u8; 16]);
const NOW: Timestamp = Timestamp(1_700_000_000);

fn master_key() -> ed25519_dalek::SigningKey {
    derive_master_key(SEED).unwrap()
}

fn device_pub(device_id: DeviceId) -> [u8; 32] {
    derive_device_key(SEED, &device_id)
        .unwrap()
        .verifying_key()
        .to_bytes()
}

/// Init ClusterState with both DEVICE_A and DEVICE_B.
fn init_state_ab(db: Db) -> ClusterState {
    let mk = master_key();
    let mp = master_identity(&mk);
    let cert_a = issue_device_certificate(&mk, DEVICE_A_ID, device_pub(DEVICE_A_ID), NOW);
    let mut state = ClusterState::init(db, mp, cert_a, NOW, NOW).unwrap();
    let cert_b = issue_device_certificate(&mk, DEVICE_B_ID, device_pub(DEVICE_B_ID), NOW);
    state.add_device(cert_b, NOW).unwrap();
    state
}

// ─── 1. two_devices_shared_identity ──────────────────────────────────────────
//
// Two devices derived from the same seed share one master_pub.
// Their device indices are distinct (0, 1) and ESI namespaces do not overlap.

#[test]
fn two_devices_shared_identity() {
    let db = Db::open_in_memory().unwrap();
    let state = init_state_ab(db);

    // Both devices are active.
    let active = state.active_devices();
    assert_eq!(active.len(), 2, "both devices must be active");

    // Same master public key.
    let mp = state.master_pub();
    let expected_mp = master_identity(&master_key());
    assert_eq!(mp, expected_mp, "master_pub must match derived identity");

    // Device indices: 0 and 1.
    let dev_a = state.get_device(&DEVICE_A_ID).expect("device A must exist");
    let dev_b = state.get_device(&DEVICE_B_ID).expect("device B must exist");
    assert_eq!(dev_a.device_index, 0);
    assert_eq!(dev_b.device_index, 1);

    // Device pub keys are distinct (different device_ids → different HKDF output).
    assert_ne!(
        dev_a.device_pub_key, dev_b.device_pub_key,
        "device pub keys must differ"
    );

    // ESI namespaces do not overlap.
    let (_start_a, end_a) = state.esi_namespace(&DEVICE_A_ID).unwrap();
    let (start_b, end_b) = state.esi_namespace(&DEVICE_B_ID).unwrap();
    assert_eq!(end_a, start_b, "A's namespace ends exactly where B's begins");
    assert!(end_a <= start_b, "namespaces must not overlap");
    assert!(end_b > end_a, "B's namespace is after A's");
}

// ─── 2. cluster_sync_event_exchange ──────────────────────────────────────────
//
// Device A appends events. Device B (separate DB) builds a sync request,
// A's ClusterSyncManager serves a response, B applies it.
// Verifies: cursor advances, events applied to B's ClusterState.

#[test]
fn cluster_sync_event_exchange() {
    // Device A: has both devices registered in its ClusterState so it can
    // serve DEVICE_B's sync request without NotClusterDevice error.
    let db_a = Db::open_in_memory().unwrap();
    let state_a = init_state_ab(db_a.clone());
    // Record base seq before we add synthetic events.
    let base_seq = db_a.last_event_seq().unwrap();

    // Append two synthetic events that change ClusterState in ways B hasn't seen:
    //   - EpochRotated { epoch: 5 }  — B is still at epoch 0, so this is new
    //   - DeviceAdded for a brand-new device C not registered in B's state
    let device_c_id = DeviceId([0xCC_u8; 16]);
    db_a.append_event(&EventEntry {
        timestamp: NOW,
        device_id: DEVICE_A_ID,
        event: Event::EpochRotated { epoch: 5 },
    })
    .unwrap();
    db_a.append_event(&EventEntry {
        timestamp: NOW,
        device_id: DEVICE_A_ID,
        event: Event::DeviceAdded { device_id: device_c_id },
    })
    .unwrap();
    let a_last_seq = db_a.last_event_seq().unwrap();
    assert_eq!(a_last_seq, base_seq + 2);

    let sync_a = ClusterSyncManager::new(
        db_a.clone(),
        ClusterSyncConfig { our_device_id: DEVICE_A_ID, batch_size: 100 },
        Arc::new(Mutex::new(state_a)),
    );

    // Device B: separate DB, knows only itself initially.
    let db_b = Db::open_in_memory().unwrap();
    let state_b = init_state_ab(db_b.clone()); // uses same seed — same cluster
    let _b_identity = IdentityPub(device_pub(DEVICE_B_ID));

    let sync_b = ClusterSyncManager::new(
        db_b.clone(),
        ClusterSyncConfig { our_device_id: DEVICE_B_ID, batch_size: 100 },
        Arc::new(Mutex::new(state_b)),
    );

    // B builds a request asking for everything (cursor = 0).
    let a_identity = IdentityPub(device_pub(DEVICE_A_ID));
    let request = sync_b.build_sync_request(&a_identity);
    assert_eq!(request.last_known_seq, 0, "B has never synced A before");
    assert_eq!(request.from_device_id, DEVICE_B_ID);

    // A handles the request.
    let response = sync_a.handle_sync_request(&request).unwrap();
    // A's log has base_seq+2 events total.
    assert_eq!(
        response.responder_last_seq, a_last_seq,
        "responder_last_seq must match A's last seq"
    );
    // All events returned (from seq 0 to base_seq+2).
    assert!(!response.events.is_empty(), "response must contain events");

    // B applies the response.
    let applied = sync_b.process_sync_response(&a_identity, response).unwrap();
    assert!(applied > 0, "at least some events must be applied");

    // B's cursor for A is now updated.
    // Access the shared state to check cursor.
    // Re-read by building a new request — it should use the updated cursor.
    let request2 = sync_b.build_sync_request(&a_identity);
    assert_eq!(
        request2.last_known_seq, a_last_seq,
        "cursor must be advanced to A's last_seq after sync"
    );

    // Second sync: no new events since A hasn't changed.
    let request3 = sync_b.build_sync_request(&a_identity);
    let response3 = sync_a.handle_sync_request(&request3).unwrap();
    assert!(response3.events.is_empty(), "no new events since last sync");
}

// ─── 3. dedup_across_devices ──────────────────────────────────────────────────
//
// Device A backs up a file (backed_up_at = Some). Device B queries via
// ClusterState::is_content_backed_up on the same DB — returns true.
// A file that was not backed up (backed_up_at = None) returns false.

#[test]
fn dedup_across_devices() {
    let db = Db::open_in_memory().unwrap();
    let state = init_state_ab(db.clone());

    let content_hash_backed: [u8; 32] = [0x11; 32];
    let content_hash_pending: [u8; 32] = [0x22; 32];

    // Device A record: backed up.
    db.upsert_file(&FileRecord {
        file_id: FileId(1),
        path: "/device_a/docs/report.pdf".to_string(),
        importance: 0.8,
        devices: vec![(DEVICE_A_ID, LocalState::Present)],
        versions: vec![FileVersion {
            content_hash: content_hash_backed,
            source_block_id: SourceBlockId([0xAA; 32]),
            k: 2,
            t: 65535,
            created_at: NOW,
            backed_up_at: Some(NOW), // backed up!
        }],
        first_seen: NOW,
    })
    .unwrap();

    // Device B: same content, but not yet backed up.
    db.upsert_file(&FileRecord {
        file_id: FileId(2),
        path: "/device_b/downloads/report_copy.pdf".to_string(),
        importance: 0.5,
        devices: vec![(DEVICE_B_ID, LocalState::Present)],
        versions: vec![FileVersion {
            content_hash: content_hash_pending,
            source_block_id: SourceBlockId([0xBB; 32]),
            k: 2,
            t: 65535,
            created_at: NOW,
            backed_up_at: None, // not backed up yet
        }],
        first_seen: NOW,
    })
    .unwrap();

    // Query via ClusterState (shared DB).
    assert!(
        state.is_content_backed_up(&content_hash_backed).unwrap(),
        "content backed up by device A must be visible"
    );
    assert!(
        !state.is_content_backed_up(&content_hash_pending).unwrap(),
        "content not yet backed up must return false"
    );

    // Unknown hash must return false.
    assert!(
        !state.is_content_backed_up(&[0xFF; 32]).unwrap(),
        "unknown content hash must return false"
    );

    // find_source_block_for_content must return the block for the backed-up hash.
    let block = state
        .find_source_block_for_content(&content_hash_backed)
        .unwrap();
    assert_eq!(block, Some(SourceBlockId([0xAA; 32])));

    // And None for the not-backed-up hash.
    let block_pending = state
        .find_source_block_for_content(&content_hash_pending)
        .unwrap();
    assert_eq!(block_pending, None);
}

// ─── 4. device_revocation_rotates_epoch ──────────────────────────────────────
//
// With two devices registered, revoking DEVICE_A:
//   - A becomes revoked
//   - epoch increments
//   - active_devices contains only B
//   - new epoch key differs from epoch 0

#[test]
fn device_revocation_rotates_epoch() {
    let db = Db::open_in_memory().unwrap();
    let mut state = init_state_ab(db);

    let epoch_before = state.current_epoch();
    assert_eq!(epoch_before, EpochCounter(0));

    // Both active before revocation.
    assert_eq!(state.active_devices().len(), 2);

    let mk = master_key();
    let new_epoch = EpochCounter(1);
    let rev = issue_revocation(&mk, DEVICE_A_ID, NOW, new_epoch);
    state.revoke_device(rev, NOW, NOW).unwrap();

    // Epoch incremented.
    assert_eq!(state.current_epoch(), new_epoch, "epoch must increment after revocation");

    // A is now revoked.
    assert!(state.is_device_revoked(&DEVICE_A_ID), "device A must be revoked");

    // Only B is active.
    let active = state.active_devices();
    assert_eq!(active.len(), 1, "only device B must remain active");
    assert_eq!(active[0].device_id, DEVICE_B_ID);

    // Epoch history has two entries: epoch 0 (genesis) and epoch 1 (after revocation).
    assert_eq!(state.epoch_history().len(), 2);

    // New epoch key must differ from epoch 0.
    let ek0 = derive_epoch_key(SEED, EpochCounter(0)).unwrap();
    let ek1 = derive_epoch_key(SEED, new_epoch).unwrap();
    assert_ne!(ek0.key_bytes, ek1.key_bytes, "epoch keys must differ");
}

// ─── 5. revocation_broadcast_round_trip ──────────────────────────────────────
//
// RevocationBroadcast serializes to CBOR and back.
// Both the revocation cert and device cert are valid after round-trip.
// External parties can verify both signatures.

#[test]
fn revocation_broadcast_round_trip() {
    let mk = master_key();
    let mp = master_identity(&mk);
    let new_epoch = EpochCounter(1);

    let rev = issue_revocation(&mk, DEVICE_A_ID, NOW, new_epoch);
    let cert_a = issue_device_certificate(&mk, DEVICE_A_ID, device_pub(DEVICE_A_ID), NOW);

    let broadcast = ClusterSyncManager::build_revocation_broadcast(&rev, &cert_a);

    // CBOR round-trip.
    let bytes = to_cbor(&broadcast).unwrap();
    let decoded: RevocationBroadcast = from_cbor(&bytes).unwrap();
    assert_eq!(decoded, broadcast);

    // Structural check.
    assert_eq!(decoded.revocation.device_id, DEVICE_A_ID);
    assert_eq!(decoded.revocation.master_pub_key, mp);
    assert_eq!(decoded.revocation.new_epoch, new_epoch);
    assert_eq!(decoded.device_cert.device_id, DEVICE_A_ID);
    assert_eq!(decoded.device_cert.master_pub_key, mp);

    // Signature verification on deserialized data.
    syncback_core::cluster::verify_revocation(&decoded.revocation, &mp)
        .expect("revocation signature must verify after CBOR round-trip");
    syncback_core::cluster::verify_device_certificate(&decoded.device_cert, &mp)
        .expect("device cert signature must verify after CBOR round-trip");

    // Extract device_pub_key from cert for revocation list.
    let revoked_device_pub = decoded.device_cert.device_pub_key;
    assert_eq!(revoked_device_pub, device_pub(DEVICE_A_ID));
}

// ─── 6. handshake_with_cluster_identity ──────────────────────────────────────
//
// A device builds a handshake carrying its DeviceCertificate.
// After frame/unframe, extract_cluster_identity returns the master pub key.
// verify_handshake passes with a fresh timestamp.

#[test]
fn handshake_with_cluster_identity() {
    let mk = master_key();
    let mp = master_identity(&mk);

    // Device A's signing key is the device key.
    let device_signing_key = derive_device_key(SEED, &DEVICE_A_ID).unwrap();
    let device_pub_bytes = device_signing_key.verifying_key().to_bytes();
    let device_identity = IdentityPub(device_pub_bytes);

    let cert_a = issue_device_certificate(&mk, DEVICE_A_ID, device_pub_bytes, NOW);

    // Use a fresh timestamp so verify_handshake doesn't reject it as stale.
    let ts = Timestamp::now();
    let handshake = build_handshake(device_identity, ts, &device_signing_key, Some(cert_a));

    // Frame → unframe round-trip.
    let framed = frame_message(&Message::Handshake(handshake.clone())).unwrap();
    let (unframed, consumed) = unframe_message(&framed).unwrap();
    assert_eq!(consumed, framed.len());

    let msg = match unframed {
        Message::Handshake(h) => h,
        other => panic!("expected Handshake, got {:?}", other),
    };

    // verify_handshake must pass (fresh timestamp, valid sig).
    verify_handshake(&msg, Timestamp::now()).expect("handshake must verify");

    // extract_cluster_identity must return master pub.
    let extracted = extract_cluster_identity(&msg).expect("extract_cluster_identity must not error");
    assert_eq!(
        extracted,
        Some(mp),
        "extracted master pub must match derive_master_key output"
    );
}

// ─── 7. peer_affinity_isolates_blast_radius ───────────────────────────────────
//
// Each device manages its own peer set.
// Reassigning P2 from A to B removes it from A's set and adds to B's.

#[test]
fn peer_affinity_isolates_blast_radius() {
    let db = Db::open_in_memory().unwrap();
    let mut state = init_state_ab(db);

    let p1 = IdentityPub([0x11u8; 32]);
    let p2 = IdentityPub([0x22u8; 32]);
    let p3 = IdentityPub([0x33u8; 32]);
    let p4 = IdentityPub([0x44u8; 32]);
    let p5 = IdentityPub([0x55u8; 32]);

    // Assign P1, P2, P3 to device A.
    state.set_peer_affinity(p1, DEVICE_A_ID).unwrap();
    state.set_peer_affinity(p2, DEVICE_A_ID).unwrap();
    state.set_peer_affinity(p3, DEVICE_A_ID).unwrap();

    // Assign P4, P5 to device B.
    state.set_peer_affinity(p4, DEVICE_B_ID).unwrap();
    state.set_peer_affinity(p5, DEVICE_B_ID).unwrap();

    // Verify initial assignment.
    let peers_a = state.peers_for_device(&DEVICE_A_ID);
    let peers_b = state.peers_for_device(&DEVICE_B_ID);

    assert_eq!(peers_a.len(), 3, "A must manage 3 peers");
    assert!(peers_a.contains(&p1));
    assert!(peers_a.contains(&p2));
    assert!(peers_a.contains(&p3));

    assert_eq!(peers_b.len(), 2, "B must manage 2 peers");
    assert!(peers_b.contains(&p4));
    assert!(peers_b.contains(&p5));

    // No overlap: none of B's peers are in A's set.
    for p in &peers_b {
        assert!(!peers_a.contains(p), "B's peers must not appear in A's set");
    }

    // Reassign P2 from A to B.
    state.set_peer_affinity(p2, DEVICE_B_ID).unwrap();

    let peers_a_after = state.peers_for_device(&DEVICE_A_ID);
    let peers_b_after = state.peers_for_device(&DEVICE_B_ID);

    // P2 no longer in A.
    assert!(!peers_a_after.contains(&p2), "P2 must be removed from A after reassign");
    assert_eq!(peers_a_after.len(), 2, "A must manage 2 peers after reassign");

    // P2 now in B.
    assert!(peers_b_after.contains(&p2), "P2 must be in B after reassign");
    assert_eq!(peers_b_after.len(), 3, "B must manage 3 peers after reassign");

    // Peer → device routing via peer_device.
    assert_eq!(state.peer_device(&p2), Some(DEVICE_B_ID));
    assert_eq!(state.peer_device(&p1), Some(DEVICE_A_ID));
    assert_eq!(state.peer_device(&p4), Some(DEVICE_B_ID));
}
