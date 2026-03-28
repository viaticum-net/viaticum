// Tests for ClusterSyncManager.
//
// All tests are synchronous — no iroh, no async.
// Uses in-memory Db and real ClusterState initialized with test keys.

#[cfg(test)]
mod cluster_sync_tests {
    use std::sync::{Arc, Mutex};

    use syncback_core::cluster::{
        derive_device_key, derive_master_key, issue_device_certificate, issue_revocation,
        master_identity, ClusterState, EpochCounter,
    };
    use syncback_core::db::Db;
    use syncback_core::messages::{from_cbor, to_cbor, ClusterSyncRequestMsg, ClusterSyncResponseMsg, RevocationBroadcast};
    use syncback_core::types::{DeviceId, Event, EventEntry, IdentityPub, Timestamp};

    use crate::daemon::cluster_sync::{ClusterSyncConfig, ClusterSyncError, ClusterSyncManager};

    // ─── Test fixtures ────────────────────────────────────────────────────────

    const SEED: [u8; 32] = [42u8; 32];
    const DEVICE_A_ID: DeviceId = DeviceId([0x0Au8; 16]);
    const DEVICE_B_ID: DeviceId = DeviceId([0x0Bu8; 16]);
    const NOW: Timestamp = Timestamp(100_000);

    fn make_master_key() -> ed25519_dalek::SigningKey {
        derive_master_key(&SEED).unwrap()
    }

    fn device_pub(device_id: DeviceId) -> [u8; 32] {
        derive_device_key(&SEED, &device_id)
            .unwrap()
            .verifying_key()
            .to_bytes()
    }

    /// Initialize a ClusterState with DEVICE_A as the first device.
    fn make_cluster_state(db: Db) -> ClusterState {
        let master_key = make_master_key();
        let master_pub = master_identity(&master_key);
        let cert_a = issue_device_certificate(&master_key, DEVICE_A_ID, device_pub(DEVICE_A_ID), NOW);
        ClusterState::init(db, master_pub, cert_a, NOW, NOW).unwrap()
    }

    /// Initialize a ClusterState with DEVICE_A + DEVICE_B as active devices.
    fn make_cluster_state_two_devices(db: Db) -> ClusterState {
        let master_key = make_master_key();
        let master_pub = master_identity(&master_key);
        let cert_a = issue_device_certificate(&master_key, DEVICE_A_ID, device_pub(DEVICE_A_ID), NOW);
        let mut state = ClusterState::init(db, master_pub, cert_a, NOW, NOW).unwrap();
        let cert_b = issue_device_certificate(&master_key, DEVICE_B_ID, device_pub(DEVICE_B_ID), NOW);
        state.add_device(cert_b, NOW).unwrap();
        state
    }

    fn make_manager_with_state(
        db: Db,
        state: ClusterState,
        our_device_id: DeviceId,
    ) -> ClusterSyncManager {
        let config = ClusterSyncConfig {
            our_device_id,
            batch_size: 100,
        };
        let shared = Arc::new(Mutex::new(state));
        ClusterSyncManager::new(db, config, shared)
    }

    fn device_a_identity() -> IdentityPub {
        IdentityPub(device_pub(DEVICE_A_ID))
    }

    fn device_b_identity() -> IdentityPub {
        IdentityPub(device_pub(DEVICE_B_ID))
    }

    // ─── 1. build_sync_request_uses_cursor ───────────────────────────────────

    #[test]
    fn build_sync_request_uses_cursor() {
        let db = Db::open_in_memory().unwrap();
        let state = make_cluster_state(db.clone());
        let peer_identity = device_b_identity();

        // Set a cursor manually via update_sync_cursor.
        let shared = Arc::new(Mutex::new(state));
        {
            let mut s = shared.lock().unwrap();
            s.update_sync_cursor(peer_identity, 42).unwrap();
        }

        let manager = ClusterSyncManager::new(
            db,
            ClusterSyncConfig { our_device_id: DEVICE_A_ID, batch_size: 100 },
            shared,
        );

        let msg = manager.build_sync_request(&peer_identity);
        assert_eq!(msg.last_known_seq, 42);
        assert_eq!(msg.from_device_id, DEVICE_A_ID);
        assert_eq!(msg.v, 1);
    }

    // ─── 2. build_sync_request_defaults_to_zero ──────────────────────────────

    #[test]
    fn build_sync_request_defaults_to_zero() {
        let db = Db::open_in_memory().unwrap();
        let state = make_cluster_state(db.clone());
        let peer_identity = device_b_identity();
        let manager = make_manager_with_state(db, state, DEVICE_A_ID);

        let msg = manager.build_sync_request(&peer_identity);
        assert_eq!(msg.last_known_seq, 0);
        assert_eq!(msg.from_device_id, DEVICE_A_ID);
    }

    // ─── 3. process_sync_response_applies_events ─────────────────────────────

    #[test]
    fn process_sync_response_applies_events() {
        let db = Db::open_in_memory().unwrap();
        let state = make_cluster_state_two_devices(db.clone());
        let shared = Arc::new(Mutex::new(state));
        let manager = ClusterSyncManager::new(
            db.clone(),
            ClusterSyncConfig { our_device_id: DEVICE_A_ID, batch_size: 100 },
            shared.clone(),
        );

        // DEVICE_B is active. Send a DeviceRevoked event via process_sync_response.
        let events = vec![(
            1u64,
            EventEntry {
                timestamp: NOW,
                device_id: DEVICE_A_ID,
                event: Event::DeviceRevoked { device_id: DEVICE_B_ID },
            },
        )];
        let response = ClusterSyncResponseMsg {
            v: 1,
            events,
            responder_last_seq: 1,
            timestamp: NOW,
        };
        let peer_identity = device_b_identity();
        let applied = manager.process_sync_response(&peer_identity, response).unwrap();
        assert_eq!(applied, 1);

        // ClusterState should reflect the revocation.
        let state = shared.lock().unwrap();
        assert!(state.is_device_revoked(&DEVICE_B_ID));
    }

    // ─── 4. process_sync_response_updates_cursor ─────────────────────────────

    #[test]
    fn process_sync_response_updates_cursor() {
        let db = Db::open_in_memory().unwrap();
        let state = make_cluster_state(db.clone());
        let shared = Arc::new(Mutex::new(state));
        let manager = ClusterSyncManager::new(
            db.clone(),
            ClusterSyncConfig { our_device_id: DEVICE_A_ID, batch_size: 100 },
            shared.clone(),
        );

        let peer_identity = device_b_identity();
        // Cursor advances by event count (not responder_last_seq) to prevent
        // a malicious peer from skipping events by sending an inflated seq.
        let events: Vec<(u64, EventEntry)> = (0..3)
            .map(|i| (i as u64 + 1, EventEntry {
                event: Event::DeviceAdded {
                    device_id: DeviceId([i as u8 + 10; 16]),
                },
                timestamp: NOW,
                device_id: DEVICE_B_ID,
            }))
            .collect();
        let response = ClusterSyncResponseMsg {
            v: 1,
            events,
            responder_last_seq: 100, // intentionally inflated — should be ignored
            timestamp: NOW,
        };
        manager.process_sync_response(&peer_identity, response).unwrap();

        // Cursor = initial(0) + events.len(3), NOT responder_last_seq(100).
        let cursor = shared.lock().unwrap().sync_cursor(&peer_identity);
        assert_eq!(cursor, 3);
    }

    // ─── 5. process_sync_response_idempotent ─────────────────────────────────

    #[test]
    fn process_sync_response_idempotent() {
        let db = Db::open_in_memory().unwrap();
        let state = make_cluster_state_two_devices(db.clone());
        let shared = Arc::new(Mutex::new(state));
        let manager = ClusterSyncManager::new(
            db.clone(),
            ClusterSyncConfig { our_device_id: DEVICE_A_ID, batch_size: 100 },
            shared.clone(),
        );

        let peer_identity = device_b_identity();
        let events = vec![(
            1u64,
            EventEntry {
                timestamp: NOW,
                device_id: DEVICE_A_ID,
                event: Event::DeviceRevoked { device_id: DEVICE_B_ID },
            },
        )];

        // Apply the same events twice.
        let response1 = ClusterSyncResponseMsg {
            v: 1,
            events: events.clone(),
            responder_last_seq: 1,
            timestamp: NOW,
        };
        let response2 = ClusterSyncResponseMsg {
            v: 1,
            events,
            responder_last_seq: 1,
            timestamp: NOW,
        };
        let applied1 = manager.process_sync_response(&peer_identity, response1).unwrap();
        let applied2 = manager.process_sync_response(&peer_identity, response2).unwrap();

        // Second apply should not double-add.
        assert_eq!(applied1, 1);
        assert_eq!(applied2, 0);

        let state = shared.lock().unwrap();
        assert!(state.is_device_revoked(&DEVICE_B_ID));
    }

    // ─── 6. handle_sync_request_returns_events_after_seq ─────────────────────

    #[test]
    fn handle_sync_request_returns_events_after_seq() {
        let db = Db::open_in_memory().unwrap();
        let state = make_cluster_state_two_devices(db.clone());

        // Append 3 more events (DB already has DeviceAdded x2 from init+add_device).
        // We'll add 3 synthetic events and ask for events after seq=2.
        // First, figure out the current last seq.
        let base_seq = db.last_event_seq().unwrap();

        for i in 0..3u64 {
            db.append_event(&EventEntry {
                timestamp: Timestamp(NOW.0 + i),
                device_id: DEVICE_A_ID,
                event: Event::EpochRotated { epoch: (i + 1) as u32 },
            }).unwrap();
        }
        let last_seq = db.last_event_seq().unwrap();
        assert_eq!(last_seq, base_seq + 3);

        let manager = make_manager_with_state(db.clone(), state, DEVICE_A_ID);

        // Request events after base_seq (i.e., the 3 synthetic ones).
        let request = ClusterSyncRequestMsg {
            v: 1,
            from_device_id: DEVICE_B_ID,
            last_known_seq: base_seq,
            timestamp: NOW,
        };
        let response = manager.handle_sync_request(&request).unwrap();

        assert_eq!(response.events.len(), 3);
        assert_eq!(response.responder_last_seq, last_seq);
        // Sequences should be base_seq+1, base_seq+2, base_seq+3.
        for (idx, (seq, _)) in response.events.iter().enumerate() {
            assert_eq!(*seq, base_seq + 1 + idx as u64);
        }
    }

    // ─── 7. handle_sync_request_returns_empty_when_caught_up ─────────────────

    #[test]
    fn handle_sync_request_returns_empty_when_caught_up() {
        let db = Db::open_in_memory().unwrap();
        let state = make_cluster_state_two_devices(db.clone());
        let last_seq = db.last_event_seq().unwrap();
        let manager = make_manager_with_state(db, state, DEVICE_A_ID);

        // Request events after last_seq — nothing to return.
        let request = ClusterSyncRequestMsg {
            v: 1,
            from_device_id: DEVICE_B_ID,
            last_known_seq: last_seq,
            timestamp: NOW,
        };
        let response = manager.handle_sync_request(&request).unwrap();
        assert!(response.events.is_empty());
        assert_eq!(response.responder_last_seq, last_seq);
    }

    // ─── 8. handle_sync_request_rejects_revoked_device ───────────────────────

    #[test]
    fn handle_sync_request_rejects_revoked_device() {
        let db = Db::open_in_memory().unwrap();
        let mut state = make_cluster_state_two_devices(db.clone());

        // Revoke DEVICE_B.
        let master_key = make_master_key();
        let rev = issue_revocation(&master_key, DEVICE_B_ID, NOW, EpochCounter(1));
        state.revoke_device(rev, NOW, NOW).unwrap();

        let manager = make_manager_with_state(db, state, DEVICE_A_ID);

        let request = ClusterSyncRequestMsg {
            v: 1,
            from_device_id: DEVICE_B_ID,
            last_known_seq: 0,
            timestamp: NOW,
        };
        let result = manager.handle_sync_request(&request);
        assert!(
            matches!(result, Err(ClusterSyncError::NotClusterDevice(id)) if id == DEVICE_B_ID),
            "expected NotClusterDevice for revoked device, got {:?}",
            result
        );
    }

    // ─── 9. handle_sync_request_rejects_unknown_device ───────────────────────

    #[test]
    fn handle_sync_request_rejects_unknown_device() {
        let db = Db::open_in_memory().unwrap();
        let state = make_cluster_state(db.clone()); // Only DEVICE_A registered.
        let manager = make_manager_with_state(db, state, DEVICE_A_ID);

        let unknown_device_id = DeviceId([0xFFu8; 16]);
        let request = ClusterSyncRequestMsg {
            v: 1,
            from_device_id: unknown_device_id,
            last_known_seq: 0,
            timestamp: NOW,
        };
        let result = manager.handle_sync_request(&request);
        assert!(
            matches!(result, Err(ClusterSyncError::NotClusterDevice(id)) if id == unknown_device_id),
            "expected NotClusterDevice for unknown device, got {:?}",
            result
        );
    }

    // ─── 10. build_revocation_broadcast_round_trip ───────────────────────────

    #[test]
    fn build_revocation_broadcast_round_trip() {
        let master_key = make_master_key();
        let master_pub = master_identity(&master_key);

        let rev = issue_revocation(&master_key, DEVICE_B_ID, NOW, EpochCounter(1));
        let cert_b = issue_device_certificate(&master_key, DEVICE_B_ID, device_pub(DEVICE_B_ID), NOW);

        let broadcast = ClusterSyncManager::build_revocation_broadcast(&rev, &cert_b);

        // CBOR round-trip.
        let bytes = to_cbor(&broadcast).unwrap();
        let decoded: RevocationBroadcast = from_cbor(&bytes).unwrap();

        assert_eq!(decoded, broadcast);
        assert_eq!(decoded.revocation.device_id, DEVICE_B_ID);
        assert_eq!(decoded.revocation.master_pub_key, master_pub);
        assert_eq!(decoded.device_cert.device_id, DEVICE_B_ID);
    }

    // ─── PROC-16: cluster_sync_request_from_revoked_device_rejected ──────────

    #[test]
    fn cluster_sync_request_from_revoked_device_rejected() {
        // A device that was added to the cluster and then revoked must not be
        // served event log entries via handle_sync_request.
        let db = Db::open_in_memory().unwrap();
        let master_key = make_master_key();

        // Set up cluster with DEVICE_A as the sole active device.
        let master_pub = master_identity(&master_key);
        let cert_a = issue_device_certificate(
            &master_key,
            DEVICE_A_ID,
            device_pub(DEVICE_A_ID),
            NOW,
        );
        let mut state = ClusterState::init(db.clone(), master_pub, cert_a, NOW, NOW).unwrap();

        // Add DEVICE_B, then immediately revoke it.
        let cert_b = issue_device_certificate(
            &master_key,
            DEVICE_B_ID,
            device_pub(DEVICE_B_ID),
            NOW,
        );
        state.add_device(cert_b, NOW).unwrap();

        let rev = issue_revocation(&master_key, DEVICE_B_ID, NOW, EpochCounter(1));
        state.revoke_device(rev, NOW, NOW).unwrap();

        // Confirm revocation took effect.
        assert!(state.is_device_revoked(&DEVICE_B_ID));

        let manager = make_manager_with_state(db, state, DEVICE_A_ID);

        // DEVICE_B sends a ClusterSyncRequest — must be rejected.
        let request = ClusterSyncRequestMsg {
            v: 1,
            from_device_id: DEVICE_B_ID,
            last_known_seq: 0,
            timestamp: NOW,
        };
        let result = manager.handle_sync_request(&request);

        assert!(
            matches!(result, Err(ClusterSyncError::NotClusterDevice(id)) if id == DEVICE_B_ID),
            "revoked device must be rejected with NotClusterDevice, got {:?}",
            result
        );
    }

    // ─── C4: per-device cursor and master_pub helper ──────────────────────────

    /// master_pub() returns the cluster's master identity used to initialise state.
    #[test]
    fn master_pub_returns_cluster_identity() {
        let db = Db::open_in_memory().unwrap();
        let master_key = make_master_key();
        let master_pub = master_identity(&master_key);
        let cert_a = issue_device_certificate(&master_key, DEVICE_A_ID, device_pub(DEVICE_A_ID), NOW);
        let state = ClusterState::init(db.clone(), master_pub, cert_a, NOW, NOW).unwrap();
        let shared = Arc::new(Mutex::new(state));
        let manager = ClusterSyncManager::new(
            db,
            ClusterSyncConfig { our_device_id: DEVICE_A_ID, batch_size: 100 },
            shared,
        );

        assert_eq!(manager.master_pub(), master_pub);
    }

    /// build_sync_request uses per-device IdentityPub(device_pub_key) as cursor key,
    /// not the master identity. Setting the cursor on the device-level key is
    /// reflected in the built request's last_known_seq.
    #[test]
    fn build_sync_request_uses_device_level_cursor_key() {
        let db = Db::open_in_memory().unwrap();
        let state = make_cluster_state_two_devices(db.clone());
        let shared = Arc::new(Mutex::new(state));

        // Cursor set on device-B's device-level IdentityPub.
        let device_b_key = IdentityPub(device_pub(DEVICE_B_ID));
        {
            let mut s = shared.lock().unwrap();
            s.update_sync_cursor(device_b_key, 77).unwrap();
        }

        let manager = ClusterSyncManager::new(
            db,
            ClusterSyncConfig { our_device_id: DEVICE_A_ID, batch_size: 100 },
            shared,
        );

        // Build request using device-level cursor — must see seq=77.
        let msg = manager.build_sync_request(&device_b_key);
        assert_eq!(msg.last_known_seq, 77, "cursor must be per device_pub_key");
        assert_eq!(msg.from_device_id, DEVICE_A_ID);
    }

    /// process_sync_response updates the cursor under the device-level IdentityPub key.
    /// A subsequent build_sync_request with the same device-level key reflects the update.
    #[test]
    fn process_sync_response_updates_device_level_cursor() {
        let db = Db::open_in_memory().unwrap();
        let state = make_cluster_state_two_devices(db.clone());
        let shared = Arc::new(Mutex::new(state));
        let manager = ClusterSyncManager::new(
            db,
            ClusterSyncConfig { our_device_id: DEVICE_A_ID, batch_size: 100 },
            shared.clone(),
        );

        let device_b_key = IdentityPub(device_pub(DEVICE_B_ID));

        // No cursor yet → request should start from 0.
        let req_before = manager.build_sync_request(&device_b_key);
        assert_eq!(req_before.last_known_seq, 0);

        // Apply a response with 5 events (cursor advances by event count).
        let events: Vec<(u64, EventEntry)> = (0..5)
            .map(|i| (i as u64 + 1, EventEntry {
                event: Event::DeviceAdded {
                    device_id: DeviceId([i as u8 + 20; 16]),
                },
                timestamp: NOW,
                device_id: DEVICE_B_ID,
            }))
            .collect();
        let response = ClusterSyncResponseMsg {
            v: 1,
            events,
            responder_last_seq: 15,
            timestamp: NOW,
        };
        manager.process_sync_response(&device_b_key, response).unwrap();

        // After response, cursor advanced by event count (5), not responder_last_seq (15).
        let req_after = manager.build_sync_request(&device_b_key);
        assert_eq!(req_after.last_known_seq, 5, "cursor must advance after process_sync_response");
    }

    // ─── Message serialization round-trips ───────────────────────────────────

    #[test]
    fn sync_request_msg_serialization_round_trip() {
        let msg = ClusterSyncRequestMsg {
            v: 1,
            from_device_id: DeviceId([1u8; 16]),
            last_known_seq: 42,
            timestamp: Timestamp(1000),
        };
        let bytes = to_cbor(&msg).unwrap();
        let decoded: ClusterSyncRequestMsg = from_cbor(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn sync_response_msg_serialization_round_trip() {
        let entry = EventEntry {
            timestamp: Timestamp(100),
            device_id: DeviceId([2u8; 16]),
            event: Event::EpochRotated { epoch: 1 },
        };
        let msg = ClusterSyncResponseMsg {
            v: 1,
            events: vec![(5, entry)],
            responder_last_seq: 5,
            timestamp: Timestamp(200),
        };
        let bytes = to_cbor(&msg).unwrap();
        let decoded: ClusterSyncResponseMsg = from_cbor(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }
}
