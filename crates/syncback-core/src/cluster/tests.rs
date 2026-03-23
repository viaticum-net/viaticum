#[cfg(test)]
mod cluster_state_tests {
    use crate::cluster::{
        derive_device_key, derive_master_key, issue_device_certificate, issue_revocation,
        master_identity, ClusterState, ClusterStateError, EpochCounter,
    };
    use crate::db::Db;
    use crate::messages::{build_handshake, extract_cluster_identity, verify_handshake};
    use crate::types::{
        DeviceId, EventEntry, Event, FileId, FileRecord, FileVersion, IdentityPub,
        LocalState, SourceBlockId, Timestamp,
    };

    const SEED: [u8; 32] = [1u8; 32];
    const DEVICE_ID_BYTES: [u8; 16] = [2u8; 16];
    const NOW: Timestamp = Timestamp(10_000);

    fn make_master_and_cert() -> (ed25519_dalek::SigningKey, IdentityPub, DeviceId, [u8; 32]) {
        let seed = SEED;
        let master_key = derive_master_key(&seed).unwrap();
        let master_pub = master_identity(&master_key);
        let device_id = DeviceId(DEVICE_ID_BYTES);
        let device_key = derive_device_key(&seed, &device_id).unwrap();
        let device_pub = device_key.verifying_key().to_bytes();
        (master_key, master_pub, device_id, device_pub)
    }

    fn make_cluster_state() -> ClusterState {
        let db = Db::open_in_memory().unwrap();
        let (master_key, master_pub, device_id, device_pub) = make_master_and_cert();
        let cert = issue_device_certificate(&master_key, device_id, device_pub, NOW);
        ClusterState::init(db, master_pub, cert, NOW, NOW).unwrap()
    }

    // 1. init creates first device
    #[test]
    fn cluster_state_init_creates_first_device() {
        let state = make_cluster_state();
        assert_eq!(state.active_devices().len(), 1);
        assert_eq!(state.current_epoch(), EpochCounter(0));
        assert_eq!(state.epoch_history().len(), 1);
    }

    // 2. load after init
    #[test]
    fn cluster_state_load_after_init() {
        let db = Db::open_in_memory().unwrap();
        let (master_key, master_pub, device_id, device_pub) = make_master_and_cert();
        let cert = issue_device_certificate(&master_key, device_id, device_pub, NOW);
        let original_master_pub = master_pub;
        let _state = ClusterState::init(db.clone(), master_pub, cert, NOW, NOW).unwrap();
        drop(_state);

        let loaded = ClusterState::load(db).unwrap();
        assert_eq!(loaded.active_devices().len(), 1);
        assert_eq!(loaded.master_pub(), original_master_pub);
    }

    // 3. load fails when not initialized
    #[test]
    fn cluster_state_load_fails_when_not_initialized() {
        let db = Db::open_in_memory().unwrap();
        let result = ClusterState::load(db);
        assert!(matches!(result, Err(ClusterStateError::NotInitialized)));
    }

    // 4. add device increments count
    #[test]
    fn add_device_increments_count() {
        let mut state = make_cluster_state();
        let (master_key, _, _, _) = make_master_and_cert();
        let device_b_id = DeviceId([3u8; 16]);
        let device_b_key = derive_device_key(&SEED, &device_b_id).unwrap();
        let device_b_pub = device_b_key.verifying_key().to_bytes();
        let cert_b = issue_device_certificate(&master_key, device_b_id, device_b_pub, NOW);
        state.add_device(cert_b, NOW).unwrap();
        assert_eq!(state.active_devices().len(), 2);
        assert_eq!(state.get_device(&device_b_id).unwrap().device_index, 1);
    }

    // 5. add duplicate fails
    #[test]
    fn add_device_duplicate_fails() {
        let mut state = make_cluster_state();
        let (master_key, _, _, _) = make_master_and_cert();
        let device_id = DeviceId(DEVICE_ID_BYTES);
        let device_key = derive_device_key(&SEED, &device_id).unwrap();
        let device_pub = device_key.verifying_key().to_bytes();
        let cert = issue_device_certificate(&master_key, device_id, device_pub, NOW);
        let result = state.add_device(cert, NOW);
        assert!(matches!(result, Err(ClusterStateError::DeviceAlreadyRegistered(_))));
    }

    // 6. add device with wrong master fails
    #[test]
    fn add_device_with_wrong_master_fails() {
        let mut state = make_cluster_state();
        let wrong_master = derive_master_key(&[99u8; 32]).unwrap();
        let device_b_id = DeviceId([4u8; 16]);
        let device_b_pub = [5u8; 32];
        let cert = issue_device_certificate(&wrong_master, device_b_id, device_b_pub, NOW);
        let result = state.add_device(cert, NOW);
        assert!(matches!(result, Err(ClusterStateError::InvalidCertificate(_))));
    }

    // 7. max 16 devices enforced
    #[test]
    fn add_device_max_16_enforced() {
        let mut state = make_cluster_state();
        let (master_key, _, _, _) = make_master_and_cert();
        // Add 15 more (total 16 including the initial one)
        for i in 3u8..18 {
            let did = DeviceId([i; 16]);
            let dkey = derive_device_key(&SEED, &did).unwrap();
            let dpub = dkey.verifying_key().to_bytes();
            let cert = issue_device_certificate(&master_key, did, dpub, NOW);
            let result = state.add_device(cert, NOW);
            if state.all_devices().len() <= 16 {
                // We already added it; check result only for the 17th attempt
                let _ = result;
            }
        }
        // At this point we should have 16 devices. Attempt one more.
        let did = DeviceId([0xFFu8; 16]);
        let dkey = derive_device_key(&SEED, &did).unwrap();
        let dpub = dkey.verifying_key().to_bytes();
        let cert = issue_device_certificate(&master_key, did, dpub, NOW);
        let result = state.add_device(cert, NOW);
        assert!(matches!(result, Err(ClusterStateError::MaxDevicesReached)));
    }

    // 8. revoke device marks revoked
    #[test]
    fn revoke_device_marks_revoked() {
        let mut state = make_cluster_state();
        let (master_key, _, _, _) = make_master_and_cert();
        let device_a_id = DeviceId(DEVICE_ID_BYTES);
        let device_b_id = DeviceId([3u8; 16]);
        let dkey_b = derive_device_key(&SEED, &device_b_id).unwrap();
        let dpub_b = dkey_b.verifying_key().to_bytes();
        let cert_b = issue_device_certificate(&master_key, device_b_id, dpub_b, NOW);
        state.add_device(cert_b, NOW).unwrap();

        let rev = issue_revocation(&master_key, device_a_id, NOW, EpochCounter(1));
        state.revoke_device(rev, NOW, NOW).unwrap();

        assert!(state.is_device_revoked(&device_a_id));
        assert_eq!(state.active_devices().len(), 1);
        assert_eq!(state.current_epoch(), EpochCounter(1));
        assert_eq!(state.epoch_history().len(), 2);
    }

    // 9. revoke already revoked fails
    #[test]
    fn revoke_already_revoked_fails() {
        let mut state = make_cluster_state();
        let (master_key, _, _, _) = make_master_and_cert();
        let device_a_id = DeviceId(DEVICE_ID_BYTES);
        let rev1 = issue_revocation(&master_key, device_a_id, NOW, EpochCounter(1));
        state.revoke_device(rev1, NOW, NOW).unwrap();

        let rev2 = issue_revocation(&master_key, device_a_id, NOW, EpochCounter(2));
        let result = state.revoke_device(rev2, NOW, NOW);
        assert!(matches!(result, Err(ClusterStateError::DeviceRevoked(_))));
    }

    // 10. revoke unknown device fails
    #[test]
    fn revoke_unknown_device_fails() {
        let mut state = make_cluster_state();
        let (master_key, _, _, _) = make_master_and_cert();
        let unknown = DeviceId([0xFF; 16]);
        let rev = issue_revocation(&master_key, unknown, NOW, EpochCounter(1));
        let result = state.revoke_device(rev, NOW, NOW);
        assert!(matches!(result, Err(ClusterStateError::DeviceNotFound(_))));
    }

    // 11. peer affinity set and get
    #[test]
    fn peer_affinity_set_and_get() {
        let mut state = make_cluster_state();
        let d1 = DeviceId(DEVICE_ID_BYTES);
        let peer_a = IdentityPub([10u8; 32]);
        state.set_peer_affinity(peer_a, d1).unwrap();
        assert_eq!(state.peer_device(&peer_a), Some(d1));
        assert!(state.peers_for_device(&d1).contains(&peer_a));
    }

    // 12. peer affinity reassign
    #[test]
    fn peer_affinity_reassign() {
        let mut state = make_cluster_state();
        let (master_key, _, _, _) = make_master_and_cert();
        let d1 = DeviceId(DEVICE_ID_BYTES);
        let d2 = DeviceId([3u8; 16]);
        let dkey2 = derive_device_key(&SEED, &d2).unwrap();
        let dpub2 = dkey2.verifying_key().to_bytes();
        let cert2 = issue_device_certificate(&master_key, d2, dpub2, NOW);
        state.add_device(cert2, NOW).unwrap();

        let peer_a = IdentityPub([10u8; 32]);
        state.set_peer_affinity(peer_a, d1).unwrap();
        state.set_peer_affinity(peer_a, d2).unwrap();

        assert_eq!(state.peer_device(&peer_a), Some(d2));
        assert!(state.peers_for_device(&d1).is_empty());
        assert!(state.peers_for_device(&d2).contains(&peer_a));
    }

    // 13. peer affinity persisted across load
    #[test]
    fn peer_affinity_persisted_across_load() {
        let db = Db::open_in_memory().unwrap();
        let (master_key, master_pub, device_id, device_pub) = make_master_and_cert();
        let cert = issue_device_certificate(&master_key, device_id, device_pub, NOW);
        let mut state = ClusterState::init(db.clone(), master_pub, cert, NOW, NOW).unwrap();

        let d1 = DeviceId(DEVICE_ID_BYTES);
        let peer_a = IdentityPub([10u8; 32]);
        state.set_peer_affinity(peer_a, d1).unwrap();
        drop(state);

        let loaded = ClusterState::load(db).unwrap();
        assert_eq!(loaded.peer_device(&peer_a), Some(d1));
    }

    fn make_file_record_with_version(
        content_hash: [u8; 32],
        backed_up_at: Option<Timestamp>,
    ) -> FileRecord {
        FileRecord {
            file_id: FileId(1),
            path: "/test/file.txt".to_string(),
            importance: 1.0,
            devices: vec![(DeviceId(DEVICE_ID_BYTES), LocalState::Present)],
            versions: vec![FileVersion {
                content_hash,
                source_block_id: SourceBlockId([0xAB; 32]),
                k: 2,
                t: 65535,
                created_at: NOW,
                backed_up_at,
            }],
            first_seen: NOW,
        }
    }

    // 14. is_content_backed_up true when version exists with backed_up_at
    #[test]
    fn is_content_backed_up_true_when_version_exists() {
        let state = make_cluster_state();
        let hash = [0xBBu8; 32];
        let record = make_file_record_with_version(hash, Some(NOW));
        state.db.upsert_file(&record).unwrap();
        assert_eq!(state.is_content_backed_up(&hash).unwrap(), true);
    }

    // 15. is_content_backed_up false when backed_up_at is None
    #[test]
    fn is_content_backed_up_false_when_not_backed_up_yet() {
        let state = make_cluster_state();
        let hash = [0xCCu8; 32];
        let record = make_file_record_with_version(hash, None);
        state.db.upsert_file(&record).unwrap();
        assert_eq!(state.is_content_backed_up(&hash).unwrap(), false);
    }

    // 16. is_content_backed_up false when no file
    #[test]
    fn is_content_backed_up_false_when_no_file() {
        let state = make_cluster_state();
        assert_eq!(state.is_content_backed_up(&[0u8; 32]).unwrap(), false);
    }

    // 17. esi_namespace correct for device
    #[test]
    fn esi_namespace_correct_for_device() {
        let mut state = make_cluster_state();
        let (master_key, _, _, _) = make_master_and_cert();
        let device_1_id = DeviceId([3u8; 16]);
        let dkey1 = derive_device_key(&SEED, &device_1_id).unwrap();
        let dpub1 = dkey1.verifying_key().to_bytes();
        let cert1 = issue_device_certificate(&master_key, device_1_id, dpub1, NOW);
        state.add_device(cert1, NOW).unwrap();

        let device_0_id = DeviceId(DEVICE_ID_BYTES);
        assert_eq!(state.esi_namespace(&device_0_id), Some((0, 1_048_576)));
        assert_eq!(state.esi_namespace(&device_1_id), Some((1_048_576, 2_097_152)));
        let unknown = DeviceId([0xFF; 16]);
        assert_eq!(state.esi_namespace(&unknown), None);
    }

    // 18. apply_events DeviceRevoked is idempotent
    #[test]
    fn apply_events_device_revoked_is_idempotent() {
        let mut state = make_cluster_state();
        let d1 = DeviceId(DEVICE_ID_BYTES);
        let events = vec![(
            1u64,
            EventEntry {
                timestamp: NOW,
                device_id: d1,
                event: Event::DeviceRevoked { device_id: d1 },
            },
        )];
        state.apply_events(&events).unwrap();
        state.apply_events(&events).unwrap();
        assert!(state.is_device_revoked(&d1));
        // Still only one entry in revoked_devices
        assert_eq!(state.all_devices().len(), 1);
    }

    // 19. apply_events epoch rotated does not regress
    #[test]
    fn apply_events_epoch_rotated_does_not_regress() {
        let mut state = make_cluster_state();
        let (master_key, _, _, _) = make_master_and_cert();
        let device_a_id = DeviceId(DEVICE_ID_BYTES);
        // Set current epoch to 3 via revoke chain
        let device_b_id = DeviceId([3u8; 16]);
        let dkeyb = derive_device_key(&SEED, &device_b_id).unwrap();
        let dpubb = dkeyb.verifying_key().to_bytes();
        let certb = issue_device_certificate(&master_key, device_b_id, dpubb, NOW);
        state.add_device(certb, NOW).unwrap();

        // Fast-forward epoch manually via apply_events
        let events = vec![
            (
                10u64,
                EventEntry {
                    timestamp: NOW,
                    device_id: device_a_id,
                    event: Event::EpochRotated { epoch: 3 },
                },
            ),
        ];
        state.apply_events(&events).unwrap();
        assert_eq!(state.current_epoch(), EpochCounter(3));

        // Now apply an older epoch — should not regress
        let older_events = vec![(
            11u64,
            EventEntry {
                timestamp: NOW,
                device_id: device_a_id,
                event: Event::EpochRotated { epoch: 2 },
            },
        )];
        state.apply_events(&older_events).unwrap();
        assert_eq!(state.current_epoch(), EpochCounter(3));
    }

    // 20. sync_cursor returns 0 when no cursor set
    #[test]
    fn sync_cursor_returns_zero_when_not_set() {
        let state = make_cluster_state();
        let peer = IdentityPub([0x42u8; 32]);
        assert_eq!(state.sync_cursor(&peer), 0);
    }

    // 21. update_sync_cursor persists and is readable
    #[test]
    fn update_sync_cursor_persists_value() {
        let mut state = make_cluster_state();
        let peer = IdentityPub([0x55u8; 32]);
        state.update_sync_cursor(peer, 42).unwrap();
        assert_eq!(state.sync_cursor(&peer), 42);
    }

    // 22. update_sync_cursor survives reload
    #[test]
    fn update_sync_cursor_survives_reload() {
        let db = Db::open_in_memory().unwrap();
        let (master_key, master_pub, device_id, device_pub) = make_master_and_cert();
        let cert = issue_device_certificate(&master_key, device_id, device_pub, NOW);
        let mut state = ClusterState::init(db.clone(), master_pub, cert, NOW, NOW).unwrap();

        let peer = IdentityPub([0xAAu8; 32]);
        state.update_sync_cursor(peer, 99).unwrap();
        drop(state);

        let loaded = ClusterState::load(db).unwrap();
        assert_eq!(loaded.sync_cursor(&peer), 99);
    }

    // 23. update_sync_cursor overwrites previous value
    #[test]
    fn update_sync_cursor_overwrites_previous_value() {
        let mut state = make_cluster_state();
        let peer = IdentityPub([0x77u8; 32]);
        state.update_sync_cursor(peer, 10).unwrap();
        state.update_sync_cursor(peer, 50).unwrap();
        assert_eq!(state.sync_cursor(&peer), 50);
    }

    // 24. sync_cursor independent per peer
    #[test]
    fn sync_cursor_independent_per_peer() {
        let mut state = make_cluster_state();
        let peer_a = IdentityPub([0x11u8; 32]);
        let peer_b = IdentityPub([0x22u8; 32]);
        state.update_sync_cursor(peer_a, 100).unwrap();
        state.update_sync_cursor(peer_b, 200).unwrap();
        assert_eq!(state.sync_cursor(&peer_a), 100);
        assert_eq!(state.sync_cursor(&peer_b), 200);
    }

    // 25. find_source_block_for_content returns Some when backed up
    #[test]
    fn find_source_block_for_content_returns_some_when_backed_up() {
        let state = make_cluster_state();
        let hash = [0xDDu8; 32];
        let expected_block = SourceBlockId([0xABu8; 32]);
        let record = FileRecord {
            file_id: FileId(5),
            path: "/some/file".to_string(),
            importance: 0.5,
            devices: vec![(DeviceId(DEVICE_ID_BYTES), LocalState::Present)],
            versions: vec![FileVersion {
                content_hash: hash,
                source_block_id: expected_block,
                k: 2,
                t: 65535,
                created_at: NOW,
                backed_up_at: Some(NOW),
            }],
            first_seen: NOW,
        };
        state.db.upsert_file(&record).unwrap();
        let result = state.find_source_block_for_content(&hash).unwrap();
        assert_eq!(result, Some(expected_block));
    }

    // 26. find_source_block_for_content returns None when not backed up
    #[test]
    fn find_source_block_for_content_returns_none_when_not_backed_up() {
        let state = make_cluster_state();
        let hash = [0xEEu8; 32];
        let record = make_file_record_with_version(hash, None);
        state.db.upsert_file(&record).unwrap();
        let result = state.find_source_block_for_content(&hash).unwrap();
        assert_eq!(result, None);
    }

    // 27. find_source_block_for_content returns None when no files
    #[test]
    fn find_source_block_for_content_returns_none_when_no_files() {
        let state = make_cluster_state();
        let result = state.find_source_block_for_content(&[0u8; 32]).unwrap();
        assert_eq!(result, None);
    }

    // 28. local_last_seq returns 0 when no events appended
    #[test]
    fn local_last_seq_returns_one_after_init() {
        let state = make_cluster_state();
        // init() appends one DeviceAdded event, so last_seq = 1
        let seq = state.local_last_seq().unwrap();
        assert_eq!(seq, 1);
    }

    // 29. local_last_seq increments with appended events
    #[test]
    fn local_last_seq_increments_with_appended_events() {
        let db = Db::open_in_memory().unwrap();
        let (master_key, master_pub, device_id, device_pub) = make_master_and_cert();
        let cert = issue_device_certificate(&master_key, device_id, device_pub, NOW);
        let state = ClusterState::init(db.clone(), master_pub, cert, NOW, NOW).unwrap();

        // init appended 1 event; append 2 more manually
        db.append_event(&EventEntry {
            timestamp: NOW,
            device_id,
            event: Event::EpochRotated { epoch: 1 },
        }).unwrap();
        db.append_event(&EventEntry {
            timestamp: NOW,
            device_id,
            event: Event::EpochRotated { epoch: 2 },
        }).unwrap();

        let seq = state.local_last_seq().unwrap();
        assert_eq!(seq, 3);
    }

    // CLUSTER-14: handshake crypto passes but state-level revocation check catches it
    #[test]
    fn handshake_with_revoked_device_cert_detected() {
        // Step 1: generate master key pair
        let master_key = derive_master_key(&SEED).unwrap();
        let master_pub = master_identity(&master_key);

        // Step 2: generate device key pair
        let device_id = DeviceId(DEVICE_ID_BYTES);
        let device_key = derive_device_key(&SEED, &device_id).unwrap();
        let device_pub = device_key.verifying_key().to_bytes();

        // Step 3: issue device certificate
        let cert = issue_device_certificate(&master_key, device_id, device_pub, NOW);

        // Step 4: build handshake — identity_pub = device pub key, signed with device key
        // device_cert.device_pub_key must match identity_pub (enforced by extract_cluster_identity)
        let device_identity_pub = IdentityPub(device_pub);
        let hs = build_handshake(device_identity_pub, NOW, &device_key, Some(cert.clone()));

        // Step 5: verify_handshake passes (signature is valid, timestamp is fresh)
        assert!(verify_handshake(&hs, NOW).is_ok(), "handshake sig must be valid");

        // Step 6: extract_cluster_identity passes (cert sig is valid)
        let extracted = extract_cluster_identity(&hs).unwrap();
        assert_eq!(extracted, Some(master_pub), "cluster identity must resolve to master pub");

        // Step 7: issue revocation for the device
        let rev = issue_revocation(&master_key, device_id, NOW, EpochCounter(1));

        // Step 8: create ClusterState with a second device so revoking device_id is possible
        // (revoke_device requires at least one active device to remain — but actually the API
        //  does not enforce that, so we can have a single-device cluster and revoke it)
        let db = Db::open_in_memory().unwrap();
        let mut state = ClusterState::init(db, master_pub, cert, NOW, NOW).unwrap();
        state.revoke_device(rev, NOW, NOW).unwrap();

        // Step 9: the state-level check must catch the revoked device
        assert!(
            state.is_device_revoked(&device_id),
            "device must be marked revoked in ClusterState"
        );

        // Summary: crypto verification (steps 5-6) passed because the cert signature is still
        // cryptographically valid. The two-layer model requires the caller to also check
        // ClusterState::is_device_revoked() after extract_cluster_identity succeeds.
    }
}

#[cfg(test)]
mod tests {
    use crate::cluster::{
        derive_device_key, derive_epoch_key, derive_iroh_key, derive_master_key, epoch_for_time,
        esi_namespace_end, esi_namespace_start, issue_device_certificate, issue_revocation,
        master_identity, next_epoch, verify_device_certificate, verify_revocation, ClusterError,
        EpochCounter,
    };
    use crate::types::{DeviceId, Timestamp};

    #[test]
    fn derive_master_key_is_deterministic() {
        let seed = [0u8; 32];
        let key1 = derive_master_key(&seed).unwrap();
        let key2 = derive_master_key(&seed).unwrap();
        assert_eq!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn derive_device_key_differs_from_master() {
        let seed = [1u8; 32];
        let master = derive_master_key(&seed).unwrap();
        let device_id = DeviceId([2u8; 16]);
        let device = derive_device_key(&seed, &device_id).unwrap();
        assert_ne!(master.to_bytes(), device.to_bytes());
    }

    #[test]
    fn derive_device_key_differs_per_device() {
        let seed = [3u8; 32];
        let device_id_a = DeviceId([0u8; 16]);
        let device_id_b = DeviceId([1u8; 16]);
        let key_a = derive_device_key(&seed, &device_id_a).unwrap();
        let key_b = derive_device_key(&seed, &device_id_b).unwrap();
        assert_ne!(key_a.to_bytes(), key_b.to_bytes());
    }

    #[test]
    fn derive_epoch_key_differs_per_epoch() {
        let seed = [4u8; 32];
        let epoch_0 = derive_epoch_key(&seed, EpochCounter(0)).unwrap();
        let epoch_1 = derive_epoch_key(&seed, EpochCounter(1)).unwrap();
        assert_ne!(epoch_0.key_bytes, epoch_1.key_bytes);
    }

    #[test]
    fn master_identity_round_trip() {
        let seed = [5u8; 32];
        let master_key = derive_master_key(&seed).unwrap();
        let identity = master_identity(&master_key);
        assert_eq!(identity.0, master_key.verifying_key().to_bytes());
    }

    #[test]
    fn issue_and_verify_device_certificate() {
        let master_key = derive_master_key(&[1u8; 32]).unwrap();
        let device_id = DeviceId([3u8; 16]);
        let device_pub = [4u8; 32];
        let cert = issue_device_certificate(&master_key, device_id, device_pub, Timestamp(1000));
        let result = verify_device_certificate(&cert, &master_identity(&master_key));
        assert!(result.is_ok());
    }

    #[test]
    fn verify_certificate_with_wrong_master_fails() {
        let master_a = derive_master_key(&[1u8; 32]).unwrap();
        let master_b = derive_master_key(&[2u8; 32]).unwrap();
        let device_id = DeviceId([3u8; 16]);
        let device_pub = [4u8; 32];
        let cert = issue_device_certificate(&master_a, device_id, device_pub, Timestamp(1000));
        let result = verify_device_certificate(&cert, &master_identity(&master_b));
        assert!(matches!(result, Err(ClusterError::InvalidSignature)));
    }

    #[test]
    fn verify_certificate_tampered_signature_fails() {
        let master_key = derive_master_key(&[1u8; 32]).unwrap();
        let device_id = DeviceId([3u8; 16]);
        let device_pub = [4u8; 32];
        let mut cert = issue_device_certificate(&master_key, device_id, device_pub, Timestamp(1000));
        cert.signature[0] ^= 1;
        let result = verify_device_certificate(&cert, &master_identity(&master_key));
        assert!(matches!(result, Err(ClusterError::InvalidSignature)));
    }

    #[test]
    fn verify_certificate_tampered_device_id_fails() {
        let master_key = derive_master_key(&[1u8; 32]).unwrap();
        let device_id = DeviceId([3u8; 16]);
        let device_pub = [4u8; 32];
        let mut cert = issue_device_certificate(&master_key, device_id, device_pub, Timestamp(1000));
        cert.device_id = DeviceId([0xFF; 16]);
        let result = verify_device_certificate(&cert, &master_identity(&master_key));
        assert!(matches!(result, Err(ClusterError::InvalidSignature)));
    }

    #[test]
    fn issue_and_verify_revocation() {
        let master_key = derive_master_key(&[1u8; 32]).unwrap();
        let device_id = DeviceId([5u8; 16]);
        let cert = issue_revocation(&master_key, device_id, Timestamp(5000), EpochCounter(1));
        let result = verify_revocation(&cert, &master_identity(&master_key));
        assert!(result.is_ok());
    }

    #[test]
    fn tampered_revocation_fails() {
        let master_key = derive_master_key(&[1u8; 32]).unwrap();
        let device_id = DeviceId([5u8; 16]);
        let mut cert = issue_revocation(&master_key, device_id, Timestamp(5000), EpochCounter(1));
        cert.new_epoch.0 += 1;
        let result = verify_revocation(&cert, &master_identity(&master_key));
        assert!(matches!(result, Err(ClusterError::InvalidSignature)));
    }

    #[test]
    fn epoch_for_time_basic() {
        let history = vec![
            (EpochCounter(0), Timestamp(0)),
            (EpochCounter(1), Timestamp(1000)),
            (EpochCounter(2), Timestamp(2000)),
        ];
        assert_eq!(epoch_for_time(&history, Timestamp(0)), EpochCounter(0));
        assert_eq!(epoch_for_time(&history, Timestamp(500)), EpochCounter(0));
        assert_eq!(epoch_for_time(&history, Timestamp(1000)), EpochCounter(1));
        assert_eq!(epoch_for_time(&history, Timestamp(1500)), EpochCounter(1));
        assert_eq!(epoch_for_time(&history, Timestamp(2000)), EpochCounter(2));
        assert_eq!(epoch_for_time(&history, Timestamp(9999)), EpochCounter(2));
    }

    #[test]
    fn epoch_for_time_before_genesis() {
        let history = vec![(EpochCounter(0), Timestamp(100))];
        assert_eq!(epoch_for_time(&history, Timestamp(50)), EpochCounter(0));
    }

    #[test]
    fn esi_namespace_no_overlap() {
        assert_eq!(esi_namespace_start(0), 0);
        assert_eq!(esi_namespace_start(1), 1_048_576);
        assert_eq!(esi_namespace_end(0), esi_namespace_start(1));

        for i in 0u8..15 {
            assert_eq!(esi_namespace_end(i), esi_namespace_start(i + 1));
        }
        assert_eq!(esi_namespace_start(15), 15 * (1 << 20));
        assert_eq!(esi_namespace_end(15), 16 * (1 << 20));
    }

    // ============================================================
    // derive_iroh_key tests
    // ============================================================

    #[test]
    fn derive_iroh_key_is_deterministic() {
        let seed = [42u8; 64];
        let device_id = DeviceId([1u8; 16]);
        let key1 = derive_iroh_key(&seed, &device_id).unwrap();
        let key2 = derive_iroh_key(&seed, &device_id).unwrap();
        assert_eq!(key1, key2, "same seed+device_id must produce same iroh key");
    }

    #[test]
    fn derive_iroh_key_differs_per_device() {
        let seed = [42u8; 64];
        let device_a = DeviceId([1u8; 16]);
        let device_b = DeviceId([2u8; 16]);
        let key_a = derive_iroh_key(&seed, &device_a).unwrap();
        let key_b = derive_iroh_key(&seed, &device_b).unwrap();
        assert_ne!(key_a, key_b, "different device_ids must produce different iroh keys");
    }

    #[test]
    fn derive_iroh_key_differs_from_device_key() {
        let seed = [42u8; 64];
        let device_id = DeviceId([1u8; 16]);
        let iroh_bytes = derive_iroh_key(&seed, &device_id).unwrap();
        let device_signing = derive_device_key(&seed, &device_id).unwrap();
        let device_bytes = device_signing.to_bytes();
        assert_ne!(iroh_bytes, device_bytes, "iroh key must differ from device signing key");
    }

    #[test]
    fn derive_iroh_key_output_is_32_bytes() {
        let seed = [0u8; 32];
        let device_id = DeviceId([0u8; 16]);
        let key = derive_iroh_key(&seed, &device_id).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn full_cluster_flow() {
        let seed = [42u8; 32];
        let master_key = derive_master_key(&seed).unwrap();
        let identity = master_identity(&master_key);

        let device_a = DeviceId([10u8; 16]);
        let device_b = DeviceId([20u8; 16]);
        let pub_a = [11u8; 32];
        let pub_b = [21u8; 32];

        let cert_a = issue_device_certificate(&master_key, device_a, pub_a, Timestamp(100));
        let cert_b = issue_device_certificate(&master_key, device_b, pub_b, Timestamp(200));

        assert!(verify_device_certificate(&cert_a, &identity).is_ok());
        assert!(verify_device_certificate(&cert_b, &identity).is_ok());

        let revocation = issue_revocation(&master_key, device_a, Timestamp(1000), EpochCounter(1));
        assert!(verify_revocation(&revocation, &identity).is_ok());
        assert_eq!(revocation.new_epoch, EpochCounter(1));
        assert_eq!(next_epoch(EpochCounter(0)), EpochCounter(1));

        let epoch_key_0 = derive_epoch_key(&seed, EpochCounter(0)).unwrap();
        let epoch_key_1 = derive_epoch_key(&seed, EpochCounter(1)).unwrap();
        assert_ne!(epoch_key_0.key_bytes, epoch_key_1.key_bytes);

        let history = vec![
            (EpochCounter(0), Timestamp(0)),
            (EpochCounter(1), Timestamp(1000)),
        ];
        assert_eq!(epoch_for_time(&history, Timestamp(500)), EpochCounter(0));
        assert_eq!(epoch_for_time(&history, Timestamp(1500)), EpochCounter(1));
    }
}
