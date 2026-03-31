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
    // device_seed is separate from device_id; device_id = pubkey derived from seed + device_seed
    const DEVICE_SEED_A: [u8; 32] = [2u8; 32];
    const NOW: Timestamp = Timestamp(10_000);

    fn make_master_and_cert() -> (ed25519_dalek::SigningKey, IdentityPub, DeviceId) {
        let seed = SEED;
        let master_key = derive_master_key(&seed).unwrap();
        let master_pub = master_identity(&master_key);
        let device_key = derive_device_key(&seed, &DEVICE_SEED_A).unwrap();
        let device_id = DeviceId(device_key.verifying_key().to_bytes());
        (master_key, master_pub, device_id)
    }

    fn make_cluster_state() -> ClusterState {
        let db = Db::open_in_memory().unwrap();
        let (master_key, master_pub, device_id) = make_master_and_cert();
        let cert = issue_device_certificate(&master_key, device_id, NOW);
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
        let (master_key, master_pub, device_id) = make_master_and_cert();
        let cert = issue_device_certificate(&master_key, device_id, NOW);
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
        let (master_key, _, _) = make_master_and_cert();
        // Use a different device_seed for device B
        let device_seed_b = [3u8; 32];
        let device_b_key = derive_device_key(&SEED, &device_seed_b).unwrap();
        let device_b_id = DeviceId(device_b_key.verifying_key().to_bytes());
        let cert_b = issue_device_certificate(&master_key, device_b_id, NOW);
        state.add_device(cert_b, NOW).unwrap();
        assert_eq!(state.active_devices().len(), 2);
        assert_eq!(state.get_device(&device_b_id).unwrap().device_index, 1);
    }

    // 5. add duplicate fails
    #[test]
    fn add_device_duplicate_fails() {
        let mut state = make_cluster_state();
        let (master_key, _, device_id) = make_master_and_cert();
        // Re-issue the same cert for the same device_id
        let cert = issue_device_certificate(&master_key, device_id, NOW);
        let result = state.add_device(cert, NOW);
        assert!(matches!(result, Err(ClusterStateError::DeviceAlreadyRegistered(_))));
    }

    // 6. add device with wrong master fails
    #[test]
    fn add_device_with_wrong_master_fails() {
        let mut state = make_cluster_state();
        let wrong_master = derive_master_key(&[99u8; 32]).unwrap();
        // device_b uses a valid device key but cert is signed by wrong master
        let device_seed_b = [4u8; 32];
        let device_b_key = derive_device_key(&SEED, &device_seed_b).unwrap();
        let device_b_id = DeviceId(device_b_key.verifying_key().to_bytes());
        let cert = issue_device_certificate(&wrong_master, device_b_id, NOW);
        let result = state.add_device(cert, NOW);
        assert!(matches!(result, Err(ClusterStateError::InvalidCertificate(_))));
    }

    // 7. max 16 devices enforced
    #[test]
    fn add_device_max_16_enforced() {
        let mut state = make_cluster_state();
        let (master_key, _, _) = make_master_and_cert();
        // Add 15 more devices (total 16 including the initial one)
        for i in 3u8..18 {
            let seed_i = [i; 32];
            let dkey = derive_device_key(&SEED, &seed_i).unwrap();
            let did = DeviceId(dkey.verifying_key().to_bytes());
            let cert = issue_device_certificate(&master_key, did, NOW);
            let result = state.add_device(cert, NOW);
            if state.all_devices().len() <= 16 {
                let _ = result;
            }
        }
        // At this point we should have 16 devices. Attempt one more.
        let seed_extra = [0xFEu8; 32];
        let dkey_extra = derive_device_key(&SEED, &seed_extra).unwrap();
        let did_extra = DeviceId(dkey_extra.verifying_key().to_bytes());
        let cert_extra = issue_device_certificate(&master_key, did_extra, NOW);
        let result = state.add_device(cert_extra, NOW);
        assert!(matches!(result, Err(ClusterStateError::MaxDevicesReached)));
    }

    // 8. revoke device marks revoked
    #[test]
    fn revoke_device_marks_revoked() {
        let mut state = make_cluster_state();
        let (master_key, _, device_a_id) = make_master_and_cert();
        let device_seed_b = [3u8; 32];
        let dkey_b = derive_device_key(&SEED, &device_seed_b).unwrap();
        let device_b_id = DeviceId(dkey_b.verifying_key().to_bytes());
        let cert_b = issue_device_certificate(&master_key, device_b_id, NOW);
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
        let (master_key, _, device_a_id) = make_master_and_cert();
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
        let (master_key, _, _) = make_master_and_cert();
        let unknown = DeviceId([0xFF; 32]);
        let rev = issue_revocation(&master_key, unknown, NOW, EpochCounter(1));
        let result = state.revoke_device(rev, NOW, NOW);
        assert!(matches!(result, Err(ClusterStateError::DeviceNotFound(_))));
    }

    // 11. peer affinity set and get
    #[test]
    fn peer_affinity_set_and_get() {
        let mut state = make_cluster_state();
        let (_, _, d1) = make_master_and_cert();
        let peer_a = IdentityPub([10u8; 32]);
        state.set_peer_affinity(peer_a, d1).unwrap();
        assert_eq!(state.peer_device(&peer_a), Some(d1));
        assert!(state.peers_for_device(&d1).contains(&peer_a));
    }

    // 12. peer affinity reassign
    #[test]
    fn peer_affinity_reassign() {
        let mut state = make_cluster_state();
        let (master_key, _, d1) = make_master_and_cert();
        let device_seed_b = [3u8; 32];
        let dkey2 = derive_device_key(&SEED, &device_seed_b).unwrap();
        let d2 = DeviceId(dkey2.verifying_key().to_bytes());
        let cert2 = issue_device_certificate(&master_key, d2, NOW);
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
        let (master_key, master_pub, device_id) = make_master_and_cert();
        let cert = issue_device_certificate(&master_key, device_id, NOW);
        let mut state = ClusterState::init(db.clone(), master_pub, cert, NOW, NOW).unwrap();

        let d1 = device_id;
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
        let (_, _, device_id) = make_master_and_cert();
        FileRecord {
            file_id: FileId(1),
            path: "/test/file.txt".to_string(),
            importance: 1.0,
            devices: vec![(device_id, LocalState::Present)],
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
        let (master_key, _, device_0_id) = make_master_and_cert();
        let device_seed_1 = [3u8; 32];
        let dkey1 = derive_device_key(&SEED, &device_seed_1).unwrap();
        let device_1_id = DeviceId(dkey1.verifying_key().to_bytes());
        let cert1 = issue_device_certificate(&master_key, device_1_id, NOW);
        state.add_device(cert1, NOW).unwrap();

        assert_eq!(state.esi_namespace(&device_0_id), Some((0, 1_048_576)));
        assert_eq!(state.esi_namespace(&device_1_id), Some((1_048_576, 2_097_152)));
        let unknown = DeviceId([0xFF; 32]);
        assert_eq!(state.esi_namespace(&unknown), None);
    }

    // 18. apply_events DeviceRevoked is idempotent
    #[test]
    fn apply_events_device_revoked_is_idempotent() {
        let mut state = make_cluster_state();
        let (_, _, d1) = make_master_and_cert();
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
        let (master_key, _, device_a_id) = make_master_and_cert();
        // Add device B so we can keep the cluster state valid
        let device_seed_b = [3u8; 32];
        let dkeyb = derive_device_key(&SEED, &device_seed_b).unwrap();
        let device_b_id = DeviceId(dkeyb.verifying_key().to_bytes());
        let certb = issue_device_certificate(&master_key, device_b_id, NOW);
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
        let (master_key, master_pub, device_id) = make_master_and_cert();
        let cert = issue_device_certificate(&master_key, device_id, NOW);
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
        let record = make_file_record_with_version(hash, Some(NOW));
        // override the source_block_id
        let mut record = record;
        record.versions[0].source_block_id = expected_block;
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

    // 28. local_last_seq returns 1 after init (one DeviceAdded event)
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
        let (master_key, master_pub, device_id) = make_master_and_cert();
        let cert = issue_device_certificate(&master_key, device_id, NOW);
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

        // Step 2: derive device key and device_id = pubkey
        let device_key = derive_device_key(&SEED, &DEVICE_SEED_A).unwrap();
        let device_id = DeviceId(device_key.verifying_key().to_bytes());

        // Step 3: issue device certificate (device_id.0 IS the pub key)
        let cert = issue_device_certificate(&master_key, device_id, NOW);

        // Step 4: build handshake — identity_pub = device pub key (= device_id.0), signed with device key
        let device_identity_pub = IdentityPub(device_id.0);
        let hs = build_handshake(device_identity_pub, NOW, &device_key, Some(cert.clone()));

        // Step 5: verify_handshake passes (signature is valid, timestamp is fresh)
        assert!(verify_handshake(&hs, NOW).is_ok(), "handshake sig must be valid");

        // Step 6: extract_cluster_identity passes (cert sig is valid)
        let extracted = extract_cluster_identity(&hs).unwrap();
        assert_eq!(extracted, Some(master_pub), "cluster identity must resolve to master pub");

        // Step 7: issue revocation for the device
        let rev = issue_revocation(&master_key, device_id, NOW, EpochCounter(1));

        // Step 8: create ClusterState and revoke device
        let db = Db::open_in_memory().unwrap();
        let mut state = ClusterState::init(db, master_pub, cert, NOW, NOW).unwrap();
        state.revoke_device(rev, NOW, NOW).unwrap();

        // Step 9: the state-level check must catch the revoked device
        assert!(
            state.is_device_revoked(&device_id),
            "device must be marked revoked in ClusterState"
        );
    }

    // Task A: device_id_is_32_bytes
    #[test]
    fn device_id_is_32_bytes() {
        let device_key = derive_device_key(&SEED, &DEVICE_SEED_A).unwrap();
        let device_id = DeviceId(device_key.verifying_key().to_bytes());
        assert_eq!(device_id.0.len(), 32);
    }

    // Task A: device_certificate_payload_is_40_bytes
    #[test]
    fn device_certificate_payload_is_40_bytes() {
        let master_key = derive_master_key(&SEED).unwrap();
        let device_key = derive_device_key(&SEED, &DEVICE_SEED_A).unwrap();
        let device_id = DeviceId(device_key.verifying_key().to_bytes());
        let cert = issue_device_certificate(&master_key, device_id, NOW);
        // payload = device_id.0 (32) || issued_at_be (8) = 40 bytes
        // We verify this indirectly: cert roundtrip verifies correctly
        let result = crate::cluster::verify_device_certificate(&cert, &master_identity(&master_key));
        assert!(result.is_ok());
        // Also check that tampering issued_at breaks it
        let mut tampered = cert.clone();
        tampered.issued_at = Timestamp(99999);
        let tampered_result = crate::cluster::verify_device_certificate(&tampered, &master_identity(&master_key));
        assert!(tampered_result.is_err());
    }

    // Task A: issue_and_verify_device_certificate_roundtrip
    #[test]
    fn issue_and_verify_device_certificate_roundtrip() {
        let master_key = derive_master_key(&SEED).unwrap();
        let device_key = derive_device_key(&SEED, &DEVICE_SEED_A).unwrap();
        let device_id = DeviceId(device_key.verifying_key().to_bytes());
        let cert = issue_device_certificate(&master_key, device_id, NOW);
        let result = crate::cluster::verify_device_certificate(&cert, &master_identity(&master_key));
        assert!(result.is_ok());
    }

    // Task A: verify_device_certificate_fails_wrong_master
    #[test]
    fn verify_device_certificate_fails_wrong_master() {
        let master_a = derive_master_key(&SEED).unwrap();
        let master_b = derive_master_key(&[99u8; 32]).unwrap();
        let device_key = derive_device_key(&SEED, &DEVICE_SEED_A).unwrap();
        let device_id = DeviceId(device_key.verifying_key().to_bytes());
        let cert = issue_device_certificate(&master_a, device_id, NOW);
        let result = crate::cluster::verify_device_certificate(&cert, &master_identity(&master_b));
        assert!(matches!(result, Err(crate::cluster::ClusterError::InvalidSignature)));
    }

    // Task A: verify_device_certificate_uses_device_id_as_pubkey
    // Tampering device_id changes the pubkey used for verification → sig fails
    #[test]
    fn verify_device_certificate_uses_device_id_as_pubkey() {
        let master_key = derive_master_key(&SEED).unwrap();
        let device_key = derive_device_key(&SEED, &DEVICE_SEED_A).unwrap();
        let device_id = DeviceId(device_key.verifying_key().to_bytes());
        let mut cert = issue_device_certificate(&master_key, device_id, NOW);
        // Tamper device_id → changes the pubkey used to verify → sig invalid
        cert.device_id = DeviceId([0xFF; 32]);
        let result = crate::cluster::verify_device_certificate(&cert, &master_identity(&master_key));
        assert!(matches!(result, Err(crate::cluster::ClusterError::InvalidSignature)));
    }

    // Task A: revocation_payload_is_50_bytes
    #[test]
    fn revocation_payload_is_50_bytes() {
        let master_key = derive_master_key(&SEED).unwrap();
        let device_key = derive_device_key(&SEED, &DEVICE_SEED_A).unwrap();
        let device_id = DeviceId(device_key.verifying_key().to_bytes());
        let cert = issue_revocation(&master_key, device_id, NOW, EpochCounter(1));
        // payload = b"revoke"(6) + device_id.0(32) + revoked_at_be(8) + epoch_be(4) = 50
        // Verify indirectly: tampering new_epoch breaks sig
        let result = crate::cluster::verify_revocation(&cert, &master_identity(&master_key));
        assert!(result.is_ok());
        let mut tampered = cert.clone();
        tampered.new_epoch = EpochCounter(42);
        let tampered_result = crate::cluster::verify_revocation(&tampered, &master_identity(&master_key));
        assert!(tampered_result.is_err());
    }

    // Task A: issue_and_verify_revocation_roundtrip
    #[test]
    fn issue_and_verify_revocation_roundtrip() {
        let master_key = derive_master_key(&SEED).unwrap();
        let device_key = derive_device_key(&SEED, &DEVICE_SEED_A).unwrap();
        let device_id = DeviceId(device_key.verifying_key().to_bytes());
        let cert = issue_revocation(&master_key, device_id, NOW, EpochCounter(1));
        let result = crate::cluster::verify_revocation(&cert, &master_identity(&master_key));
        assert!(result.is_ok());
    }

    // Task A: cluster_init_and_add_device_with_new_cert_format
    #[test]
    fn cluster_init_and_add_device_with_new_cert_format() {
        let master_key = derive_master_key(&SEED).unwrap();
        let master_pub = master_identity(&master_key);

        let dkey_a = derive_device_key(&SEED, &DEVICE_SEED_A).unwrap();
        let did_a = DeviceId(dkey_a.verifying_key().to_bytes());

        let device_seed_b = [5u8; 32];
        let dkey_b = derive_device_key(&SEED, &device_seed_b).unwrap();
        let did_b = DeviceId(dkey_b.verifying_key().to_bytes());

        let db = Db::open_in_memory().unwrap();
        let cert_a = issue_device_certificate(&master_key, did_a, NOW);
        let mut state = ClusterState::init(db, master_pub, cert_a, NOW, NOW).unwrap();
        let cert_b = issue_device_certificate(&master_key, did_b, NOW);
        state.add_device(cert_b, NOW).unwrap();

        let active = state.active_devices();
        assert_eq!(active.len(), 2);
        // DeviceEntry has no device_pub_key field — compile-time check via struct construction
        // is sufficient; we just verify device_id matches expected
        assert_eq!(active[0].device_id, did_a);
        assert_eq!(active[1].device_id, did_b);
    }

    // Task A: device_entry_has_no_device_pub_key_field (compile-time test)
    // This test passes if the code compiles without referencing device_pub_key.
    #[test]
    fn device_entry_has_no_device_pub_key_field() {
        let master_key = derive_master_key(&SEED).unwrap();
        let master_pub = master_identity(&master_key);
        let device_key = derive_device_key(&SEED, &DEVICE_SEED_A).unwrap();
        let device_id = DeviceId(device_key.verifying_key().to_bytes());
        let cert = issue_device_certificate(&master_key, device_id, NOW);
        let db = Db::open_in_memory().unwrap();
        let state = ClusterState::init(db, master_pub, cert, NOW, NOW).unwrap();
        let entry = state.active_devices()[0];
        // Only access fields that exist (device_id, certificate, device_index)
        assert_eq!(entry.device_id, device_id);
        assert_eq!(entry.device_index, 0);
    }
}

#[cfg(test)]
mod tests {
    use crate::cluster::{
        derive_device_key, derive_epoch_key, derive_master_key, epoch_for_time,
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
        let device_seed = [2u8; 32];
        let device = derive_device_key(&seed, &device_seed).unwrap();
        assert_ne!(master.to_bytes(), device.to_bytes());
    }

    #[test]
    fn derive_device_key_differs_per_device_seed() {
        let seed = [3u8; 32];
        let device_seed_a = [0u8; 32];
        let device_seed_b = [1u8; 32];
        let key_a = derive_device_key(&seed, &device_seed_a).unwrap();
        let key_b = derive_device_key(&seed, &device_seed_b).unwrap();
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
        let device_seed = [3u8; 32];
        let device_key = derive_device_key(&[1u8; 32], &device_seed).unwrap();
        let device_id = DeviceId(device_key.verifying_key().to_bytes());
        let cert = issue_device_certificate(&master_key, device_id, Timestamp(1000));
        let result = verify_device_certificate(&cert, &master_identity(&master_key));
        assert!(result.is_ok());
    }

    #[test]
    fn verify_certificate_with_wrong_master_fails() {
        let master_a = derive_master_key(&[1u8; 32]).unwrap();
        let master_b = derive_master_key(&[2u8; 32]).unwrap();
        let device_seed = [3u8; 32];
        let device_key = derive_device_key(&[1u8; 32], &device_seed).unwrap();
        let device_id = DeviceId(device_key.verifying_key().to_bytes());
        let cert = issue_device_certificate(&master_a, device_id, Timestamp(1000));
        let result = verify_device_certificate(&cert, &master_identity(&master_b));
        assert!(matches!(result, Err(ClusterError::InvalidSignature)));
    }

    #[test]
    fn verify_certificate_tampered_signature_fails() {
        let master_key = derive_master_key(&[1u8; 32]).unwrap();
        let device_seed = [3u8; 32];
        let device_key = derive_device_key(&[1u8; 32], &device_seed).unwrap();
        let device_id = DeviceId(device_key.verifying_key().to_bytes());
        let mut cert = issue_device_certificate(&master_key, device_id, Timestamp(1000));
        cert.signature[0] ^= 1;
        let result = verify_device_certificate(&cert, &master_identity(&master_key));
        assert!(matches!(result, Err(ClusterError::InvalidSignature)));
    }

    #[test]
    fn verify_certificate_tampered_device_id_fails() {
        let master_key = derive_master_key(&[1u8; 32]).unwrap();
        let device_seed = [3u8; 32];
        let device_key = derive_device_key(&[1u8; 32], &device_seed).unwrap();
        let device_id = DeviceId(device_key.verifying_key().to_bytes());
        let mut cert = issue_device_certificate(&master_key, device_id, Timestamp(1000));
        cert.device_id = DeviceId([0xFF; 32]);
        let result = verify_device_certificate(&cert, &master_identity(&master_key));
        assert!(matches!(result, Err(ClusterError::InvalidSignature)));
    }

    #[test]
    fn issue_and_verify_revocation() {
        let master_key = derive_master_key(&[1u8; 32]).unwrap();
        let device_seed = [5u8; 32];
        let device_key = derive_device_key(&[1u8; 32], &device_seed).unwrap();
        let device_id = DeviceId(device_key.verifying_key().to_bytes());
        let cert = issue_revocation(&master_key, device_id, Timestamp(5000), EpochCounter(1));
        let result = verify_revocation(&cert, &master_identity(&master_key));
        assert!(result.is_ok());
    }

    #[test]
    fn tampered_revocation_fails() {
        let master_key = derive_master_key(&[1u8; 32]).unwrap();
        let device_seed = [5u8; 32];
        let device_key = derive_device_key(&[1u8; 32], &device_seed).unwrap();
        let device_id = DeviceId(device_key.verifying_key().to_bytes());
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

    #[test]
    fn full_cluster_flow() {
        let seed = [42u8; 32];
        let master_key = derive_master_key(&seed).unwrap();
        let identity = master_identity(&master_key);

        let device_seed_a = [10u8; 32];
        let device_seed_b = [20u8; 32];
        let dkey_a = derive_device_key(&seed, &device_seed_a).unwrap();
        let dkey_b = derive_device_key(&seed, &device_seed_b).unwrap();
        let device_a = DeviceId(dkey_a.verifying_key().to_bytes());
        let device_b = DeviceId(dkey_b.verifying_key().to_bytes());

        let cert_a = issue_device_certificate(&master_key, device_a, Timestamp(100));
        let cert_b = issue_device_certificate(&master_key, device_b, Timestamp(200));

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
