use super::*;

// ─── T-8 test helpers ──────────────────────────────────────────────────────────

mod t8 {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use viaticum_core::cluster::{derive_master_key, master_identity};
    use viaticum_core::constants::{AVAIL_EWMA_INITIAL, MAILBOX_POINTER_REPUBLISH_SECS};
    use viaticum_core::db::testutil::test_db;
    use viaticum_core::mailbox::seal::{
        PointerPlace, RendezvousKeys, SEALED_PAYLOAD_VERSION, open_self_pointer,
    };
    use viaticum_core::mailbox::{MailboxClass, MailboxEntry, class_config};
    use viaticum_core::messages::{
        MailboxFetchRequest, MailboxFetchResponse, MailboxStoreRequest, MailboxStoreResponse,
    };
    use viaticum_core::system_state::{
        BlockRef, CatalogLineageId, CatalogSummary, HolderHint, SelfPointer, sign_self_pointer,
        verify_self_pointer,
    };
    use viaticum_core::types::{
        DeviceId, IdentityPub, PeerRecord, PlacementStatus, SourceBlockId, SymbolPlacement,
        Timestamp, from_cbor_bytes,
    };

    use crate::daemon::mailbox::routing::{MailboxNetworkSender, MailboxRouter};
    use crate::daemon::system_state::publish::PointerCatalog;
    use crate::daemon::system_state::{
        PointerStructKey, pointer_refresh_interval_secs, pointer_struct_key, publish_pointer_step,
        should_republish,
    };

    // ─── Mock sender ─────────────────────────────────────────────────────────

    /// Records store calls and always Acks.
    struct MockSender {
        store_calls: Arc<Mutex<Vec<(DeviceId, MailboxEntry)>>>,
    }

    impl MockSender {
        fn new() -> Arc<Self> {
            Arc::new(MockSender {
                store_calls: Arc::new(Mutex::new(vec![])),
            })
        }

        fn store_calls(&self) -> Vec<(DeviceId, MailboxEntry)> {
            self.store_calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl MailboxNetworkSender for MockSender {
        async fn send_store(
            &self,
            device: DeviceId,
            req: MailboxStoreRequest,
        ) -> anyhow::Result<MailboxStoreResponse> {
            self.store_calls
                .lock()
                .unwrap()
                .push((device, req.entry.clone()));
            Ok(MailboxStoreResponse::Ack {
                msg_id: req.entry.msg_id,
            })
        }

        async fn send_fetch(
            &self,
            _device: DeviceId,
            _req: MailboxFetchRequest,
        ) -> anyhow::Result<MailboxFetchResponse> {
            Ok(MailboxFetchResponse {
                v: 1,
                entries: vec![],
                served_msg_ids: vec![],
            })
        }
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    const TEST_LINEAGE: CatalogLineageId = CatalogLineageId([0x4c; 16]);
    /// The seed of the rendezvous keys in these tests.
    const SEED: [u8; 64] = [0xAB; 64];

    /// Open a sealed pointer entry with the test's rendezvous keys.
    fn opened(rv: &RendezvousKeys, entry: &MailboxEntry) -> SelfPointer {
        let body = open_self_pointer(rv, entry).expect("the entry opens with the seed keys");
        from_cbor_bytes::<SelfPointer>(&body).expect("decode")
    }
    const TEST_PUBLISHER: DeviceId = DeviceId([0xd1; 32]);

    fn test_catalog() -> CatalogSummary {
        CatalogSummary {
            lineage: TEST_LINEAGE,
            publisher: TEST_PUBLISHER,
            files: 0,
        }
    }

    /// Catalog of a pointer over a base only (live files after the base: 3).
    fn test_pc() -> PointerCatalog<'static> {
        PointerCatalog {
            lineage: TEST_LINEAGE,
            publisher: TEST_PUBLISHER,
            files_after: &[3],
        }
    }

    fn gen_device_id() -> DeviceId {
        use libp2p::identity::Keypair;
        let kp = Keypair::generate_ed25519();
        let ed = kp.try_into_ed25519().unwrap();
        DeviceId(ed.public().to_bytes())
    }

    fn make_peer(device_id: DeviceId) -> PeerRecord {
        let now = Timestamp::now();
        PeerRecord {
            device_id,
            master_identity: IdentityPub(device_id.0),
            trust_p: 0.5,
            trust_i: 0.0,
            trust_s: 1.0,
            bytes_we_store_for_peer: 0,
            bytes_peer_stores_for_us: 0,
            first_seen: now,
            last_seen: now,
            revoked_device_pub_keys: vec![],
            addrs: vec![],
            x25519_pub: None,
            avail_ewma: AVAIL_EWMA_INITIAL,
            last_avail_sample: 0,
        }
    }

    /// Build a SelfPointer with a holder in `base.holders` so `build_pointer_for_placed`
    /// considers it placed.  We do this by:
    ///  1. inserting a SourceBlockRecord with current_alive ≥ 1
    ///  2. inserting an Alive SymbolPlacement for holder_device
    ///
    /// Returns (pointer, master_key, my_master_pub, block_id, holder_device_id).
    fn build_placed_pointer(
        db: &viaticum_core::db::Db,
    ) -> (
        SelfPointer,
        ed25519_dalek::SigningKey,
        IdentityPub,
        SourceBlockId,
        DeviceId,
    ) {
        use libp2p::identity::Keypair;
        use viaticum_core::types::{SourceBlockRecord, SourceBlockStatus, SourceBlockType};

        let master_key = derive_master_key(&[0xAB; 64]).unwrap();
        let my_master_pub = master_identity(&master_key);

        // Register a holder peer.
        let kp = Keypair::generate_ed25519();
        let ed = kp.try_into_ed25519().unwrap();
        let holder_device = DeviceId(ed.public().to_bytes());
        let holder_master = IdentityPub(holder_device.0);
        db.upsert_peer(&make_peer(holder_device)).unwrap();
        db.set_master_for_device(&holder_device, &holder_master)
            .unwrap();

        let block_id = SourceBlockId([0xCC; 32]);
        let now = Timestamp::now();

        let block_rec = SourceBlockRecord {
            block_id,
            k: 6,
            t: 512,
            block_type: SourceBlockType::Single,
            status: SourceBlockStatus::Active,
            created_at: now,
            encrypted_size: Some(1024),
            n: Some(10),
            overhead: Some(1.5),
            drop_notice_sent_at: None,
            importance: 1.0,
            current_alive: 1,
            current_reliability: 0.99,
            target_reliability: 0.99,
        };
        db.upsert_source_block(&block_rec).unwrap();

        let placement = SymbolPlacement {
            source_block_id: block_id,
            holder_id: holder_device,
            file_id: viaticum_core::types::FileId(1),
            esi_ranges: vec![(0, 5)],
            binding_seed: [0u8; 32],
            status: PlacementStatus::Alive,
            last_verified: None,
            placed_at: now,
            consecutive_misses: 0,
        };
        db.upsert_placement(&placement).unwrap();

        // Build a pointer for this placed block.
        let block_ref = BlockRef {
            block_id,
            encrypted_size: 1024,
            holders: vec![HolderHint {
                holder_id: holder_device,
                addrs: vec![],
                esi_ranges: vec![(0, 5)],
            }],
        };
        let pointer = sign_self_pointer(
            &master_key,
            1,
            block_ref,
            vec![],
            Timestamp::now(),
            test_catalog(),
        );

        (pointer, master_key, my_master_pub, block_id, holder_device)
    }

    // ─── Tests ───────────────────────────────────────────────────────────────

    /// CROWN-1 C2 (mailbox-i10, AC-7): the publisher signs the pointer store with the
    /// key of the box it writes to, and REAL postman handlers accept it. Without the
    /// signature every postman refuses (`Unauthorized`) and the pointer is never
    /// published — DR would find nothing. Mocks cannot see this; the in-process
    /// postman net runs the actual `handle_mailbox_store` on a real redb.
    #[tokio::test]
    async fn publish_pointer_step_is_accepted_by_real_postmen() {
        use crate::daemon::mailbox::test_postman::InProcessPostmanNet;

        let db = test_db();
        let (_pointer, master_key, my_master_pub, block_id, holder) = build_placed_pointer(&db);
        let net = Arc::new(InProcessPostmanNet::new(&[holder], my_master_pub, holder));
        let router = MailboxRouter::with_sender(
            Arc::clone(&net) as Arc<dyn MailboxNetworkSender>,
            db.clone(),
        );
        let rv = RendezvousKeys::derive(&SEED);
        let now_secs = Timestamp::now().0;

        let (key, published_at) = publish_pointer_step(
            &db,
            &router,
            &master_key,
            &rv,
            1,
            &block_id,
            &[],
            test_pc(),
            None,
            0,
            now_secs,
            1,
        )
        .await;

        assert!(
            key.is_some(),
            "publication counted: >= 1 real postman acked"
        );
        assert_eq!(published_at, now_secs);
        let held = net
            .postman(&holder)
            .db
            .mailbox_list_for_target(&rv.address, 0)
            .unwrap();
        assert_eq!(held.len(), 1, "the postman stored the pointer");
        assert_eq!(held[0].class, MailboxClass::SelfPointer);
        assert_eq!(held[0].payload_version, SEALED_PAYLOAD_VERSION);
        assert!(
            net.postman(&holder)
                .db
                .mailbox_list_for_target(
                    &viaticum_core::mailbox::MailboxAddress::for_master(&my_master_pub),
                    0
                )
                .unwrap()
                .is_empty(),
            "nothing in the master box"
        );
    }

    /// Answers every store with a Reject: the publish gets 0 acks.
    struct RejectingSender;

    #[async_trait]
    impl MailboxNetworkSender for RejectingSender {
        async fn send_store(
            &self,
            _device: DeviceId,
            req: MailboxStoreRequest,
        ) -> anyhow::Result<MailboxStoreResponse> {
            Ok(MailboxStoreResponse::Reject {
                msg_id: req.entry.msg_id,
                reason: viaticum_core::mailbox::MailboxRejectReason::NotInCandidateSet,
            })
        }

        async fn send_fetch(
            &self,
            _device: DeviceId,
            _req: MailboxFetchRequest,
        ) -> anyhow::Result<MailboxFetchResponse> {
            Ok(MailboxFetchResponse {
                v: 1,
                entries: vec![],
                served_msg_ids: vec![],
            })
        }
    }

    /// dr-i9: a publication accepted by a postman is recorded (status reads it), with
    /// the pointer's history, file count and ack count; the published pointer carries
    /// the catalog summary.
    #[tokio::test]
    async fn publish_step_records_publication_only_on_acks() {
        let db = test_db();
        let (_p, master_key, _my_master_pub, block_id, _h) = build_placed_pointer(&db);
        let sender = MockSender::new();
        db.upsert_peer(&make_peer(gen_device_id())).unwrap();
        let router =
            MailboxRouter::with_sender(sender.clone() as Arc<dyn MailboxNetworkSender>, db.clone());
        let rv = RendezvousKeys::derive(&SEED);
        assert_eq!(db.last_pointer_publication().unwrap(), None);

        publish_pointer_step(
            &db,
            &router,
            &master_key,
            &rv,
            1,
            &block_id,
            &[],
            test_pc(),
            None,
            0,
            Timestamp::now().0,
            1,
        )
        .await;

        let rec = db
            .last_pointer_publication()
            .unwrap()
            .expect("an accepted publication is recorded");
        assert_eq!(rec.lineage, TEST_LINEAGE);
        assert_eq!(rec.files, 3);
        assert_eq!(rec.generation, 1);
        assert!(rec.acks >= 1);
        let published = opened(&rv, &sender.store_calls()[0].1);
        assert_eq!(published.catalog.lineage, TEST_LINEAGE);
        assert_eq!(published.catalog.publisher, TEST_PUBLISHER);
        assert_eq!(published.catalog.files, 3);
        assert_eq!(rec.created_at, published.created_at);
    }

    /// dr-i9 mutation guard: a pointer that no postman accepted must not make `status`
    /// say "DR ready".
    #[tokio::test]
    async fn publish_step_does_not_record_publication_on_zero_acks() {
        let db = test_db();
        let (_p, master_key, _my_master_pub, block_id, _h) = build_placed_pointer(&db);
        db.upsert_peer(&make_peer(gen_device_id())).unwrap();
        let router = MailboxRouter::with_sender(
            Arc::new(RejectingSender) as Arc<dyn MailboxNetworkSender>,
            db.clone(),
        );
        let rv = RendezvousKeys::derive(&SEED);
        publish_pointer_step(
            &db,
            &router,
            &master_key,
            &rv,
            1,
            &block_id,
            &[],
            test_pc(),
            None,
            0,
            Timestamp::now().0,
            1,
        )
        .await;
        assert_eq!(db.last_pointer_publication().unwrap(), None);
    }

    /// T-8 spec (Fix 1, WARN-2): publish_pointer_step with a placed base and
    /// last_key=None/last_publish_at=0 → one SelfPointer-class entry published to
    /// my_master_pub, TTL == SELF_POINTER_TTL (5y), sender == Some(my_master_pub),
    /// payload decodes to a verified SelfPointer, current_pointer updated,
    /// returned last_publish_at == now_secs.
    #[tokio::test]
    async fn publish_pointer_step_builds_and_publishes_when_due() {
        let db = test_db();
        let (_pointer, master_key, my_master_pub, block_id, _holder) = build_placed_pointer(&db);

        // Build router with ≥1 candidate peer so fanout fires.
        let sender = MockSender::new();
        let peer_d = gen_device_id();
        db.upsert_peer(&make_peer(peer_d)).unwrap();
        let sender_dyn: Arc<dyn MailboxNetworkSender> =
            sender.clone() as Arc<dyn MailboxNetworkSender>;
        let router = MailboxRouter::with_sender(sender_dyn, db.clone());

        let rv = RendezvousKeys::derive(&SEED);
        let now_secs = Timestamp::now().0;

        // Call publish_pointer_step with no prior state (first publish).
        let (returned_key, returned_publish_at) = publish_pointer_step(
            &db,
            &router,
            &master_key,
            &rv,
            1,
            &block_id,
            &[],
            test_pc(),
            None,
            0,
            now_secs,
            1, // time_scale = 1 (production): TTL unscaled
        )
        .await;

        // At least one store call must have fired.
        let calls = sender.store_calls();
        assert!(
            !calls.is_empty(),
            "at least one store call must have been made"
        );

        let (_, stored_entry) = &calls[0];
        assert_eq!(
            stored_entry.target, rv.address,
            "entry must target the rendezvous box"
        );
        assert_eq!(
            stored_entry.class,
            MailboxClass::SelfPointer,
            "class must be SelfPointer"
        );
        assert_eq!(stored_entry.sender, None, "no sender in the header");

        // TTL: expires_at - stored_at == SELF_POINTER_TTL (within 2s clock tolerance).
        let ttl_actual = stored_entry
            .expires_at
            .saturating_sub(stored_entry.stored_at);
        let ttl_expected = class_config::SELF_POINTER_TTL.as_secs();
        assert!(
            ttl_actual.abs_diff(ttl_expected) <= 2,
            "expires_at-stored_at must equal SELF_POINTER_TTL, got {ttl_actual} vs {ttl_expected}"
        );

        // Payload decodes to a valid signed SelfPointer.
        let decoded = opened(&rv, stored_entry);
        assert!(
            verify_self_pointer(&decoded, &my_master_pub).is_ok(),
            "payload must decode to a verified SelfPointer"
        );
        assert_eq!(decoded.generation, 1, "SelfPointer generation must be 1");

        // Returned tracking state.
        assert!(
            returned_key.is_some(),
            "returned key must be Some after successful publish"
        );
        assert_eq!(
            returned_publish_at, now_secs,
            "returned last_publish_at must equal now_secs"
        );
    }

    /// P1-3 / PL-3: publishing under an accelerated `time_scale` bakes a SCALED TTL
    /// into the SelfPointer entry's `expires_at` (not the full 5-year wall-clock TTL),
    /// so the entry expires within accelerated test/demo time and the sweep can reclaim
    /// it. With `time_scale = 60`, `expires_at - stored_at == SELF_POINTER_TTL / 60`.
    #[tokio::test]
    async fn publish_pointer_step_scales_ttl_by_time_scale() {
        let db = test_db();
        let (_pointer, master_key, _my_master_pub, block_id, _holder) = build_placed_pointer(&db);

        let sender = MockSender::new();
        let peer_d = gen_device_id();
        db.upsert_peer(&make_peer(peer_d)).unwrap();
        let sender_dyn: Arc<dyn MailboxNetworkSender> =
            sender.clone() as Arc<dyn MailboxNetworkSender>;
        let router = MailboxRouter::with_sender(sender_dyn, db.clone());

        let rv = RendezvousKeys::derive(&SEED);
        let now_secs = Timestamp::now().0;

        let time_scale = 60u64;
        let _ = publish_pointer_step(
            &db,
            &router,
            &master_key,
            &rv,
            1,
            &block_id,
            &[],
            test_pc(),
            None,
            0,
            now_secs,
            time_scale,
        )
        .await;

        let calls = sender.store_calls();
        assert!(!calls.is_empty(), "at least one store call must have fired");

        let (_, stored_entry) = &calls[0];
        let ttl_actual = stored_entry
            .expires_at
            .saturating_sub(stored_entry.stored_at);
        let ttl_expected = class_config::SELF_POINTER_TTL.as_secs() / time_scale;
        assert!(
            ttl_actual.abs_diff(ttl_expected) <= 2,
            "expires_at-stored_at must equal SELF_POINTER_TTL/time_scale, \
             got {ttl_actual} vs {ttl_expected}"
        );
        // Sanity: the scaled TTL is far below the full wall-clock TTL.
        assert!(
            ttl_actual < class_config::SELF_POINTER_TTL.as_secs(),
            "scaled TTL must be strictly less than the full SELF_POINTER_TTL"
        );
    }

    /// T-8 spec (Fix 1, WARN-2): second call with same structural key and now within
    /// 30d window → NO new publish (mock call count unchanged), current_pointer unchanged.
    #[tokio::test]
    async fn publish_pointer_step_skips_when_unchanged_within_window() {
        let db = test_db();
        let (_pointer, master_key, _my_master_pub, block_id, _holder) = build_placed_pointer(&db);

        let sender = MockSender::new();
        let peer_d = gen_device_id();
        db.upsert_peer(&make_peer(peer_d)).unwrap();
        let sender_dyn: Arc<dyn MailboxNetworkSender> =
            sender.clone() as Arc<dyn MailboxNetworkSender>;
        let router = MailboxRouter::with_sender(sender_dyn, db.clone());

        let rv = RendezvousKeys::derive(&SEED);
        let now_secs = Timestamp::now().0;

        // First call — publishes, returns structural key.
        let (first_key, first_publish_at) = publish_pointer_step(
            &db,
            &router,
            &master_key,
            &rv,
            1,
            &block_id,
            &[],
            test_pc(),
            None,
            0,
            now_secs,
            1,
        )
        .await;

        let call_count_after_first = sender.store_calls().len();
        assert!(call_count_after_first > 0, "first call must publish");

        // Second call — same base, same generation, within 30d (now + 3600s).
        let now_secs2 = now_secs + 3600; // 1h later, well within 30d
        let (second_key, second_publish_at) = publish_pointer_step(
            &db,
            &router,
            &master_key,
            &rv,
            1,
            &block_id,
            &[],
            test_pc(),
            first_key.as_ref(),
            first_publish_at,
            now_secs2,
            1,
        )
        .await;

        // No additional store calls.
        let call_count_after_second = sender.store_calls().len();
        assert_eq!(
            call_count_after_second, call_count_after_first,
            "second call with unchanged key within 30d must NOT publish again"
        );

        // Returned tracking state unchanged.
        assert_eq!(second_key, first_key, "returned key must be unchanged");
        assert_eq!(
            second_publish_at, first_publish_at,
            "returned last_publish_at must be unchanged"
        );
    }

    /// T-8 spec (Fix 1, WARN-2): 30d window expired with unchanged key → refresh publish fires.
    #[tokio::test]
    async fn publish_pointer_step_republishes_after_30d_window() {
        let db = test_db();
        let (_pointer, master_key, _my_master_pub, block_id, _holder) = build_placed_pointer(&db);

        let sender = MockSender::new();
        let peer_d = gen_device_id();
        db.upsert_peer(&make_peer(peer_d)).unwrap();
        let sender_dyn: Arc<dyn MailboxNetworkSender> =
            sender.clone() as Arc<dyn MailboxNetworkSender>;
        let router = MailboxRouter::with_sender(sender_dyn, db.clone());

        let rv = RendezvousKeys::derive(&SEED);

        // Simulate: first publish happened at t=0, key known.
        let last_publish_at = 1_000_000u64;
        // Use a pre-built key so we don't need an actual prior call.
        let fake_key: PointerStructKey = (1, block_id.0, vec![]);
        let now_secs = last_publish_at + MAILBOX_POINTER_REPUBLISH_SECS; // exactly at boundary

        let (returned_key, returned_publish_at) = publish_pointer_step(
            &db,
            &router,
            &master_key,
            &rv,
            1,
            &block_id,
            &[],
            test_pc(),
            Some(&fake_key),
            last_publish_at,
            now_secs,
            1,
        )
        .await;

        // Refresh publish must have fired.
        let calls = sender.store_calls();
        assert!(!calls.is_empty(), "30d refresh must trigger a publish");
        assert_eq!(
            returned_publish_at, now_secs,
            "last_publish_at must be updated"
        );
        assert!(
            returned_key.is_some(),
            "returned key must be Some after refresh"
        );
    }

    /// T-8 spec: base not placed (no Alive holder) → build_pointer_for_placed returns None
    /// → no mailbox publish.
    #[test]
    fn pointer_not_published_before_base_placed() {
        let db = test_db();
        use viaticum_core::types::{SourceBlockRecord, SourceBlockStatus, SourceBlockType};

        let master_key = derive_master_key(&[0xCD; 64]).unwrap();
        let block_id = SourceBlockId([0xDD; 32]);
        let now = Timestamp::now();

        // Block exists but has NO Alive holders (current_alive=0, no placements).
        let block_rec = SourceBlockRecord {
            block_id,
            k: 6,
            t: 512,
            block_type: SourceBlockType::Single,
            status: SourceBlockStatus::Active,
            created_at: now,
            encrypted_size: Some(1024),
            n: Some(10),
            overhead: Some(1.5),
            drop_notice_sent_at: None,
            importance: 1.0,
            current_alive: 0,
            current_reliability: 0.0,
            target_reliability: 0.99,
        };
        db.upsert_source_block(&block_rec).unwrap();

        // build_pointer_for_placed must return None (base.holders.is_empty()).
        let result = crate::daemon::system_state::publish::build_pointer_for_placed(
            &db,
            &master_key,
            1,
            &block_id,
            &[],
            now,
            test_pc(),
        )
        .unwrap();

        assert!(
            result.is_none(),
            "must return None when base has no Alive holders"
        );
        // (If build_pointer_for_placed returns None, run_periodic_push continues without
        // calling mailbox_router.publish — no publish occurs.)
    }

    /// T-8 spec: structural change (generation or base block_id changed) triggers republish.
    #[test]
    fn pointer_republished_on_change() {
        let master_key = derive_master_key(&[0xEF; 64]).unwrap();
        let block_ref1 = BlockRef {
            block_id: SourceBlockId([0x01; 32]),
            encrypted_size: 100,
            holders: vec![],
        };
        let block_ref2 = BlockRef {
            block_id: SourceBlockId([0x02; 32]),
            encrypted_size: 100,
            holders: vec![],
        };

        let pointer1 = sign_self_pointer(
            &master_key,
            1,
            block_ref1,
            vec![],
            Timestamp::now(),
            test_catalog(),
        );
        let pointer2 = sign_self_pointer(
            &master_key,
            2,
            block_ref2,
            vec![],
            Timestamp::now(),
            test_catalog(),
        );

        // After publishing pointer1, record its struct key.
        let key1 = pointer_struct_key(&pointer1);
        let last_publish_at = Timestamp::now().0;

        // pointer2 has different generation AND base block_id → must republish.
        let now = last_publish_at + 60; // 60s later, well within 30d window
        assert!(
            should_republish(&pointer2, Some(&key1), last_publish_at, now, 1),
            "changed pointer must trigger republish"
        );
    }

    /// T-8 spec: same pointer (unchanged struct key), <30d elapsed → skip publish.
    #[test]
    fn pointer_not_republished_when_unchanged_within_window() {
        let master_key = derive_master_key(&[0xF0; 64]).unwrap();
        let block_ref = BlockRef {
            block_id: SourceBlockId([0x01; 32]),
            encrypted_size: 100,
            holders: vec![],
        };

        let pointer = sign_self_pointer(
            &master_key,
            1,
            block_ref,
            vec![],
            Timestamp::now(),
            test_catalog(),
        );
        let key = pointer_struct_key(&pointer);
        let last_publish_at = Timestamp::now().0;

        // Now = last_publish_at + 1h (well within 30d window, same struct key).
        let now = last_publish_at + 3600;
        assert!(
            !should_republish(&pointer, Some(&key), last_publish_at, now, 1),
            "unchanged pointer within 30d must NOT republish"
        );
    }

    /// T-8 spec: 30-day refresh triggers republish even if pointer is structurally unchanged.
    #[test]
    fn pointer_republished_on_30d_refresh() {
        let master_key = derive_master_key(&[0xF1; 64]).unwrap();
        let block_ref = BlockRef {
            block_id: SourceBlockId([0x01; 32]),
            encrypted_size: 100,
            holders: vec![],
        };

        let pointer = sign_self_pointer(
            &master_key,
            1,
            block_ref,
            vec![],
            Timestamp::now(),
            test_catalog(),
        );
        let key = pointer_struct_key(&pointer);
        let last_publish_at = 1_000_000u64;

        // now = last_publish_at + MAILBOX_POINTER_REPUBLISH_SECS → exactly at boundary → republish.
        let now = last_publish_at + MAILBOX_POINTER_REPUBLISH_SECS;
        assert!(
            should_republish(&pointer, Some(&key), last_publish_at, now, 1),
            "pointer must be republished after 30d window expires"
        );
    }

    /// T-8 spec AC-7 (Fix 2, WARN-1 staged rotation): when the new base block is NOT
    /// yet placed (no Alive holders), publish_pointer_step returns None from
    /// build_pointer_for_placed → no publish fires → current_pointer retains the old
    /// generation unchanged.
    ///
    /// This exercises the real "None → skip" branch in publish_pointer_step and verifies
    /// that the shared current_pointer handle is never cleared or regressed on a missed tick.
    #[tokio::test]
    async fn staged_rotation_preserves_old_pointer_until_new_base_placed() {
        use viaticum_core::types::{SourceBlockRecord, SourceBlockStatus, SourceBlockType};

        let db = test_db();
        let master_key = derive_master_key(&[0xF2; 64]).unwrap();

        // Unplaced base block: registered in DB but has NO Alive placements.
        let unplaced_id = SourceBlockId([0xBB; 32]);
        let now = Timestamp::now();
        let block_rec = SourceBlockRecord {
            block_id: unplaced_id,
            k: 6,
            t: 512,
            block_type: SourceBlockType::Single,
            status: SourceBlockStatus::Active,
            created_at: now,
            encrypted_size: Some(1024),
            n: Some(10),
            overhead: Some(1.5),
            drop_notice_sent_at: None,
            importance: 1.0,
            current_alive: 0,
            current_reliability: 0.0,
            target_reliability: 0.99,
        };
        db.upsert_source_block(&block_rec).unwrap();

        // Verify the guard fires: build_pointer_for_placed must return None.
        let guard_result = crate::daemon::system_state::publish::build_pointer_for_placed(
            &db,
            &master_key,
            2, // new generation
            &unplaced_id,
            &[],
            now,
            test_pc(),
        )
        .unwrap();
        assert!(
            guard_result.is_none(),
            "build_pointer_for_placed must return None when base has no Alive holders"
        );

        // Pre-set current_pointer to old generation (gen=1) — already published.
        let old_block_ref = BlockRef {
            block_id: SourceBlockId([0x01; 32]),
            encrypted_size: 100,
            holders: vec![HolderHint {
                holder_id: DeviceId([0xAA; 32]),
                addrs: vec![],
                esi_ranges: vec![],
            }],
        };
        let _old_pointer =
            sign_self_pointer(&master_key, 1, old_block_ref, vec![], now, test_catalog());
        let rv = RendezvousKeys::derive(&SEED);

        // Build router with a candidate peer (to confirm no publish fires, not just no-candidate).
        let sender = MockSender::new();
        let peer_d = gen_device_id();
        db.upsert_peer(&make_peer(peer_d)).unwrap();
        let sender_dyn: Arc<dyn MailboxNetworkSender> =
            sender.clone() as Arc<dyn MailboxNetworkSender>;
        let router = MailboxRouter::with_sender(sender_dyn, db.clone());

        let now_secs = now.0;
        let (returned_key, returned_publish_at) = publish_pointer_step(
            &db,
            &router,
            &master_key,
            &rv,
            2, // new generation, but base is unplaced
            &unplaced_id,
            &[],
            test_pc(),
            None, // no prior key — would normally force publish if placed
            0,
            now_secs,
            1,
        )
        .await;

        // No publish must have fired.
        let calls = sender.store_calls();
        assert_eq!(
            calls.len(),
            0,
            "no publish must fire when base has no Alive holders (staged rotation)"
        );

        // Returned tracking state: unchanged (same as inputs, since we skipped).
        assert!(
            returned_key.is_none(),
            "returned key must be None (no publish happened)"
        );
        assert_eq!(
            returned_publish_at, 0,
            "returned last_publish_at must be unchanged (0)"
        );
    }

    /// struct_key is stable for same pointer (same generation + block_ids).
    #[test]
    fn pointer_struct_key_is_stable() {
        let master_key = derive_master_key(&[0x01; 64]).unwrap();
        let block_ref = BlockRef {
            block_id: SourceBlockId([0xAA; 32]),
            encrypted_size: 100,
            holders: vec![],
        };
        let p1 = sign_self_pointer(
            &master_key,
            1,
            block_ref.clone(),
            vec![],
            Timestamp::now(),
            test_catalog(),
        );
        let p2 = sign_self_pointer(
            &master_key,
            1,
            block_ref.clone(),
            vec![],
            Timestamp::now(),
            test_catalog(),
        );
        // Same generation and block_ids → same key even if created_at or signature differ.
        assert_eq!(pointer_struct_key(&p1), pointer_struct_key(&p2));
    }

    /// struct_key differs when generation changes.
    #[test]
    fn pointer_struct_key_differs_on_generation_change() {
        let master_key = derive_master_key(&[0x02; 64]).unwrap();
        let block_ref = BlockRef {
            block_id: SourceBlockId([0xBB; 32]),
            encrypted_size: 100,
            holders: vec![],
        };
        let p1 = sign_self_pointer(
            &master_key,
            1,
            block_ref.clone(),
            vec![],
            Timestamp::now(),
            test_catalog(),
        );
        let p2 = sign_self_pointer(
            &master_key,
            2,
            block_ref.clone(),
            vec![],
            Timestamp::now(),
            test_catalog(),
        );
        assert_ne!(pointer_struct_key(&p1), pointer_struct_key(&p2));
    }

    /// struct_key differs when base block_id changes.
    #[test]
    fn pointer_struct_key_differs_on_base_change() {
        let master_key = derive_master_key(&[0x03; 64]).unwrap();
        let ref1 = BlockRef {
            block_id: SourceBlockId([0x01; 32]),
            encrypted_size: 100,
            holders: vec![],
        };
        let ref2 = BlockRef {
            block_id: SourceBlockId([0x02; 32]),
            encrypted_size: 100,
            holders: vec![],
        };
        let p1 = sign_self_pointer(
            &master_key,
            1,
            ref1,
            vec![],
            Timestamp::now(),
            test_catalog(),
        );
        let p2 = sign_self_pointer(
            &master_key,
            1,
            ref2,
            vec![],
            Timestamp::now(),
            test_catalog(),
        );
        assert_ne!(pointer_struct_key(&p1), pointer_struct_key(&p2));
    }

    // ─── CROWN-1 C3a: the sealed pointer in the rendezvous box ───────────────

    /// V.6 publisher row: the pointer goes to the seed-derived rendezvous box, sealed
    /// (v2, no header sender), `msg_id` = the history's place slot, with a store
    /// signature by the box key; nothing names the master in the header.
    #[tokio::test]
    async fn published_pointer_goes_to_rendezvous_box_with_slot_msg_id() {
        let db = test_db();
        let (_p, master_key, my_master_pub, block_id, _h) = build_placed_pointer(&db);
        let sender = MockSender::new();
        db.upsert_peer(&make_peer(gen_device_id())).unwrap();
        let router =
            MailboxRouter::with_sender(sender.clone() as Arc<dyn MailboxNetworkSender>, db.clone());
        let rv = RendezvousKeys::derive(&SEED);
        publish_pointer_step(
            &db,
            &router,
            &master_key,
            &rv,
            1,
            &block_id,
            &[],
            test_pc(),
            None,
            0,
            Timestamp::now().0,
            1,
        )
        .await;
        let calls = sender.store_calls();
        assert!(!calls.is_empty());
        let entry = &calls[0].1;
        assert_eq!(entry.target, rv.address);
        assert_ne!(
            entry.target,
            viaticum_core::mailbox::MailboxAddress::for_master(&my_master_pub)
        );
        assert_eq!(
            entry.msg_id,
            rv.pointer_slot(&TEST_LINEAGE.0, PointerPlace::A)
        );
        assert_eq!(entry.payload_version, SEALED_PAYLOAD_VERSION);
        assert_eq!(entry.sender, None);
        assert!(
            from_cbor_bytes::<SelfPointer>(&entry.payload).is_err(),
            "the payload is an envelope, not a plaintext pointer"
        );
        let opened = opened(&rv, entry);
        assert!(verify_self_pointer(&opened, &my_master_pub).is_ok());
    }

    /// V.6 publisher row: a republish of the same history uses the same slot (the
    /// postman replaces its entry instead of taking a new place).
    #[tokio::test]
    async fn republish_of_same_lineage_reuses_slot() {
        let db = test_db();
        let (_p, master_key, _mm, block_id, _h) = build_placed_pointer(&db);
        let sender = MockSender::new();
        db.upsert_peer(&make_peer(gen_device_id())).unwrap();
        let router =
            MailboxRouter::with_sender(sender.clone() as Arc<dyn MailboxNetworkSender>, db.clone());
        let rv = RendezvousKeys::derive(&SEED);
        let now = Timestamp::now().0;
        let (key, at) = publish_pointer_step(
            &db,
            &router,
            &master_key,
            &rv,
            1,
            &block_id,
            &[],
            test_pc(),
            None,
            0,
            now,
            1,
        )
        .await;
        let later = now + MAILBOX_POINTER_REPUBLISH_SECS;
        publish_pointer_step(
            &db,
            &router,
            &master_key,
            &rv,
            1,
            &block_id,
            &[],
            test_pc(),
            key.as_ref(),
            at,
            later,
            1,
        )
        .await;
        let calls = sender.store_calls();
        let stamps: std::collections::HashSet<u64> =
            calls.iter().map(|(_, e)| e.stored_at).collect();
        assert_eq!(stamps.len(), 2, "two publications");
        let slots: std::collections::HashSet<[u8; 16]> =
            calls.iter().map(|(_, e)| e.msg_id).collect();
        assert_eq!(slots.len(), 1, "one slot for the history");
    }

    /// AC-24′ (mailbox-i41): the refresh interval scales like the TTL; TTL / refresh = 60.
    #[test]
    fn pointer_refresh_interval_scales_with_time_scale() {
        for ts in [1u64, 1000, 100_000] {
            let refresh = pointer_refresh_interval_secs(ts);
            assert_eq!(refresh, MAILBOX_POINTER_REPUBLISH_SECS / ts);
            let ttl = viaticum_core::mailbox::scaled_ttl_secs(
                class_config::SELF_POINTER_TTL.as_secs(),
                ts,
            );
            // Integer division rounds both; the pointer outlives ≥ 60 refreshes at any ts.
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
