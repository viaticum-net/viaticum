// Phase 1 gate integration test.
// Verifies cross-module correctness — not just unit behaviour in isolation.

use viaticum_core::{
    budget::{estimate_budget, select_backup_batch},
    cluster::{
        EpochCounter, derive_device_key, derive_epoch_key, derive_master_key,
        issue_device_certificate, issue_revocation, master_identity, next_epoch,
        verify_device_certificate, verify_revocation,
    },
    db::testutil::test_db,
    erasure::{ErasureEncoder, RaptorQEncoder},
    pos::{VerifyOutcome, compute_chain_hash, outcome_from_verify, verify_hash_response},
    trust::{PosOutcome, TrustEngine},
    types::{
        DeviceId, ErasureParams, Event, EventEntry, FileId, FileRecord, FileVersion, IdentityPub,
        LocalState, PlacementStatus, SourceBlockId, SourceBlockRecord, SourceBlockStatus,
        SourceBlockType, SymbolPlacement, Timestamp,
    },
};

// ─── helpers ────────────────────────────────────────────────────────────────

fn test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

fn block_id(byte: u8) -> SourceBlockId {
    SourceBlockId([byte; 32])
}

fn peer_id(byte: u8) -> DeviceId {
    DeviceId([byte; 32])
}

fn device_seed(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn device_id(byte: u8) -> DeviceId {
    DeviceId([byte; 32])
}

fn seed(byte: u8) -> Vec<u8> {
    vec![byte; 64]
}

fn now() -> Timestamp {
    Timestamp(1_700_000_000)
}

// ─── 1. full_encode_decode_pipeline ─────────────────────────────────────────

#[test]
fn full_encode_decode_pipeline() {
    // One symbol of source data (65535 bytes).
    let source = test_data(65_535);
    let params = ErasureParams::compute(65_535, 0.7).unwrap();
    let bid = block_id(1);
    let holder = peer_id(1);
    let enc = RaptorQEncoder::new();

    // Encode k_eff bound symbols.
    let k_eff = params.k_eff;
    let bound = enc
        .encode(&source, &params, 0, k_eff, &bid, &holder)
        .expect("encode must succeed");
    assert_eq!(bound.len(), k_eff as usize);

    // Unbind all.
    let unbound: Vec<_> = bound
        .into_iter()
        .map(|s| enc.unbind(s, &bid, &holder))
        .collect();

    // Decode and verify.
    let decoded = enc.decode(&unbound, &params).expect("decode must succeed");
    assert_eq!(&decoded[..source.len()], source.as_slice());
}

// ─── 2. pos_hash_challenge_verify_roundtrip ─────────────────────────────────

#[test]
fn pos_hash_challenge_verify_roundtrip() {
    let source = test_data(65_535);
    let params = ErasureParams::compute(65_535, 0.5).unwrap();
    let bid = block_id(2);
    let holder = peer_id(2);
    let enc = RaptorQEncoder::new();

    // ESI ranges assigned to the holder: ESIs 0..4.
    let esi_ranges = vec![(0u32, 4u32)];
    let esis: Vec<u32> = (0..4).collect();

    // Owner side: encode all symbols and compute expected chain hash.
    let mut symbol_data: Vec<(u32, Vec<u8>)> = Vec::new();
    for &esi in &esis {
        let bound = enc
            .encode(&source, &params, esi, 1, &bid, &holder)
            .expect("encode must succeed");
        symbol_data.push((esi, bound[0].data.clone()));
    }
    let challenge_id = [0u8; 16];
    let refs: Vec<(u32, &[u8])> = symbol_data
        .iter()
        .map(|(e, d)| (*e, d.as_slice()))
        .collect();
    let expected_hash =
        compute_chain_hash(&challenge_id, &refs).expect("compute_chain_hash must succeed");

    // Holder side: reads same symbols and computes same chain hash.
    let holder_refs: Vec<(u32, &[u8])> = symbol_data
        .iter()
        .map(|(e, d)| (*e, d.as_slice()))
        .collect();
    let holder_hash =
        compute_chain_hash(&challenge_id, &holder_refs).expect("holder compute_chain_hash");

    // Verify.
    let first_esi = esi_ranges[0].0;
    let outcome = verify_hash_response(&holder_hash, &expected_hash, first_esi);
    assert_eq!(outcome, VerifyOutcome::Pass);

    // Unused but kept for completeness.
    let _ = esi_ranges;
}

// ─── 3. pos_hash_challenge_detect_corruption ────────────────────────────────

#[test]
fn pos_hash_challenge_detect_corruption() {
    let source = test_data(65_535);
    let params = ErasureParams::compute(65_535, 0.5).unwrap();
    let bid = block_id(3);
    let holder = peer_id(3);
    let enc = RaptorQEncoder::new();

    // ESI range: 0..4.
    let esis: Vec<u32> = (0..4).collect();
    let first_esi = esis[0];

    // Owner computes expected chain hash from correct symbol data.
    let mut symbol_data: Vec<(u32, Vec<u8>)> = Vec::new();
    for &esi in &esis {
        let bound = enc
            .encode(&source, &params, esi, 1, &bid, &holder)
            .expect("encode must succeed");
        symbol_data.push((esi, bound[0].data.clone()));
    }
    let challenge_id = [0u8; 16];
    let refs: Vec<(u32, &[u8])> = symbol_data
        .iter()
        .map(|(e, d)| (*e, d.as_slice()))
        .collect();
    let expected_hash =
        compute_chain_hash(&challenge_id, &refs).expect("compute expected chain hash");

    // Holder has corrupted data: all zeros for each symbol.
    let corrupt_symbol_data: Vec<(u32, Vec<u8>)> = esis
        .iter()
        .map(|&esi| (esi, vec![0u8; params.t as usize]))
        .collect();
    let corrupt_refs: Vec<(u32, &[u8])> = corrupt_symbol_data
        .iter()
        .map(|(e, d)| (*e, d.as_slice()))
        .collect();
    let corrupt_hash =
        compute_chain_hash(&challenge_id, &corrupt_refs).expect("compute corrupt chain hash");

    // Verify: hash mismatch → Fail.
    let outcome = verify_hash_response(&corrupt_hash, &expected_hash, first_esi);
    assert!(
        matches!(outcome, VerifyOutcome::Fail { esi } if esi == first_esi),
        "expected Fail{{esi: {first_esi}}}, got {outcome:?}"
    );
}

// ─── 4. trust_records_pos_results ───────────────────────────────────────────

#[test]
fn trust_records_pos_results() {
    let mut engine = TrustEngine::new();
    let peer = peer_id(4);
    let t0 = now();

    engine.upsert_peer_device(peer, IdentityPub([0u8; 32]), t0);

    // Initial score should be low (no history).
    let initial = engine.recalculate(&peer, t0, 1).expect("recalculate");
    let initial_combined = initial.combined;

    // Record 10 passing outcomes in week 1.
    for _ in 0..10 {
        engine
            .record_pos_result(
                peer,
                PosOutcome {
                    week_number: 1,
                    challenged: 1,
                    passed: 1,
                },
            )
            .expect("record_pos_result");
    }
    let after_pass = engine
        .recalculate(&peer, t0, 1)
        .expect("recalculate after pass");
    assert!(
        after_pass.combined > initial_combined,
        "trust must increase after passes: {} > {}",
        after_pass.combined,
        initial_combined
    );

    // Record 20 failing outcomes in week 2.
    for _ in 0..20 {
        engine
            .record_pos_result(
                peer,
                PosOutcome {
                    week_number: 2,
                    challenged: 1,
                    passed: 0,
                },
            )
            .expect("record_pos_result");
    }
    let after_fail = engine
        .recalculate(&peer, t0, 2)
        .expect("recalculate after fail");
    assert!(
        after_fail.combined < after_pass.combined,
        "trust must decrease after fails: {} < {}",
        after_fail.combined,
        after_pass.combined
    );
}

// ─── 5. db_stores_and_retrieves_full_records ────────────────────────────────

#[test]
fn db_stores_and_retrieves_full_records() {
    let db = test_db();
    let t = now();
    let fid = FileId(100);
    let bid = block_id(5);
    let holder = peer_id(5);

    // Insert FileRecord with a version.
    let file = FileRecord {
        file_id: fid,
        path: "/home/user/docs/report.pdf".to_string(),
        importance: 0.9,
        devices: vec![(device_id(1), LocalState::Present)],
        versions: vec![FileVersion {
            content_hash: [0xAB; 32],
            source_block_id: bid,
            k: 1,
            t: 65_535,
            created_at: t,
            backed_up_at: Some(t),
        }],
        first_seen: t,
        on_disk_confirmed: true,
    };
    db.upsert_file(&file).expect("upsert_file");

    let retrieved = db
        .get_file("/home/user/docs/report.pdf")
        .expect("get_file")
        .expect("must be present");
    assert_eq!(retrieved.file_id, fid);
    assert_eq!(retrieved.versions.len(), 1);
    assert_eq!(retrieved.versions[0].source_block_id, bid);

    // Insert SourceBlockRecord.
    let sbr = SourceBlockRecord {
        block_id: bid,
        k: 1,
        t: 65_535,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: t,
        encrypted_size: None,
        n: None,
        overhead: None,
        drop_notice_sent_at: None,
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
    };
    db.upsert_source_block(&sbr).expect("upsert_source_block");

    let retrieved_sb = db
        .get_source_block(&bid)
        .expect("get_source_block")
        .expect("must be present");
    assert_eq!(retrieved_sb.block_id, bid);

    // Insert SymbolPlacement.
    let placement = SymbolPlacement {
        source_block_id: bid,
        holder_id: holder,
        file_id: fid,
        esi_ranges: vec![(0, 3)],
        binding_seed: [0xCC; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: t,
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).expect("upsert_placement");

    // Verify hot cache updated.
    let hot = db.hot();
    let agg = hot
        .placements
        .get(&(bid, holder))
        .expect("placement must be in hot cache");
    assert_eq!(agg.symbol_count, 3);
    assert_eq!(agg.status, PlacementStatus::Alive);
    drop(hot);

    // List placements for block.
    let placements = db
        .list_placements_for_block(&bid)
        .expect("list_placements_for_block");
    assert_eq!(placements.len(), 1);
    assert_eq!(placements[0].holder_id, holder);
    assert_eq!(placements[0].symbol_count(), 3);

    // Cross-reference: list holders for file.
    let holders = db
        .list_holders_for_file(fid)
        .expect("list_holders_for_file");
    assert_eq!(holders.len(), 1);
    assert_eq!(holders[0], holder);
}

// ─── 6. cluster_key_hierarchy_end_to_end ────────────────────────────────────

#[test]
fn cluster_key_hierarchy_end_to_end() {
    let seed_bytes = seed(6);
    let t = now();

    // Derive master key.
    let master_key = derive_master_key(&seed_bytes).expect("derive_master_key");
    let identity = master_identity(&master_key);

    // Derive device key. device_id = pubkey of derived signing key.
    let dev_seed = device_seed(1);
    let device_key = derive_device_key(&seed_bytes, &dev_seed).expect("derive_device_key");
    let did = DeviceId(device_key.verifying_key().to_bytes());

    // Issue and verify device certificate.
    let cert = issue_device_certificate(&master_key, did, t);
    verify_device_certificate(&cert, &identity).expect("verify_device_certificate");

    // Issue and verify revocation.
    let new_epoch = EpochCounter(1);
    let rev = issue_revocation(&master_key, did, t, new_epoch);
    verify_revocation(&rev, &identity).expect("verify_revocation");
    assert_eq!(rev.new_epoch, new_epoch);

    // Derive epoch keys for epochs 0 and 1 — they must differ.
    let ek0 = derive_epoch_key(&seed_bytes, EpochCounter(0)).expect("derive epoch 0");
    let ek1 = derive_epoch_key(&seed_bytes, EpochCounter(1)).expect("derive epoch 1");
    assert_ne!(ek0.key_bytes, ek1.key_bytes, "epoch keys must differ");

    // next_epoch arithmetic.
    assert_eq!(next_epoch(EpochCounter(0)), EpochCounter(1));
    assert_eq!(next_epoch(EpochCounter(4)), EpochCounter(5));
}

// ─── 7. budget_selects_files_within_capacity ────────────────────────────────

#[test]
fn budget_selects_files_within_capacity() {
    // 2 GB committed, estimate gives ~3 GB total budget (0.5 success rate, 0.5 factor).
    let committed_bytes = 2u64 * 1024 * 1024 * 1024;
    let budget = estimate_budget(committed_bytes, None, 0.0);
    assert!(budget.total_gb > 0.0);

    // Candidates: one large low-importance, one small high-importance.
    // Use small enough sizes to fit within budget.
    let candidates: Vec<(String, f64, u64)> = vec![
        ("big_low.bin".to_string(), 0.1, 100 * 1024 * 1024), // 100 MB, low importance
        ("small_high.pdf".to_string(), 0.9, 10 * 1024 * 1024), // 10 MB, high importance
        ("medium_mid.zip".to_string(), 0.5, 50 * 1024 * 1024), // 50 MB, medium
    ];

    let batch = select_backup_batch(&candidates, budget.total_gb);

    // High importance must come first.
    assert!(
        !batch.candidates.is_empty(),
        "at least one file must be selected"
    );
    assert_eq!(
        batch.candidates[0].path, "small_high.pdf",
        "highest importance must be first"
    );

    // Total must not exceed budget.
    assert!(
        batch.total_required_gb <= budget.total_gb,
        "selected total {} must not exceed budget {}",
        batch.total_required_gb,
        budget.total_gb
    );

    // importance=0 files are not included (none here, but verify count makes sense).
    assert_eq!(
        batch.candidates.len() + batch.deferred_count,
        3,
        "all eligible files accounted for"
    );
}

// ─── 9. db_event_log_append_and_replay ──────────────────────────────────────

#[test]
fn db_event_log_append_and_replay() {
    let db = test_db();
    let did = device_id(9);
    let t = now();

    let events = vec![
        Event::DeviceAdded { device_id: did },
        Event::FileAdded {
            file_id: FileId(1),
            path: "/photos/a.jpg".to_string(),
        },
        Event::EpochRotated { epoch: 1 },
        Event::FileModified {
            file_id: FileId(1),
            content_hash: [0x11; 32],
        },
        Event::FileDeleted {
            file_id: FileId(1),
            device_id: did,
        },
    ];

    let mut seqs = Vec::new();
    for event in &events {
        let seq = db
            .append_event(&EventEntry {
                timestamp: t,
                device_id: did,
                event: event.clone(),
            })
            .expect("append_event");
        seqs.push(seq);
    }

    // Sequences are monotonically increasing from 1.
    assert_eq!(seqs, vec![1, 2, 3, 4, 5]);

    // events_after(0) returns all 5.
    let all = db.events_after(0, 100).expect("events_after(0)");
    assert_eq!(all.len(), 5);
    assert_eq!(all[0].0, 1);
    assert_eq!(all[4].0, 5);

    // events_after(2) returns last 3 (seq 3, 4, 5).
    let tail = db.events_after(2, 100).expect("events_after(2)");
    assert_eq!(tail.len(), 3);
    assert_eq!(tail[0].0, 3);

    // events_after with limit.
    let limited = db.events_after(0, 2).expect("events_after limited");
    assert_eq!(limited.len(), 2);

    // last_event_seq.
    let last_seq = db.last_event_seq().expect("last_event_seq");
    assert_eq!(last_seq, 5);
}

// ─── 10. full_owner_flow ────────────────────────────────────────────────────

#[test]
fn full_owner_flow() {
    // Setup: keys, DB, encoder.
    let seed_bytes = seed(10);
    let master_key = derive_master_key(&seed_bytes).expect("derive_master_key");
    let identity = master_identity(&master_key);
    let enc = RaptorQEncoder::new();
    let db = test_db();
    let t = now();
    let holder = peer_id(10);

    // ── Step 1: source block + file record ──────────────────────────────────
    let source = test_data(65_535);
    let params = ErasureParams::compute(65_535, 0.8).unwrap();
    let bid = block_id(10);
    let fid = FileId(10);

    let file = FileRecord {
        file_id: fid,
        path: "/backup/critical.dat".to_string(),
        importance: 0.8,
        devices: vec![(device_id(10), LocalState::Present)],
        versions: vec![FileVersion {
            content_hash: [0xDD; 32],
            source_block_id: bid,
            k: params.k,
            t: params.t,
            created_at: t,
            backed_up_at: None,
        }],
        first_seen: t,
        on_disk_confirmed: true,
    };
    db.upsert_file(&file).expect("upsert_file");

    let sbr = SourceBlockRecord {
        block_id: bid,
        k: params.k,
        t: params.t,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: t,
        encrypted_size: None,
        n: None,
        overhead: None,
        drop_notice_sent_at: None,
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
    };
    db.upsert_source_block(&sbr).expect("upsert_source_block");

    // ── Step 2: encode symbols and store placement ───────────────────────────
    let k_eff = params.k_eff;
    let bound = enc
        .encode(&source, &params, 0, k_eff, &bid, &holder)
        .expect("encode");
    assert_eq!(bound.len(), k_eff as usize);

    let placement = SymbolPlacement {
        source_block_id: bid,
        holder_id: holder,
        file_id: fid,
        esi_ranges: vec![(0, k_eff)],
        binding_seed: [0xEE; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: t,
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).expect("upsert_placement");

    // Verify hot cache reflects placement.
    {
        let hot = db.hot();
        let agg = hot.placements.get(&(bid, holder)).expect("hot cache entry");
        assert_eq!(agg.symbol_count, k_eff);
    }

    // ── Step 3: generate hash PoS challenge and verify ──────────────────────
    let loaded_placement = db
        .get_placement(&bid, &holder)
        .expect("get_placement")
        .expect("must exist");

    // Owner encodes all symbols and computes expected chain hash.
    let mut symbol_data: Vec<(u32, Vec<u8>)> = Vec::new();
    for &(start, count) in &loaded_placement.esi_ranges {
        for esi in start..start + count {
            let bound = enc
                .encode(&source, &params, esi, 1, &bid, &holder)
                .expect("encode for challenge");
            symbol_data.push((esi, bound[0].data.clone()));
        }
    }
    let challenge_id = [0u8; 16];
    let refs: Vec<(u32, &[u8])> = symbol_data
        .iter()
        .map(|(e, d)| (*e, d.as_slice()))
        .collect();
    let expected_hash =
        compute_chain_hash(&challenge_id, &refs).expect("compute expected chain hash");

    // Holder computes the same chain hash and returns it.
    let holder_refs: Vec<(u32, &[u8])> = symbol_data
        .iter()
        .map(|(e, d)| (*e, d.as_slice()))
        .collect();
    let holder_hash =
        compute_chain_hash(&challenge_id, &holder_refs).expect("holder compute chain hash");

    let first_esi = loaded_placement
        .esi_ranges
        .first()
        .map(|&(s, _)| s)
        .unwrap_or(0);
    let outcome = verify_hash_response(&holder_hash, &expected_hash, first_esi);
    assert_eq!(outcome, VerifyOutcome::Pass);

    // ── Step 4: record PoS result in TrustEngine ─────────────────────────────
    let mut trust = TrustEngine::new();
    trust.upsert_peer_device(holder, IdentityPub([0u8; 32]), t);

    let pos_outcome = outcome_from_verify(&outcome, 1);
    trust
        .record_pos_result(holder, pos_outcome)
        .expect("record_pos_result");

    let score = trust.recalculate(&holder, t, 1).expect("recalculate");

    // After one pass, P > initial (0.1) and combined > 0.
    assert!(
        score.combined > 0.0,
        "trust must be positive after PoS pass: {}",
        score.combined
    );

    // ── Step 5: epoch key used for identity matches derived key ──────────────
    let ek = derive_epoch_key(&seed_bytes, EpochCounter(0)).expect("derive_epoch_key");
    assert_eq!(ek.epoch, EpochCounter(0));
    assert_ne!(ek.key_bytes, [0u8; 32]);

    // Master identity is stable.
    let master_key2 = derive_master_key(&seed_bytes).expect("rederive");
    assert_eq!(master_identity(&master_key2), identity);

    // ── Step 6: append event to log ─────────────────────────────────────────
    let seq = db
        .append_event(&EventEntry {
            timestamp: t,
            device_id: device_id(10),
            event: Event::SymbolsVerified {
                source_block_id: bid,
                holder_id: holder,
            },
        })
        .expect("append_event");
    assert_eq!(seq, 1);

    let log = db.events_after(0, 10).expect("events_after");
    assert_eq!(log.len(), 1);

    // ── Final assertion: file still in DB with correct version ───────────────
    let final_file = db
        .get_file("/backup/critical.dat")
        .expect("get_file")
        .expect("must exist");
    assert_eq!(final_file.versions[0].source_block_id, bid);
    assert_eq!(final_file.importance, 0.8);
}
