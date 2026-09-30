use crate::constants::POS_BASE_CHALLENGES_PER_WEEK;
use crate::pos::{
    PosError, VerifyOutcome, apply_pos_outcome, challenges_per_week, compute_chain_hash,
    due_challenges, outcome_from_verify, verify_hash_response,
};
use crate::types::{DeviceId, FileId, PlacementStatus, SourceBlockId, SymbolPlacement, Timestamp};

// ─── helpers ────────────────────────────────────────────────────────────────

fn block_id(byte: u8) -> SourceBlockId {
    SourceBlockId([byte; 32])
}

fn holder(byte: u8) -> DeviceId {
    DeviceId([byte; 32])
}

fn make_placement(
    block: SourceBlockId,
    h: DeviceId,
    esi_ranges: Vec<(u32, u32)>,
) -> SymbolPlacement {
    SymbolPlacement {
        source_block_id: block,
        holder_id: h,
        file_id: FileId(1),
        esi_ranges,
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp(0),
        consecutive_misses: 0,
    }
}

fn make_placement_with_status(
    block: SourceBlockId,
    h: DeviceId,
    esi_ranges: Vec<(u32, u32)>,
    status: PlacementStatus,
    consecutive_misses: u32,
) -> SymbolPlacement {
    SymbolPlacement {
        source_block_id: block,
        holder_id: h,
        file_id: FileId(1),
        esi_ranges,
        binding_seed: [0u8; 32],
        status,
        last_verified: None,
        placed_at: Timestamp(0),
        consecutive_misses,
    }
}

// ─── challenges_per_week ─────────────────────────────────────────────────────

#[test]
fn challenges_per_week_minimum_is_base() {
    let result = challenges_per_week(0, 1.0);
    assert_eq!(result, POS_BASE_CHALLENGES_PER_WEEK);
}

#[test]
fn challenges_per_week_scales_with_volume() {
    let result_1k = challenges_per_week(1000, 0.5);
    let result_2k = challenges_per_week(2000, 0.5);
    assert!(result_2k > result_1k);
}

#[test]
fn challenges_per_week_scales_with_low_trust() {
    // Use 2000 symbols (volume_factor=2) so trust difference propagates through ceil.
    // trust=0.9: ceil(1 * 2 * 1.1) = 3
    // trust=0.1: ceil(1 * 2 * 1.9) = 4
    let result_high = challenges_per_week(2000, 0.9);
    let result_low = challenges_per_week(2000, 0.1);
    assert!(result_low > result_high);
}

#[test]
fn challenges_per_week_formula_example() {
    // 1500 symbols, trust=0.5:
    //   volume_factor = ceil(1500/1000) = 2
    //   trust_factor  = 2.0 - 0.5 = 1.5
    //   result = ceil(1 * 2 * 1.5) = 3
    let result = challenges_per_week(1500, 0.5);
    assert_eq!(result, 3);
}

// ─── due_challenges ──────────────────────────────────────────────────────────

#[test]
fn due_challenges_returns_placement_with_no_last_verified() {
    let bid = block_id(1);
    let hid = holder(2);
    let placement = make_placement(bid, hid, vec![(0, 10)]);
    let now = Timestamp(1_000_000);
    let last_verified: Vec<(SourceBlockId, DeviceId, Option<Timestamp>)> = vec![(bid, hid, None)];

    let entries = due_challenges(&[placement], &last_verified, now, |_| 0.5, 1);
    assert_eq!(entries.len(), 1);
}

#[test]
fn due_challenges_skips_recently_verified() {
    let bid = block_id(1);
    let hid = holder(2);
    let placement = make_placement(bid, hid, vec![(0, 10)]);

    // cpw = 1, interval = 7 days = 604800 secs
    // Verified 1 day ago, not yet due
    let now = Timestamp(1_000_000);
    let last_verified_ts = Timestamp(now.0 - 86400); // 1 day ago
    let last_verified: Vec<(SourceBlockId, DeviceId, Option<Timestamp>)> =
        vec![(bid, hid, Some(last_verified_ts))];

    let entries = due_challenges(&[placement], &last_verified, now, |_| 1.0, 1);
    assert!(entries.is_empty());
}

#[test]
fn due_challenges_returns_overdue_placement() {
    let bid = block_id(1);
    let hid = holder(2);
    let placement = make_placement(bid, hid, vec![(0, 10)]);

    // cpw=1, interval=7 days. Verified 8 days ago → overdue.
    let now = Timestamp(2_000_000);
    let last_verified_ts = Timestamp(now.0 - 8 * 24 * 3600); // 8 days ago
    let last_verified: Vec<(SourceBlockId, DeviceId, Option<Timestamp>)> =
        vec![(bid, hid, Some(last_verified_ts))];

    let entries = due_challenges(&[placement], &last_verified, now, |_| 1.0, 1);
    assert_eq!(entries.len(), 1);
}

/// CS-POS-9: a due placement yields one entry identifying its (block, holder). The
/// entry no longer carries an expanded ESI list — the scheduler builds the challenge
/// from the placement's own `esi_ranges`.
#[test]
fn due_challenges_entry_identifies_block_and_holder() {
    let bid = block_id(1);
    let hid = holder(2);
    let placement = make_placement(bid, hid, vec![(100, 3)]);
    let now = Timestamp(1_000_000);
    let last_verified: Vec<(SourceBlockId, DeviceId, Option<Timestamp>)> = vec![(bid, hid, None)];

    let entries = due_challenges(&[placement], &last_verified, now, |_| 0.5, 1);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].source_block_id, bid);
    assert_eq!(entries[0].holder_id, hid);
}

/// Block id `i` for the scale test: distinct for every u32.
fn indexed_block(i: u32) -> SourceBlockId {
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(&i.to_le_bytes());
    SourceBlockId(id)
}

/// pos-i7: `due_challenges` is linear in the placements. 50 000 placements with
/// `last_verified` in the reverse order: the former per-placement linear `find` is
/// ~1.25·10⁹ comparisons (seconds even in release); the index is milliseconds. Every
/// even placement was never verified (due), every odd one was verified just now (not
/// due): the lookup must also find the right row.
#[test]
fn due_challenges_is_linear_in_placements() {
    const N: u32 = 50_000;
    let now = Timestamp(10_000_000);
    let placements: Vec<SymbolPlacement> = (0..N)
        .map(|i| make_placement(indexed_block(i), holder((i % 8) as u8), vec![(0, 10)]))
        .collect();
    let last_verified: Vec<(SourceBlockId, DeviceId, Option<Timestamp>)> = (0..N)
        .rev()
        .map(|i| {
            let p = &placements[i as usize];
            let ts = if i % 2 == 0 { None } else { Some(now) };
            (p.source_block_id, p.holder_id, ts)
        })
        .collect();

    let started = std::time::Instant::now();
    let entries = due_challenges(&placements, &last_verified, now, |_| 0.5, 1);
    let elapsed = started.elapsed();

    assert_eq!(
        entries.len(),
        (N / 2) as usize,
        "the never-verified half is due"
    );
    assert!(
        entries.iter().all(|e| e.source_block_id.0[0] % 2 == 0),
        "only never-verified placements are due"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "due_challenges over {N} placements took {elapsed:?} (must be linear)"
    );
}

/// pos-i7: every entry carries the challenges-per-week its interval was derived from.
#[test]
fn due_challenges_reports_cpw_of_each_entry() {
    let now = Timestamp(1_000_000);
    // 10 symbols at trust 1.0 → cpw 1; 1500 symbols at trust 0.5 → cpw 3.
    let small = make_placement(block_id(1), holder(2), vec![(0, 10)]);
    let large = make_placement(block_id(3), holder(4), vec![(0, 1500)]);
    let last_verified: Vec<(SourceBlockId, DeviceId, Option<Timestamp>)> = vec![
        (small.source_block_id, small.holder_id, None),
        (large.source_block_id, large.holder_id, None),
    ];
    let trust = |h: &DeviceId| if *h == holder(2) { 1.0 } else { 0.5 };

    let entries = due_challenges(&[small, large], &last_verified, now, trust, 1);

    let cpw_of = |b: SourceBlockId| {
        entries
            .iter()
            .find(|e| e.source_block_id == b)
            .map(|e| e.cpw)
    };
    assert_eq!(cpw_of(block_id(1)), Some(1));
    assert_eq!(cpw_of(block_id(3)), Some(3));
}

// ─── outcome_from_verify ─────────────────────────────────────────────────────

#[test]
fn outcome_from_verify_pass() {
    let outcome = outcome_from_verify(&VerifyOutcome::Pass, 5);
    assert_eq!(outcome.week_number, 5);
    assert_eq!(outcome.challenged, 1);
    assert_eq!(outcome.passed, 1);
}

#[test]
fn outcome_from_verify_fail_counts_as_challenged() {
    let outcome = outcome_from_verify(&VerifyOutcome::Fail { esi: 7 }, 5);
    assert_eq!(outcome.week_number, 5);
    assert_eq!(outcome.challenged, 1);
    assert_eq!(outcome.passed, 0);
}

#[test]
fn outcome_from_verify_timeout_counts_as_challenged() {
    let outcome = outcome_from_verify(&VerifyOutcome::Timeout, 5);
    assert_eq!(outcome.week_number, 5);
    assert_eq!(outcome.challenged, 1);
    assert_eq!(outcome.passed, 0);
}

// ─── apply_pos_outcome state machine ────────────────────────────────────────

#[test]
fn apply_pos_outcome_pass_resets_to_alive() {
    // Placement was Uncertain with consecutive_misses=2
    let placement = make_placement_with_status(
        block_id(1),
        holder(2),
        vec![(0, 5)],
        PlacementStatus::Uncertain,
        2,
    );
    let result = apply_pos_outcome(&placement, &VerifyOutcome::Pass);
    assert_eq!(result.new_status, PlacementStatus::Alive);
    assert_eq!(result.new_consecutive_misses, 0);
    assert!(!result.trigger_repair);
}

#[test]
fn apply_pos_outcome_fail_immediately_marks_lost() {
    let placement = make_placement(block_id(1), holder(2), vec![(0, 5)]);
    let result = apply_pos_outcome(&placement, &VerifyOutcome::Fail { esi: 42 });
    assert_eq!(result.new_status, PlacementStatus::Lost);
    assert_eq!(result.new_consecutive_misses, 0);
    assert!(result.trigger_repair);
}

#[test]
fn apply_pos_outcome_not_held_immediately_marks_lost() {
    let placement = make_placement(block_id(1), holder(2), vec![(0, 5)]);
    let result = apply_pos_outcome(&placement, &VerifyOutcome::NotHeld { esi: 7 });
    assert_eq!(result.new_status, PlacementStatus::Lost);
    assert_eq!(result.new_consecutive_misses, 0);
    assert!(result.trigger_repair);
}

#[test]
fn apply_pos_outcome_first_timeout_gives_uncertain() {
    // Alive, consecutive_misses=0: first timeout → Uncertain (misses=1)
    let placement = make_placement(block_id(1), holder(2), vec![(0, 5)]);
    let result = apply_pos_outcome(&placement, &VerifyOutcome::Timeout);
    assert_eq!(result.new_status, PlacementStatus::Uncertain);
    assert_eq!(result.new_consecutive_misses, 1);
    assert!(!result.trigger_repair);
}

#[test]
fn apply_pos_outcome_second_timeout_stays_uncertain() {
    // Uncertain, consecutive_misses=1: second timeout → Uncertain (misses=2)
    let placement = make_placement_with_status(
        block_id(1),
        holder(2),
        vec![(0, 5)],
        PlacementStatus::Uncertain,
        1,
    );
    let result = apply_pos_outcome(&placement, &VerifyOutcome::Timeout);
    assert_eq!(result.new_status, PlacementStatus::Uncertain);
    assert_eq!(result.new_consecutive_misses, 2);
    assert!(!result.trigger_repair);
}

#[test]
fn apply_pos_outcome_third_timeout_gives_presumed_lost() {
    // Uncertain, consecutive_misses=2: third timeout → PresumedLost (misses=3)
    let placement = make_placement_with_status(
        block_id(1),
        holder(2),
        vec![(0, 5)],
        PlacementStatus::Uncertain,
        2,
    );
    let result = apply_pos_outcome(&placement, &VerifyOutcome::Timeout);
    assert_eq!(result.new_status, PlacementStatus::PresumedLost);
    assert_eq!(result.new_consecutive_misses, 3);
    assert!(result.trigger_repair);
}

#[test]
fn apply_pos_outcome_presumed_lost_pass_recovers_to_alive() {
    let placement = make_placement_with_status(
        block_id(1),
        holder(2),
        vec![(0, 5)],
        PlacementStatus::PresumedLost,
        3,
    );
    let result = apply_pos_outcome(&placement, &VerifyOutcome::Pass);
    assert_eq!(result.new_status, PlacementStatus::Alive);
    assert_eq!(result.new_consecutive_misses, 0);
    assert!(!result.trigger_repair);
}

#[test]
fn apply_pos_outcome_lost_is_noop_for_all_outcomes() {
    let placement = make_placement_with_status(
        block_id(1),
        holder(2),
        vec![(0, 5)],
        PlacementStatus::Lost,
        0,
    );
    let outcomes = [
        VerifyOutcome::Pass,
        VerifyOutcome::Fail { esi: 0 },
        VerifyOutcome::NotHeld { esi: 0 },
        VerifyOutcome::Timeout,
        VerifyOutcome::CannotVerify,
    ];
    for outcome in &outcomes {
        let result = apply_pos_outcome(&placement, outcome);
        assert_eq!(
            result.new_status,
            PlacementStatus::Lost,
            "outcome: {:?}",
            outcome
        );
        assert!(!result.trigger_repair, "outcome: {:?}", outcome);
    }
}

#[test]
fn apply_pos_outcome_deleting_is_noop_for_all_outcomes() {
    let placement = make_placement_with_status(
        block_id(1),
        holder(2),
        vec![(0, 5)],
        PlacementStatus::Deleting,
        0,
    );
    let outcomes = [
        VerifyOutcome::Pass,
        VerifyOutcome::Fail { esi: 0 },
        VerifyOutcome::Timeout,
        VerifyOutcome::CannotVerify,
    ];
    for outcome in &outcomes {
        let result = apply_pos_outcome(&placement, outcome);
        assert_eq!(
            result.new_status,
            PlacementStatus::Deleting,
            "outcome: {:?}",
            outcome
        );
        assert!(!result.trigger_repair, "outcome: {:?}", outcome);
    }
}

#[test]
fn outcome_from_verify_not_held_is_trust_neutral() {
    // NotHeld = holder honestly reports missing symbol.
    // Must NOT penalize trust (incentivize PosNack over silence).
    let outcome = outcome_from_verify(&VerifyOutcome::NotHeld { esi: 3 }, 7);
    assert_eq!(outcome.week_number, 7);
    assert_eq!(outcome.challenged, 0, "NotHeld must not record a challenge");
    assert_eq!(outcome.passed, 0, "NotHeld must not record a pass");
}

#[test]
fn verify_outcome_enum_has_not_held_variant() {
    let o = VerifyOutcome::NotHeld { esi: 0 };
    assert!(matches!(o, VerifyOutcome::NotHeld { .. }));
}

// ─── CannotVerify ────────────────────────────────────────────────────────────

#[test]
fn outcome_from_verify_cannot_verify_produces_no_trust_event() {
    let outcome = outcome_from_verify(&VerifyOutcome::CannotVerify, 5);
    assert_eq!(outcome.week_number, 5);
    assert_eq!(
        outcome.challenged, 0,
        "CannotVerify must not record a challenge"
    );
    assert_eq!(outcome.passed, 0, "CannotVerify must not record a pass");
}

#[test]
fn apply_pos_outcome_cannot_verify_is_noop_on_alive() {
    let placement = make_placement(block_id(1), holder(2), vec![(0, 5)]);
    let result = apply_pos_outcome(&placement, &VerifyOutcome::CannotVerify);
    assert_eq!(result.new_status, PlacementStatus::Alive);
    assert_eq!(result.new_consecutive_misses, 0);
    assert!(!result.trigger_repair);
}

#[test]
fn apply_pos_outcome_cannot_verify_is_noop_on_uncertain() {
    let placement = make_placement_with_status(
        block_id(1),
        holder(2),
        vec![(0, 5)],
        PlacementStatus::Uncertain,
        2,
    );
    let result = apply_pos_outcome(&placement, &VerifyOutcome::CannotVerify);
    assert_eq!(result.new_status, PlacementStatus::Uncertain);
    assert_eq!(result.new_consecutive_misses, 2);
    assert!(!result.trigger_repair);
}

// ─── POS-31: Deleting/Lost placements do not trigger repair on any outcome ───

#[test]
fn pos_should_skip_deleting_placements_no_repair_on_fail() {
    // A Deleting placement that receives a Fail outcome must NOT trigger repair.
    // Deletion is in progress — repairing would be wasteful and incorrect.
    let placement = make_placement_with_status(
        block_id(1),
        holder(2),
        vec![(0, 5)],
        PlacementStatus::Deleting,
        0,
    );
    let result = apply_pos_outcome(&placement, &VerifyOutcome::Fail { esi: 3 });
    assert_eq!(
        result.new_status,
        PlacementStatus::Deleting,
        "Deleting placement must stay Deleting after Fail"
    );
    assert!(
        !result.trigger_repair,
        "Deleting placement must NOT trigger repair on Fail"
    );
}

#[test]
fn pos_should_skip_deleting_placements_no_repair_on_not_held() {
    // A Deleting placement where holder responds NotHeld must NOT trigger repair.
    // Holder correctly dropped the symbols per the delete protocol.
    let placement = make_placement_with_status(
        block_id(1),
        holder(2),
        vec![(0, 5)],
        PlacementStatus::Deleting,
        0,
    );
    let result = apply_pos_outcome(&placement, &VerifyOutcome::NotHeld { esi: 3 });
    assert_eq!(result.new_status, PlacementStatus::Deleting);
    assert!(
        !result.trigger_repair,
        "Deleting placement must NOT trigger repair on NotHeld"
    );
}

#[test]
fn pos_due_challenges_does_not_filter_by_status() {
    // due_challenges does NOT filter by placement status — the caller (daemon scheduler)
    // is responsible for pre-filtering Deleting/Lost placements before calling.
    // This test documents that behavior: a Deleting placement with valid ESI ranges
    // WILL appear in due_challenges results if the caller doesn't filter.
    let bid = block_id(1);
    let hid = holder(2);
    let mut placement = make_placement(bid, hid, vec![(0, 10)]);
    placement.status = PlacementStatus::Deleting;

    let now = Timestamp(1_000_000);
    let last_verified: Vec<(SourceBlockId, DeviceId, Option<Timestamp>)> = vec![(bid, hid, None)];

    // due_challenges returns it — caller must filter before using
    let entries = due_challenges(&[placement], &last_verified, now, |_| 0.5, 1);
    assert_eq!(
        entries.len(),
        1,
        "due_challenges does not filter by PlacementStatus — caller responsibility"
    );
}

// ─── PROP-11: challenges_per_week always >= POS_BASE_CHALLENGES_PER_WEEK ─────

#[test]
fn challenges_per_week_always_at_least_base() {
    // Sweep symbol_count and trust across a wide range.
    // Result must always be >= POS_BASE_CHALLENGES_PER_WEEK.
    let symbol_counts = [0u32, 1, 100, 1000, 10000];
    let trust_values = [0.0_f64, 0.1, 0.5, 1.0, 2.0];

    for symbol_count in symbol_counts {
        for trust in trust_values {
            let result = challenges_per_week(symbol_count, trust);
            assert!(
                result >= POS_BASE_CHALLENGES_PER_WEEK,
                "challenges_per_week({symbol_count}, {trust}) = {result} \
                 — must be >= POS_BASE_CHALLENGES_PER_WEEK ({POS_BASE_CHALLENGES_PER_WEEK})"
            );
        }
    }
}

// ─── SCHED-06: adaptive_rate_low_trust_more_challenges ───────────────────────

#[test]
fn adaptive_rate_low_trust_more_challenges() {
    // The challenge rate adapts to trust: lower trust → more challenges.
    // trust_factor = 2.0 - trust, so lower trust → higher factor → more challenges.
    // Need volume_factor=2 (symbol_count=2000) so ceil() resolves the difference:
    //   trust=0.1: ceil(1 * 2 * 1.9) = ceil(3.8) = 4
    //   trust=0.9: ceil(1 * 2 * 1.1) = ceil(2.2) = 3
    let symbol_count = 2000;
    let low_trust = 0.1;
    let high_trust = 0.9;

    let low_result = challenges_per_week(symbol_count, low_trust);
    let high_result = challenges_per_week(symbol_count, high_trust);

    assert!(
        low_result > high_result,
        "low trust ({low_trust}) should produce more challenges ({low_result}) \
         than high trust ({high_trust}) ({high_result})"
    );
}

// ─── compute_chain_hash ──────────────────────────────────────────────────────

#[test]
fn compute_chain_hash_single_symbol() {
    use sha2::{Digest, Sha256};
    let challenge_id = [0u8; 16];
    let data = vec![0xABu8; 64];
    let symbols = vec![(0u32, data.as_slice())];
    let hash = compute_chain_hash(&challenge_id, &symbols).unwrap();
    // Manual: h0 = SHA256(challenge_id), h1 = SHA256(h0 || data)
    let h0: [u8; 32] = Sha256::digest(&challenge_id[..]).into();
    let mut hasher = Sha256::new();
    hasher.update(h0);
    hasher.update(&data);
    let expected: [u8; 32] = hasher.finalize().into();
    assert_eq!(hash, expected);
}

#[test]
fn compute_chain_hash_order_dependent() {
    let challenge_id = [0u8; 16];
    let sym_a = vec![1u8; 32];
    let sym_b = vec![2u8; 32];
    let hash_ab = compute_chain_hash(
        &challenge_id,
        &[(0, sym_a.as_slice()), (1, sym_b.as_slice())],
    )
    .unwrap();
    let hash_ba = compute_chain_hash(
        &challenge_id,
        &[(0, sym_b.as_slice()), (1, sym_a.as_slice())],
    )
    .unwrap();
    assert_ne!(hash_ab, hash_ba);
}

#[test]
fn compute_chain_hash_empty_errors() {
    let challenge_id = [0u8; 16];
    let result = compute_chain_hash(&challenge_id, &[]);
    assert!(matches!(result, Err(PosError::ChainHashEmptyInput)));
}

#[test]
fn verify_hash_response_pass() {
    let hash = [0xAAu8; 32];
    assert_eq!(verify_hash_response(&hash, &hash, 0), VerifyOutcome::Pass);
}

#[test]
fn verify_hash_response_fail() {
    let hash_a = [0xAAu8; 32];
    let hash_b = [0xBBu8; 32];
    let result = verify_hash_response(&hash_a, &hash_b, 42);
    assert_eq!(result, VerifyOutcome::Fail { esi: 42 });
}

// ─── L-T1..L-T5: challenge_id freshness (MED-4) ─────────────────────────────

#[test]
fn pos_chain_hash_includes_challenge_id_in_seed() {
    // Security property: same symbols, different challenge_id → different hash.
    let challenge_id_a: [u8; 16] = [0xAA; 16];
    let challenge_id_b: [u8; 16] = [0xBB; 16];
    let data = vec![0x01u8; 64];
    let symbols: &[(u32, &[u8])] = &[(0u32, data.as_slice())];

    let hash_a = compute_chain_hash(&challenge_id_a, symbols).unwrap();
    let hash_b = compute_chain_hash(&challenge_id_b, symbols).unwrap();

    assert_ne!(
        hash_a, hash_b,
        "different challenge_ids must produce different chain hashes for the same symbols"
    );
}

#[test]
fn pos_chain_hash_correct_with_challenge_id() {
    // Sanity: verifier and holder compute the same hash for the same inputs.
    let challenge_id: [u8; 16] = [0x42; 16];
    let data_a = vec![0xABu8; 64];
    let data_b = vec![0xCDu8; 64];
    let symbols: &[(u32, &[u8])] = &[(0u32, data_a.as_slice()), (1u32, data_b.as_slice())];

    let verifier_hash = compute_chain_hash(&challenge_id, symbols).unwrap();
    let holder_hash = compute_chain_hash(&challenge_id, symbols).unwrap();

    assert_eq!(
        verifier_hash, holder_hash,
        "verifier and holder must compute identical hashes for same (challenge_id, symbols)"
    );
}

#[test]
fn pos_chain_hash_rejects_old_precomputed_answer() {
    // Simulates pre-compute attack: cached hash from old challenge does not satisfy new challenge.
    let data = vec![0x01u8; 64];
    let symbols: &[(u32, &[u8])] = &[(0u32, data.as_slice())];

    let old_challenge_id: [u8; 16] = [0x00; 16];
    let new_challenge_id: [u8; 16] = [0x01; 16];

    let precomputed = compute_chain_hash(&old_challenge_id, symbols).unwrap();
    let expected = compute_chain_hash(&new_challenge_id, symbols).unwrap();

    // verify_hash_response uses expected from new challenge:
    let outcome = verify_hash_response(&precomputed, &expected, 0);
    assert_eq!(
        outcome,
        VerifyOutcome::Fail { esi: 0 },
        "pre-computed hash from old challenge must not satisfy new challenge"
    );
}

#[test]
fn pos_chain_hash_deterministic_with_fixed_seed() {
    // Reproducibility: same inputs always produce the same output.
    let challenge_id: [u8; 16] = [0x55; 16];
    let data = vec![0xFFu8; 64];
    let symbols: &[(u32, &[u8])] = &[(0u32, data.as_slice())];

    let hash1 = compute_chain_hash(&challenge_id, symbols).unwrap();
    let hash2 = compute_chain_hash(&challenge_id, symbols).unwrap();

    assert_eq!(hash1, hash2, "compute_chain_hash must be deterministic");
}

#[test]
fn pos_chain_seed_is_sha256_of_challenge_id() {
    // Documents and verifies the exact seed formula: h_0 = SHA256(challenge_id).
    use sha2::{Digest, Sha256};

    let challenge_id: [u8; 16] = [0x42; 16];
    let data = [0xABu8; 64];
    let symbols: &[(u32, &[u8])] = &[(0u32, data.as_slice())];

    // Expected: h0 = SHA256(challenge_id), h1 = SHA256(h0 || data)
    let h0: [u8; 32] = Sha256::digest(&challenge_id[..]).into();
    let h1: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(h0);
        hasher.update(data);
        hasher.finalize().into()
    };

    let result = compute_chain_hash(&challenge_id, symbols).unwrap();
    assert_eq!(
        result, h1,
        "chain hash seed must be SHA256(challenge_id), not raw challenge_id"
    );
}

// ─── POS-32: trust_factor clamped when trust > 1.0 ───────────────────────────

#[test]
fn trust_factor_clamped_above_two() {
    // challenges_per_week clamps trust to [0.0, 1.0] before computing trust_factor.
    // trust_factor = 2.0 - trust.clamp(0.0, 1.0)
    // If trust = 2.0, clamped trust = 1.0, trust_factor = 1.0 (not 0.0).
    // Result must be >= POS_BASE_CHALLENGES_PER_WEEK.
    let symbol_count = 1000u32;

    // trust > 1.0 should not produce trust_factor = 0.0 (which could give 0 challenges).
    let result_over = challenges_per_week(symbol_count, 2.0);
    assert!(
        result_over >= POS_BASE_CHALLENGES_PER_WEEK,
        "trust=2.0 must not drop below base challenges: got {result_over}"
    );

    // trust = 1.0 (maximum valid): trust_factor = 2.0 - 1.0 = 1.0.
    let result_one = challenges_per_week(symbol_count, 1.0);
    assert_eq!(
        result_over, result_one,
        "trust=2.0 should give same result as trust=1.0 due to clamping"
    );

    // trust = -1.0 (below range): clamped to 0.0, trust_factor = 2.0.
    // Should produce more challenges than trust=1.0.
    let result_neg = challenges_per_week(symbol_count, -1.0);
    assert!(
        result_neg >= result_one,
        "trust=-1.0 (clamped to 0.0) should produce >= challenges of trust=1.0"
    );
}

// ─── pos-i3: a stale verdict does not revive a placement without symbols ─────

fn assert_every_outcome_is_noop(status: PlacementStatus) {
    let placement = make_placement_with_status(block_id(1), holder(2), vec![(0, 5)], status, 2);
    let outcomes = [
        VerifyOutcome::Pass,
        VerifyOutcome::Timeout,
        VerifyOutcome::Fail { esi: 0 },
        VerifyOutcome::NotHeld { esi: 0 },
        VerifyOutcome::CannotVerify,
    ];
    for outcome in &outcomes {
        let result = apply_pos_outcome(&placement, outcome);
        assert_eq!(result.new_status, status, "outcome: {outcome:?}");
        assert_eq!(result.new_consecutive_misses, 2, "outcome: {outcome:?}");
        assert!(!result.trigger_repair, "outcome: {outcome:?}");
    }
}

#[test]
fn apply_pos_outcome_ignores_offered_placement() {
    assert_every_outcome_is_noop(PlacementStatus::Offered);
}

#[test]
fn apply_pos_outcome_ignores_accepted_placement() {
    assert_every_outcome_is_noop(PlacementStatus::Accepted);
}
