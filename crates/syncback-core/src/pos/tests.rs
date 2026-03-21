use crate::constants::{POS_BASE_CHALLENGES_PER_WEEK, POS_TIMEOUT_SECS};
use crate::erasure::{ErasureEncoder, RaptorQEncoder};
use crate::pos::{
    apply_pos_outcome, challenges_per_week, due_challenges, is_timed_out, outcome_from_verify,
    select_challenge_esi, verify_response, PosChallenge, PosError, PosResponse, VerifyOutcome,
};
use crate::types::{
    ErasureParams, FileId, IdentityPub, PlacementStatus, SourceBlockId, SymbolPlacement, Timestamp,
};

// ─── helpers ────────────────────────────────────────────────────────────────

fn block_id(byte: u8) -> SourceBlockId {
    SourceBlockId([byte; 32])
}

fn holder(byte: u8) -> IdentityPub {
    IdentityPub([byte; 32])
}

fn make_placement(block: SourceBlockId, h: IdentityPub, esi_ranges: Vec<(u32, u32)>) -> SymbolPlacement {
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
    h: IdentityPub,
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

/// Small source block padded to exactly params.t bytes (1 symbol).
fn small_source_block(params: &ErasureParams) -> Vec<u8> {
    let mut data = b"hello world".to_vec();
    data.resize(params.t as usize, 0u8);
    data
}

/// ErasureParams for 1-symbol source block (block_size = t).
fn small_params() -> ErasureParams {
    // Use 1 source symbol: block_size = SYMBOL_SIZE = 65535
    ErasureParams::compute(65_535, 0.5)
}

// ─── select_challenge_esi ────────────────────────────────────────────────────

#[test]
fn select_challenge_esi_selects_valid_esi() {
    let placement = make_placement(block_id(1), holder(2), vec![(0, 100)]);
    let result = select_challenge_esi(&placement, 42);
    assert!(result.is_ok());
    let esi = result.unwrap();
    assert!(esi < 100);
}

#[test]
fn select_challenge_esi_is_deterministic() {
    let placement = make_placement(block_id(1), holder(2), vec![(0, 100)]);
    let result1 = select_challenge_esi(&placement, 99).unwrap();
    let result2 = select_challenge_esi(&placement, 99).unwrap();
    assert_eq!(result1, result2);
}

#[test]
fn select_challenge_esi_varies_with_nonce() {
    let placement = make_placement(block_id(1), holder(2), vec![(0, 1000)]);
    let results: std::collections::HashSet<u32> =
        (0..20).map(|n| select_challenge_esi(&placement, n).unwrap()).collect();
    assert!(results.len() > 10, "expected nonce diversity, got {} unique ESIs", results.len());
}

#[test]
fn select_challenge_esi_works_with_multiple_ranges() {
    let placement = make_placement(block_id(1), holder(2), vec![(0, 10), (500, 5)]);
    for nonce in 0..15 {
        let esi = select_challenge_esi(&placement, nonce).unwrap();
        let in_first = esi < 10;
        let in_second = esi >= 500 && esi < 505;
        assert!(in_first || in_second, "ESI {} not in expected ranges", esi);
    }
}

#[test]
fn select_challenge_esi_fails_for_empty_placement() {
    let placement = make_placement(block_id(1), holder(2), vec![]);
    let result = select_challenge_esi(&placement, 0);
    assert!(matches!(result, Err(PosError::NoEsis(_))));
}

// ─── verify_response ─────────────────────────────────────────────────────────

#[test]
fn verify_response_pass_matches_encoder() {
    let params = small_params();
    let source_block = small_source_block(&params);
    let bid = block_id(1);
    let hid = holder(2);
    let encoder = RaptorQEncoder::new();

    let symbols = encoder.encode(&source_block, &params, 0, 1, &bid, &hid).unwrap();
    let expected_data = symbols[0].data.clone();

    let response = PosResponse {
        challenge_id: [0u8; 16],
        esi: 0,
        data: expected_data,
    };

    let result = verify_response(&response, &source_block, &params, &bid, &hid, &encoder);
    assert_eq!(result.unwrap(), VerifyOutcome::Pass);
}

#[test]
fn verify_response_fail_on_corrupt_data() {
    let params = small_params();
    let source_block = small_source_block(&params);
    let bid = block_id(1);
    let hid = holder(2);
    let encoder = RaptorQEncoder::new();

    let symbols = encoder.encode(&source_block, &params, 0, 1, &bid, &hid).unwrap();
    let mut data = symbols[0].data.clone();
    data[0] ^= 0xFF;

    let response = PosResponse {
        challenge_id: [0u8; 16],
        esi: 0,
        data,
    };

    let result = verify_response(&response, &source_block, &params, &bid, &hid, &encoder);
    assert!(matches!(result, Ok(VerifyOutcome::Fail { esi: 0 })));
}

#[test]
fn verify_response_fail_on_wrong_holder() {
    let params = small_params();
    let source_block = small_source_block(&params);
    let bid = block_id(1);
    let holder_a = IdentityPub([0xAA; 32]);
    let holder_b = IdentityPub([0xBB; 32]);
    let encoder = RaptorQEncoder::new();

    let symbols = encoder.encode(&source_block, &params, 0, 1, &bid, &holder_a).unwrap();
    let response = PosResponse {
        challenge_id: [0u8; 16],
        esi: 0,
        data: symbols[0].data.clone(),
    };

    let result = verify_response(&response, &source_block, &params, &bid, &holder_b, &encoder);
    assert!(matches!(result, Ok(VerifyOutcome::Fail { .. })));
}

#[test]
fn verify_response_size_mismatch_returns_error() {
    let params = small_params();
    let source_block = small_source_block(&params);
    let bid = block_id(1);
    let hid = holder(2);
    let encoder = RaptorQEncoder::new();

    let response = PosResponse {
        challenge_id: [0u8; 16],
        esi: 0,
        data: vec![0u8; 100],
    };

    let result = verify_response(&response, &source_block, &params, &bid, &hid, &encoder);
    assert!(matches!(result, Err(PosError::ResponseSizeMismatch { .. })));
}

#[test]
fn verify_response_consistent_across_calls() {
    let params = small_params();
    let source_block = small_source_block(&params);
    let bid = block_id(1);
    let hid = holder(2);
    let encoder = RaptorQEncoder::new();

    let symbols = encoder.encode(&source_block, &params, 0, 1, &bid, &hid).unwrap();
    let response = PosResponse {
        challenge_id: [0u8; 16],
        esi: 0,
        data: symbols[0].data.clone(),
    };

    let result1 = verify_response(&response, &source_block, &params, &bid, &hid, &encoder);
    let result2 = verify_response(&response, &source_block, &params, &bid, &hid, &encoder);
    assert_eq!(result1.unwrap(), result2.unwrap());
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
    let last_verified = vec![(bid, hid, None)];

    let entries = due_challenges(&[placement], &last_verified, now, |_| 0.5);
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
    let last_verified = vec![(bid, hid, Some(last_verified_ts))];

    let entries = due_challenges(&[placement], &last_verified, now, |_| 1.0);
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
    let last_verified = vec![(bid, hid, Some(last_verified_ts))];

    let entries = due_challenges(&[placement], &last_verified, now, |_| 1.0);
    assert_eq!(entries.len(), 1);
}

#[test]
fn due_challenges_available_esis_match_ranges() {
    let bid = block_id(1);
    let hid = holder(2);
    let placement = make_placement(bid, hid, vec![(100, 3)]);
    let now = Timestamp(1_000_000);
    let last_verified = vec![(bid, hid, None)];

    let entries = due_challenges(&[placement], &last_verified, now, |_| 0.5);
    assert_eq!(entries.len(), 1);
    let available = &entries[0].available_esis;
    assert_eq!(available, &[100, 101, 102]);
}

// ─── is_timed_out ────────────────────────────────────────────────────────────

#[test]
fn is_timed_out_false_before_deadline() {
    let challenge = PosChallenge {
        challenge_id: [0u8; 16],
        source_block_id: block_id(1),
        esi: 0,
        issued_at: Timestamp(1_000_000),
    };
    let now = Timestamp(1_000_000 + POS_TIMEOUT_SECS - 1);
    assert!(!is_timed_out(&challenge, now));
}

#[test]
fn is_timed_out_true_at_and_after_deadline() {
    let challenge = PosChallenge {
        challenge_id: [0u8; 16],
        source_block_id: block_id(1),
        esi: 0,
        issued_at: Timestamp(1_000_000),
    };

    let now = Timestamp(1_000_000 + POS_TIMEOUT_SECS);
    assert!(is_timed_out(&challenge, now));

    let now2 = Timestamp(1_000_000 + POS_TIMEOUT_SECS + 3600);
    assert!(is_timed_out(&challenge, now2));
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
        block_id(1), holder(2), vec![(0, 5)],
        PlacementStatus::Uncertain, 2,
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
        block_id(1), holder(2), vec![(0, 5)],
        PlacementStatus::Uncertain, 1,
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
        block_id(1), holder(2), vec![(0, 5)],
        PlacementStatus::Uncertain, 2,
    );
    let result = apply_pos_outcome(&placement, &VerifyOutcome::Timeout);
    assert_eq!(result.new_status, PlacementStatus::PresumedLost);
    assert_eq!(result.new_consecutive_misses, 3);
    assert!(result.trigger_repair);
}

#[test]
fn apply_pos_outcome_presumed_lost_pass_recovers_to_alive() {
    let placement = make_placement_with_status(
        block_id(1), holder(2), vec![(0, 5)],
        PlacementStatus::PresumedLost, 3,
    );
    let result = apply_pos_outcome(&placement, &VerifyOutcome::Pass);
    assert_eq!(result.new_status, PlacementStatus::Alive);
    assert_eq!(result.new_consecutive_misses, 0);
    assert!(!result.trigger_repair);
}

#[test]
fn apply_pos_outcome_lost_is_noop_for_all_outcomes() {
    let placement = make_placement_with_status(
        block_id(1), holder(2), vec![(0, 5)],
        PlacementStatus::Lost, 0,
    );
    let outcomes = [
        VerifyOutcome::Pass,
        VerifyOutcome::Fail { esi: 0 },
        VerifyOutcome::NotHeld { esi: 0 },
        VerifyOutcome::Timeout,
    ];
    for outcome in &outcomes {
        let result = apply_pos_outcome(&placement, outcome);
        assert_eq!(result.new_status, PlacementStatus::Lost, "outcome: {:?}", outcome);
        assert!(!result.trigger_repair, "outcome: {:?}", outcome);
    }
}

#[test]
fn apply_pos_outcome_deleting_is_noop_for_all_outcomes() {
    let placement = make_placement_with_status(
        block_id(1), holder(2), vec![(0, 5)],
        PlacementStatus::Deleting, 0,
    );
    let outcomes = [
        VerifyOutcome::Pass,
        VerifyOutcome::Fail { esi: 0 },
        VerifyOutcome::Timeout,
    ];
    for outcome in &outcomes {
        let result = apply_pos_outcome(&placement, outcome);
        assert_eq!(result.new_status, PlacementStatus::Deleting, "outcome: {:?}", outcome);
        assert!(!result.trigger_repair, "outcome: {:?}", outcome);
    }
}

#[test]
fn outcome_from_verify_not_held_counts_as_challenged() {
    let outcome = outcome_from_verify(&VerifyOutcome::NotHeld { esi: 3 }, 7);
    assert_eq!(outcome.week_number, 7);
    assert_eq!(outcome.challenged, 1);
    assert_eq!(outcome.passed, 0);
}

#[test]
fn verify_outcome_enum_has_not_held_variant() {
    let o = VerifyOutcome::NotHeld { esi: 0 };
    assert!(matches!(o, VerifyOutcome::NotHeld { .. }));
}
