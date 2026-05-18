use super::{
    binomial_survival, block_reliability, build_report, commitment_to_survival_prob,
    file_reliability, per_holder_impact, solve_n_for_target, target_reliability,
    weighted_mean_trust, BlockReliabilityInput, HolderCandidate, HolderReliabilityInput,
    ReliabilityError,
};
use crate::commitment::CommitmentScore;
use crate::constants::{MAX_OVERHEAD_FACTOR, MIN_REDUNDANCY};
use crate::types::{DeviceId, SourceBlockId};

// ============================================================
// Test helpers
// ============================================================

fn block_id(byte: u8) -> SourceBlockId {
    let mut b = [0u8; 32];
    b[0] = byte;
    SourceBlockId(b)
}

fn holder_id(byte: u8) -> DeviceId {
    let mut b = [0u8; 32];
    b[0] = byte;
    DeviceId(b)
}

fn single_holder_input(alive_symbols: u32, survival_prob: f64) -> BlockReliabilityInput {
    BlockReliabilityInput {
        block_id: block_id(1),
        k_eff: 5,
        holders: vec![HolderReliabilityInput {
            holder_id: holder_id(1),
            alive_symbols,
            survival_prob,
        }],
    }
}

// ============================================================
// Tests: binomial_survival — core math
// ============================================================

#[test]
fn binomial_survival_k_zero_always_one() {
    let result = binomial_survival(10, 0, 0.7);
    assert_eq!(result.unwrap(), 1.0);
}

#[test]
fn binomial_survival_p_zero_k_positive_returns_zero() {
    let result = binomial_survival(10, 1, 0.0);
    assert_eq!(result.unwrap(), 0.0);
}

#[test]
fn binomial_survival_p_one_returns_one() {
    let result = binomial_survival(10, 10, 1.0);
    assert_eq!(result.unwrap(), 1.0);
}

#[test]
fn binomial_survival_n_zero_k_positive_returns_zero() {
    let result = binomial_survival(0, 1, 0.7);
    assert_eq!(result.unwrap(), 0.0);
}

#[test]
fn binomial_survival_known_value_k5_n15_p07() {
    // From docs/beta/raptorq.md reliability table: K=5, N=15, p=0.7 → ~99.93%
    let result = binomial_survival(15, 5, 0.7).unwrap();
    assert!(
        (result - 0.9993).abs() < 0.001,
        "expected ~0.9993, got {result}"
    );
}

#[test]
fn binomial_survival_known_value_k5_n10_p07() {
    // From the table: K=5, N=10, overhead=2.0x, p=0.7 → ~95.3%
    let result = binomial_survival(10, 5, 0.7).unwrap();
    assert!(
        (result - 0.953).abs() < 0.001,
        "expected ~0.953, got {result}"
    );
}

#[test]
fn binomial_survival_known_value_k5_n20_p07() {
    // From the table: K=5, N=20, overhead=4.0x, p=0.7 → ~99.9994%
    let result = binomial_survival(20, 5, 0.7).unwrap();
    assert!(
        (result - 0.999994).abs() < 0.0001,
        "expected ~0.999994, got {result}"
    );
}

#[test]
fn binomial_survival_invalid_p_returns_error() {
    let r1 = binomial_survival(10, 5, 1.5);
    assert!(
        matches!(r1, Err(ReliabilityError::InvalidSurvivalProb(p)) if (p - 1.5).abs() < 1e-9)
    );

    let r2 = binomial_survival(10, 5, -0.1);
    assert!(
        matches!(r2, Err(ReliabilityError::InvalidSurvivalProb(p)) if (p - (-0.1)).abs() < 1e-9)
    );
}

#[test]
fn binomial_survival_k_greater_than_n() {
    // P(Binomial(3, 0.7) >= 5) = 0 (impossible)
    let result = binomial_survival(3, 5, 0.7).unwrap();
    assert!(
        (result - 0.0).abs() < 1e-10,
        "expected 0.0, got {result}"
    );
}

#[test]
fn binomial_survival_exact_vs_normal_approx_agrees() {
    // At the boundary: n=99 uses exact, n=100 uses normal approx.
    // Both should agree within 0.1% for well-behaved parameters.
    let r_exact = binomial_survival(99, 50, 0.7).unwrap();
    let r_approx = binomial_survival(100, 50, 0.7).unwrap();
    assert!(
        (r_exact - r_approx).abs() < 0.001,
        "exact={r_exact}, approx={r_approx}, diff={}",
        (r_exact - r_approx).abs()
    );
}

#[test]
fn binomial_survival_large_n_normal_approx() {
    // K=200, N=480, overhead=2.4x, p=0.7 → table says ~99.999%
    let result = binomial_survival(480, 200, 0.7).unwrap();
    assert!(
        result > 0.9999,
        "expected > 0.9999, got {result}"
    );
}

// ============================================================
// Tests: block_reliability
// ============================================================

#[test]
fn block_reliability_single_holder_exact() {
    // One holder: 15 symbols, k_eff=5, survival_prob=0.7
    // Expected: same as binomial_survival(15, 5, 0.7) ≈ 0.9993
    let input = BlockReliabilityInput {
        block_id: block_id(1),
        k_eff: 5,
        holders: vec![HolderReliabilityInput {
            holder_id: holder_id(1),
            alive_symbols: 15,
            survival_prob: 0.7,
        }],
    };
    let result = block_reliability(&input).unwrap();
    assert!(
        (result - 0.9993).abs() < 0.001,
        "expected ~0.9993, got {result}"
    );
}

#[test]
fn block_reliability_empty_holders_below_k_eff() {
    // No holders: total_alive = 0, k_eff = 5 → P = 0
    let input = BlockReliabilityInput {
        block_id: block_id(1),
        k_eff: 5,
        holders: vec![],
    };
    let result = block_reliability(&input).unwrap();
    assert_eq!(result, 0.0);
}

#[test]
fn block_reliability_multiple_holders_weighted_mean() {
    // Holder A: 10 symbols, p=0.9
    // Holder B: 5 symbols, p=0.5
    // weighted mean p = (10 * 0.9 + 5 * 0.5) / 15 = 11.5 / 15 ≈ 0.7667
    let input = BlockReliabilityInput {
        block_id: block_id(1),
        k_eff: 5,
        holders: vec![
            HolderReliabilityInput {
                holder_id: holder_id(1),
                alive_symbols: 10,
                survival_prob: 0.9,
            },
            HolderReliabilityInput {
                holder_id: holder_id(2),
                alive_symbols: 5,
                survival_prob: 0.5,
            },
        ],
    };
    let result = block_reliability(&input).unwrap();
    let expected = binomial_survival(15, 5, 11.5 / 15.0).unwrap();
    assert!(
        (result - expected).abs() < 1e-9,
        "expected {expected}, got {result}"
    );
}

#[test]
fn block_reliability_invalid_k_eff_zero() {
    let input = BlockReliabilityInput {
        block_id: block_id(1),
        k_eff: 0,
        holders: vec![HolderReliabilityInput {
            holder_id: holder_id(1),
            alive_symbols: 10,
            survival_prob: 0.7,
        }],
    };
    let result = block_reliability(&input);
    assert!(matches!(result, Err(ReliabilityError::InvalidKEff(0))));
}

#[test]
fn block_reliability_invalid_survival_prob() {
    let input = BlockReliabilityInput {
        block_id: block_id(1),
        k_eff: 5,
        holders: vec![HolderReliabilityInput {
            holder_id: holder_id(1),
            alive_symbols: 10,
            survival_prob: 1.5,
        }],
    };
    let result = block_reliability(&input);
    assert!(matches!(
        result,
        Err(ReliabilityError::InvalidSurvivalProb(p)) if (p - 1.5).abs() < 1e-9
    ));
}

// ============================================================
// Tests: file_reliability
// ============================================================

#[test]
fn file_reliability_empty_blocks_returns_one() {
    let result = file_reliability(&[]).unwrap();
    assert_eq!(result, 1.0);
}

#[test]
fn file_reliability_single_block() {
    // (alive=15, k_eff=5, p=0.7) → same as binomial_survival(15, 5, 0.7) ≈ 0.9993
    let result = file_reliability(&[(15, 5, 0.7)]).unwrap();
    let expected = binomial_survival(15, 5, 0.7).unwrap();
    assert!(
        (result - expected).abs() < 1e-9,
        "expected {expected}, got {result}"
    );
}

#[test]
fn file_reliability_two_blocks_multiply() {
    // Block 1: (15, 5, 0.7) → r1 ≈ 0.9993
    // Block 2: (10, 5, 0.7) → r2 ≈ 0.953
    let result = file_reliability(&[(15, 5, 0.7), (10, 5, 0.7)]).unwrap();
    let r1 = binomial_survival(15, 5, 0.7).unwrap();
    let r2 = binomial_survival(10, 5, 0.7).unwrap();
    let expected = r1 * r2;
    assert!(
        (result - expected).abs() < 0.001,
        "expected ~{expected}, got {result}"
    );
}

#[test]
fn file_reliability_large_file_many_blocks() {
    // 16-block file, each (15, 5, 0.7) ≈ 0.9993 reliable
    // P(file) = 0.9993^16 ≈ 0.9893
    let blocks: Vec<(u32, u32, f64)> = std::iter::repeat((15, 5, 0.7)).take(16).collect();
    let result = file_reliability(&blocks).unwrap();
    assert!(
        (result - 0.9893).abs() < 0.005,
        "expected ~0.9893, got {result}"
    );
}

#[test]
fn file_reliability_one_degraded_block_drags_down() {
    // Block 1: N=5, k_eff=5, p=0.7 → P(all 5 survive) = 0.7^5 ≈ 0.168 (very low)
    // Block 2: N=5, k_eff=10, p=0.7 → 0 (can't get 10 from 5 symbols)
    // The file should end up below 0.5
    let result = file_reliability(&[(5, 5, 0.7), (5, 10, 0.7)]).unwrap();
    assert!(
        result < 0.5,
        "expected < 0.5, got {result}"
    );
}

#[test]
fn file_reliability_invalid_k_eff_zero_propagates() {
    let result = file_reliability(&[(10, 0, 0.7)]);
    assert!(matches!(result, Err(ReliabilityError::InvalidKEff(0))));
}

// ─── REL-14: multi-block file reliability is P(block)^block_count ────────────

#[test]
fn multi_block_file_reliability_is_product_of_block_reliabilities() {
    // For a 16-block file where each block has the same parameters,
    // P(file) must equal P(single_block)^16.
    // This verifies the independence assumption: all blocks must survive.
    let alive_symbols = 15u32;
    let k_eff = 5u32;
    let survival_prob = 0.7_f64;
    let block_count = 16usize;

    let single_block_p = binomial_survival(alive_symbols, k_eff, survival_prob).unwrap();
    let expected_file_p = single_block_p.powi(block_count as i32);

    let blocks: Vec<(u32, u32, f64)> = std::iter::repeat((alive_symbols, k_eff, survival_prob))
        .take(block_count)
        .collect();
    let file_p = file_reliability(&blocks).unwrap();

    assert!(
        (file_p - expected_file_p).abs() < 1e-9,
        "P(file) = {file_p} must equal P(block)^{block_count} = {expected_file_p}"
    );
}

#[test]
fn multi_block_file_reliability_single_block_equals_block_reliability() {
    // Special case: a 1-block file has P(file) = P(block).
    let p = binomial_survival(15, 5, 0.7).unwrap();
    let file_p = file_reliability(&[(15, 5, 0.7)]).unwrap();
    assert!(
        (file_p - p).abs() < 1e-9,
        "1-block file: P(file)={file_p} must equal P(block)={p}"
    );
}

#[test]
fn multi_block_file_reliability_decreases_as_block_count_increases() {
    // Adding more blocks to a file reduces overall reliability
    // (more things that can independently fail).
    let params = (15u32, 5u32, 0.9_f64);
    let p1 = file_reliability(&[params]).unwrap();
    let p2 = file_reliability(&[params, params]).unwrap();
    let p8 = file_reliability(&vec![params; 8]).unwrap();

    assert!(
        p1 > p2,
        "P(1-block file)={p1} must be > P(2-block file)={p2}"
    );
    assert!(
        p2 > p8,
        "P(2-block file)={p2} must be > P(8-block file)={p8}"
    );
}

// ============================================================
// Tests: per_holder_impact
// ============================================================

#[test]
fn per_holder_impact_only_holder_removes_all() {
    // One holder with 15 symbols, k_eff=5.
    // Without the only holder: total_alive = 0 → P = 0.
    let input = BlockReliabilityInput {
        block_id: block_id(1),
        k_eff: 5,
        holders: vec![HolderReliabilityInput {
            holder_id: holder_id(1),
            alive_symbols: 15,
            survival_prob: 0.7,
        }],
    };
    let result = per_holder_impact(&input, &holder_id(1)).unwrap();
    assert_eq!(result, 0.0);
}

#[test]
fn per_holder_impact_redundant_holder() {
    // Holder A: 15 symbols. Holder B: 3 symbols. k_eff=5.
    // Removing B leaves 15 symbols — still highly reliable.
    let input = BlockReliabilityInput {
        block_id: block_id(1),
        k_eff: 5,
        holders: vec![
            HolderReliabilityInput {
                holder_id: holder_id(1),
                alive_symbols: 15,
                survival_prob: 0.8,
            },
            HolderReliabilityInput {
                holder_id: holder_id(2),
                alive_symbols: 3,
                survival_prob: 0.8,
            },
        ],
    };
    let r_without_b = per_holder_impact(&input, &holder_id(2)).unwrap();
    assert!(
        r_without_b > 0.99,
        "expected > 0.99 without redundant holder, got {r_without_b}"
    );
}

#[test]
fn per_holder_impact_holder_not_found() {
    let input = single_holder_input(15, 0.7);
    let unknown = holder_id(99);
    let result = per_holder_impact(&input, &unknown);
    assert!(matches!(result, Err(ReliabilityError::HolderNotFound(id)) if id == unknown));
}

// ============================================================
// Tests: build_report
// ============================================================

#[test]
fn build_report_healthy_block() {
    // 2 holders, 15 symbols each, k_eff=5, survival_prob=0.9
    let input = BlockReliabilityInput {
        block_id: block_id(1),
        k_eff: 5,
        holders: vec![
            HolderReliabilityInput {
                holder_id: holder_id(1),
                alive_symbols: 15,
                survival_prob: 0.9,
            },
            HolderReliabilityInput {
                holder_id: holder_id(2),
                alive_symbols: 15,
                survival_prob: 0.9,
            },
        ],
    };
    let report = build_report(&input).unwrap();
    assert_eq!(report.symbols_alive, 30);
    assert_eq!(report.symbols_needed, 5);
    assert!(
        report.current_reliability > 0.999,
        "expected > 0.999, got {}",
        report.current_reliability
    );
    assert!(!report.needs_repair);
    assert!(report.weakest_holder_impact.is_some());
}

#[test]
fn build_report_degraded_block_needs_repair() {
    // Only 6 alive symbols for k_eff=5, low survival_prob=0.5
    // P(Binomial(6, 0.5) >= 5) is low.
    let input = BlockReliabilityInput {
        block_id: block_id(1),
        k_eff: 5,
        holders: vec![HolderReliabilityInput {
            holder_id: holder_id(1),
            alive_symbols: 6,
            survival_prob: 0.5,
        }],
    };
    let report = build_report(&input).unwrap();
    assert!(
        report.needs_repair,
        "expected needs_repair=true, current_reliability={}",
        report.current_reliability
    );
}

#[test]
fn build_report_weakest_holder_is_largest() {
    // Holder A: 12 symbols (p=0.8). Holder B: 3 symbols (p=0.8). k_eff=10.
    // Removing A leaves only 3 symbols — catastrophic. B is less critical.
    let id_a = holder_id(1);
    let id_b = holder_id(2);
    let input = BlockReliabilityInput {
        block_id: block_id(1),
        k_eff: 10,
        holders: vec![
            HolderReliabilityInput {
                holder_id: id_a,
                alive_symbols: 12,
                survival_prob: 0.8,
            },
            HolderReliabilityInput {
                holder_id: id_b,
                alive_symbols: 3,
                survival_prob: 0.8,
            },
        ],
    };
    let report = build_report(&input).unwrap();
    let impact = report.weakest_holder_impact.unwrap();
    assert_eq!(impact.holder_id, id_a);
    assert_eq!(impact.symbols_held, 12);
}

#[test]
fn build_report_no_holders() {
    let input = BlockReliabilityInput {
        block_id: block_id(1),
        k_eff: 5,
        holders: vec![],
    };
    let report = build_report(&input).unwrap();
    assert_eq!(report.symbols_alive, 0);
    assert_eq!(report.current_reliability, 0.0);
    assert!(report.needs_repair);
    assert!(report.weakest_holder_impact.is_none());
}

// ============================================================
// Tests: commitment_to_survival_prob
// ============================================================

#[test]
fn commitment_to_survival_prob_full_score() {
    let score = CommitmentScore::new(1.0);
    let result = commitment_to_survival_prob(score);
    assert!(
        (result - 1.0).abs() < 1e-9,
        "expected 1.0, got {result}"
    );
}

#[test]
fn commitment_to_survival_prob_zero_score() {
    let score = CommitmentScore::new(0.0);
    let result = commitment_to_survival_prob(score);
    assert!(
        (result - 0.0).abs() < 1e-9,
        "expected 0.0, got {result}"
    );
}

#[test]
fn commitment_to_survival_prob_midpoint() {
    // score^2 = 0.5^2 = 0.25
    let score = CommitmentScore::new(0.5);
    let result = commitment_to_survival_prob(score);
    assert!(
        (result - 0.25).abs() < 1e-9,
        "expected 0.25, got {result}"
    );
}

#[test]
fn commitment_to_survival_prob_default_churn() {
    // survival_prob = score^2 = 0.7 → score = sqrt(0.7) ≈ 0.8367
    let score = CommitmentScore::new(0.7_f64.sqrt());
    let result = commitment_to_survival_prob(score);
    assert!(
        (result - 0.7).abs() < 1e-6,
        "expected ~0.7, got {result}"
    );
}

#[test]
fn survival_prob_round_trips_commitment() {
    // survival_prob should equal 1.0 - eviction_risk(score)
    use crate::commitment::eviction_risk;
    for score_val in [0.0_f64, 0.3, 0.5, 0.7, 0.9, 1.0] {
        let score = CommitmentScore::new(score_val);
        let sp = commitment_to_survival_prob(score);
        let er = eviction_risk(score);
        assert!(
            ((sp + er) - 1.0).abs() < 1e-9,
            "score={score_val}: sp={sp}, er={er}, sum={}",
            sp + er
        );
    }
}

// ─── PROP-06: binomial_survival monotone with N ──────────────────────────────

#[test]
fn binomial_survival_monotone_with_n() {
    // Fixed K=5, p=0.95. As N increases from 5 to 29 (inclusive),
    // P(Binomial(N, p) >= K) must be non-decreasing.
    let k = 5u32;
    let p = 0.95_f64;
    let mut prev = binomial_survival(k, k, p).unwrap();
    for n in (k + 1)..30 {
        let curr = binomial_survival(n, k, p).unwrap();
        assert!(
            curr >= prev - 1e-12,
            "binomial_survival not monotone: N={} gives {curr} < N={} gives {prev}",
            n,
            n - 1
        );
        prev = curr;
    }
}

// ─── PROP-07: binomial_survival result always in [0.0, 1.0] ─────────────────

#[test]
fn binomial_survival_in_zero_one_range() {
    let n_values = [1u32, 5, 10, 20, 50];
    let k_values = [1u32, 3, 5, 10];
    let p_values = [0.0_f64, 0.5, 0.8, 0.95, 1.0];

    for n in n_values {
        for k in k_values {
            if k > n {
                continue;
            }
            for p in p_values {
                let result = binomial_survival(n, k, p).unwrap();
                assert!(
                    result >= 0.0 && result <= 1.0,
                    "binomial_survival({n}, {k}, {p}) = {result} — out of [0, 1]"
                );
            }
        }
    }
}

// ─── PROP-14: block_reliability always in [0.0, 1.0] ────────────────────────

#[test]
fn block_reliability_in_zero_one() {
    // Sweep various BlockReliabilityInput configurations.
    // Result must always be in [0.0, 1.0].
    let k_eff_values = [1u32, 3, 5, 10];
    let alive_values = [0u32, 1, 5, 10, 20];
    let survival_values = [0.0_f64, 0.3, 0.5, 0.8, 0.95, 1.0];

    for k_eff in k_eff_values {
        for alive in alive_values {
            for survival_prob in survival_values {
                let input = BlockReliabilityInput {
                    block_id: block_id(1),
                    k_eff,
                    holders: vec![HolderReliabilityInput {
                        holder_id: holder_id(1),
                        alive_symbols: alive,
                        survival_prob,
                    }],
                };
                let result = block_reliability(&input).unwrap();
                assert!(
                    result >= 0.0 && result <= 1.0,
                    "block_reliability(k_eff={k_eff}, alive={alive}, p={survival_prob}) = {result} — out of [0, 1]"
                );
            }
        }
    }
}

// ─── PROP-21: binomial_survival with K > N returns 0.0 ──────────────────────

#[test]
fn binomial_survival_k_greater_than_n_returns_zero() {
    // For K > N, it is impossible to get K successes from N trials with p in (0,1).
    let cases = [(3u32, 5u32), (1, 2), (5, 10), (0, 1), (10, 11)];
    for (n, k) in cases {
        // Only test with p in (0, 1) — p=0 and p=1 are handled by edge-case logic.
        for p in [0.3_f64, 0.5, 0.7, 0.9] {
            let result = binomial_survival(n, k, p).unwrap();
            assert!(
                result == 0.0,
                "binomial_survival({n}, {k}, {p}) = {result} — expected 0.0 for K > N"
            );
        }
    }
}

// ============================================================
// Wave 3 helpers
// ============================================================

fn candidate(survival_prob: f64) -> HolderCandidate {
    HolderCandidate { survival_prob }
}

fn pool(probs: &[f64]) -> Vec<HolderCandidate> {
    probs.iter().copied().map(candidate).collect()
}

// ============================================================
// Tests: target_reliability — formula correctness
// ============================================================

#[test]
fn target_reliability_at_importance_zero_returns_half() {
    let result = target_reliability(0.0);
    let expected = 1.0 - 10f64.powf(-0.3);
    assert!(
        (result - expected).abs() < 1e-9,
        "target_reliability(0.0) = {result}, expected {expected}"
    );
    assert!(
        (result - 0.499).abs() < 0.001,
        "target_reliability(0.0) = {result}, expected ~0.499"
    );
}

#[test]
fn target_reliability_at_importance_one_returns_five_nines() {
    let result = target_reliability(1.0);
    let expected = 1.0 - 1e-5;
    assert!(
        (result - expected).abs() < 1e-9,
        "target_reliability(1.0) = {result}, expected {expected}"
    );
}

#[test]
fn target_reliability_known_anchors() {
    // Tolerances account for rounding in the anchor table (values shown to 2 sig figs).
    // Formula: 1 - 10^(-(0.3 + imp * 4.7)).
    // imp=0.05: exact=0.7083, table≈0.71 (rounded to 2dp), tol=0.002
    // imp=0.20: exact=0.9425, table≈0.94 (rounded to 2dp), tol=0.003
    // imp=0.65: exact=0.99956, table≈0.9996, tol=0.0001
    // imp=0.95: exact=0.999983, table≈0.99998, tol=0.00001
    // imp=1.00: exact=0.99999, table=0.99999, tol=1e-9
    let cases: &[(f64, f64, f64)] = &[
        (0.05, 0.71, 0.002),
        (0.20, 0.94, 0.003),
        (0.65, 0.9996, 0.0001),
        (0.95, 0.99998, 0.00001),
        (1.00, 0.99999, 1e-9),
    ];
    for &(imp, expected, tol) in cases {
        let got = target_reliability(imp);
        assert!(
            (got - expected).abs() <= tol,
            "target_reliability({imp}) = {got}, expected {expected} ±{tol}"
        );
    }
}

#[test]
fn target_reliability_monotonic_in_importance() {
    let mut prev = target_reliability(0.0);
    let steps = 100;
    for i in 1..=steps {
        let imp = i as f64 / steps as f64;
        let curr = target_reliability(imp);
        assert!(
            curr >= prev - 1e-12,
            "target_reliability not monotone: imp={imp:.2} gives {curr} < prev {prev}"
        );
        prev = curr;
    }
}

#[test]
fn target_reliability_clamps_below_zero_input() {
    let below = target_reliability(-0.5);
    let at_zero = target_reliability(0.0);
    assert!(
        (below - at_zero).abs() < 1e-9,
        "target_reliability(-0.5) = {below}, expected same as target_reliability(0.0) = {at_zero}"
    );
}

#[test]
fn target_reliability_clamps_above_one_input() {
    let above = target_reliability(1.5);
    let at_one = target_reliability(1.0);
    assert!(
        (above - at_one).abs() < 1e-9,
        "target_reliability(1.5) = {above}, expected same as target_reliability(1.0) = {at_one}"
    );
}

#[test]
fn target_reliability_output_always_in_zero_one() {
    for imp in [-1.0_f64, -0.1, 0.0, 0.5, 1.0, 1.5, 2.0] {
        let result = target_reliability(imp);
        assert!(
            result >= 0.0 && result <= 1.0,
            "target_reliability({imp}) = {result} — out of [0, 1]"
        );
    }
}

// ============================================================
// Tests: weighted_mean_trust
// ============================================================

#[test]
fn weighted_mean_trust_equal_weights_single_holder() {
    let p = pool(&[0.75]);
    let result = weighted_mean_trust(&p).unwrap();
    assert!(
        (result - 0.75).abs() < 1e-9,
        "expected 0.75, got {result}"
    );
}

#[test]
fn weighted_mean_trust_equal_weights_multiple_holders() {
    // (0.9 + 0.5 + 0.7 + 0.8) / 4 = 2.9 / 4 = 0.725
    // A symbol-weighted mean (if holders had symbol counts 10, 1, 1, 1) would give 0.877.
    // Equal-weight must produce 0.725, not 0.877.
    let p = pool(&[0.9, 0.5, 0.7, 0.8]);
    let result = weighted_mean_trust(&p).unwrap();
    assert!(
        (result - 0.725).abs() < 1e-9,
        "expected 0.725 (equal-weight), got {result}"
    );
}

#[test]
fn weighted_mean_trust_empty_holders_returns_error() {
    let result = weighted_mean_trust(&[]);
    assert!(
        matches!(result, Err(ReliabilityError::EmptyHolderSlice)),
        "expected EmptyHolderSlice, got {result:?}"
    );
}

#[test]
fn weighted_mean_trust_invalid_survival_prob_returns_error() {
    let p = pool(&[1.5]);
    let result = weighted_mean_trust(&p);
    assert!(
        matches!(result, Err(ReliabilityError::InvalidSurvivalProb(v)) if (v - 1.5).abs() < 1e-9),
        "expected InvalidSurvivalProb(1.5), got {result:?}"
    );
}

#[test]
fn weighted_mean_trust_all_zero_survival() {
    let p = pool(&[0.0, 0.0, 0.0]);
    let result = weighted_mean_trust(&p).unwrap();
    assert!(
        (result - 0.0).abs() < 1e-9,
        "expected 0.0, got {result}"
    );
}

#[test]
fn weighted_mean_trust_all_full_survival() {
    let p = pool(&[1.0, 1.0, 1.0, 1.0]);
    let result = weighted_mean_trust(&p).unwrap();
    assert!(
        (result - 1.0).abs() < 1e-9,
        "expected 1.0, got {result}"
    );
}

// ============================================================
// Tests: solve_n_for_target — bounds and floor
// ============================================================

#[test]
fn solve_n_for_target_min_redundancy_floor() {
    // k_eff=10, all survival_prob=1.0, target_p=0.0
    // Even with trivially satisfied target, floor = 10 + 2 = 12
    let k_eff = 10u32;
    let p = pool(&[1.0, 1.0, 1.0, 1.0]);
    let result = solve_n_for_target(k_eff, &p, 0.0).unwrap();
    assert_eq!(result, k_eff + MIN_REDUNDANCY, "expected floor n={}", k_eff + MIN_REDUNDANCY);
}

#[test]
fn solve_n_for_target_respects_max_overhead_factor() {
    // k_eff=5, all dead pool, target=0.99 — unachievable
    // Must return k_eff * MAX_OVERHEAD_FACTOR = 50, never more
    let k_eff = 5u32;
    let max_n = k_eff * MAX_OVERHEAD_FACTOR;
    let dead = pool(&[0.0, 0.0, 0.0]);
    let result = solve_n_for_target(k_eff, &dead, 0.99).unwrap();
    assert_eq!(result, max_n, "expected max_n={max_n}, got {result}");
}

#[test]
fn solve_n_for_target_min_redundancy_never_below_floor_on_easy_target() {
    // k_eff=8, high-trust pool, easy target → must return exactly 10 (floor)
    let k_eff = 8u32;
    let floor = k_eff + MIN_REDUNDANCY;
    let high_trust = pool(&[0.99, 0.99, 0.99, 0.99, 0.99, 0.99]);
    let n = solve_n_for_target(k_eff, &high_trust, 0.01).unwrap();
    assert!(n >= floor, "n={n} is below floor={floor}");
    assert_eq!(n, floor, "expected n=floor={floor} for trivially easy target, got n={n}");
}

// ============================================================
// Tests: solve_n_for_target — minimum overhead selection
// ============================================================

#[test]
fn solve_n_for_target_picks_min_overhead_for_target() {
    let k_eff = 5u32;
    let pool_v = pool(&[0.82, 0.82, 0.82, 0.82, 0.82, 0.82, 0.82, 0.82]);
    let target_p = 0.94;
    let n = solve_n_for_target(k_eff, &pool_v, target_p).unwrap();
    let mean_p = 0.82;

    assert!(n >= k_eff + MIN_REDUNDANCY, "n={n} below floor {}", k_eff + MIN_REDUNDANCY);
    assert!(
        binomial_survival(n, k_eff, mean_p).unwrap() >= target_p,
        "n={n} does not satisfy target_p={target_p}"
    );
    if n > k_eff + MIN_REDUNDANCY {
        assert!(
            binomial_survival(n - 1, k_eff, mean_p).unwrap() < target_p,
            "n-1={} also satisfies target_p — n={n} is not minimal",
            n - 1
        );
    }
}

// ============================================================
// Tests: solve_n_for_target — pool quality effects
// ============================================================

#[test]
fn solve_n_for_target_grows_n_when_pool_is_weak() {
    let k_eff = 5u32;
    let target_p = 0.99999;
    let strong = pool(&[0.85, 0.85, 0.85, 0.85, 0.85, 0.85, 0.85, 0.85]);
    let weak = pool(&[0.40, 0.40, 0.40, 0.40, 0.40, 0.40, 0.40, 0.40]);
    let n_strong = solve_n_for_target(k_eff, &strong, target_p).unwrap();
    let n_weak = solve_n_for_target(k_eff, &weak, target_p).unwrap();
    assert!(
        n_weak >= n_strong,
        "weaker pool should need >= n: n_weak={n_weak}, n_strong={n_strong}"
    );
}

#[test]
fn solve_n_for_target_returns_max_when_target_unachievable() {
    let k_eff = 5u32;
    let max_n = k_eff * MAX_OVERHEAD_FACTOR;
    let dead_pool = pool(&[0.05, 0.05, 0.05]);
    let result = solve_n_for_target(k_eff, &dead_pool, 0.99).unwrap();
    assert_eq!(result, max_n, "expected max_n={max_n}, got {result}");
}

// ============================================================
// Tests: solve_n_for_target — error cases
// ============================================================

#[test]
fn solve_n_for_target_empty_holders_errors() {
    let result = solve_n_for_target(5, &[], 0.9);
    assert!(
        matches!(result, Err(ReliabilityError::EmptyHolderSlice)),
        "expected EmptyHolderSlice, got {result:?}"
    );
}

#[test]
fn solve_n_for_target_zero_k_eff_errors() {
    let p = pool(&[0.8]);
    let result = solve_n_for_target(0, &p, 0.9);
    assert!(
        matches!(result, Err(ReliabilityError::InvalidKEff(0))),
        "expected InvalidKEff(0), got {result:?}"
    );
}

#[test]
fn solve_n_for_target_invalid_survival_prob_errors() {
    let bad = pool(&[1.5]);
    let result = solve_n_for_target(5, &bad, 0.9);
    assert!(
        matches!(result, Err(ReliabilityError::InvalidSurvivalProb(v)) if (v - 1.5).abs() < 1e-9),
        "expected InvalidSurvivalProb(1.5), got {result:?}"
    );
}

// ============================================================
// Tests: solve_n_for_target — monotonicity (regression guard)
// ============================================================

#[test]
fn solve_n_for_target_monotonic_in_target_p() {
    let k_eff = 5u32;
    let pool_v = pool(&[0.75, 0.75, 0.75, 0.75, 0.75, 0.75]);
    let targets = [0.70, 0.80, 0.90, 0.95, 0.99, 0.9999, 0.99999];
    let mut prev_n = 0u32;
    for &target_p in &targets {
        let n = solve_n_for_target(k_eff, &pool_v, target_p).unwrap();
        assert!(
            n >= prev_n,
            "solve_n_for_target not monotone in target_p: target={target_p} gives n={n} < prev {prev_n}"
        );
        prev_n = n;
    }
}

#[test]
fn solve_n_for_target_monotonic_in_holder_trust() {
    let k_eff = 5u32;
    let target_p = 0.99;
    let trust_levels: &[f64] = &[0.3, 0.5, 0.7, 0.85, 0.95, 1.0];

    // Iterate high→low trust: each lower-trust pool must need n >= previous.
    let mut prev_n = u32::MAX;
    for &p in trust_levels.iter().rev() {
        let pool_v = pool(&[p; 6]);
        let n = solve_n_for_target(k_eff, &pool_v, target_p).unwrap();
        assert!(
            n >= prev_n || prev_n == u32::MAX,
            "lower trust should need >= n: trust={p} gave n={n} < prev n={prev_n}"
        );
        prev_n = n;
    }

    // Iterate low→high trust: n must be non-increasing.
    let mut prev_n = u32::MAX;
    for &p in trust_levels {
        let pool_v = pool(&[p; 6]);
        let n = solve_n_for_target(k_eff, &pool_v, target_p).unwrap();
        if prev_n != u32::MAX {
            assert!(
                n <= prev_n,
                "higher trust should need <= n: trust={p} gave n={n} > prev n={prev_n}"
            );
        }
        prev_n = n;
    }
}

// ============================================================
// Tests: integration anchor (matches R8 table end-to-end)
// ============================================================

#[test]
fn solve_n_for_target_anchor_unknown_importance() {
    // importance=0.05 → target_p ≈ 0.71, k_eff=5, pool at 0.7 survival
    let k_eff = 5u32;
    let target_p = target_reliability(0.05);
    let pool_v = pool(&[0.7; 8]);
    let n = solve_n_for_target(k_eff, &pool_v, target_p).unwrap();
    let mean_p = 0.7;

    assert!(n >= k_eff + MIN_REDUNDANCY, "n={n} below floor");
    let achieved = binomial_survival(n, k_eff, mean_p).unwrap();
    assert!(
        achieved >= target_p || n == k_eff * MAX_OVERHEAD_FACTOR,
        "n={n} achieves {achieved}, target={target_p}, and is not at cap"
    );
}

#[test]
fn solve_n_for_target_anchor_important_data() {
    let k_eff = 5u32;
    let target_p = target_reliability(1.0);
    let pool_v = pool(&[0.7; 8]);
    let n = solve_n_for_target(k_eff, &pool_v, target_p).unwrap();
    let mean_p = 0.7;

    assert!(n >= k_eff + MIN_REDUNDANCY, "below floor");
    let achieved = binomial_survival(n, k_eff, mean_p).unwrap();
    assert!(
        achieved >= target_p || n == k_eff * MAX_OVERHEAD_FACTOR,
        "n={n} achieves {achieved}, target={target_p}, and is not at cap"
    );
}
