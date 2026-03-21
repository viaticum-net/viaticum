use super::{
    binomial_survival, block_reliability, build_report, commitment_to_survival_prob,
    file_reliability, per_holder_impact, BlockReliabilityInput, HolderReliabilityInput,
    ReliabilityError,
};
use crate::commitment::CommitmentScore;
use crate::types::{IdentityPub, SourceBlockId};

// ============================================================
// Test helpers
// ============================================================

fn block_id(byte: u8) -> SourceBlockId {
    let mut b = [0u8; 32];
    b[0] = byte;
    SourceBlockId(b)
}

fn holder_id(byte: u8) -> IdentityPub {
    let mut b = [0u8; 32];
    b[0] = byte;
    IdentityPub(b)
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
