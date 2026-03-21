use super::{compute_allocation, holder_weight, HolderCandidate, PlacementError};
use crate::types::{ErasureParams, IdentityPub};

fn identity(byte: u8) -> IdentityPub {
    let mut key = [0u8; 32];
    key[0] = byte;
    IdentityPub(key)
}

fn candidate(byte: u8, trust: f64) -> HolderCandidate {
    HolderCandidate {
        identity: identity(byte),
        trust,
    }
}

fn params(importance: f64) -> ErasureParams {
    // 1 MB block: K = ceil(1MB / 65535) = 16, K_eff = 19, N ~ 29..57 range.
    ErasureParams::compute(1024 * 1024, importance)
}

fn params_large(importance: f64) -> ErasureParams {
    // 8 MB block: K = ceil(8MB / 65535) = 123, K_eff = 126, N ~ 189..378 range.
    ErasureParams::compute(8 * 1024 * 1024, importance)
}

// ─── holder_weight tests ─────────────────────────────────────────────────────

#[test]
fn holder_weight_formula_at_half_trust() {
    let w = holder_weight(0.5);
    assert!((w - 0.5_f64 / 0.5_f64.sqrt()).abs() < 1e-10, "w={w}");
}

#[test]
fn holder_weight_increases_with_trust() {
    let w1 = holder_weight(0.2);
    let w2 = holder_weight(0.5);
    let w3 = holder_weight(0.8);
    let w4 = holder_weight(0.9);
    assert!(w1 < w2 && w2 < w3 && w3 < w4);
}

#[test]
fn holder_weight_clamps_degenerate_inputs() {
    let w_max = holder_weight(1.5);
    let w_min = holder_weight(-0.5);
    assert!(w_max.is_finite());
    assert!(w_min.is_finite());
    assert!(w_min > 0.0);
}

// ─── error cases ─────────────────────────────────────────────────────────────

#[test]
fn compute_allocation_no_candidates_fails() {
    let p = params(0.5);
    let result = compute_allocation(&[], &p);
    assert!(matches!(result, Err(PlacementError::NoCandidates)));
}

#[test]
fn compute_allocation_single_holder_fails() {
    let p = params(0.5);
    let candidates = vec![candidate(1, 0.8)];
    let result = compute_allocation(&candidates, &p);
    assert!(matches!(
        result,
        Err(PlacementError::TooFewHolders { count: 1 })
    ));
}

#[test]
fn compute_allocation_all_trust_maximum_fails() {
    let p = params(0.5);
    let candidates = vec![candidate(1, 1.0), candidate(2, 1.5), candidate(3, 2.0)];
    let result = compute_allocation(&candidates, &p);
    assert!(matches!(result, Err(PlacementError::AllTrustMaximum)));
}

#[test]
fn compute_allocation_filters_degenerate_keeps_valid() {
    let p = params(0.5);
    let candidates = vec![candidate(1, 1.0), candidate(2, 0.7)];
    let result = compute_allocation(&candidates, &p);
    assert!(matches!(
        result,
        Err(PlacementError::TooFewHolders { count: 1 })
    ));
}

#[test]
fn compute_allocation_n_too_small_returns_error() {
    // 5 candidates but N = 3 (impossible to assign 1 each)
    let candidates: Vec<_> = (0..5).map(|i| candidate(i, 0.5)).collect();
    let p = ErasureParams {
        k: 1,
        k_eff: 4,
        t: 65535,
        overhead: 1.5,
        n: 3,
    };
    let result = compute_allocation(&candidates, &p);
    assert!(matches!(result, Err(PlacementError::NTooSmall { .. })));
}

// ─── basic correctness ───────────────────────────────────────────────────────

#[test]
fn compute_allocation_total_equals_n() {
    let p = params_large(0.6);
    let candidates: Vec<_> = (1..=15)
        .map(|b| {
            let trust = 0.2 + (b as f64 - 1.0) * 0.05; // 0.2..0.9
            candidate(b, trust)
        })
        .collect();
    let allocs = compute_allocation(&candidates, &p).unwrap();
    let total: u32 = allocs.iter().map(|a| a.symbol_count).sum();
    assert_eq!(total, p.n);
}

#[test]
fn compute_allocation_all_above_one_symbol() {
    let p = params_large(0.5);
    let candidates: Vec<_> = (1..=10).map(|b| candidate(b, 0.5)).collect();
    let allocs = compute_allocation(&candidates, &p).unwrap();
    for alloc in &allocs {
        assert!(alloc.symbol_count >= 1);
    }
}

#[test]
fn compute_allocation_none_exceed_max_per_holder() {
    let p = params_large(0.5);
    let max = p.max_per_holder();
    let candidates: Vec<_> = (1..=8).map(|b| candidate(b, 0.7)).collect();
    let allocs = compute_allocation(&candidates, &p).unwrap();
    for alloc in &allocs {
        assert!(alloc.symbol_count <= max);
    }
}

#[test]
fn compute_allocation_esi_ranges_are_contiguous_non_overlapping() {
    let p = params_large(0.5);
    let candidates: Vec<_> = (1..=10).map(|b| candidate(b, 0.6)).collect();
    let mut allocs = compute_allocation(&candidates, &p).unwrap();
    allocs.sort_by_key(|a| a.start_esi);
    let mut next_esi = 0;
    for alloc in &allocs {
        assert_eq!(alloc.start_esi, next_esi);
        next_esi = alloc.start_esi + alloc.symbol_count;
    }
    assert_eq!(next_esi, p.n);
}

#[test]
fn compute_allocation_high_trust_holder_gets_more_symbols() {
    let p = params_large(0.5);
    let candidates = vec![
        candidate(1, 0.95),
        candidate(2, 0.3),
        candidate(3, 0.5),
    ];
    let allocs = compute_allocation(&candidates, &p).unwrap();
    let alloc_95 = allocs.iter().find(|a| a.identity == identity(1)).unwrap();
    let alloc_30 = allocs.iter().find(|a| a.identity == identity(2)).unwrap();
    assert!(alloc_95.symbol_count > alloc_30.symbol_count);
}

#[test]
fn compute_allocation_equal_trust_distributes_evenly() {
    let p = params_large(0.5);
    let candidates: Vec<_> = (0..3).map(|i| candidate(i + 1, 0.7)).collect();
    let allocs = compute_allocation(&candidates, &p).unwrap();
    let expected = p.n / 3;
    for alloc in &allocs {
        assert!((alloc.symbol_count as i64 - expected as i64).abs() <= 1);
    }
}

#[test]
fn compute_allocation_cap_enforced_with_very_high_trust() {
    let p = params_large(0.5);
    let max = p.max_per_holder();
    let candidates = vec![
        candidate(1, 0.99),
        candidate(2, 0.01),
        candidate(3, 0.01),
    ];
    let allocs = compute_allocation(&candidates, &p).unwrap();
    let alloc_99 = allocs.iter().find(|a| a.identity == identity(1)).unwrap();
    assert!(alloc_99.symbol_count <= max);
    let total: u32 = allocs.iter().map(|a| a.symbol_count).sum();
    assert_eq!(total, p.n);
}

#[test]
fn compute_allocation_two_candidates_minimum_viable() {
    // 2 holders is the minimum. With only 2 holders, the concentration cap
    // prevents distributing all N symbols (by design — you need more holders).
    // This test verifies the algorithm doesn't crash and produces valid output.
    let p = params_large(0.5);
    let max = p.max_per_holder();
    let candidates = vec![candidate(1, 0.8), candidate(2, 0.6)];
    let allocs = compute_allocation(&candidates, &p).unwrap();
    assert_eq!(allocs.len(), 2);
    for alloc in &allocs {
        assert!(alloc.symbol_count >= 1);
        assert!(alloc.symbol_count <= max);
    }
}

#[test]
fn compute_allocation_sorted_descending_by_symbol_count() {
    let p = params_large(0.5);
    let candidates: Vec<_> = (1..=6)
        .map(|b| candidate(b, b as f64 * 0.1 + 0.1))
        .collect();
    let allocs = compute_allocation(&candidates, &p).unwrap();
    for window in allocs.windows(2) {
        assert!(window[0].symbol_count >= window[1].symbol_count);
    }
}

#[test]
fn compute_allocation_fifteen_holders_realistic_params() {
    let p = ErasureParams::compute(128 * 1024 * 1024, 0.6);
    let candidates: Vec<_> = (1..=15)
        .map(|b| {
            let trust = 0.2 + (b as f64 - 1.0) * 0.05;
            candidate(b, trust)
        })
        .collect();
    let allocs = compute_allocation(&candidates, &p).unwrap();
    assert_eq!(allocs.len(), 15);
    let total: u32 = allocs.iter().map(|a| a.symbol_count).sum();
    assert_eq!(total, p.n);
    let max = p.max_per_holder();
    for alloc in &allocs {
        assert!(alloc.symbol_count >= 1);
        assert!(alloc.symbol_count <= max);
    }
    // Verify ESI coverage
    let mut seen = vec![false; p.n as usize];
    for alloc in &allocs {
        for esi in alloc.start_esi..alloc.start_esi + alloc.symbol_count {
            assert!(!seen[esi as usize], "duplicate ESI {esi}");
            seen[esi as usize] = true;
        }
    }
    assert!(seen.iter().all(|&b| b));
}

#[test]
fn esi_range_helper_returns_start_and_count() {
    use super::HolderAllocation;
    let alloc = HolderAllocation {
        identity: identity(1),
        symbol_count: 100,
        start_esi: 500,
    };
    assert_eq!(alloc.esi_range(), (500, 100));
}

#[test]
fn holder_weight_at_half_is_sqrt_half() {
    let w = holder_weight(0.5);
    // 0.5/sqrt(0.5) = 0.5/0.7071... ≈ 0.7071
    assert!((w - 0.7071).abs() < 0.001);
}
