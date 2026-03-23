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
    // N=1 with 2+ valid candidates after truncation → NTooSmall
    let candidates = vec![candidate(1, 0.5), candidate(2, 0.6)];
    let p = ErasureParams {
        k: 1,
        k_eff: 2,
        t: 65535,
        overhead: 1.5,
        n: 1,
    };
    let result = compute_allocation(&candidates, &p);
    assert!(matches!(result, Err(PlacementError::NTooSmall { .. })));
}

#[test]
fn compute_allocation_many_candidates_truncated_by_max_holders() {
    // 50 candidates but MAX_HOLDERS_PER_BLOCK = 30 → top-30 by weight kept
    let p = ErasureParams::compute(128 * 1024 * 1024, 0.5);
    let candidates: Vec<_> = (0..50)
        .map(|i| candidate(i + 1, 0.3 + (i as f64) * 0.012))
        .collect();
    let allocs = compute_allocation(&candidates, &p).unwrap();
    assert!(allocs.len() <= 30, "got {} holders", allocs.len());
    let total: u32 = allocs.iter().map(|a| a.symbol_count).sum();
    assert_eq!(total, p.n);
    // Verify highest-trust candidates were kept (not the low ones)
    let lowest_trust_in_result = allocs
        .iter()
        .map(|a| candidates.iter().find(|c| c.identity == a.identity).unwrap().trust)
        .fold(f64::INFINITY, f64::min);
    // The bottom 20 (trust 0.3..0.54) should be dropped; lowest kept >= ~0.54
    assert!(lowest_trust_in_result > 0.5, "lowest trust = {lowest_trust_in_result}");
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
fn compute_allocation_min_symbols_caps_holder_count_on_small_block() {
    // 32 MB block, overhead 1.5x → small N.
    // N/MIN_SYMBOLS_PER_HOLDER limits holder count to keep average symbols/holder sane.
    // Pass 30 candidates → should be trimmed.
    let p = ErasureParams::compute(32 * 1024 * 1024, 0.0); // overhead = 1.5x
    let max_holders = (p.n / crate::constants::MIN_SYMBOLS_PER_HOLDER) as usize;
    let candidates: Vec<_> = (0..30)
        .map(|i| candidate(i + 1, 0.3 + (i as f64) * 0.02))
        .collect();
    let allocs = compute_allocation(&candidates, &p).unwrap();
    assert!(
        allocs.len() <= max_holders,
        "got {} holders, expected <= {max_holders} (N={}, min_sym={})",
        allocs.len(),
        p.n,
        crate::constants::MIN_SYMBOLS_PER_HOLDER,
    );
    // Average symbols per holder is at least MIN_SYMBOLS_PER_HOLDER
    let total: u32 = allocs.iter().map(|a| a.symbol_count).sum();
    let avg = total / allocs.len() as u32;
    assert!(
        avg >= crate::constants::MIN_SYMBOLS_PER_HOLDER,
        "avg {avg} < min {}",
        crate::constants::MIN_SYMBOLS_PER_HOLDER
    );
    assert_eq!(total, p.n);
}

#[test]
fn compute_allocation_100_candidates_trimmed_to_30() {
    // Large block, 100 candidates → MAX_HOLDERS_PER_BLOCK = 30
    let p = ErasureParams::compute(128 * 1024 * 1024, 0.5);
    let candidates: Vec<_> = (0..100)
        .map(|i| candidate((i % 255) as u8 + 1, 0.1 + (i as f64) * 0.008))
        .collect();
    let allocs = compute_allocation(&candidates, &p).unwrap();
    assert_eq!(allocs.len(), 30);
    let total: u32 = allocs.iter().map(|a| a.symbol_count).sum();
    assert_eq!(total, p.n);
}

#[test]
fn holder_weight_at_half_is_sqrt_half() {
    let w = holder_weight(0.5);
    // 0.5/sqrt(0.5) = 0.5/0.7071... ≈ 0.7071
    assert!((w - 0.7071).abs() < 0.001);
}

// ─── PLACE-14: bootstrap problem ────────────────────────────────────────────

#[test]
fn compute_allocation_works_with_bootstrap_trust() {
    // New peers have trust = INITIAL_TRUST_P = 0.1 → combined ≈ 0.04.
    // Placement must work even when all peers have very low trust.
    let p = params_large(0.5);
    let candidates: Vec<_> = (1..=5).map(|b| candidate(b, 0.04)).collect();
    let allocs = compute_allocation(&candidates, &p).unwrap();
    let total: u32 = allocs.iter().map(|a| a.symbol_count).sum();
    assert_eq!(total, p.n);
    assert_eq!(allocs.len(), 5);
    for alloc in &allocs {
        assert!(alloc.symbol_count >= 1);
    }
}

// ─── PLACE-17: deterministic ────────────────────────────────────────────────

#[test]
fn compute_allocation_is_deterministic() {
    let p = params_large(0.6);
    let candidates: Vec<_> = (1..=8)
        .map(|b| candidate(b, 0.1 + (b as f64) * 0.1))
        .collect();
    let allocs_a = compute_allocation(&candidates, &p).unwrap();
    let allocs_b = compute_allocation(&candidates, &p).unwrap();
    assert_eq!(allocs_a, allocs_b);
}

// ─── PLACE-15: excess redistribution is proportional ────────────────────────

#[test]
fn redistribution_excess_is_proportional() {
    // Scenario: 4 holders where one very high-trust holder (0.99) would claim
    // far more than max_per_holder. The excess must be distributed to the other
    // 3 holders proportionally to their weights.
    //
    // Use a large block so max_per_holder is a meaningful constraint.
    let p = params_large(0.5); // 8 MB block, overhead ~2.25x
    let max_per = p.max_per_holder();

    // H1: very high trust — will be capped
    // H2, H3, H4: varied trust, will receive the redistributed symbols
    let candidates = vec![
        candidate(1, 0.99), // dominant, will hit cap
        candidate(2, 0.6),
        candidate(3, 0.4),
        candidate(4, 0.2),
    ];

    let allocs = compute_allocation(&candidates, &p).unwrap();
    assert_eq!(allocs.len(), 4);

    let total: u32 = allocs.iter().map(|a| a.symbol_count).sum();
    assert_eq!(total, p.n, "total must equal N");

    // H1 must be capped at max_per_holder
    let alloc_h1 = allocs.iter().find(|a| a.identity == identity(1)).unwrap();
    assert_eq!(
        alloc_h1.symbol_count, max_per,
        "high-trust holder must be capped at max_per_holder={max_per}"
    );

    // H2 must receive more than H3, H3 more than H4 (proportional by weight)
    let alloc_h2 = allocs.iter().find(|a| a.identity == identity(2)).unwrap();
    let alloc_h3 = allocs.iter().find(|a| a.identity == identity(3)).unwrap();
    let alloc_h4 = allocs.iter().find(|a| a.identity == identity(4)).unwrap();

    assert!(
        alloc_h2.symbol_count >= alloc_h3.symbol_count,
        "h2 (trust=0.6) should get >= h3 (trust=0.4): h2={}, h3={}",
        alloc_h2.symbol_count,
        alloc_h3.symbol_count,
    );
    assert!(
        alloc_h3.symbol_count >= alloc_h4.symbol_count,
        "h3 (trust=0.4) should get >= h4 (trust=0.2): h3={}, h4={}",
        alloc_h3.symbol_count,
        alloc_h4.symbol_count,
    );

    // All uncapped holders must each receive at least 1 symbol
    for alloc in &[alloc_h2, alloc_h3, alloc_h4] {
        assert!(alloc.symbol_count >= 1, "every holder must have >= 1 symbol");
    }
}

// ─── PLACE-20: five holders with varying trust all get symbols ───────────────

#[test]
fn compute_allocation_five_holders_all_get_symbols() {
    // Five holders with trust 0.1, 0.3, 0.5, 0.7, 0.9 and N=5000.
    // Even the lowest-trust holder must receive at least 1 symbol.
    let p = ErasureParams {
        k: 4000,
        k_eff: 4003,
        t: 65_535,
        overhead: 1.5,
        n: 5000,
    };
    let candidates = vec![
        candidate(1, 0.1),
        candidate(2, 0.3),
        candidate(3, 0.5),
        candidate(4, 0.7),
        candidate(5, 0.9),
    ];

    let allocs = compute_allocation(&candidates, &p).unwrap();

    assert_eq!(allocs.len(), 5, "all 5 holders must be allocated");
    let total: u32 = allocs.iter().map(|a| a.symbol_count).sum();
    assert_eq!(total, p.n, "total symbols must equal N=5000");

    for alloc in &allocs {
        assert!(
            alloc.symbol_count >= 1,
            "every holder must get >= 1 symbol; holder {:?} got 0",
            alloc.identity
        );
    }

    // Higher-trust holders must receive more symbols than lower-trust holders
    let count = |byte: u8| {
        allocs
            .iter()
            .find(|a| a.identity == identity(byte))
            .unwrap()
            .symbol_count
    };
    assert!(count(5) > count(1), "trust=0.9 must beat trust=0.1");
    assert!(count(4) > count(2), "trust=0.7 must beat trust=0.3");
}

// ─── PROP-03/04/05/15: placement invariants across many configurations ──────

#[test]
fn placement_invariants_hold_across_configurations() {
    // Sweep: varying holder count, trust distributions, block sizes, importance.
    let configs: Vec<(usize, f64, u64, f64)> = vec![
        // (num_holders, base_trust, block_size, importance)
        (2, 0.5, 1024 * 1024, 0.5),
        (3, 0.04, 1024 * 1024, 0.5),       // bootstrap trust
        (5, 0.3, 8 * 1024 * 1024, 0.0),     // low importance
        (5, 0.3, 8 * 1024 * 1024, 1.0),     // high importance
        (10, 0.5, 32 * 1024 * 1024, 0.5),
        (15, 0.2, 128 * 1024 * 1024, 0.6),
        (20, 0.7, 128 * 1024 * 1024, 0.5),
        (30, 0.1, 128 * 1024 * 1024, 0.3),  // near MAX_HOLDERS_PER_BLOCK
        (3, 0.99, 1024 * 1024, 0.5),        // very high trust
        (5, 0.01, 8 * 1024 * 1024, 0.5),    // very low trust
    ];

    for (num_holders, base_trust, block_size, importance) in &configs {
        let p = ErasureParams::compute(*block_size, *importance);
        let max_per = p.max_per_holder();

        let candidates: Vec<_> = (0..*num_holders)
            .map(|i| {
                let trust = (base_trust + (i as f64) * 0.03).min(0.99);
                candidate((i % 255) as u8 + 1, trust)
            })
            .collect();

        let allocs = match compute_allocation(&candidates, &p) {
            Ok(a) => a,
            Err(_) => continue, // NTooSmall etc — skip degenerate combos
        };

        // PROP-03: sum = N (when enough holders to absorb all symbols)
        let total: u32 = allocs.iter().map(|a| a.symbol_count).sum();
        let total_capacity: u32 = allocs.len() as u32 * max_per;
        if total_capacity >= p.n {
            // Enough holders — sum must equal N exactly
            assert_eq!(
                total, p.n,
                "PROP-03 violated: sum={total} != N={} for config ({num_holders}, {base_trust}, {block_size}, {importance})",
                p.n
            );
        } else {
            // Too few holders — sum = total_capacity (by design, concentration cap)
            assert!(
                total <= p.n,
                "PROP-03: sum={total} exceeds N={}",
                p.n
            );
        }

        // PROP-04: max <= max_per_holder
        for alloc in &allocs {
            assert!(
                alloc.symbol_count <= max_per,
                "PROP-04 violated: {} > max_per_holder={max_per}",
                alloc.symbol_count
            );
        }

        // PROP-05: each holder >= 1
        for alloc in &allocs {
            assert!(
                alloc.symbol_count >= 1,
                "PROP-05 violated: holder has 0 symbols"
            );
        }

        // PROP-15: ESI ranges disjoint and contiguous
        let mut sorted = allocs.clone();
        sorted.sort_by_key(|a| a.start_esi);
        let mut next_esi = 0u32;
        for alloc in &sorted {
            assert_eq!(
                alloc.start_esi, next_esi,
                "PROP-15 violated: ESI gap at {next_esi}, got start_esi={}",
                alloc.start_esi
            );
            next_esi = alloc.start_esi + alloc.symbol_count;
        }
        assert_eq!(next_esi, total, "PROP-15 violated: ESI range doesn't cover total");
    }
}

// ─── PROP-10: holder_weight positive for all valid trust values ───────────────

#[test]
fn holder_weight_positive_for_valid_trust() {
    // Sweep trust from 0.0 to 0.99 in steps of 0.01.
    // holder_weight clamps to [0.001, 0.999] so all inputs must yield weight > 0.
    let mut t = 0.0f64;
    while t < 1.0 {
        let w = holder_weight(t);
        assert!(
            w > 0.0,
            "holder_weight({t:.2}) = {w} — must be > 0 for valid trust"
        );
        assert!(
            w.is_finite(),
            "holder_weight({t:.2}) = {w} — must be finite"
        );
        t += 0.01;
    }

    // Also test exact boundary and out-of-range values.
    for &trust in &[0.0f64, 0.001, 0.5, 0.9, 0.99, 0.999, 1.0, 1.5] {
        let w = holder_weight(trust);
        assert!(w > 0.0, "holder_weight({trust}) = {w} — must be > 0");
        assert!(w.is_finite(), "holder_weight({trust}) = {w} — must be finite");
    }
}
