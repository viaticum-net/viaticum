use crate::priority::priority;

#[test]
fn priority_new_block_equals_importance_when_alive_zero() {
    let result = priority(0.8, 0, 10, 1.5);
    assert!((result - 0.8).abs() < 1e-9, "expected 0.8, got {result}");
}

#[test]
fn priority_completed_block_scales_by_one_plus_k() {
    let r1 = priority(0.5, 14, 14, 1.5);
    assert!((r1 - 1.25).abs() < 1e-9, "expected 1.25, got {r1}");

    let r2 = priority(1.0, 10, 10, 1.5);
    assert!((r2 - 2.5).abs() < 1e-9, "expected 2.5, got {r2}");

    let r3 = priority(0.8, 5, 5, 0.0);
    assert!((r3 - 0.8).abs() < 1e-9, "expected 0.8, got {r3}");
}

#[test]
fn priority_monotonic_in_importance() {
    let mut prev = priority(0.0, 5, 10, 1.5);
    for i in 1..=10 {
        let imp = i as f64 * 0.1;
        let curr = priority(imp, 5, 10, 1.5);
        assert!(
            curr >= prev,
            "priority not monotonic at importance={imp}: prev={prev}, curr={curr}"
        );
        prev = curr;
    }
}

#[test]
fn priority_monotonic_in_current_alive() {
    let mut prev = priority(0.7, 0, 20, 1.5);
    for alive in 1..=20u32 {
        let curr = priority(0.7, alive, 20, 1.5);
        assert!(
            curr >= prev,
            "priority not monotonic at current_alive={alive}: prev={prev}, curr={curr}"
        );
        prev = curr;
    }
}

#[test]
fn priority_k_zero_returns_pure_importance() {
    let r1 = priority(0.7, 0, 10, 0.0);
    assert!((r1 - 0.7).abs() < 1e-9, "expected 0.7, got {r1}");

    let r2 = priority(0.7, 5, 10, 0.0);
    assert!((r2 - 0.7).abs() < 1e-9, "expected 0.7, got {r2}");

    let r3 = priority(0.7, 10, 10, 0.0);
    assert!((r3 - 0.7).abs() < 1e-9, "expected 0.7, got {r3}");
}

#[test]
fn priority_n_target_zero_returns_importance() {
    let r1 = priority(0.9, 0, 0, 1.5);
    assert!((r1 - 0.9).abs() < 1e-9, "expected 0.9, got {r1}");

    let r2 = priority(0.9, 5, 0, 1.5);
    assert!((r2 - 0.9).abs() < 1e-9, "expected 0.9, got {r2}");
}

#[test]
fn priority_over_complete_clamps_ratio_to_one() {
    let over = priority(1.0, 15, 10, 1.5);
    let full = priority(1.0, 10, 10, 1.5);
    assert!(
        (over - full).abs() < 1e-9,
        "over-complete should equal fully-complete: over={over}, full={full}"
    );
    assert!((over - 2.5).abs() < 1e-9, "expected 2.5, got {over}");
}

#[test]
fn priority_clamps_negative_importance_to_zero() {
    let result = priority(-0.5, 5, 10, 1.5);
    assert!((result - 0.0).abs() < 1e-9, "expected 0.0, got {result}");
}

#[test]
fn priority_clamps_importance_above_one_to_one() {
    let clamped = priority(1.5, 5, 10, 1.5);
    let normal = priority(1.0, 5, 10, 1.5);
    assert!(
        (clamped - normal).abs() < 1e-9,
        "clamped should equal priority(1.0,...): clamped={clamped}, normal={normal}"
    );
    // priority(1.0, 5, 10, 1.5) = 1.0 * (1 + 1.5 * 0.5) = 1.0 * 1.75 = 1.75
    assert!(
        (clamped - 1.75).abs() < 1e-9,
        "expected 1.75, got {clamped}"
    );
}

#[test]
fn priority_clamps_negative_k_to_zero() {
    let clamped = priority(0.8, 5, 10, -1.0);
    let pure_imp = priority(0.8, 5, 10, 0.0);
    assert!(
        (clamped - pure_imp).abs() < 1e-9,
        "negative k should behave as k=0: clamped={clamped}, pure_imp={pure_imp}"
    );
    assert!((clamped - 0.8).abs() < 1e-9, "expected 0.8, got {clamped}");
}

#[test]
fn priority_scenarios_match_unified_spec_table() {
    // Row 1: Important new (1.0) vs unimportant near-done (0.2 at current_alive=12, n=14)
    let row1_a = priority(1.0, 0, 14, 1.5);
    let row1_b = priority(0.2, 12, 14, 1.5);
    let row1_b_expected = 0.2_f64 * (1.0 + 1.5 * (12.0 / 14.0));
    assert!(
        (row1_a - 1.0_f64).abs() < 1e-9,
        "Row1A: expected 1.0, got {row1_a}"
    );
    assert!(
        (row1_b - row1_b_expected).abs() < 1e-9,
        "Row1B: expected {row1_b_expected}, got {row1_b}"
    );
    assert!(
        row1_a > row1_b,
        "Row1: important new should win (1.0 > {row1_b:.6})"
    );

    // Row 2: Same-importance new (0.5) vs partial at halfway (current_alive=7, n=14)
    let row2_a = priority(0.5, 0, 14, 1.5);
    let row2_b = priority(0.5, 7, 14, 1.5);
    let row2_b_expected = 0.5_f64 * 1.75_f64;
    assert!(
        (row2_a - 0.5_f64).abs() < 1e-9,
        "Row2A: expected 0.5, got {row2_a}"
    );
    assert!(
        (row2_b - row2_b_expected).abs() < 1e-9,
        "Row2B: expected {row2_b_expected}, got {row2_b}"
    );
    assert!(
        row2_b > row2_a,
        "Row2: partial should win over new at same importance ({row2_b:.6} > {row2_a:.6})"
    );

    // Row 3: Heavily degraded high (1.0 at current_alive=1, n=10) vs near-done lower (0.5 at 9/10)
    let row3_a = priority(1.0, 1, 10, 1.5);
    let row3_b = priority(0.5, 9, 10, 1.5);
    let row3_a_expected = 1.15_f64;
    let row3_b_expected = 0.5_f64 * (1.0 + 1.5 * 0.9_f64);
    assert!(
        (row3_a - row3_a_expected).abs() < 1e-9,
        "Row3A: expected {row3_a_expected}, got {row3_a}"
    );
    assert!(
        (row3_b - row3_b_expected).abs() < 1e-9,
        "Row3B: expected {row3_b_expected}, got {row3_b}"
    );
    assert!(
        row3_b > row3_a,
        "Row3: near-done lower should win (1.175 > 1.15): row3_b={row3_b:.9}, row3_a={row3_a:.9}"
    );

    // Row 4: New high (1.0) vs near-done medium (0.5 at 9/10)
    let row4_a = priority(1.0, 0, 10, 1.5);
    let row4_b = priority(0.5, 9, 10, 1.5);
    let row4_b_expected = 0.5_f64 * (1.0 + 1.5 * 0.9_f64);
    assert!(
        (row4_a - 1.0_f64).abs() < 1e-9,
        "Row4A: expected 1.0, got {row4_a}"
    );
    assert!(
        (row4_b - row4_b_expected).abs() < 1e-9,
        "Row4B: expected {row4_b_expected}, got {row4_b}"
    );
    assert!(
        row4_b > row4_a,
        "Row4: completion bonus tips near-done medium over new high ({row4_b:.9} > {row4_a:.9})"
    );
}
