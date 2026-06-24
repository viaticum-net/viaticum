use super::*;

// ---- spearman ----

#[test]
fn spearman_is_one_for_identical_ascending_sequences() {
    let a = [1.0, 2.0, 3.0, 4.0];
    let b = [10.0, 20.0, 30.0, 40.0]; // same order, no ties
    assert!((spearman(&a, &b) - 1.0).abs() < 1e-12);
}

#[test]
fn spearman_is_minus_one_for_perfectly_reversed_sequences() {
    let a = [1.0, 2.0, 3.0, 4.0];
    let b = [40.0, 30.0, 20.0, 10.0];
    assert!((spearman(&a, &b) + 1.0).abs() < 1e-12);
}

#[test]
fn spearman_returns_zero_when_fewer_than_two_elements() {
    // n < 2 guard: cannot rank-correlate a single point or an empty sequence.
    assert_eq!(spearman(&[], &[]), 0.0);
    assert_eq!(spearman(&[1.0], &[2.0]), 0.0);
}

#[test]
fn spearman_returns_zero_when_lengths_differ() {
    assert_eq!(spearman(&[1.0, 2.0], &[1.0]), 0.0);
}

#[test]
fn spearman_handles_ties_via_averaged_ranks() {
    // `a` has a tie at the two 2.0 values; `b` strictly increasing. With averaged
    // ranks the tie group [2.0,2.0] both get rank 2.5. The Spearman value is the
    // standard 1 − 6Σd²/(n(n²−1)) on those averaged ranks, NOT 1.0 — exercising
    // the tie-averaging branch of dense_ranks (the no-tie happy path never does).
    let a = [1.0, 2.0, 2.0, 4.0];
    let b = [10.0, 20.0, 30.0, 40.0];
    let s = spearman(&a, &b);
    // Ranks(a) = [1, 2.5, 2.5, 4]; Ranks(b) = [1,2,3,4].
    // d = [0, 0.5, -0.5, 0] → Σd² = 0.5 → 1 − 6·0.5/(4·15) = 1 − 3/60 = 0.95.
    assert!(
        (s - 0.95).abs() < 1e-12,
        "tie-averaged spearman = {s}, want 0.95"
    );
}

// ---- dense_ranks (tie-averaging path directly) ----

#[test]
fn dense_ranks_averages_tied_values() {
    // Two values tie at 5.0; they must share the averaged rank of the [2,3] group
    // = 2.5. Distinct values get their plain 1-based ranks.
    let v = [5.0, 1.0, 5.0, 9.0];
    // sorted: 1.0(rank1), 5.0&5.0(ranks 2,3 → avg 2.5), 9.0(rank4)
    let r = dense_ranks(&v);
    assert_eq!(r[1], 1.0, "smallest value → rank 1");
    assert!((r[0] - 2.5).abs() < 1e-12, "tied 5.0 → averaged rank 2.5");
    assert!((r[2] - 2.5).abs() < 1e-12, "tied 5.0 → averaged rank 2.5");
    assert_eq!(r[3], 4.0, "largest value → rank 4");
}

#[test]
fn dense_ranks_no_ties_are_plain_ranks() {
    let v = [30.0, 10.0, 20.0];
    let r = dense_ranks(&v);
    assert_eq!(r, vec![3.0, 1.0, 2.0]);
}
