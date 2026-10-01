// Unit tests for the Kademlia lookup diagnostics (C-DK Р-7).

use std::time::{Duration, Instant};

use super::{EMPTY_LOOKUP_WARN_EVERY, LookupStats, empty_lookup_warn_due};

#[test]
fn lookup_stats_of_a_query_that_never_started_are_zero() {
    let stats = LookupStats::from_query(&libp2p::kad::QueryStats::empty());
    assert_eq!(
        stats,
        LookupStats {
            requests: 0,
            successes: 0,
            failures: 0,
            duration_ms: 0,
        }
    );
}

#[test]
fn empty_lookup_warn_fires_only_for_nonempty_table_and_empty_result() {
    let now = Instant::now();
    assert!(empty_lookup_warn_due(None, now, 1, 0));
    assert!(
        !empty_lookup_warn_due(None, now, 0, 0),
        "empty table is H4, not a WARN"
    );
    assert!(!empty_lookup_warn_due(None, now, 3, 2), "found peers");
}

#[test]
fn empty_lookup_warn_is_rate_limited_to_once_per_ten_minutes() {
    let t0 = Instant::now();
    let just_before = t0 + EMPTY_LOOKUP_WARN_EVERY - Duration::from_secs(1);
    let at = t0 + EMPTY_LOOKUP_WARN_EVERY;
    assert!(!empty_lookup_warn_due(Some(t0), just_before, 1, 0));
    assert!(empty_lookup_warn_due(Some(t0), at, 1, 0));
}
