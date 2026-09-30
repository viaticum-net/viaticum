// backup-i7: the WARN "cannot load source block for PoS" is written once per day per block,
// on the monotonic clock (never scaled by `time_scale`); the clock is injected.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use viaticum_core::types::SourceBlockId;

use crate::daemon::scheduler::issue::{POS_LOAD_WARN_INTERVAL, should_warn};

const DAY: Duration = Duration::from_secs(86_400);

#[test]
fn pos_load_failure_warns_once_per_day_per_block() {
    let mut map = HashMap::new();
    let (a, b) = (SourceBlockId([1; 32]), SourceBlockId([2; 32]));
    let t0 = Instant::now();

    assert_eq!(POS_LOAD_WARN_INTERVAL, DAY);
    assert!(should_warn(&mut map, a, t0), "the first failure is a WARN");
    // Every tick of the day after it is quiet: a tick each hour, and each minute.
    for minutes in 1..24 * 60 {
        assert!(
            !should_warn(&mut map, a, t0 + Duration::from_secs(minutes * 60)),
            "minute {minutes}: DEBUG, not a WARN"
        );
    }
    assert!(
        !should_warn(&mut map, a, t0 + DAY - Duration::from_secs(1)),
        "one second short of the day"
    );
    // Another block has its own day.
    assert!(should_warn(&mut map, b, t0 + Duration::from_secs(5)));
    assert!(!should_warn(&mut map, b, t0 + Duration::from_secs(6)));
    // The day is over: one WARN again, and its day starts from that moment.
    assert!(should_warn(&mut map, a, t0 + DAY));
    assert!(!should_warn(&mut map, a, t0 + DAY + Duration::from_secs(1)));
    assert!(!should_warn(
        &mut map,
        a,
        t0 + DAY + DAY - Duration::from_secs(1)
    ));
    assert!(should_warn(&mut map, a, t0 + DAY + DAY));
}

#[test]
fn should_warn_drops_entries_that_ran_out() {
    let mut map = HashMap::new();
    let t0 = Instant::now();
    for i in 0..10u8 {
        assert!(should_warn(&mut map, SourceBlockId([i; 32]), t0));
    }
    assert_eq!(map.len(), 10);
    // A day later a WARN for a new block sweeps the ten expired ones.
    assert!(should_warn(&mut map, SourceBlockId([99; 32]), t0 + DAY));
    assert_eq!(map.len(), 1);
}
