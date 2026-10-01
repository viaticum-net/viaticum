// Unit tests of the Kademlia lookup cadence (Р-17 v3.3, network-i43).

use std::time::Duration;

use super::{BootstrapOrigin, KadCadence, SettleReason, bootstrap_origin, settled_interval};

#[test]
fn discovery_interval_settles_after_known_20() {
    let mut c = KadCadence::new(Some(1));
    assert_eq!(c.on_known(19), None);
    assert_eq!(c.on_known(20), Some(SettleReason::Known));
    assert_eq!(c.on_known(21), None, "settles once");
    assert_eq!(c.settled_period(), Some(Duration::from_secs(1800)));
}

/// M19 (unit): two non-empty rounds without an unknown peer settle a small circle.
#[test]
fn kad_cadence_settles_after_two_quiet_rounds() {
    let mut c = KadCadence::new(Some(60));
    assert_eq!(c.on_discovery_round(true, false), None);
    assert_eq!(c.on_discovery_round(true, false), Some(SettleReason::Quiet));
    assert_eq!(c.settled(), Some(SettleReason::Quiet));
}

#[test]
fn kad_cadence_empty_round_does_not_count() {
    let mut c = KadCadence::new(Some(60));
    assert_eq!(c.on_discovery_round(true, false), None);
    assert_eq!(c.on_discovery_round(false, false), None, "empty: reset");
    assert_eq!(
        c.on_discovery_round(true, false),
        None,
        "the streak starts over"
    );
    assert_eq!(
        c.on_discovery_round(true, true),
        None,
        "an unknown peer resets too"
    );
    assert_eq!(c.on_discovery_round(true, false), None);
    assert_eq!(c.on_discovery_round(true, false), Some(SettleReason::Quiet));
}

#[test]
fn kad_cadence_never_settles_with_policy_off() {
    let mut c = KadCadence::new(None);
    assert_eq!(c.on_known(500), None);
    for _ in 0..5 {
        assert_eq!(c.on_discovery_round(true, false), None);
    }
    assert_eq!(c.settled(), None);
    assert_eq!(c.slow_down(false), None);
}

#[test]
fn kad_first_tick_kept_when_settled_before_it() {
    // Settled at start (a restarted node with ≥ 20 known): nothing changes until
    // the first tick ran its lookups; then the timer slows down, once.
    let mut c = KadCadence::new(Some(1));
    assert_eq!(c.on_known(25), Some(SettleReason::Known));
    assert_eq!(c.slow_down(false), Some(Duration::from_secs(1800)));
    assert_eq!(
        c.slow_down(true),
        None,
        "an already slow timer is left alone"
    );
}

#[test]
fn kad_lookup_timer_uses_60s_floor_after_settle() {
    assert_eq!(settled_interval(1), Duration::from_secs(1800));
    assert_eq!(settled_interval(30), Duration::from_secs(60));
    assert_eq!(
        settled_interval(60),
        Duration::from_secs(60),
        "30 s → floor 60 s"
    );
    assert_eq!(
        settled_interval(1200),
        Duration::from_secs(60),
        "1.5 s → floor 60 s"
    );
}

#[test]
fn bootstrap_progress_of_unknown_query_is_auto() {
    assert_eq!(bootstrap_origin(false, 1), Some(BootstrapOrigin::Auto));
    assert_eq!(
        bootstrap_origin(false, 2),
        None,
        "only the first step starts it"
    );
    assert_eq!(
        bootstrap_origin(true, 1),
        None,
        "ours were logged when started"
    );
}
