use super::{DEFAULT_COOLDOWN_SECS, PeerBackoff};
use syncback_core::types::DeviceId;

fn dev(byte: u8) -> DeviceId {
    DeviceId([byte; 32])
}

#[test]
fn fresh_peer_is_not_in_backoff() {
    let backoff = PeerBackoff::new(60);
    assert!(!backoff.is_in_backoff(&dev(1)));
}

#[test]
fn record_reject_puts_peer_in_backoff() {
    let backoff = PeerBackoff::new(60);
    backoff.record_reject(dev(1));
    assert!(backoff.is_in_backoff(&dev(1)));
    assert!(!backoff.is_in_backoff(&dev(2)));
}

#[test]
fn record_accept_clears_backoff() {
    let backoff = PeerBackoff::new(60);
    backoff.record_reject(dev(1));
    assert!(backoff.is_in_backoff(&dev(1)));
    backoff.record_accept(&dev(1));
    assert!(!backoff.is_in_backoff(&dev(1)));
}

#[test]
fn cooldown_expires_after_duration() {
    // Use a 1s cooldown so the test is fast.
    let backoff = PeerBackoff::new(1);
    backoff.record_reject(dev(1));
    assert!(backoff.is_in_backoff(&dev(1)));
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert!(!backoff.is_in_backoff(&dev(1)));
}

#[test]
fn filter_drops_peers_in_backoff() {
    let backoff = PeerBackoff::new(60);
    backoff.record_reject(dev(1));
    backoff.record_reject(dev(3));
    let candidates = vec![dev(1), dev(2), dev(3), dev(4)];
    let kept = backoff.filter(candidates, 2, |d| d);
    assert_eq!(kept, vec![dev(2), dev(4)]);
}

#[test]
fn filter_returns_empty_sentinel_when_below_min_required() {
    // All candidates on cooldown — filter returns empty so caller falls back
    // to the raw list (encoded by the empty sentinel).
    let backoff = PeerBackoff::new(60);
    backoff.record_reject(dev(1));
    backoff.record_reject(dev(2));
    let candidates = vec![dev(1), dev(2)];
    let kept = backoff.filter(candidates, 2, |d| d);
    assert!(kept.is_empty(), "expected empty sentinel");
}

#[test]
fn filter_returns_kept_when_exactly_min_required() {
    let backoff = PeerBackoff::new(60);
    backoff.record_reject(dev(1));
    let candidates = vec![dev(1), dev(2), dev(3)];
    let kept = backoff.filter(candidates, 2, |d| d);
    assert_eq!(kept, vec![dev(2), dev(3)]);
}

#[test]
fn gc_removes_expired_entries() {
    let backoff = PeerBackoff::new(1);
    backoff.record_reject(dev(1));
    backoff.record_reject(dev(2));
    std::thread::sleep(std::time::Duration::from_millis(1100));
    backoff.gc();
    let map_len = backoff.cooldowns.lock().unwrap().len();
    assert_eq!(map_len, 0);
}

#[test]
fn record_reject_overwrites_earlier_cooldown() {
    let backoff = PeerBackoff::new(60);
    backoff.record_reject(dev(1));
    let first_deadline = *backoff.cooldowns.lock().unwrap().get(&dev(1)).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    backoff.record_reject(dev(1));
    let second_deadline = *backoff.cooldowns.lock().unwrap().get(&dev(1)).unwrap();
    assert!(second_deadline > first_deadline);
}

#[test]
fn default_uses_production_cooldown_secs() {
    let backoff = PeerBackoff::default();
    assert_eq!(backoff.cooldown.as_secs(), DEFAULT_COOLDOWN_SECS);
}
