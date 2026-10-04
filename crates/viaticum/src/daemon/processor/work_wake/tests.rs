// Unit tests of the work-pipeline wake rate (C-DK Р-18).

use std::time::{Duration, Instant};

use viaticum_core::types::DeviceId;

use super::{WorkWakeLimiter, work_wake_min};

#[test]
fn work_wake_rate_limited_per_device() {
    let t0 = Instant::now();
    let min = work_wake_min(Some(1));
    assert_eq!(min, Some(Duration::from_secs(600)));
    let mut l = WorkWakeLimiter::default();
    let (a, b) = (DeviceId([1; 32]), DeviceId([2; 32]));
    assert!(l.allow(a, false, min, t0), "first return of a: wakes");
    assert!(
        !l.allow(a, false, min, t0 + Duration::from_secs(60)),
        "a again within 10 min: suppressed"
    );
    assert!(
        l.allow(b, false, min, t0 + Duration::from_secs(60)),
        "per device: b wakes"
    );
    assert!(
        l.allow(a, true, min, t0 + Duration::from_secs(61)),
        "a new peer always wakes"
    );
    assert!(
        l.allow(a, false, min, t0 + Duration::from_secs(700)),
        "after 10 min again"
    );
}

#[test]
fn work_wake_window_scales_and_is_off_without_time_scale() {
    assert_eq!(work_wake_min(Some(1200)), Some(Duration::from_millis(500)));
    assert_eq!(work_wake_min(None), None);
    let mut l = WorkWakeLimiter::default();
    let t0 = Instant::now();
    let a = DeviceId([1; 32]);
    assert!(l.allow(a, false, None, t0));
    assert!(
        l.allow(a, false, None, t0),
        "no time_scale: no limit, as before C4"
    );
}
