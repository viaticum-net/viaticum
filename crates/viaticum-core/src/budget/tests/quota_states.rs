// F-Q: the three quota states (holder-i1, holder-i2, holder-i3). A child of `budget/tests.rs`.

use super::*;

fn trust(_: &IdentityPub) -> f64 {
    0.5
}

/// `n` holdings of `each` bytes, distinct blocks and owners, equal priority.
fn holdings(n: u8, each: u64) -> Vec<HoldingRecord> {
    (0..n)
        .map(|i| {
            make_holding(
                [i; 32],
                [i; 32],
                0.5,
                each,
                HoldingStatus::Active,
                Timestamp(0),
            )
        })
        .collect()
}

/// holder-i1: free disk at or below the reserve is Critical — offers refused, foreign data
/// evicted down to the hard floor. Never "unlimited".
#[test]
fn free_below_reserve_is_critical_and_rejects_offers() {
    // free 5 + held 10 ≤ reserve 20 ⇒ no room at all.
    let held = holdings(5, gib(2));
    let q = compute_effective_quota(0, Some(gib(5)), gib(10), gib(20));
    assert_eq!(q, Quota::Bytes(0));
    assert!(should_reject_offers(q, gib(10)));

    // No hard floor: everything goes.
    let r = evaluate_pressure(q, 0, gib(10), &held, trust, 0);
    assert_eq!(r.pressure, DiskPressure::Hard);
    assert_eq!(r.immediate_evictions.len(), 5);
    assert_eq!(r.freed_bytes, gib(10));
    assert!(r.drop_notices.is_empty());

    // Hard floor 4 GiB: evicted down to the floor, not below.
    let r = evaluate_pressure(q, gib(4), gib(10), &held, trust, 0);
    assert_eq!(r.pressure, DiskPressure::Hard);
    assert_eq!(r.freed_bytes, gib(6));
    assert_eq!(r.immediate_evictions.len(), 3);

    // An empty holder on a full disk: nothing to evict, still Critical and refusing.
    let q = compute_effective_quota(gib(50), Some(gib(10)), 0, gib(20));
    assert_eq!(q, Quota::Bytes(0));
    assert_eq!(
        evaluate_pressure(q, 0, 0, &[], trust, 0).pressure,
        DiskPressure::Hard
    );
    assert!(should_reject_offers(q, 0));

    // Free below the reserve with more held than the gap: the quota is what may stay
    // (free + held − reserve = 20 of 30 held) — over quota ⇒ Hard, refused, evicting.
    let held = holdings(6, gib(5));
    let q = compute_effective_quota(0, Some(gib(10)), gib(30), gib(20));
    assert_eq!(q, Quota::Bytes(gib(20)));
    assert!(should_reject_offers(q, gib(30)));
    let r = evaluate_pressure(q, 0, gib(30), &held, trust, 0);
    assert_eq!(r.pressure, DiskPressure::Hard);
    assert!(!r.immediate_evictions.is_empty());
}

/// holder-i2: the disk could not be read and no soft quota is set — offers refused, nothing
/// evicted (not "evict everything to the floor" on every NAS).
#[test]
fn unknown_disk_free_rejects_offers_without_evicting() {
    let held = holdings(5, gib(2));
    let q = compute_effective_quota(0, None, gib(10), gib(20));
    assert_eq!(q, Quota::Unknown);
    assert!(should_reject_offers(q, gib(10)));
    assert!(should_reject_offers(q, 0));
    let r = evaluate_pressure(q, 0, gib(10), &held, trust, 0);
    assert_eq!(r.pressure, DiskPressure::Soft);
    assert!(r.immediate_evictions.is_empty());
    assert!(r.drop_notices.is_empty());
    assert_eq!(r.freed_bytes, 0);
}

/// holder-i2: the disk could not be read but a soft quota is set — the node works by it.
#[test]
fn unknown_disk_free_with_soft_quota_works_by_soft_quota() {
    let q = compute_effective_quota(gib(50), None, gib(10), gib(20));
    assert_eq!(q, Quota::Bytes(gib(50)));
    assert!(!should_reject_offers(q, gib(10)));
    assert_eq!(
        evaluate_pressure(q, 0, gib(10), &[], trust, 0).pressure,
        DiskPressure::Normal
    );
    // Near the soft quota it refuses; over it, it evicts — by the soft quota alone.
    assert!(should_reject_offers(q, gib(45)));
    let held = holdings(7, gib(7));
    let r = evaluate_pressure(q, 0, gib(49), &held, trust, 0);
    assert_eq!(r.pressure, DiskPressure::Hard);
    assert!(!r.immediate_evictions.is_empty());
}

/// holder-i3: a holder on a disk with 100 GiB free and a 20 GiB reserve takes offers until
/// soft pressure; its disk_free shrinks by what it holds. Counted once, the quota stays
/// `free₀ − reserve` = 80 GiB and it fills to the soft threshold of it (69 GiB); counted
/// twice the quota shrinks with every byte held and it stops near half (37 GiB).
#[test]
fn used_holdings_are_not_counted_twice() {
    let free0 = gib(100);
    let reserve = gib(20);
    let offer = gib(1);
    let mut used = 0u64;
    loop {
        // One snapshot: the same `used` goes to the quota and to the offer rule.
        let q = compute_effective_quota(0, Some(free0 - used), used, reserve);
        assert_eq!(q, Quota::Bytes(free0 - reserve), "used={used}");
        let Quota::Bytes(n) = q else { unreachable!() };
        if should_reject_offers(q, used) || used + offer > n {
            break;
        }
        used += offer;
    }
    assert_eq!(
        used,
        gib(69),
        "fills to the soft threshold of free₀ − reserve"
    );
}

/// Only the explicit `Unlimited` (tests) means "no limit".
#[test]
fn unlimited_quota_is_normal_and_accepts() {
    assert!(!should_reject_offers(Quota::Unlimited, gib(1000)));
    let r = evaluate_pressure(
        Quota::Unlimited,
        0,
        gib(1000),
        &holdings(3, gib(1)),
        trust,
        0,
    );
    assert_eq!(r.pressure, DiskPressure::Normal);
    assert!(r.immediate_evictions.is_empty());
}
