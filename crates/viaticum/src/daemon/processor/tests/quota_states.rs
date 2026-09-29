// F-Q on the offer path: the offer rule over the three quota states. A child of
// `processor/tests.rs` (reuses `make_processor_with_quota`).

use tempfile::TempDir;
use viaticum_core::db::Db;

use super::super::offer_shadow::OfferSnapshot;
use super::make_processor_with_quota;

fn snap(held_bytes: u64, disk_free: Option<u64>) -> OfferSnapshot {
    OfferSnapshot {
        held_bytes,
        disk_free,
    }
}

/// holder-i3: the snapshot's held bytes are the quota's `used_holdings` — 60 held + 40 free,
/// no reserve ⇒ quota 100, an offer of 10 fits. Counted twice (quota 40) it would be refused.
#[tokio::test]
async fn offer_rule_counts_the_snapshot_holdings_once() {
    let dir = TempDir::new().unwrap();
    let mut p = make_processor_with_quota(Db::open_in_memory().unwrap(), &dir, 0, 0).await;
    p.disk_reserve_bytes = 0;
    assert!(p.decide_symbol_offer_on(10, &snap(60, Some(40))));
    assert!(!p.decide_symbol_offer_on(41, &snap(60, Some(40))));
}

/// holder-i1: free disk plus held at or below the reserve ⇒ every offer refused.
#[tokio::test]
async fn offer_rule_refuses_on_a_full_disk() {
    let dir = TempDir::new().unwrap();
    let mut p = make_processor_with_quota(Db::open_in_memory().unwrap(), &dir, 0, 0).await;
    p.disk_reserve_bytes = 100;
    assert!(!p.decide_symbol_offer_on(1, &snap(60, Some(40))));
    assert!(!p.decide_symbol_offer_on(1, &snap(0, Some(100))));
    p.soft_quota_bytes = 1 << 30;
    assert!(!p.decide_symbol_offer_on(1, &snap(0, Some(100))));
}

/// holder-i2: unreadable disk ⇒ refused without a soft quota, decided by it with one.
#[tokio::test]
async fn offer_rule_on_an_unreadable_disk_follows_the_soft_quota_or_refuses() {
    let dir = TempDir::new().unwrap();
    let mut p = make_processor_with_quota(Db::open_in_memory().unwrap(), &dir, 0, 0).await;
    p.disk_reserve_bytes = 100;
    assert!(!p.decide_symbol_offer_on(1, &snap(0, None)));
    p.soft_quota_bytes = 1000;
    assert!(p.decide_symbol_offer_on(10, &snap(0, None)));
    assert!(!p.decide_symbol_offer_on(10, &snap(900, None)));
}
