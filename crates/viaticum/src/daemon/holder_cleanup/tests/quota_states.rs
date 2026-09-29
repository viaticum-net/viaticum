// F-Q on the pressure tick: one holdings snapshot feeds both the quota and the pressure
// (holder-i3, line A's requirement), the unknown-disk WARN is daily on the monotonic clock
// and says where (holder-i2).

use std::path::Path;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use viaticum_core::budget::{DiskPressure, Quota};
use viaticum_core::db::Db;
use viaticum_core::four_r_holder::FourRParams;
use viaticum_core::types::{HoldingRecord, HoldingStatus, Timestamp};

use super::super::{UnknownDiskWarn, check_pressure, pressure_on_snapshot, unreadable_disk_note};
use super::{block_id, holder_master_pub, make_router_and_sender, owner_id, test_key};
use crate::daemon::four_r_log::tests::capture;

fn holding(b: u8, bytes: u64) -> HoldingRecord {
    HoldingRecord {
        source_block_id: block_id(b),
        owner_id: owner_id(b),
        esi_ranges: vec![(0, 1)],
        importance: 0.5,
        total_bytes: bytes,
        status: HoldingStatus::Active,
        received_at: Timestamp(0),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    }
}

/// holder-i3: the held bytes summed from the snapshot are both the quota's `used_holdings`
/// and the pressure's `used_bytes`. 60 held + 40 free, no reserve ⇒ quota 100, 40 % free ⇒
/// Normal. A quota computed without the snapshot's 60 (40) would be Hard on the same tick.
#[test]
fn quota_and_pressure_read_one_holdings_snapshot() {
    let hs = vec![holding(1, 30), holding(2, 30)];
    let (used, quota, res) = pressure_on_snapshot(&hs, Some(40), 0, 0, 0, |_| 0.5, 0);
    assert_eq!(used, 60);
    assert_eq!(quota, Quota::Bytes(100));
    assert_eq!(res.pressure, DiskPressure::Normal);
    assert!(res.immediate_evictions.is_empty());
}

/// holder-i1 on the tick: free + held ≤ reserve ⇒ every holding above the (zero) floor goes.
#[test]
fn full_disk_on_the_tick_evicts_to_the_floor() {
    let hs = vec![holding(1, 30), holding(2, 30)];
    let (_, quota, res) = pressure_on_snapshot(&hs, Some(10), 0, 0, 100, |_| 0.5, 0);
    assert_eq!(quota, Quota::Bytes(0));
    assert_eq!(res.pressure, DiskPressure::Hard);
    assert_eq!(res.freed_bytes, 60);
}

/// holder-i2 on the tick: unreadable disk, no soft quota ⇒ nothing evicted.
#[test]
fn unreadable_disk_on_the_tick_evicts_nothing() {
    let hs = vec![holding(1, 30), holding(2, 30)];
    let (_, quota, res) = pressure_on_snapshot(&hs, None, 0, 0, 100, |_| 0.5, 0);
    assert_eq!(quota, Quota::Unknown);
    assert_eq!(res.pressure, DiskPressure::Soft);
    assert!(res.immediate_evictions.is_empty() && res.drop_notices.is_empty());
}

/// holder-i2: the WARN is due once, then not again for 24 h of monotonic time.
#[test]
fn unknown_disk_warn_is_due_at_most_once_per_day() {
    let mut w = UnknownDiskWarn::default();
    let t0 = Instant::now();
    assert!(w.due(t0));
    assert!(!w.due(t0));
    assert!(!w.due(t0 + Duration::from_secs(24 * 3600 - 1)));
    assert!(w.due(t0 + Duration::from_secs(24 * 3600)));
    assert!(!w.due(t0 + Duration::from_secs(24 * 3600 + 60)));
}

/// holder-i2: the note names the path and what the node does about it.
#[test]
fn unreadable_disk_note_names_the_path_and_the_consequence() {
    let p = Path::new("/srv/viaticum");
    let no_soft = unreadable_disk_note(p, 0);
    assert!(
        no_soft.contains("could not read free space on /srv/viaticum"),
        "{no_soft}"
    );
    assert!(no_soft.contains("not taking friends' data"), "{no_soft}");
    let soft = unreadable_disk_note(p, 1 << 30);
    assert!(soft.contains("soft quota"), "{soft}");
}

/// holder-i2 wired: the pressure tick over an unreadable data dir WARNs, naming the path —
/// once for two ticks within a day.
#[tokio::test]
async fn check_pressure_on_an_unreadable_disk_warns_once() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let (router, _sender) = make_router_and_sender(&db);
    let missing = dir.path().join("gone");
    let mut warn = UnknownDiskWarn::default();
    let (sink, guard) = capture("viaticum::daemon::holder_cleanup=warn");
    for _ in 0..2 {
        check_pressure(
            &db,
            dir.path(),
            &router,
            holder_master_pub(),
            0,
            0,
            &missing,
            0,
            1,
            &test_key(),
            &FourRParams::default(),
            &mut warn,
        )
        .await
        .unwrap();
    }
    drop(guard);
    let text = sink.text();
    let needle = format!("could not read free space on {}", missing.display());
    assert_eq!(text.matches(&needle).count(), 1, "{text}");
    assert!(text.contains("WARN"), "{text}");
}
